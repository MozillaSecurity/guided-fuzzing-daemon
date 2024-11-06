# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import hashlib
import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from dataclasses import dataclass
from datetime import datetime
from logging import getLogger
from pathlib import Path, PurePosixPath
from random import sample
from shutil import rmtree
from time import perf_counter
from typing import Any, Iterable, Iterator
from uuid import uuid4

import boto3
import botocore
from google.cloud import storage as gcp_storage

from .stats import GeneratedField, StatAggregator
from .utils import Executor

if sys.version_info[:2] < (3, 12):
    from .utils import batched
else:
    from itertools import batched

LOG = getLogger("gfd.storage")
QUEUE_UPLOAD_PERIOD = 7200


@dataclass
class Corpus:
    """Corpus for coverage guided fuzzing.

    This is a local folder of files, either input or output for AFL++/libFuzzer.
    """

    path: Path
    _uuid: str | None = None

    @property
    def uuid(self) -> str:
        if self._uuid is None:
            self._uuid = str(uuid4())
        return self._uuid


class CloudStorageFile(ABC):
    def __init__(self, name: PurePosixPath, modified: datetime | None):
        self.path = name
        self._modified = modified
        self._have_meta = modified is not None

    @abstractmethod
    def _refresh(self) -> None:
        pass

    @property
    def modified(self) -> datetime:
        if not self._have_meta:
            self._refresh()
        assert self._modified is not None
        return self._modified

    @abstractmethod
    def download_to_file(self, dest: Path) -> None:
        pass

    @abstractmethod
    def upload_from_file(self, src: Path, ignore_failure: bool = False) -> None:
        pass

    @abstractmethod
    def trunc(self) -> None:
        pass

    @abstractmethod
    def delete(self) -> None:
        pass

    @abstractmethod
    def exists(self) -> bool:
        pass


@dataclass
class CloudStorageProvider(ABC):
    bucket_name: str

    @abstractmethod
    def iter(self, prefix: PurePosixPath) -> Iterable[CloudStorageFile]:
        pass

    @abstractmethod
    def iter_projects(self, prefix: str = "") -> Iterable[str]:
        pass

    @abstractmethod
    def delete(self, files: Iterable[CloudStorageFile]) -> None:
        pass

    @abstractmethod
    def __getitem__(self, name: PurePosixPath) -> CloudStorageFile:
        pass

    def get_corpus_status(self, project: str) -> dict[str, int]:
        """Return status data for the corpus of the specified bucket/project

        Args:
            project_name: Name of the project folder inside the S3 bucket

        Returns:
            Dictionary containing corpus size per date modified
        """
        status_data = {}

        for file in self.iter(PurePosixPath(project) / "corpus"):
            date_str = file.modified.strftime("%Y-%m-%d")

            if date_str not in status_data:
                status_data[date_str] = 0
            status_data[date_str] += 1

        return status_data

    def get_queue_status(self, project: str) -> dict[str, int]:
        """Return status data for all queues in the specified S3 bucket/project

        Returns:
            Dictionary containing queue size per queue
        """
        status_data = {}

        for file in self.iter(PurePosixPath(project) / "queues"):
            queue_name = file.path.parts[2]  # skip project and "queues" folders

            if queue_name not in status_data:
                status_data[queue_name] = 0
            status_data[queue_name] += 1

        return status_data


class S3File(CloudStorageFile):
    def __init__(
        self,
        name: PurePosixPath,
        modified: datetime | None,
        _provider: S3Storage,
    ) -> None:
        super().__init__(name, modified)
        self._provider = _provider

    def _refresh(self) -> None:
        resp = self._provider.client.head_object(
            Bucket=self._provider.bucket_name, Key=str(self.path)
        )
        self._modified = resp["LastModified"]
        self._have_meta = True

    def download_to_file(self, dest: Path) -> None:
        LOG.debug("downloading %s", dest)
        with dest.open("wb") as fobj:
            self._provider.client.download_fileobj(
                self._provider.bucket_name, str(self.path), fobj
            )

    def upload_from_file(self, src: Path, ignore_failure: bool = False) -> None:
        try:
            with src.open("rb") as fobj:
                self._provider.client.upload_fileobj(
                    fobj, self._provider.bucket_name, str(self.path)
                )
        except FileNotFoundError as exc:
            if not ignore_failure:
                raise
            LOG.warning("file upload failed: %s", exc)

    def trunc(self) -> None:
        self._provider.client.put_object(
            Bucket=self._provider.bucket_name, Key=str(self.path), Body=b""
        )

    def delete(self) -> None:
        self._provider.client.delete_object(
            Bucket=self._provider.bucket_name, Key=str(self.path)
        )

    def exists(self) -> bool:
        try:
            self._provider.client.head_object(
                Bucket=self._provider.bucket_name, Key=str(self.path)
            )
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] == "404":
                return False
            raise  # pragma: no cover
        return True


class S3Storage(CloudStorageProvider):
    def __init__(self, bucket_name: str) -> None:
        super().__init__(bucket_name)
        config = botocore.config.Config(
            retries={
                "max_attempts": 10,
                "mode": "standard",
            }
        )
        self.client = boto3.client("s3", config=config)

    def delete(self, files: Iterable[CloudStorageFile]) -> None:
        keys = []
        for file in files:
            assert isinstance(file, S3File)
            assert file._provider is self  # pylint: disable=protected-access
            keys.append({"Key": str(file.path)})
        with Executor() as executor:
            # The S3 rate limit for DELETE is 3500/s, so use a factor of that.
            # The max allowed delete size is 1000.
            for del_keys in batched(keys, 500):
                executor.submit(
                    self.client.delete_objects,
                    Bucket=self.bucket_name,
                    Delete={"Objects": del_keys, "Quiet": True},
                )

    def iter(self, prefix: PurePosixPath) -> Iterable[CloudStorageFile]:
        result = self.client.list_objects_v2(
            Bucket=self.bucket_name, Prefix=f"{prefix}/"
        )
        for obj in result.get("Contents", ()):
            yield S3File(PurePosixPath(obj["Key"]), obj["LastModified"], self)
        while result["IsTruncated"]:
            result = self.client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"{prefix}/",
                ContinuationToken=result["NextContinuationToken"],
            )
            for obj in result["Contents"]:
                yield S3File(PurePosixPath(obj["Key"]), obj["LastModified"], self)

    def iter_projects(self, prefix: str = "") -> Iterable[str]:
        result = self.client.list_objects_v2(
            Bucket=self.bucket_name,
            Prefix=prefix,
            Delimiter="/",
        )
        for obj in result["CommonPrefixes"]:
            yield obj["Prefix"][:-1]  # trim trailing delimiter
        while result["IsTruncated"]:
            result = self.client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix,
                Delimiter="/",
                ContinuationToken=result["NextContinuationToken"],
            )
            for obj in result["CommonPrefixes"]:
                yield obj["Prefix"][:-1]  # trim trailing delimiter

    def __getitem__(self, name: PurePosixPath) -> CloudStorageFile:
        return S3File(name, None, self)


class GCSFile(CloudStorageFile):
    def __init__(
        self,
        name: PurePosixPath,
        modified: datetime | None,
        _provider: GoogleCloudStorage,
    ) -> None:
        super().__init__(name, modified)
        self._provider = _provider

    def _refresh(self) -> None:
        blob = self._provider.bucket.blob(str(self.path))
        self._modified = blob.updated
        self._have_meta = True

    def download_to_file(self, dest: Path) -> None:
        LOG.debug("downloading %s", dest)
        with dest.open("wb") as fobj:
            self._provider.bucket.blob(str(self.path)).download_to_file(fobj)

    def upload_from_file(self, src: Path, ignore_failure: bool = False) -> None:
        try:
            with src.open("rb") as fobj:
                self._provider.bucket.blob(str(self.path)).upload_from_file(fobj)
        except FileNotFoundError as exc:
            if not ignore_failure:
                raise
            LOG.warning("file upload failed: %s", exc)

    def trunc(self) -> None:
        self._provider.bucket.blob(str(self.path)).upload_from_string(b"")

    def delete(self) -> None:
        self._provider.bucket.blob(str(self.path)).delete()

    def exists(self) -> bool:
        return bool(self._provider.bucket.blob(str(self.path)).exists())


class GoogleCloudStorage(CloudStorageProvider):
    def __init__(self, bucket_name: str) -> None:
        super().__init__(bucket_name)
        self.client = gcp_storage.Client()
        self.bucket = self.client.bucket(bucket_name)

    def delete(self, files: Iterable[CloudStorageFile]) -> None:
        file_list = []
        for file in files:
            assert isinstance(file, GCSFile)
            assert file._provider is self  # pylint: disable=protected-access
            file_list.append(str(file.path))
        with Executor() as executor:
            for del_files in batched(file_list, 100):
                executor.submit(self.bucket.delete_blobs, del_files)

    def iter(self, prefix: PurePosixPath) -> Iterator[CloudStorageFile]:
        for blob in self.bucket.list_blobs(prefix=f"{prefix}/"):
            yield GCSFile(PurePosixPath(blob.name), blob.updated, self)

    def iter_projects(self, prefix: str = "") -> Iterable[str]:
        blobs = self.bucket.list_blobs(prefix=prefix, delimiter="/")
        # must consume iterator to get the response
        for _ in blobs:
            pass  # pragma: no cover
        for result in blobs.prefixes:
            yield result[:-1]  # trim trailing delimiter

    def __getitem__(self, name: PurePosixPath) -> CloudStorageFile:
        return GCSFile(name, None, self)


@dataclass(init=False)
class CorpusSyncer:
    provider: CloudStorageProvider
    corpus: Corpus
    project: PurePosixPath | None

    def __init__(
        self, provider: CloudStorageProvider, corpus: Corpus, project: str | None
    ) -> None:
        self.provider = provider
        self.corpus = corpus
        if project is None:
            self.project = None
        else:
            self.project = PurePosixPath(project)

    def download_corpus(self, random_subset_size: int | None = None) -> int:
        assert self.project is not None
        start = perf_counter()
        with Executor() as executor:
            prefix = self.project / "corpus"
            downloaded = 0
            if random_subset_size is None:
                file_iter = self.provider.iter(prefix)
            else:
                all_files = tuple(self.provider.iter(prefix))
                n_files = min(random_subset_size, len(all_files))
                LOG.info(
                    "selecting %d files at random from %d total corpus files",
                    random_subset_size,
                    n_files,
                )
                file_iter = sample(all_files, random_subset_size)
            for file in file_iter:
                out_path = self.corpus.path / file.path.name
                assert not out_path.exists()
                executor.submit(file.download_to_file, out_path)
                downloaded += 1
            n_files = downloaded
        LOG.info(
            "download_corpus() -> downloaded=%d, total=%d (%.03fs)",
            downloaded,
            n_files,
            perf_counter() - start,
        )
        return downloaded

    def upload_corpus(self, delete_existing: bool = False) -> None:
        assert self.project is not None
        start = perf_counter()
        with Executor() as executor:
            prefix = self.project / "corpus"
            # get list of files to delete if upload is successful
            existing = {file.path.name: file for file in self.provider.iter(prefix)}
            old_corpus_size = len(existing)
            # upload new files
            uploaded = 0
            for testcase in self.corpus.path.iterdir():
                hash_name = hashlib.sha1(testcase.read_bytes()).hexdigest()
                if hash_name in existing:
                    # remove from existing so it isn't deleted
                    del existing[hash_name]
                else:
                    remote_obj = self.provider[prefix / hash_name]
                    executor.submit(remote_obj.upload_from_file, testcase)
                    uploaded += 1

        # delete files that no longer exist in the local corpus
        if delete_existing:
            deleted = len(existing)
            self.provider.delete(tuple(existing.values()))
            LOG.info(
                "upload_corpus() -> before=%d, new=%d, deleted=%d, after=%d (%.03fs)",
                old_corpus_size,
                uploaded,
                deleted,
                uploaded + old_corpus_size - deleted,
                perf_counter() - start,
            )
        else:
            LOG.info(
                "upload_corpus() -> before=%d, new=%d, after=%d (%.03fs)",
                old_corpus_size,
                uploaded,
                uploaded + old_corpus_size,
                perf_counter() - start,
            )

    def upload_queue(self, skip_hashes: Iterable[str]) -> None:
        assert self.project is not None
        start = perf_counter()
        # get list of files existing
        prefix = self.project / "queues" / self.corpus.uuid
        existing = {file.path.name for file in self.provider.iter(prefix)}
        old_corpus_size = len(existing)
        existing |= set(skip_hashes)
        # upload new files
        uploaded = 0
        errors = 0
        with Executor() as executor:
            for testcase in self.corpus.path.iterdir():
                try:
                    hash_name = hashlib.sha1(testcase.read_bytes()).hexdigest()
                except FileNotFoundError:
                    LOG.error("-> file gone before we could hash it: %s", testcase)
                    errors += 1
                    continue
                except IsADirectoryError:
                    LOG.error("-> directory detected in corpus: %s", testcase)
                    errors += 1
                    continue
                if hash_name not in existing:
                    remote_obj = self.provider[prefix / hash_name]
                    executor.submit(remote_obj.upload_from_file, testcase, True)
                    uploaded += 1
        LOG.info(
            "upload_to_queue() -> before=%d, new=%d, after=%d, errors=%d (%.03fs)",
            old_corpus_size,
            uploaded,
            uploaded + old_corpus_size,
            errors,
            perf_counter() - start,
        )

    def delete_queues(self) -> None:
        assert self.project is not None
        start = perf_counter()
        # get list of queue files to delete
        prefix = self.project / "queues"
        existing = tuple(self.provider.iter(prefix))
        self.provider.delete(existing)
        LOG.info(
            "delete_queues() -> deleted=%d (%.03fs)",
            len(existing),
            perf_counter() - start,
        )

    def download_queues(self) -> dict[str, int]:
        assert self.project is not None
        start = perf_counter()
        # download all queue files to corpus
        status_data = {}
        downloaded = 0
        dupes = 0

        prefix = self.project / "queues"
        with Executor() as executor:
            for file in self.provider.iter(prefix):
                queue_name = file.path.parts[2]  # skip project and "queues" folders
                if queue_name not in status_data:
                    status_data[queue_name] = 0
                status_data[queue_name] += 1

                out_path = self.corpus.path / file.path.name
                if out_path.exists():
                    dupes += 1
                else:
                    executor.submit(file.download_to_file, out_path)
                    downloaded += 1
        LOG.info(
            "download_queues() -> downloaded=%d, skipped=%d (%.03fs)",
            downloaded,
            dupes,
            perf_counter() - start,
        )

        return status_data


class CorpusRefreshContext:

    def __init__(self, opts: Namespace, storage: CloudStorageProvider, extra_files: Iterable[Path] = ()) -> None:
        self.project = opts.project
        self.cloud_path = f"{opts.provider.lower()}://{opts.bucket}/{opts.project}"
        self.storage = storage
        self.stats = opts.stats
        self.exit_code: int | None = None
        self.extra_files = extra_files

        self.refresh_stats = StatAggregator()
        self.refresh_stats.add_field("queue_files", GeneratedField())
        self.refresh_stats.add_field("corpus_pre", GeneratedField())
        self.refresh_stats.add_field("corpus_post", GeneratedField())
        self.refresh_stats.add_sys_stats()

        self.queues_dir = opts.corpus_refresh / "queues"
        self.queues_dir.mkdir(parents=True, exist_ok=True)

        # Ensure the directory for our new tests is empty
        self.updated_tests_dir = opts.corpus_refresh / "tests"
        if self.updated_tests_dir.exists():
            rmtree(self.updated_tests_dir)
        self.updated_tests_dir.mkdir()

        try:
            queue_downloader = CorpusSyncer(
                self.storage, Corpus(self.queues_dir), self.project
            )

            # Download our current corpus into the queues directory
            LOG.info(
                "Downloading corpus from %s/corpus/ to %s",
                self.cloud_path,
                self.queues_dir,
            )
            corpus_size = queue_downloader.download_corpus()
            self.refresh_stats.fields["corpus_pre"].update(corpus_size)

            LOG.info(
                "Downloading queues from %s/queues/ to %s",
                self.cloud_path,
                self.queues_dir,
            )
            queue_stats = queue_downloader.download_queues()
            self.refresh_stats.fields["queue_files"].update(sum(queue_stats.values()))

        except:  # noqa pylint: disable=bare-except
            try:
                if self.stats:
                    self.refresh_stats.write_file(self.stats, [])
            finally:
                raise

    def __enter__(self) -> CorpusRefreshContext:
        return self

    def __exit__(self, exc_type: Any, _exc_val: Any, _exc_tb: Any) -> None:
        if exc_type is not None:
            if self.stats:
                self.refresh_stats.write_file(self.stats, [])
            raise

        self.refresh_stats.fields["corpus_post"].update(
            sum(1 for _ in self.updated_tests_dir.iterdir())
        )

        if self.stats:
            self.refresh_stats.write_file(self.stats, [])

        if not any(self.updated_tests_dir.iterdir()):
            LOG.error("error: Merge returned empty result, refusing to upload.")
            self.exit_code = 2
            return

        # replace existing corpus with reduced corpus
        LOG.info("Uploading reduced corpus to %s/corpus/", self.cloud_path)
        corpus_uploader = CorpusSyncer(
            self.storage, Corpus(self.updated_tests_dir), self.project
        )
        corpus_uploader.upload_corpus(delete_existing=True)
        for extra in self.extra_files:
            remote_obj = self.storage[self.project / "corpus" / extra.name]
            remote_obj.upload_from_file(extra)
        corpus_uploader.delete_queues()

        self.exit_code = 0
