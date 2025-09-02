# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from itertools import chain
from logging import getLogger
from pathlib import Path, PurePosixPath
from shutil import rmtree
from time import perf_counter
from typing import Any, Iterable, Iterator
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

import boto3
import botocore
from google.cloud import storage as gcp_storage

from .stats import GeneratedField, StatAggregator
from .utils import Executor, TempPath

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
    def __init__(
        self, name: PurePosixPath, modified: datetime | None, size: int | None
    ):
        self.path = name
        self._modified = modified
        self._size = size
        self._have_meta = modified is not None and size is not None

    @abstractmethod
    def _refresh(self) -> None:
        pass

    @property
    def modified(self) -> datetime:
        if not self._have_meta:
            self._refresh()
        assert self._modified is not None
        return self._modified

    @property
    def size(self) -> int:
        if not self._have_meta:
            self._refresh()
        assert self._size is not None
        return self._size

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
        size: int | None,
        _provider: S3Storage,
    ) -> None:
        super().__init__(name, modified, size)
        self._provider = _provider

    def _refresh(self) -> None:
        resp = self._provider.client.head_object(
            Bucket=self._provider.bucket_name, Key=str(self.path)
        )
        self._modified = resp["LastModified"]
        self._size = resp["ContentLength"]
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
        if not keys:
            return
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
            yield S3File(
                PurePosixPath(obj["Key"]),
                obj["LastModified"],
                obj["Size"],
                self,
            )
        while result["IsTruncated"]:
            result = self.client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"{prefix}/",
                ContinuationToken=result["NextContinuationToken"],
            )
            for obj in result["Contents"]:
                yield S3File(
                    PurePosixPath(obj["Key"]),
                    obj["LastModified"],
                    obj["Size"],
                    self,
                )

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
        return S3File(name, None, None, self)


class GCSFile(CloudStorageFile):
    def __init__(
        self,
        name: PurePosixPath,
        modified: datetime | None,
        size: int | None,
        _provider: GoogleCloudStorage,
    ) -> None:
        super().__init__(name, modified, size)
        self._provider = _provider

    def _refresh(self) -> None:
        blob = self._provider.bucket.blob(str(self.path))
        blob.reload()
        self._modified = blob.updated
        self._size = blob.size
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
        if not file_list:
            return
        with Executor() as executor:
            for del_files in batched(file_list, 100):
                executor.submit(self.bucket.delete_blobs, del_files)

    def iter(self, prefix: PurePosixPath) -> Iterator[CloudStorageFile]:
        for blob in self.bucket.list_blobs(prefix=f"{prefix}/"):
            yield GCSFile(PurePosixPath(blob.name), blob.updated, blob.size, self)

    def iter_projects(self, prefix: str = "") -> Iterable[str]:
        blobs = self.bucket.list_blobs(prefix=prefix, delimiter="/")
        # must consume iterator to get the response
        for _ in blobs:
            pass  # pragma: no cover
        for result in blobs.prefixes:
            yield result[:-1]  # trim trailing delimiter

    def __getitem__(self, name: PurePosixPath) -> CloudStorageFile:
        return GCSFile(name, None, None, self)


class ResourceType(str, Enum):
    QUEUE = "queues"
    CORPUS = "corpus"


@dataclass(init=False)
class CorpusSyncer:
    provider: CloudStorageProvider
    corpus: Corpus
    suffix: str | None  # only add files with this extension
    extra_queues: list[Corpus]  # only used by upload_queues()
    project: PurePosixPath | None

    def __init__(
        self,
        provider: CloudStorageProvider,
        corpus: Corpus,
        project: str | None,
        suffix: str | None = None,
    ) -> None:
        self.provider = provider
        self.corpus = corpus
        self.extra_queues = []
        if project is None:
            self.project = None
        else:
            self.project = PurePosixPath(project)
        self.suffix = suffix

    def upload_corpus(self) -> None:
        assert self.project is not None
        start = perf_counter()

        uploaded = 0

        # get list of files to delete if upload is successful
        to_delete = {
            file.path.name: file for file in self.provider.iter(self.project / "corpus")
        }
        # remove corpus.zip, it will be overwritten on success
        to_delete.pop("corpus.zip", None)

        with TempPath() as tmpd:
            corpus_zip_remote = self.provider[self.project / "corpus.zip"]
            corpus_zip_local = tmpd / "corpus.zip"

            with ZipFile(corpus_zip_local, "w", ZIP_DEFLATED) as zfp:
                for testcase in self.corpus.path.iterdir():
                    if self.suffix is None or testcase.suffix == self.suffix:
                        zfp.write(testcase, arcname=testcase.name)
                        uploaded += 1

            if uploaded:
                corpus_zip_remote.upload_from_file(corpus_zip_local)
                LOG.info("Uploaded ZIP: %s", corpus_zip_local.name)
            else:
                LOG.warning("Corpus is empty! Not deleting existing corpus")
                to_delete.clear()

        self.provider.delete(to_delete.values())

        LOG.info(
            "upload_corpus() -> uploaded=%d (%.03fs)",
            uploaded,
            perf_counter() - start,
        )

    def upload_queue(self, skip_names: Iterable[str]) -> None:
        assert self.project is not None
        start = perf_counter()

        skip_names = set(skip_names)
        uploaded = 0
        errors = 0

        # Create a temporary ZIP file
        with TempPath() as tmpd:
            queue_zip_remote = self.provider[
                self.project / "queues" / f"{self.corpus.uuid}.zip"
            ]
            queue_zip_local = tmpd / f"{self.corpus.uuid}.zip"

            with ZipFile(queue_zip_local, "w", ZIP_DEFLATED) as zfp:
                for queue in [self.corpus, *self.extra_queues]:
                    if not queue.path.is_dir():
                        continue
                    for testcase in queue.path.iterdir():
                        if testcase.is_dir():
                            LOG.error("-> directory detected in corpus: %s", testcase)
                            errors += 1
                            continue

                        if testcase.name in skip_names:
                            continue

                        if self.suffix is None or testcase.suffix == self.suffix:
                            zfp.write(testcase, arcname=testcase.name)
                            uploaded += 1

            queue_zip_remote.upload_from_file(queue_zip_local, True)
            LOG.info("Uploaded ZIP: %s", queue_zip_local.name)

        LOG.info(
            "upload_to_queue() -> uploaded=%d, errors=%d (%.03fs)",
            uploaded,
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

    def download_resource(self, target: ResourceType) -> int:
        assert self.project is not None
        start = perf_counter()

        paths = self.provider.iter(self.project / target.value)
        if target == ResourceType.CORPUS:
            paths = chain(paths, [self.provider[self.project / "corpus.zip"]])

        total = 0
        downloaded = 0
        duplicates = 0

        zips = []
        with TempPath() as tmpd:
            with Executor() as executor:
                for file in paths:
                    if not file.exists():
                        continue
                    if not file.size > 0:
                        LOG.warning("skipping invalid path: %s", file.path)
                        continue
                    if file.path.suffix == ".zip":
                        out_path = tmpd / file.path.name
                        zips.append(out_path)
                    else:
                        # download directly to corpus path
                        out_path = self.corpus.path / file.path.name
                        total += 1

                    executor.submit(file.download_to_file, out_path)
                    downloaded += 1

            extracted = 0
            for zip_file in zips:
                with ZipFile(zip_file) as zf:
                    for entry in zf.infolist():
                        total += 1
                        if (self.corpus.path / entry.filename).exists():
                            duplicates += 1
                        else:
                            zf.extract(entry.filename, self.corpus.path)
                            extracted += 1
                zip_file.unlink()

        LOG.info(
            "download_resources() -> "
            + "path=%s, total=%d, downloaded=%d, extracted=%d, skipped=%d (%.03fs)",
            target.value,
            total,
            downloaded,
            extracted,
            duplicates,
            perf_counter() - start,
        )

        return total


class CorpusRefreshContext:
    def __init__(
        self,
        opts: Namespace,
        storage: CloudStorageProvider,
        subdir: str | None = None,
        suffix: str | None = None,
        extra_files: Iterable[Path] = (),
    ) -> None:
        self.project = opts.project
        self.cloud_path = f"{opts.provider.lower()}://{opts.bucket}/{opts.project}"
        self.storage = storage
        self.stats = opts.stats
        self.exit_code: int | None = None
        self.suffix = suffix
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
        self.output_subdir = subdir

        try:
            queue_downloader = CorpusSyncer(
                self.storage, Corpus(self.queues_dir), self.project, self.suffix
            )

            # Download our current corpus into the queues directory
            LOG.info(
                "Downloading corpus from %s/corpus/ to %s",
                self.cloud_path,
                self.queues_dir,
            )
            corpus_size = queue_downloader.download_resource(ResourceType.CORPUS)
            self.refresh_stats.fields["corpus_pre"].update(corpus_size)

            LOG.info(
                "Downloading queues from %s/queues/ to %s",
                self.cloud_path,
                self.queues_dir,
            )
            queue_size = queue_downloader.download_resource(ResourceType.QUEUE)
            self.refresh_stats.fields["queue_files"].update(queue_size)

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

        updated_tests_dir = self.updated_tests_dir
        if self.output_subdir is not None:
            updated_tests_dir = updated_tests_dir / self.output_subdir

        self.refresh_stats.fields["corpus_post"].update(
            sum(
                1
                for f in updated_tests_dir.iterdir()
                if self.suffix is None or f.suffix == self.suffix
            )
        )

        if self.stats:
            self.refresh_stats.write_file(self.stats, [])

        if not self.refresh_stats.fields["corpus_post"].value:
            LOG.error("error: Merge returned empty result, refusing to upload.")
            self.exit_code = 2
            return

        # replace existing corpus with reduced corpus
        LOG.info("Uploading reduced corpus to %s/corpus/", self.cloud_path)
        corpus_uploader = CorpusSyncer(
            self.storage, Corpus(updated_tests_dir), self.project, self.suffix
        )
        corpus_uploader.upload_corpus()
        for extra in self.extra_files:
            remote_obj = self.storage[
                PurePosixPath(self.project) / "corpus" / extra.name
            ]
            remote_obj.upload_from_file(extra)
        corpus_uploader.delete_queues()

        self.exit_code = 0
