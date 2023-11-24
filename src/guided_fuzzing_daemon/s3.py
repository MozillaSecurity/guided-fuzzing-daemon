# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""S3Manager

Class to manage builds, corpus and queues for AFL and libFuzzer on AWS S3

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
"""
import hashlib
import os
import platform
import random
import shutil
import stat
import sys
from argparse import Namespace
from pathlib import Path, PurePosixPath
from subprocess import DEVNULL, Popen, run
from tempfile import mkstemp
from time import sleep, time
from typing import Dict, Iterable, Optional, Set
from zipfile import ZIP_DEFLATED, ZipFile

from boto.s3.connection import S3Connection
from boto.s3.key import Key
from boto.utils import parse_ts as boto_parse_ts

from .stats import (
    GeneratedField,
    StatAggregator,
)


class S3Manager:
    def __init__(
        self,
        bucket_name: str,
        project_name: str,
        build_project_name: Optional[str] = None,
        zip_name: str = "build.zip",
    ):
        """Initialize S3Manager

        Args:
            bucket_name: Name of the S3 bucket to use
            project_name: Name of the project folder inside the S3 bucket
            cmdline_file: Path to the cmdline file to upload
        """
        assert bucket_name
        assert project_name

        self.bucket_name = bucket_name
        self.project_name = project_name
        self.build_project_name = build_project_name
        self.zip_name = zip_name

        self.connection = S3Connection()
        self.bucket = self.connection.get_bucket(self.bucket_name)

        # Define some path constants that define the folder structure on S3
        self.remote_path_queues = f"{self.project_name}/queues/"
        self.remote_path_corpus = f"{self.project_name}/corpus/"
        self.remote_path_corpus_bundle = f"{self.project_name}/corpus.zip"

        if self.build_project_name:
            self.remote_path_build = f"{self.build_project_name}/{self.zip_name}"
        else:
            self.remote_path_build = f"{self.project_name}/{self.zip_name}"

        # Memorize which files we have uploaded/downloaded before, so we never attempt
        # to re-upload them to a different queue or re-download them after a local
        # merge.
        self.uploaded_files: Set[str] = set()
        self.downloaded_files: Set[str] = set()

    def upload_libfuzzer_queue_dir(
        self, base_dir: Path, corpus_dir: Path, original_corpus: Set[str]
    ) -> None:
        """Synchronize the corpus directory of the specified libFuzzer corpus directory
        to the specified S3 bucket. This method only uploads files that don't
        exist yet on the receiving side and excludes all files in the original corpus.

        Args:
            base_dir: libFuzzer base directory
            corpus_dir: libFuzzer corpus directory
            original_corpus: Set of original corpus files to exclude from
                             synchronization
        """
        upload_files = [
            x.name
            for x in corpus_dir.iterdir()
            if x.name not in original_corpus and x.name not in self.uploaded_files
        ]

        # Memorize files selected for upload
        self.uploaded_files.update(upload_files)

        cmdline_file = base_dir / "cmdline"

        self.__upload_queue_files(corpus_dir, upload_files, base_dir, cmdline_file)

    def download_libfuzzer_queues(self, corpus_dir: Path) -> None:
        """Synchronize files from open libFuzzer queues directly back into the local
        corpus directory.

        Args:
            corpus_dir: libFuzzer corpus directory
        """
        remote_keys = list(self.bucket.list(self.remote_path_queues))
        remote_queues_closed_names = [
            x.name.rsplit("/", 1)[0] for x in remote_keys if x.name.endswith("/closed")
        ]

        for remote_key in remote_keys:
            # Ignore any folders
            if remote_key.name.endswith("/"):
                continue

            # Ignore the cmdline and closed files
            if remote_key.name.endswith("/cmdline") or remote_key.name.endswith(
                "/closed"
            ):
                continue

            (queue_name, filename) = remote_key.name.rsplit("/", 1)

            if queue_name in remote_queues_closed_names:
                # If the file is in a queue marked as closed, ignore it
                continue

            basename = PurePosixPath(remote_key.name).name

            if basename in self.downloaded_files or basename in self.uploaded_files:
                # If we ever downloaded this file before, ignore it
                continue

            dest_file = corpus_dir / basename
            if dest_file.exists():
                # If the file already exists locally, ignore it
                continue

            print(f"Syncing from queue {queue_name}: {filename}")
            remote_key.get_contents_to_filename(str(dest_file))

            self.downloaded_files.add(basename)

    def upload_afl_queue_dir(self, base_path: Path, new_cov_only: bool = True) -> None:
        """Synchronize the queue directory of the specified AFL base directory
        to the specified S3 bucket. This method only uploads files that don't
        exist yet on the receiving side.

        Args:
            base_path: AFL base directory
            new_cov_only: Only upload files that have new coverage
        """
        queue_path = base_path / "queue"
        queue_files = []

        for queue_file in queue_path.iterdir():
            # Ignore all files that aren't crash results
            if not queue_file.name.startswith("id:"):
                continue

            # Only upload files that have new coverage if we aren't told
            # otherwise by the caller.
            if new_cov_only and "+cov" not in queue_file.name:
                continue

            # Ignore files that have been obtained from other local queues
            # to avoid duplicate uploading
            if ",sync:" in queue_file.name:
                continue

            queue_files.append(queue_file.name)

        cmdline_file = base_path / "cmdline"
        self.__upload_queue_files(queue_path, queue_files, base_path, cmdline_file)

    def download_queue_dirs(self, work_path: Path) -> Dict[str, int]:
        """Downloads all queue files into the queues sub directory of the specified
        local work directory. The files are renamed to match their SHA1 hashes
        to avoid file collisions.

        This method marks all remote queues that have been downloaded as closed.

        Args:
            work_path: Local work directory

        Returns:
            {queue: count} statistics for what was downloaded
        """
        download_path = work_path / "queues"
        download_path.mkdir(exist_ok=True)

        queue_counts: Dict[str, int] = {}

        remote_keys = list(self.bucket.list(self.remote_path_queues))

        remote_queue_names = set()
        remote_queues_already_closed = set()

        # Close all queues that aren't closed already.
        # This will stop the clients from uploading new data into these queues.
        #
        # Unfortunately we have to iterate over all files in the queue path to figure
        # out which queues exist. Then we have to determine which of them might already
        # been closed (this shouldn't happen normally), but we should check this anyway
        # and not consider it an error.
        for remote_key in remote_keys:
            (queue_name, filename) = remote_key.name.rsplit("/", 1)
            remote_queue_names.add(queue_name)
            if filename == "closed":
                remote_queues_already_closed.add(queue_name)

        for remote_queue_name in remote_queue_names:
            if remote_queue_name not in remote_queues_already_closed:
                closed_key = self.bucket.new_key(remote_queue_name + "/closed")
                closed_key.set_contents_from_string("")

        for remote_key in remote_keys:
            # Ignore any folders and the closed file
            if remote_key.name.endswith("/") or remote_key.name.endswith("/closed"):
                continue

            (queue_name, filename) = remote_key.name.rsplit("/", 1)

            # This queue was closed before, assume we downloaded it before to save
            # download requests.
            if queue_name in remote_queues_already_closed:
                continue

            # If we see a cmdline file, fetch it into the main work directory
            if PurePosixPath(remote_key.name).name == "cmdline":
                remote_key.get_contents_to_filename(str(work_path / "cmdline"))
                continue

            tmp_file = download_path / "tmp"

            remote_key.get_contents_to_filename(str(tmp_file))

            hash_name = hashlib.sha1(tmp_file.read_bytes()).hexdigest()

            tmp_file.rename(download_path / hash_name)

            queue_counts.setdefault(queue_name, 0)
            queue_counts[queue_name] += 1

        return queue_counts

    def clean_queue_dirs(self) -> None:
        """Delete all closed remote queues."""
        remote_keys = list(self.bucket.list(self.remote_path_queues))
        remote_keys_for_deletion = []

        remote_queues_closed_names = [
            x.name.rsplit("/", 1)[0] for x in remote_keys if x.name.endswith("/closed")
        ]

        for remote_key in remote_keys:
            # For folders, check if they are empty and if so, remove them
            if remote_key.name.endswith("/"):
                # TODO: This might not work in current boto, check later
                if remote_key.size == 0:
                    remote_keys_for_deletion.append(remote_key.name)
                continue

            (queue_name, _) = remote_key.name.rsplit("/", 1)
            if queue_name in remote_queues_closed_names:
                remote_keys_for_deletion.append(remote_key.name)

        for remote_key_for_deletion in remote_keys_for_deletion:
            print(f"Deleting old key {remote_key_for_deletion}")

        self.bucket.delete_keys(remote_keys_for_deletion, quiet=True)

    def get_queue_status(self) -> Dict[str, int]:
        """Return status data for all queues in the specified S3 bucket/project

        Returns:
            Dictionary containing queue size per queue
        """
        remote_keys = list(self.bucket.list(self.remote_path_queues))
        remote_queues_closed_names = [
            x.name.rsplit("/", 1)[0] for x in remote_keys if x.name.endswith("/closed")
        ]

        status_data = {}

        for remote_key in remote_keys:
            # Ignore any folders
            if remote_key.name.endswith("/"):
                continue

            # Ignore the cmdline and closed files
            if remote_key.name.endswith("/cmdline") or remote_key.name.endswith(
                "/closed"
            ):
                continue

            (queue_name, _) = remote_key.name.rsplit("/", 1)

            if queue_name in remote_queues_closed_names:
                queue_name += "*"

            if queue_name not in status_data:
                status_data[queue_name] = 0
            status_data[queue_name] += 1

        return status_data

    def get_corpus_status(self) -> Dict[str, int]:
        """Return status data for the corpus of the specified S3 bucket/project

        Args:
            bucket_name: Name of the S3 bucket to use
            project_name: Name of the project folder inside the S3 bucket

        Returns:
            Dictionary containing corpus size per date modified
        """
        remote_keys = list(self.bucket.list(self.remote_path_corpus))

        status_data = {}

        for remote_key in remote_keys:
            # Ignore any folders
            if remote_key.name.endswith("/"):
                continue

            date_obj = boto_parse_ts(remote_key.last_modified)

            date_str = f"{date_obj.year}-{date_obj.month:02d}-{date_obj.day:02d}"

            if date_str not in status_data:
                status_data[date_str] = 0
            status_data[date_str] += 1

        return status_data

    def download_build(self, build_path: Path) -> None:
        """Downloads build.zip from the specified S3 bucket and unpacks it
        into the specified build directory.

        Args:
            base_path: Build directory
            bucket_name: Name of the S3 bucket to use
            project_name: Name of the project folder inside the S3 bucket
        """
        # Clear any previous builds
        if build_path.exists():
            shutil.rmtree(str(build_path))
        build_path.mkdir()

        zip_dest = build_path / self.zip_name

        remote_key = Key(self.bucket)
        remote_key.name = self.remote_path_build
        remote_key.get_contents_to_filename(str(zip_dest))

        run(["unzip", str(zip_dest), "-d", str(build_path)], check=True)

    def upload_build(self, build_path: Path) -> None:
        """Upload the given build zip file to the specified S3 bucket/project
        directory.

        Args:
            build_file: (ZIP) file containing the build that should be uploaded
        """
        if not build_path.exists() or not build_path.is_file():
            print("error: Build must be a (zip) file.", file=sys.stderr)
            return

        remote_key = Key(self.bucket)
        remote_key.name = self.remote_path_build
        print(f"Uploading file {build_path} -> {remote_key.name}")
        remote_key.set_contents_from_filename(str(build_path))

    def download_corpus(
        self, corpus_dir: Path, random_subset_size: Optional[int] = None
    ) -> int:
        """Downloads the test corpus from the specified S3 bucket and project
        into the specified directory, without overwriting any files.

        Args:
            corpus_dir: Directory where to store test corpus files
            random_subset_size: If specified, only download a random subset of
                                the corpus, with the specified size.

        Returns:
            corpus size downloaded
        """
        corpus_dir.mkdir(exist_ok=True)

        if not random_subset_size:
            # If we are not instructed to download only a sample of the corpus,
            # we can try and look for a corpus bundle (zip file) for faster download.
            remote_key = Key(self.bucket)
            remote_key.name = self.remote_path_corpus_bundle
            if remote_key.exists():
                (zip_fd, zip_dest) = mkstemp(prefix="libfuzzer-s3-corpus")
                os.close(zip_fd)
                print("Found corpus bundle, downloading...")

                try:
                    remote_key.get_contents_to_filename(zip_dest)

                    with ZipFile(zip_dest, "r") as zip_file:
                        if zip_file.testzip():
                            # Warn, but don't throw, we can try to download the corpus
                            # directly
                            print(
                                f"Bad CRC for downloaded zipfile {zip_dest}",
                                file=sys.stderr,
                            )
                        else:
                            before = set(corpus_dir.iterdir())
                            zip_file.extractall(str(corpus_dir))
                            after = set(corpus_dir.iterdir())
                            return len(after - before)
                finally:
                    os.remove(zip_dest)

        remote_keys = list(self.bucket.list(self.remote_path_corpus))

        if random_subset_size and len(remote_keys) > random_subset_size:
            remote_keys = random.sample(remote_keys, random_subset_size)

        result = 0
        for remote_key in remote_keys:
            dest_file = corpus_dir / PurePosixPath(remote_key.name).name

            if not dest_file.exists():
                remote_key.get_contents_to_filename(str(dest_file))
                result += 1
        return result

    def upload_corpus(self, corpus_dir: Path, corpus_delete: bool = False) -> None:
        """Synchronize the specified test corpus directory to the specified S3 bucket.
        This method only uploads files that don't exist yet on the receiving side.

        Args:
            corpus_dir: Directory where the test corpus files are stored
            corpus_delete: Delete all remote files that don't exist on our side
        """
        test_files = [file for file in corpus_dir.iterdir() if file.is_file()]

        if not test_files:
            print("error: Corpus is empty, refusing upload.", file=sys.stderr)
            return

        # Make a zip bundle and upload it
        (zip_fd, zip_dest) = mkstemp(prefix="libfuzzer-s3-corpus")
        os.close(zip_fd)
        with ZipFile(zip_dest, "w", ZIP_DEFLATED) as zip_file:
            for test_file in test_files:
                zip_file.write(str(test_file), arcname=test_file.name)
        remote_key = Key(self.bucket)
        remote_key.name = self.remote_path_corpus_bundle
        print(f"Uploading file {zip_dest} -> {remote_key.name}")
        remote_key.set_contents_from_filename(zip_dest)
        os.remove(zip_dest)

        remote_path = self.remote_path_corpus
        remote_files = [
            key.name.replace(remote_path, "", 1)
            for key in list(self.bucket.list(remote_path))
        ]

        upload_list = []
        delete_list = []

        for test_file in test_files:
            if test_file.name not in remote_files:
                upload_list.append(test_file)

        if corpus_delete:
            for remote_file in remote_files:
                if (corpus_dir / remote_file) not in test_files:
                    delete_list.append(remote_path + remote_file)

        for upload_file in upload_list:
            remote_key = Key(self.bucket)
            remote_key.name = remote_path + upload_file.name
            print(f"Uploading file {upload_file} -> {remote_key.name}")
            remote_key.set_contents_from_filename(str(upload_file))

        if corpus_delete:
            self.bucket.delete_keys(delete_list, quiet=True)

    @staticmethod
    def __get_machine_id(base_dir: Path, refresh: bool = False) -> str:
        """Get (and if necessary generate) the machine id which is based on
        the current timestamp and the hostname of the machine. The
        generated ID is cached inside the base directory, so all
        future calls to this method return the same ID.

        Args:
            base_dir: Base directory
            refresh: Force generating a new machine ID

        Returns:
            The generated/cached machine ID
        """
        id_file = base_dir / "s3_id"

        # We initially create a unique ID based on the hostname and the
        # current timestamp, then we store this ID in a file inside the
        # fuzzing working directory so we can retrieve it later.
        if refresh or not id_file.exists():
            hasher = hashlib.new("sha1")
            hasher.update(platform.node().encode("utf-8"))
            hasher.update(str(time()).encode("utf-8"))
            digest = hasher.hexdigest()
            id_file.write_text(digest)
            return digest
        return id_file.read_text()

    def __upload_queue_files(
        self,
        queue_basedir: Path,
        queue_files: Iterable[str],
        base_dir: Path,
        cmdline_file: Path,
    ) -> None:
        machine_id = self.__get_machine_id(base_dir)
        remote_path = f"{self.remote_path_queues}{machine_id}/"
        remote_files = [
            key.name.replace(remote_path, "", 1)
            for key in list(self.bucket.list(remote_path))
        ]

        if "closed" in remote_files:
            # The queue we are assigned has been closed remotely.
            # Switch to a new queue instead.
            print(f"Remote queue {machine_id} closed, switching to new queue...")
            machine_id = self.__get_machine_id(base_dir, refresh=True)
            remote_path = f"{self.remote_path_queues}{machine_id}/"
            remote_files = [
                key.name.replace(remote_path, "", 1)
                for key in list(self.bucket.list(remote_path))
            ]

        upload_list = []

        for queue_file in queue_files:
            if queue_file not in remote_files:
                upload_list.append(queue_basedir / queue_file)

        if "cmdline" not in remote_files:
            upload_list.append(cmdline_file)

        for upload_file in upload_list:
            remote_key = Key(self.bucket)
            remote_key.name = remote_path + upload_file.name
            print(f"Uploading file {upload_file} -> {remote_key.name}")
            try:
                remote_key.set_contents_from_filename(str(upload_file))
            except OSError:
                # Newer libFuzzer can delete files from the corpus if it finds a shorter
                # version in the same run.
                pass


def s3_main(opts: Namespace) -> int:
    if opts.s3_list_projects:
        connection = S3Connection()
        bucket = connection.get_bucket(opts.s3_bucket)
        for key in bucket.list(prefix=opts.project or "", delimiter="/"):
            print(key.name[:-1])  # trim trailing delimiter
        return 0

    s3m = S3Manager(
        opts.s3_bucket, opts.project, opts.build_project, opts.build_zip_name
    )

    if opts.s3_build_download:
        s3m.download_build(opts.s3_build_download)

    elif opts.s3_build_upload:
        s3m.upload_build(opts.s3_build_upload)

    elif opts.s3_corpus_download:
        s3m.download_corpus(opts.s3_corpus_download, opts.s3_corpus_download_size)

    elif opts.s3_corpus_refresh:
        corpus_path = Path(opts.s3_corpus_refresh)
        refresh_stats = StatAggregator()
        refresh_stats.add_field("queue_files", GeneratedField())
        refresh_stats.add_field("corpus_pre", GeneratedField())
        refresh_stats.add_field("corpus_post", GeneratedField())
        refresh_stats.add_sys_stats()

        corpus_path.mkdir(parents=True, exist_ok=True)

        queues_dir = corpus_path / "queues"

        print(f"Cleaning old queues from s3://{opts.s3_bucket}/{opts.project}/queues/")
        s3m.clean_queue_dirs()

        print(
            f"Downloading queues from s3://{opts.s3_bucket}/{opts.project}/queues/ to "
            f"{queues_dir}"
        )
        queue_stats = s3m.download_queue_dirs(opts.s3_corpus_refresh)
        refresh_stats.fields["queue_files"].update(sum(queue_stats.values()))

        cmdline_file = corpus_path / "cmdline"
        if not cmdline_file.exists():
            # this can happen in a few legitimate cases:
            #  - project folder does not exist at all (new project)
            #  - only closed queues existed (old project)
            #  - no queues exist (recently refreshed manually)
            # print the error, but return 0
            print(
                "error: Failed to download a cmdline file from queue directories.",
                file=sys.stderr,
            )
            return 0

        if opts.build:
            build_path = Path(opts.build)
        else:
            print("Downloading build")
            build_path = corpus_path / "build"
            s3m.download_build(build_path)

        if opts.mode != "nyx":
            cmdline = (corpus_path / "cmdline").read_text().splitlines()

            # Assume cmdline[0] is the name of the binary
            binary_name = Path(cmdline[0]).name

            # Try locating our binary in the build we just unpacked
            binary_search_result = [
                file
                for file in build_path.glob("**/*")
                if file.is_file()
                and file.name == binary_name
                and (stat.S_IXUSR & file.stat().st_mode)
            ]

            if not binary_search_result:
                print(
                    f"error: Failed to locate binary {binary_name} in unpacked build.",
                    file=sys.stderr,
                )
                return 2

            if len(binary_search_result) > 1:
                print(
                    f"error: Binary name {binary_name} is ambiguous in unpacked build.",
                    file=sys.stderr,
                )
                return 2

            cmdline[0] = str(binary_search_result[0])

        # Download our current corpus into the queues directory as well
        print(
            f"Downloading corpus from s3://{opts.s3_bucket}/{opts.project}/corpus/ to "
            f"{queues_dir}"
        )
        corpus_size = s3m.download_corpus(queues_dir)
        refresh_stats.fields["corpus_pre"].update(corpus_size)

        # Ensure the directory for our new tests is empty
        updated_tests_dir = corpus_path / "tests"
        if updated_tests_dir.exists():
            shutil.rmtree(str(updated_tests_dir))
        updated_tests_dir.mkdir()

        try:
            if opts.mode == "nyx":
                assert opts.aflbindir.is_dir()
                assert opts.sharedir.is_dir()

                # Run afl-cmin
                afl_cmin = Path(opts.aflbindir) / "afl-cmin"
                if not afl_cmin.exists():
                    print("error: Unable to locate afl-cmin binary.", file=sys.stderr)
                    return 2

                afl_cmdline = [
                    str(afl_cmin),
                    "-e",
                    "-i",
                    str(queues_dir),
                    "-o",
                    str(updated_tests_dir),
                    "-t",
                    str(opts.afl_timeout),
                    "-m",
                    "none",
                    "-X",
                    str(opts.sharedir),
                ]

                print("Running afl-cmin")
                # pylint: disable=consider-using-with
                proc = Popen(afl_cmdline, stdout=None if opts.debug else DEVNULL)
                last_stats_report = 0.0
                while proc.poll() is None:
                    # Calculate stats
                    if opts.stats and last_stats_report < time() - 30:
                        refresh_stats.write_file(opts.stats, [])
                    last_stats_report = time()
                    sleep(0.1)
                assert not proc.wait()

            else:
                cmdline.extend(["-merge=1", str(updated_tests_dir), str(queues_dir)])

                # Filter out any -dict arguments that we don't need anyway for merging
                cmdline = [x for x in cmdline if not x.startswith("-dict=")]

                # Filter out any -max_len arguments because the length should only be
                # enforced by the instance(s) doing the actual testing.
                cmdline = [x for x in cmdline if not x.startswith("-max_len=")]

                print("Running libFuzzer merge")
                env = os.environ.copy()
                env["LD_LIBRARY_PATH"] = str(Path(cmdline[0]).parent)
                devnull: Optional[int] = DEVNULL
                if opts.debug:
                    devnull = None
                # pylint: disable=consider-using-with
                proc = Popen(cmdline, stdout=devnull, env=env)
                last_stats_report = 0.0
                while proc.poll() is None:
                    # Calculate stats
                    if opts.stats and last_stats_report < time() - 30:
                        refresh_stats.write_file(opts.stats, [])
                    last_stats_report = time()
                    sleep(0.1)
                assert not proc.wait()

            refresh_stats.fields["corpus_post"].update(
                sum(1 for _ in updated_tests_dir.iterdir())
            )

        finally:
            if opts.stats:
                refresh_stats.write_file(opts.stats, [])

        if not any(updated_tests_dir.iterdir()):
            print(
                "error: Merge returned empty result, refusing to upload.",
                file=sys.stderr,
            )
            return 2

        # replace existing corpus with reduced corpus
        print(
            f"Uploading reduced corpus to s3://{opts.s3_bucket}/{opts.project}/corpus/"
        )
        s3m.upload_corpus(updated_tests_dir, corpus_delete=True)

        # Prune the queues directory once we successfully uploaded the new
        # test corpus, but leave everything that's part of our new corpus
        # so we don't have to download those files again.
        test_files = [
            file.name for file in updated_tests_dir.iterdir() if file.is_file()
        ]
        obsolete_queue_files = [
            file.name
            for file in queues_dir.iterdir()
            if file.is_file() and file.name not in test_files
        ]

        for file in obsolete_queue_files:
            (queues_dir / file).unlink()

    elif opts.s3_corpus_status:
        status_data = s3m.get_corpus_status()
        total_corpus_files = 0

        for status_dt, status_cnt in sorted(status_data.items()):
            print(f"Added {status_dt}: {status_cnt}")
            total_corpus_files += status_cnt
        print(f"Total corpus files: {total_corpus_files}")

    elif opts.s3_corpus_upload:
        s3m.upload_corpus(opts.s3_corpus_upload, opts.s3_corpus_replace)

    elif opts.s3_queue_cleanup:
        s3m.clean_queue_dirs()

    elif opts.s3_queue_status:
        status_data = s3m.get_queue_status()
        total_queue_files = 0

        for queue_name, status in status_data.items():
            print(f"Queue {queue_name}: {status}")
            total_queue_files += status
        print(f"Total queue files: {total_queue_files}")

    return 0
