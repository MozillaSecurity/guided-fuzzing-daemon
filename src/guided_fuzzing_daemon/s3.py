"""
S3Manager -- Class to manage builds, corpus and queues for AFL and libFuzzer on AWS S3

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
import subprocess
import sys
import time
from pathlib import Path
from tempfile import mkstemp
from zipfile import ZIP_DEFLATED, ZipFile

from boto.s3.connection import S3Connection
from boto.s3.key import Key
from boto.utils import parse_ts as boto_parse_ts

from .utils import setup_firefox


class S3Manager:
    def __init__(
        self, bucket_name, project_name, build_project_name=None, zip_name="build.zip"
    ):
        """
        @type bucket_name: String
        @param bucket_name: Name of the S3 bucket to use

        @type project_name: String
        @param project_name: Name of the project folder inside the S3 bucket

        @type cmdline_file: String
        @param cmdline_file: Path to the cmdline file to upload.
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
        self.uploaded_files = set()
        self.downloaded_files = set()

    def upload_libfuzzer_queue_dir(self, base_dir, corpus_dir, original_corpus):
        """
        Synchronize the corpus directory of the specified libFuzzer corpus directory
        to the specified S3 bucket. This method only uploads files that don't
        exist yet on the receiving side and excludes all files in the original corpus.

        @type base_dir: String
        @param base_dir: libFuzzer base directory

        @type corpus_dir: String
        @param corpus_dir: libFuzzer corpus directory

        @type original_corpus: Set
        @param original_corpus: Set of original corpus files to exclude from
                                synchronization
        """
        upload_files = [
            x
            for x in os.listdir(corpus_dir)
            if x not in original_corpus and x not in self.uploaded_files
        ]

        # Memorize files selected for upload
        self.uploaded_files.update(upload_files)

        cmdline_file = os.path.join(base_dir, "cmdline")

        return self.__upload_queue_files(
            corpus_dir, upload_files, base_dir, cmdline_file
        )

    def download_libfuzzer_queues(self, corpus_dir):
        """
        Synchronize files from open libFuzzer queues directly back into the local corpus
        directory.

        @type corpus_dir: String
        @param corpus_dir: libFuzzer corpus directory
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

            basename = os.path.basename(remote_key.name)

            if basename in self.downloaded_files or basename in self.uploaded_files:
                # If we ever downloaded this file before, ignore it
                continue

            dest_file = os.path.join(corpus_dir, basename)
            if os.path.exists(dest_file):
                # If the file already exists locally, ignore it
                continue

            print(f"Syncing from queue {queue_name}: {filename}")
            remote_key.get_contents_to_filename(dest_file)

            self.downloaded_files.add(basename)

    def upload_afl_queue_dir(self, base_dir, new_cov_only=True):
        """
        Synchronize the queue directory of the specified AFL base directory
        to the specified S3 bucket. This method only uploads files that don't
        exist yet on the receiving side.

        @type base_dir: String
        @param base_dir: AFL base directory

        @type new_cov_only: Boolean
        @param new_cov_only: Only upload files that have new coverage
        """
        queue_dir = os.path.join(base_dir, "queue")
        queue_files = []

        for queue_file in os.listdir(queue_dir):
            # Ignore all files that aren't crash results
            if not queue_file.startswith("id:"):
                continue

            # Only upload files that have new coverage if we aren't told
            # otherwise by the caller.
            if new_cov_only and "+cov" not in queue_file:
                continue

            # Ignore files that have been obtained from other local queues
            # to avoid duplicate uploading
            if ",sync:" in queue_file:
                continue

            queue_files.append(queue_file)

        cmdline_file = os.path.join(base_dir, "cmdline")
        return self.__upload_queue_files(queue_dir, queue_files, base_dir, cmdline_file)

    def download_queue_dirs(self, work_dir):
        """
        Downloads all queue files into the queues sub directory of the specified
        local work directory. The files are renamed to match their SHA1 hashes
        to avoid file collisions.

        This method marks all remote queues that have been downloaded as closed.

        @type work_dir: String
        @param work_dir: Local work directory
        """
        download_dir = os.path.join(work_dir, "queues")

        if not os.path.exists(download_dir):
            os.mkdir(download_dir)

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
            if os.path.basename(remote_key.name) == "cmdline":
                remote_key.get_contents_to_filename(os.path.join(work_dir, "cmdline"))
                continue

            tmp_file = os.path.join(download_dir, "tmp")

            remote_key.get_contents_to_filename(tmp_file)

            with open(tmp_file, "rb") as tmp_fd:
                hash_name = hashlib.sha1(tmp_fd.read()).hexdigest()

            os.rename(tmp_file, os.path.join(download_dir, hash_name))

    def clean_queue_dirs(self):
        """
        Delete all closed remote queues.
        """
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

    def get_queue_status(self):
        """
        Return status data for all queues in the specified S3 bucket/project

        @rtype: dict
        @return: Dictionary containing queue size per queue
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

    def get_corpus_status(self):
        """
        Return status data for the corpus of the specified S3 bucket/project

        @type bucket_name: String
        @param bucket_name: Name of the S3 bucket to use

        @type project_name: String
        @param project_name: Name of the project folder inside the S3 bucket

        @rtype: dict
        @return: Dictionary containing corpus size per date modified
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

    def download_build(self, build_dir):
        """
        Downloads build.zip from the specified S3 bucket and unpacks it
        into the specified build directory.

        @type base_dir: String
        @param base_dir: Build directory

        @type bucket_name: String
        @param bucket_name: Name of the S3 bucket to use

        @type project_name: String
        @param project_name: Name of the project folder inside the S3 bucket
        """
        # Clear any previous builds
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)

        os.mkdir(build_dir)

        zip_dest = os.path.join(build_dir, self.zip_name)

        remote_key = Key(self.bucket)
        remote_key.name = self.remote_path_build
        remote_key.get_contents_to_filename(zip_dest)

        subprocess.run(["unzip", zip_dest, "-d", build_dir], check=True)

    def upload_build(self, build_file):
        """
        Upload the given build zip file to the specified S3 bucket/project
        directory.

        @type build_file: String
        @param build_file: (ZIP) file containing the build that should be uploaded
        """

        if not os.path.exists(build_file) or not os.path.isfile(build_file):
            print("Error: Build must be a (zip) file.", file=sys.stderr)
            return

        remote_key = Key(self.bucket)
        remote_key.name = self.remote_path_build
        print(f"Uploading file {build_file} -> {remote_key.name}")
        remote_key.set_contents_from_filename(build_file)

    def download_corpus(self, corpus_dir, random_subset_size=None):
        """
        Downloads the test corpus from the specified S3 bucket and project
        into the specified directory, without overwriting any files.

        @type corpus_dir: String
        @param corpus_dir: Directory where to store test corpus files

        @type random_subset_size: int
        @param random_subset_size: If specified, only download a random subset of
                                   the corpus, with the specified size.
        """
        if not os.path.exists(corpus_dir):
            os.mkdir(corpus_dir)

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
                            zip_file.extractall(corpus_dir)
                            return
                finally:
                    os.remove(zip_dest)

        remote_keys = list(self.bucket.list(self.remote_path_corpus))

        if random_subset_size and len(remote_keys) > random_subset_size:
            remote_keys = random.sample(remote_keys, random_subset_size)

        for remote_key in remote_keys:
            dest_file = os.path.join(corpus_dir, os.path.basename(remote_key.name))

            if not os.path.exists(dest_file):
                remote_key.get_contents_to_filename(dest_file)

    def upload_corpus(self, corpus_dir, corpus_delete=False):
        """
        Synchronize the specified test corpus directory to the specified S3 bucket.
        This method only uploads files that don't exist yet on the receiving side.

        @type corpus_dir: String
        @param corpus_dir: Directory where the test corpus files are stored

        @type corpus_delete: bool
        @param corpus_delete: Delete all remote files that don't exist on our side
        """
        test_files = [
            file
            for file in os.listdir(corpus_dir)
            if os.path.isfile(os.path.join(corpus_dir, file))
        ]

        if not test_files:
            print("Error: Corpus is empty, refusing upload.", file=sys.stderr)
            return

        # Make a zip bundle and upload it
        (zip_fd, zip_dest) = mkstemp(prefix="libfuzzer-s3-corpus")
        os.close(zip_fd)
        with ZipFile(zip_dest, "w", ZIP_DEFLATED) as zip_file:
            for test_file in test_files:
                zip_file.write(os.path.join(corpus_dir, test_file), arcname=test_file)
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
            if test_file not in remote_files:
                upload_list.append(os.path.join(corpus_dir, test_file))

        if corpus_delete:
            for remote_file in remote_files:
                if remote_file not in test_files:
                    delete_list.append(remote_path + remote_file)

        for upload_file in upload_list:
            remote_key = Key(self.bucket)
            remote_key.name = remote_path + os.path.basename(upload_file)
            print(f"Uploading file {upload_file} -> {remote_key.name}")
            remote_key.set_contents_from_filename(upload_file)

        if corpus_delete:
            self.bucket.delete_keys(delete_list, quiet=True)

    @staticmethod
    def __get_machine_id(base_dir, refresh=False):
        """
        Get (and if necessary generate) the machine id which is based on
        the current timestamp and the hostname of the machine. The
        generated ID is cached inside the base directory, so all
        future calls to this method return the same ID.

        @type base_dir: String
        @param base_dir: Base directory

        @type refresh: bool
        @param refresh: Force generating a new machine ID

        @rtype: String
        @return: The generated/cached machine ID
        """
        id_file = os.path.join(base_dir, "s3_id")

        # We initially create a unique ID based on the hostname and the
        # current timestamp, then we store this ID in a file inside the
        # fuzzing working directory so we can retrieve it later.
        if refresh or not os.path.exists(id_file):
            hasher = hashlib.new("sha1")
            hasher.update(platform.node().encode("utf-8"))
            hasher.update(str(time.time()).encode("utf-8"))
            digest = hasher.hexdigest()
            with open(id_file, "w") as id_fd:
                id_fd.write(digest)
            return digest
        with open(id_file) as id_fd:
            return id_fd.read()

    def __upload_queue_files(self, queue_basedir, queue_files, base_dir, cmdline_file):
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
                upload_list.append(os.path.join(queue_basedir, queue_file))

        if "cmdline" not in remote_files:
            upload_list.append(cmdline_file)

        for upload_file in upload_list:
            remote_key = Key(self.bucket)
            remote_key.name = remote_path + os.path.basename(upload_file)
            print(f"Uploading file {upload_file} -> {remote_key.name}")
            try:
                remote_key.set_contents_from_filename(upload_file)
            except OSError:
                # Newer libFuzzer can delete files from the corpus if it finds a shorter
                # version in the same run.
                pass


def s3_main(opts):
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
        if not os.path.exists(opts.s3_corpus_refresh):
            os.makedirs(opts.s3_corpus_refresh)

        queues_dir = os.path.join(opts.s3_corpus_refresh, "queues")

        print(f"Cleaning old queues from s3://{opts.s3_bucket}/{opts.project}/queues/")
        s3m.clean_queue_dirs()

        print(
            f"Downloading queues from s3://{opts.s3_bucket}/{opts.project}/queues/ to "
            f"{queues_dir}"
        )
        s3m.download_queue_dirs(opts.s3_corpus_refresh)

        cmdline_file = os.path.join(opts.s3_corpus_refresh, "cmdline")
        if not os.path.exists(cmdline_file):
            # this can happen in a few legitimate cases:
            #  - project folder does not exist at all (new project)
            #  - only closed queues existed (old project)
            #  - no queues exist (recently refreshed manually)
            # print the error, but return 0
            print(
                "Error: Failed to download a cmdline file from queue directories.",
                file=sys.stderr,
            )
            return 0

        build_path = os.path.join(opts.s3_corpus_refresh, "build")

        if opts.build:
            build_path = opts.build
        else:
            print("Downloading build")
            s3m.download_build(build_path)

        cmdline = (Path(opts.s3_corpus_refresh) / "cmdline").read_text().splitlines()

        # Assume cmdline[0] is the name of the binary
        binary_name = Path(cmdline[0]).name

        # Try locating our binary in the build we just unpacked
        binary_search_result = [
            os.path.join(dirpath, filename)
            for dirpath, dirnames, filenames in os.walk(build_path)
            for filename in filenames
            if (
                filename == binary_name
                and (stat.S_IXUSR & (Path(dirpath) / filename).stat().st_mode)
            )
        ]

        if not binary_search_result:
            print(
                f"Error: Failed to locate binary {binary_name} in unpacked build.",
                file=sys.stderr,
            )
            return 2

        if len(binary_search_result) > 1:
            print(
                f"Error: Binary name {binary_name} is ambiguous in unpacked build.",
                file=sys.stderr,
            )
            return 2

        cmdline[0] = binary_search_result[0]

        # Download our current corpus into the queues directory as well
        print(
            f"Downloading corpus from s3://{opts.s3_bucket}/{opts.project}/corpus/ to "
            f"{queues_dir}"
        )
        s3m.download_corpus(queues_dir)

        # Ensure the directory for our new tests is empty
        updated_tests_dir = os.path.join(opts.s3_corpus_refresh, "tests")
        if os.path.exists(updated_tests_dir):
            shutil.rmtree(updated_tests_dir)
        os.mkdir(updated_tests_dir)

        if opts.mode == "aflfuzz":
            assert opts.aflbindir

            # Run afl-cmin
            afl_cmin = os.path.join(opts.aflbindir, "afl-cmin")
            if not os.path.exists(afl_cmin):
                print("Error: Unable to locate afl-cmin binary.", file=sys.stderr)
                return 2

            if opts.firefox:
                (ffp, ff_cmd, ff_env) = setup_firefox(
                    cmdline[0],
                    opts.firefox_prefs,
                    opts.firefox_extensions,
                    opts.firefox_testpath,
                )
                cmdline = ff_cmd

            afl_cmdline = [
                afl_cmin,
                "-e",
                "-i",
                queues_dir,
                "-o",
                updated_tests_dir,
                "-t",
                str(opts.afl_timeout),
                "-m",
                "none",
            ]

            if opts.test_file:
                afl_cmdline.extend(["-f", opts.test_file])

            afl_cmdline.extend(cmdline)

            print("Running afl-cmin")
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = str(Path(cmdline[0]).parent)
            if opts.firefox:
                env.update(ff_env)
            devnull = subprocess.DEVNULL
            if opts.debug:
                devnull = None
            subprocess.run(afl_cmdline, stdout=devnull, env=env, check=True)

            if opts.firefox:
                ffp.clean_up()
        else:
            cmdline.extend(["-merge=1", updated_tests_dir, queues_dir])

            # Filter out any -dict arguments that we don't need anyway for merging
            cmdline = [x for x in cmdline if not x.startswith("-dict=")]

            # Filter out any -max_len arguments because the length should only be
            # enforced by the instance(s) doing the actual testing.
            cmdline = [x for x in cmdline if not x.startswith("-max_len=")]

            print("Running libFuzzer merge")
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = str(Path(cmdline[0]).parent)
            devnull = subprocess.DEVNULL
            if opts.debug:
                devnull = None
            subprocess.run(cmdline, stdout=devnull, env=env, check=True)

        if not os.listdir(updated_tests_dir):
            print(
                "Error: Merge returned empty result, refusing to upload.",
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
            file
            for file in os.listdir(updated_tests_dir)
            if os.path.isfile(os.path.join(updated_tests_dir, file))
        ]
        obsolete_queue_files = [
            file
            for file in os.listdir(queues_dir)
            if os.path.isfile(os.path.join(queues_dir, file)) and file not in test_files
        ]

        for file in obsolete_queue_files:
            os.remove(os.path.join(queues_dir, file))

    elif opts.s3_corpus_status:
        status_data = s3m.get_corpus_status()
        total_corpus_files = 0

        for (status_dt, status_cnt) in sorted(status_data.items()):
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
