# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import io
import os
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from shutil import copyfile
from zipfile import ZipFile

import pytest
from botocore.stub import ANY, Stubber

from guided_fuzzing_daemon.storage import (
    CloudStorageFile,
    CloudStorageProvider,
    Corpus,
    CorpusRefreshContext,
    CorpusSyncer,
    GCSFile,
    GoogleCloudStorage,
    ResourceType,
    S3File,
    S3Storage,
)


class _TestExc(Exception):
    pass


class LocalTestStorageFile(CloudStorageFile):
    def __init__(self, name: PurePosixPath, root: Path) -> None:
        super().__init__(name, None, None)
        self._root = root

    def _refresh(self) -> None:
        file_object = self._root / self.path
        self._modified = datetime.fromtimestamp(
            file_object.stat().st_mtime, timezone.utc
        )
        self._size = file_object.stat().st_size

    def download_to_file(self, dest: Path) -> None:
        copyfile(self._root / self.path, dest)

    def upload_from_file(self, src: Path, ignore_failure: bool = False) -> None:
        dest = self._root / self.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        copyfile(src, dest)

    def trunc(self) -> None:
        os.truncate(self._root / self.path, 0)

    def delete(self) -> None:
        (self._root / self.path).unlink()

    def exists(self) -> bool:
        return (self._root / self.path).is_file()


class LocalTestStorageProvider(CloudStorageProvider):
    def __init__(self, root: Path) -> None:
        super().__init__("")  # bucket_name -> don't care
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def iter(self, prefix: PurePosixPath):
        for f in self.iter_local():
            result = [
                a == b for a, b in zip(f.relative_to(self.root).parts, prefix.parts)
            ]
            if len(result) == len(prefix.parts) and all(result):
                yield LocalTestStorageFile(f.relative_to(self.root), self.root)

    def iter_local(self):
        for f in self.root.glob("**/*"):
            if f.is_file():
                yield f

    def iter_projects(self, prefix: str = ""):
        for f in self.root.glob("*"):
            if f.is_dir() and f.name.startswith(prefix):
                yield f.name

    def delete(self, files):
        for f in files:
            f.delete()

    def __getitem__(self, name: PurePosixPath):
        return LocalTestStorageFile(name, self.root)


@pytest.fixture(autouse=True)
def _patches(mocker, monkeypatch):
    executor = mocker.patch("guided_fuzzing_daemon.storage.Executor", autospec=True)
    obj = executor.return_value.__enter__.return_value

    def _fake_submit(func, *args, **kwds):
        return func(*args, **kwds)

    obj.submit.side_effect = _fake_submit

    mocker.patch("guided_fuzzing_daemon.stats.CPU_POLL_INTERVAL", 0)

    # Mocked AWS Credentials for boto3.
    mocker.patch("boto3.Session.get_credentials", return_value=None)
    mocker.patch("botocore.credentials.RefreshableCredentials", return_value=None)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(name="csp")
def mock_cloudstorageprovider():
    # This mock class can be used to test the abstract methods
    class MockProvider(CloudStorageProvider):
        def iter(self, prefix: PurePosixPath):
            pass

        def iter_projects(self, prefix: str = ""):
            pass

        def delete(self, files):
            pass

        def __getitem__(self, name: PurePosixPath):
            pass

    return MockProvider(bucket_name="test-bucket")


@pytest.fixture(name="gcs")
def mock_gcs(mocker):
    mock_client = mocker.patch("guided_fuzzing_daemon.storage.gcp_storage.Client")

    # Create a mock for the bucket and blob
    mock_blob = mocker.MagicMock()
    mock_blob.updated = datetime(2023, 8, 24)
    mock_bucket = mocker.MagicMock()
    mock_bucket.blob.return_value = mock_blob
    mock_client.return_value.bucket.return_value = mock_bucket

    storage = GoogleCloudStorage("test_bucket")
    storage.client = mock_client
    storage.bucket = mock_bucket
    return storage


@pytest.fixture(name="gcsfile")
def mock_gcs_file(gcs):
    return GCSFile(
        name=PurePosixPath("test_file.txt"), modified=None, size=None, _provider=gcs
    )


@pytest.fixture(name="stubber")
def mock_stubber(s3storage):
    with Stubber(s3storage.client) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


@pytest.fixture(name="s3file")
def mock_s3file(s3storage):
    mock_name = PurePosixPath("test_file.txt")
    return S3File(name=mock_name, modified=None, size=None, _provider=s3storage)


@pytest.fixture(name="s3storage")
def mock_s3storage():
    return S3Storage(bucket_name="test-bucket")


def _read_stats(path):
    stats = dict(
        [v.strip() for v in line.split(":", 1)]
        for line in path.read_text().splitlines()
    )
    assert stats.keys() == {
        "queue_files",
        "corpus_post",
        "corpus_pre",
        "cpu/load",
        "memory",
        "disk",
        "updated",
    }
    return stats


def test_cloudstorageprovider_01(csp, mocker):
    """test CloudStorageProvider.get_corpus_status()"""
    # Mock files that would be returned by the iter method
    mock_files = [
        mocker.Mock(spec=CloudStorageFile, modified=datetime(2023, 8, 24)),
        mocker.Mock(spec=CloudStorageFile, modified=datetime(2023, 8, 24)),
        mocker.Mock(spec=CloudStorageFile, modified=datetime(2023, 8, 23)),
    ]

    # Mock the iter method to return the above files
    mocker.patch.object(csp, "iter", return_value=mock_files)

    # Call the method under test
    status = csp.get_corpus_status("test_project")

    # Verify the result
    assert status == {
        "2023-08-24": 2,
        "2023-08-23": 1,
    }


def test_cloudstorageprovider_02(csp, mocker):
    """test CloudStorageProvider.get_queue_status()"""
    # Mock files with different queue names (part of their paths)
    mock_files = [
        mocker.Mock(
            spec=CloudStorageFile,
            path=PurePosixPath("test_project/queues/queue1/file1"),
        ),
        mocker.Mock(
            spec=CloudStorageFile,
            path=PurePosixPath("test_project/queues/queue1/file2"),
        ),
        mocker.Mock(
            spec=CloudStorageFile,
            path=PurePosixPath("test_project/queues/queue2/file1"),
        ),
    ]

    # Mock the iter method to return the above files
    mocker.patch.object(csp, "iter", return_value=mock_files)

    # Call the method under test
    status = csp.get_queue_status("test_project")

    # Verify the result
    assert status == {
        "queue1": 2,
        "queue2": 1,
    }


def test_context_raise(tmp_path):
    """refresh context raises, writes stats"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()
    # touch corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w"):
        pass

    refresh_dir = tmp_path / "refresh"
    queues_dir = refresh_dir / "queues"
    queues_dir.mkdir(parents=True)
    tests_dir = refresh_dir / "tests"
    tests_dir.mkdir()
    (tests_dir / "test").touch()

    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )

    with pytest.raises(_TestExc):
        with CorpusRefreshContext(opts, storage):
            raise _TestExc()

    assert set(queues_dir.iterdir()) == set()
    assert set(tests_dir.iterdir()) == set()
    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "0"
    assert stats["corpus_post"] == "0"
    assert stats["corpus_pre"] == "0"


def test_context_raise_during(mocker, tmp_path):
    """refresh context init raises, writes stats"""
    refresh_dir = tmp_path / "refresh"
    queues_dir = refresh_dir / "queues"
    tests_dir = refresh_dir / "tests"

    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    mocker.patch("guided_fuzzing_daemon.storage.CorpusSyncer", side_effect=_TestExc())

    with pytest.raises(_TestExc):
        with CorpusRefreshContext(opts, storage):
            raise _TestExc()

    assert set(queues_dir.iterdir()) == set()
    assert set(tests_dir.iterdir()) == set()
    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "0"
    assert stats["corpus_post"] == "0"
    assert stats["corpus_pre"] == "0"

    assert storage.method_calls == []


def test_context_no_refresh(tmp_path):
    """refresh context does nothing, exits 2"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()
    # touch corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w"):
        pass

    refresh_dir = tmp_path / "refresh"
    queues_dir = refresh_dir / "queues"
    tests_dir = refresh_dir / "tests"

    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )

    with CorpusRefreshContext(opts, storage) as ctx:
        pass

    assert ctx.exit_code == 2

    assert set(queues_dir.iterdir()) == set()
    assert set(tests_dir.iterdir()) == set()
    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "0"
    assert stats["corpus_post"] == "0"
    assert stats["corpus_pre"] == "0"


def test_context_refresh(tmp_path):
    """refresh context does refresh, exits 0"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()
    # create corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w") as zf:
        zf.writestr("a", b"")
    # create existing queues
    (storage.root / "t_proj" / "queues" / "queue1").mkdir(parents=True)
    (storage.root / "t_proj" / "queues" / "queue1" / "b").write_text("b")
    (storage.root / "t_proj" / "queues" / "queue1" / "c").write_text("c")
    with ZipFile(storage.root / "t_proj" / "queues" / "queue2.zip", "w") as zf:
        zf.writestr("d", b"")

    refresh_dir = tmp_path / "refresh"
    tests_dir = refresh_dir / "tests"

    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )

    with CorpusRefreshContext(opts, storage) as ctx:
        (tests_dir / "e").write_text("e")
        (tests_dir / "f").write_text("f")

    assert ctx.exit_code == 0

    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "3"
    assert stats["corpus_post"] == "2"
    assert stats["corpus_pre"] == "1"

    assert set(storage.iter_local()) == {
        storage.root / "t_proj" / "corpus" / "corpus.zip"
    }

    with ZipFile(storage.root / "t_proj" / "corpus" / "corpus.zip") as zf:
        assert set(zf.namelist()) == {"e", "f"}


def test_context_refresh_suffix(tmp_path):
    """refresh context only counts output suffix files"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()
    # create corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w") as zf:
        zf.writestr("a", b"")
    # create existing queues
    (storage.root / "t_proj" / "queues" / "queue1").mkdir(parents=True)
    (storage.root / "t_proj" / "queues" / "queue1" / "b.bin").write_text("b")
    (storage.root / "t_proj" / "queues" / "queue1" / "c.bin").write_text("c")
    with ZipFile(storage.root / "t_proj" / "queues" / "queue2.zip", "w") as zf:
        zf.writestr("d.txt", b"")

    refresh_dir = tmp_path / "refresh"
    tests_dir = refresh_dir / "tests"

    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )

    with CorpusRefreshContext(opts, storage, suffix=".txt") as ctx:
        (tests_dir / "e.txt").write_text("e")
        (tests_dir / "f.txt").write_text("f")
        (tests_dir / "g.bin").write_text("g")

    assert ctx.exit_code == 0

    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "3"
    assert stats["corpus_post"] == "2"
    assert stats["corpus_pre"] == "1"

    assert set(storage.iter_local()) == {
        storage.root / "t_proj" / "corpus" / "corpus.zip"
    }

    with ZipFile(storage.root / "t_proj" / "corpus" / "corpus.zip") as zf:
        assert set(zf.namelist()) == {"e.txt", "f.txt"}


def test_context_keyboard_interrupt(mocker, tmp_path):
    """test CorpusRefreshContext.__exit__ with KeyboardInterrupt"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()

    refresh_dir = tmp_path / "refresh"
    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )

    # Mock CorpusSyncer methods
    mock_upload_queue = mocker.spy(CorpusSyncer, "upload_queue")
    mock_delete_queues = mocker.patch(
        "guided_fuzzing_daemon.storage.CorpusSyncer.delete_queues"
    )
    mock_upload_corpus = mocker.spy(CorpusSyncer, "upload_corpus")

    # Test KeyboardInterrupt handling
    with pytest.raises(KeyboardInterrupt):
        with CorpusRefreshContext(opts, storage, separate_corpus=True) as merger:
            (merger.corpus_dir / "a.bin").touch()
            (merger.corpus_dir / "b.bin").touch()
            (merger.queues_dir / "c.bin").touch()
            (merger.queues_dir / "d.bin").touch()

            # Create some files in updated_tests_dir so upload methods get called
            (merger.updated_tests_dir / ".traces").mkdir(parents=True, exist_ok=True)
            # Only write 1 of 2 of the queue files to ensure pruning occurs
            for filename in ["a.bin", "b.bin", "c.bin"]:
                (merger.updated_tests_dir / filename).touch()
                (merger.updated_tests_dir / ".traces" / filename).touch()

            # Create hidden files (should be excluded from corpus_post count)
            (merger.updated_tests_dir / ".hidden_file").write_text("hidden")

            raise KeyboardInterrupt()

    # Verify corpus was created with the expected files and uploaded
    mock_upload_corpus.assert_called_once()
    corpus_zip_path = storage.root / "t_proj" / "corpus" / "corpus.zip"
    assert corpus_zip_path.exists()
    with ZipFile(corpus_zip_path) as zf:
        assert set(zf.namelist()) == {"a.bin", "b.bin", "c.bin"}

    # Verify queue methods were called
    mock_upload_queue.assert_called_once()
    assert set(mock_upload_queue.call_args[1]["skip_names"]) == {
        "a.bin",
        "b.bin",
        "c.bin",
    }

    # Verify queue zip was created with expected files (excluding skipped ones)
    queue_zip_name = mock_upload_queue.spy_return
    queue_zip_path = storage.root / "t_proj" / "queues" / queue_zip_name
    assert queue_zip_path.exists()
    with ZipFile(queue_zip_path) as zf:
        # Should contain d.bin (the only file not skipped from queues_dir)
        assert set(zf.namelist()) == {"d.bin"}

    mock_delete_queues.assert_called_once_with(
        skip_names=(mock_upload_queue.spy_return,)
    )

    # Verify that corpus_post excludes hidden files and directories
    stats = _read_stats(tmp_path / "stats")
    assert stats["corpus_post"] == "3"


def test_gcsfile_01(gcsfile):
    """test GCSFile.refresh()"""
    assert gcsfile._modified is None  # pylint: disable=protected-access
    assert gcsfile.modified == datetime(2023, 8, 24)


def test_gcsfile_02(gcs, gcsfile, mocker, tmp_path):
    """test GCSFile.download_to_file()"""
    # Mock the destination path and open method
    mock_blob = gcs.bucket.blob.return_value
    mock_dest = tmp_path / "downloaded_file.txt"
    mocker.patch("builtins.open", mocker.mock_open())

    # Call the download_to_file method and verify the blob's download_to_file is called
    gcsfile.download_to_file(mock_dest)
    mock_blob.download_to_file.assert_called_once()


def test_gcsfile_03(gcs, gcsfile, mocker, tmp_path):
    """test GCSFile.upload_from_file()"""
    # Mock the source path and open method
    mock_blob = gcs.bucket.blob.return_value
    mock_src = tmp_path / "source_file.txt"
    mock_src.touch()
    mocker.patch("builtins.open", mocker.mock_open())

    # Call the upload_from_file method and verify the blob's upload_from_file is called
    gcsfile.upload_from_file(mock_src)
    mock_blob.upload_from_file.assert_called_once()


def test_gcsfile_04(gcs, gcsfile, mocker):
    """test GCSFile.trunc()"""
    # Mock the blob's upload_from_string method
    mock_blob = gcs.bucket.blob.return_value

    # Call the trunc method and verify the blob's upload_from_string is called with an
    # empty string
    gcsfile.trunc()
    assert mock_blob.mock_calls == [mocker.call.upload_from_string(b"")]


def test_gcsfile_05(gcs, gcsfile, mocker):
    """test GCSFile.delete()"""
    # Mock the blob's delete method
    mock_blob = gcs.bucket.blob.return_value

    # Call the delete method and verify the blob's delete is called
    gcsfile.delete()
    assert mock_blob.mock_calls == [mocker.call.delete()]


def test_gcsfile_06(gcs, gcsfile, mocker):
    """test GCSFile.exists()"""
    # Mock the blob's exists method to return True
    mock_blob = gcs.bucket.blob.return_value
    mock_blob.exists.return_value = True

    # Call the exists method and verify it returns True
    assert gcsfile.exists() is True
    assert mock_blob.mock_calls == [mocker.call.exists()]


@pytest.mark.parametrize(
    "ignore", [pytest.param(True, id="ignore"), pytest.param(False, id="no-ignore")]
)
def test_gcsfile_07(gcsfile, tmp_path, ignore):
    """test GCSFile.upload_from_file() - missing file"""
    mock_src = tmp_path / "missing_file.txt"

    if ignore:
        gcsfile.upload_from_file(mock_src, ignore_failure=ignore)
    else:
        with pytest.raises(FileNotFoundError):
            gcsfile.upload_from_file(mock_src, ignore_failure=ignore)


def test_googlecloudstorage_01(gcs, mocker):
    """test GoogleCloudStorage.delete()"""
    mock_file = mocker.MagicMock(
        _provider=gcs,
        path=PurePosixPath("test_file.txt"),
        spec=GCSFile,
    )

    gcs.delete([mock_file])
    gcs.bucket.delete_blobs.assert_called_once()


def test_googlecloudstorage_02(gcs, mocker):
    """test GoogleCloudStorage.iter()"""
    mock_blob = mocker.MagicMock(updated=datetime(2023, 8, 23))
    mock_blob.name = "test_file.txt"
    gcs.bucket.list_blobs.return_value = [mock_blob]

    files = list(gcs.iter(PurePosixPath("prefix")))

    assert len(files) == 1
    assert isinstance(files[0], GCSFile)
    assert files[0].path == PurePosixPath("test_file.txt")


def test_googlecloudstorage_03(gcs, mocker):
    """test GoogleCloudStorage.iter_projects()"""
    # Create a mock for the iterator that `list_blobs` returns
    mock_blobs = mocker.MagicMock(prefixes=["project1/", "project2/"])

    # Simulate the return value of list_blobs to include `prefixes`
    gcs.bucket.list_blobs.return_value = mock_blobs

    # Call iter_projects and check the returned project prefixes
    projects = list(gcs.iter_projects("prefix"))

    assert len(projects) == 2
    assert projects == ["project1", "project2"]


def test_googlecloudstorage_04(gcs):
    """test GoogleCloudStorage.__getitem__()"""
    mock_name = PurePosixPath("test_file.txt")
    file = gcs[mock_name]

    assert isinstance(file, GCSFile)
    assert file.path == mock_name


def test_s3file_01(s3file, stubber):
    """test S3File.refresh()"""
    stubber.add_response(
        "head_object",
        {"LastModified": datetime(2023, 8, 24), "ContentLength": 446284},
        {"Bucket": "test-bucket", "Key": "test_file.txt"},
    )
    assert s3file._modified is None  # pylint: disable=protected-access
    assert s3file.modified == datetime(2023, 8, 24)


def test_s3file_02(s3file, stubber, tmp_path):
    """test S3File.download_to_file()"""
    # Stub the head_object call
    stubber.add_response(
        "head_object",
        {
            "LastModified": datetime(2023, 8, 24),
            "ContentLength": 123,
            "ETag": '"12345abcdef"',
            "ContentType": "text/plain",
        },
        {"Bucket": "test-bucket", "Key": "test_file.txt"},
    )

    # Stub the get_object call
    file_content = b"Hello, this is the file content."

    stubber.add_response(
        "get_object",
        {
            "Body": io.BytesIO(file_content),  # Use BytesIO to simulate file content
            "ContentLength": len(file_content),
            "LastModified": datetime(2023, 8, 24),
        },
        {"Bucket": "test-bucket", "Key": "test_file.txt"},
    )

    # Prepare the destination file path
    mock_dest = tmp_path / "downloaded_file.txt"

    # Run the download_to_file method
    s3file.download_to_file(mock_dest)

    # Verify that the file was downloaded with the correct content
    assert mock_dest.exists()
    assert mock_dest.read_bytes() == file_content


def test_s3file_03(s3file, stubber, tmp_path):
    """test S3File.upload_from_file()"""
    mock_src = tmp_path / "source_file.txt"
    mock_src.write_text("dummy data")  # Write some dummy data to the file

    # Stub the response for the put_object call without checking the Body parameter
    stubber.add_response(
        "put_object",
        {},
        {
            # We don't strictly match the Body since boto3 wraps it in ReadFileChunk
            "Body": ANY,
            "Bucket": "test-bucket",
            "ChecksumAlgorithm": "CRC32",
            "Key": "test_file.txt",
        },
    )

    s3file.upload_from_file(mock_src)

    # Verify the file exists (although we do not validate the upload content here)
    assert mock_src.exists()


def test_s3file_04(s3file, stubber):
    """test S3File.trunc()"""
    stubber.add_response(
        "put_object", {}, {"Bucket": "test-bucket", "Key": "test_file.txt", "Body": b""}
    )
    s3file.trunc()


def test_s3file_05(s3file, stubber):
    """test S3File.delete()"""
    stubber.add_response(
        "delete_object", {}, {"Bucket": "test-bucket", "Key": "test_file.txt"}
    )
    s3file.delete()


def test_s3file_06(s3file, stubber):
    """test S3File.exists()"""
    stubber.add_response(
        "head_object", {}, {"Bucket": "test-bucket", "Key": "test_file.txt"}
    )
    assert s3file.exists()


def test_s3file_07(s3file, stubber):
    """test S3File.exists() -> 404"""
    stubber.add_client_error(
        "head_object",
        expected_params={"Bucket": "test-bucket", "Key": "test_file.txt"},
        service_error_code="404",
        service_message="Not Found",
    )
    assert not s3file.exists()


@pytest.mark.parametrize(
    "ignore", [pytest.param(True, id="ignore"), pytest.param(False, id="no-ignore")]
)
def test_s3file_08(s3file, tmp_path, ignore):
    """test S3File.upload_from_file() - missing file"""
    mock_src = tmp_path / "missing_file.txt"

    if ignore:
        s3file.upload_from_file(mock_src, ignore_failure=ignore)
    else:
        with pytest.raises(FileNotFoundError):
            s3file.upload_from_file(mock_src, ignore_failure=ignore)


def test_s3storage_01(s3storage, stubber):
    """test S3Storage.delete()"""
    stubber.add_response(
        "delete_objects",
        {},
        {
            "Bucket": "test-bucket",
            "Delete": {
                "Objects": ({"Key": "test_file1.txt"}, {"Key": "test_file2.txt"}),
                "Quiet": True,
            },
        },
    )

    s3storage.delete(
        [
            S3File(
                name=PurePosixPath("test_file1.txt"),
                modified=None,
                size=None,
                _provider=s3storage,
            ),
            S3File(
                name=PurePosixPath("test_file2.txt"),
                modified=None,
                size=None,
                _provider=s3storage,
            ),
        ]
    )


def test_s3storage_02(s3storage, stubber):
    """test S3Storage.iter()"""
    stubber.add_response(
        "list_objects_v2",
        {
            "Contents": [
                {
                    "Size": 446284,
                    "Key": "prefix/test_file1.txt",
                    "LastModified": datetime(2023, 8, 23),
                },
            ],
            "IsTruncated": True,
            "NextContinuationToken": "token123",
        },
        {"Bucket": "test-bucket", "Prefix": "prefix/"},
    )
    stubber.add_response(
        "list_objects_v2",
        {
            "Contents": [
                {
                    "Size": 446284,
                    "Key": "prefix/test_file2.txt",
                    "LastModified": datetime(2023, 8, 24),
                },
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": "test-bucket",
            "Prefix": "prefix/",
            "ContinuationToken": "token123",
        },
    )
    files = list(s3storage.iter(PurePosixPath("prefix")))

    assert len(files) == 2
    assert isinstance(files[0], S3File)
    assert files[0].path == PurePosixPath("prefix/test_file1.txt")
    assert files[1].path == PurePosixPath("prefix/test_file2.txt")


def test_s3storage_03(s3storage, stubber):
    """test S3Storage.iter_projects()"""
    stubber.add_response(
        "list_objects_v2",
        {
            "CommonPrefixes": [
                {"Prefix": "project1/"},
            ],
            "IsTruncated": True,
            "NextContinuationToken": "token123",
        },
        {"Bucket": "test-bucket", "Prefix": "", "Delimiter": "/"},
    )
    stubber.add_response(
        "list_objects_v2",
        {
            "CommonPrefixes": [
                {"Prefix": "project2/"},
            ],
            "IsTruncated": False,
        },
        {
            "Bucket": "test-bucket",
            "Prefix": "",
            "Delimiter": "/",
            "ContinuationToken": "token123",
        },
    )
    projects = list(s3storage.iter_projects())

    assert len(projects) == 2
    assert projects == ["project1", "project2"]


def test_s3storage_04(s3storage):
    """test S3Storage.__getitem__()"""
    file = s3storage[PurePosixPath("test_file.txt")]

    assert isinstance(file, S3File)
    assert file.path == PurePosixPath("test_file.txt")


def test_syncer_download_corpus(tmp_path):
    """test download_corpus()"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj" / "corpus").mkdir(parents=True)
    # create corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w") as zf:
        zf.writestr("a", b"a")
        zf.writestr("b", b"b")
    (storage.root / "t_proj" / "corpus" / "c").write_text("c")

    out_path = tmp_path / "out"
    out_path.mkdir()
    corpus = Corpus(out_path)
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    assert syncer.download_resource(ResourceType.CORPUS) == 3
    assert (out_path / "a").is_file()
    assert (out_path / "b").is_file()
    assert (out_path / "c").is_file()


def test_syncer_upload_corpus(tmp_path):
    """test upload_corpus()"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj" / "corpus").mkdir(parents=True)
    # create corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w"):
        pass
    (storage.root / "t_proj" / "corpus" / "file1").touch()

    in_path = tmp_path / "in"
    in_path.mkdir()
    corpus = Corpus(in_path)
    (in_path / "c").write_text("c")
    (in_path / "d").write_text("d")
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.upload_corpus()

    assert set(storage.iter_local()) == {
        storage.root / "t_proj" / "corpus" / "corpus.zip"
    }
    out_path = tmp_path / "out"
    with ZipFile(storage.root / "t_proj" / "corpus" / "corpus.zip") as zf:
        assert set(zf.namelist()) == {"c", "d"}
        zf.extractall(out_path)
    assert (out_path / "c").read_text() == "c"
    assert (out_path / "d").read_text() == "d"


def test_syncer_upload_corpus_empty(tmp_path):
    """test upload_corpus() doesn't delete existing corpus if empty result given"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj" / "corpus").mkdir(parents=True)
    # create corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w") as zf:
        zf.writestr("a", b"")
    (storage.root / "t_proj" / "corpus" / "file1").touch()

    in_path = tmp_path / "in"
    in_path.mkdir()
    corpus = Corpus(in_path)
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.upload_corpus()

    assert set(storage.iter_local()) == {
        storage.root / "t_proj" / "corpus.zip",
        storage.root / "t_proj" / "corpus" / "file1",
    }
    with ZipFile(storage.root / "t_proj" / "corpus.zip") as zf:
        assert set(zf.namelist()) == {"a"}


def test_syncer_upload_corpus_suffix(tmp_path):
    """test upload_corpus() only uploads given suffix"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj" / "corpus").mkdir(parents=True)
    # create corpus.zip
    with ZipFile(storage.root / "t_proj" / "corpus.zip", "w"):
        pass
    (storage.root / "t_proj" / "corpus" / "file1").touch()

    in_path = tmp_path / "in"
    in_path.mkdir()
    corpus = Corpus(in_path)
    (in_path / "c.txt").write_text("c")
    (in_path / "d.bin").write_text("d")
    syncer = CorpusSyncer(storage, corpus, "t_proj", ".bin")
    syncer.upload_corpus()

    assert set(storage.iter_local()) == {
        storage.root / "t_proj" / "corpus" / "corpus.zip"
    }
    out_path = tmp_path / "out"
    with ZipFile(storage.root / "t_proj" / "corpus" / "corpus.zip") as zf:
        assert set(zf.namelist()) == {"d.bin"}
        zf.extractall(out_path)
    assert (out_path / "d.bin").read_text() == "d"


@pytest.mark.parametrize("skip_names", ([], ["d"]))
def test_syncer_upload_queue(skip_names, tmp_path):
    """test upload_queue()"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()

    in_path = tmp_path / "in"
    corpus = Corpus(in_path)
    in_path.mkdir()
    (in_path / "a").write_text("a")
    (in_path / "b").write_text("b")
    (in_path / "c").write_text("c")
    (in_path / "d").write_text("d")
    (in_path / "e").mkdir()  # directory -> ignored
    (in_path / "e" / "f").touch()

    syncer = CorpusSyncer(storage, corpus, "t_proj")
    result = syncer.upload_queue(skip_names=skip_names)

    # Test that upload_queue returns the zip filename
    assert result == f"{corpus.uuid}.zip"

    out_path = tmp_path / "out"

    expected_paths = {out_path / "a", out_path / "b", out_path / "c"}
    if not skip_names:
        expected_paths.add(out_path / "d")

    # Verify zip file contents
    assert (storage.root / "t_proj" / "queues" / f"{corpus.uuid}.zip").is_file()
    with ZipFile(storage.root / "t_proj" / "queues" / f"{corpus.uuid}.zip") as zf:
        zf.extractall(out_path)
    assert set(out_path.glob("**/*")) == expected_paths
    for p in expected_paths:
        assert p.read_text() == p.name


def test_syncer_upload_queue_suffix(tmp_path):
    """test upload_queue() only uploads given suffix"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()

    in_path = tmp_path / "in"
    corpus = Corpus(in_path)
    in_path.mkdir()
    (in_path / "a.txt").write_text("a")
    (in_path / "b.bin").write_text("b")

    syncer = CorpusSyncer(storage, corpus, "t_proj", ".bin")
    syncer.upload_queue(skip_names=[])

    out_path = tmp_path / "out"

    expected_paths = {out_path / "b.bin"}

    # Verify zip file contents
    assert (storage.root / "t_proj" / "queues" / f"{corpus.uuid}.zip").is_file()
    with ZipFile(storage.root / "t_proj" / "queues" / f"{corpus.uuid}.zip") as zf:
        zf.extractall(out_path)
    assert set(out_path.glob("**/*")) == expected_paths
    for p in expected_paths:
        assert p.read_text() == p.stem


def test_syncer_delete_queues(tmp_path):
    """test delete_queues()"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj" / "queues" / "queue1").mkdir(parents=True)
    (storage.root / "t_proj" / "queues" / "queue1" / "a").touch()
    with ZipFile(storage.root / "t_proj" / "queues" / "old_queue.zip", "w"):
        pass
    with ZipFile(storage.root / "t_proj" / "queues" / "replacement_queue.zip", "w"):
        pass

    corpus = Corpus(tmp_path)
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.delete_queues(skip_names=["replacement_queue.zip"])

    # Only the skipped file should remain
    remaining_files = list(storage.iter_local())
    assert len(remaining_files) == 1
    assert (
        remaining_files[0]
        == storage.root / "t_proj" / "queues" / "replacement_queue.zip"
    )


def test_syncer_download_queues(tmp_path):
    """test download_queues()"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    # pre-zip queue
    (storage.root / "t_proj" / "queues" / "queue1").mkdir(parents=True)
    (storage.root / "t_proj" / "queues" / "queue1" / "a").write_text("a")
    # new location of queue.zip
    with ZipFile(storage.root / "t_proj" / "queues" / "queue2.zip", "w") as zf:
        zf.writestr("b", b"b")
        zf.writestr("c", b"c")
    # old location of queue.zip
    (storage.root / "t_proj" / "queues" / "queue3").mkdir()
    with ZipFile(
        storage.root / "t_proj" / "queues" / "queue3" / "queue3.zip", "w"
    ) as zf:
        zf.writestr("c", b"c")
        zf.writestr("d", b"d")
    out_path = tmp_path / "out"
    out_path.mkdir()
    corpus = Corpus(out_path)

    syncer = CorpusSyncer(storage, corpus, "t_proj")
    result = syncer.download_resource(ResourceType.QUEUE)
    assert result == 5

    assert set(out_path.glob("**/*")) == {
        out_path / "a",
        out_path / "b",
        out_path / "c",
        out_path / "d",
    }


@pytest.mark.parametrize("skip_names", ([], ["d"]))
def test_syncer_upload_queue_extras(skip_names, tmp_path):
    """test upload_queue() with extras"""
    storage = LocalTestStorageProvider(tmp_path / "cloud")
    (storage.root / "t_proj").mkdir()

    # create a queue with 4 files, 1 of which might be skipped by skip_names
    q1 = tmp_path / "in1"
    q1.mkdir()
    corpus = Corpus(q1)
    (q1 / "a").write_text("a")
    (q1 / "b").write_text("b")
    (q1 / "c").write_text("c")
    (q1 / "d").write_text("d")
    # second queue contains 2 files, 1 of which already exists in the first
    q2 = tmp_path / "in2"
    q2.mkdir()
    (q2 / "d").write_text("d")
    (q2 / "e").write_text("e")
    # third queue contains 1 unique file, to show that all queues are uploaded
    q3 = tmp_path / "in3"
    q3.mkdir()
    (q3 / "f").write_text("f")
    # non-existent extra queue is skipped
    q4 = tmp_path / "in4"

    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.extra_queues.extend((Corpus(q2), Corpus(q3), Corpus(q4)))
    syncer.upload_queue(skip_names=skip_names)

    out_path = tmp_path / "out"

    expected_paths = {
        out_path / "a",
        out_path / "b",
        out_path / "c",
        out_path / "e",
        out_path / "f",
    }
    if not skip_names:
        expected_paths.add(out_path / "d")

    # Verify zip file contents
    assert (storage.root / "t_proj" / "queues" / f"{corpus.uuid}.zip").is_file()
    with ZipFile(storage.root / "t_proj" / "queues" / f"{corpus.uuid}.zip") as zf:
        zf.extractall(out_path)
    assert set(out_path.glob("**/*")) == expected_paths
    for p in expected_paths:
        assert p.read_text() == p.name
