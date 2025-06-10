# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import io
import sys
import zipfile
from argparse import Namespace
from datetime import datetime
from pathlib import PurePosixPath

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
    S3File,
    S3Storage,
)

if sys.version_info[:2] < (3, 12):
    from guided_fuzzing_daemon.utils import batched
else:
    from itertools import batched


class _TestExc(Exception):
    pass


@pytest.fixture(autouse=True)
def _patches(mocker, monkeypatch):
    executor = mocker.patch("guided_fuzzing_daemon.storage.Executor", autospec=True)
    obj = executor.return_value.__enter__.return_value

    def _fake_submit(func, *args, **kwds):
        return func(*args, **kwds)

    obj.submit.side_effect = _fake_submit

    sample = mocker.patch("guided_fuzzing_daemon.storage.sample", autospec=True)

    def _fake_sample(iterable, count):
        return iterable[:count]

    sample.side_effect = _fake_sample

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
    return GCSFile(name=PurePosixPath("test_file.txt"), modified=None, _provider=gcs)


@pytest.fixture(name="stubber")
def mock_stubber(s3storage):
    with Stubber(s3storage.client) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


@pytest.fixture(name="s3file")
def mock_s3file(s3storage):
    mock_name = PurePosixPath("test_file.txt")
    return S3File(name=mock_name, modified=None, _provider=s3storage)


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


def test_context_01(mocker, tmp_path):
    """refresh context raises, writes stats"""
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
    storage = mocker.MagicMock(spec=CloudStorageProvider)

    with pytest.raises(_TestExc):
        with CorpusRefreshContext(opts, storage):
            raise _TestExc()

    assert set(queues_dir.iterdir()) == set()
    assert set(tests_dir.iterdir()) == set()
    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "0"
    assert stats["corpus_post"] == "0"
    assert stats["corpus_pre"] == "0"

    assert storage.method_calls == [
        mocker.call.iter(PurePosixPath("t_proj/corpus")),
        mocker.call.iter(PurePosixPath("t_proj/queues")),
    ]


def test_context_02(mocker, tmp_path):
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


def test_context_03(mocker, tmp_path):
    """refresh context does nothing, exits 2"""
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

    with CorpusRefreshContext(opts, storage) as ctx:
        pass

    assert ctx.exit_code == 2

    assert set(queues_dir.iterdir()) == set()
    assert set(tests_dir.iterdir()) == set()
    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "0"
    assert stats["corpus_post"] == "0"
    assert stats["corpus_pre"] == "0"

    assert storage.method_calls == [
        mocker.call.iter(PurePosixPath("t_proj/corpus")),
        mocker.call.iter(PurePosixPath("t_proj/queues")),
    ]


def test_context_04(mocker, tmp_path):
    """refresh context does refresh, exits 0"""
    refresh_dir = tmp_path / "refresh"
    queues_dir = refresh_dir / "queues"
    queue_dir = queues_dir / "queue1"
    queue_dir.mkdir(parents=True)
    tests_dir = refresh_dir / "tests"
    (queue_dir / "61").write_text("a")
    (queue_dir / "62").write_text("b")

    opts = Namespace(
        bucket="t_bucket",
        corpus_refresh=refresh_dir,
        project="t_proj",
        provider="s3",
        stats=tmp_path / "stats",
    )
    storage = mocker.MagicMock(spec=CloudStorageProvider)

    queue_good = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath("t_proj/queues/queue1/61")
    )
    queue_bad = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath("t_proj/queues/queue1/62")
    )
    corp_bad = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/62")
    )

    def _fake_iter(prefix):
        if prefix.name == "queues":
            return [queue_good, queue_bad]
        return [corp_bad]

    storage.iter.side_effect = _fake_iter

    with CorpusRefreshContext(opts, storage) as ctx:
        (tests_dir / "61").write_text("a")

    assert ctx.exit_code == 0

    assert set(tests_dir.iterdir()) == {tests_dir / "61"}
    assert set(f for f in queues_dir.glob("**/*") if f.is_file()) == {
        queue_dir / "61",
        queue_dir / "62",
    }
    stats = _read_stats(tmp_path / "stats")
    assert stats["queue_files"] == "2"
    assert stats["corpus_post"] == "1"
    assert stats["corpus_pre"] == "1"

    assert storage.method_calls == [
        mocker.call.iter(PurePosixPath("t_proj/corpus")),
        mocker.call.iter(PurePosixPath("t_proj/queues")),
        mocker.call.iter(PurePosixPath("t_proj/corpus")),
        mocker.call.delete((corp_bad,)),
        mocker.call.iter(PurePosixPath("t_proj/queues")),
        mocker.call.delete((queue_good, queue_bad)),
    ]


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
        {"LastModified": datetime(2023, 8, 24)},
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
                _provider=s3storage,
            ),
            S3File(
                name=PurePosixPath("test_file2.txt"),
                modified=None,
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
                {"Key": "prefix/test_file1.txt", "LastModified": datetime(2023, 8, 23)},
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
                {"Key": "prefix/test_file2.txt", "LastModified": datetime(2023, 8, 24)},
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


def test_syncer_01(mocker, tmp_path):
    """test download_corpus()"""
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    corpus = Corpus(tmp_path)
    f1 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/file1"))
    f2 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/file2"))
    storage.iter.side_effect = [(f1, f2)]
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    assert syncer.download_corpus() == 2
    assert f1.method_calls == [mocker.call.download_to_file(tmp_path / "file1")]
    assert f2.method_calls == [mocker.call.download_to_file(tmp_path / "file2")]


def test_syncer_02(mocker, tmp_path):
    """test download_corpus(random subset)"""
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    corpus = Corpus(tmp_path)
    f1 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/file1"))
    f2 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/file2"))
    f3 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/file3"))
    storage.iter.side_effect = [(f1, f2, f3)]
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    assert syncer.download_corpus(1) == 1

    assert f1.method_calls == [mocker.call.download_to_file(tmp_path / "file1")]
    assert f2.method_calls == []
    assert f3.method_calls == []


def test_syncer_03(mocker, tmp_path):
    """test upload_corpus()"""
    # pylint: disable=unnecessary-dunder-call
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    corpus = Corpus(tmp_path)
    (tmp_path / "62").write_text("b")
    l3 = tmp_path / "63"
    l3.write_text("c")
    l4 = tmp_path / "64"
    l4.write_text("d")
    f1 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/61"))
    f2 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/corpus/62"))
    storage.iter.side_effect = [(f1, f2)]
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.upload_corpus()
    assert storage.mock_calls.pop(0) == mocker.call.iter(PurePosixPath("t_proj/corpus"))
    assert storage.mock_calls.pop() == mocker.call.delete((f1,))

    expected_paths = {
        PurePosixPath("t_proj/corpus/63"): l3,
        PurePosixPath("t_proj/corpus/64"): l4,
    }

    # after `iter`/`delete`, there should be an even number of calls:
    # - get the remote object by path
    # - upload from the corresponding local path
    assert len(storage.mock_calls) % 2 == 0
    # batched will return the calls in chunks of 2
    for item_call, upload_call in batched(storage.mock_calls, 2):
        remote_path = item_call.args[0]
        assert remote_path in expected_paths
        local_path = expected_paths.pop(remote_path)
        assert item_call == mocker.call.__getitem__(remote_path)
        assert upload_call == mocker.call.__getitem__().upload_from_file(local_path)
    # all should have been consumed
    assert not expected_paths


@pytest.mark.parametrize("skip_names", ([], ["64"]))
def test_syncer_04(mocker, skip_names, tmp_path):
    """test upload_queue()"""
    # pylint: disable=unnecessary-dunder-call
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    corpus = Corpus(tmp_path)
    (tmp_path / "61").write_text("a")
    l2 = tmp_path / "62"
    l2.write_text("b")
    l3 = tmp_path / "63"
    l3.write_text("c")
    l4 = tmp_path / "64"
    l4.write_text("d")
    f1 = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath(f"t_proj/queues/{corpus.uuid}/61")
    )
    storage.iter.side_effect = [(f1,)]

    # Create separate path for building the zipfile
    (work_dir := tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    mocker.patch("guided_fuzzing_daemon.utils.mkdtemp", return_value=str(work_dir))

    # Prevent cleaning the tmpdir
    mocker.patch("guided_fuzzing_daemon.utils.rmtree")

    zip_name = f"{corpus.uuid}.zip"
    zip_path = work_dir / zip_name

    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.upload_queue(skip_names=skip_names)

    assert storage.mock_calls.pop(0) == mocker.call.iter(PurePosixPath("t_proj/queues"))

    assert storage.__getitem__.call_count == 1
    remote_path = PurePosixPath(f"t_proj/queues/{zip_name}")
    assert storage.__getitem__.call_args == mocker.call.__getitem__(remote_path)

    expected_paths = {
        PurePosixPath(f"t_proj/queues/{corpus.uuid}/62"): l2,
        PurePosixPath(f"t_proj/queues/{corpus.uuid}/63"): l3,
    }
    if not skip_names:
        expected_paths[PurePosixPath(f"t_proj/queues/{corpus.uuid}/64")] = l4

    # Verify zip file contents
    assert zip_path.exists()

    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_contents = set(zf.namelist())

    assert zip_contents == {p.name for p in expected_paths.values()}


def test_syncer_05(mocker, tmp_path):
    """test delete_queues()"""
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    corpus = Corpus(tmp_path)
    f1 = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath(f"t_proj/queues/{corpus.uuid}/61")
    )
    f2 = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath(f"t_proj/queues/{corpus.uuid}/62")
    )
    storage.iter.side_effect = [(f1, f2)]
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.delete_queues()
    assert storage.mock_calls == [
        mocker.call.iter(PurePosixPath("t_proj/queues")),
        mocker.call.delete((f1, f2)),
    ]


def test_syncer_06(mocker, tmp_path):
    """test download_queues()"""
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    corpus = Corpus(tmp_path)
    (tmp_path / "61").write_text("a")

    def _write_path(dest):
        dest.touch()

    # Regular files
    f1 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/queues/a/61"))
    f1.download_to_file.side_effect = _write_path
    f2 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/queues/a/62"))
    f2.download_to_file.side_effect = _write_path
    # Duplicate in the queue
    f3 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/queues/b/62"))
    f3.download_to_file.side_effect = _write_path
    f4 = mocker.Mock(spec=CloudStorageFile, path=PurePosixPath("t_proj/queues/b/63"))
    f4.download_to_file.side_effect = _write_path

    # Mock ZIP file
    zip_path = PurePosixPath("t_proj/queues/b/b.zip")
    f5 = mocker.Mock(spec=CloudStorageFile, path=zip_path)

    def _write_zip(dest):
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            (tmp_path / "64").write_text("a")  # New queue entry
            (tmp_path / "62").write_text("a")  # Duplicate queue entry
            zf.write(tmp_path / "64", arcname="64")
            zf.write(tmp_path / "62", arcname="62")

    f5.download_to_file.side_effect = _write_zip

    storage.iter.side_effect = [(f1, f2, f3, f4, f5)]
    syncer = CorpusSyncer(storage, corpus, "t_proj")
    result = syncer.download_queues()
    assert storage.mock_calls == [mocker.call.iter(PurePosixPath("t_proj/queues"))]
    assert f1.mock_calls == []
    assert f2.mock_calls == [mocker.call.download_to_file(tmp_path / "62")]
    assert f3.mock_calls == []
    assert f4.mock_calls == [mocker.call.download_to_file(tmp_path / "63")]

    assert f5.download_to_file.call_count == 1

    # Counts file total and in the case of a zip, the file count within the archive
    assert result == {"a": 2, "b": 4}
    assert {f.name for f in tmp_path.iterdir()} == {"61", "62", "63", "64"}


@pytest.mark.parametrize("skip_names", ([], ["64"]))
def test_syncer_07(mocker, skip_names, tmp_path):
    """test upload_queue() with extras"""
    # pylint: disable=unnecessary-dunder-call
    storage = mocker.MagicMock(spec=CloudStorageProvider)
    # create a queue with 4 files, 1 of which might be skipped by skip_names
    q1 = tmp_path / "1"
    q1.mkdir()
    corpus = Corpus(q1)
    (q1 / "61").write_text("a")
    l2 = q1 / "62"
    l2.write_text("b")
    l3 = q1 / "63"
    l3.write_text("c")
    l4 = q1 / "64"
    l4.write_text("d")
    # second queue contains 2 files, 1 of which exists in the first (never uploaded)
    q2 = tmp_path / "2"
    q2.mkdir()
    (q2 / "64").write_text("d")
    l5 = q2 / "65"
    l5.write_text("e")
    # third queue contains 1 unique file, to show that all queues are uploaded
    q3 = tmp_path / "3"
    q3.mkdir()
    l6 = q3 / "66"
    l6.write_text("f")
    f1 = mocker.Mock(
        spec=CloudStorageFile, path=PurePosixPath(f"t_proj/queues/{corpus.uuid}/61")
    )
    storage.iter.side_effect = [(f1,)]

    # Patch mkdtemp to ensure zip file is created inside tmp_path
    mocker.patch("guided_fuzzing_daemon.utils.mkdtemp", return_value=str(tmp_path))

    # Prevent cleaning the tmpdir
    mocker.patch("guided_fuzzing_daemon.utils.rmtree")

    # Prevent the zip file from being deleted before checking contents
    mocker.patch("guided_fuzzing_daemon.storage.Path.unlink", autospec=True)

    # Expected ZIP file path
    zip_name = f"{corpus.uuid}.zip"
    zip_path = tmp_path / zip_name

    syncer = CorpusSyncer(storage, corpus, "t_proj")
    syncer.extra_queues.extend((Corpus(q2), Corpus(q3)))
    syncer.upload_queue(skip_names=skip_names)

    assert storage.mock_calls.pop(0) == mocker.call.iter(
        PurePosixPath("t_proj/queues") / corpus.uuid
    )
    # Ensure only one upload happens (the ZIP file)
    assert storage.__getitem__.call_count == 1
    remote_path = PurePosixPath(f"t_proj/queues/{zip_name}")
    assert storage.__getitem__.call_args == mocker.call.__getitem__(remote_path)
    assert (
        storage.__getitem__().upload_from_file.call_args
        == mocker.call.upload_from_file(zip_path, True)
    )

    # Define expected file paths in the ZIP archive
    expected_paths = {
        "62": l2,
        "63": l3,
        "65": l5,
        "66": l6,
    }
    if not skip_names:
        expected_paths["64"] = l4

    # Ensure the ZIP file exists and contains the correct files
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_contents = set(zf.namelist())

    assert zip_contents == set(expected_paths.keys())

    # Ensure the ZIP file is deleted after verification
    zip_path.unlink(missing_ok=True)
