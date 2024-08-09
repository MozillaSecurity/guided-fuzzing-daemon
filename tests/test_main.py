# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from guided_fuzzing_daemon.main import main

S3_ARGS = frozenset(
    (
        "corpus_download",
        "corpus_status",
        "corpus_upload",
        "list_projects",
        "queue_status",
    )
)


@pytest.mark.parametrize("arg", S3_ARGS)
def test_main_01(arg, mocker, tmp_path):
    """storage functions are called"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    args_mock.return_value.provider = "S3"
    mocker.patch("guided_fuzzing_daemon.main.Collector")
    syncer = mocker.patch("guided_fuzzing_daemon.main.CorpusSyncer").return_value
    storage = mocker.patch("guided_fuzzing_daemon.main.S3Storage").return_value
    # return non-empty data to cover the status accumulation loops in main()
    storage.get_corpus_status.return_value = {"dt": 1}
    storage.get_queue_status.return_value = {"dt": 1}
    storage.iter_projects.return_value = ["proj"]
    mocker.patch("guided_fuzzing_daemon.main.afl_main")
    mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main")
    mocker.patch("guided_fuzzing_daemon.main.nyx_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, None)
    setattr(args_mock.return_value, arg, tmp_path)

    main()
    if arg == "corpus_download":
        assert syncer.download_corpus.called
    elif arg == "corpus_status":
        assert storage.get_corpus_status.called
    elif arg == "corpus_upload":
        assert syncer.upload_corpus.called
    elif arg == "list_projects":
        assert storage.iter_projects.called
    elif arg == "queue_status":
        assert storage.get_queue_status.called


def test_main_02(caplog, mocker):
    """unhandled main"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    args_mock.return_value.provider = "S3"
    mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Storage")
    mocker.patch("guided_fuzzing_daemon.main.afl_main")
    mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main")
    mocker.patch("guided_fuzzing_daemon.main.nyx_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, None)
    args_mock.return_value.fuzzmanager = False
    assert main() == 2
    assert any("Unhandled case" in record.message for record in caplog.records)


@pytest.mark.parametrize("mode", ("afl", "libfuzzer", "nyx"))
def test_main_03(mocker, mode):
    """fuzzer modes"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    args_mock.return_value.provider = "S3"
    mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Storage")
    mocks = {
        "afl": mocker.patch("guided_fuzzing_daemon.main.afl_main"),
        "libfuzzer": mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main"),
        "nyx": mocker.patch("guided_fuzzing_daemon.main.nyx_main"),
    }
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, None)
    args_mock.return_value.fuzzmanager = False
    args_mock.return_value.mode = mode
    main()
    assert mocks[mode].called


def test_main_04(mocker, tmp_path):
    """FuzzManager args"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    args_mock.return_value.provider = "S3"
    collector_mock = mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Storage")
    mocker.patch("guided_fuzzing_daemon.main.afl_main")
    mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main")
    mocker.patch("guided_fuzzing_daemon.main.nyx_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, None)
    auth_token = tmp_path / "token"
    auth_token.write_text("token-val")
    args_mock.return_value.serverauthtokenfile = str(auth_token)
    main()
    assert collector_mock.called
