# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from guided_fuzzing_daemon.main import main

S3_ARGS = {
    "s3_build_download",
    "s3_build_upload",
    "s3_corpus_download",
    "s3_corpus_refresh",
    "s3_corpus_status",
    "s3_corpus_upload",
    "s3_list_projects",
    "s3_queue_cleanup",
    "s3_queue_status",
}


@pytest.mark.parametrize("arg", S3_ARGS)
def test_main_01(mocker, arg):
    """s3 main is called"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Manager")
    mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main")
    mocker.patch("guided_fuzzing_daemon.main.nyx_main")
    s3_main_mock = mocker.patch("guided_fuzzing_daemon.main.s3_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, False)
    setattr(args_mock.return_value, arg, True)
    main()
    assert s3_main_mock.called


def test_main_02(capsys, mocker):
    """unhandled main"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Manager")
    mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main")
    mocker.patch("guided_fuzzing_daemon.main.nyx_main")
    mocker.patch("guided_fuzzing_daemon.main.s3_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, False)
    args_mock.return_value.fuzzmanager = False
    assert main() == 2
    stdio = capsys.readouterr()
    assert "Unhandled case" in stdio.err


@pytest.mark.parametrize("mode", ("libfuzzer", "nyx"))
def test_main_03(mode, mocker):
    """fuzzer modes"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Manager")
    mocks = {
        "libfuzzer": mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main"),
        "nyx": mocker.patch("guided_fuzzing_daemon.main.nyx_main"),
    }
    mocker.patch("guided_fuzzing_daemon.main.s3_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, False)
    args_mock.return_value.fuzzmanager = False
    args_mock.return_value.mode = mode
    main()
    assert mocks[mode].called


def test_main_04(mocker, tmp_path):
    """FuzzManager args"""
    args_mock = mocker.patch("guided_fuzzing_daemon.main.parse_args")
    collector_mock = mocker.patch("guided_fuzzing_daemon.main.Collector")
    mocker.patch("guided_fuzzing_daemon.main.S3Manager")
    mocker.patch("guided_fuzzing_daemon.main.libfuzzer_main")
    mocker.patch("guided_fuzzing_daemon.main.nyx_main")
    mocker.patch("guided_fuzzing_daemon.main.s3_main")
    for s3_arg in S3_ARGS:
        setattr(args_mock.return_value, s3_arg, False)
    auth_token = tmp_path / "token"
    auth_token.write_text("token-val")
    args_mock.return_value.serverauthtokenfile = str(auth_token)
    main()
    assert collector_mock.called
