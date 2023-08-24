# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from guided_fuzzing_daemon.s3 import s3_main

S3_ACTIONS = {
    "s3_build_download": "download_build",
    "s3_build_upload": "upload_build",
    "s3_corpus_download": "download_corpus",
    "s3_corpus_status": "get_corpus_status",
    "s3_corpus_upload": "upload_corpus",
    "s3_queue_cleanup": "clean_queue_dirs",
    "s3_queue_status": "get_queue_status",
    # "s3_corpus_refresh",
}


@pytest.mark.parametrize("arg, method", S3_ACTIONS.items())
def test_s3_main_01(mocker, arg, method):
    """simple s3 main test"""
    mgr = mocker.patch("guided_fuzzing_daemon.s3.S3Manager")
    args = mocker.Mock()
    args.s3_corpus_refresh = None
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    setattr(args, arg, True)
    assert s3_main(args) == 0
    assert getattr(mgr.return_value, method).call_count == 1


def test_s3_main_02(mocker, tmp_path):
    """s3 corpus refresh"""
    mgr = mocker.patch("guided_fuzzing_daemon.s3.S3Manager")
    args = mocker.Mock()
    args.mode = "libfuzzer"
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    args.s3_corpus_refresh = tmp_path
    args.build = None
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
    ]
    mgr.reset_mock()
    (tmp_path / "cmdline").write_text("build/firefox")
    (tmp_path / "build").mkdir()

    def fake_run(*_args, **_kwds):
        (tmp_path / "tests" / "test").touch()

    (tmp_path / "queues").mkdir()
    binary = tmp_path / "build" / "firefox"
    binary.touch()
    binary.chmod(0o777)
    mocker.patch("guided_fuzzing_daemon.s3.run", side_effect=fake_run)
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
        mocker.call.download_build(tmp_path / "build"),
        mocker.call.download_corpus(tmp_path / "queues"),
        mocker.call.upload_corpus(tmp_path / "tests", corpus_delete=True),
    ]
