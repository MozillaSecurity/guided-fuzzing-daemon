# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from pathlib import Path

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
    args.s3_list_projects = False
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    setattr(args, arg, True)
    assert s3_main(args) == 0
    assert getattr(mgr.return_value, method).call_count == 1


def test_s3_main_02(mocker, tmp_path):
    """libfuzzer s3 corpus refresh"""
    mocker.patch("guided_fuzzing_daemon.s3.StatAggregator", autospec=True)
    mgr = mocker.patch("guided_fuzzing_daemon.s3.S3Manager")
    args = mocker.Mock()
    args.mode = "libfuzzer"
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    args.s3_corpus_refresh = tmp_path
    args.s3_list_projects = False
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
        return mocker.DEFAULT

    (tmp_path / "queues").mkdir()
    binary = tmp_path / "build" / "firefox"
    binary.touch()
    binary.chmod(0o777)
    popen = mocker.patch("guided_fuzzing_daemon.s3.Popen", side_effect=fake_run)
    popen.return_value.wait.return_value = 0
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
        mocker.call.download_build(tmp_path / "build"),
        mocker.call.download_corpus(tmp_path / "queues"),
        mocker.call.upload_corpus(tmp_path / "tests", corpus_delete=True),
    ]


def test_s3_main_03(mocker, tmp_path):
    """Nyx S3 corpus refresh"""
    mocker.patch("guided_fuzzing_daemon.s3.StatAggregator", autospec=True)
    mgr = mocker.patch("guided_fuzzing_daemon.s3.S3Manager")
    args = mocker.Mock()
    args.mode = "nyx"
    args.aflbindir = tmp_path
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    args.s3_corpus_refresh = tmp_path
    args.s3_list_projects = False
    args.build = None
    args.sharedir = tmp_path / "sharedir"
    (tmp_path / "sharedir").mkdir()
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
    ]
    (tmp_path / "config.sh").write_text("build/firefox")
    (tmp_path / "build").mkdir()

    def fake_run(*_args, **_kwds):
        (tmp_path / "tests" / "test").touch()
        return mocker.DEFAULT

    (tmp_path / "queues").mkdir()
    binary = tmp_path / "build" / "firefox"
    binary.touch()
    binary.chmod(0o777)
    popen = mocker.patch("guided_fuzzing_daemon.s3.Popen", side_effect=fake_run)
    popen.return_value.wait.return_value = 0
    assert s3_main(args) == 2
    (tmp_path / "afl-cmin").touch()
    mgr.reset_mock()
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
        mocker.call.download_build(tmp_path / "build"),
        mocker.call.download_corpus(tmp_path / "queues"),
        mocker.call.upload_corpus(tmp_path / "tests", corpus_delete=True),
    ]


def test_s3_main_04(capsys, mocker):
    s3c = mocker.patch("guided_fuzzing_daemon.s3.S3Connection")
    args = mocker.Mock()
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    args.s3_list_projects = True
    args.project = None
    key = mocker.Mock()
    key.name = "project/"
    s3c.return_value.get_bucket.return_value.list.return_value = [key]
    assert s3_main(args) == 0
    assert s3c.return_value.get_bucket.call_args_list == [mocker.call(args.s3_bucket)]
    bucket = s3c.return_value.get_bucket.return_value
    assert bucket.list.call_args_list == [mocker.call(prefix="", delimiter="/")]
    stdio = capsys.readouterr()
    assert stdio.out.splitlines() == ["project"]


def test_s3_main_05(mocker, tmp_path):
    """AFL s3 corpus refresh"""
    mocker.patch("guided_fuzzing_daemon.s3.StatAggregator", autospec=True)
    mgr = mocker.patch("guided_fuzzing_daemon.s3.S3Manager")
    args = mocker.Mock()
    args.mode = "afl"
    for s3_action in S3_ACTIONS:
        setattr(args, s3_action, None)
    args.s3_corpus_refresh = tmp_path
    args.s3_list_projects = False
    args.build = None
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
    ]
    mgr.reset_mock()
    (tmp_path / "cmdline").write_text("build/firefox")
    (tmp_path / "build").mkdir()

    def fake_run(*_args, **kwds):
        (tmp_path / "tests" / "test").touch()
        assert "env" in kwds
        assert "LD_LIBRARY_PATH" in kwds["env"]
        ld_lib_path = tuple(Path(p) for p in kwds["env"]["LD_LIBRARY_PATH"].split(":"))
        assert {binary.parent / "gtest", binary.parent} <= set(ld_lib_path)
        assert ld_lib_path.index(binary.parent / "gtest") < ld_lib_path.index(
            binary.parent
        )
        return mocker.DEFAULT

    (tmp_path / "queues").mkdir()
    binary = tmp_path / "build" / "firefox"
    binary.touch()
    binary.chmod(0o777)
    popen = mocker.patch("guided_fuzzing_daemon.s3.Popen", side_effect=fake_run)
    popen.return_value.wait.return_value = 0
    args.rargs = [str(binary)]
    args.aflbindir = tmp_path
    assert s3_main(args) == 2
    mgr.reset_mock()
    (tmp_path / "afl-cmin").touch()
    assert s3_main(args) == 0
    assert mgr.return_value.method_calls == [
        mocker.call.clean_queue_dirs(),
        mocker.call.download_queue_dirs(tmp_path),
        mocker.call.download_build(tmp_path / "build"),
        mocker.call.download_corpus(tmp_path / "queues"),
        mocker.call.upload_corpus(tmp_path / "tests", corpus_delete=True),
    ]
