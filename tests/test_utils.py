# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import hashlib
import re
import sys
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from time import sleep

import pytest
from FTB.ProgramConfiguration import ProgramConfiguration

from guided_fuzzing_daemon.utils import (
    Executor,
    LogFile,
    LogTee,
    create_envs,
    open_log_handle,
    rename_files_to_hash,
)


def test_create_envs(mocker):
    orig_env = {
        "global": "glval",
    }
    base_cfg = mocker.Mock(spec=ProgramConfiguration, env={})
    created_cfgs = []

    def new_cfg(orig_cfg):
        result = mocker.Mock(spec=ProgramConfiguration, env=orig_cfg.env.copy())
        created_cfgs.append(result)
        return result

    copy = mocker.patch("guided_fuzzing_daemon.utils.copy", side_effect=new_cfg)
    rnd = mocker.patch(
        "guided_fuzzing_daemon.utils.uniform",
        side_effect=(0.5, 60.0, 60.0, 25.0, 6.0, 0.0),
    )
    args = mocker.Mock()
    args.env = {"var1": "val1", "var2": "val2a"}
    # use OrderedDict to ensure calls to uniform above line up with var2/var3 order
    args.env_percent = OrderedDict(
        var2=OrderedDict(val2b=1.0, val2c=5.0),
        var3={"val3": 50.0},
    )
    envs, cfgs = create_envs(orig_env, args, 3, base_cfg)
    assert rnd.call_count == 6
    assert len(envs) == 3
    assert len(cfgs) == 3
    assert len(orig_env) == 1
    assert envs[0] == {
        "global": "glval",
        "var1": "val1",
        "var2": "val2b",
    }
    assert envs[1] == {
        "global": "glval",
        "var1": "val1",
        "var2": "val2a",
        "var3": "val3",
    }
    assert envs[2] == {
        "global": "glval",
        "var1": "val1",
        "var2": "val2c",
        "var3": "val3",
    }
    assert copy.call_count == 4
    assert created_cfgs[0].addEnvironmentVariables.call_args_list == [
        mocker.call({"var1": "val1", "var2": "val2a"}),
    ]
    assert cfgs[0].addEnvironmentVariables.call_args_list == [
        mocker.call({"var2": "val2b"})
    ]
    assert cfgs[1].addEnvironmentVariables.call_args_list == [
        mocker.call({"var3": "val3"})
    ]
    assert cfgs[2].addEnvironmentVariables.call_args_list == [
        mocker.call({"var2": "val2c", "var3": "val3"})
    ]


@pytest.mark.skipif(sys.version_info[:2] >= (3, 12), reason="batched in stdlib 3.12+")
def test_batched():
    """test for batched"""
    # pylint: disable=import-outside-toplevel
    from guided_fuzzing_daemon.utils import batched

    with pytest.raises(ValueError):
        list(batched(range(10), 0))
    assert list(batched(range(10), 2)) == [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9)]
    assert list(batched(range(5), 2)) == [(0, 1), (2, 3), (4,)]


def test_executor_01():
    """test that tasks run correctly in parallel"""

    def task():
        pass

    with Executor() as executor:
        futures = [executor.submit(task) for _ in range(5)]

    results = [f.result() for f in futures]

    assert len(results) == 5
    assert all(not f.cancelled() for f in futures)


def test_executor_02(mocker):
    """test that tasks not yet started are cancelled if an exception occurs"""
    mocker.patch("guided_fuzzing_daemon.utils.THREAD_WORKERS", 1)
    lock = Lock()

    def task(x):
        with lock:
            if x == 1:
                raise ValueError("Test exception")
            sleep(0.1)
            return x * 2

    with pytest.raises(ValueError):
        with Executor() as executor:
            with lock:
                futures = [executor.submit(task, i) for i in range(5)]

    # Ensure that some tasks were cancelled
    cancelled_futures = [f for f in futures if f.cancelled()]
    assert len(cancelled_futures) > 0
    assert len(cancelled_futures) <= 3  # at least one should pass, and one should raise
    exceptions = [f for f in futures if not f.cancelled() and f.exception()]
    assert len(exceptions) == 1


def test_logfile(capsys, tmp_path):
    """test that LogFile works"""
    called = False

    def on_pattern(_line, _match):
        nonlocal called
        called = True

    with (tmp_path / "test.txt").open("w") as fd:
        lf = LogFile(fd, "[0] ")
        lf.add_pattern(re.compile(r"^test"), on_pattern)
        assert not called
        # check that 'hello world' is printed and doesn't match pattern
        print("hello world", file=fd)
        fd.flush()
        lf.print()
        cap = capsys.readouterr()
        assert cap.out == "[0] hello world\n"
        assert cap.err == ""
        assert not called
        # check that partial write is buffered and does match pattern
        print("tes", file=fd, end="")
        fd.flush()
        lf.print()
        cap = capsys.readouterr()
        assert cap.out == ""
        assert cap.err == ""
        assert not called
        print("t", file=fd)
        fd.flush()
        lf.print()
        cap = capsys.readouterr()
        assert cap.out == "[0] test\n"
        assert cap.err == ""
        assert called
        called = False
        # check that final flushed print will still match pattern
        print("test", file=fd, end="")
        fd.flush()
        lf.print()
        cap = capsys.readouterr()
        assert cap.out == ""
        assert cap.err == ""
        assert not called
        lf.print(flush=True)
        cap = capsys.readouterr()
        assert cap.out == "[0] test\n"
        assert cap.err == ""
        assert called


# instances are 0 based, so 100 instances is 0..99, etc.
@pytest.mark.parametrize(
    "instances,width", ((1, 1), (10, 1), (11, 2), (100, 2), (101, 3))
)
def test_logtee_width(instances, width):
    """test that logtee instance count correctly calculates prefix width"""
    lt = LogTee(False, instances)
    assert lt.instance_width == width


def test_logtee_1(mocker, tmp_path):
    """test that logtee passes calls through to a logfile instance"""

    def on_pattern(_line, _match):
        pass

    lf = mocker.patch("guided_fuzzing_daemon.utils.LogFile")
    lt = LogTee(False, 1)
    assert lt.pattern is None
    pat = re.compile(r"")
    lt.add_pattern(pat, on_pattern)
    assert lt.pattern is pat
    with (tmp_path / "test.txt").open("w") as fd:
        lt.append(fd)
        assert lf.call_args_list == [mocker.call(fd, "[0] ")]
        lf0 = lf.return_value
        assert lf0.add_pattern.call_args_list == [mocker.call(pat, on_pattern)]
        assert lf0.print.call_count == 0
        lt.print()
        assert lf0.print.call_args_list == [mocker.call()]
        lt.close()
        assert lf0.print.call_args_list == [mocker.call(), mocker.call(flush=True)]
        assert lf0.handle.close.call_count == 1


def test_logtee_2(mocker, tmp_path):
    """test that logtee passes calls through to two logfile instances"""

    def on_pattern(_line, _match):
        pass

    lf = mocker.patch("guided_fuzzing_daemon.utils.LogFile")
    lt = LogTee(False, 1)
    assert lt.pattern is None
    pat = re.compile(r"")
    with (tmp_path / "test1.txt").open("w") as f1, (tmp_path / "test2.txt").open(
        "w"
    ) as f2:
        lt.append(f1)
        assert lf.call_args_list == [mocker.call(f1, "[0] ")]
        # TODO: mocker doesn't give an easy way to distinguish multiple return values
        # so all calls below are doubled, as if they occurred on the same LogFile()
        lf0 = lf.return_value
        lt.append(f2)
        assert lf.call_args_list == [mocker.call(f1, "[0] "), mocker.call(f2, "[1] ")]
        lt.add_pattern(pat, on_pattern)
        assert lt.pattern is pat
        assert lf0.add_pattern.call_args_list == [
            mocker.call(pat, on_pattern),
            mocker.call(pat, on_pattern),
        ]
        assert lf0.print.call_count == 0
        lt.print()
        assert lf0.print.call_args_list == [mocker.call(), mocker.call()]
        lt.close()
        assert lf0.print.call_args_list == [
            mocker.call(),
            mocker.call(),
            mocker.call(flush=True),
            mocker.call(flush=True),
        ]
        assert lf0.handle.close.call_count == 2


@pytest.mark.parametrize(
    "pattern, idx, expected",
    [
        ("log%d.txt", 3, "log3.txt"),
        ("fixed.log", 0, "fixed.log"),
        (None, 2, "screen2.log"),
    ],
)
def test_open_log_handle(tmp_path: Path, pattern: str | None, idx: int, expected: str):
    full_pattern = str(tmp_path / pattern) if pattern else None
    f = open_log_handle(full_pattern, tmp_path, idx)
    assert Path(f.name).name == expected
    f.close()


def test_rename_files_to_hash_with_exclusions(tmp_path):
    """Test file renaming to hash values with and without exclusions"""
    (tmp_path / "config.sh").touch()
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    (tmp_path / "c").write_text("b")
    (tmp_path / "d").mkdir()

    rename_files_to_hash(tmp_path, skip_names=["config.sh"])

    assert (tmp_path / "config.sh").exists()
    renamed_files = [
        f for f in tmp_path.iterdir() if f.is_file() and f.name != "config.sh"
    ]
    assert len(renamed_files) == 2
    for f in renamed_files:
        data = f.read_text()
        assert data in ("a", "b")


def test_rename_files_to_hash_file_already_named_correctly(tmp_path, mocker):
    """Test that files already named with their hash are not renamed"""
    content = "test content"
    expected_hash = hashlib.blake2b(content.encode()).hexdigest()

    # Create a file that has been previously hashed
    previously_hashed = tmp_path / expected_hash
    previously_hashed.write_text(content)

    # Spy on the rename method to ensure the correctly named file is not renamed
    spy_rename = mocker.spy(Path, "rename")

    rename_files_to_hash(tmp_path)

    # The correctly named file should still exist and not have been renamed
    assert previously_hashed.exists()
    assert previously_hashed.read_text() == content

    # Only one file should remain
    remaining_files = [f for f in tmp_path.iterdir() if f.is_file()]
    assert len(remaining_files) == 1
    assert remaining_files[0].name == expected_hash

    # The correctly named file should not have been renamed
    # (spy_rename should not have been called on the correctly named file)
    rename_calls = [
        call for call in spy_rename.call_args_list if call[0][0].name == expected_hash
    ]
    assert len(rename_calls) == 0
