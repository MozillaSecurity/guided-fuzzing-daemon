# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import chain

import pytest

from guided_fuzzing_daemon.args import parse_args


@pytest.mark.parametrize(
    "args, msg",
    (
        pytest.param([], "usage: gfd ", id="empty"),
        pytest.param(["--libfuzzer"], "No arguments", id="libfuzzer"),
        pytest.param(
            ["--libfuzzer-auto-reduce=0"], "Auto reduce threshold", id="lf-auto-reduce"
        ),
        pytest.param(
            ["--list-projects"],
            "Must specify --bucket",
            id="list-projects",
        ),
        pytest.param(
            ["--corpus-refresh=nx"],
            "Must specify both --bucket",
            id="corp-refresh",
        ),
    ),
)
def test_args_01(args, msg, capsys):
    """incomplete and invalid args"""
    with pytest.raises(SystemExit):
        parse_args(["gfd", *args])
    stdio = capsys.readouterr()
    assert msg in stdio.err


def test_args_02(capsys, tmp_path):
    """missing transformation script"""
    with pytest.raises(SystemExit):
        parse_args(["gfd", "--transform", str(tmp_path / "nx")])
    stdio = capsys.readouterr()
    assert "Failed to locate transformation" in stdio.err


@pytest.mark.parametrize("mode", (["--afl", "tmp/file"], ["--nyx", "--sharedir", ""]))
@pytest.mark.parametrize(
    "args, msg",
    (
        pytest.param([], "Must specify --afl-binary-dir ", id="wo-bindir"),
        pytest.param(
            ["--afl-binary-dir", ""],
            "specify --corpus-in",
            id="wo-corpus-in",
        ),
        pytest.param(
            ["--afl-binary-dir", "", "-i", "tmp"],
            "specify --corpus-out",
            id="wo-corpus-out",
        ),
        pytest.param(
            [
                "--afl-binary-dir",
                "",
                "--afl-log-pattern",
                "%n",
                "-i",
                "tmp",
                "-o",
                "tmp",
            ],
            "afl-log-pattern %d placeholder not recognized",
            id="bad-afl-pattern",
        ),
        pytest.param(
            [
                "--afl-binary-dir",
                "",
                "--nyx-log-pattern",
                "%n",
                "-i",
                "tmp",
                "-o",
                "tmp",
            ],
            "nyx-log-pattern %d placeholder not recognized",
            id="bad-nyx-pattern",
        ),
        pytest.param(
            [
                "--afl-binary-dir",
                "",
                "--instances",
                "2",
                "--afl-log-pattern",
                "%d%d",
                "-i",
                "tmp",
                "-o",
                "tmp",
            ],
            "afl-log-pattern expects exactly one",
            id="too-many-afl-pattern",
        ),
        pytest.param(
            [
                "--afl-binary-dir",
                "",
                "--instances",
                "2",
                "--nyx-log-pattern",
                "%d%d",
                "-i",
                "tmp",
                "-o",
                "tmp",
            ],
            "nyx-log-pattern expects exactly one",
            id="too-many-nyx-pattern",
        ),
        pytest.param(
            [
                "--afl-binary-dir",
                "",
                "--afl-hide-logs",
                "-i",
                "tmp",
                "-o",
                "tmp",
            ],
            "afl-hide-logs requires --afl-log-pattern",
            id="afl-hide-needs-pattern",
        ),
        pytest.param(
            [
                "--afl-binary-dir",
                "",
                "--max-runtime",
                "-1",
                "-i",
                "tmp",
                "-o",
                "tmp",
            ],
            "max-runtime must be positive",
            id="max-runtime-positive",
        ),
    ),
)
def test_args_03(args, capsys, mocker, mode, msg, tmp_path):
    """misc afl/nyx args"""
    if "--afl" in mode and "--nyx-log-pattern" in args:
        pytest.skip()
    mocker.patch("guided_fuzzing_daemon.args.which", return_value=None)
    (tmp_path / "file").touch()
    args = [
        {"tmp": str(tmp_path), "tmp/file": str(tmp_path / "file")}.get(arg, arg)
        for arg in chain(args, mode)
    ]
    with pytest.raises(SystemExit):
        parse_args(["gfd", *args])
    stdio = capsys.readouterr()
    assert msg in stdio.err


def test_args_04(capsys):
    """misc afl args"""
    with pytest.raises(SystemExit):
        parse_args(["gfd", "--afl"])
    stdio = capsys.readouterr()
    assert "AFL mode expects at least one arg" in stdio.err


@pytest.mark.parametrize(
    "args, msg",
    (
        pytest.param([], "specify --sharedir", id="wo-sharedir"),
        pytest.param([""], "takes no positional", id="extra-args"),
    ),
)
def test_args_05(args, capsys, msg, tmp_path):
    """misc nyx args"""
    args = [(arg if arg != "tmp" else str(tmp_path)) for arg in args]
    with pytest.raises(SystemExit):
        parse_args(["gfd", "--nyx", *args])
    stdio = capsys.readouterr()
    assert msg in stdio.err


def test_args_06(tmp_path):
    """nyx %d checking"""
    parse_args(
        [
            "gfd",
            "--nyx",
            "--instances",
            "2",
            "--sharedir",
            "",
            "--afl-binary-dir",
            "",
            "--afl-log-pattern",
            "%d",
            "-i",
            str(tmp_path),
            "-o",
            str(tmp_path),
        ]
    )


def test_args_07(mocker, tmp_path):
    """--afl-binary-dir is found automatically"""
    mocker.patch("guided_fuzzing_daemon.args.which", return_value=tmp_path)
    opts = parse_args(
        [
            "gfd",
            "--nyx",
            "--sharedir",
            str(tmp_path),
            "-i",
            str(tmp_path),
            "-o",
            str(tmp_path),
        ]
    )
    assert opts.aflbindir == tmp_path.parent


def test_args_08():
    """--env and --env-percent parsing"""
    opts = parse_args(
        [
            "gfd",
            "--env",
            "var1=val1",
            "--env",
            "var2=val2",
            "--env-percent",
            "25",
            "var3=val3a",
            "--env-percent",
            "12.5",
            "var3=val3b",
            "--env-percent",
            "50",
            "var4=val4",
        ]
    )
    assert opts.env == {
        "var1": "val1",
        "var2": "val2",
    }
    assert opts.env_percent == {
        "var3": {
            "val3a": 25.0,
            "val3b": 12.5,
        },
        "var4": {
            "val4": 50.0,
        },
    }


@pytest.mark.parametrize(
    "args, error",
    (
        (("--env", "var1"), "missing value"),
        (("--env", "var1=val1", "--env", "var1=val2"), "Multiple values"),
        (("--env-percent", "10", "var1"), "missing value"),
        (
            ("--env-percent", "10", "var1=val1", "--env-percent", "15", "var1=val1"),
            "Multiple probabilities",
        ),
        (("--env-percent", "nan", "var=val"), "Invalid value"),
        (("--env-percent", "inf", "var=val"), "Invalid value"),
        (("--env-percent", "-1", "var=val"), "Invalid value"),
        (("--env-percent", "101", "var=val"), "Invalid value"),
        (
            ("--env-percent", "100", "var=val1", "--env-percent", "1", "var=val2"),
            "Total probabilities",
        ),
    ),
)
def test_args_09(args, capsys, error):
    """--env and --env-percent parse errors"""
    with pytest.raises(SystemExit):
        parse_args(["gfd", *args])
    stdio = capsys.readouterr()
    assert error in stdio.err


def test_args_10(caplog):
    """test --afl-timeout deprecation"""
    args = parse_args(["gfd", "--afl-timeout=10"])
    assert any(
        "afl-timeout is deprecated" in record.message for record in caplog.records
    )
    assert args.timeout == 10
