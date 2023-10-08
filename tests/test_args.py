# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from guided_fuzzing_daemon.args import parse_args


@pytest.mark.parametrize(
    "args, msg",
    (
        pytest.param([], "usage: gfd ", id="empty"),
        pytest.param(
            ["--aflfuzz", "--firefox"], "require FFPuppet to be installed", id="afl"
        ),
        pytest.param(["--libfuzzer"], "No arguments", id="libfuzzer"),
        pytest.param(
            ["--libfuzzer-auto-reduce=0"], "Auto reduce threshold", id="lf-auto-reduce"
        ),
        pytest.param(
            ["--s3-corpus-refresh=nx"],
            "Must specify both --s3-bucket",
            id="s3-corp-refresh",
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


@pytest.mark.parametrize(
    "args, msg",
    (
        pytest.param(["--firefox"], "require --firefox-prefs", id="ff-prefs"),
        pytest.param(["--cmd"], "with afl in firefox mode", id="cmd-wo-ff"),
        pytest.param(
            ["--firefox", "--custom-cmdline-file=nx"],
            "incompatible with firefox",
            id="custom-cmd",
        ),
        pytest.param(
            ["--firefox-start-afl=nx", "--firefox-prefs=nx", "--firefox-testpath=nx"],
            "Must specify --afl-binary-dir for start",
            id="ff-start-wo-bindir",
        ),
        pytest.param(["--fuzzmanager"], "Must specify AFL output", id="fm-wo-outdir"),
        pytest.param(
            ["--s3-corpus-refresh=nx", "--s3-bucket=nx", "--project=test"],
            "Must specify --afl-binary-dir for refresh",
            id="s3-refresh-wo-bindir",
        ),
    ),
)
def test_args_03(args, msg, capsys, mocker):
    """misc aflfuzz args"""
    mocker.patch("guided_fuzzing_daemon.args.HAVE_FFPUPPET", True)
    with pytest.raises(SystemExit):
        parse_args(["gfd", "--aflfuzz", *args])
    stdio = capsys.readouterr()
    assert msg in stdio.err


def test_args_04():
    """libfuzzer does not need args when doing s3 actions"""
    parse_args(
        [
            "gfd",
            "--libfuzzer",
            "--s3-corpus-refresh",
            "corpus",
            "--s3-bucket",
            "bucket",
            "--project",
            "test",
        ]
    )


@pytest.mark.parametrize(
    "args, msg",
    (
        pytest.param([], "specify --sharedir", id="wo-sharedir"),
        pytest.param([""], "takes no positional", id="extra-args"),
        pytest.param(
            ["--sharedir", ""], "Must specify --afl-binary-dir for Nyx", id="wo-bindir"
        ),
        pytest.param(
            ["--sharedir", "", "--afl-binary-dir", ""],
            "specify --corpus-in",
            id="wo-corpus-in",
        ),
        pytest.param(
            ["--sharedir", "", "--afl-binary-dir", "", "-i", "tmp"],
            "specify --corpus-out",
            id="wo-corpus-out",
        ),
        pytest.param(
            [
                "--sharedir",
                "",
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
                "--sharedir",
                "",
                "--afl-binary-dir",
                "",
                "--nyx-instances",
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
                "--sharedir",
                "",
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
                "--sharedir",
                "",
                "--afl-binary-dir",
                "",
                "--nyx-instances",
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
                "--sharedir",
                "",
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
    ),
)
def test_args_05(args, capsys, mocker, msg, tmp_path):
    """misc nyx args"""
    mocker.patch("guided_fuzzing_daemon.args.which", return_value=None)
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
            "--nyx-instances",
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
