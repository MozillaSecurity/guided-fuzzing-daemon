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
        pytest.param(["--nyx"], "specify --spec-fuzzer", id="nyx"),
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


def test_args_04(capsys, tmp_path):
    """misc nyx args"""
    with pytest.raises(SystemExit):
        parse_args(["gfd", "--nyx", f"--spec-fuzzer={tmp_path}"])
    stdio = capsys.readouterr()
    assert "Must specify --sharedir" in stdio.err


def test_args_05():
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
