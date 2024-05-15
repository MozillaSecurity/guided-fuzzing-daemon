# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import chain, count, repeat
from os import chdir
from pathlib import Path
from subprocess import TimeoutExpired

import pytest
from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration

from guided_fuzzing_daemon.afl import afl_main
from guided_fuzzing_daemon.s3 import S3Manager


class MainBreak(Exception):
    """Break out of main loop"""


def _get_path_args(arg, args):
    start = 0
    while start < len(args):
        try:
            loc = args.index(arg, start)
        except ValueError:
            break
        yield Path(args[loc + 1])
        start = loc + 2


def _instance_no(popen_args):
    if "-M" in popen_args[0]:
        return int(popen_args[0][popen_args[0].index("-M") + 1])
    return int(popen_args[0][popen_args[0].index("-S") + 1])


@pytest.fixture(name="afl")
def afl_common(mocker, tmp_path):
    """afl unittest boilerplate"""

    class _result:
        aflbindir = tmp_path / "aflbindir"
        (tmp_path / "target").touch()
        args = mocker.Mock()
        autorunner = mocker.patch("guided_fuzzing_daemon.afl.AutoRunner", autospec=True)
        cfg = mocker.patch(
            "guided_fuzzing_daemon.afl.ProgramConfiguration", autospec=True
        )
        crash_info = mocker.patch("guided_fuzzing_daemon.afl.CrashInfo", autospec=True)
        collector = mocker.Mock(spec=Collector)
        corpus_in = tmp_path / "corpus"
        corpus_out = tmp_path / "corpus.out"
        popen = mocker.patch("guided_fuzzing_daemon.afl.Popen", autospec=True)
        s3m = mocker.Mock(spec=S3Manager)
        sharedir = tmp_path / "sharedir"
        # set `side_effect=chain(repeat(None, <n>), [MainBreak])` to control how many
        # times the main loop will iterate before breaking
        sleep = mocker.patch(
            "guided_fuzzing_daemon.afl.sleep",
            autospec=True,
            side_effect=[MainBreak, None],
        )
        # time() increasing by 1.0s every call
        time = mocker.patch(
            "guided_fuzzing_daemon.afl.time", autospec=True, side_effect=count(1.0, 1.0)
        )
        warn_local = mocker.patch("guided_fuzzing_daemon.afl.warn_local", autospec=True)

        def __init__(self):
            def is_terminated():
                if (
                    self.popen.return_value.terminate.call_count
                    or self.popen.return_value.kill.call_count
                ):
                    return 2
                return None

            self.popen.return_value.poll.side_effect = is_terminated
            self.popen.return_value.wait.return_value = 2

            def popen_touch_fuzzer_stats(*args, **_kwds):
                idx = str(_instance_no(args))
                (self.corpus_out / idx).mkdir(exist_ok=True)
                (self.corpus_out / idx / "crashes").mkdir(exist_ok=True)
                (self.corpus_out / idx / "fuzzer_stats").touch()
                return mocker.DEFAULT

            self.popen.side_effect = popen_touch_fuzzer_stats
            (self.sharedir / "firefox").mkdir(parents=True)
            binary = self.sharedir / "firefox" / "firefox"
            binary.touch()
            self.aflbindir.mkdir()
            self.corpus_in.mkdir()

            self.args.afl_hide_logs = False
            self.args.afl_log_pattern = None
            self.args.aflbindir = self.aflbindir
            self.args.corpus_in = self.corpus_in
            (self.corpus_in / "test1.bin").write_text("A")
            (self.corpus_in / "test2.bin").write_text("B")
            self.args.corpus_out = self.corpus_out
            self.args.env = None
            self.args.env_percent = None
            self.args.max_runtime = 0.0
            self.args.metadata = []
            self.args.afl_async_corpus = False
            self.args.afl_add_corpus = []
            self.args.instances = 1
            self.args.afl_log_pattern = None
            self.args.rargs = [str(tmp_path / "target")]
            self.args.s3_queue_upload = False
            self.args.sharedir = self.sharedir
            self.args.stats = None

        def main(self):
            chdir(tmp_path)
            with pytest.raises(MainBreak):
                return afl_main(self.args, self.collector, self.s3m)

    yield _result()


def test_afl_01(afl, mocker, tmp_path):
    """afl processes startup"""
    # setup
    mocker.patch("os.environ", {"genv1": "gval1"})
    afl.sleep.side_effect = chain(repeat(None, 124), [MainBreak, None])
    afl.args.instances = 2
    afl.args.env = {"env1": "val1", "env2": "val2"}
    afl.args.metadata.extend(("meta1=metaval1", "meta2=metaval2"))
    stats = mocker.patch("guided_fuzzing_daemon.afl.AFLStats", autospec=True)

    # test
    afl.main()

    # check
    assert stats.return_value.update_and_write.call_count == 0
    assert afl.popen.call_count == 2
    cfg_inst = afl.cfg.fromBinary.return_value
    assert cfg_inst.addEnvironmentVariables.call_args_list == [
        mocker.call({"env1": "val1", "env2": "val2"})
    ]
    assert cfg_inst.addMetadata.call_args_list == [
        mocker.call({"meta1": "metaval1", "meta2": "metaval2"})
    ]
    assert afl.popen.call_args.kwargs["env"] == {
        "AFL_NO_CRASH_README": "1",
        "AFL_NO_UI": "1",
        "LD_LIBRARY_PATH": f"{tmp_path / 'gtest'}:{tmp_path}",
        "genv1": "gval1",
        "env1": "val1",
        "env2": "val2",
    }
    # check that terminate is called, not kill
    popen = afl.popen.return_value
    assert popen.terminate.call_count == 2
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 0
    assert popen.wait.call_count == 0


def test_afl_02(afl, mocker):
    """afl queue is uploaded"""
    # setup
    mocker.patch("guided_fuzzing_daemon.afl.QUEUE_UPLOAD_PERIOD", 90)
    afl.sleep.side_effect = chain(repeat(None, 60), [MainBreak, None])
    afl.args.s3_queue_upload = True

    # test
    afl.main()

    # check that upload is called once in the loop, once in finally
    assert afl.s3m.upload_afl_queue_dir.call_count == 2
    assert afl.s3m.upload_afl_queue_dir.call_args == mocker.call(
        afl.corpus_out / "0", afl.corpus_out / "0" / "cmdline", include_sync=True
    )


def test_afl_03a(afl):
    """afl subprocess are terminated then killed"""
    afl.sleep.side_effect = chain(repeat(None, 64), [MainBreak], repeat(None))

    def is_killed():
        if afl.popen.return_value.kill.call_count:
            return 2
        return None

    afl.popen.return_value.poll.side_effect = is_killed

    # test
    afl.main()

    # check that terminate is called, then kill
    popen = afl.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 1
    assert popen.wait.call_count == 1


def test_afl_03b(afl, capsys):
    """afl subprocess are terminated then killed but kill is ignored"""
    afl.sleep.side_effect = chain(repeat(None, 64), [MainBreak], repeat(None))

    afl.popen.return_value.pid = 123
    afl.popen.return_value.poll.side_effect = repeat(None)
    afl.popen.return_value.wait.side_effect = TimeoutExpired([], 1)

    # test
    afl.main()

    # check that terminate is called, then kill
    popen = afl.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 1
    assert popen.wait.call_count == 1
    stdio = capsys.readouterr()
    assert "123 did not exit after SIGKILL" in stdio.err


@pytest.mark.parametrize(
    "dupe, have_collector, autorun_repro",
    [
        pytest.param(False, False, True, id="no-collector"),
        pytest.param(True, True, True, id="dupe"),
        pytest.param(False, True, True, id="report"),
        pytest.param(False, False, False, id="no-repro-no-collector"),
        pytest.param(False, True, False, id="no-repro-report"),
    ],
)
def test_afl_04(afl, autorun_repro, dupe, have_collector, tmp_path):
    """afl crashes are re-run using AutoRunner and reported"""
    # setup
    afl.sleep.side_effect = chain(repeat(None, 32), [MainBreak, None])
    runner = afl.autorunner.fromBinaryArgs.return_value
    crash_info = runner.getCrashInfo.return_value
    crash_info.stdout = "blah\n"
    crash_info.stderr = "error\n"
    runner.run.return_value = autorun_repro
    orig_popen_cb = afl.popen.side_effect

    def popen_create_crash(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        (afl.corpus_out / "0" / "crashes" / "crash").touch()
        return result

    afl.popen.side_effect = popen_create_crash
    if have_collector:
        if dupe:
            (tmp_path / "sig").touch()
            afl.collector.search.return_value = (tmp_path / "sig", {})
        else:
            afl.collector.search.return_value = (None, None)
            afl.collector.submit.return_value = {
                "id": 1234,
                "shortSignature": "SecurityError: this looks bad",
            }
    else:
        assert not dupe
        afl.collector = None

    # test
    afl.main()

    # check
    if have_collector:
        assert (afl.corpus_out / "0" / "crashes" / "crash.processed").exists()
        assert not (afl.corpus_out / "0" / "crashes" / "crash").exists()
        assert runner.run.call_count == 1
        if autorun_repro:
            assert afl.crash_info.fromRawCrashData.call_count == 0
        else:
            assert afl.crash_info.fromRawCrashData.call_count == 1
        if dupe:
            assert afl.collector.submit.call_count == 0
        else:
            assert afl.collector.submit.call_count == 1
    else:
        assert runner.run.call_count == 0
        assert not (afl.corpus_out / "0" / "crashes" / "crash.processed").is_file()


def test_afl_05(afl, mocker, tmp_path):
    """afl async corpus mode"""
    # setup
    mocker.patch("os.environ", {})
    afl.sleep.side_effect = chain(repeat(None, 124), [MainBreak, None])
    afl.args.afl_async_corpus = True
    afl.args.instances = 2
    orig_popen_cb = afl.popen.side_effect

    def popen_check_corpus(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        corpus = Path(args[0][args[0].index("-i") + 1])
        assert corpus != afl.corpus_in
        assert len(list(corpus.iterdir())) == 1
        assert next(corpus.iterdir()).read_text() in {"A", "B"}
        return result

    afl.popen.side_effect = popen_check_corpus

    # test
    afl.main()

    # check
    popen_calls = afl.popen.call_args_list
    assert len(popen_calls) == 2
    main, sec = popen_calls
    assert main.kwargs["env"] == {
        "AFL_FINAL_SYNC": "1",
        "AFL_IMPORT_FIRST": "1",
        "AFL_NO_CRASH_README": "1",
        "AFL_NO_UI": "1",
        "LD_LIBRARY_PATH": f"{tmp_path / 'gtest'}:{tmp_path}",
    }
    assert sec.kwargs["env"] == {
        "AFL_NO_CRASH_README": "1",
        "AFL_NO_UI": "1",
        "LD_LIBRARY_PATH": f"{tmp_path / 'gtest'}:{tmp_path}",
    }
    assert (
        main.args[0][main.args[0].index("-i") + 1]
        == sec.args[0][sec.args[0].index("-i") + 1]
    )
    assert set(_get_path_args("-F", main.args[0])) == {afl.corpus_in}
    assert afl.corpus_in not in set(_get_path_args("-F", sec.args[0]))


def test_afl_06(afl, mocker, tmp_path):
    """afl stats are written"""
    # setup
    stats = mocker.patch("guided_fuzzing_daemon.afl.AFLStats", autospec=True)
    afl.sleep.side_effect = chain(repeat(None, 100), [MainBreak, None])
    afl.args.stats = tmp_path / "stats"

    # test
    afl.main()

    # stats should be written a few times in 100 loops
    assert stats.return_value.update_and_write.call_count > 3
    assert stats.return_value.update_and_write.call_args == mocker.call(
        tmp_path / "stats", [afl.corpus_out / "0"]
    )


def test_afl_07(afl):
    """afl exited processes are restarted"""
    # setup
    afl.sleep.side_effect = chain(repeat(None, 200), [MainBreak, None])
    is_terminated = afl.popen.return_value.poll.side_effect

    def is_terminated_iter():
        while True:
            yield is_terminated()

    afl.popen.return_value.poll.side_effect = chain(
        repeat(None, 30), [1], is_terminated_iter()
    )

    # test
    afl.main()

    # exited process should have been restarted once
    assert afl.popen.call_count == 2
    assert afl.popen.return_value.terminate.call_count == 1


# test that logs are teed
@pytest.mark.parametrize(
    "instances, hide, pattern",
    [
        pytest.param(1, False, "%d", id="instance-pattern"),
        pytest.param(1, False, "", id="instance-plain"),
        pytest.param(2, False, "%d", id="two-instances"),
        pytest.param(1, True, "", id="hide-logs"),
    ],
)
def test_afl_08(afl, capsys, hide, instances, pattern, tmp_path):
    """afl exited processes are restarted"""
    # setup
    afl.sleep.side_effect = chain(repeat(None, 124), [MainBreak, None])
    afl.args.afl_hide_logs = hide
    afl.args.afl_log_pattern = str(tmp_path / f"afl{pattern}")
    afl.args.instances = instances

    out = []
    out_line = [None] * instances
    ctrs = [count(1) for _ in range(instances)]
    orig_sleep_iter = afl.sleep.side_effect

    def sleep_write_logs(*args, **_kwds):
        # write to log files whenever sleep() is called in the afl_main loop
        for args, _kwds in afl.popen.call_args_list:
            idx = _instance_no(args)
            filename = afl.args.afl_log_pattern
            if pattern:
                filename = filename % (idx,)
            value = next(ctrs[idx])
            cont = bool(value % 2)
            with open(filename, "a", encoding="utf-8") as hnd:
                print(value, end="" if cont else "\n", file=hnd)
            # save the values as printed to log files, so we can compare to stdout
            if not hide:
                if out_line[idx] is None:
                    out_line[idx] = len(out)
                    out.append(f"[{idx}] {value}")
                else:
                    out[out_line[idx]] = f"{out[out_line[idx]]}{value}"
                if not cont:
                    out_line[idx] = None
        # handle default sleep() side-effects
        result = next(orig_sleep_iter)
        if isinstance(result, type) and issubclass(result, Exception):
            raise result()
        return result

    afl.sleep.side_effect = sleep_write_logs

    # test
    afl.main()

    # logs should have been written to stdout
    stdio = capsys.readouterr()
    assert stdio.out.splitlines() == out


def test_afl_09(afl, tmp_path):
    """afl max runtime"""
    # setup
    afl.args.max_runtime = 30.0
    afl.sleep.side_effect = chain(repeat(None, 60), [MainBreak, None])

    # test
    chdir(tmp_path)
    result = afl_main(afl.args, afl.collector, afl.s3m)

    assert result == 0


def test_afl_10(afl, mocker):
    """afl multiple instances use different env vars and configurations"""
    # setup
    cfg1 = mocker.Mock(spec=ProgramConfiguration)
    cfg2 = mocker.Mock(spec=ProgramConfiguration)
    mocker.patch(
        "guided_fuzzing_daemon.afl.create_envs",
        return_value=(
            ({"env1": "val1", "env2": "val2"}, {"env3": "val3", "env4": "val4"}),
            (cfg1, cfg2),
        ),
    )
    afl.sleep.side_effect = chain(repeat(None, 64), [MainBreak, None])
    runner = afl.autorunner.fromBinaryArgs.return_value
    afl.args.instances = 2
    orig_popen_cb = afl.popen.side_effect

    def popen_create_crash(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        idx = _instance_no(args)
        (afl.corpus_out / str(idx) / "crashes" / "crash").touch()
        return result

    afl.popen.side_effect = popen_create_crash
    afl.collector.search.return_value = (None, None)
    afl.collector.submit.return_value = {
        "id": 1234,
        "shortSignature": "SecurityError: this looks bad",
    }

    # test
    afl.main()

    # check
    assert afl.popen.call_count == 2
    assert afl.popen.call_args_list[0][1]["env"] == {
        "AFL_FINAL_SYNC": "1",
        "env1": "val1",
        "env2": "val2",
    }
    assert afl.popen.call_args_list[1][1]["env"] == {
        "env3": "val3",
        "env4": "val4",
    }
    assert runner.getCrashInfo.call_count == 2


def test_afl_11(afl, mocker, tmp_path):
    """afl additional corpus"""
    # setup
    mocker.patch("os.environ", {})
    afl.sleep.side_effect = chain(repeat(None, 124), [MainBreak, None])
    corpus_add = tmp_path / "corpus.add"
    afl.args.afl_add_corpus.append(corpus_add)
    afl.args.instances = 2

    # test
    afl.main()

    # check
    popen_calls = afl.popen.call_args_list
    assert len(popen_calls) == 2
    main, sec = popen_calls
    assert set(_get_path_args("-F", main.args[0])) == {corpus_add}
    assert set(_get_path_args("-F", sec.args[0])) == set()
