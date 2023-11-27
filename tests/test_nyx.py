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
from FTB.Signatures.CrashInfo import TraceParsingError

from guided_fuzzing_daemon.nyx import (
    NyxStats,
    nyx_main,
)
from guided_fuzzing_daemon.s3 import S3Manager


class NyxMainBreak(Exception):
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


@pytest.fixture(name="nyx")
def nyx_common(mocker, tmp_path):
    """nyx unittest boilerplate"""

    class _result:
        aflbindir = tmp_path / "aflbindir"
        args = mocker.Mock()
        asan_sym = mocker.patch("guided_fuzzing_daemon.nyx.ASAN_SYMBOLIZE")
        cfg = mocker.patch(
            "guided_fuzzing_daemon.nyx.ProgramConfiguration", autospec=True
        )
        crash_info = mocker.patch("guided_fuzzing_daemon.nyx.CrashInfo", autospec=True)
        collector = mocker.Mock(spec=Collector)
        corpus_in = tmp_path / "corpus"
        corpus_out = tmp_path / "corpus.out"
        popen = mocker.patch("guided_fuzzing_daemon.nyx.Popen", autospec=True)
        run = mocker.patch("guided_fuzzing_daemon.nyx.run", autospec=True)
        s3m = mocker.Mock(spec=S3Manager)
        sharedir = tmp_path / "sharedir"
        # set `side_effect=chain(repeat(None, <n>), [NyxMainBreak])` to control how many
        # times the main loop will iterate before breaking
        sleep = mocker.patch(
            "guided_fuzzing_daemon.nyx.sleep",
            autospec=True,
            side_effect=[NyxMainBreak, None],
        )
        # time() increasing by 1.0s every call
        time = mocker.patch(
            "guided_fuzzing_daemon.nyx.time", autospec=True, side_effect=count(1.0, 1.0)
        )
        warn_local = mocker.patch("guided_fuzzing_daemon.nyx.warn_local", autospec=True)

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
            self.args.nyx_async_corpus = False
            self.args.nyx_add_corpus = []
            self.args.nyx_instances = 1
            self.args.nyx_log_pattern = None
            self.args.rargs = []
            self.args.s3_queue_upload = False
            self.args.sharedir = self.sharedir
            self.args.stats = None

        def main(self):
            chdir(tmp_path)
            with pytest.raises(NyxMainBreak):
                return nyx_main(self.args, self.collector, self.s3m)

    yield _result()


def test_nyx_01(mocker, nyx):
    """nyx processes startup"""
    # setup
    mocker.patch("os.environ", {"genv1": "gval1"})
    nyx.sleep.side_effect = chain(repeat(None, 124), [NyxMainBreak, None])
    nyx.args.nyx_instances = 2
    nyx.args.env = {"env1": "val1", "env2": "val2"}
    nyx.args.metadata.extend(("meta1=metaval1", "meta2=metaval2"))
    stats = mocker.patch("guided_fuzzing_daemon.nyx.NyxStats", autospec=True)

    # test
    nyx.main()

    # check
    assert stats.return_value.update_and_write.call_count == 0
    assert nyx.popen.call_count == 2
    cfg_inst = nyx.cfg.fromBinary.return_value
    assert cfg_inst.addEnvironmentVariables.call_args_list == [
        mocker.call({"env1": "val1", "env2": "val2"})
    ]
    assert cfg_inst.addMetadata.call_args_list == [
        mocker.call({"meta1": "metaval1", "meta2": "metaval2"})
    ]
    assert nyx.popen.call_args.kwargs["env"] == {
        "AFL_NO_UI": "1",
        "genv1": "gval1",
        "env1": "val1",
        "env2": "val2",
    }
    # check that terminate is called, not kill
    popen = nyx.popen.return_value
    assert popen.terminate.call_count == 2
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 0
    assert popen.wait.call_count == 0


def test_nyx_02(mocker, nyx):
    """nyx queue is uploaded"""
    # setup
    mocker.patch("guided_fuzzing_daemon.nyx.QUEUE_UPLOAD_PERIOD", 90)
    nyx.sleep.side_effect = chain(repeat(None, 60), [NyxMainBreak, None])
    nyx.args.s3_queue_upload = True

    # test
    nyx.main()

    # check that upload is called once in the loop, once in finally
    assert nyx.s3m.upload_afl_queue_dir.call_count == 2
    assert nyx.s3m.upload_afl_queue_dir.call_args == mocker.call(nyx.corpus_out / "0")


def test_nyx_03a(nyx):
    """nyx subprocess are terminated then killed"""
    nyx.sleep.side_effect = chain(repeat(None, 64), [NyxMainBreak], repeat(None))

    def is_killed():
        if nyx.popen.return_value.kill.call_count:
            return 2
        return None

    nyx.popen.return_value.poll.side_effect = is_killed

    # test
    nyx.main()

    # check that terminate is called, then kill
    popen = nyx.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 1
    assert popen.wait.call_count == 1


def test_nyx_03b(capsys, nyx):
    """nyx subprocess are terminated then killed but kill is ignored"""
    nyx.sleep.side_effect = chain(repeat(None, 64), [NyxMainBreak], repeat(None))

    nyx.popen.return_value.pid = 123
    nyx.popen.return_value.poll.side_effect = repeat(None)
    nyx.popen.return_value.wait.side_effect = TimeoutExpired([], 1)

    # test
    nyx.main()

    # check that terminate is called, then kill
    popen = nyx.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 1
    assert popen.wait.call_count == 1
    stdio = capsys.readouterr()
    assert "123 did not exit after SIGKILL" in stdio.err


@pytest.mark.parametrize(
    "dupe, fail_last_line, have_collector, symbolize_ret",
    [
        pytest.param(False, False, False, 0, id="no-collector"),
        pytest.param(True, False, True, 0, id="dupe"),
        pytest.param(False, False, True, 0, id="report"),
        pytest.param(False, False, False, 1, id="no-sym-no-collector"),
        pytest.param(False, False, True, 1, id="no-sym-report"),
        pytest.param(False, True, True, 0, id="retry-last-line"),
    ],
)
def test_nyx_04(
    dupe, fail_last_line, have_collector, mocker, nyx, symbolize_ret, tmp_path
):
    """nyx crashes are symbolized and reported"""
    # setup
    nyx.sleep.side_effect = chain(repeat(None, 64), [NyxMainBreak, None])
    inp_log = "ld_preload_fuzz_no_pt.so\n/home/user/firefox/firefox\nblah\n"
    nyx.run.return_value.stdout = inp_log
    nyx.run.return_value.stderr = "error\n"
    nyx.run.return_value.returncode = symbolize_ret
    orig_popen_cb = nyx.popen.side_effect

    if fail_last_line:

        def from_raw_mock(*_args, **kwds):
            if "blah" in kwds["auxCrashData"]:
                raise TraceParsingError(line_no=kwds["auxCrashData"].index("blah"))
            return mocker.DEFAULT

        nyx.crash_info.fromRawCrashData.side_effect = from_raw_mock

    def popen_create_crash(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        (nyx.corpus_out / "0" / "crashes" / "crash").touch()
        (nyx.corpus_out / "0" / "crashes" / "crash.log").write_text(inp_log)
        return result

    nyx.popen.side_effect = popen_create_crash
    if have_collector:
        if dupe:
            (tmp_path / "sig").touch()
            nyx.collector.search.return_value = (tmp_path / "sig", {})
        else:
            nyx.collector.search.return_value = (None, None)
            nyx.collector.submit.return_value = {
                "id": 1234,
                "shortSignature": "SecurityError: this looks bad",
            }
    else:
        assert not dupe
        nyx.collector = None

    # test
    nyx.main()

    # check
    assert nyx.run.call_count == 1
    args, kwds = nyx.run.call_args
    assert args[0][0] == nyx.asan_sym
    assert kwds["input"] == (
        f'{nyx.sharedir / "ld_preload_fuzz_no_pt.so"}\n'
        f'{nyx.sharedir / "firefox" / "firefox"}\n'
        "blah\n"
    )
    assert not (nyx.corpus_out / "0" / "crashes" / "crash.log").exists()
    assert (nyx.corpus_out / "0" / "crashes" / "crash.log.processed").exists()
    assert (
        nyx.corpus_out / "0" / "crashes" / "crash.log.processed"
    ).read_text() == inp_log
    if have_collector:
        assert not (nyx.corpus_out / "0" / "crashes" / "crash.log.symbolized").exists()
        if dupe:
            assert nyx.collector.submit.call_count == 0
        else:
            if fail_last_line:
                assert nyx.crash_info.fromRawCrashData.call_count == 2
                stderr = ["blah"]
                crashdata = "".join(inp_log.splitlines(keepends=True)[:-1])
            else:
                assert nyx.crash_info.fromRawCrashData.call_count == 1
                stderr = []
                # if symbolizer failed, crashdata should be unsymbolized
                crashdata = kwds["input"] if symbolize_ret else inp_log
            assert nyx.crash_info.fromRawCrashData.call_args == mocker.call(
                [],
                stderr,
                nyx.cfg.fromBinary.return_value,
                auxCrashData=crashdata.splitlines(),
            )
            assert nyx.collector.submit.call_count == 1
            assert nyx.collector.submit.call_args == mocker.call(
                nyx.crash_info.fromRawCrashData.return_value,
                str(nyx.corpus_out / "0" / "crashes" / "crash"),
                metaData={"afl-instance": "0", "afl-crash": "crash"},
            )
            assert nyx.collector.generate.call_count == 1
    elif not symbolize_ret:
        assert (
            nyx.corpus_out / "0" / "crashes" / "crash.log.symbolized"
        ).read_text() == (
            "ld_preload_fuzz_no_pt.so\n" "/home/user/firefox/firefox\n" "blah\n"
        )

    else:
        assert not (nyx.corpus_out / "0" / "crashes" / "crash.log.symbolized").is_file()


def test_nyx_05(mocker, nyx):
    """nyx async corpus mode"""
    # setup
    mocker.patch("os.environ", {})
    nyx.sleep.side_effect = chain(repeat(None, 124), [NyxMainBreak, None])
    nyx.args.nyx_async_corpus = True
    nyx.args.nyx_instances = 2
    orig_popen_cb = nyx.popen.side_effect

    def popen_check_corpus(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        corpus = Path(args[0][args[0].index("-i") + 1])
        assert corpus != nyx.corpus_in
        assert len(list(corpus.iterdir())) == 1
        assert next(corpus.iterdir()).read_text() in {"A", "B"}
        return result

    nyx.popen.side_effect = popen_check_corpus

    # test
    nyx.main()

    # check
    popen_calls = nyx.popen.call_args_list
    assert len(popen_calls) == 2
    main, sec = popen_calls
    assert main.kwargs["env"] == {
        "AFL_FINAL_SYNC": "1",
        "AFL_IMPORT_FIRST": "1",
        "AFL_NO_UI": "1",
    }
    assert sec.kwargs["env"] == {
        "AFL_NO_UI": "1",
    }
    assert (
        main.args[0][main.args[0].index("-i") + 1]
        == sec.args[0][sec.args[0].index("-i") + 1]
    )
    assert set(_get_path_args("-F", main.args[0])) == {nyx.corpus_in}
    assert nyx.corpus_in not in set(_get_path_args("-F", sec.args[0]))


def test_nyx_06(mocker, nyx, tmp_path):
    """nyx stats are written"""
    # setup
    stats = mocker.patch("guided_fuzzing_daemon.nyx.NyxStats", autospec=True)
    nyx.sleep.side_effect = chain(repeat(None, 100), [NyxMainBreak, None])
    nyx.args.stats = tmp_path / "stats"

    # test
    nyx.main()

    # stats should be written a few times in 100 loops
    assert stats.return_value.update_and_write.call_count > 3
    assert stats.return_value.update_and_write.call_args == mocker.call(
        tmp_path / "stats", [nyx.corpus_out / "0"]
    )


def test_nyx_07(nyx):
    """nyx exited processes are restarted"""
    # setup
    nyx.sleep.side_effect = chain(repeat(None, 200), [NyxMainBreak, None])
    is_terminated = nyx.popen.return_value.poll.side_effect

    def is_terminated_iter():
        while True:
            yield is_terminated()

    nyx.popen.return_value.poll.side_effect = chain(
        repeat(None, 30), [1], is_terminated_iter()
    )

    # test
    nyx.main()

    # exited process should have been restarted once
    assert nyx.popen.call_count == 2
    assert nyx.popen.return_value.terminate.call_count == 1


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
def test_nyx_08(capsys, hide, instances, nyx, pattern, tmp_path):
    """nyx exited processes are restarted"""
    # setup
    nyx.sleep.side_effect = chain(repeat(None, 124), [NyxMainBreak, None])
    nyx.args.afl_hide_logs = hide
    nyx.args.afl_log_pattern = str(tmp_path / f"afl{pattern}")
    nyx.args.nyx_instances = instances
    nyx.args.nyx_log_pattern = str(tmp_path / f"nyx{pattern}")

    out = []
    out_line = [None] * instances
    ctrs = [count(1) for _ in range(instances)]
    orig_sleep_iter = nyx.sleep.side_effect

    def sleep_write_logs(*args, **_kwds):
        # write to log files whenever sleep() is called in the nyx_main loop
        for args, _kwds in nyx.popen.call_args_list:
            idx = _instance_no(args)
            filename = nyx.args.afl_log_pattern
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

    nyx.sleep.side_effect = sleep_write_logs

    # test
    nyx.main()

    # logs should have been written to stdout
    stdio = capsys.readouterr()
    assert stdio.out.splitlines() == out
    # nyx log should have been given as env var
    for chld in nyx.popen.call_args_list:
        idx = _instance_no(chld.args)
        filename = nyx.args.nyx_log_pattern
        if pattern:
            filename = filename % (idx,)
        assert chld.kwargs["env"]["AFL_NYX_LOG"] == filename


def test_nyx_09a(mocker, tmp_path):
    """nyx stats calculation (positive)"""
    (tmp_path / "0").mkdir()
    (tmp_path / "0" / "fuzzer_stats").touch()
    mocker.patch.object(NyxStats, "add_sys_stats")
    stats = NyxStats(2)
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0"])
    assert not (tmp_path / "stats").exists()
    (tmp_path / "0" / "fuzzer_stats").write_text(
        "execs_done        : 77617\n"
        "execs_per_sec     : 22.64\n"
        "pending_favs      : 12\n"
        "pending_total     : 21\n"
        "corpus_variable   : 13\n"
        "saved_crashes     : 7\n"
        "saved_hangs       : 4\n"
        "exec_timeout      : 20000\n"
        "cycles_done       : 3\n"
        "bitmap_cvg        : 0.13%\n"
        "last_find         : 1696207996\n"
    )
    (tmp_path / "1").mkdir()
    (tmp_path / "1" / "fuzzer_stats").write_text(
        "execs_done        : 77617\n"
        "execs_per_sec     : 22.64\n"
        "pending_favs      : 24\n"
        "pending_total     : 21\n"
        "corpus_variable   : 13\n"
        "saved_crashes     : 1\n"
        "saved_hangs       : 9\n"
        "exec_timeout      : 30000\n"
        "cycles_done       : 1\n"
        "bitmap_cvg        : 0.04%\n"
        "last_find         : 1726207996\n"
        "random_crap       : who cares\n"
    )
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0", tmp_path / "1"])
    stat_lines = dict(
        map(str.strip, line.split(":", 1))
        for line in (tmp_path / "stats").read_text().splitlines()
    )
    assert stat_lines == {
        "execs_done": "155234 total (77617-77617 min/max)",
        "execs_per_sec": "45.28 total (22.64-22.64 min/max)",
        "pending_favs": "36",
        "pending_total": "42",
        "corpus_variable": "26",
        "saved_crashes": "8",
        "saved_hangs": "13",
        "exec_timeout": "25000",
        "cycles_done": "1 (1×), 3 (1×)",  # noqa: RUF001
        "bitmap_cvg": "0.09% avg (0.04%-0.13% min/max)",
        "last_find": "2024-09-13T06:13:16Z",
        "instances": "0/2",
    }


def test_nyx_09b(mocker, tmp_path):
    """nyx stats calculation (negative)"""
    (tmp_path / "0").mkdir()
    (tmp_path / "0" / "fuzzer_stats").touch()
    mocker.patch.object(NyxStats, "add_sys_stats")
    stats = NyxStats(1)
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0"])
    assert not (tmp_path / "stats").exists()
    (tmp_path / "0" / "fuzzer_stats").write_text(
        "execs_done        : 7.76.17\n"
        "execs_per_sec     : 22.64\n"
        "pending_favs      : 12\n"
        "pending_total     : 21\n"
        "corpus_variable   : 13\n"
        "saved_crashes     : 7\n"
        "saved_hangs       : 4\n"
        "cycles_done       : 3\n"
        "bitmap_cvg        : 0.13%\n"
        "last_find         : 1696207996\n"
    )
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0"])
    stat_lines = dict(
        map(str.strip, line.split(":", 1))
        for line in (tmp_path / "stats").read_text().splitlines()
    )
    assert stat_lines == {
        "execs_done": "0 total (nan-nan min/max)",
        "execs_per_sec": "22.64 total (22.64-22.64 min/max)",
        "pending_favs": "12",
        "pending_total": "21",
        "corpus_variable": "13",
        "saved_crashes": "7",
        "saved_hangs": "4",
        "exec_timeout": "nan",
        "cycles_done": "3 (1×)",  # noqa: RUF001
        "bitmap_cvg": "0.13% avg (0.13%-0.13% min/max)",
        "last_find": "2023-10-02T00:53:16Z",
        "instances": "0/1",
    }


def test_nyx_10(nyx, tmp_path):
    """nyx max runtime"""
    # setup
    nyx.args.max_runtime = 30.0
    nyx.sleep.side_effect = chain(repeat(None, 60), [NyxMainBreak, None])

    # test
    chdir(tmp_path)
    result = nyx_main(nyx.args, nyx.collector, nyx.s3m)

    assert result == 0


def test_nyx_11(mocker, nyx):
    """nyx multiple instances use different env vars and configurations"""
    # setup
    cfg1 = mocker.Mock(spec=ProgramConfiguration)
    cfg2 = mocker.Mock(spec=ProgramConfiguration)
    mocker.patch(
        "guided_fuzzing_daemon.nyx.create_envs",
        return_value=(
            ({"env1": "val1", "env2": "val2"}, {"env3": "val3", "env4": "val4"}),
            (cfg1, cfg2),
        ),
    )
    nyx.sleep.side_effect = chain(repeat(None, 64), [NyxMainBreak, None])
    inp_log = "ld_preload_fuzz_no_pt.so\n/home/user/firefox/firefox\nblah\n"
    nyx.run.return_value.stdout = inp_log
    nyx.run.return_value.stderr = "error\n"
    nyx.run.return_value.returncode = 0
    nyx.args.nyx_instances = 2
    orig_popen_cb = nyx.popen.side_effect

    def popen_create_crash(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        idx = _instance_no(args)
        (nyx.corpus_out / str(idx) / "crashes" / "crash").touch()
        (nyx.corpus_out / str(idx) / "crashes" / "crash.log").write_text(inp_log)
        return result

    nyx.popen.side_effect = popen_create_crash
    nyx.collector.search.return_value = (None, None)
    nyx.collector.submit.return_value = {
        "id": 1234,
        "shortSignature": "SecurityError: this looks bad",
    }

    # test
    nyx.main()

    # check
    assert nyx.popen.call_count == 2
    assert nyx.popen.call_args_list[0][1]["env"] == {
        "AFL_FINAL_SYNC": "1",
        "env1": "val1",
        "env2": "val2",
    }
    assert nyx.popen.call_args_list[1][1]["env"] == {
        "env3": "val3",
        "env4": "val4",
    }
    assert nyx.crash_info.fromRawCrashData.call_count == 2
    assert nyx.crash_info.fromRawCrashData.call_args_list == [
        mocker.call([], [], cfg1, auxCrashData=inp_log.splitlines()),
        mocker.call([], [], cfg2, auxCrashData=inp_log.splitlines()),
    ]


def test_nyx_12(mocker, nyx, tmp_path):
    """nyx additional corpus"""
    # setup
    mocker.patch("os.environ", {})
    nyx.sleep.side_effect = chain(repeat(None, 124), [NyxMainBreak, None])
    corpus_add = tmp_path / "corpus.add"
    nyx.args.nyx_add_corpus.append(corpus_add)
    nyx.args.nyx_instances = 2

    # test
    nyx.main()

    # check
    popen_calls = nyx.popen.call_args_list
    assert len(popen_calls) == 2
    main, sec = popen_calls
    assert set(_get_path_args("-F", main.args[0])) == {corpus_add}
    assert set(_get_path_args("-F", sec.args[0])) == {corpus_add}
