# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from functools import partial
from itertools import chain, count, repeat
from pathlib import Path
from queue import Empty

import pytest

from guided_fuzzing_daemon.libfuzzer import (
    LibFuzzerMonitor,
    libfuzzer_main,
    write_aggregated_stats_libfuzzer,
)
from guided_fuzzing_daemon.s3 import S3Manager


def test_libfuzzer_01(mocker, tmp_path):
    """monitor exit terminates main"""
    popen = mocker.patch("guided_fuzzing_daemon.libfuzzer.Popen")
    cfg = mocker.patch("guided_fuzzing_daemon.libfuzzer.ProgramConfiguration")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.run")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.test_binary_asan")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.warn_local")
    writer = mocker.patch(
        "guided_fuzzing_daemon.libfuzzer.write_aggregated_stats_libfuzzer"
    )
    monitor = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerMonitor")
    mocker.patch("os.environ", {"genv1": "gval1"})
    monitor.return_value.is_alive.return_value = False
    monitor.return_value.inited = True
    monitor.return_value.exc = None
    queue = mocker.patch("guided_fuzzing_daemon.libfuzzer.Queue")
    queue.return_value.get.side_effect = chain([0], repeat(Empty))

    args = mocker.Mock()
    collector = mocker.Mock()
    s3m = mocker.Mock(spec=S3Manager)

    binary = tmp_path / "firefox"
    binary.touch()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    args.env = ["env1=val1", "env2=val2"]
    args.libfuzzer_auto_reduce = 5
    args.libfuzzer_auto_reduce_min = 1000
    args.libfuzzer_instances = 1
    args.libfuzzer_restarts = 1
    args.metadata = ["meta1=metaval1", "meta2=metaval2"]
    args.rargs = [str(binary), str(corpus)]
    args.stats = None
    assert libfuzzer_main(args, collector, s3m) == 0
    assert monitor.call_count == 1
    assert queue.return_value.get.call_count == 2
    assert writer.call_count == 0
    cfg_inst = cfg.fromBinary.return_value
    assert cfg_inst.addEnvironmentVariables.call_args_list == [
        mocker.call({"env1": "val1", "env2": "val2"})
    ]
    assert cfg_inst.addMetadata.call_args_list == [
        mocker.call({"meta1": "metaval1", "meta2": "metaval2"})
    ]
    assert popen.call_args.kwargs["env"] == {
        "LD_LIBRARY_PATH": str(tmp_path),
        "genv1": "gval1",
        "env1": "val1",
        "env2": "val2",
    }
    assert cfg_inst.addProgramArguments.call_args_list == [mocker.call([str(corpus)])]


def test_libfuzzer_02(mocker, tmp_path):
    """libfuzzer-restarts determines number of tries before exit"""
    mocker.patch("guided_fuzzing_daemon.libfuzzer.Popen")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.ProgramConfiguration")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.run")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.test_binary_asan")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.warn_local")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.write_aggregated_stats_libfuzzer")
    monitor = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerMonitor")
    monitor.return_value.is_alive.return_value = False
    monitor.return_value.inited = True
    monitor.return_value.exc = None
    queue = mocker.patch("guided_fuzzing_daemon.libfuzzer.Queue")
    # queue.get indicates the monitor exited (which means the target exited)
    queue.return_value.get.side_effect = chain([0] * 10, repeat(Empty))

    args = mocker.Mock()
    collector = mocker.Mock()
    s3m = mocker.Mock(spec=S3Manager)

    binary = tmp_path / "firefox"
    binary.touch()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    args.env = []
    args.libfuzzer_auto_reduce = 5
    args.libfuzzer_auto_reduce_min = 1000
    args.libfuzzer_instances = 1
    args.libfuzzer_restarts = 10
    args.metadata = []
    args.rargs = [str(binary), str(corpus)]
    args.stats = None
    assert libfuzzer_main(args, collector, s3m) == 0
    assert queue.return_value.get.call_count == 11


def test_libfuzzer_03(mocker, tmp_path):
    """libfuzzer-instances creates multiple monitors"""
    mocker.patch("guided_fuzzing_daemon.libfuzzer.Popen")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.ProgramConfiguration")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.run")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.test_binary_asan")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.warn_local")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.write_aggregated_stats_libfuzzer")
    monitor = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerMonitor")
    monitor.return_value.is_alive.return_value = False
    monitor.return_value.inited = True
    monitor.return_value.exc = None
    queue = mocker.patch("guided_fuzzing_daemon.libfuzzer.Queue")
    queue.return_value.get.side_effect = chain([0, 1, 2], repeat(Empty))

    args = mocker.Mock()
    collector = mocker.Mock()
    s3m = mocker.Mock(spec=S3Manager)

    binary = tmp_path / "firefox"
    binary.touch()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    args.env = []
    args.libfuzzer_auto_reduce = 5
    args.libfuzzer_auto_reduce_min = 1000
    args.libfuzzer_instances = 3
    args.libfuzzer_restarts = 3
    args.metadata = []
    args.rargs = [str(binary), str(corpus)]
    args.stats = None
    assert libfuzzer_main(args, collector, s3m) == 0
    assert monitor.call_count == 3
    assert queue.return_value.get.call_count == 3


def test_libfuzzer_04(mocker, tmp_path):
    """stats are written"""
    mocker.patch("guided_fuzzing_daemon.libfuzzer.CrashInfo")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.Popen")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.ProgramConfiguration")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.run")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.test_binary_asan")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.warn_local")
    writer = mocker.patch(
        "guided_fuzzing_daemon.libfuzzer.write_aggregated_stats_libfuzzer"
    )
    monitor = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerMonitor")
    monitor.return_value.is_alive.return_value = False
    monitor.return_value.inited = True
    monitor.return_value.exc = None
    monitor.return_value.get_testcase.return_value.name = "crash-"
    queue = mocker.patch("guided_fuzzing_daemon.libfuzzer.Queue")
    queue.return_value.get.side_effect = chain([Empty, 0], repeat(Empty))

    args = mocker.Mock()
    collector = mocker.Mock()
    collector.search.return_value = (None, None)
    s3m = mocker.Mock(spec=S3Manager)

    binary = tmp_path / "firefox"
    binary.touch()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    args.env = []
    args.libfuzzer_auto_reduce = 5
    args.libfuzzer_auto_reduce_min = 1000
    args.libfuzzer_instances = 1
    args.libfuzzer_restarts = 1
    args.metadata = []
    args.rargs = [str(binary), str(corpus)]
    args.stats = True
    assert libfuzzer_main(args, collector, s3m) == 0
    assert monitor.call_count == 1
    assert queue.return_value.get.call_count == 3
    assert writer.call_count > 0


def test_libfuzzer_05(mocker, tmp_path, capsys):
    """negative arg tests"""
    mocker.patch("guided_fuzzing_daemon.libfuzzer.Popen")
    cfg = mocker.patch("guided_fuzzing_daemon.libfuzzer.ProgramConfiguration")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.run")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
    asan_test = mocker.patch("guided_fuzzing_daemon.libfuzzer.test_binary_asan")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.warn_local")
    mocker.patch("guided_fuzzing_daemon.libfuzzer.write_aggregated_stats_libfuzzer")
    monitor = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerMonitor")
    monitor.return_value.is_alive.return_value = False
    monitor.return_value.inited = True
    monitor.return_value.exc = None
    queue = mocker.patch("guided_fuzzing_daemon.libfuzzer.Queue")
    queue.return_value.get.side_effect = chain([0], repeat(Empty))

    args = mocker.Mock()
    collector = mocker.Mock()
    s3m = mocker.Mock(spec=S3Manager)

    binary = tmp_path / "firefox"
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    args.env = []
    args.libfuzzer_auto_reduce = 5
    args.libfuzzer_auto_reduce_min = 1000
    args.libfuzzer_instances = 1
    args.libfuzzer_restarts = 1
    args.metadata = []
    args.rargs = [str(binary)]
    args.stats = None
    assert libfuzzer_main(args, collector, s3m) == 2
    stdio = capsys.readouterr()
    assert "binary does not exist" in stdio.err
    binary.touch()

    assert libfuzzer_main(args, collector, s3m) == 2
    stdio = capsys.readouterr()
    assert "corpus directory" in stdio.err
    args.rargs.append(str(corpus))

    asan_test.return_value = False
    assert libfuzzer_main(args, collector, s3m) == 2
    stdio = capsys.readouterr()
    assert "binaries built with AddressSanitizer" in stdio.err

    cfg.fromBinary.return_value = None
    assert libfuzzer_main(args, collector, s3m) == 2
    stdio = capsys.readouterr()
    assert "load program configuration" in stdio.err


def test_libfuzzer_monitor_01(mocker):
    """libfuzzer monitor tests"""
    proc = mocker.Mock()
    proc.stderr.readline.side_effect = ["Test unit written to blah", ""]
    queue = mocker.Mock()
    mon = LibFuzzerMonitor(proc, mid=0, mqueue=queue)
    mon.run()
    assert mon.get_testcase() == Path("blah")
    assert mon.get_stderr() == ["Test unit written to blah"]
    assert not mon.get_asan_trace()
    assert queue.put.call_args_list == [mocker.call(0)]
    assert mon.exc is None
    assert not mon.inited
    assert mon.last_new_pc == 0


def test_libfuzzer_monitor_02(mocker):
    """libfuzzer monitor exception"""
    err = Exception("123")
    proc = mocker.Mock()
    proc.stderr.readline.side_effect = err
    mon = LibFuzzerMonitor(proc)
    mon.run()
    assert mon.exc is err


@pytest.mark.parametrize("evt", "INITED|NEW|RELOAD|REDUCE|pulse".split("|"))
def test_libfuzzer_monitor_03(mocker, evt):
    """libfuzzer monitor stats"""
    time_counter = partial(next, count(1))
    mocker.patch("guided_fuzzing_daemon.libfuzzer.time", side_effect=time_counter)

    proc = mocker.Mock()
    proc.stderr.readline.side_effect = [
        f"#700 {evt} cov: 123 exec/s: 5 rss: 16Mb ft: 12",
        "#701 NEW_PC: 0x",
        "",
    ]
    mon = LibFuzzerMonitor(proc)
    mon.run()
    assert mon.get_stderr() == [
        f"#700 {evt} cov: 123 exec/s: 5 rss: 16Mb ft: 12",
        "#701 NEW_PC: 0x",
    ]
    assert mon.get_testcase() is None
    assert not mon.get_asan_trace()
    assert mon.exc is None
    assert mon.inited == bool(evt == "INITED")
    if evt == "NEW":
        assert mon.last_new == 1
        assert mon.last_new_pc == 2
    else:
        assert mon.last_new == 0
        assert mon.last_new_pc == 1
    assert mon.execs_done == 700
    assert mon.cov == 123
    assert mon.execs_per_sec == 5
    assert mon.rss_mb == 16
    assert mon.feat == 12


def test_libfuzzer_monitor_04(mocker):
    """libfuzzer monitor trace collection"""
    time_counter = partial(next, count(1))
    mocker.patch("guided_fuzzing_daemon.libfuzzer.time", side_effect=time_counter)

    proc = mocker.Mock()
    proc.stderr.readline.side_effect = [
        "==ERROR: AddressSanitizer",
        "crash data",
        "==ABORTING",
        "non-crash data",
        "",
    ]
    mon = LibFuzzerMonitor(proc)
    mon.run()
    assert mon.get_stderr() == ["==ABORTING", "non-crash data"]
    assert mon.get_testcase() is None
    assert mon.get_asan_trace() == [
        "==ERROR: AddressSanitizer",
        "crash data",
        "==ABORTING",
    ]
    assert mon.exc is None
    assert not mon.in_trace


def test_libfuzzer_monitor_05(mocker, tmp_path):
    """libfuzzer monitor thread limit ignores testcase"""
    testcase = tmp_path / "test"
    testcase.touch()
    proc = mocker.Mock()
    proc.stderr.readline.side_effect = [
        f"Test unit written to {testcase}",
        "==AddressSanitizer: Thread limit",
        "",
    ]
    mon = LibFuzzerMonitor(proc)
    mon.run()
    assert mon.get_stderr() == [
        f"Test unit written to {testcase}",
        "==AddressSanitizer: Thread limit",
    ]
    assert not mon.get_asan_trace()
    assert mon.exc is None
    assert not mon.inited
    # testcase was removed
    assert mon.get_testcase() is None
    assert not testcase.exists()


@pytest.mark.parametrize("kill_on_oom", (True, False))
def test_libfuzzer_monitor_06(mocker, kill_on_oom):
    """libfuzzer monitor kill on oom honoured"""
    proc = mocker.Mock()
    proc.stderr.readline.side_effect = ["ERROR: libFuzzer: out-of-memory", ""]
    mon = LibFuzzerMonitor(proc, kill_on_oom=kill_on_oom)
    mon.run()
    assert mon.get_stderr() == ["ERROR: libFuzzer: out-of-memory"]
    assert not mon.get_asan_trace()
    assert mon.exc is None
    assert proc.kill.call_count == int(kill_on_oom)
    assert mon.had_oom == kill_on_oom


def test_libfuzzer_monitor_07(mocker):
    """libfuzzer monitor terminate"""
    sleep = mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
    proc = mocker.Mock()
    mon = LibFuzzerMonitor(proc)
    proc.poll.return_value = None
    mon.terminate()
    assert proc.terminate.call_count == 1
    assert sleep.call_count > 10
    assert proc.poll.call_count == sleep.call_count + 2
    assert proc.kill.call_count == 1
    assert proc.wait.call_count == 1

    proc.reset_mock()
    sleep.reset_mock()
    proc.poll.return_value = 1
    mon.terminate()
    assert proc.terminate.call_count == 1
    assert sleep.call_count == 0
    assert proc.poll.call_count == 2
    assert proc.kill.call_count == 0
    assert proc.wait.call_count == 0


def test_libfuzzer_stats_01(mocker):
    """libfuzzer write stats"""
    outf = mocker.Mock()
    warns = mocker.Mock()

    global_stats = {
        "corpus_size": 500,
        "next_auto_reduce": 1000,
        "crashes": 12,
        "timeouts": 50,
        "ooms": 3333,
        "execs_done": 100,
        "last_new": 0,
        "last_new_pc": 0,
    }

    mon1 = LibFuzzerMonitor(mocker.Mock())
    mon1.cov = 10
    mon1.feat = 20
    mon1.execs_done = 30
    mon1.execs_per_sec = 40
    mon1.rss_mb = 50
    mon1.last_new = 60
    mon1.last_new_pc = 70

    mon2 = LibFuzzerMonitor(mocker.Mock())
    mon2.cov = 5
    mon2.feat = 15
    mon2.execs_done = 25
    mon2.execs_per_sec = 35
    mon2.rss_mb = 45
    mon2.last_new = 55
    mon2.last_new_pc = 65

    monitors = [mon1, mon2]

    write_stats = mocker.patch("guided_fuzzing_daemon.libfuzzer.write_stats_file")
    write_aggregated_stats_libfuzzer(outf, global_stats, monitors, warns)
    assert write_stats.call_args_list == [
        mocker.call(
            outf,
            [
                "execs_done",
                "execs_per_sec",
                "rss_mb",
                "corpus_size",
                "next_auto_reduce",
                "crashes/timeouts/ooms",
                "cov",
                "feat",
                "last_new",
                "last_new_pc",
            ],
            {
                "cov": "5-10 min/max",
                "feat": "15-20 min/max",
                "execs_done": 155,
                "execs_per_sec": "75 total (35-40 min/max)",
                "rss_mb": "95 total (45-50 min/max)",
                "corpus_size": 500,
                "next_auto_reduce": 1000,
                "crashes": 12,
                "timeouts": 50,
                "ooms": 3333,
                "crashes/timeouts/ooms": "12, 50, 3333",
                "last_new": "1970-01-01T00:01:00Z",
                "last_new_pc": "1970-01-01T00:01:10Z",
            },
            warns,
        )
    ]
    assert global_stats == {
        "corpus_size": 500,
        "next_auto_reduce": 1000,
        "crashes": 12,
        "timeouts": 50,
        "ooms": 3333,
        "execs_done": 100,
        "last_new": 60,
        "last_new_pc": 70,
    }
    global_stats["last_new"] = 100
    write_stats.reset_mock()
    write_aggregated_stats_libfuzzer(outf, global_stats, monitors, warns)
    assert write_stats.call_args_list == [
        mocker.call(
            outf,
            [
                "execs_done",
                "execs_per_sec",
                "rss_mb",
                "corpus_size",
                "next_auto_reduce",
                "crashes/timeouts/ooms",
                "cov",
                "feat",
                "last_new",
                "last_new_pc",
            ],
            {
                "cov": "5-10 min/max",
                "feat": "15-20 min/max",
                "execs_done": 155,
                "execs_per_sec": "75 total (35-40 min/max)",
                "rss_mb": "95 total (45-50 min/max)",
                "corpus_size": 500,
                "next_auto_reduce": 1000,
                "crashes": 12,
                "timeouts": 50,
                "ooms": 3333,
                "crashes/timeouts/ooms": "12, 50, 3333",
                "last_new": "1970-01-01T00:01:40Z",
                "last_new_pc": "1970-01-01T00:01:10Z",
            },
            warns,
        )
    ]
