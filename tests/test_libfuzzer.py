# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from functools import partial
from itertools import chain, count, repeat
from os import chdir
from pathlib import Path, PurePosixPath
from queue import Empty

import pytest

from guided_fuzzing_daemon.libfuzzer import (
    LibFuzzerMonitor,
    LibFuzzerStats,
    libfuzzer_main,
)
from guided_fuzzing_daemon.storage import CloudStorageFile, CloudStorageProvider


@pytest.fixture(name="libf")
def libfuzzer_common(mocker, tmp_path):
    """libfuzzer unittest boilerplate"""

    def storage_file_factory(path):
        file_type = mocker.Mock(spec=CloudStorageFile)
        file_type.return_value.path = PurePosixPath(path)
        return file_type()

    def iter_impl(prefix):
        if "/queues/" in str(prefix):
            yield storage_file_factory("project/queues/test.bin")
        else:
            yield storage_file_factory("project/corpus/test.bin")

    class _result:
        args = mocker.Mock()
        asan_test = mocker.patch("guided_fuzzing_daemon.libfuzzer.test_binary_asan")
        cfg = mocker.patch("guided_fuzzing_daemon.libfuzzer.ProgramConfiguration")
        collector = mocker.Mock()
        mocker.patch("guided_fuzzing_daemon.libfuzzer.warn_local")
        monitor = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerMonitor")
        popen = mocker.patch("guided_fuzzing_daemon.libfuzzer.Popen")
        queue = mocker.patch("guided_fuzzing_daemon.libfuzzer.Queue")
        mocker.patch("guided_fuzzing_daemon.libfuzzer.run")
        s3m = mocker.Mock(spec=CloudStorageProvider)
        s3m.iter.side_effect = iter_impl
        mocker.patch("guided_fuzzing_daemon.libfuzzer.sleep")
        writer = mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerStats")

        def __init__(self):
            self.monitor.return_value.exc = None
            self.monitor.return_value.inited = True
            self.monitor.return_value.is_alive.return_value = False

            binary = tmp_path / "firefox"
            binary.touch()
            corpus = tmp_path / "corpus"
            corpus.mkdir()
            chdir(tmp_path)

            self.args.bucket = "bucket"
            self.args.corpus_refresh = False
            self.args.env = None
            self.args.env_percent = None
            self.args.instances = 1
            self.args.libfuzzer_auto_reduce = 5
            self.args.libfuzzer_auto_reduce_min = 1000
            self.args.libfuzzer_restarts = 1
            self.args.metadata = []
            self.args.project = "project"
            self.args.provider = "test"
            self.args.rargs = [str(binary), str(corpus)]
            self.args.stats = None

        def ret_main(self):
            return libfuzzer_main(self.args, self.collector, self.s3m)

    yield _result()


def test_libfuzzer_01(libf, mocker, tmp_path):
    """monitor exit terminates main"""
    mocker.patch("os.environ", {"genv1": "gval1"})
    libf.queue.return_value.get.side_effect = chain([0], repeat(Empty))
    libf.args.env = {"env1": "val1", "env2": "val2"}
    libf.args.metadata = ["meta1=metaval1", "meta2=metaval2"]
    corpus = libf.args.rargs[-1]

    assert libf.ret_main() == 0
    assert libf.monitor.call_count == 1
    assert libf.queue.return_value.get.call_count == 2
    assert libf.writer.update_and_write.call_count == 0
    cfg_inst = libf.cfg.fromBinary.return_value
    assert cfg_inst.addEnvironmentVariables.call_args_list == [
        mocker.call({"env1": "val1", "env2": "val2"})
    ]
    assert cfg_inst.addMetadata.call_args_list == [
        mocker.call({"meta1": "metaval1", "meta2": "metaval2"})
    ]
    assert libf.popen.call_args.kwargs["env"] == {
        "LD_LIBRARY_PATH": str(tmp_path),
        "genv1": "gval1",
        "env1": "val1",
        "env2": "val2",
    }
    assert cfg_inst.addProgramArguments.call_args_list == [mocker.call([corpus])]


def test_libfuzzer_02(libf):
    """libfuzzer-restarts determines number of tries before exit"""
    # queue.get indicates the monitor exited (which means the target exited)
    libf.queue.return_value.get.side_effect = chain([0] * 10, repeat(Empty))
    libf.args.libfuzzer_restarts = 10

    assert libf.ret_main() == 0
    assert libf.queue.return_value.get.call_count == 11


def test_libfuzzer_03(libf):
    """libfuzzer-instances creates multiple monitors"""
    libf.queue.return_value.get.side_effect = chain([0, 1, 2], repeat(Empty))
    libf.args.instances = 3
    libf.args.libfuzzer_restarts = 3

    assert libf.ret_main() == 0
    assert libf.monitor.call_count == 3
    assert libf.queue.return_value.get.call_count == 3


def test_libfuzzer_04(libf, mocker):
    """stats are written"""
    mocker.patch("guided_fuzzing_daemon.libfuzzer.CrashInfo")
    libf.monitor.return_value.get_testcase.return_value.name = "crash-"
    libf.queue.return_value.get.side_effect = chain([Empty, 0], repeat(Empty))
    libf.collector.search.return_value = (None, None)
    libf.args.stats = True

    assert libf.ret_main() == 0
    assert libf.monitor.call_count == 1
    assert libf.queue.return_value.get.call_count == 3
    assert libf.writer.call_count > 0


def test_libfuzzer_05(caplog, libf, tmp_path):
    """negative arg tests"""
    libf.queue.return_value.get.side_effect = chain([0], repeat(Empty))
    (tmp_path / "firefox").unlink()
    binary, corpus = map(Path, libf.args.rargs)
    libf.args.rargs.pop()

    assert libf.ret_main() == 2
    assert any("binary does not exist" in record.message for record in caplog.records)
    binary.touch()

    assert libf.ret_main() == 2
    assert any("corpus directory" in record.message for record in caplog.records)
    libf.args.rargs.append(str(corpus))

    libf.args.rargs.append("-jobs=")
    assert libf.ret_main() == 2
    assert any(
        "-jobs and -workers is incompatible" in record.message
        for record in caplog.records
    )
    libf.args.rargs[-1] = "-workers="
    assert libf.ret_main() == 2
    assert any(
        "-jobs and -workers is incompatible" in record.message
        for record in caplog.records
    )
    libf.args.rargs.pop()

    libf.asan_test.return_value = False
    assert libf.ret_main() == 2
    assert any(
        "binaries built with AddressSanitizer" in record.message
        for record in caplog.records
    )

    libf.cfg.fromBinary.return_value = None
    assert libf.ret_main() == 2
    assert any(
        "load program configuration" in record.message for record in caplog.records
    )


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
    mon = LibFuzzerMonitor(proc, 0, mocker.Mock())
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
    mon = LibFuzzerMonitor(proc, 0, mocker.Mock())
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
    mon = LibFuzzerMonitor(proc, 0, mocker.Mock())
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
    mon = LibFuzzerMonitor(proc, 0, mocker.Mock())
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
    mon = LibFuzzerMonitor(proc, 0, mocker.Mock(), kill_on_oom=kill_on_oom)
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
    mon = LibFuzzerMonitor(proc, 0, mocker.Mock())
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

    mocker.patch("guided_fuzzing_daemon.libfuzzer.LibFuzzerStats.add_sys_stats")
    stats = LibFuzzerStats()
    stats.fields["corpus_size"].update(500)
    stats.fields["next_auto_reduce"].update(1000)
    stats.fields["crashes"].update(12)
    stats.fields["timeouts"].update(50)
    stats.fields["ooms"].update(3333)
    stats.fields["execs_done"].add_to_base(100)

    mon1 = LibFuzzerMonitor(mocker.Mock(), 0, mocker.Mock())
    mon1.cov = 10
    mon1.feat = 20
    mon1.execs_done = 30
    mon1.execs_per_sec = 40
    mon1.rss_mb = 50
    mon1.last_new = 60
    mon1.last_new_pc = 70

    mon2 = LibFuzzerMonitor(mocker.Mock(), 0, mocker.Mock())
    mon2.cov = 5
    mon2.feat = 15
    mon2.execs_done = 25
    mon2.execs_per_sec = 35
    mon2.rss_mb = 45
    mon2.last_new = 55
    mon2.last_new_pc = 65

    monitors = [mon1, mon2]

    stats.write_file = mocker.Mock()
    stats.update_and_write(outf, monitors, warns)
    assert stats.write_file.call_args_list == [mocker.call(outf, warns)]
    assert str(stats.fields["cov"]) == "5-10 min/max"
    assert str(stats.fields["feat"]) == "15-20 min/max"
    assert str(stats.fields["execs_done"]) == "155"
    assert str(stats.fields["execs_per_sec"]) == "75 total (35-40 min/max)"
    assert str(stats.fields["rss_mb"]) == "95 total (45-50 min/max)"
    assert str(stats.fields["corpus_size"]) == "500"
    assert str(stats.fields["next_auto_reduce"]) == "1000"
    assert str(stats.fields["crashes"]) == "12"
    assert str(stats.fields["timeouts"]) == "50"
    assert str(stats.fields["ooms"]) == "3333"
    assert str(stats.fields["crashes/timeouts/ooms"]) == "12, 50, 3333"
    assert str(stats.fields["last_new"]) == "1970-01-01T00:01:00Z"
    assert str(stats.fields["last_new_pc"]) == "1970-01-01T00:01:10Z"

    stats.fields["last_new"].update(100)
    stats.write_file.reset_mock()
    stats.update_and_write(outf, monitors, warns)
    assert stats.write_file.call_args_list == [mocker.call(outf, warns)]
    assert str(stats.fields["cov"]) == "5-10 min/max"
    assert str(stats.fields["feat"]) == "15-20 min/max"
    assert str(stats.fields["execs_done"]) == "155"
    assert str(stats.fields["execs_per_sec"]) == "75 total (35-40 min/max)"
    assert str(stats.fields["rss_mb"]) == "95 total (45-50 min/max)"
    assert str(stats.fields["corpus_size"]) == "500"
    assert str(stats.fields["next_auto_reduce"]) == "1000"
    assert str(stats.fields["crashes"]) == "12"
    assert str(stats.fields["timeouts"]) == "50"
    assert str(stats.fields["ooms"]) == "3333"
    assert str(stats.fields["crashes/timeouts/ooms"]) == "12, 50, 3333"
    assert str(stats.fields["last_new"]) == "1970-01-01T00:01:40Z"
    assert str(stats.fields["last_new_pc"]) == "1970-01-01T00:01:10Z"


def test_libfuzzer_refresh_01(libf, mocker, tmp_path):
    """libFuzzer corpus refresh"""
    # setup
    stats = mocker.patch("guided_fuzzing_daemon.storage.StatAggregator", autospec=True)
    syncer = mocker.patch("guided_fuzzing_daemon.storage.CorpusSyncer", autospec=True)
    libf.args.corpus_refresh = tmp_path / "refresh"

    def fake_run(*args, **kwds):
        (tmp_path / "refresh" / "tests" / "min.bin").touch()
        assert "-merge=1" in args[0]
        assert "env" in kwds
        assert "LD_LIBRARY_PATH" in kwds["env"]
        ld_lib_path = {Path(p) for p in kwds["env"]["LD_LIBRARY_PATH"].split(":")}
        assert binary.parent in ld_lib_path
        return mocker.DEFAULT

    binary = tmp_path / "firefox"
    libf.args.stats = tmp_path / "stats"
    libf.popen.side_effect = fake_run
    libf.popen.return_value.poll.side_effect = chain(repeat(None, 35), [0])
    libf.popen.return_value.wait.return_value = 0

    # test
    result = libf.ret_main()

    # check
    assert result == 0
    assert syncer.return_value.method_calls == [
        mocker.call.download_corpus(),
        mocker.call.download_queues(),
        mocker.call.upload_corpus(delete_existing=True),
        mocker.call.delete_queues(),
    ]
    assert stats.return_value.write_file.call_count == 2
