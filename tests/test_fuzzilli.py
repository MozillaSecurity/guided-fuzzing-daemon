# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import chain, count, repeat
from logging import DEBUG
from os import chdir
from pathlib import Path, PurePosixPath
from shutil import rmtree

import pytest
from Collector.Collector import Collector

from guided_fuzzing_daemon.fuzzilli import main
from guided_fuzzing_daemon.storage import (
    CloudStorageFile,
    CloudStorageProvider,
    ResourceType,
)


class MainBreak(Exception):
    """Break out of main loop"""


@pytest.fixture(name="fuzzilli")
def fuzzilli_common(mocker, tmp_path):
    """fuzzilli unittest boilerplate"""

    def storage_file_factory(path):
        file_type = mocker.Mock(spec=CloudStorageFile)
        file_type.return_value.path = PurePosixPath(path)
        return file_type()

    def iter_impl(prefix):
        if "/queues/" in str(prefix):
            yield storage_file_factory("project/queues/test.js")
        else:
            yield storage_file_factory("project/corpus/test.js")

    class _result:
        build_dir = tmp_path / "fuzzillibuilddir"
        args = mocker.Mock()
        autorunner = mocker.patch(
            "guided_fuzzing_daemon.fuzzilli.AutoRunner", autospec=True
        )
        cfg = mocker.patch(
            "guided_fuzzing_daemon.fuzzilli.ProgramConfiguration", autospec=True
        )
        collector = mocker.Mock(spec=Collector)
        corpus = tmp_path / "corpus"
        crash_info = mocker.patch(
            "guided_fuzzing_daemon.fuzzilli.CrashInfo", autospec=True
        )
        popen = mocker.patch("guided_fuzzing_daemon.fuzzilli.Popen", autospec=True)
        s3m = mocker.Mock(spec=CloudStorageProvider)
        s3m.iter.side_effect = iter_impl
        # set `side_effect=chain(repeat(None, <n>), [MainBreak])` to control how many
        # times the main loop will iterate before breaking
        sleep = mocker.patch(
            "guided_fuzzing_daemon.fuzzilli.sleep",
            autospec=True,
            side_effect=[MainBreak, None],
        )
        # time() increasing by 1.0s every call
        time = mocker.patch(
            "guided_fuzzing_daemon.fuzzilli.time",
            autospec=True,
            side_effect=count(1.0, 1.0),
        )
        warn_local = mocker.patch(
            "guided_fuzzing_daemon.fuzzilli.warn_local", autospec=True
        )

        def __init__(self):
            def is_terminated():
                if (
                    self.popen.return_value.terminate.call_count
                    or self.popen.return_value.kill.call_count
                ):
                    return 2
                return None

            self.popen.return_value.poll.side_effect = is_terminated
            self.popen.return_value.pid = 1337
            self.popen.return_value.returncode = 2

            def popen_touch_crashes(*_, **kwds):
                self.stdout = kwds["stdout"]  # pylint: disable=attribute-defined-outside-init
                if self.args.differential:
                    (self.corpus / "differentials").mkdir(exist_ok=True)
                else:
                    (self.corpus / "crashes").mkdir(exist_ok=True)
                return mocker.DEFAULT

            self.popen.side_effect = popen_touch_crashes
            (tmp_path / "firefox").mkdir(parents=True)
            binary = tmp_path / "firefox" / "firefox"
            binary.touch()
            self.build_dir.mkdir()
            (self.corpus / "corpus").mkdir(parents=True)
            (self.corpus / "corpus" / "test1.js").write_text("A")
            (self.corpus / "corpus" / "test2.js").write_text("B")

            self.args.fuzzilli_build_dir = self.build_dir
            self.args.bucket = "bucket"
            self.args.corpus_out = self.corpus
            self.args.corpus_refresh = False
            self.args.differential = False
            self.args.env = None
            self.args.env_percent = None
            self.args.instances = 1
            self.args.max_runtime = 0.0
            self.args.metadata = []
            self.args.project = "project"
            self.args.provider = "test"
            self.args.queue_upload = False
            self.args.rargs = [str(tmp_path / "firefox" / "firefox")]
            self.args.stats = None

        def ret_main(self):
            chdir(tmp_path)
            return main(self.args, self.collector, self.s3m)

        def main(self):
            chdir(tmp_path)
            with pytest.raises(MainBreak):
                return main(self.args, self.collector, self.s3m)

    yield _result()


@pytest.mark.parametrize("corpus", (True, False))
def test_fuzzilli_01(corpus, fuzzilli, mocker, tmp_path):
    """fuzzilli process startup"""
    # setup
    mocker.patch("os.environ", {"genv1": "gval1"})
    fuzzilli.sleep.side_effect = chain(repeat(None, 124), [MainBreak, None])
    fuzzilli.args.instances = 2
    fuzzilli.args.env = {"env1": "val1", "env2": "val2"}
    fuzzilli.args.metadata.extend(("meta1=metaval1", "meta2=metaval2"))
    if not corpus:
        # clear the corpus
        rmtree(fuzzilli.corpus / "corpus")

    # test
    fuzzilli.main()

    # check
    assert fuzzilli.popen.call_count == 1
    cfg_inst = fuzzilli.cfg.fromBinary.return_value
    assert cfg_inst.addEnvironmentVariables.call_args_list == [
        mocker.call({"env1": "val1", "env2": "val2"})
    ]
    assert cfg_inst.addMetadata.call_args_list == [
        mocker.call({"meta1": "metaval1", "meta2": "metaval2"})
    ]
    assert fuzzilli.popen.call_args.kwargs["cwd"] == fuzzilli.build_dir
    assert fuzzilli.popen.call_args.kwargs["env"] == {
        "LD_LIBRARY_PATH": str(tmp_path / "firefox"),
        "genv1": "gval1",
        "env1": "val1",
        "env2": "val2",
    }
    # check that terminate is called, not kill
    popen = fuzzilli.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 0


def test_fuzzilli_02(fuzzilli, mocker):
    """fuzzilli queue is uploaded"""
    # setup
    mocker.patch("guided_fuzzing_daemon.fuzzilli.QUEUE_UPLOAD_PERIOD", 90)
    fuzzilli.sleep.side_effect = chain(repeat(None, 60), [MainBreak, None])
    fuzzilli.args.queue_upload = True
    syncer = mocker.patch("guided_fuzzing_daemon.fuzzilli.CorpusSyncer", autospec=True)
    syncer.return_value.extra_queues = []

    # test
    fuzzilli.main()

    # check that upload is called once in the loop, once in finally
    assert syncer.call_count == 1
    assert syncer.call_args[0][1].path == fuzzilli.corpus / "corpus"
    assert syncer.return_value.upload_queue.call_count == 2


def test_fuzzilli_03a(fuzzilli):
    """fuzzilli subprocess is terminated then killed"""
    fuzzilli.time.side_effect = count(1.0, 0.1)
    fuzzilli.sleep.side_effect = chain(repeat(None, 64), [MainBreak], repeat(None))
    kill_delay = False

    def is_killed():
        if fuzzilli.popen.return_value.kill.call_count:
            nonlocal kill_delay
            if kill_delay:
                return 2
            kill_delay = True
        return None

    fuzzilli.popen.return_value.poll.side_effect = is_killed

    # test
    fuzzilli.main()

    # check that terminate is called, then kill
    popen = fuzzilli.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 1


def test_fuzzilli_03b(caplog, fuzzilli):
    """fuzzilli subprocess are terminated then killed but kill is ignored"""
    fuzzilli.args.max_runtime = 30.0
    fuzzilli.sleep.side_effect = chain(repeat(None, 60), [MainBreak], repeat(None))

    fuzzilli.popen.return_value.pid = 123
    fuzzilli.popen.return_value.poll.side_effect = repeat(None)
    fuzzilli.popen.return_value.returncode = 0

    # test
    result = fuzzilli.ret_main()

    # check that terminate is called, then kill
    assert result == 1
    popen = fuzzilli.popen.return_value
    assert popen.terminate.call_count == 1
    assert popen.poll.call_count > 0
    assert popen.kill.call_count == 1
    assert any(
        "123 did not exit after SIGKILL" in record.message for record in caplog.records
    )


def test_fuzzilli_04(fuzzilli, tmp_path):
    """fuzzilli max runtime"""
    # setup
    fuzzilli.args.max_runtime = 30.0
    fuzzilli.sleep.side_effect = chain(repeat(None, 60), [MainBreak, None])
    fuzzilli.popen.return_value.returncode = 0

    # test
    chdir(tmp_path)
    result = main(fuzzilli.args, fuzzilli.collector, fuzzilli.s3m)

    assert result == 0


@pytest.mark.parametrize(
    "have_collector, autorun_repro, differential",
    [
        pytest.param(False, True, False, id="no-collector"),
        pytest.param(True, True, False, id="report"),
        pytest.param(False, False, False, id="no-repro-no-collector"),
        pytest.param(True, False, False, id="no-repro-report"),
        pytest.param(True, False, True, id="no-repro-diff"),
        pytest.param(True, True, True, id="repro-diff"),  # autorunner not used w/ diff
    ],
)
def test_fuzzilli_05(autorun_repro, differential, fuzzilli, have_collector):
    """fuzzilli maybe re-run using AutoRunner and reported either way"""
    # setup
    fuzzilli.sleep.side_effect = chain(repeat(None, 32), [MainBreak, None])
    runner = fuzzilli.autorunner.fromBinaryArgs.return_value
    crash_info = runner.getCrashInfo.return_value
    crash_info.stdout = "blah\n"
    crash_info.stderr = "error\n"
    runner.run.return_value = autorun_repro
    orig_popen_cb = fuzzilli.popen.side_effect
    fuzzilli.args.differential = differential

    crash_dir = fuzzilli.corpus / ("differentials" if differential else "crashes")

    def popen_create_crash(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        (crash_dir / "README").touch()  # check that ignored
        (crash_dir / "program_crash.fzil").touch()
        (crash_dir / "program_crash.js").write_text(
            "// TARGET ARGS: ./js --reprl --crash-flag\n"
            "// CRASH INFO\n"
            "// #0 crash_func\n"
        )
        return result

    fuzzilli.popen.side_effect = popen_create_crash
    if have_collector:
        fuzzilli.collector.search.return_value = (None, None)
        fuzzilli.collector.submit.return_value = {
            "id": 1234,
            "shortSignature": "SecurityError: this looks bad",
        }
    else:
        fuzzilli.collector = None

    # test
    fuzzilli.main()

    # check
    if have_collector:
        if differential:
            assert (crash_dir / "program_crash.js.submitted").exists()
            assert runner.run.call_count == 0
            assert fuzzilli.crash_info.fromRawCrashData.call_count == 1
        else:
            if autorun_repro:
                assert (crash_dir / "program_crash.js.submitted").exists()
            else:
                assert (crash_dir / "program_crash.js.failed").exists()
            assert runner.run.call_count == 1
            if autorun_repro:
                assert fuzzilli.crash_info.fromRawCrashData.call_count == 0
            else:
                assert fuzzilli.crash_info.fromRawCrashData.call_count == 1
        assert fuzzilli.collector.submit.call_count == 1
    else:
        assert runner.run.call_count == 0
        assert not (crash_dir / "program_crash.js.submitted").is_file()
        assert not (crash_dir / "program_crash.js.failed").is_file()


def test_fuzzilli_06(fuzzilli, tmp_path):
    """fuzzilli stats are collected from stdout"""
    # setup
    fuzzilli.sleep.side_effect = chain(repeat(None, 32), [MainBreak, None])
    orig_popen_cb = fuzzilli.popen.side_effect
    fuzzilli.args.stats = tmp_path / "stats"

    def popen_write_stats(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        fuzzilli.stdout.write("Fuzzer Statistics\nstats: 1234\n\n\n")
        fuzzilli.stdout.seek(0)
        return result

    fuzzilli.popen.side_effect = popen_write_stats
    fuzzilli.collector = None

    # test
    fuzzilli.main()

    # stats should be written
    assert (tmp_path / "stats").read_text() == "Fuzzer Statistics\nstats: 1234\n"


def test_fuzzilli_07(caplog, fuzzilli):
    """fuzzilli debug is handled"""
    # setup
    fuzzilli.sleep.side_effect = chain(repeat(None, 32), [MainBreak, None])
    orig_popen_cb = fuzzilli.popen.side_effect

    def popen_print_output(*args, **kwds):
        result = orig_popen_cb(*args, **kwds)
        fuzzilli.stdout.write("hello world\n")
        fuzzilli.stdout.seek(0)
        return result

    fuzzilli.popen.side_effect = popen_print_output

    # test
    fuzzilli.main()

    # stdout is output on debug logger
    assert any(
        "hello world" in record.message
        for record in caplog.records
        if record.levelno == DEBUG
    )


def test_fuzzilli_08(fuzzilli):
    """fuzzilli exit is not restarted"""
    # setup
    fuzzilli.sleep.side_effect = chain(repeat(None, 200), [MainBreak, None])
    fuzzilli.popen.return_value.returncode = 0

    fuzzilli.popen.return_value.poll.side_effect = chain(repeat(None, 30), repeat(1))

    # test
    result = fuzzilli.ret_main()

    # exited process should have been restarted once
    assert result == 0
    assert fuzzilli.popen.call_count == 1
    assert fuzzilli.popen.return_value.terminate.call_count == 0


def test_fuzzilli_09(fuzzilli, mocker, tmp_path):
    """fuzzilli corpus refresh"""
    # setup
    stats = mocker.patch("guided_fuzzing_daemon.storage.StatAggregator", autospec=True)
    syncer = mocker.patch("guided_fuzzing_daemon.storage.CorpusSyncer", autospec=True)
    fuzzilli.args.corpus_refresh = tmp_path / "refresh"

    def fake_run(*_args, **kwds):
        (tmp_path / "refresh" / "tests" / "corpus").mkdir()
        (tmp_path / "refresh" / "tests" / "corpus" / "min.js").touch()
        assert "env" in kwds
        assert "LD_LIBRARY_PATH" in kwds["env"]
        ld_lib_path = tuple(Path(p) for p in kwds["env"]["LD_LIBRARY_PATH"].split(":"))
        assert {binary.parent} <= set(ld_lib_path)
        return mocker.DEFAULT

    binary = tmp_path / "firefox" / "firefox"
    fuzzilli.args.stats = tmp_path / "stats"
    fuzzilli.popen.side_effect = fake_run
    fuzzilli.popen.return_value.poll.side_effect = chain(repeat(None, 35), [0])
    fuzzilli.popen.return_value.wait.return_value = 0
    fuzzilli.sleep.side_effect = repeat(None)

    # test
    result = fuzzilli.ret_main()

    # check
    assert result == 0
    assert syncer.return_value.method_calls == [
        mocker.call.download_resource(ResourceType.CORPUS),
        mocker.call.download_resource(ResourceType.QUEUE),
        mocker.call.upload_corpus(),
        mocker.call.delete_queues(),
    ]
    assert stats.return_value.write_file.call_count == 2
