# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
import re
from argparse import Namespace
from collections import deque
from logging import getLogger
from pathlib import Path
from queue import Empty, Queue
from shutil import move, rmtree
from subprocess import DEVNULL, PIPE, Popen, run
from tempfile import mkdtemp
from threading import Thread
from time import sleep, time
from typing import cast

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

from .stats import (
    STATS_UPLOAD_PERIOD,
    GeneratedField,
    JoinField,
    MaxTimeField,
    MinMaxField,
    StatAggregator,
    SumField,
    SumMinMaxField,
)
from .storage import (
    QUEUE_UPLOAD_PERIOD,
    CloudStorageProvider,
    Corpus,
    CorpusRefreshContext,
    CorpusSyncer,
)
from .utils import apply_transform, create_envs, test_binary_asan, warn_local

LOG = getLogger("gfd.libfuzzer")
RE_LIBFUZZER_STATUS = re.compile(
    r"\s*#(\d+)\s+(INITED|NEW|RELOAD|REDUCE|pulse)\s+cov: (\d+)"
)
RE_LIBFUZZER_NEWPC = re.compile(r"\s+NEW_PC:\s+0x")
RE_LIBFUZZER_EXECS = re.compile(r"\s+exec/s: (\d+)")
RE_LIBFUZZER_RSS = re.compile(r"\s+rss: (\d+)Mb")
RE_LIBFUZZER_FEAT = re.compile(r"\s+ft: (\d+)")

# Used to set initialized to true, as the INITED message is not present with an empty
# corpus
NO_CORPUS_MSG = "INFO: A corpus is not provided, starting from an empty corpus"
OOM_WAIT = 30


class LibFuzzerMonitor(Thread):
    def __init__(
        self,
        process: Popen[str],
        mid: int,
        mqueue: Queue[int],
        kill_on_oom: bool = True,
    ) -> None:
        Thread.__init__(self)

        self.process = process
        stderr = process.stderr
        assert stderr is not None
        self.process_stderr = stderr
        self.trace: list[str] = []
        self.stderr: deque[str] = deque([], 128)
        self.in_trace = False
        self.testcase: Path | None = None
        self.kill_on_oom = kill_on_oom
        self.had_oom = False
        self.hit_thread_limit = False
        self.inited = False
        self.mid = mid
        self.mqueue: Queue[int] | None = mqueue

        # Keep some statistics
        self.cov = 0
        self.feat = 0
        self.execs_done = 0
        self.execs_per_sec = 0
        self.rss_mb = 0
        self.last_new = 0
        self.last_new_pc = 0

        # Store potential exceptions
        self.exc: Exception | None = None

    def run(self) -> None:
        assert not self.hit_thread_limit
        assert not self.had_oom
        oom_detected: float | None = None

        try:
            while True:
                line = self.process_stderr.readline(4096)

                if not line:
                    break

                status_match = RE_LIBFUZZER_STATUS.search(line)

                if status_match is not None:
                    self.execs_done = int(status_match.group(1))
                    self.cov = int(status_match.group(3))

                    if status_match.group(2) == "NEW":
                        self.last_new = int(time())

                    exec_match = RE_LIBFUZZER_EXECS.search(line)
                    rss_match = RE_LIBFUZZER_RSS.search(line)
                    feat_match = RE_LIBFUZZER_FEAT.search(line)

                    if exec_match is not None:
                        self.execs_per_sec = int(exec_match.group(1))
                    if rss_match is not None:
                        self.rss_mb = int(rss_match.group(1))
                    if feat_match is not None:
                        self.feat = int(feat_match.group(1))

                elif RE_LIBFUZZER_NEWPC.search(line) is not None:
                    self.last_new_pc = int(time())

                elif self.in_trace:
                    self.trace.append(line.rstrip())
                    if line.find("==ABORTING") >= 0:
                        self.in_trace = False

                elif line.find("==ERROR: AddressSanitizer") >= 0:
                    self.trace.append(line.rstrip())
                    self.in_trace = True

                elif line.find("==AddressSanitizer: Thread limit") >= 0:
                    self.hit_thread_limit = True

                if not self.in_trace:
                    self.stderr.append(line)

                if not self.inited and (
                    line.find("INITED cov") >= 0 or line.find(NO_CORPUS_MSG) >= 0
                ):
                    self.inited = True

                if line.find("Test unit written to ") >= 0:
                    self.testcase = Path(line.split()[-1])

                # libFuzzer sometimes hangs on out-of-memory. Kill it
                # if we detect this situation.
                if (
                    self.kill_on_oom
                    and line.find("ERROR: libFuzzer: out-of-memory") >= 0
                ):
                    self.had_oom = True
                    LOG.error("oom detected, waiting for process to terminate")
                    oom_detected = time()

                # Pass-through output
                if self.mid is not None:
                    LOG.info("[Job %d] %s", self.mid, line)
                else:
                    LOG.info("%s", line)

                if oom_detected is not None:
                    # wait for process to exit before calling kill()
                    if (
                        self.process.poll() is None
                        and (time() - oom_detected) >= OOM_WAIT
                    ):
                        self.process.kill()
                        # set back to None so we don't kill() again
                        oom_detected = None

            self.process_stderr.close()

            if self.hit_thread_limit and self.testcase and self.testcase.exists():
                # If we hit ASan's global thread limit, ignore the error and remove
                # the resulting testcase, as it won't be useful anyway.
                # Not that this thread limit is not a concurrent thread limit, but
                # a limit imposed on the number of threads ever started during the
                # lifetime of the process.
                self.testcase.unlink()
                self.testcase = None
        except Exception as exc:  # pylint: disable=broad-except
            self.exc = exc
        finally:
            if self.mqueue is not None:
                self.mqueue.put(self.mid)

    def get_asan_trace(self) -> list[str]:
        return self.trace

    def get_testcase(self) -> Path | None:
        return self.testcase

    def get_stderr(self) -> list[str]:
        return list(self.stderr)

    def terminate(self) -> None:
        LOG.warning("[Job %d] Received terminate request...", self.mid)

        # Avoid sending anything through the queue when the run() loop exits
        self.mqueue = None
        self.process.terminate()

        # Emulate a wait() with timeout through poll and sleep
        (max_sleep_time, poll_interval) = (10.0, 0.2)
        while self.process.poll() is None and max_sleep_time > 0:
            max_sleep_time -= poll_interval
            sleep(poll_interval)

        # Process is still alive, kill it and wait
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


class LibFuzzerStats(StatAggregator):
    def __init__(self) -> None:
        super().__init__()
        self.add_field("execs_done", SumField())
        self.add_field("execs_per_sec", SumMinMaxField())
        self.add_field("rss_mb", SumMinMaxField())
        self.add_field("corpus_size", GeneratedField(ignore_reset=True))
        self.add_field("next_auto_reduce", GeneratedField(ignore_reset=True))
        self.add_field("crashes", GeneratedField(hidden=True, ignore_reset=True))
        self.add_field("timeouts", GeneratedField(hidden=True, ignore_reset=True))
        self.add_field("ooms", GeneratedField(hidden=True, ignore_reset=True))
        self.add_field(
            "crashes/timeouts/ooms",
            JoinField(
                (self.fields["crashes"], self.fields["timeouts"], self.fields["ooms"])
            ),
        )
        self.add_field("cov", MinMaxField())
        self.add_field("feat", MinMaxField())
        self.add_field("last_new", MaxTimeField(ignore_reset=True))
        self.add_field("last_new_pc", MaxTimeField(ignore_reset=True))
        self.add_sys_stats()

    def update_and_write(
        self,
        outfile: Path,
        monitors: list[LibFuzzerMonitor | None],
        warnings: list[str],
    ) -> None:
        self.reset()

        for monitor in monitors:
            if monitor is None:
                continue
            for field, val in self.fields.items():
                if val.generated or val.hidden:
                    continue
                assert hasattr(monitor, field), f"Field {field} not in monitor"
                val.update(getattr(monitor, field))

        self.write_file(outfile, warnings)


def _extend_unique(lst: list[str], ext: list[str]) -> None:
    """As list.extend, but only values not already in the list are appended"""
    lst.extend(val for val in ext if val not in set(lst))


def libfuzzer_main(
    opts: Namespace, collector: Collector | None, storage: CloudStorageProvider
) -> int:
    assert opts.rargs
    binary = Path(opts.rargs[0])
    if not binary.exists():
        LOG.error("error: Specified binary does not exist: %s", binary)
        return 2

    base_cfg = ProgramConfiguration.fromBinary(binary)
    if base_cfg is None:
        LOG.error("error: Failed to load program configuration based on binary")
        return 2

    # Build our libFuzzer command line. We add certain parameters automatically for
    # convenience.
    cmdline = []
    cmdline.extend(opts.rargs)
    cmdline_add_args = []
    if test_binary_asan(binary):
        # With ASan, we always want to disable the internal signal handlers
        # libFuzzer uses.
        cmdline_add_args.extend(
            [
                "-handle_segv=0",
                "-handle_bus=0",
                "-handle_abrt=0",
                "-handle_ill=0",
                "-handle_fpe=0",
            ]
        )
    else:
        # We currently don't support non-ASan binaries because the logic in
        # LibFuzzerMonitor expects an ASan trace on crash and CrashInfo doesn't
        # parse internal libFuzzer traces.
        LOG.error(
            "error: This wrapper currently only supports binaries built with "
            "AddressSanitizer."
        )
        return 2

    for arg in cmdline:
        if arg.startswith("-jobs=") or arg.startswith("-workers="):
            LOG.error(
                "error: Using -jobs and -workers is incompatible with this wrapper."
            )
            LOG.error(
                "       You can use --libfuzzer-instances to run multiple instances"
                " instead."
            )
            return 2

    # Used by statistics and useful in general
    cmdline_add_args.append("-print_pcs=1")

    # Append args if they don't exist already
    for arg in cmdline_add_args:
        if arg not in cmdline:
            cmdline.append(arg)

    devnull: int | None = DEVNULL
    if opts.debug:
        devnull = None

    base_env = os.environ.copy()
    # Set LD_LIBRARY_PATH for convenience
    if "LD_LIBRARY_PATH" not in base_env:
        base_env["LD_LIBRARY_PATH"] = str(binary.parent)

    if opts.corpus_refresh:
        with CorpusRefreshContext(opts, storage) as merger:
            cmdline.extend(
                ["-merge=1", str(merger.updated_tests_dir), str(merger.queues_dir)]
            )

            # Filter out any -dict arguments that we don't need anyway for merging
            cmdline = [x for x in cmdline if not x.startswith("-dict=")]

            # Filter out any -max_len arguments because the length should only be
            # enforced by the instance(s) doing the actual testing.
            cmdline = [x for x in cmdline if not x.startswith("-max_len=")]

            LOG.info("Running libFuzzer merge")
            # pylint: disable=consider-using-with
            proc = Popen(cmdline, stdout=devnull, env=base_env)
            last_stats_report = 0.0
            while proc.poll() is None:
                # Calculate stats
                if opts.stats and last_stats_report < time() - STATS_UPLOAD_PERIOD:
                    merger.refresh_stats.write_file(opts.stats, [])
                last_stats_report = time()
                sleep(0.1)
            assert not proc.wait()

        assert merger.exit_code is not None
        return merger.exit_code

    args = opts.rargs[1:]
    if args:
        base_cfg.addProgramArguments(args)

    metadata = {}
    if opts.metadata:
        metadata.update(dict(kv.split("=", 1) for kv in opts.metadata))
        base_cfg.addMetadata(metadata)

    envs, cfgs = create_envs(base_env, opts, opts.instances, base_cfg)

    signature_repeat_count = 0
    last_signature = None
    last_queue_upload = 0
    restarts = opts.libfuzzer_restarts

    # Find the first corpus directory from our command line
    corpus_dir = None
    for rarg in opts.rargs:
        rarg_path = Path(rarg)
        if rarg_path.is_dir():
            corpus_dir = rarg_path.resolve()
            break

    if corpus_dir is None:
        LOG.error("error: Failed to find a corpus directory on command line.")
        return 2

    # At this point we know that we will be running libFuzzer locally
    warn_local(opts)

    # Memorize the original corpus, so we can exclude it from uploading later
    original_corpus = {item.name for item in corpus_dir.iterdir()}

    corpus_auto_reduce_threshold = None
    corpus_auto_reduce_ratio: float | None = None
    if opts.libfuzzer_auto_reduce is not None:
        assert opts.libfuzzer_auto_reduce >= 5

        corpus_auto_reduce_ratio = float(opts.libfuzzer_auto_reduce) / float(100)

        if len(original_corpus) >= opts.libfuzzer_auto_reduce_min:
            corpus_auto_reduce_threshold = int(
                len(original_corpus) * (1 + corpus_auto_reduce_ratio)
            )
        else:
            # Corpus is smaller than --libfuzzer-auto-reduce-min specifies, so we
            # calculate the threshold based on that value in combination with the
            # ratio instead, initially.
            corpus_auto_reduce_threshold = int(
                opts.libfuzzer_auto_reduce_min * (1 + corpus_auto_reduce_ratio)
            )

        if corpus_auto_reduce_threshold <= len(original_corpus):
            LOG.error("error: Invalid auto reduce threshold specified.")
            return 2

    corpus_syncer = CorpusSyncer(storage, Corpus(corpus_dir), opts.project)

    monitors: list[LibFuzzerMonitor | None] = [None] * opts.instances
    monitor_queue: Queue[int] = Queue()

    # Keep track how often we crash to abort in certain situations
    crashes_per_minute_interval = 0
    crashes_per_minute = 0

    # Global stats
    stats = LibFuzzerStats()
    stats.fields["corpus_size"].update(len(original_corpus))

    # Memorize if we just did a corpus reduction, for S3 sync
    corpus_reduction_done = False

    # Memorize which corpus files we deleted (e.g. for timing out),
    # as this can happen in multiple subprocesses at once.
    removed_corpus_files = set()

    try:
        while True:
            if (
                restarts is not None
                and restarts < 0
                and all(x is None for x in monitors)
            ):
                LOG.info("Run completed.")
                break

            # Check if we need to (re)start any monitors
            for idx, monitor in enumerate(monitors):
                if monitor is None:
                    if restarts is not None:
                        restarts -= 1
                        if restarts < 0:
                            break

                    # pylint: disable=consider-using-with
                    process = Popen(
                        cmdline,
                        # stdout=None,
                        stderr=PIPE,
                        env=envs[idx],
                        text=True,
                    )

                    mon = LibFuzzerMonitor(process, mid=idx, mqueue=monitor_queue)
                    monitors[idx] = mon
                    mon.start()

            corpus_size: int | None = None
            if corpus_auto_reduce_threshold is not None or opts.stats:
                # We need the corpus size for stats and the auto reduce feature,
                # so we cache it here to avoid running listdir multiple times.
                corpus_size = sum(1 for _ in corpus_dir.iterdir())

            if (
                corpus_auto_reduce_threshold is not None
                and corpus_size is not None
                and corpus_size >= corpus_auto_reduce_threshold
            ):
                LOG.info("Preparing automated merge...")

                # Time to Auto-reduce
                for idx, monitor in enumerate(monitors):
                    if monitor is not None:
                        LOG.info("Asking monitor %d to terminate...", idx)
                        monitor.terminate()
                        monitor.join(30)
                        if monitor.is_alive():
                            raise RuntimeError("Monitor refusing to stop.")

                        # Indicate that this monitor is dead, so it is restarted
                        # later on
                        monitors[idx] = None

                        if opts.stats:
                            # Make sure the execs that this monitor did survive in
                            # stats
                            cast(SumField, stats.fields["execs_done"]).add_to_base(
                                monitor.execs_done
                            )

                # All monitors are assumed to be dead now, clear the monitor queue
                # in case it has remaining ids from monitors that terminated on
                # their own before we terminated them.
                while not monitor_queue.empty():
                    monitor_queue.get_nowait()

                merge_cmdline = []
                merge_cmdline.extend(cmdline)

                # Filter all directories on the command line, these are likely
                # corpus dirs
                merge_cmdline = [x for x in merge_cmdline if not Path(x).is_dir()]

                # Filter out other stuff we don't want for merging
                merge_cmdline = [x for x in merge_cmdline if not x.startswith("-dict=")]

                new_corpus_dir = Path(mkdtemp(prefix="fm-libfuzzer-automerge-"))
                merge_cmdline.extend(["-merge=1", str(new_corpus_dir), str(corpus_dir)])

                LOG.info("Running automated merge...")
                env = os.environ.copy()
                env["LD_LIBRARY_PATH"] = str(Path(merge_cmdline[0]).parent)
                LOG.debug("run(%r, env=%r)", merge_cmdline, env)
                run(merge_cmdline, stdout=devnull, env=env, check=True)

                if not any(new_corpus_dir.iterdir()):
                    LOG.error(
                        "error: Merge returned empty result, refusing to continue."
                    )
                    return 2

                rmtree(str(corpus_dir))
                move(str(new_corpus_dir), str(corpus_dir))

                # Update our corpus size
                corpus_size = sum(1 for _ in corpus_dir.iterdir())

                # Update our auto-reduction target
                assert corpus_auto_reduce_ratio is not None
                if corpus_size >= opts.libfuzzer_auto_reduce_min:
                    corpus_auto_reduce_threshold = int(
                        corpus_size * (1 + corpus_auto_reduce_ratio)
                    )
                else:
                    # Corpus is now smaller than --libfuzzer-auto-reduce-min
                    # specifies.
                    corpus_auto_reduce_threshold = int(
                        opts.libfuzzer_auto_reduce_min * (1 + corpus_auto_reduce_ratio)
                    )

                corpus_reduction_done = True

                # Continue, our instances will be restarted with the next loop
                continue

            if opts.stats:
                stats.fields["corpus_size"].update(corpus_size)
                if corpus_auto_reduce_threshold is not None:
                    stats.fields["next_auto_reduce"].update(
                        corpus_auto_reduce_threshold
                    )

                stats.update_and_write(opts.stats, monitors, [])

            # Only upload new corpus files every 2 hours or after corpus reduction
            if opts.queue_upload and (
                corpus_reduction_done
                or last_queue_upload < int(time()) - QUEUE_UPLOAD_PERIOD
            ):
                corpus_syncer.upload_queue(original_corpus)

                last_queue_upload = int(time())
                corpus_reduction_done = False

            try:
                result = monitor_queue.get(True, 10)
            except Empty:
                continue

            assert result is not None
            monitor = monitors[result]
            assert monitor is not None
            monitor.join(20)
            if monitor.is_alive():
                raise RuntimeError(
                    f"Monitor {result} still alive although it signaled termination."
                )

            # Monitor is dead, mark it for restarts
            monitors[result] = None

            if monitor.exc is not None:
                # If the monitor had an exception, re-raise it here
                raise monitor.exc

            if opts.stats:
                # Make sure the execs that this monitor did survive in stats
                cast(SumField, stats.fields["execs_done"]).add_to_base(
                    monitor.execs_done
                )

            LOG.info("Job %d terminated, processing results...", result)

            trace = monitor.get_asan_trace()
            testcase = monitor.get_testcase()
            stderr = monitor.get_stderr()

            if not monitor.inited and not trace and not testcase:
                LOG.error("Process did not startup correctly, aborting... (1)")
                return 2

            # libFuzzer can exit due to OOM with and without a testcase.
            # The case of having an OOM with a testcase is handled further below.
            if not testcase and monitor.had_oom:
                stats.fields["ooms"] += 1  # type: ignore
                continue

            # Don't bother sending stuff to the server with neither trace nor
            # testcase
            if not trace and not testcase:
                continue

            # Ignore slow units and oom files
            if testcase is not None:
                testcase_name = testcase.name

                if not monitor.inited:
                    if testcase_name.startswith("oom-") or testcase_name.startswith(
                        "timeout-"
                    ):
                        hashname = testcase_name.split("-")[1]
                        potential_corpus_file = corpus_dir / hashname
                        if potential_corpus_file.exists():
                            LOG.warning(
                                "Removing problematic corpus file %s...", hashname
                            )
                            potential_corpus_file.unlink()
                            removed_corpus_files.add(potential_corpus_file)

                        if potential_corpus_file in removed_corpus_files:
                            continue

                    # If neither an OOM or a Timeout caused the startup failure or
                    # we couldn't find and remove the offending file, we should bail
                    # out at this point.
                    LOG.error("Process did not startup correctly, aborting... (2)")
                    return 2

                if testcase_name.startswith("slow-unit-"):
                    continue
                if testcase_name.startswith("oom-"):
                    stats.fields["ooms"] += 1  # type: ignore
                    continue
                if testcase_name.startswith("timeout-"):
                    stats.fields["timeouts"] += 1  # type: ignore
                    continue

            stats.fields["crashes"] += 1  # type: ignore

            if int(time()) - crashes_per_minute_interval > 60:
                crashes_per_minute_interval = int(time())
                crashes_per_minute = 0
            crashes_per_minute += 1

            if crashes_per_minute >= 10:
                LOG.warning("Too many frequent crashes, exiting...")

                if opts.stats:
                    # If statistics are reported to EC2SpotManager, this helps us to
                    # see when fuzzing has become impossible due to excessive
                    # crashes.
                    warning = "Fuzzing terminated due to excessive crashes."
                    stats.update_and_write(opts.stats, monitors, [warning])
                break

            if not monitor.inited:
                LOG.warning("Process crashed at startup, aborting...")
                if opts.stats:
                    # If statistics are reported to EC2SpotManager, this helps us to
                    # see when fuzzing has become impossible due to excessive
                    # crashes.
                    warning = "Fuzzing did not startup correctly."
                    stats.update_and_write(opts.stats, monitors, [warning])
                return 2

            if opts.transform:
                # If a transformation script was supplied, update the testcase path
                # to point to the archive which includes both, the original and
                # updated testcases
                assert testcase is not None
                try:
                    testcase = apply_transform(opts.transform, testcase)
                except Exception:  # pylint: disable=broad-except
                    LOG.exception("exception while applying transform")

            # If we run in local mode (no --fuzzmanager specified), then we just
            # continue after each crash
            if not opts.fuzzmanager:
                continue
            assert collector is not None

            crash_info = CrashInfo.fromRawCrashData(
                [], stderr, cfgs[result], auxCrashData=trace
            )

            (sigfile, metadata) = collector.search(crash_info)

            if sigfile is not None:
                if last_signature == sigfile:
                    signature_repeat_count += 1
                else:
                    last_signature = sigfile
                    signature_repeat_count = 0

                LOG.warning("Crash matches signature %s, not submitting...", sigfile)
            else:
                collector.generate(
                    crash_info,
                    forceCrashAddress=True,
                    forceCrashInstruction=False,
                    numFrames=8,
                )
                collector.submit(crash_info, testcase)
                LOG.info("Successfully submitted crash.")
    finally:
        LOG.info("Shutting down...")
        # Before doing anything, try to shutdown our monitors
        for monitor in monitors:
            if monitor is not None:
                monitor.terminate()
                monitor.join(10)

        if opts.queue_upload:
            corpus_syncer.upload_queue(original_corpus)

    return 0
