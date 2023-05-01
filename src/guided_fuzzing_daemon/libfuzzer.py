# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from shutil import move, rmtree
from subprocess import DEVNULL, PIPE, Popen, run
from tempfile import mkdtemp
from threading import Thread
from time import sleep, time
from traceback import print_exc

from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

from .utils import apply_transform, test_binary_asan, warn_local, write_stats_file

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


class LibFuzzerMonitor(Thread):
    def __init__(self, process, kill_on_oom=True, mid=None, mqueue=None):
        Thread.__init__(self)

        self.process = process
        self.process_stderr = process.stderr
        self.trace = []
        self.stderr = deque([], 128)
        self.in_trace = False
        self.testcase = None
        self.kill_on_oom = kill_on_oom
        self.had_oom = False
        self.hit_thread_limit = False
        self.inited = False
        self.mid = mid
        self.mqueue = mqueue

        # Keep some statistics
        self.cov = 0
        self.feat = 0
        self.execs_done = 0
        self.execs_per_sec = 0
        self.rss_mb = 0
        self.last_new = 0
        self.last_new_pc = 0

        # Store potential exceptions
        self.exc = None

    def run(self):
        assert not self.hit_thread_limit
        assert not self.had_oom

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
                # right away if we detect this situation.
                if (
                    self.kill_on_oom
                    and line.find("ERROR: libFuzzer: out-of-memory") >= 0
                ):
                    self.had_oom = True
                    self.process.kill()

                # Pass-through output
                if self.mid is not None:
                    sys.stderr.write(f"[Job {self.mid}] {line}")
                else:
                    sys.stderr.write(line)

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

    def get_asan_trace(self):
        return self.trace

    def get_testcase(self):
        return self.testcase

    def get_stderr(self):
        return list(self.stderr)

    def terminate(self):
        print(f"[Job {self.mid}] Received terminate request...", file=sys.stderr)

        # Avoid sending anything through the queue when the run() loop exits
        self.mqueue = None
        self.process.terminate()

        # Emulate a wait() with timeout through poll and sleep
        (max_sleep_time, poll_interval) = (10, 0.2)
        while self.process.poll() is None and max_sleep_time > 0:
            max_sleep_time -= poll_interval
            sleep(poll_interval)

        # Process is still alive, kill it and wait
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def _extend_unique(lst, ext):
    """As list.extend, but only values not already in the list are appended"""
    lst.extend(val for val in ext if val not in set(lst))


def write_aggregated_stats_libfuzzer(outfile, stats, monitors, warnings):
    """
    Generate aggregated statistics for the given overall libfuzzer stats and the
    individual monitors.  Results are written to the specified output file.

    @type outfile: str
    @param outfile: Output file for aggregated statistics

    @type stats: dict
    @param stats: Dictionary containing overall stats

    @type monitors: list
    @param monitors: A list of LibFuzzerMonitor instances

    @type warnings: list
    @param warnings: Any textual warnings to write in addition to stats
    """

    # Which fields to add
    wanted_fields_total = [
        "execs_done",
        "execs_per_sec",
        "rss_mb",
        "corpus_size",
        "next_auto_reduce",
        "crashes",
        "timeouts",
        "ooms",
    ]

    # Fields to track min/max across jobs
    wanted_fields_minmax = [
        "cov",
        "feat",
        "execs_per_sec",
        "rss_mb",
    ]

    # Which fields should be aggregated by max
    wanted_fields_max = ["last_new", "last_new_pc"]

    # This is a list of fields mentioned in one of the lists above already,
    # that should *additionally* also be aggregated with the global state.
    # Only supported for total and max aggregation.
    wanted_fields_global_aggr = ["execs_done", "last_new", "last_new_pc"]

    # These fields should already be defined above, and will be converted
    # from unix timestamp to ISO8601 format before being written.
    wanted_fields_conv_time = ["last_new", "last_new_pc"]

    # Generate total list of fields to write
    fields = []
    fields.extend(wanted_fields_total)
    _extend_unique(fields, wanted_fields_minmax)
    _extend_unique(fields, wanted_fields_max)

    aggregated_stats = {}
    minmax_stats = {}

    # In certain cases, e.g. when exiting, one or more monitors can be down.
    monitors = [monitor for monitor in monitors if monitor is not None]

    if monitors:
        for field in wanted_fields_total:
            if hasattr(monitors[0], field):
                aggregated_stats[field] = 0
                for monitor in monitors:
                    aggregated_stats[field] += getattr(monitor, field)
                if field in wanted_fields_global_aggr:
                    aggregated_stats[field] += stats[field]
            else:
                # Assume global field
                aggregated_stats[field] = stats[field]

        for field in wanted_fields_minmax:
            assert hasattr(monitors[0], field), f"Field {field} not in monitor"
            for monitor in monitors:
                value = getattr(monitor, field)
                if field in minmax_stats:
                    minmax_stats[field] = (
                        min(value, minmax_stats[field][0]),
                        max(value, minmax_stats[field][1]),
                    )
                else:
                    minmax_stats[field] = (value, value)

        for field in wanted_fields_max:
            assert hasattr(monitors[0], field), f"Field {field} not in monitor"
            aggregated_stats[field] = 0
            for monitor in monitors:
                val = getattr(monitor, field)
                if val > aggregated_stats[field]:
                    aggregated_stats[field] = val
            if (
                field in wanted_fields_global_aggr
                and stats[field] > aggregated_stats[field]
            ):
                aggregated_stats[field] = stats[field]

        for field in wanted_fields_global_aggr:
            # Write aggregated stats back into the global stats for max fields
            if field in wanted_fields_max:
                stats[field] = aggregated_stats[field]

        for field in wanted_fields_conv_time:
            aggregated_stats[field] = (
                datetime.fromtimestamp(aggregated_stats[field], tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )

    # Format min/max fields
    for field in wanted_fields_minmax:
        if field not in minmax_stats:
            continue  # pragma: no cover
        minvalue, maxvalue = minmax_stats[field]
        if field in aggregated_stats:
            aggregated_stats[
                field
            ] = f"{aggregated_stats[field]} total ({minvalue}-{maxvalue} min/max)"
        else:
            aggregated_stats[field] = f"{minvalue}-{maxvalue} min/max"

    # Merge crashes/timeouts/ooms
    fields[fields.index("crashes")] = "crashes/timeouts/ooms"
    fields.remove("timeouts")
    fields.remove("ooms")
    aggregated_stats["crashes/timeouts/ooms"] = (
        f"{aggregated_stats['crashes']}, {aggregated_stats['timeouts']}, "
        f"{aggregated_stats['ooms']}"
    )

    # Write out data
    write_stats_file(outfile, fields, aggregated_stats, warnings)


def libfuzzer_main(opts, collector, s3m):
    assert opts.rargs
    binary = Path(opts.rargs[0])
    if not binary.exists():
        print(f"error: Specified binary does not exist: {binary}", file=sys.stderr)
        return 2

    configuration = ProgramConfiguration.fromBinary(binary)
    if configuration is None:
        print(
            "error: Failed to load program configuration based on binary",
            file=sys.stderr,
        )
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
        print(
            "error: This wrapper currently only supports binaries built with "
            "AddressSanitizer.",
            file=sys.stderr,
        )
        return 2

    for arg in cmdline:
        if arg.startswith("-jobs=") or arg.startswith("-workers="):
            print(
                "error: Using -jobs and -workers is incompatible with this wrapper.",
                file=sys.stderr,
            )
            print(
                "       You can use --libfuzzer-instances to run multiple instances"
                " instead.",
                file=sys.stderr,
            )
            return 2

    # Used by statistics and useful in general
    cmdline_add_args.append("-print_pcs=1")

    # Append args if they don't exist already
    for arg in cmdline_add_args:
        if arg not in cmdline:
            cmdline.append(arg)

    # Copy the system environment variables by default and overwrite them
    # if they are specified through env.
    env = dict(os.environ)
    if opts.env:
        oenv = dict(kv.split("=", 1) for kv in opts.env)
        configuration.addEnvironmentVariables(oenv)
        for envkey in oenv:
            env[envkey] = oenv[envkey]

    args = opts.rargs[1:]
    if args:
        configuration.addProgramArguments(args)

    metadata = {}
    if opts.metadata:
        metadata.update(dict(kv.split("=", 1) for kv in opts.metadata))
        configuration.addMetadata(metadata)

    # Set LD_LIBRARY_PATH for convenience
    if "LD_LIBRARY_PATH" not in env:
        env["LD_LIBRARY_PATH"] = str(binary.parent)

    signature_repeat_count = 0
    last_signature = None
    last_queue_upload = 0
    restarts = opts.libfuzzer_restarts

    # The base directory for libFuzzer is the current working directory
    base_dir = Path.cwd()

    # Find the first corpus directory from our command line
    corpus_dir = None
    for rarg in opts.rargs:
        rarg_path = Path(rarg)
        if rarg_path.is_dir():
            corpus_dir = rarg_path.resolve()
            break

    if corpus_dir is None:
        print(
            "error: Failed to find a corpus directory on command line.",
            file=sys.stderr,
        )
        return 2

    # At this point we know that we will be running libFuzzer locally
    warn_local(opts)

    # Memorize the original corpus, so we can exclude it from uploading later
    original_corpus = {item.name for item in corpus_dir.iterdir()}

    corpus_auto_reduce_threshold = None
    corpus_auto_reduce_ratio = None
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
            print("error: Invalid auto reduce threshold specified.", file=sys.stderr)
            return 2

    # Write a cmdline file, similar to what our AFL fork does
    with open("cmdline", "w", encoding="utf-8") as cmdline_fd:
        for rarg in opts.rargs:
            # Omit any corpus directory that is in the command line
            if not Path(rarg).is_dir():
                print(rarg, file=cmdline_fd)

    monitors = [None] * opts.libfuzzer_instances
    monitor_queue = Queue()

    # Keep track how often we crash to abort in certain situations
    crashes_per_minute_interval = 0
    crashes_per_minute = 0

    # Global stats
    stats = {
        "cov": 0,
        "feat": 0,
        "crashes": 0,
        "crashes_per_minute": 0,
        "timeouts": 0,
        "ooms": 0,
        "corpus_size": len(original_corpus),
        "execs_done": 0,
        "last_new": 0,
        "last_new_pc": 0,
        "next_auto_reduce": 0,
    }

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
                print("Run completed.", file=sys.stderr)
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
                        env=env,
                        text=True,
                    )

                    monitors[idx] = LibFuzzerMonitor(
                        process, mid=idx, mqueue=monitor_queue
                    )
                    monitors[idx].start()

            corpus_size = None
            if corpus_auto_reduce_threshold is not None or opts.stats:
                # We need the corpus size for stats and the auto reduce feature,
                # so we cache it here to avoid running listdir multiple times.
                corpus_size = sum(1 for _ in corpus_dir.iterdir())

            if (
                corpus_auto_reduce_threshold is not None
                and corpus_size >= corpus_auto_reduce_threshold
            ):
                print("Preparing automated merge...", file=sys.stderr)

                # Time to Auto-reduce
                for idx, monitor in enumerate(monitors):
                    if monitor is not None:
                        print(f"Asking monitor {idx} to terminate...", file=sys.stderr)
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
                            stats["execs_done"] += monitor.execs_done

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

                new_corpus_dir = mkdtemp(prefix="fm-libfuzzer-automerge-")
                merge_cmdline.extend(["-merge=1", new_corpus_dir, str(corpus_dir)])

                print("Running automated merge...", file=sys.stderr)
                env = os.environ.copy()
                env["LD_LIBRARY_PATH"] = str(Path(merge_cmdline[0]).parent)
                devnull = DEVNULL
                if opts.debug:
                    devnull = None
                run(merge_cmdline, stdout=devnull, env=env, check=True)

                if not any(Path(new_corpus_dir).iterdir()):
                    print("error: Merge returned empty result, refusing to continue.")
                    return 2

                rmtree(str(corpus_dir))
                move(new_corpus_dir, str(corpus_dir))

                # Update our corpus size
                corpus_size = sum(1 for _ in corpus_dir.iterdir())

                # Update our auto-reduction target
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
                stats["corpus_size"] = corpus_size
                if corpus_auto_reduce_threshold is not None:
                    stats["next_auto_reduce"] = corpus_auto_reduce_threshold

                write_aggregated_stats_libfuzzer(opts.stats, stats, monitors, [])

            # Only upload new corpus files every 2 hours or after corpus reduction
            if opts.s3_queue_upload and (
                corpus_reduction_done or last_queue_upload < int(time()) - 7200
            ):
                s3m.upload_libfuzzer_queue_dir(
                    str(base_dir), str(corpus_dir), original_corpus
                )

                # Pull down queue files from other queues directly into the corpus
                s3m.download_libfuzzer_queues(str(corpus_dir))

                last_queue_upload = int(time())
                corpus_reduction_done = False

            try:
                result = monitor_queue.get(True, 10)
            except Empty:
                continue

            monitor = monitors[result]
            monitor.join(20)
            if monitor.is_alive():
                raise RuntimeError(
                    f"Monitor {result} still alive although it signaled " "termination."
                )

            # Monitor is dead, mark it for restarts
            monitors[result] = None

            if monitor.exc is not None:
                # If the monitor had an exception, re-raise it here
                raise monitor.exc

            if opts.stats:
                # Make sure the execs that this monitor did survive in stats
                stats["execs_done"] += monitor.execs_done

            print(f"Job {result} terminated, processing results...", file=sys.stderr)

            trace = monitor.get_asan_trace()
            testcase = monitor.get_testcase()
            stderr = monitor.get_stderr()

            if not monitor.inited and not trace and not testcase:
                print(
                    "Process did not startup correctly, aborting... (1)",
                    file=sys.stderr,
                )
                return 2

            # libFuzzer can exit due to OOM with and without a testcase.
            # The case of having an OOM with a testcase is handled further below.
            if not testcase and monitor.had_oom:
                stats["ooms"] += 1
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
                            print(
                                f"Removing problematic corpus file {hashname}...",
                                file=sys.stderr,
                            )
                            potential_corpus_file.unlink()
                            removed_corpus_files.add(potential_corpus_file)

                        if potential_corpus_file in removed_corpus_files:
                            continue

                    # If neither an OOM or a Timeout caused the startup failure or
                    # we couldn't find and remove the offending file, we should bail
                    # out at this point.
                    print(
                        "Process did not startup correctly, aborting... (2)",
                        file=sys.stderr,
                    )
                    return 2

                if testcase_name.startswith("slow-unit-"):
                    continue
                if testcase_name.startswith("oom-"):
                    stats["ooms"] += 1
                    continue
                if testcase_name.startswith("timeout-"):
                    stats["timeouts"] += 1
                    continue

            stats["crashes"] += 1

            if int(time()) - crashes_per_minute_interval > 60:
                crashes_per_minute_interval = int(time())
                crashes_per_minute = 0
            crashes_per_minute += 1
            stats["crashes_per_minute"] = crashes_per_minute

            if crashes_per_minute >= 10:
                print("Too many frequent crashes, exiting...", file=sys.stderr)

                if opts.stats:
                    # If statistics are reported to EC2SpotManager, this helps us to
                    # see when fuzzing has become impossible due to excessive
                    # crashes.
                    warning = "Fuzzing terminated due to excessive crashes."
                    write_aggregated_stats_libfuzzer(
                        opts.stats, stats, monitors, [warning]
                    )
                break

            if not monitor.inited:
                print("Process crashed at startup, aborting...", file=sys.stderr)
                if opts.stats:
                    # If statistics are reported to EC2SpotManager, this helps us to
                    # see when fuzzing has become impossible due to excessive
                    # crashes.
                    warning = "Fuzzing did not startup correctly."
                    write_aggregated_stats_libfuzzer(
                        opts.stats, stats, monitors, [warning]
                    )
                return 2

            if opts.transform:
                # If a transformation script was supplied, update the testcase path
                # to point to the archive which includes both, the original and
                # updated testcases
                try:
                    testcase = Path(apply_transform(opts.transform, testcase))
                except Exception as exc:  # pylint: disable=broad-except
                    print(exc.args[1], file=sys.stderr)

            # If we run in local mode (no --fuzzmanager specified), then we just
            # continue after each crash
            if not opts.fuzzmanager:
                continue

            crash_info = CrashInfo.fromRawCrashData(
                [], stderr, configuration, auxCrashData=trace
            )

            (sigfile, metadata) = collector.search(crash_info)

            if sigfile is not None:
                if last_signature == sigfile:
                    signature_repeat_count += 1
                else:
                    last_signature = sigfile
                    signature_repeat_count = 0

                print(
                    f"Crash matches signature {sigfile}, not submitting...",
                    file=sys.stderr,
                )
            else:
                collector.generate(
                    crash_info,
                    forceCrashAddress=True,
                    forceCrashInstruction=False,
                    numFrames=8,
                )
                collector.submit(crash_info, testcase)
                print("Successfully submitted crash.", file=sys.stderr)
    finally:
        try:
            # Before doing anything, try to shutdown our monitors
            for monitor in monitors:
                if monitor is not None:
                    monitor.terminate()
                    monitor.join(10)
        finally:
            if sys.exc_info()[0] is not None:
                # We caught an exception, print it now when all our monitors are
                # down
                print_exc()

    return 0
