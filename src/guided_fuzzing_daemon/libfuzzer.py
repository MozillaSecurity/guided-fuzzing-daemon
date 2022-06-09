import collections
import os
import re
import sys
import threading
import time
from pathlib import Path

from .utils import write_stats_file

RE_LIBFUZZER_STATUS = re.compile(r"\s*#(\d+)\s+(INITED|NEW|RELOAD|REDUCE|pulse)\s+cov:")
RE_LIBFUZZER_NEWPC = re.compile(r"\s+NEW_PC:\s+0x")
RE_LIBFUZZER_EXECS = re.compile(r"\s+exec/s: (\d+)\s+")
RE_LIBFUZZER_RSS = re.compile(r"\s+rss: (\d+)Mb")

# Used to set initialized to true, as the INITED message is not present with an empty
# corpus
NO_CORPUS_MSG = "INFO: A corpus is not provided, starting from an empty corpus"


class LibFuzzerMonitor(threading.Thread):
    def __init__(self, process, kill_on_oom=True, mid=None, mqueue=None):
        threading.Thread.__init__(self)

        self.process = process
        self.process_stderr = process.stderr
        self.trace = []
        self.stderr = collections.deque([], 128)
        self.in_trace = False
        self.testcase = None
        self.kill_on_oom = kill_on_oom
        self.had_oom = False
        self.hit_thread_limit = False
        self.inited = False
        self.mid = mid
        self.mqueue = mqueue

        # Keep some statistics
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

                if status_match:
                    self.execs_done = int(status_match.group(1))

                    if status_match.group(2) == "NEW":
                        self.last_new = int(time.time())

                    exec_match = RE_LIBFUZZER_EXECS.search(line)
                    rss_match = RE_LIBFUZZER_RSS.search(line)

                    if exec_match:
                        self.execs_per_sec = int(exec_match.group(1))
                    if rss_match:
                        self.rss_mb = int(rss_match.group(1))
                elif RE_LIBFUZZER_NEWPC.search(line):
                    self.last_new_pc = int(time.time())
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
                    self.testcase = line.split()[-1]

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

            if (
                self.hit_thread_limit
                and self.testcase
                and Path(self.testcase).exists()
            ):
                # If we hit ASan's global thread limit, ignore the error and remove
                # the resulting testcase, as it won't be useful anyway.
                # Not that this thread limit is not a concurrent thread limit, but
                # a limit imposed on the number of threads ever started during the
                # lifetime of the process.
                os.remove(self.testcase)
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
            time.sleep(poll_interval)

        # Process is still alive, kill it and wait
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


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

    # Which fields to aggregate by mean
    wanted_fields_mean = []

    # Which fields should be displayed per fuzzer instance
    wanted_fields_all = []

    # Which fields should be aggregated by max
    wanted_fields_max = ["last_new", "last_new_pc"]

    # This is a list of fields mentioned in one of the lists above already,
    # that should *additionally* also be aggregated with the global state.
    # Only supported for total and max aggregation.
    wanted_fields_global_aggr = ["execs_done", "last_new", "last_new_pc"]

    # Generate total list of fields to write
    fields = []
    fields.extend(wanted_fields_total)
    fields.extend(wanted_fields_mean)
    fields.extend(wanted_fields_all)
    fields.extend(wanted_fields_max)

    aggregated_stats = {}

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

        for field in wanted_fields_mean:
            assert hasattr(monitors[0], field), f"Field {field} not in monitor"
            aggregated_stats[field] = 0
            for monitor in monitors:
                aggregated_stats[field] += getattr(monitor, field)
            aggregated_stats[field] = float(aggregated_stats[field]) / float(
                len(monitors)
            )

        for field in wanted_fields_all:
            assert hasattr(monitors[0], field), f"Field {field} not in monitor"
            aggregated_stats[field] = []
            for monitor in monitors:
                aggregated_stats[field].append(getattr(monitor, field))

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

    # Write out data
    write_stats_file(outfile, fields, aggregated_stats, warnings)
