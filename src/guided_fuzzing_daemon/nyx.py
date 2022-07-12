import re
import subprocess
import sys
import time
from pathlib import Path

import msgpack
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

EXT_SYMBOLIZER_SCRIPT = Path(__file__).parent / "asan_symbolize.py"
CRASH_PATTERN = re.compile(r"MOZ|ERROR|SUMMARY")
POLL_PERIOD = 5  # check for fuzzer exit and/or crashes
PRINT_PERIOD = 30  # print fuzzer stats and crash summary
QUEUE_UPLOAD_PERIOD = 7200


class NyxCrash:
    def __init__(self, signature, log_path, testcase_path):
        self.signature = signature
        self.log_path = log_path
        self.testcase_path = testcase_path

    def report(self, collector, configuration):

        # TODO: at this point we should try to reproduce to get a better log &
        #       stacktrace. eg.
        # AFL_IGNORE_PROBLEMS=1 NYX_FUZZER=IPC_Generic MOZ_FUZZ_TESTFILE=test.bin \
        #  ffpuppet /path/to/firefox --xvfb -u fuzz.html -d

        # manually symbolize
        trace = subprocess.run(
            [
                sys.executable,
                EXT_SYMBOLIZER_SCRIPT,
                "--demangle",
                "--logfile",
                str(self.log_path),
            ],
            capture_output=True,
            check=True,
        ).stdout

        crash_info = CrashInfo.fromRawCrashData(
            [], [], configuration, auxCrashData=trace
        )

        sigfile, _metadata = collector.search(crash_info)

        if sigfile is not None:
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
            collector.submit(crash_info, str(self.testcase_path), testCaseQuality=5)
            print("Successfully submitted crash.", file=sys.stderr)


class NyxStatus:
    def __init__(self, workdir):
        self.total_execs = 0
        self.total_last_1000_execs_per_sec = 0.0
        self.last_1000_execs_time = 0.0
        self.overall_execs_per_sec = 0.0
        self.uptime = 0.0
        # dict[str, NyxCrash]
        self.crashes = {}
        self.workdir = workdir

    def scan(self):
        # reset
        self.__init__(self.workdir)
        for stats in self.workdir.glob("thread_stats_*.msgp"):
            with stats.open("rb") as stats_fp:
                data = msgpack.unpack(stats_fp)
            self.total_execs += data["execs"]
            self.total_last_1000_execs_per_sec += data["last_1000_execs_per_sec"]
            self.last_1000_execs_time += data["last_1000_execs_time"]
            self.overall_execs_per_sec += data["overall_execs_per_sec"]
            self.uptime = max(self.uptime, data["uptime"])

        for crash in self.iter_crashes():
            self.crashes.setdefault(crash.signature, [])
            self.crashes[crash.signature].append(crash)

    def iter_crashes(self):
        """
        Yields: (short_signature: str, log: Path, testcase: Path)
        """
        for log in (self.workdir / "corpus" / "crash").glob("*.log"):
            with log.open() as log_fp:
                for line in log_fp:
                    if CRASH_PATTERN.search(line) is not None:
                        line = line.rstrip()
                        testcase = log.parent / f"cnt_{log.stem}.bin"
                        assert testcase.is_file()
                        yield NyxCrash(line, log, testcase)

    def __str__(self):
        lines = [
            f"total_execs:\t\t\t{self.total_execs}",
            f"total_last_1000_execs_per_sec:\t{self.total_last_1000_execs_per_sec}",
            f"last_1000_execs_time:\t\t{self.last_1000_execs_time}",
            f"overall_execs_per_sec:\t\t{self.overall_execs_per_sec}",
            f"uptime:\t\t\t\t{self.uptime}",
        ]

        for sig in sorted(self.crashes):
            count = len(self.crashes[sig])
            lines.append(f"{count:>6} {sig}")

        return "\n".join(lines)


def nyx_main(opts, collector, s3m):
    assert opts.sharedir
    assert opts.spec_fuzzer
    assert opts.workdir

    reported = set()
    status = NyxStatus(opts.workdir)
    out = None if opts.debug else subprocess.DEVNULL

    configuration = ProgramConfiguration.fromBinary(
        str(opts.sharedir / "firefox" / "firefox")
    )
    if configuration is None:
        print(
            "Error: Failed to load program configuration based on binary",
            file=sys.stderr,
        )
        return 2

    # TODO: args & env are defined in the sharedir, and not easily
    # reported in ProgramConfiguration

    metadata = {}
    if opts.metadata:
        metadata.update(dict(kv.split("=", 1) for kv in opts.metadata))
        configuration.addMetadata(metadata)

    cargo_cmdline = [
        "cargo",
        "run",
        "--release",
        "--",
        "-s",
        str(opts.sharedir.resolve()),
    ]
    last_status_print = 0
    last_queue_upload = 0  # download existing queues immediately
    with subprocess.Popen(
        cargo_cmdline, cwd=opts.spec_fuzzer, stdout=out, stderr=out
    ) as process:
        while True:
            time.sleep(POLL_PERIOD)

            # update status
            status.scan()

            # report any new crashes
            for crashes in status.crashes.values():
                crash = crashes[0]
                if crash.signature in reported:
                    continue
                crash.report(collector, configuration)
                reported.add(crash.signature)
                last_status_print = 0

            # print status
            now = time.time()
            if now - last_status_print >= PRINT_PERIOD:
                print("", file=sys.stderr)
                print(status, file=sys.stderr)
                last_status_print = now

            # Only upload new corpus files periodically
            if opts.s3_queue_upload and (
                now - last_queue_upload >= QUEUE_UPLOAD_PERIOD
            ):
                s3m.upload_nyx_queue_dir(opts.workdir)

                # Pull down queue files from other queues
                s3m.download_nyx_queues(opts.workdir)

                last_queue_upload = time.time()

            if process.poll() is not None:
                result = process.wait()
                print(f"Nyx exited: {result}", file=sys.stderr)
                if opts.s3_queue_upload:
                    s3m.upload_nyx_queue_dir(opts.workdir)
                return result
