# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
from argparse import Namespace
from copy import copy
from dataclasses import dataclass
from logging import getLogger
from pathlib import Path
from subprocess import DEVNULL, Popen
from time import monotonic as time
from time import sleep

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner
from FTB.Signatures.CrashInfo import CrashInfo

from .stats import STATS_UPLOAD_PERIOD
from .storage import (
    QUEUE_UPLOAD_PERIOD,
    CloudStorageProvider,
    Corpus,
    CorpusRefreshContext,
    CorpusSyncer,
)
from .utils import LogFile, TempPath, create_envs, warn_local

LOG = getLogger("gfd.fzli")


def _failed(crash_file: Path) -> Path:
    return crash_file.parent / f"{crash_file.name}.failed"


def _submitted(crash_file: Path) -> Path:
    return crash_file.parent / f"{crash_file.name}.submitted"


def scan_crashes(
    crash_dir: Path,
    collector: Collector,
    env: dict[str, str],
    cfg: ProgramConfiguration,
    reproduce: bool = True,
) -> None:
    """Scan the base directory for crash tests and submit them to FuzzManager.

    @type crash_dir: String
    @param crash_dir: Fuzzilli crashes directory

    @type env_path: String
    @param env_path: Optional file containing environment variables.

    @type reproduce: bool
    @param reproduce: If we should try to reproduce the crash.

    @rtype: int
    @return: Non-zero return code on failure
    """
    # do nothing until Fuzzilli has started up
    if not crash_dir.is_dir():
        return

    env = env.copy()
    env["ASAN_OPTIONS"] = f"{env.get('ASAN_OPTIONS', '')}:symbolize=1"
    env["UBSAN_OPTIONS"] = (
        f"{env.get('UBSAN_OPTIONS', '')}:handle_segv=1:abort_on_error=1:symbolize=1"
    )

    for crash_file in crash_dir.iterdir():
        # Ignore all files that aren't crash results
        if not crash_file.name.startswith("program_"):
            continue

        # Ignore protobuf files
        if crash_file.suffix in {".protobuf", ".fzil"}:
            continue

        # Ignore our own status files
        if crash_file.suffix in {".submitted", ".failed"}:
            continue

        # Ignore files we already processed
        if _submitted(crash_file).exists() or _failed(crash_file).exists():
            continue

        LOG.info("Processing crash file %s", crash_file)

        # Read target arguments and potential crash trace from the test file itself
        cmdline = None
        in_crash_info = False
        crash_info_from_test = []
        with crash_file.open() as crash_fd:
            for line in crash_fd:
                if line.startswith("// CRASH INFO"):
                    in_crash_info = True

                if in_crash_info:
                    crash_info_from_test.append(line.replace("// ", "", 1).rstrip())

                if line.startswith("// TARGET ARGS:"):
                    line = line.replace("// TARGET ARGS: ", "").strip()
                    cmdline = line.split(" ")
                    cmdline.remove("--reprl")

        assert cmdline

        configuration = copy(cfg)
        configuration.addProgramArguments(cmdline[1:])

        if not reproduce:
            crash_info = CrashInfo.fromRawCrashData(
                [], [], configuration, ["FUZZILLI: submitted without reproducing"]
            )
            result = collector.submit(crash_info, crash_file)
            _submitted(crash_file).touch()
            LOG.info("Success: Submitted crash to server: %r", result)
            continue

        # The test file itself is not part of the arguments Fuzzilli outputs
        cmdline.append(str(crash_file))

        runner = AutoRunner.fromBinaryArgs(cmdline[0], cmdline[1:], env=env)
        if runner.run():
            crash_info = runner.getCrashInfo(configuration)
            result = collector.submit(crash_info, crash_file)
            _submitted(crash_file).touch()
            LOG.info("Success: Submitted crash to server: %r", result)
        else:
            crash_info = CrashInfo.fromRawCrashData(
                [], [], configuration, crash_info_from_test
            )
            result = collector.submit(crash_info, crash_file)
            _failed(crash_file).touch()
            LOG.error(
                "Error: Failed to reproduce the given crash, submitted with crash "
                "information from test: %r",
                result,
            )


@dataclass
class StatsCollectionData:
    path: Path | None
    lines: list[str]

    def write(self) -> None:
        assert self.path is not None
        with self.path.open("w") as stats_f:
            for st_line in self.lines:
                print(st_line, file=stats_f)
        self.lines.clear()

    def add_line(self, line: str) -> None:
        if self.lines:
            if not line:
                self.write()
            else:
                self.lines.append(line)
        elif self.path is not None and line == "Fuzzer Statistics":
            self.lines.append(line)


def _poll(
    proc: Popen[str],
    logf: LogFile,
    stats: StatsCollectionData,
    flush: bool = False,
) -> int | None:
    """poll a Popen for stats on stdout"""
    for line in logf.lines(flush):
        LOG.debug(line)
        stats.add_line(line)
    return proc.poll()


def main(
    opts: Namespace, collector: Collector | None, storage: CloudStorageProvider
) -> int:
    assert opts.rargs, "--fuzzilli expects at least one positional arg (target binary)"
    assert opts.instances >= 1

    binary = Path(opts.rargs[0]).resolve()
    assert binary.is_file()

    if opts.corpus_refresh:
        with CorpusRefreshContext(opts, storage, "corpus", ".fzil") as merger:
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = str(binary.parent)

            cmdline = [  # TODO: Some of these shouldn't be hardcoded
                "swift",
                "run",
                "FuzzilliCli",
                "--corpusImportMode=unminimized",
                f"--importCorpus={merger.queues_dir}",
                f"--jobs={opts.instances}",
                "--maxIterations=1",
                "--profile=spidermonkey",
                f"--storagePath={merger.updated_tests_dir}",
                f"--timeout={opts.timeout or 3000}",
            ]

            if opts.wasm:
                cmdline.append("--wasm")

            cmdline.append(str(binary))

            LOG.info("Running Fuzzilli merge")
            # pylint: disable=consider-using-with
            proc = Popen(
                cmdline,
                stdout=None if opts.debug else DEVNULL,
                env=env,
                cwd=opts.fuzzilli_build_dir,
            )
            assert proc is not None
            try:
                last_stats_report = 0.0
                while proc.poll() is None:
                    # Calculate stats
                    if opts.stats and last_stats_report < time() - STATS_UPLOAD_PERIOD:
                        merger.refresh_stats.write_file(opts.stats, [])
                        last_stats_report = time()
                    sleep(0.1)
            finally:
                assert proc.wait() == 0
        assert merger.exit_code is not None
        return merger.exit_code

    assert opts.corpus_out
    corpus_syncer = CorpusSyncer(
        storage, Corpus(opts.corpus_out / "corpus"), opts.project, ".fzil"
    )

    base_cfg = ProgramConfiguration.fromBinary(binary)
    if collector is not None:
        assert base_cfg

    metadata = {}
    if opts.metadata:
        metadata.update(dict(kv.split("=", 1) for kv in opts.metadata))
        if collector is not None:
            base_cfg.addMetadata(metadata)

    # environment settings that apply to all instances
    base_env = os.environ.copy()
    base_env["LD_LIBRARY_PATH"] = str(binary.parent)

    # Fuzzilli manages multi-proc
    (env,), (cfg,) = create_envs(base_env, opts, 1, base_cfg)

    warn_local(opts)

    start = last_queue_upload = time()

    cmdline = [
        "swift",
        "run",
        "FuzzilliCli",
        f"--timeout={opts.timeout or 2000}",
        "--profile=spidermonkey",
        f"--storagePath={opts.corpus_out}",
        "--resume",
        f"--jobs={opts.instances}",
    ]

    if opts.differential:
        cmdline.append("--differentialRate=0.5")
    else:
        cmdline.append("--argumentRandomization")

    if opts.wasm:
        cmdline.append("--wasm")

    crashes_dir = opts.corpus_out / "crashes"
    diffs_dir = opts.corpus_out / "differentials"

    if opts.max_runtime == 0.0:
        opts.max_runtime = float("inf")

    stats = StatsCollectionData(opts.stats, [])

    # Memorize the original corpus, so we can exclude it from uploading later
    if (opts.corpus_out / "corpus").is_dir():
        original_corpus = {item.name for item in (opts.corpus_out / "corpus").iterdir()}
    else:
        original_corpus = set()

    cmdline.append(str(binary))

    with (
        TempPath() as tmpd,
        open(tmpd / "stdout.log", "w", encoding="utf-8") as fp,
    ):
        logf = LogFile(fp, "")
        # pylint: disable=consider-using-with
        fuzzer_proc = Popen(
            cmdline, stdout=fp, text=True, env=env, cwd=opts.fuzzilli_build_dir
        )
        try:
            while opts.max_runtime > time() - start:
                if collector:
                    scan_crashes(crashes_dir, collector, env, cfg)

                    # TODO: For now we don't do anything special with differential
                    # results and just act as if they were crashes, without trying to
                    # reproduce them
                    if diffs_dir.exists():
                        scan_crashes(diffs_dir, collector, env, cfg, reproduce=False)

                # Only upload new corpus files periodically
                if (
                    opts.queue_upload
                    and last_queue_upload < time() - QUEUE_UPLOAD_PERIOD
                ):
                    corpus_syncer.upload_queue(original_corpus)
                    last_queue_upload = time()

                if _poll(fuzzer_proc, logf, stats) is not None:
                    LOG.warning("Fuzzilli exited")
                    break

                sleep(1)
            else:
                LOG.info("max-runtime is up")
        finally:
            # terminate(), wait(10), kill(), wait()
            if _poll(fuzzer_proc, logf, stats) is None:
                fuzzer_proc.terminate()
                start_term = time()
                while start_term > time() - 10:
                    sleep(0.1)
                    if _poll(fuzzer_proc, logf, stats) is not None:
                        break
                else:
                    LOG.info("need to kill")
                    fuzzer_proc.kill()
                    start_term = time()
                    while start_term > time() - 1:
                        sleep(0.1)
                        if _poll(fuzzer_proc, logf, stats) is not None:
                            break
                    else:
                        LOG.warning(
                            "Process %d did not exit after SIGKILL", fuzzer_proc.pid
                        )

            if opts.queue_upload:
                corpus_syncer.upload_queue(original_corpus)

        if _poll(fuzzer_proc, logf, stats, True) is None:
            return 1
        return fuzzer_proc.returncode
