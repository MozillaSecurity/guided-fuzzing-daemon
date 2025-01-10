# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
import re
from argparse import Namespace
from logging import getLogger
from pathlib import Path
from random import choice
from shutil import copy, rmtree
from subprocess import DEVNULL, STDOUT, Popen, TimeoutExpired
from tempfile import mkdtemp
from time import sleep, time

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner
from FTB.Signatures.CrashInfo import CrashInfo

from .stats import (
    STATS_UPLOAD_PERIOD,
    GeneratedField,
    MaxTimeField,
    MeanField,
    MeanMinMaxField,
    StatAggregator,
    SumField,
    SumMinMaxField,
    ValueCounterField,
)
from .storage import (
    QUEUE_UPLOAD_PERIOD,
    CloudStorageProvider,
    Corpus,
    CorpusRefreshContext,
    CorpusSyncer,
)
from .utils import LogTee, create_envs, warn_local

LOG = getLogger("gfd.afl")
POWER_SCHEDS = ("explore", "coe", "lin", "quad", "exploit", "rare")


class AFLStats(StatAggregator):
    def __init__(self, instances: int) -> None:
        super().__init__()
        self.add_field("execs_done", SumMinMaxField())
        self.add_field("execs_per_sec", SumMinMaxField())
        self.add_field("pending_favs", SumField())
        self.add_field("pending_total", SumField())
        self.add_field("corpus_variable", SumField())
        self.add_field("saved_crashes", SumField())
        self.add_field("saved_hangs", SumField())
        self.add_field("exec_timeout", MeanField())
        self.add_field("cycles_done", ValueCounterField())
        self.add_field("bitmap_cvg", MeanMinMaxField(suffix="%"))
        self.add_field("last_find", MaxTimeField())
        self.add_field("instances", GeneratedField(suffix=f"/{instances}"))
        self.add_sys_stats()

    def update_and_write(
        self,
        outfile: Path,
        base_dirs: list[Path],
    ) -> None:
        """Generate aggregated statistics from the given base directories
        and write them to the specified output file.

        Args:
            outfile: Output file for aggregated statistics
            base_dirs: List of AFL base directories
            cmdline_path: Optional command line file to use instead of the
                          one found inside the base directory.
        """
        self.reset()
        percent_fields = {"bitmap_cvg"}

        any_stat = False

        def convert_num(num: str) -> float | int:
            if "." in num or num == "inf":
                return float(num)
            return int(num)

        for base_dir in base_dirs:
            stats_path = base_dir / "fuzzer_stats"

            if stats_path.exists():
                stats = stats_path.read_text()

                for line in stats.splitlines():
                    try:
                        (field_name, field_val) = line.split(":", 1)
                    except ValueError:
                        LOG.error("error parsing status line: %r", line)
                        continue
                    field_name = field_name.strip()
                    field_val = field_val.strip()

                    if field_name not in self.fields:
                        continue

                    if field_name in percent_fields:
                        field_val = field_val.rstrip("%")

                    try:
                        self.fields[field_name].update(convert_num(field_val))
                    except ValueError as exc:
                        # ignore errors
                        LOG.error(
                            "error reading %s from %s: %s", field_name, stats_path, exc
                        )
                        continue

                    any_stat = True

        # If we don't have any data here, then the fuzzers haven't written any
        # statistics yet
        if not any_stat:
            return

        self.write_file(outfile, [])


def afl_main(
    opts: Namespace, collector: Collector | None, storage: CloudStorageProvider
) -> int:
    assert opts.aflbindir.is_dir()
    assert opts.rargs, "--afl expects at least one positional arg (target binary)"
    assert opts.instances >= 1
    # afl-fuzz suggested running with AFL_DEBUG=1
    run_with_debug = False
    # num. of times AFL_DEBUG=1 has been run
    debug_runs = 0

    binary = Path(opts.rargs[0]).resolve()
    assert binary.is_file()

    timeout = opts.timeout or 1000

    if opts.corpus_refresh:
        # Run afl-cmin
        afl_cmin = Path(opts.aflbindir) / "afl-cmin"
        if not afl_cmin.exists():
            LOG.error("error: Unable to locate afl-cmin binary.")
            return 2

        with CorpusRefreshContext(opts, storage) as merger:
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = f"{binary.parent / 'gtest'}:{binary.parent}"

            afl_cmdline = [
                str(afl_cmin),
                "-e",
                "-i",
                str(merger.queues_dir),
                "-o",
                str(merger.updated_tests_dir),
                "-t",
                str(timeout),
                "-m",
                "none",
                str(binary),
            ]

            LOG.info("Running afl-cmin")
            # pylint: disable=consider-using-with
            proc: Popen[str] | None = Popen(
                afl_cmdline, stdout=None if opts.debug else DEVNULL, text=True, env=env
            )
            last_stats_report = 0.0
            assert proc is not None
            while proc.poll() is None:
                # Calculate stats
                if opts.stats and last_stats_report < time() - STATS_UPLOAD_PERIOD:
                    merger.refresh_stats.write_file(opts.stats, [])
                    last_stats_report = time()
                sleep(0.1)
            assert not proc.wait()

        assert merger.exit_code is not None
        return merger.exit_code

    assert opts.corpus_in
    assert opts.corpus_out
    assert opts.corpus_in.is_dir()

    opts.corpus_out.mkdir(parents=True, exist_ok=True)
    corpus_syncer = CorpusSyncer(
        storage, Corpus(opts.corpus_out / "0" / "queue"), opts.project
    )
    # sync all queues, since AFL_FINAL_SYNC isn't foolproof
    corpus_syncer.extra_queues.extend(
        Corpus(opts.corpus_out / str(inst) / "queue")
        for inst in range(1, opts.instances)
    )

    start = last_queue_upload = last_stats_report = time()
    last_afl_start = 0.0
    base_cfg = ProgramConfiguration.fromBinary(binary)
    if collector is not None:
        assert base_cfg
    stats = AFLStats(opts.instances)

    metadata = {}
    if opts.metadata:
        metadata.update(dict(kv.split("=", 1) for kv in opts.metadata))
        if collector is not None:
            base_cfg.addMetadata(metadata)

    # environment settings that apply to all instances
    base_env = os.environ.copy()
    base_env["AFL_NO_CRASH_README"] = "1"
    base_env["AFL_NO_UI"] = "1"
    base_env["LD_LIBRARY_PATH"] = f"{binary.parent / 'gtest'}:{binary.parent}"

    envs, cfgs = create_envs(base_env, opts, opts.instances, base_cfg)

    warn_local(opts)

    def on_afl_debug_suggested(_line: str, _match: re.Match[str]) -> None:
        nonlocal run_with_debug
        LOG.warning(
            "AFL_DEBUG=1 suggested by afl-fuzz, will run once with AFL_DEBUG and then "
            "exit"
        )
        run_with_debug = True

    procs: list[Popen[str] | None] = [None] * opts.instances
    log_tee = LogTee(opts.afl_hide_logs, opts.instances)
    log_tee.add_pattern(
        re.compile(r".*Run again with AFL_DEBUG=1"), on_afl_debug_suggested
    )

    # Memorize the original corpus, so we can exclude it from uploading later
    original_corpus = {item.name for item in opts.corpus_in.iterdir()}

    afl_fuzz = opts.aflbindir / "afl-fuzz"
    tmp_base = Path(mkdtemp(prefix="gfd-"))
    try:
        for idx in range(opts.instances):
            if opts.afl_log_pattern:
                if "%" in opts.afl_log_pattern:
                    # pylint: disable=consider-using-with
                    log_tee.append(
                        open(opts.afl_log_pattern % (idx,), "w", encoding="utf-8")
                    )
                else:
                    # pylint: disable=consider-using-with
                    log_tee.append(open(opts.afl_log_pattern, "w", encoding="utf-8"))
            else:
                log_tee.append((tmp_base / f"screen{idx}.log").open("w"))

        seed = choice([inp for inp in opts.corpus_in.iterdir() if inp.is_file()])
        corpus_seed = tmp_base / "corpus_seed"
        corpus_seed.mkdir()
        copy(seed, corpus_seed)

        while opts.max_runtime > time() - start:
            # check and restart subprocesses
            for idx, proc in enumerate(procs):
                if proc and proc.poll() is not None:
                    LOG.warning("afl-fuzz returned early: %d", proc.wait())
                    procs[idx] = proc = None
                    stats.fields["instances"] -= 1  # type: ignore
                    if run_with_debug and debug_runs:
                        # we ran once with AFL_DEBUG=1, time to stop
                        return 1

                if (
                    proc is None
                    # rate limit AFL++ instance launch to 1/minute
                    and last_afl_start < time() - 60
                    # don't launch secondary instances until main instance has finished
                    # initializing
                    and (not idx or (opts.corpus_out / "0" / "fuzzer_stats").exists())
                    # if AFL_DEBUG=1 was suggested, only launch the main instance once
                    # more before terminating
                    and (
                        not run_with_debug
                        or (
                            not idx
                            and not debug_runs
                            and not stats.fields["instances"].value
                        )
                    )
                ):
                    if idx:
                        cmd = ["-S", str(idx), "-p", choice(POWER_SCHEDS)]
                    else:
                        cmd = ["-M", "0"]
                        if opts.afl_async_corpus:
                            cmd.extend(("-F", str(opts.corpus_in)))
                        if opts.afl_add_corpus:
                            for additional_corpus in opts.afl_add_corpus:
                                cmd.extend(("-F", str(additional_corpus)))

                    if opts.memory_limit:
                        cmd.extend(("-m", f"{opts.memory_limit}"))

                    # environment settings that apply to this instance
                    this_env = envs[idx].copy()
                    if opts.afl_async_corpus and not idx:
                        this_env["AFL_IMPORT_FIRST"] = "1"
                    if not idx:
                        this_env["AFL_FINAL_SYNC"] = "1"
                        if run_with_debug:
                            this_env["AFL_DEBUG"] = "1"
                            debug_runs += 1

                    # pylint: disable=consider-using-with
                    procs[idx] = Popen(
                        [
                            str(afl_fuzz),
                            "-t",
                            str(timeout),
                            *cmd,
                            "-i",
                            str(
                                (
                                    corpus_seed
                                    if opts.afl_async_corpus
                                    else opts.corpus_in
                                ).resolve()
                            ),
                            "-o",
                            str(opts.corpus_out.resolve()),
                            "--",
                            str(binary),
                        ],
                        text=True,
                        env=this_env,
                        stderr=STDOUT,
                        stdout=log_tee.open_files[idx].handle,
                    )
                    last_afl_start = time()
                    stats.fields["instances"] += 1  # type: ignore

            # tee logs
            log_tee.print()

            # submit any crashes
            if collector:
                # AFL++ writes crashes in the output directory like:
                #     {output-dir}/{instance-id}/crashes/{testcase}
                for crash_path in opts.corpus_out.glob("*/crashes/*"):
                    if (
                        crash_path.suffix == ".processed"
                        or (
                            crash_path.parent / f"{crash_path.name}.processed"
                        ).is_file()
                    ):
                        continue

                    # repro to collect logs
                    crashing_instance = int(crash_path.parent.parent.name)
                    env = envs[crashing_instance].copy()
                    env["MOZ_FUZZ_TESTFILE"] = str(crash_path.resolve())
                    runner = AutoRunner.fromBinaryArgs(binary, env=env)
                    if runner.run():
                        crash_info = runner.getCrashInfo(cfgs[crashing_instance])
                    else:
                        crash_info = CrashInfo.fromRawCrashData(
                            [], [], cfgs[crashing_instance]
                        )
                        LOG.warning(
                            "Warning: Failed to reproduce the given crash, submitting "
                            "without crash information.",
                        )

                    (sigfile, metadata) = collector.search(crash_info)

                    if sigfile is not None:
                        LOG.warning(
                            "Crash matches signature %s, not submitting...", sigfile
                        )
                    else:
                        collector.generate(
                            crash_info,
                            forceCrashAddress=True,
                            forceCrashInstruction=False,
                            numFrames=8,
                        )
                        result = collector.submit(
                            crash_info,
                            str(crash_path),
                            metaData={
                                "afl-instance": crash_path.parent.parent.name,
                                "afl-crash": crash_path.name,
                            },
                        )
                        LOG.info(
                            'Successfully submitted crash: "%s" as %s',
                            result["shortSignature"],
                            result["id"],
                        )
                    crash_path.rename(
                        crash_path.parent / f"{crash_path.name}.processed"
                    )

            # Only upload new corpus files every 2 hours or after corpus reduction
            if opts.queue_upload and last_queue_upload < time() - QUEUE_UPLOAD_PERIOD:
                corpus_syncer.upload_queue(original_corpus)
                last_queue_upload = time()

            # Calculate stats
            if opts.stats and last_stats_report < time() - STATS_UPLOAD_PERIOD:
                stats.update_and_write(
                    opts.stats,
                    [path.parent for path in opts.corpus_out.glob("*/fuzzer_stats")],
                )
                last_stats_report = time()

            sleep(0.1)
    finally:
        # terminate(), wait(10), kill(), wait()
        # but do in parallel in case there are many procs,
        # we only need to wait 10s total not for each.
        start_term = time()
        for proc in procs:
            if proc:
                proc.terminate()
        while any(procs) and start_term > time() - 10:
            sleep(0.1)
            for idx, proc in enumerate(procs):
                if proc and proc.poll() is not None:
                    procs[idx] = None
        if any(procs):
            LOG.info("need to kill %d", sum(1 for proc in procs if proc))
        for proc in procs:
            if proc:
                proc.kill()
                try:
                    proc.wait(timeout=1)
                except TimeoutExpired:
                    LOG.warning("Process %d did not exit after SIGKILL", proc.pid)

        log_tee.close()

        if opts.queue_upload:
            corpus_syncer.upload_queue(original_corpus)

        # final stats
        if opts.stats:
            stats.update_and_write(
                opts.stats,
                [path.parent for path in opts.corpus_out.glob("*/fuzzer_stats")],
            )

        rmtree(tmp_base)

    return 0
