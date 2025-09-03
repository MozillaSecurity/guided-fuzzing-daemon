# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
import re
import signal
from argparse import Namespace
from logging import getLogger
from pathlib import Path
from random import choice
from shutil import copy, rmtree
from subprocess import STDOUT, Popen, TimeoutExpired
from time import sleep, time

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner

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
from .utils import LogTee, TempPath, create_envs, open_log_handle, warn_local

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

    base_env = os.environ.copy()
    library_path = [str(binary.parent / "gtest"), str(binary.parent)]
    library_path.extend(base_env.get("LD_LIBRARY_PATH", "").split(":"))
    base_env["LD_LIBRARY_PATH"] = ":".join(library_path)

    timeout = opts.timeout or 1000

    if opts.corpus_refresh:
        # Run afl-cmin
        afl_cmin = Path(opts.aflbindir) / "afl-cmin"
        if not afl_cmin.exists():
            LOG.error("error: Unable to locate afl-cmin binary.")
            return 2

        with (
            CorpusRefreshContext(opts, storage, separate_corpus=True) as merger,
            TempPath() as tmp_base,
            LogTee(opts.afl_hide_logs, opts.instances) as log_tee,
        ):
            log_tee.append(open_log_handle(opts.afl_log_pattern, tmp_base, 0))
            base_args = [
                str(afl_cmin),
                "-e",
                "-o",
                str(merger.updated_tests_dir),
                "-t",
                str(timeout),
                "-m",
                "none",
            ]

            if opts.instances > 1:
                base_args.extend(["-T", str(opts.instances)])

            LOG.info("Running afl-cmin")

            last_stats_report = 0.0
            collect_proc = None

            i = 0
            input_dirs = [merger.corpus_dir, merger.queues_dir]
            try:
                for i, input_dir in enumerate(input_dirs):
                    if not any(f.is_file() for f in input_dir.iterdir()):
                        continue
                    # pylint: disable=consider-using-with
                    collect_proc = Popen(
                        [
                            *base_args,
                            "-i",
                            str(input_dir),
                            "-c",
                            "--",
                            str(binary),
                            *opts.rargs[1:],
                        ],
                        stderr=STDOUT,
                        stdout=log_tee.open_files[0].handle,
                        text=True,
                        env=base_env,
                        start_new_session=True,
                    )

                    assert collect_proc is not None
                    while collect_proc.poll() is None:
                        if (
                            opts.stats
                            and last_stats_report < time() - STATS_UPLOAD_PERIOD
                        ):
                            merger.refresh_stats.write_file(opts.stats, [])
                            last_stats_report = time()
                        sleep(0.1)
                    assert not collect_proc.wait()

            except KeyboardInterrupt:
                if i == 0:
                    LOG.warning("Interrupt detected during initial corpus processing")
                    raise

                LOG.warning("Interrupt detected - processing the results we have")
                if collect_proc is not None:
                    try:
                        collect_proc.wait(timeout=2)
                    except TimeoutExpired:
                        os.killpg(os.getpgid(collect_proc.pid), signal.SIGKILL)
                        collect_proc.wait(timeout=5)
                raise
            finally:
                if i > 0:
                    trace_path = merger.updated_tests_dir / ".traces"
                    if not any(f.is_file() for f in trace_path.iterdir()):
                        LOG.error("No results found in the test directory!")
                    else:
                        # pylint: disable=consider-using-with
                        process_proc = Popen(
                            [
                                *base_args,
                                "-i",
                                str(merger.corpus_dir),
                                "-i",
                                str(merger.queues_dir),
                                "-p",
                                "--",
                                str(binary),
                                *opts.rargs[1:],
                            ],
                            stderr=STDOUT,
                            stdout=log_tee.open_files[0].handle,
                            text=True,
                            env=base_env,
                        )
                        assert not process_proc.wait()

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
    tmp_base = TempPath().path

    try:
        for idx in range(opts.instances):
            log_tee.append(open_log_handle(opts.afl_log_pattern, tmp_base, idx))

        seed = choice([inp for inp in opts.corpus_in.iterdir() if inp.is_file()])
        corpus_seed = tmp_base / "corpus_seed"
        corpus_seed.mkdir()
        copy(seed, corpus_seed)

        while opts.max_runtime > time() - start:
            # check and restart subprocesses
            for idx, collect_proc in enumerate(procs):
                if collect_proc and collect_proc.poll() is not None:
                    LOG.warning("afl-fuzz returned early: %d", collect_proc.wait())
                    procs[idx] = collect_proc = None
                    stats.fields["instances"] -= 1  # type: ignore
                    if run_with_debug and debug_runs:
                        # we ran once with AFL_DEBUG=1, time to stop
                        return 1

                if (
                    collect_proc is None
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

                    if opts.max_fuzz_runs:
                        cmd.extend(("-E", f"{opts.max_fuzz_runs}"))

                    if opts.max_fuzz_time:
                        cmd.extend(("-V", f"{opts.max_fuzz_time}"))

                    if opts.memory_limit:
                        cmd.extend(("-m", f"{opts.memory_limit}"))

                    if "TOKENS" in envs[idx]:
                        cmd.extend(("-x", envs[idx]["TOKENS"]))

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
                            *opts.rargs[1:],
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
                        or crash_path.suffix == ".norepro"
                        or (crash_path.parent / f"{crash_path.name}.norepro").is_file()
                    ):
                        continue

                    # repro to collect logs
                    crashing_instance = int(crash_path.parent.parent.name)
                    env = envs[crashing_instance].copy()
                    env["MOZ_FUZZ_TESTFILE"] = str(crash_path.resolve())
                    # many targets require `AFL_PRELOAD` to get coverage from dlopen-ed
                    # libraries, but we don't care about coverage for repro, so just
                    # ignore problems (using `LD_PRELOAD` silences the warnings, but
                    # breaks `llvm-symbolizer`)
                    env["AFL_IGNORE_PROBLEMS"] = "1"
                    if "ASAN_OPTIONS" in env:
                        env["ASAN_OPTIONS"] = env["ASAN_OPTIONS"].replace(
                            "symbolize=0", "symbolize=1"
                        )
                    runner = AutoRunner.fromBinaryArgs(binary, env=env)
                    if runner.run():
                        crash_info = runner.getCrashInfo(cfgs[crashing_instance])
                    else:
                        LOG.warning(
                            "Warning: Failed to reproduce the given crash, "
                            "not submitting."
                        )
                        crash_path.rename(
                            crash_path.parent / f"{crash_path.name}.norepro"
                        )
                        continue

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
        for collect_proc in procs:
            if collect_proc:
                collect_proc.terminate()
        while any(procs) and start_term > time() - 10:
            sleep(0.1)
            for idx, collect_proc in enumerate(procs):
                if collect_proc and collect_proc.poll() is not None:
                    procs[idx] = None
        if any(procs):
            LOG.info("need to kill %d", sum(1 for proc in procs if proc))
        for collect_proc in procs:
            if collect_proc:
                collect_proc.kill()
                try:
                    collect_proc.wait(timeout=1)
                except TimeoutExpired:
                    LOG.warning(
                        "Process %d did not exit after SIGKILL", collect_proc.pid
                    )

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
