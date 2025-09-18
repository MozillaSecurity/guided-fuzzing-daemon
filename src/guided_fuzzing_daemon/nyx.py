# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
import signal
from argparse import Namespace
from collections.abc import Iterator
from contextlib import contextmanager
from logging import getLogger
from pathlib import Path, PurePosixPath
from random import choice
from shutil import copy, move, rmtree, which
from subprocess import STDOUT, Popen, TimeoutExpired, run
from time import sleep, time
from typing import Any

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo, TraceParsingError

from .afl import POWER_SCHEDS, AFLStats
from .stats import STATS_UPLOAD_PERIOD
from .storage import (
    QUEUE_UPLOAD_PERIOD,
    CloudStorageProvider,
    Corpus,
    CorpusRefreshContext,
    CorpusSyncer,
)
from .utils import LogTee, TempPath, create_envs, open_log_handle, warn_local

ASAN_SYMBOLIZE = which("asan_symbolize")
LOG = getLogger("gfd.nyx")

# Depending on where in the fuzzing loop we are when the interrupt is sent,
# AFL may take up to 15 minutes to exit
AFL_INTERRUPT_WAIT = 15 * 60


@contextmanager
def ForceClosingPopen(*args: Any, **kwds: Any) -> Iterator[Popen[str]]:  # pylint: disable=invalid-name
    # pylint: disable=consider-using-with
    proc = Popen(*args, **kwds)
    try:
        yield proc
    finally:
        try:
            proc.wait(timeout=2)
        except TimeoutExpired:
            # SIGKILL is needed to ensure Nyx/Qemu processes are terminated
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        assert proc.wait(timeout=5) == 0


def nyx_main(
    opts: Namespace,
    collector: Collector | None,
    storage: CloudStorageProvider,
) -> int:
    assert opts.aflbindir.is_dir()
    assert opts.sharedir.is_dir()
    assert ASAN_SYMBOLIZE is not None
    assert not opts.rargs, "--nyx takes no positional args"

    timeout = opts.timeout or 1000

    config_file = opts.sharedir / "config.sh"

    if opts.corpus_refresh:
        # Run afl-cmin
        afl_cmin = Path(opts.aflbindir) / "afl-cmin"
        if not afl_cmin.exists():
            LOG.error("error: Unable to locate afl-cmin binary.")
            return 2

        with (
            CorpusRefreshContext(
                opts, storage, separate_corpus=True, extra_files=[config_file]
            ) as merger,
            TempPath() as tmp_base,
            LogTee(opts.afl_hide_logs, opts.instances) as log_tee,
        ):
            # Copy config.sh to sharedir
            for src_dir in (merger.queues_dir, merger.corpus_dir):
                if (src_dir / "config.sh").exists():
                    move(src_dir / "config.sh", config_file)
                    break
            else:
                raise RuntimeError(
                    "Cannot refresh corpus without config.sh file. Aborting..."
                )

            log_tee.append(open_log_handle(opts.afl_log_pattern, tmp_base, 0))

            env = os.environ.copy()
            if opts.nyx_log_pattern:
                if "%" in opts.nyx_log_pattern:
                    env["AFL_NYX_LOG"] = opts.nyx_log_pattern % (0,)
                else:
                    env["AFL_NYX_LOG"] = opts.nyx_log_pattern

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

            LOG.info("Running afl-cmin")
            last_stats_report = 0.0
            collect_proc = None
            i = 0
            try:
                for i, input_dir in enumerate((merger.corpus_dir, merger.queues_dir)):
                    if not any(f.is_file() for f in input_dir.iterdir()):
                        continue
                    with ForceClosingPopen(
                        [
                            *base_args,
                            "-i",
                            str(input_dir),
                            "-c",
                            "-X",
                            str(opts.sharedir),
                        ],
                        stderr=STDOUT,
                        stdout=log_tee.open_files[0].handle,
                        text=True,
                        env=env,
                        start_new_session=True,
                    ) as collect_proc:
                        try:
                            while collect_proc.poll() is None:
                                if (
                                    opts.stats
                                    and last_stats_report < time() - STATS_UPLOAD_PERIOD
                                ):
                                    merger.refresh_stats.write_file(opts.stats, [])
                                    last_stats_report = time()
                                sleep(0.1)

                        except KeyboardInterrupt:
                            if i == 0:
                                LOG.warning(
                                    "Interrupt detected during "
                                    "initial corpus processing"
                                )
                            else:
                                LOG.warning(
                                    "Interrupt detected - "
                                    "processing the results we have"
                                )
                            raise
            finally:
                if i > 0:
                    trace_path = merger.updated_tests_dir / ".traces"
                    if not any(f.is_file() for f in trace_path.iterdir()):
                        LOG.error("No results found in the test directory!")
                    else:
                        with ForceClosingPopen(
                            [
                                *base_args,
                                "-i",
                                str(merger.corpus_dir),
                                "-i",
                                str(merger.queues_dir),
                                "-p",
                                "-X",
                                str(opts.sharedir),
                            ],
                            env=env,
                            start_new_session=True,
                            stderr=STDOUT,
                            stdout=log_tee.open_files[0].handle,
                            text=True,
                        ) as process_proc:
                            try:
                                process_proc.wait()
                            except KeyboardInterrupt:
                                LOG.warning(
                                    "Interrupt detected during post-trace processing"
                                )
                                raise

        assert merger.exit_code is not None
        return merger.exit_code

    assert opts.corpus_in
    assert opts.corpus_out
    assert opts.corpus_in.is_dir()
    assert opts.instances >= 1
    assert config_file.is_file()

    opts.corpus_out.mkdir(parents=True, exist_ok=True)
    queue = Corpus(opts.corpus_out / "0" / "queue")
    corpus_syncer = CorpusSyncer(storage, queue, opts.project)
    # sync all queues, since AFL_FINAL_SYNC isn't foolproof
    corpus_syncer.extra_queues.extend(
        Corpus(opts.corpus_out / str(inst) / "queue")
        for inst in range(1, opts.instances)
    )

    # Memorize the original corpus, so we can exclude it from uploading later
    original_corpus = {item.name for item in opts.corpus_in.iterdir()}

    if opts.max_runtime == 0.0:
        opts.max_runtime = float("inf")

    start = last_queue_upload = last_stats_report = time()
    last_afl_start = 0.0
    base_cfg = ProgramConfiguration.fromBinary(
        str(opts.sharedir / "firefox" / "firefox")
    )
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
    base_env["AFL_NO_UI"] = "1"

    envs, cfgs = create_envs(base_env, opts, opts.instances, base_cfg)

    warn_local(opts)

    procs: list[Popen[str] | None] = [None] * opts.instances
    log_tee = LogTee(opts.afl_hide_logs, opts.instances)

    afl_fuzz = opts.aflbindir / "afl-fuzz"
    tmp_base = TempPath().path
    try:
        for idx in range(opts.instances):
            log_tee.append(open_log_handle(opts.afl_log_pattern, tmp_base, idx))

        seed = choice([inp for inp in opts.corpus_in.iterdir() if inp.is_file()])
        corpus_seed = tmp_base / "corpus_seed"
        corpus_seed.mkdir()
        copy(seed, corpus_seed)

        if AFL_INTERRUPT_WAIT > opts.max_runtime:
            LOG.warning("Max runtime is less than interrupt wait time.  Aborting...")
            return 0

        while opts.max_runtime - AFL_INTERRUPT_WAIT > time() - start:
            # check and restart subprocesses
            for idx, proc in enumerate(procs):
                if proc and proc.poll() is not None:
                    LOG.warning("afl-fuzz returned early: %d", proc.wait())
                    procs[idx] = proc = None
                    stats.fields["instances"] -= 1  # type: ignore

                if (
                    proc is None
                    # rate limit AFL++ instance launch to 1/minute
                    and last_afl_start < time() - 60
                    # don't launch secondary instances until main instance has finished
                    # initializing
                    and (not idx or (opts.corpus_out / "0" / "fuzzer_stats").exists())
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

                    # environment settings that apply to this instance
                    this_env = envs[idx].copy()
                    if opts.afl_async_corpus and not idx:
                        this_env["AFL_IMPORT_FIRST"] = "1"
                    if not idx:
                        this_env["AFL_FINAL_SYNC"] = "1"
                    if opts.nyx_log_pattern:
                        if "%" in opts.nyx_log_pattern:
                            this_env["AFL_NYX_LOG"] = opts.nyx_log_pattern % (idx,)
                        else:
                            this_env["AFL_NYX_LOG"] = opts.nyx_log_pattern

                    # pylint: disable=consider-using-with
                    procs[idx] = Popen(
                        [
                            str(afl_fuzz),
                            "-t",
                            str(timeout),
                            "-Y",
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
                            str(opts.sharedir.resolve()),
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
            # AFL++ writes crashes in the output directory like:
            #     {output-dir}/{instance-id}/crashes/{testcase}
            # Nyx mode also adds `{testcase}.log` beside it, which
            # is an unsymbolized ASan log copied out of the QEMU VM.
            for log in opts.corpus_out.glob("*/crashes/*.log"):
                idx = int(log.parent.parent.name)
                crash_path = log.with_suffix("")
                log_content = log.read_text()
                LOG.info("symbolizing %s (len=%d)", log, len(log_content))
                log_content = log_content.replace(
                    "ld_preload_fuzz_no_pt.so",
                    str(opts.sharedir.resolve() / "ld_preload_fuzz_no_pt.so"),
                ).replace(
                    "/home/user/firefox", str(opts.sharedir.resolve() / "firefox")
                )
                sym_result = run(
                    [ASAN_SYMBOLIZE, "-d"],
                    input=log_content,
                    capture_output=True,
                    text=True,
                )
                if sym_result.returncode:
                    LOG.warning("asan_symbolize returned %d", sym_result.returncode)
                    LOG.warning("=" * 20)
                    if sym_result.stderr.strip():
                        for line in sym_result.stderr.splitlines():
                            LOG.warning(line)
                    LOG.warning("=" * 20)
                    # silence pylint (possibly-used-before-assignment)
                    symbolized = ""
                else:
                    log_content = symbolized = sym_result.stdout
                if collector is not None:
                    log_lines = log_content.splitlines()
                    try:
                        crash_info = CrashInfo.fromRawCrashData(
                            [],
                            [],
                            cfgs[idx],
                            auxCrashData=log_lines,
                        )
                    except TraceParsingError as exc:
                        # try again with the error lines omitted
                        LOG.warning(
                            "CrashInfo.fromRawCrashData raised TraceParsingError: %s",
                            exc,
                        )
                        LOG.warning("original crash data")
                        LOG.warning("=" * 20)
                        for line_no, line in enumerate(log_lines):
                            if line_no == exc.line_no:
                                LOG.warning("=> %s <=", line)
                            else:
                                LOG.warning("   %s", line)
                        LOG.warning("=" * 20)
                        LOG.warning(
                            "Retrying without last %d lines",
                            len(log_lines) - exc.line_no,
                        )
                        crash_info = CrashInfo.fromRawCrashData(
                            [],
                            log_lines[exc.line_no :],
                            cfgs[idx],
                            auxCrashData=log_lines[: exc.line_no],
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
                                "afl-instance": log.parent.parent.name,
                                "afl-crash": crash_path.name,
                            },
                        )
                        LOG.info(
                            'Successfully submitted crash: "%s" as %s',
                            result["shortSignature"],
                            result["id"],
                        )
                elif not sym_result.returncode:
                    log.with_suffix(".log.symbolized").write_text(symbolized)
                log.rename(log.with_suffix(".log.processed"))

            # Only upload new corpus files every 2 hours or after corpus reduction
            if opts.queue_upload and last_queue_upload < time() - QUEUE_UPLOAD_PERIOD:
                corpus_syncer.upload_queue(original_corpus)
                remote_obj = storage[
                    PurePosixPath(opts.project) / "queues" / queue.uuid / "config.sh"
                ]
                remote_obj.upload_from_file(config_file, True)
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
            LOG.warning("need to kill %d", sum(1 for proc in procs if proc))
        for proc in procs:
            if proc:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=AFL_INTERRUPT_WAIT)
                except TimeoutExpired:
                    LOG.error("Process %d did not exit after SIGINT", proc.pid)

        log_tee.close()

        if opts.queue_upload:
            corpus_syncer.upload_queue(original_corpus)
            remote_obj = storage[
                PurePosixPath(opts.project) / "queues" / queue.uuid / "config.sh"
            ]
            remote_obj.upload_from_file(config_file, True)

        # final stats
        if opts.stats:
            stats.update_and_write(
                opts.stats,
                [path.parent for path in opts.corpus_out.glob("*/fuzzer_stats")],
            )

        rmtree(tmp_base)

    return 0
