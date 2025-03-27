# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
from argparse import Namespace
from logging import getLogger
from pathlib import Path, PurePosixPath
from random import choice
from shutil import copy, move, rmtree, which
from subprocess import STDOUT, Popen, TimeoutExpired, run
from tempfile import mkdtemp
from time import sleep, time

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
from .utils import LogTee, create_envs, open_log_handle, warn_local

ASAN_SYMBOLIZE = which("asan_symbolize")
LOG = getLogger("gfd.nyx")


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

    log_tee = LogTee(opts.afl_hide_logs, opts.instances)
    tmp_base = Path(mkdtemp(prefix="gfd-"))

    if opts.corpus_refresh:
        # Run afl-cmin
        afl_cmin = Path(opts.aflbindir) / "afl-cmin"
        if not afl_cmin.exists():
            LOG.error("error: Unable to locate afl-cmin binary.")
            return 2

        with CorpusRefreshContext(opts, storage, extra_files=[config_file]) as merger:
            # Copy config.sh to sharedir
            if not (merger.queues_dir / "config.sh").exists():
                raise RuntimeError(
                    "Cannot refresh corpus without config.sh file. Aborting..."
                )

            move(merger.queues_dir / "config.sh", config_file)

            log_tee.append(open_log_handle(opts.afl_log_pattern, tmp_base, 0))

            env = os.environ.copy()
            if opts.nyx_log_pattern:
                if "%" in opts.nyx_log_pattern:
                    env["AFL_NYX_LOG"] = opts.nyx_log_pattern % (0,)
                else:
                    env["AFL_NYX_LOG"] = opts.nyx_log_pattern

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
                "-X",
                str(opts.sharedir),
            ]

            try:

                LOG.info("Running afl-cmin")
                # pylint: disable=consider-using-with
                proc: Popen[str] | None = Popen(
                    afl_cmdline,
                    env=env,
                    stderr=STDOUT,
                    stdout=log_tee.open_files[0].handle,
                    text=True,
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
                log_tee.print()
            finally:
                log_tee.close()
                rmtree(tmp_base)

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

    afl_fuzz = opts.aflbindir / "afl-fuzz"
    try:
        for idx in range(opts.instances):
            log_tee.append(open_log_handle(opts.afl_log_pattern, tmp_base, idx))

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
                proc.kill()
                try:
                    proc.wait(timeout=1)
                except TimeoutExpired:
                    LOG.error("Process %d did not exit after SIGKILL", proc.pid)

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
