# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import sys
from argparse import Namespace
from pathlib import Path
from random import choice
from shutil import copy, rmtree, which
from subprocess import STDOUT, Popen, TimeoutExpired, run
from tempfile import mkdtemp
from time import sleep, time
from typing import List, Optional

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo, TraceParsingError

from .afl import POWER_SCHEDS, AFLStats
from .s3 import S3Manager
from .utils import LogTee, create_envs, warn_local

ASAN_SYMBOLIZE = which("asan_symbolize")
QUEUE_UPLOAD_PERIOD = 7200


def nyx_main(
    opts: Namespace, collector: Optional[Collector], s3m: Optional[S3Manager]
) -> int:
    assert opts.aflbindir.is_dir()
    assert opts.sharedir.is_dir()
    assert ASAN_SYMBOLIZE is not None
    assert not opts.rargs, "--nyx takes no positional args"
    assert opts.corpus_in
    assert opts.corpus_out
    assert opts.corpus_in.is_dir()
    assert opts.instances >= 1

    opts.corpus_out.mkdir(parents=True, exist_ok=True)

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

    procs: List[Optional["Popen[str]"]] = [None] * opts.instances
    log_tee = LogTee(opts.afl_hide_logs, opts.instances)

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
                    print(f"afl-fuzz returned early: {proc.wait()}", file=sys.stderr)
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
                    if opts.afl_log_pattern:
                        if "%" in opts.afl_log_pattern:
                            this_env["AFL_NYX_LOG"] = opts.afl_log_pattern % (idx,)
                        else:
                            this_env["AFL_NYX_LOG"] = opts.afl_log_pattern

                    # pylint: disable=consider-using-with
                    procs[idx] = Popen(
                        [
                            str(afl_fuzz),
                            "-t",
                            str(opts.afl_timeout),
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
                print(f"symbolizing {log} (len={len(log_content)})", file=sys.stderr)
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
                    print(
                        f"asan_symbolize returned {sym_result.returncode}",
                        file=sys.stderr,
                    )
                    print("=" * 20, file=sys.stderr)
                    if sym_result.stderr.strip():
                        sys.stderr.write(sym_result.stderr)
                    print("=" * 20, file=sys.stderr)
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
                        print(
                            "CrashInfo.fromRawCrashData raised TraceParsingError:",
                            exc,
                            file=sys.stderr,
                        )
                        print("original crash data", file=sys.stderr)
                        print("=" * 20, file=sys.stderr)
                        for line_no, line in enumerate(log_lines):
                            if line_no == exc.line_no:
                                print(f"=> {line} <=", file=sys.stderr)
                            else:
                                print(f"   {line}", file=sys.stderr)
                        print("=" * 20, file=sys.stderr)
                        print(
                            f"Retrying without last {len(log_lines) - exc.line_no} "
                            "lines",
                            file=sys.stderr,
                        )
                        crash_info = CrashInfo.fromRawCrashData(
                            [],
                            log_lines[exc.line_no :],
                            cfgs[idx],
                            auxCrashData=log_lines[: exc.line_no],
                        )

                    (sigfile, metadata) = collector.search(crash_info)

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
                        result = collector.submit(
                            crash_info,
                            str(crash_path),
                            metaData={
                                "afl-instance": log.parent.parent.name,
                                "afl-crash": crash_path.name,
                            },
                        )
                        print(
                            'Successfully submitted crash: "'
                            f"{result['shortSignature']}\" as {result['id']}",
                            file=sys.stderr,
                        )
                elif not sym_result.returncode:
                    log.with_suffix(".log.symbolized").write_text(symbolized)
                log.rename(log.with_suffix(".log.processed"))

            # Only upload new corpus files every 2 hours or after corpus reduction
            if (
                opts.s3_queue_upload
                and last_queue_upload < time() - QUEUE_UPLOAD_PERIOD
            ):
                assert s3m is not None
                s3m.upload_afl_queue_dir(
                    opts.corpus_out / "0",
                    opts.sharedir / "config.sh",
                    include_sync=True,
                )
                last_queue_upload = time()

            # Calculate stats
            if opts.stats and last_stats_report < time() - 30:
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
            print(f"need to kill {sum(1 for proc in procs if proc)}", file=sys.stderr)
        for proc in procs:
            if proc:
                proc.kill()
                try:
                    proc.wait(timeout=1)
                except TimeoutExpired:
                    print(
                        f"Process {proc.pid} did not exit after SIGKILL",
                        file=sys.stderr,
                    )

        log_tee.close()

        if s3m and opts.s3_queue_upload:
            s3m.upload_afl_queue_dir(
                opts.corpus_out / "0", opts.sharedir / "config.sh", include_sync=True
            )

        # final stats
        if opts.stats:
            stats.update_and_write(
                opts.stats,
                [path.parent for path in opts.corpus_out.glob("*/fuzzer_stats")],
            )

        rmtree(tmp_base)

    return 0
