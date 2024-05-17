# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import sys
from argparse import Namespace
from pathlib import Path
from random import choice
from shutil import copy, rmtree
from subprocess import STDOUT, Popen, TimeoutExpired
from tempfile import mkdtemp
from time import sleep, time
from typing import List, Optional, Union

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner
from FTB.Signatures.CrashInfo import CrashInfo

from .s3 import S3Manager
from .stats import (
    GeneratedField,
    MaxTimeField,
    MeanField,
    MeanMinMaxField,
    StatAggregator,
    SumField,
    SumMinMaxField,
    ValueCounterField,
)
from .utils import LogTee, create_envs, warn_local

POWER_SCHEDS = ("explore", "coe", "lin", "quad", "exploit", "rare")
QUEUE_UPLOAD_PERIOD = 7200


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
        base_dirs: List[Path],
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

        def convert_num(num: str) -> Union[float, int]:
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
                        print(f"error parsing status line: {line!r}", file=sys.stderr)
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
                        print(
                            f"error reading {field_name} from {stats_path}: {exc}",
                            file=sys.stderr,
                        )
                        continue

                    any_stat = True

        # If we don't have any data here, then the fuzzers haven't written any
        # statistics yet
        if not any_stat:
            return

        self.write_file(outfile, [])


def afl_main(
    opts: Namespace, collector: Optional[Collector], s3m: Optional[S3Manager]
) -> int:
    assert opts.aflbindir.is_dir()
    assert opts.rargs, "--afl expects at least one positional arg (target binary)"
    assert opts.corpus_in
    assert opts.corpus_out
    assert opts.corpus_in.is_dir()
    assert opts.instances >= 1

    binary = Path(opts.rargs[0]).resolve()
    assert binary.is_file()
    opts.corpus_out.mkdir(parents=True, exist_ok=True)

    if opts.max_runtime == 0.0:
        opts.max_runtime = float("inf")

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

                    # pylint: disable=consider-using-with
                    procs[idx] = Popen(
                        [
                            str(afl_fuzz),
                            "-t",
                            str(opts.afl_timeout),
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
                        print(
                            "Warning: Failed to reproduce the given crash, submitting "
                            "without crash information.",
                            file=sys.stderr,
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
                                "afl-instance": crash_path.parent.parent.name,
                                "afl-crash": crash_path.name,
                            },
                        )
                        print(
                            'Successfully submitted crash: "'
                            f"{result['shortSignature']}\" as {result['id']}",
                            file=sys.stderr,
                        )
                    crash_path.rename(
                        crash_path.parent / f"{crash_path.name}.processed"
                    )

            # Only upload new corpus files every 2 hours or after corpus reduction
            if (
                opts.s3_queue_upload
                and last_queue_upload < time() - QUEUE_UPLOAD_PERIOD
            ):
                assert s3m is not None
                s3m.upload_afl_queue_dir(
                    opts.corpus_out / "0",
                    opts.corpus_out / "0" / "cmdline",
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
                opts.corpus_out / "0",
                opts.corpus_out / "0" / "cmdline",
                include_sync=True,
            )

        # final stats
        if opts.stats:
            stats.update_and_write(
                opts.stats,
                [path.parent for path in opts.corpus_out.glob("*/fuzzer_stats")],
            )

        rmtree(tmp_base)

    return 0
