# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import shutil
import subprocess
import sys
import time
import traceback
from argparse import Namespace
from pathlib import Path
from typing import List, Optional, Tuple, Union

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner

from .s3 import S3Manager
from .stats import ListField, MaxTimeField, MeanField, StatAggregator, SumField
from .utils import HAVE_FFPUPPET, apply_transform, setup_firefox, warn_local


def command_file_to_list(cmd_file: Path) -> Tuple[Optional[int], List[str]]:
    """Open and parse custom command line file

    Args:
        cmd_file: Command line file containing list of commands

    Returns:
        Test index in list and the command as a list of strings
    """
    cmdline = []
    idx = 0
    test_idx = None
    with open(cmd_file, encoding="utf-8") as cmd_fp:
        for line in cmd_fp:
            if "@@" in line:
                test_idx = idx
            cmdline.append(line.rstrip())
            idx += 1

    return test_idx, cmdline


def scan_crashes(
    base_dir: Path,
    collector: Collector,
    cmdline_path: Optional[Path] = None,
    env_path: Optional[Path] = None,
    test_path: Optional[Path] = None,
    firefox: bool = False,
    firefox_prefs: Optional[Path] = None,
    firefox_extensions: Optional[List[Path]] = None,
    firefox_testpath: Optional[Path] = None,
    transform: Optional[Path] = None,
) -> None:
    """Scan the base directory for crash tests and submit them to FuzzManager.

    Args:
        base_dir: AFL base directory
        cmdline_path: Optional command line file to use instead of the
                      one found inside the base directory.
        env_path: Optional file containing environment variables.
        test_path: Optional filename where to copy the test before
                   attempting to reproduce a crash.
        transform: Optional path to script for applying post-crash
                   transformations.

    Returns:
        Non-zero return code on failure
    """
    crash_dir = base_dir / "crashes"
    crash_files = []

    for crash_path in crash_dir.iterdir():
        # Ignore all files that aren't crash results
        if not crash_path.name.startswith("id:"):
            continue

        # Ignore our own status files
        if crash_path.suffix in {".submitted", ".failed"}:
            continue

        # Ignore files we already processed
        if (crash_dir / f"{crash_path.name}.submitted").exists() or (
            crash_dir / f"{crash_path.name}.failed"
        ).exists():
            continue

        crash_files.append(crash_path)

    if crash_files:
        # First try to read necessary information for reproducing crashes

        base_env = {}
        test_in_env = None
        if env_path:
            with open(env_path, encoding="utf-8") as env_file:
                for line in env_file:
                    (name, val) = line.rstrip("\n").split("=", 1)
                    base_env[name] = val

                    if "@@" in val:
                        test_in_env = name

        if not cmdline_path:
            cmdline_path = base_dir / "cmdline"

        test_idx, cmdline = command_file_to_list(cmdline_path)
        if test_idx is not None:
            orig_test_arg = cmdline[test_idx]

        configuration = ProgramConfiguration.fromBinary(cmdline[0])
        if not configuration:
            raise RuntimeError(
                "Creating program configuration from binary failed. "
                "Check your binary configuration file."
            )

        if firefox:
            assert firefox_prefs is not None
            assert firefox_testpath is not None
            (ffp, ff_cmd, ff_env) = setup_firefox(
                Path(cmdline[0]),
                firefox_prefs,
                firefox_extensions or [],
                firefox_testpath,
            )
            cmdline = ff_cmd
            base_env.update(ff_env)

        for crash_file in crash_files:
            stdin = None
            env = {}

            if base_env:
                env = dict(base_env)

            submission = crash_file
            if transform:
                try:
                    submission = apply_transform(transform, crash_file)
                except Exception as exc:  # pylint: disable=broad-except
                    print(exc.args[1], file=sys.stderr)

            if test_idx is not None:
                cmdline[test_idx] = orig_test_arg.replace("@@", str(crash_file))
            elif test_in_env is not None:
                env[test_in_env] = env[test_in_env].replace("@@", str(crash_file))
            elif test_path is not None:
                shutil.copy(str(crash_file), test_path)
            else:
                stdin = crash_file.read_text()

            print(f"Processing crash file {crash_file}", file=sys.stderr)

            runner = AutoRunner.fromBinaryArgs(
                cmdline[0], cmdline[1:], env=env, stdin=stdin
            )
            if runner.run():
                crash_info = runner.getCrashInfo(configuration)
                collector.submit(crash_info, submission)
                (submission.parent / f"{submission.name}.submitted").touch()
                print("Success: Submitted crash to server.", file=sys.stderr)
            else:
                (submission.parent / f"{submission.name}.failed").touch()
                print(
                    "error: Failed to reproduce the given crash, cannot submit.",
                    file=sys.stderr,
                )

        if firefox:
            ffp.clean_up()


class AFLStats(StatAggregator):
    def __init__(self) -> None:
        super().__init__()
        self.add_field("execs_done", SumField())
        self.add_field("execs_per_sec", SumField())
        self.add_field("pending_favs", SumField())
        self.add_field("pending_total", SumField())
        self.add_field("variable_paths", SumField())
        self.add_field("unique_crashes", SumField())
        self.add_field("unique_hangs", SumField())
        self.add_field("exec_timeout", MeanField())
        self.add_field("cycles_done", ListField())
        self.add_field("bitmap_cvg", ListField())
        self.add_field("last_path", MaxTimeField())
        self.add_sys_stats()

    def update_and_write(
        self,
        outfile: Path,
        base_dirs: List[Path],
        cmdline_path: Optional[Path] = None,
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
        do_not_convert = {"cycles_done", "bitmap_cvg"}
        renames = {"last_find": "last_path"}

        # Warnings to include
        warnings = []

        any_stat = False

        def convert_num(num: str) -> Union[float, int]:
            if "." in num:
                return float(num)
            return int(num)

        for base_dir in base_dirs:
            stats_path = base_dir / "fuzzer_stats"

            if not cmdline_path:
                cmdline_path = base_dir / "cmdline"

            if stats_path.exists():
                stats = stats_path.read_text()

                for line in stats.splitlines():
                    (field_name, field_val) = line.split(":", 1)
                    field_name = field_name.strip()
                    field_val = field_val.strip()

                    field_name = renames.get(field_name, field_name)

                    if field_name not in self.fields:
                        continue

                    if field_name in do_not_convert:
                        self.fields[field_name].update(field_val)
                    else:
                        self.fields[field_name].update(convert_num(field_val))

                    any_stat = True

        # If we don't have any data here, then the fuzzers haven't written any
        # statistics yet
        if not any_stat:
            return

        # Verify fuzzmanagerconf exists and can be parsed
        assert cmdline_path is not None
        _, cmdline = command_file_to_list(cmdline_path)
        target_binary = cmdline[0] if cmdline else None

        if target_binary is not None:
            if not Path(f"{target_binary}.fuzzmanagerconf").is_file():
                warnings.append(f"WARNING: Missing {target_binary}.fuzzmanagerconf\n")
            elif ProgramConfiguration.fromBinary(target_binary) is None:
                warnings.append(f"WARNING: Invalid {target_binary}.fuzzmanagerconf\n")

        # Look for unreported crashes
        failed_reports = 0
        for base_dir in base_dirs:
            crashes_dir = base_dir / "crashes"
            if not crashes_dir.is_dir():
                continue
            for crash_file in crashes_dir.iterdir():
                if crash_file.suffix == ".failed":
                    failed_reports += 1
        if failed_reports:
            warnings.append(
                f"WARNING: Unreported crashes detected ({failed_reports})\n"
            )

        self.write_file(outfile, warnings)


def aflfuzz_main(
    opts: Namespace, collector: Optional[Collector], s3m: Optional[S3Manager]
) -> int:
    assert not opts.cmd or opts.firefox

    if opts.firefox or opts.firefox_start_afl:
        assert HAVE_FFPUPPET
        assert not opts.custom_cmdline_file
        assert opts.firefox_prefs and opts.firefox_testpath

    if opts.firefox_start_afl:
        assert opts.aflbindir

        (ffp, cmd, env) = setup_firefox(
            opts.firefox_start_afl,
            opts.firefox_prefs,
            opts.firefox_extensions,
            opts.firefox_testpath,
        )

        afl_cmd = [str(opts.aflbindir / "afl-fuzz")]

        opts.rargs.remove("--")

        afl_cmd.extend(opts.rargs)
        afl_cmd.extend(cmd)

        try:
            subprocess.run(afl_cmd, env=env)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()

        ffp.clean_up()
        return 0

    afl_out_dirs = []
    if opts.afloutdir:
        if not (opts.afloutdir / "crashes").exists():
            # The specified directory doesn't have a "crashes" sub directory.
            # Either the wrong directory was specified, or this is an AFL
            # multi-process synchronization directory. Try to figure this out here.
            for sync_dir in opts.afloutdir.iterdir():
                if (sync_dir / "crashes").exists():
                    afl_out_dirs.append(sync_dir)

            if not afl_out_dirs:
                print(
                    f"error: Directory {opts.afloutdir} does not appear to be a "
                    "valid AFL output/sync directory",
                    file=sys.stderr,
                )
                return 2
        else:
            afl_out_dirs.append(opts.afloutdir)

    # Upload and FuzzManager modes require specifying the AFL directory
    assert not (opts.s3_queue_upload or opts.fuzzmanager) or opts.afloutdir

    if opts.fuzzmanager or opts.s3_queue_upload or opts.stats:
        last_queue_upload = 0

        # If we reach this point, we know that AFL will be running on this machine,
        # so do the local warning check
        warn_local(opts)

        stats = AFLStats()

        while True:
            if opts.fuzzmanager:
                for afl_out_dir in afl_out_dirs:
                    scan_crashes(
                        afl_out_dir,
                        collector,
                        opts.custom_cmdline_file,
                        opts.env_file,
                        opts.test_file,
                    )

            # Only upload queue files every 20 minutes
            if opts.s3_queue_upload and last_queue_upload < int(time.time()) - 1200:
                assert s3m is not None
                for afl_out_dir in afl_out_dirs:
                    s3m.upload_afl_queue_dir(afl_out_dir, new_cov_only=True)
                last_queue_upload = int(time.time())

            if opts.stats:
                stats.update_and_write(
                    opts.stats,
                    afl_out_dirs,
                    cmdline_path=opts.custom_cmdline_file,
                )

            time.sleep(10)

    return 0
