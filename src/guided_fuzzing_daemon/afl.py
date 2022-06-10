import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner

from .utils import (
    HAVE_FFPUPPET,
    apply_transform,
    setup_firefox,
    warn_local,
    write_stats_file,
)


def command_file_to_list(cmd_file):
    """
    Open and parse custom command line file

    @type cmd_file: String
    @param cmd_file: Command line file containing list of commands

    @rtype: Tuple
    @return: Test index in list and the command as a list of strings
    """
    cmdline = []
    idx = 0
    test_idx = None
    with open(cmd_file) as cmd_fp:
        for line in cmd_fp:
            if "@@" in line:
                test_idx = idx
            cmdline.append(line.rstrip())
            idx += 1

    return test_idx, cmdline


def scan_crashes(
    base_dir,
    collector,
    cmdline_path=None,
    env_path=None,
    test_path=None,
    firefox=None,
    firefox_prefs=None,
    firefox_extensions=None,
    firefox_testpath=None,
    transform=None,
):
    """
    Scan the base directory for crash tests and submit them to FuzzManager.

    @type base_dir: String
    @param base_dir: AFL base directory

    @type cmdline_path: String
    @param cmdline_path: Optional command line file to use instead of the
                         one found inside the base directory.

    @type env_path: String
    @param env_path: Optional file containing environment variables.

    @type test_path: String
    @param test_path: Optional filename where to copy the test before
                      attempting to reproduce a crash.

    @type transform: String
    @param transform: Optional path to script for applying post-crash
                      transformations.

    @rtype: int
    @return: Non-zero return code on failure
    """
    crash_dir = Path(base_dir) / "crashes"
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
            with open(env_path) as env_file:
                for line in env_file:
                    (name, val) = line.rstrip("\n").split("=", 1)
                    base_env[name] = val

                    if "@@" in val:
                        test_in_env = name

        if not cmdline_path:
            cmdline_path = Path(base_dir) / "cmdline"

        test_idx, cmdline = command_file_to_list(cmdline_path)
        if test_idx is not None:
            orig_test_arg = cmdline[test_idx]

        configuration = ProgramConfiguration.fromBinary(cmdline[0])
        if not configuration:
            raise Exception(
                "Creating program configuration from binary failed. "
                "Check your binary configuration file."
            )

        if firefox:
            (ffp, ff_cmd, ff_env) = setup_firefox(
                cmdline[0], firefox_prefs, firefox_extensions, firefox_testpath
            )
            cmdline = ff_cmd
            base_env.update(ff_env)

        for crash_file in crash_files:
            stdin = None
            env = None

            if base_env:
                env = dict(base_env)

            submission = crash_file
            if transform:
                try:
                    submission = Path(apply_transform(transform, crash_file))
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
                    "Error: Failed to reproduce the given crash, cannot submit.",
                    file=sys.stderr,
                )

        if firefox:
            ffp.clean_up()


def write_aggregated_stats_afl(base_dirs, outfile, cmdline_path=None):
    """
    Generate aggregated statistics from the given base directories
    and write them to the specified output file.

    @type base_dirs: list
    @param base_dirs: List of AFL base directories

    @type outfile: str
    @param outfile: Output file for aggregated statistics

    @type cmdline_path: String
    @param cmdline_path: Optional command line file to use instead of the
                         one found inside the base directory.
    """

    # Which fields to add
    wanted_fields_total = [
        "execs_done",
        "execs_per_sec",
        "pending_favs",
        "pending_total",
        "variable_paths",
        "unique_crashes",
        "unique_hangs",
    ]

    # Which fields to aggregate by mean
    wanted_fields_mean = ["exec_timeout"]

    # Which fields should be displayed per fuzzer instance
    wanted_fields_all = ["cycles_done", "bitmap_cvg"]

    # Which fields should be aggregated by max
    wanted_fields_max = ["last_path"]

    # Generate total list of fields to write
    fields = []
    fields.extend(wanted_fields_total)
    fields.extend(wanted_fields_mean)
    fields.extend(wanted_fields_all)
    fields.extend(wanted_fields_max)

    # Warnings to include
    warnings = []

    aggregated_stats = {}

    for field in wanted_fields_total:
        aggregated_stats[field] = 0

    for field in wanted_fields_mean:
        aggregated_stats[field] = (0, 0)

    for field in wanted_fields_all:
        aggregated_stats[field] = []

    def convert_num(num):
        if "." in num:
            return float(num)
        return int(num)

    for base_dir in base_dirs:
        stats_path = Path(base_dir) / "fuzzer_stats"

        if not cmdline_path:
            cmdline_path = Path(base_dir) / "cmdline"

        if stats_path.exists():
            stats = stats_path.read_text()

            for line in stats.splitlines():
                (field_name, field_val) = line.split(":", 1)
                field_name = field_name.strip()
                field_val = field_val.strip()

                if field_name in wanted_fields_total:
                    aggregated_stats[field_name] += convert_num(field_val)
                elif field_name in wanted_fields_mean:
                    (val, cnt) = aggregated_stats[field_name]
                    aggregated_stats[field_name] = (
                        val + convert_num(field_val),
                        cnt + 1,
                    )
                elif field_name in wanted_fields_all:
                    aggregated_stats[field_name].append(field_val)
                elif field_name in wanted_fields_max:
                    num_val = convert_num(field_val)
                    if (field_name not in aggregated_stats) or aggregated_stats[
                        field_name
                    ] < num_val:
                        aggregated_stats[field_name] = num_val

    # If we don't have any data here, then the fuzzers haven't written any statistics
    # yet
    if not aggregated_stats:
        return

    # Mean conversion
    for field_name in wanted_fields_mean:
        (val, cnt) = aggregated_stats[field_name]
        if cnt:
            aggregated_stats[field_name] = float(val) / float(cnt)
        else:
            aggregated_stats[field_name] = val

    # Verify fuzzmanagerconf exists and can be parsed
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
        crashes_dir = Path(base_dir) / "crashes"
        if not crashes_dir.is_dir():
            continue
        for crash_file in crashes_dir.iterdir():
            if crash_file.suffix == ".failed":
                failed_reports += 1
    if failed_reports:
        warnings.append(f"WARNING: Unreported crashes detected ({failed_reports})\n")

    # Write out data
    write_stats_file(outfile, fields, aggregated_stats, warnings)


def aflfuzz_main(opts, collector, s3m):
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

        afl_cmd = [str(Path(opts.aflbindir) / "afl-fuzz")]

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
        if not (Path(opts.afloutdir) / "crashes").exists():
            # The specified directory doesn't have a "crashes" sub directory.
            # Either the wrong directory was specified, or this is an AFL
            # multi-process synchronization directory. Try to figure this out here.
            for sync_dir in Path(opts.afloutdir).iterdir():
                if (sync_dir / "crashes").exists():
                    afl_out_dirs.append(str(sync_dir))

            if not afl_out_dirs:
                print(
                    f"Error: Directory {opts.afloutdir} does not appear to be a "
                    "valid AFL output/sync directory",
                    file=sys.stderr,
                )
                return 2
        else:
            afl_out_dirs.append(opts.afloutdir)

    # Upload and FuzzManager modes require specifying the AFL directory
    assert not (opts.s3_queue_upload or opts.fuzzmanager) or opts.afloutdir

    if opts.fuzzmanager or opts.s3_queue_upload or opts.aflstats:
        last_queue_upload = 0

        # If we reach this point, we know that AFL will be running on this machine,
        # so do the local warning check
        warn_local(opts)

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
                for afl_out_dir in afl_out_dirs:
                    s3m.upload_afl_queue_dir(afl_out_dir, new_cov_only=True)
                last_queue_upload = int(time.time())

            if opts.stats or opts.aflstats:
                write_aggregated_stats_afl(
                    afl_out_dirs,
                    opts.aflstats,
                    cmdline_path=opts.custom_cmdline_file,
                )

            time.sleep(10)

    return 0
