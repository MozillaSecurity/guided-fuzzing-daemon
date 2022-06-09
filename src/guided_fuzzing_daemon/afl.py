import os.path
import shutil
import sys

from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Running.AutoRunner import AutoRunner

from .utils import apply_transform, setup_firefox, write_stats_file


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
    crash_dir = os.path.join(base_dir, "crashes")
    crash_files = []

    for crash_file in os.listdir(crash_dir):
        # Ignore all files that aren't crash results
        if not crash_file.startswith("id:"):
            continue

        crash_file = os.path.join(crash_dir, crash_file)

        # Ignore our own status files
        if crash_file.endswith(".submitted") or crash_file.endswith(".failed"):
            continue

        # Ignore files we already processed
        if os.path.exists(crash_file + ".submitted") or os.path.exists(
            crash_file + ".failed"
        ):
            continue

        crash_files.append(crash_file)

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
            cmdline_path = os.path.join(base_dir, "cmdline")

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
                    submission = apply_transform(transform, crash_file)
                except Exception as exc:  # pylint: disable=broad-except
                    print(exc.args[1], file=sys.stderr)

            if test_idx is not None:
                cmdline[test_idx] = orig_test_arg.replace("@@", crash_file)
            elif test_in_env is not None:
                env[test_in_env] = env[test_in_env].replace("@@", crash_file)
            elif test_path is not None:
                shutil.copy(crash_file, test_path)
            else:
                with open(crash_file) as crash_fd:
                    stdin = crash_fd.read()

            print(f"Processing crash file {crash_file}", file=sys.stderr)

            runner = AutoRunner.fromBinaryArgs(
                cmdline[0], cmdline[1:], env=env, stdin=stdin
            )
            if runner.run():
                crash_info = runner.getCrashInfo(configuration)
                collector.submit(crash_info, submission)
                # pylint: disable=consider-using-with
                open(submission + ".submitted", "ab").close()
                print("Success: Submitted crash to server.", file=sys.stderr)
            else:
                # pylint: disable=consider-using-with
                open(submission + ".failed", "ab").close()
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
        stats_path = os.path.join(base_dir, "fuzzer_stats")

        if not cmdline_path:
            cmdline_path = os.path.join(base_dir, "cmdline")

        if os.path.exists(stats_path):
            with open(stats_path) as stats_file:
                stats = stats_file.read()

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
        if not os.path.isfile(f"{target_binary}.fuzzmanagerconf"):
            warnings.append(f"WARNING: Missing {target_binary}.fuzzmanagerconf\n")
        elif ProgramConfiguration.fromBinary(target_binary) is None:
            warnings.append(f"WARNING: Invalid {target_binary}.fuzzmanagerconf\n")

    # Look for unreported crashes
    failed_reports = 0
    for base_dir in base_dirs:
        crashes_dir = os.path.join(base_dir, "crashes")
        if not os.path.isdir(crashes_dir):
            continue
        for crash_file in os.listdir(crashes_dir):
            if crash_file.endswith(".failed"):
                failed_reports += 1
    if failed_reports:
        warnings.append(f"WARNING: Unreported crashes detected ({failed_reports})\n")

    # Write out data
    write_stats_file(outfile, fields, aggregated_stats, warnings)
