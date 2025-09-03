# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import re
import sys
from argparse import REMAINDER, SUPPRESS, ArgumentParser, Namespace
from logging import getLogger
from pathlib import Path
from shutil import which

LOG = getLogger("gfd.args")


def _check_log_pattern(
    instances: int, pattern: str, arg_name: str, parser: ArgumentParser
) -> None:
    if instances > 1 and pattern.count("%") != 1:
        parser.error(f"{arg_name} expects exactly one %d placeholder")
    if (
        "%" in pattern
        and re.search(r"%[#0 +-]*\d*\.?\d*[hlL]?[diouxX]", pattern) is None
    ):
        parser.error(f"{arg_name} %d placeholder not recognized")
    # I don't think non-distinct or malformed cases below can be hit, but be
    # extra cautious.
    try:
        if len({(pattern % (i,)) for i in range(1000)}) != 1000:
            parser.error(
                f"{arg_name} does not produce distinct paths"
            )  # pragma: no cover
    except TypeError as exc:  # pragma: no cover
        parser.error(f"{arg_name} is malformed: {exc}")


def parse_args(argv: list[str] | None = None) -> Namespace:
    if argv is None:
        argv = sys.argv.copy()  # pragma: no cover

    program_name = Path(argv.pop(0)).name

    # setup argparser
    parser = ArgumentParser(
        usage=(
            f"{program_name} --afl or --fuzzilli or --libfuzzer or --nyx [OPTIONS] "
            "--cmd <COMMAND AND ARGUMENTS>"
        )
    )

    main_group = parser.add_argument_group(title="Main Options", description=None)
    afl_group = parser.add_argument_group(
        title="AFL Options", description="Use these arguments in AFL mode."
    )
    libf_group = parser.add_argument_group(
        title="Libfuzzer Options", description="Use these arguments in Libfuzzer mode."
    )
    nyx_group = parser.add_argument_group(
        title="Nyx Options", description="Use these arguments in Nyx mode."
    )
    fzli_group = parser.add_argument_group(
        title="Fuzzilli Options", description="Use these arguments in Fuzzilli mode."
    )
    fm_group = parser.add_argument_group(
        title="FuzzManager Options",
        description="Use these to specify or override FuzzManager parameters."
        " Most of these parameters are typically specified in the global FuzzManager"
        " configuration file.",
    )
    storage_group = parser.add_argument_group(
        title="Cloud Storage Options",
        description="Use these arguments for various cloud storage actions and"
        " parameters related to operating fuzzers in the cloud and managing build,"
        " corpus and progress in cloud storage.",
    )

    fm_or_local_group = main_group.add_mutually_exclusive_group()
    fm_or_local_group.add_argument(
        "--fuzzmanager",
        action="store_true",
        help="Use FuzzManager to submit crash results",
    )
    fm_or_local_group.add_argument(
        "--local",
        action="store_true",
        help="Don't submit crash results anywhere (default)",
    )

    mode_group = main_group.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--afl",
        action="store_const",
        const="afl",
        dest="mode",
        help="Enable AFL mode",
    )
    mode_group.add_argument(
        "--fuzzilli",
        action="store_const",
        const="fuzzilli",
        dest="mode",
        help="Enable Fuzzilli mode",
    )
    mode_group.add_argument(
        "--libfuzzer",
        action="store_const",
        const="libfuzzer",
        dest="mode",
        help="Enable libFuzzer mode",
    )
    mode_group.add_argument(
        "--nyx",
        action="store_const",
        const="nyx",
        dest="mode",
        help="Enable Nyx mode",
    )
    main_group.add_argument(
        "--debug",
        action="store_true",
        help="Show debug information (e.g. disable command output suppression)",
    )
    main_group.add_argument(
        "--stats",
        type=Path,
        help="Collect aggregated statistics in specified file",
        metavar="FILE",
    )
    main_group.add_argument(
        "--transform",
        type=Path,
        help="Apply post crash transformation to the testcase",
        metavar="FILE",
    )
    main_group.add_argument(
        "--instances",
        type=int,
        default=1,
        help="Number of parallel instances to run",
        metavar="COUNT",
    )
    main_group.add_argument(
        "--timeout",
        type=int,
        help="Timeout per test (applies to AFL, Fuzzilli, Nyx)",
        metavar="MSECS",
    )
    main_group.add_argument(
        "--corpus-out",
        "-o",
        type=Path,
        help="Output directory for findings. (applies to AFL, Fuzzilli, Nyx)",
        metavar="DIR",
    )
    main_group.add_argument("rargs", nargs=REMAINDER)

    storage_group.add_argument(
        "--list-projects",
        action="store_true",
        help="List projects in cloud storage (use --project to filter by prefix)",
    )
    storage_group.add_argument(
        "--provider",
        choices=("S3", "GCS"),
        default="S3",
        help="Specify cloud storage provider (S3 or GCS)",
    )
    storage_group.add_argument(
        "--queue-upload",
        action="store_true",
        help="Use cloud storage to synchronize queues",
    )
    storage_group.add_argument(
        "--queue-status",
        action="store_true",
        help="Display cloud storage queue status",
    )
    storage_group.add_argument(
        "--queue-download",
        type=Path,
        help="Use cloud storage to download the queues for the specified project",
        metavar="DIR",
    )
    storage_group.add_argument(
        "--corpus-download",
        type=Path,
        help="Use cloud storage to download the test corpus for the specified project",
        metavar="DIR",
    )
    storage_group.add_argument(
        "--corpus-upload",
        type=Path,
        help="Use cloud storage to upload a test corpus for the specified project",
        metavar="DIR",
    )
    # deprecated (default)
    storage_group.add_argument(
        "--corpus-replace",
        action="store_true",
        help=SUPPRESS,
    )
    storage_group.add_argument(
        "--corpus-refresh",
        type=Path,
        help="Download queues and corpus from cloud storage, combine and minimize, then"
        " re-upload.",
        metavar="DIR",
    )
    storage_group.add_argument(
        "--corpus-refresh-resume",
        help="Check for previous traces when performing a corpus refresh",
        action="store_true",
    )
    storage_group.add_argument(
        "--corpus-status",
        action="store_true",
        help="Display cloud storage corpus status",
    )
    storage_group.add_argument(
        "--bucket",
        help="Name of the cloud storage bucket to use",
        metavar="NAME",
    )
    storage_group.add_argument(
        "--project",
        help="Name of the subfolder/project inside the cloud storage bucket",
        metavar="NAME",
    )

    fzli_group.add_argument(
        "--build-dir",
        dest="fuzzilli_build_dir",
        type=Path,
        help="Path to the Fuzzilli build directory",
        metavar="DIR",
    )
    fzli_group.add_argument(
        "--differential",
        action="store_true",
        help="Enable differential mode",
    )
    fzli_group.add_argument(
        "--wasm",
        action="store_true",
        help="Enable wasm mode",
    )

    libf_group.add_argument(
        "--env",
        action="append",
        type=str,
        metavar="KEY=VALUE",
        help="Set an environment variable in the form 'KEY=VALUE'",
    )
    libf_group.add_argument(
        "--env-percent",
        action="append",
        nargs=2,
        metavar="% KEY=VALUE",
        help="Set an environment variable sometimes (%%/100) in the form 'KEY=VALUE'",
    )
    libf_group.add_argument(
        "--cmd", action="store_true", help="Command with parameters to run"
    )
    libf_group.add_argument(
        "--libfuzzer-restarts",
        type=int,
        help="Maximum number of restarts to do with libFuzzer",
        metavar="COUNT",
    )
    libf_group.add_argument(
        "--libfuzzer-auto-reduce",
        type=int,
        help="Auto-reduce the corpus once it has grown by this percentage",
        metavar="PERCENT",
    )
    libf_group.add_argument(
        "--libfuzzer-auto-reduce-min",
        type=int,
        default=1000,
        help="Minimum corpus size for auto-reduce to apply.",
        metavar="COUNT",
    )

    nyx_group.add_argument(
        "--sharedir",
        help="Path to Nyx 'sharedir'",
        type=Path,
        metavar="DIR",
    )
    nyx_group.add_argument(
        "--nyx-log-pattern",
        help="Write Nyx hprint logs to a separate path (and hide on console). Must "
        "contain %%d placeholder if --nyx-instances > 1.",
    )

    fm_group.add_argument(
        "--serverhost",
        help="Server hostname for remote signature management.",
        metavar="HOST",
    )
    fm_group.add_argument(
        "--serverport",
        type=int,
        help="Server port to use",
        metavar="PORT",
    )
    fm_group.add_argument(
        "--serverproto",
        help="Server protocol to use (default is https)",
        metavar="PROTO",
    )
    fm_group.add_argument(
        "--serverauthtokenfile",
        type=Path,
        help="File containing the server authentication token",
        metavar="FILE",
    )
    fm_group.add_argument(
        "--clientid",
        help="Client ID to use when submitting issues",
        metavar="ID",
    )
    fm_group.add_argument(
        "--platform",
        help="Platform this crash appeared on",
        metavar="(x86|x86-64|arm)",
    )
    fm_group.add_argument(
        "--product",
        help="Product this crash appeared on",
        metavar="PRODUCT",
    )
    fm_group.add_argument(
        "--productversion",
        dest="product_version",
        help="Product version this crash appeared on",
        metavar="VERSION",
    )
    fm_group.add_argument(
        "--os",
        help="OS this crash appeared on",
        metavar="(windows|linux|macosx|b2g|android)",
    )
    fm_group.add_argument(
        "--tool",
        help="Name of the tool that found this issue",
        metavar="NAME",
    )
    fm_group.add_argument(
        "--metadata",
        nargs="+",
        type=str,
        help="List of metadata variables in the form 'KEY=VALUE'",
    )
    fm_group.add_argument("--sigdir", help="Signature cache directory", metavar="DIR")

    afl_group.add_argument(
        "--afl-log-pattern",
        help="Redirect AFL logs to a separate path. Must contain %%d placeholder if "
        "--instances > 1. (applies to Nyx)",
    )
    afl_group.add_argument(
        "--afl-hide-logs",
        action="store_true",
        help="Don't print AFL logs on stdout. Requires --afl-log-pattern or "
        "--nyx-log-pattern. (applies to Nyx)",
    )
    afl_group.add_argument(
        "--test-file",
        type=Path,
        help="Optional path to copy the test file to before reproducing",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--memory-limit",
        "-m",
        help="Set memory limit for child process",
        metavar="MEGS",
    )
    afl_group.add_argument(
        "--env-file",
        type=Path,
        help="Path to a file with additional environment variables",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--afl-binary-dir",
        type=Path,
        dest="aflbindir",
        help="Path to the AFL binary directory to use. (applies to Nyx)",
        metavar="DIR",
    )
    afl_group.add_argument(
        "--afl-async-corpus",
        action="store_true",
        help="Init AFL with a single random file from the corpus, and load the rest "
        "after init in the main process only. (applies to Nyx)",
    )
    afl_group.add_argument(
        "--afl-add-corpus",
        action="append",
        type=Path,
        help="Add additional corpus path. (applies to Nyx)",
    )
    afl_group.add_argument(
        "--max-runtime",
        type=float,
        default=0.0,
        help="Specify maximum runtime in seconds for the whole session. "
        "(applies to Nyx)",
    )
    afl_group.add_argument(
        "--max-fuzz-time",
        type=int,
        help="Specify maximum runtime of the fuzzer (applies to Nyx)",
    )
    afl_group.add_argument(
        "--max-fuzz-runs",
        type=int,
        help="Specify maximum executions of the fuzzer (approximate, applies to Nyx)",
    )
    afl_group.add_argument(
        "--corpus-in",
        "-i",
        type=Path,
        help="AFL input directory with test cases. (applies to Nyx)",
        metavar="DIR",
    )
    afl_group.add_argument("--afl-timeout", type=int, help=SUPPRESS)

    if not argv:
        parser.print_help(sys.stderr)
        parser.exit(2)

    opts = parser.parse_args(argv)

    # try to find afl-fuzz if --afl-binary-dir not given
    if not opts.aflbindir:
        afl_auto_dir = which("afl-fuzz")
        if afl_auto_dir is not None:
            opts.aflbindir = Path(afl_auto_dir).parent

    if opts.transform and not opts.transform.is_file():
        parser.error(f"Failed to locate transformation script {opts.transform}")

    storage_main = (
        opts.corpus_download
        or opts.corpus_status
        or opts.corpus_upload
        or opts.list_projects
        or opts.queue_download
        or opts.queue_status
    )
    if (
        opts.queue_upload
        or opts.corpus_refresh
        or (storage_main and not opts.list_projects)
    ):
        if not opts.bucket or not opts.project:
            parser.error(
                "Must specify both --bucket and --project for cloud storage actions"
            )
    elif opts.list_projects and not opts.bucket:
        parser.error("Must specify --bucket for cloud storage list projects action")

    if opts.env:
        result = {}
        for var in opts.env:
            try:
                key, value = var.split("=", 1)
            except ValueError:
                parser.error(f"Definition of --env {var} missing value")
            if key in result:
                parser.error(f"Multiple values given for --env {key}")
            result[key] = value
        opts.env = result

    if opts.env_percent:
        result = {}
        for pct, var in opts.env_percent:
            try:
                key, value = var.split("=", 1)
            except ValueError:
                parser.error(f"Definition of --env-percent {var} missing value")
            result.setdefault(key, {})  # value => probability
            if value in result[key]:
                parser.error(f"Multiple probabilities given for --env-percent {var}")
            pct = float(pct)
            if not 0 <= pct <= 100:  # don't invert range to exclude inf & nan
                parser.error(f"Invalid value for --env-percent {key}")
            if sum(result[key].values()) + pct > 100:
                parser.error(f"Total probabilities for --env-percent {key} > 100")
            result[key][value] = pct
        opts.env_percent = result

    if opts.afl_timeout is not None:
        LOG.warning("--afl-timeout is deprecated, use --timeout instead")
        assert opts.timeout is None
        opts.timeout = opts.afl_timeout

    if opts.corpus_replace:
        LOG.warning("--corpus-replace is deprecated (now default behavior)")

    if opts.corpus_refresh_resume and not opts.corpus_refresh:
        parser.error("Corpus refresh resume mode specified without corpus refresh")

    if opts.mode == "nyx":
        if opts.rargs:
            parser.error("Nyx mode takes no positional args")
        if not opts.sharedir or not opts.sharedir.is_dir():
            parser.error("Must specify --sharedir with --nyx")
        if opts.nyx_log_pattern is not None:
            _check_log_pattern(
                opts.instances, opts.nyx_log_pattern, "--nyx-log-pattern", parser
            )

    if opts.mode == "afl":
        if not opts.rargs or not Path(opts.rargs[0]).is_file():
            parser.error("AFL mode expects at least one arg (target binary)")

    if opts.mode in {"afl", "nyx"}:
        if not opts.aflbindir:
            parser.error("Must specify --afl-binary-dir for AFL/Nyx mode")
        if not opts.corpus_refresh:
            if not opts.corpus_in or not opts.corpus_in.is_dir():
                parser.error("Must specify --corpus-in with --afl/--nyx")
            if not opts.corpus_out:
                # don't check existence, main() will auto-create
                parser.error("Must specify --corpus-out with --afl/--nyx")
        if opts.afl_log_pattern is not None:
            _check_log_pattern(
                opts.instances, opts.afl_log_pattern, "--afl-log-pattern", parser
            )
        if (
            opts.afl_hide_logs
            and opts.afl_log_pattern is None
            and (opts.mode == "afl" or opts.nyx_log_pattern is None)
        ):
            parser.error(
                "--afl-hide-logs requires --afl-log-pattern or --nyx-log-pattern"
            )

    if opts.max_runtime < 0.0:
        parser.error("--max-runtime must be positive (or 0 to disable).")
    elif opts.max_runtime == 0.0:
        opts.max_runtime = float("inf")

    if opts.mode == "fuzzilli":
        if not opts.rargs or not Path(opts.rargs[0]).is_file():
            parser.error("Fuzzilli mode expects at least one arg (target binary)")
        if not opts.fuzzilli_build_dir:
            parser.error("Must specify --build-dir for Fuzzilli mode")
        if not opts.corpus_refresh:
            if not opts.corpus_out:
                # don't check existence, main() will auto-create
                parser.error("Must specify --corpus-out with --fuzzilli")

    if opts.mode == "libfuzzer" and not opts.rargs:
        parser.error("No arguments specified")

    if opts.libfuzzer_auto_reduce is not None:
        if opts.libfuzzer_auto_reduce < 5:
            parser.error("Auto reduce threshold should at least be 5%.")

    return opts
