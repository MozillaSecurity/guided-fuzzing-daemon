# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import re
import sys
from argparse import REMAINDER, ArgumentParser, Namespace
from pathlib import Path
from typing import List, Optional

from .utils import HAVE_FFPUPPET


def _check_log_pattern(
    instances: int, pattern: str, arg_name: str, parser: ArgumentParser
) -> None:
    if instances > 1 and pattern.count("%") != 1:
        parser.error(f"{arg_name} expects exactly one %d pattern")
    if (
        "%" in pattern
        and re.search(r"%[#0 +-]*\d*\.\d*[hlL]?[diouxX]", pattern) is None
    ):
        parser.error(f"{arg_name} %d pattern not recognized")
        try:
            if len({(pattern % (i,)) for i in range(1000)}) != 1000:
                parser.error(f"{arg_name} does not produce distinct paths")
        except TypeError as exc:
            parser.error(f"{arg_name} is malformed: {exc}")


def parse_args(argv: Optional[List[str]] = None) -> Namespace:
    if argv is None:
        argv = sys.argv.copy()  # pragma: no cover

    program_name = Path(argv.pop(0)).name

    # setup argparser
    parser = ArgumentParser(
        usage=(
            f"{program_name} --libfuzzer or --nyx or --aflfuzz [OPTIONS] "
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
    fm_group = parser.add_argument_group(
        title="FuzzManager Options",
        description="Use these to specify or override FuzzManager parameters."
        " Most of these parameters are typically specified in the global FuzzManager"
        " configuration file.",
    )
    s3_group = parser.add_argument_group(
        title="AWS S3 Options",
        description="Use these arguments for various S3 actions"
        " and parameters related to operating libFuzzer/AFL within AWS and managing"
        " build, corpus and progress in S3.",
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
        "--libfuzzer",
        action="store_const",
        const="libfuzzer",
        dest="mode",
        help="Enable libFuzzer mode",
    )
    mode_group.add_argument(
        "--aflfuzz",
        action="store_const",
        const="aflfuzz",
        dest="mode",
        help="Enable AFL mode",
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
        help=(
            "Shows useful debug information (e.g. disables command output suppression)"
        ),
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

    s3_group.add_argument(
        "--s3-queue-upload",
        action="store_true",
        help="Use S3 to synchronize queues",
    )
    s3_group.add_argument(
        "--s3-queue-cleanup",
        action="store_true",
        help="Cleanup S3 closed queues.",
    )
    s3_group.add_argument(
        "--s3-queue-status",
        action="store_true",
        help="Display S3 queue status",
    )
    s3_group.add_argument(
        "--s3-build-download",
        type=Path,
        help="Use S3 to download the build for the specified project",
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-build-upload",
        type=Path,
        help="Use S3 to upload a new build for the specified project",
        metavar="FILE",
    )
    s3_group.add_argument(
        "--s3-corpus-download",
        type=Path,
        help="Use S3 to download the test corpus for the specified project",
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-corpus-download-size",
        type=int,
        help="When downloading the corpus, select only SIZE files randomly",
        metavar="SIZE",
    )
    s3_group.add_argument(
        "--s3-corpus-upload",
        type=Path,
        help="Use S3 to upload a test corpus for the specified project",
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-corpus-replace",
        action="store_true",
        help=(
            "In conjunction with --s3-corpus-upload, deletes all other remote test "
            "files"
        ),
    )
    s3_group.add_argument(
        "--s3-corpus-refresh",
        type=Path,
        help=(
            "Download queues and corpus from S3, combine and minimize, then re-upload."
        ),
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-corpus-status",
        action="store_true",
        help="Display S3 corpus status",
    )
    s3_group.add_argument(
        "--s3-bucket",
        help="Name of the S3 bucket to use",
        metavar="NAME",
    )
    s3_group.add_argument(
        "--project",
        help="Name of the subfolder/project inside the S3 bucket",
        metavar="NAME",
    )
    s3_group.add_argument(
        "--build",
        type=Path,
        help=(
            "Local build directory to use during corpus refresh instead of downloading."
        ),
        metavar="DIR",
    )
    s3_group.add_argument(
        "--build-project",
        help="If specified, this overrides --project for fetching the build from S3.",
        metavar="NAME",
    )
    s3_group.add_argument(
        "--build-zip-name",
        default="build.zip",
        help="Override default build.zip name when working with S3 builds.",
        metavar="NAME",
    )

    libf_group.add_argument(
        "--env",
        nargs="+",
        type=str,
        help="List of environment variables in the form 'KEY=VALUE'",
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
        "--libfuzzer-instances",
        type=int,
        default=1,
        help="Number of parallel libfuzzer instances to run",
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
        "--nyx-instances",
        type=int,
        default=1,
        help="Number of parallel Nyx instances to run",
        metavar="COUNT",
    )
    nyx_group.add_argument(
        "--afl-log-pattern",
        help="Redirect AFL logs to a separate path. Must contain %d pattern if "
        "--nyx-instances > 1.",
    )
    nyx_group.add_argument(
        "--nyx-log-pattern",
        help="Write Nyx hprint logs to a separate path. Must contain %d pattern if "
        "--nyx-instances > 1.",
    )
    nyx_group.add_argument(
        "--nyx-async-corpus",
        action="store_true",
        help="Init AFL with a single random file from the corpus, and load the rest "
        "after init in the main process only.",
    )

    fm_group.add_argument(
        "--custom-cmdline-file",
        type=Path,
        help="Path to custom cmdline file",
        metavar="FILE",
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
        "--test-file",
        type=Path,
        help="Optional path to copy the test file to before reproducing",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--afl-timeout",
        type=int,
        default=1000,
        help="Timeout per test to pass to AFL for corpus refreshing",
        metavar="MSECS",
    )
    afl_group.add_argument(
        "--firefox",
        action="store_true",
        help="Test Program is Firefox (requires FFPuppet installed)",
    )
    afl_group.add_argument(
        "--firefox-prefs",
        type=Path,
        help="Path to prefs.js file for Firefox",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--firefox-extensions",
        nargs="+",
        type=str,
        help="Path extension file for Firefox",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--firefox-testpath",
        type=Path,
        help="Path to file to open with Firefox",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--firefox-start-afl",
        type=Path,
        metavar="FILE",
        help=(
            "Start AFL with the given Firefox binary, remaining arguments being "
            "passed to AFL"
        ),
    )
    afl_group.add_argument(
        "--env-file",
        type=Path,
        help="Path to a file with additional environment variables",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--afl-output-dir",
        type=Path,
        dest="afloutdir",
        help="Path to the AFL output directory to manage",
        metavar="DIR",
    )
    afl_group.add_argument(
        "--afl-binary-dir",
        type=Path,
        dest="aflbindir",
        help="Path to the AFL binary directory to use",
        metavar="DIR",
    )
    afl_group.add_argument("rargs", nargs=REMAINDER)

    if not argv:
        parser.print_help(sys.stderr)
        parser.exit(2)

    # For backwards compatibility, --aflfuzz is the default if nothing else is
    # specified.
    parser.set_defaults(
        mode="aflfuzz",
    )

    opts = parser.parse_args(argv)

    if opts.transform and not opts.transform.is_file():
        parser.error(f"Failed to locate transformation script {opts.transform}")

    s3_main = (
        opts.s3_build_download
        or opts.s3_build_upload
        or opts.s3_corpus_download
        or opts.s3_corpus_refresh
        or opts.s3_corpus_status
        or opts.s3_corpus_upload
        or opts.s3_queue_cleanup
        or opts.s3_queue_status
    )
    if opts.s3_queue_upload or s3_main:
        if not opts.s3_bucket or not opts.project:
            parser.error("Must specify both --s3-bucket and --project for S3 actions")

    if opts.mode == "nyx":
        if not opts.sharedir or not opts.sharedir.is_dir():
            parser.error("Must specify --sharedir with --nyx")
        if not opts.aflbindir:
            parser.error("Must specify --afl-binary-dir for Nyx mode")
        if len(opts.rargs) != 2:
            parser.error("Nyx mode expects positional args: CORPUS_IN CORPUS_OUT")
        if opts.nyx_log_pattern is not None:
            _check_log_pattern(
                opts.nyx_instances, opts.nyx_log_pattern, "--nyx-log-pattern", parser
            )
        if opts.afl_log_pattern is not None:
            _check_log_pattern(
                opts.nyx_instances, opts.afl_log_pattern, "--afl-log-pattern", parser
            )

    if opts.mode == "libfuzzer" and not s3_main:
        if not opts.rargs:
            parser.error("No arguments specified")

    if opts.libfuzzer_auto_reduce is not None:
        if opts.libfuzzer_auto_reduce < 5:
            parser.error("Auto reduce threshold should at least be 5%.")

    if opts.mode == "aflfuzz":
        if opts.cmd and not opts.firefox:
            parser.error("Use --cmd either with libfuzzer or with afl in firefox mode")

        if opts.firefox or opts.firefox_start_afl:
            if not HAVE_FFPUPPET:
                parser.error(
                    "--firefox and --firefox-start-afl require FFPuppet to be "
                    "installed"
                )

            if opts.custom_cmdline_file:
                parser.error(
                    "--custom-cmdline-file is incompatible with firefox options"
                )

            if not opts.firefox_prefs or not opts.firefox_testpath:
                parser.error(
                    "--firefox and --firefox-start-afl require --firefox-prefs "
                    "and --firefox-testpath to be specified"
                )

        if opts.firefox_start_afl:
            if not opts.aflbindir:
                parser.error(
                    "Must specify --afl-binary-dir for starting AFL with firefox"
                )

        # Upload and FuzzManager modes require specifying the AFL directory
        if opts.s3_queue_upload or opts.fuzzmanager:
            if not opts.afloutdir:
                parser.error("Must specify AFL output directory using --afl-output-dir")

        if opts.s3_corpus_refresh and not opts.aflbindir:
            parser.error("Must specify --afl-binary-dir for refreshing the test corpus")

    return opts
