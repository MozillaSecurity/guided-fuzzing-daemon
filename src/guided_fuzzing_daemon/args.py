import argparse
import os.path
import sys
import time


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv.copy()

    program_name = os.path.basename(argv.pop(0))

    # setup argparser
    parser = argparse.ArgumentParser(
        usage=(
            f"{program_name} --libfuzzer or --aflfuzz [OPTIONS] "
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
        dest="fuzzmanager",
        action="store_true",
        help="Use FuzzManager to submit crash results",
    )
    fm_or_local_group.add_argument(
        "--local",
        dest="local",
        action="store_true",
        help="Don't submit crash results anywhere (default)",
    )

    main_group.add_argument(
        "--libfuzzer",
        dest="libfuzzer",
        action="store_true",
        help="Enable libFuzzer mode",
    )
    main_group.add_argument(
        "--aflfuzz", dest="aflfuzz", action="store_true", help="Enable AFL mode"
    )
    main_group.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help=(
            "Shows useful debug information (e.g. disables command output suppression)"
        ),
    )
    main_group.add_argument(
        "--stats",
        dest="stats",
        help="Collect aggregated statistics in specified file",
        metavar="FILE",
    )
    main_group.add_argument(
        "--transform",
        dest="transform",
        help="Apply post crash transformation to the testcase",
        metavar="FILE",
    )

    s3_group.add_argument(
        "--s3-queue-upload",
        dest="s3_queue_upload",
        action="store_true",
        help="Use S3 to synchronize queues",
    )
    s3_group.add_argument(
        "--s3-queue-cleanup",
        dest="s3_queue_cleanup",
        action="store_true",
        help="Cleanup S3 closed queues.",
    )
    s3_group.add_argument(
        "--s3-queue-status",
        dest="s3_queue_status",
        action="store_true",
        help="Display S3 queue status",
    )
    s3_group.add_argument(
        "--s3-build-download",
        dest="s3_build_download",
        help="Use S3 to download the build for the specified project",
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-build-upload",
        dest="s3_build_upload",
        help="Use S3 to upload a new build for the specified project",
        metavar="FILE",
    )
    s3_group.add_argument(
        "--s3-corpus-download",
        dest="s3_corpus_download",
        help="Use S3 to download the test corpus for the specified project",
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-corpus-download-size",
        dest="s3_corpus_download_size",
        help="When downloading the corpus, select only SIZE files randomly",
        metavar="SIZE",
    )
    s3_group.add_argument(
        "--s3-corpus-upload",
        dest="s3_corpus_upload",
        help="Use S3 to upload a test corpus for the specified project",
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-corpus-replace",
        dest="s3_corpus_replace",
        action="store_true",
        help=(
            "In conjunction with --s3-corpus-upload, deletes all other remote test "
            "files"
        ),
    )
    s3_group.add_argument(
        "--s3-corpus-refresh",
        dest="s3_corpus_refresh",
        help=(
            "Download queues and corpus from S3, combine and minimize, then re-upload."
        ),
        metavar="DIR",
    )
    s3_group.add_argument(
        "--s3-corpus-status",
        dest="s3_corpus_status",
        action="store_true",
        help="Display S3 corpus status",
    )
    s3_group.add_argument(
        "--s3-bucket",
        dest="s3_bucket",
        help="Name of the S3 bucket to use",
        metavar="NAME",
    )
    s3_group.add_argument(
        "--project",
        dest="project",
        help="Name of the subfolder/project inside the S3 bucket",
        metavar="NAME",
    )
    s3_group.add_argument(
        "--build",
        dest="build",
        help=(
            "Local build directory to use during corpus refresh instead of downloading."
        ),
        metavar="DIR",
    )
    s3_group.add_argument(
        "--build-project",
        dest="build_project",
        help="If specified, this overrides --project for fetching the build from S3.",
        metavar="NAME",
    )
    s3_group.add_argument(
        "--build-zip-name",
        dest="build_zip_name",
        default="build.zip",
        help="Override default build.zip name when working with S3 builds.",
        metavar="NAME",
    )

    libf_group.add_argument(
        "--env",
        dest="env",
        nargs="+",
        type=str,
        help="List of environment variables in the form 'KEY=VALUE'",
    )
    libf_group.add_argument(
        "--cmd", dest="cmd", action="store_true", help="Command with parameters to run"
    )
    libf_group.add_argument(
        "--libfuzzer-restarts",
        dest="libfuzzer_restarts",
        type=int,
        help="Maximum number of restarts to do with libFuzzer",
        metavar="COUNT",
    )
    libf_group.add_argument(
        "--libfuzzer-instances",
        dest="libfuzzer_instances",
        type=int,
        default=1,
        help="Number of parallel libfuzzer instances to run",
        metavar="COUNT",
    )
    libf_group.add_argument(
        "--libfuzzer-auto-reduce",
        dest="libfuzzer_auto_reduce",
        type=int,
        help="Auto-reduce the corpus once it has grown by this percentage",
        metavar="PERCENT",
    )
    libf_group.add_argument(
        "--libfuzzer-auto-reduce-min",
        dest="libfuzzer_auto_reduce_min",
        type=int,
        default=1000,
        help="Minimum corpus size for auto-reduce to apply.",
        metavar="COUNT",
    )

    fm_group.add_argument(
        "--custom-cmdline-file",
        dest="custom_cmdline_file",
        help="Path to custom cmdline file",
        metavar="FILE",
    )
    fm_group.add_argument(
        "--env-file",
        dest="env_file",
        help="Path to a file with additional environment variables",
        metavar="FILE",
    )
    fm_group.add_argument(
        "--serverhost",
        dest="serverhost",
        help="Server hostname for remote signature management.",
        metavar="HOST",
    )
    fm_group.add_argument(
        "--serverport",
        dest="serverport",
        type=int,
        help="Server port to use",
        metavar="PORT",
    )
    fm_group.add_argument(
        "--serverproto",
        dest="serverproto",
        help="Server protocol to use (default is https)",
        metavar="PROTO",
    )
    fm_group.add_argument(
        "--serverauthtokenfile",
        dest="serverauthtokenfile",
        help="File containing the server authentication token",
        metavar="FILE",
    )
    fm_group.add_argument(
        "--clientid",
        dest="clientid",
        help="Client ID to use when submitting issues",
        metavar="ID",
    )
    fm_group.add_argument(
        "--platform",
        dest="platform",
        help="Platform this crash appeared on",
        metavar="(x86|x86-64|arm)",
    )
    fm_group.add_argument(
        "--product",
        dest="product",
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
        dest="os",
        help="OS this crash appeared on",
        metavar="(windows|linux|macosx|b2g|android)",
    )
    fm_group.add_argument(
        "--tool",
        dest="tool",
        help="Name of the tool that found this issue",
        metavar="NAME",
    )
    fm_group.add_argument(
        "--metadata",
        dest="metadata",
        nargs="+",
        type=str,
        help="List of metadata variables in the form 'KEY=VALUE'",
    )
    fm_group.add_argument(
        "--sigdir", dest="sigdir", help="Signature cache directory", metavar="DIR"
    )

    afl_group.add_argument(
        "--test-file",
        dest="test_file",
        help="Optional path to copy the test file to before reproducing",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--afl-timeout",
        dest="afl_timeout",
        type=int,
        default=1000,
        help="Timeout per test to pass to AFL for corpus refreshing",
        metavar="MSECS",
    )
    afl_group.add_argument(
        "--firefox",
        dest="firefox",
        action="store_true",
        help="Test Program is Firefox (requires FFPuppet installed)",
    )
    afl_group.add_argument(
        "--firefox-prefs",
        dest="firefox_prefs",
        help="Path to prefs.js file for Firefox",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--firefox-extensions",
        nargs="+",
        type=str,
        dest="firefox_extensions",
        help="Path extension file for Firefox",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--firefox-testpath",
        dest="firefox_testpath",
        help="Path to file to open with Firefox",
        metavar="FILE",
    )
    afl_group.add_argument(
        "--firefox-start-afl",
        dest="firefox_start_afl",
        metavar="FILE",
        help=(
            "Start AFL with the given Firefox binary, remaining arguments being "
            "passed to AFL"
        ),
    )
    afl_group.add_argument(
        "--afl-output-dir",
        dest="afloutdir",
        help="Path to the AFL output directory to manage",
        metavar="DIR",
    )
    afl_group.add_argument(
        "--afl-binary-dir",
        dest="aflbindir",
        help="Path to the AFL binary directory to use",
        metavar="DIR",
    )
    afl_group.add_argument(
        "--afl-stats",
        dest="aflstats",
        help="Deprecated, use --stats instead",
        metavar="FILE",
    )
    afl_group.add_argument("rargs", nargs=argparse.REMAINDER)

    if not argv:
        parser.print_help()
        parser.print_help()
        parser.exit(2)

    opts = parser.parse_args(argv)

    if opts.aflstats:
        print("Error: --afl-stats is deprecated, use --stats instead.", file=sys.stderr)
        time.sleep(2)

    if not opts.libfuzzer and not opts.aflfuzz:
        # For backwards compatibility, --aflfuzz is the default if nothing else is
        # specified.
        opts.aflfuzz = True

    if opts.libfuzzer and opts.aflfuzz:
        parser.error("Error: --libfuzzer and --aflfuzz are mutually exclusive.")

    if opts.transform and not os.path.isfile(opts.transform):
        parser.error(f"Error: Failed to locate transformation script {opts.transform}")

    return opts
