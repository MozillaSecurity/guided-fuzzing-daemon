"""
AFL Management Daemon -- Tool to manage AFL queue and results

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
"""
import os
import os.path
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

from .afl import scan_crashes, write_aggregated_stats_afl
from .args import parse_args
from .libfuzzer import LibFuzzerMonitor, write_aggregated_stats_libfuzzer
from .s3 import S3Manager
from .utils import HAVE_FFPUPPET, apply_transform, setup_firefox, test_binary_asan


def main(argv=None):
    """Command line options."""

    opts = parse_args(argv)

    if opts.fuzzmanager:
        serverauthtoken = None
        if opts.serverauthtokenfile:
            serverauthtoken = Path(opts.serverauthtokenfile).read_text().rstrip()

        collector = Collector(
            sigCacheDir=opts.sigdir,
            serverHost=opts.serverhost,
            serverPort=opts.serverport,
            serverProtocol=opts.serverproto,
            serverAuthToken=serverauthtoken,
            clientId=opts.clientid,
            tool=opts.tool,
        )

    def warn_local():
        if not opts.fuzzmanager and not opts.local:
            # User didn't specify --fuzzmanager but also didn't specify --local
            # explicitly, so we should warn them that their crash results won't end up
            # anywhere except on the local machine. This method is called for AFL and
            # libFuzzer separately whenever it is determined that the user is running
            # fuzzing locally.
            print(
                "Warning: You are running in local mode, crashes won't be submitted "
                "anywhere...",
                file=sys.stderr,
            )
            time.sleep(2)

    # ## Begin generic S3 action handling ##

    s3m = None

    if (
        opts.s3_queue_upload
        or opts.s3_corpus_refresh
        or opts.s3_build_download
        or opts.s3_build_upload
        or opts.s3_corpus_download
        or opts.s3_corpus_upload
        or opts.s3_queue_status
        or opts.s3_corpus_status
        or opts.s3_queue_cleanup
    ):
        if not opts.s3_bucket or not opts.project:
            print(
                "Error: Must specify both --s3-bucket and --project for S3 actions",
                file=sys.stderr,
            )
            return 2

        s3m = S3Manager(
            opts.s3_bucket, opts.project, opts.build_project, opts.build_zip_name
        )

    if opts.s3_queue_status:
        status_data = s3m.get_queue_status()
        total_queue_files = 0

        for queue_name, status in status_data.items():
            print(f"Queue {queue_name}: {status}")
            total_queue_files += status
        print(f"Total queue files: {total_queue_files}")

        return 0

    if opts.s3_corpus_status:
        status_data = s3m.get_corpus_status()
        total_corpus_files = 0

        for (status_dt, status_cnt) in sorted(status_data.items()):
            print(f"Added {status_dt}: {status_cnt}")
            total_corpus_files += status_cnt
        print(f"Total corpus files: {total_corpus_files}")

        return 0

    if opts.s3_queue_cleanup:
        s3m.clean_queue_dirs()
        return 0

    if opts.s3_build_download:
        s3m.download_build(opts.s3_build_download)
        return 0

    if opts.s3_build_upload:
        s3m.upload_build(opts.s3_build_upload)
        return 0

    if opts.s3_corpus_download:
        if opts.s3_corpus_download_size is not None:
            opts.s3_corpus_download_size = int(opts.s3_corpus_download_size)

        s3m.download_corpus(opts.s3_corpus_download, opts.s3_corpus_download_size)
        return 0

    if opts.s3_corpus_upload:
        s3m.upload_corpus(opts.s3_corpus_upload, opts.s3_corpus_replace)
        return 0

    if opts.s3_corpus_refresh:
        if opts.aflfuzz and not opts.aflbindir:
            print(
                "Error: Must specify --afl-binary-dir for refreshing the test corpus",
                file=sys.stderr,
            )
            return 2

        if not os.path.exists(opts.s3_corpus_refresh):
            os.makedirs(opts.s3_corpus_refresh)

        queues_dir = os.path.join(opts.s3_corpus_refresh, "queues")

        print(f"Cleaning old queues from s3://{opts.s3_bucket}/{opts.project}/queues/")
        s3m.clean_queue_dirs()

        print(
            f"Downloading queues from s3://{opts.s3_bucket}/{opts.project}/queues/ to "
            f"{queues_dir}"
        )
        s3m.download_queue_dirs(opts.s3_corpus_refresh)

        cmdline_file = os.path.join(opts.s3_corpus_refresh, "cmdline")
        if not os.path.exists(cmdline_file):
            # this can happen in a few legitimate cases:
            #  - project folder does not exist at all (new project)
            #  - only closed queues existed (old project)
            #  - no queues exist (recently refreshed manually)
            # print the error, but return 0
            print(
                "Error: Failed to download a cmdline file from queue directories.",
                file=sys.stderr,
            )
            return 0

        build_path = os.path.join(opts.s3_corpus_refresh, "build")

        if opts.build:
            build_path = opts.build
        else:
            print("Downloading build")
            s3m.download_build(build_path)

        cmdline = (Path(opts.s3_corpus_refresh) / "cmdline").read_text().splitlines()

        # Assume cmdline[0] is the name of the binary
        binary_name = Path(cmdline[0]).name

        # Try locating our binary in the build we just unpacked
        binary_search_result = [
            os.path.join(dirpath, filename)
            for dirpath, dirnames, filenames in os.walk(build_path)
            for filename in filenames
            if (
                filename == binary_name
                and (
                    stat.S_IXUSR
                    & (Path(dirpath) / filename).stat().st_mode
                )
            )
        ]

        if not binary_search_result:
            print(
                f"Error: Failed to locate binary {binary_name} in unpacked build.",
                file=sys.stderr,
            )
            return 2

        if len(binary_search_result) > 1:
            print(
                f"Error: Binary name {binary_name} is ambiguous in unpacked build.",
                file=sys.stderr,
            )
            return 2

        cmdline[0] = binary_search_result[0]

        # Download our current corpus into the queues directory as well
        print(
            f"Downloading corpus from s3://{opts.s3_bucket}/{opts.project}/corpus/ to "
            f"{queues_dir}"
        )
        s3m.download_corpus(queues_dir)

        # Ensure the directory for our new tests is empty
        updated_tests_dir = os.path.join(opts.s3_corpus_refresh, "tests")
        if os.path.exists(updated_tests_dir):
            shutil.rmtree(updated_tests_dir)
        os.mkdir(updated_tests_dir)

        if opts.aflfuzz:
            # Run afl-cmin
            afl_cmin = os.path.join(opts.aflbindir, "afl-cmin")
            if not os.path.exists(afl_cmin):
                print("Error: Unable to locate afl-cmin binary.", file=sys.stderr)
                return 2

            if opts.firefox:
                (ffp, ff_cmd, ff_env) = setup_firefox(
                    cmdline[0],
                    opts.firefox_prefs,
                    opts.firefox_extensions,
                    opts.firefox_testpath,
                )
                cmdline = ff_cmd

            afl_cmdline = [
                afl_cmin,
                "-e",
                "-i",
                queues_dir,
                "-o",
                updated_tests_dir,
                "-t",
                str(opts.afl_timeout),
                "-m",
                "none",
            ]

            if opts.test_file:
                afl_cmdline.extend(["-f", opts.test_file])

            afl_cmdline.extend(cmdline)

            print("Running afl-cmin")
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = str(Path(cmdline[0]).parent)
            if opts.firefox:
                env.update(ff_env)
            devnull = subprocess.DEVNULL
            if opts.debug:
                devnull = None
            subprocess.run(afl_cmdline, stdout=devnull, env=env, check=True)

            if opts.firefox:
                ffp.clean_up()
        else:
            cmdline.extend(["-merge=1", updated_tests_dir, queues_dir])

            # Filter out any -dict arguments that we don't need anyway for merging
            cmdline = [x for x in cmdline if not x.startswith("-dict=")]

            # Filter out any -max_len arguments because the length should only be
            # enforced by the instance(s) doing the actual testing.
            cmdline = [x for x in cmdline if not x.startswith("-max_len=")]

            print("Running libFuzzer merge")
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = str(Path(cmdline[0]).parent)
            devnull = subprocess.DEVNULL
            if opts.debug:
                devnull = None
            subprocess.run(cmdline, stdout=devnull, env=env, check=True)

        if not os.listdir(updated_tests_dir):
            print("Error: Merge returned empty result, refusing to upload.")
            return 2

        # replace existing corpus with reduced corpus
        print(
            f"Uploading reduced corpus to s3://{opts.s3_bucket}/{opts.project}/corpus/"
        )
        s3m.upload_corpus(updated_tests_dir, corpus_delete=True)

        # Prune the queues directory once we successfully uploaded the new
        # test corpus, but leave everything that's part of our new corpus
        # so we don't have to download those files again.
        test_files = [
            file
            for file in os.listdir(updated_tests_dir)
            if os.path.isfile(os.path.join(updated_tests_dir, file))
        ]
        obsolete_queue_files = [
            file
            for file in os.listdir(queues_dir)
            if os.path.isfile(os.path.join(queues_dir, file)) and file not in test_files
        ]

        for file in obsolete_queue_files:
            os.remove(os.path.join(queues_dir, file))

        return 0

    # ## End generic S3 action handling ##

    if opts.cmd and opts.aflfuzz:
        if not opts.firefox:
            print(
                "Error: Use --cmd either with libfuzzer or with afl in firefox mode",
                file=sys.stderr,
            )
            return 2

    if opts.libfuzzer:
        if not opts.rargs:
            print("Error: No arguments specified", file=sys.stderr)
            return 2

        binary = opts.rargs[0]
        if not os.path.exists(binary):
            print(f"Error: Specified binary does not exist: {binary}", file=sys.stderr)
            return 2

        configuration = ProgramConfiguration.fromBinary(binary)
        if configuration is None:
            print(
                "Error: Failed to load program configuration based on binary",
                file=sys.stderr,
            )
            return 2

        # Build our libFuzzer command line. We add certain parameters automatically for
        # convenience.
        cmdline = []
        cmdline.extend(opts.rargs)
        cmdline_add_args = []
        if test_binary_asan(binary):
            # With ASan, we always want to disable the internal signal handlers
            # libFuzzer uses.
            cmdline_add_args.extend(
                [
                    "-handle_segv=0",
                    "-handle_bus=0",
                    "-handle_abrt=0",
                    "-handle_ill=0",
                    "-handle_fpe=0",
                ]
            )
        else:
            # We currently don't support non-ASan binaries because the logic in
            # LibFuzzerMonitor expects an ASan trace on crash and CrashInfo doesn't
            # parse internal libFuzzer traces.
            print(
                "Error: This wrapper currently only supports binaries built with "
                "AddressSanitizer.",
                file=sys.stderr,
            )
            return 2

        for arg in cmdline:
            if arg.startswith("-jobs=") or arg.startswith("-workers="):
                print(
                    "Error: Using -jobs and -workers is incompatible with this "
                    "wrapper.",
                    file=sys.stderr,
                )
                print(
                    "       You can use --libfuzzer-instances to run multiple instances"
                    " instead.",
                    file=sys.stderr,
                )
                return 2

        # Used by statistics and useful in general
        cmdline_add_args.append("-print_pcs=1")

        # Append args if they don't exist already
        for arg in cmdline_add_args:
            if arg not in cmdline:
                cmdline.append(arg)

        env = {}
        if opts.env:
            env = dict(kv.split("=", 1) for kv in opts.env)
            configuration.addEnvironmentVariables(env)

        # Copy the system environment variables by default and overwrite them
        # if they are specified through env.
        env = dict(os.environ)
        if opts.env:
            oenv = dict(kv.split("=", 1) for kv in opts.env)
            configuration.addEnvironmentVariables(oenv)
            for envkey in oenv:
                env[envkey] = oenv[envkey]

        args = opts.rargs[1:]
        if args:
            configuration.addProgramArguments(args)

        metadata = {}
        if opts.metadata:
            metadata.update(dict(kv.split("=", 1) for kv in opts.metadata))
            configuration.addMetadata(metadata)

            # Set LD_LIBRARY_PATH for convenience
            if "LD_LIBRARY_PATH" not in env:
                env["LD_LIBRARY_PATH"] = str(Path(binary).parent)

        signature_repeat_count = 0
        last_signature = None
        last_queue_upload = 0
        restarts = opts.libfuzzer_restarts

        # The base directory for libFuzzer is the current working directory
        base_dir = os.getcwd()

        # Find the first corpus directory from our command line
        corpus_dir = None
        for rarg in opts.rargs:
            if os.path.isdir(rarg):
                corpus_dir = os.path.abspath(rarg)
                break

        if corpus_dir is None:
            print(
                "Error: Failed to find a corpus directory on command line.",
                file=sys.stderr,
            )
            return 2

        # At this point we know that we will be running libFuzzer locally
        warn_local()

        # Memorize the original corpus, so we can exclude it from uploading later
        original_corpus = set(os.listdir(corpus_dir))

        corpus_auto_reduce_threshold = None
        corpus_auto_reduce_ratio = None
        if opts.libfuzzer_auto_reduce is not None:
            if opts.libfuzzer_auto_reduce < 5:
                print(
                    "Error: Auto reduce threshold should at least be 5%.",
                    file=sys.stderr,
                )
                return 2

            corpus_auto_reduce_ratio = float(opts.libfuzzer_auto_reduce) / float(100)

            if len(original_corpus) >= opts.libfuzzer_auto_reduce_min:
                corpus_auto_reduce_threshold = int(
                    len(original_corpus) * (1 + corpus_auto_reduce_ratio)
                )
            else:
                # Corpus is smaller than --libfuzzer-auto-reduce-min specifies, so we
                # calculate the threshold based on that value in combination with the
                # ratio instead, initially.
                corpus_auto_reduce_threshold = int(
                    opts.libfuzzer_auto_reduce_min * (1 + corpus_auto_reduce_ratio)
                )

            if corpus_auto_reduce_threshold <= len(original_corpus):
                print(
                    "Error: Invalid auto reduce threshold specified.", file=sys.stderr
                )
                return 2

        # Write a cmdline file, similar to what our AFL fork does
        with open("cmdline", "w") as cmdline_fd:
            for rarg in opts.rargs:
                # Omit any corpus directory that is in the command line
                if not os.path.isdir(rarg):
                    print(rarg, file=cmdline_fd)

        monitors = [None] * opts.libfuzzer_instances
        monitor_queue = queue.Queue()

        # Keep track how often we crash to abort in certain situations
        crashes_per_minute_interval = 0
        crashes_per_minute = 0

        # Global stats
        stats = {
            "crashes": 0,
            "crashes_per_minute": 0,
            "timeouts": 0,
            "ooms": 0,
            "corpus_size": len(original_corpus),
            "execs_done": 0,
            "last_new": 0,
            "last_new_pc": 0,
            "next_auto_reduce": 0,
        }

        # Memorize if we just did a corpus reduction, for S3 sync
        corpus_reduction_done = False

        # Memorize which corpus files we deleted (e.g. for timing out),
        # as this can happen in multiple subprocesses at once.
        removed_corpus_files = set()

        try:
            while True:
                if (
                    restarts is not None
                    and restarts < 0
                    and all(x is None for x in monitors)
                ):
                    print("Run completed.", file=sys.stderr)
                    break

                # Check if we need to (re)start any monitors
                for idx, monitor in enumerate(monitors):
                    if monitor is None:
                        if restarts is not None:
                            restarts -= 1
                            if restarts < 0:
                                break

                        # pylint: disable=consider-using-with
                        process = subprocess.Popen(
                            cmdline,
                            # stdout=None,
                            stderr=subprocess.PIPE,
                            env=env,
                            text=True,
                        )

                        monitors[idx] = LibFuzzerMonitor(
                            process, mid=idx, mqueue=monitor_queue
                        )
                        monitors[idx].start()

                corpus_size = None
                if corpus_auto_reduce_threshold is not None or opts.stats:
                    # We need the corpus size for stats and the auto reduce feature,
                    # so we cache it here to avoid running listdir multiple times.
                    corpus_size = len(os.listdir(corpus_dir))

                if (
                    corpus_auto_reduce_threshold is not None
                    and corpus_size >= corpus_auto_reduce_threshold
                ):
                    print("Preparing automated merge...", file=sys.stderr)

                    # Time to Auto-reduce
                    for idx, monitor in enumerate(monitors):
                        if monitor is not None:
                            print(
                                f"Asking monitor {idx} to terminate...", file=sys.stderr
                            )
                            monitor.terminate()
                            monitor.join(30)
                            if monitor.is_alive():
                                raise RuntimeError("Monitor refusing to stop.")

                            # Indicate that this monitor is dead, so it is restarted
                            # later on
                            monitors[idx] = None

                            if opts.stats:
                                # Make sure the execs that this monitor did survive in
                                # stats
                                stats["execs_done"] += monitor.execs_done

                    # All monitors are assumed to be dead now, clear the monitor queue
                    # in case it has remaining ids from monitors that terminated on
                    # their own before we terminated them.
                    while not monitor_queue.empty():
                        monitor_queue.get_nowait()

                    merge_cmdline = []
                    merge_cmdline.extend(cmdline)

                    # Filter all directories on the command line, these are likely
                    # corpus dirs
                    merge_cmdline = [x for x in merge_cmdline if not Path(x).is_dir()]

                    # Filter out other stuff we don't want for merging
                    merge_cmdline = [
                        x for x in merge_cmdline if not x.startswith("-dict=")
                    ]

                    new_corpus_dir = tempfile.mkdtemp(prefix="fm-libfuzzer-automerge-")
                    merge_cmdline.extend(["-merge=1", new_corpus_dir, corpus_dir])

                    print("Running automated merge...", file=sys.stderr)
                    env = os.environ.copy()
                    env["LD_LIBRARY_PATH"] = str(Path(merge_cmdline[0]).parent)
                    devnull = subprocess.DEVNULL
                    if opts.debug:
                        devnull = None
                    subprocess.run(merge_cmdline, stdout=devnull, env=env, check=True)

                    if not os.listdir(new_corpus_dir):
                        print(
                            "Error: Merge returned empty result, refusing to continue."
                        )
                        return 2

                    shutil.rmtree(corpus_dir)
                    shutil.move(new_corpus_dir, corpus_dir)

                    # Update our corpus size
                    corpus_size = len(os.listdir(corpus_dir))

                    # Update our auto-reduction target
                    if corpus_size >= opts.libfuzzer_auto_reduce_min:
                        corpus_auto_reduce_threshold = int(
                            corpus_size * (1 + corpus_auto_reduce_ratio)
                        )
                    else:
                        # Corpus is now smaller than --libfuzzer-auto-reduce-min
                        # specifies.
                        corpus_auto_reduce_threshold = int(
                            opts.libfuzzer_auto_reduce_min
                            * (1 + corpus_auto_reduce_ratio)
                        )

                    corpus_reduction_done = True

                    # Continue, our instances will be restarted with the next loop
                    continue

                if opts.stats:
                    stats["corpus_size"] = corpus_size
                    if corpus_auto_reduce_threshold is not None:
                        stats["next_auto_reduce"] = corpus_auto_reduce_threshold

                    write_aggregated_stats_libfuzzer(opts.stats, stats, monitors, [])

                # Only upload new corpus files every 2 hours or after corpus reduction
                if opts.s3_queue_upload and (
                    corpus_reduction_done or last_queue_upload < int(time.time()) - 7200
                ):
                    s3m.upload_libfuzzer_queue_dir(
                        base_dir, corpus_dir, original_corpus
                    )

                    # Pull down queue files from other queues directly into the corpus
                    s3m.download_libfuzzer_queues(corpus_dir)

                    last_queue_upload = int(time.time())
                    corpus_reduction_done = False

                try:
                    result = monitor_queue.get(True, 10)
                except queue.Empty:
                    continue

                monitor = monitors[result]
                monitor.join(20)
                if monitor.is_alive():
                    raise RuntimeError(
                        f"Monitor {result} still alive although it signaled "
                        "termination."
                    )

                # Monitor is dead, mark it for restarts
                monitors[result] = None

                if monitor.exc is not None:
                    # If the monitor had an exception, re-raise it here
                    raise monitor.exc

                if opts.stats:
                    # Make sure the execs that this monitor did survive in stats
                    stats["execs_done"] += monitor.execs_done

                print(
                    f"Job {result} terminated, processing results...", file=sys.stderr
                )

                trace = monitor.get_asan_trace()
                testcase = monitor.get_testcase()
                stderr = monitor.get_stderr()

                if not monitor.inited and not trace and not testcase:
                    print(
                        "Process did not startup correctly, aborting... (1)",
                        file=sys.stderr,
                    )
                    return 2

                # libFuzzer can exit due to OOM with and without a testcase.
                # The case of having an OOM with a testcase is handled further below.
                if not testcase and monitor.had_oom:
                    stats["ooms"] += 1
                    continue

                # Don't bother sending stuff to the server with neither trace nor
                # testcase
                if not trace and not testcase:
                    continue

                # Ignore slow units and oom files
                if testcase is not None:
                    testcase_name = Path(testcase).name

                    if not monitor.inited:
                        if testcase_name.startswith("oom-") or testcase_name.startswith(
                            "timeout-"
                        ):
                            hashname = testcase_name.split("-")[1]
                            potential_corpus_file = Path(corpus_dir) / hashname
                            if potential_corpus_file.exists():
                                print(
                                    f"Removing problematic corpus file {hashname}...",
                                    file=sys.stderr,
                                )
                                potential_corpus_file.unlink()
                                removed_corpus_files.add(potential_corpus_file)

                            if potential_corpus_file in removed_corpus_files:
                                continue

                        # If neither an OOM or a Timeout caused the startup failure or
                        # we couldn't find and remove the offending file, we should bail
                        # out at this point.
                        print(
                            "Process did not startup correctly, aborting... (2)",
                            file=sys.stderr,
                        )
                        return 2

                    if testcase_name.startswith("slow-unit-"):
                        continue
                    if testcase_name.startswith("oom-"):
                        stats["ooms"] += 1
                        continue
                    if testcase_name.startswith("timeout-"):
                        stats["timeouts"] += 1
                        continue

                stats["crashes"] += 1

                if int(time.time()) - crashes_per_minute_interval > 60:
                    crashes_per_minute_interval = int(time.time())
                    crashes_per_minute = 0
                crashes_per_minute += 1
                stats["crashes_per_minute"] = crashes_per_minute

                if crashes_per_minute >= 10:
                    print("Too many frequent crashes, exiting...", file=sys.stderr)

                    if opts.stats:
                        # If statistics are reported to EC2SpotManager, this helps us to
                        # see when fuzzing has become impossible due to excessive
                        # crashes.
                        warning = "Fuzzing terminated due to excessive crashes."
                        write_aggregated_stats_libfuzzer(
                            opts.stats, stats, monitors, [warning]
                        )
                    break

                if not monitor.inited:
                    print("Process crashed at startup, aborting...", file=sys.stderr)
                    if opts.stats:
                        # If statistics are reported to EC2SpotManager, this helps us to
                        # see when fuzzing has become impossible due to excessive
                        # crashes.
                        warning = "Fuzzing did not startup correctly."
                        write_aggregated_stats_libfuzzer(
                            opts.stats, stats, monitors, [warning]
                        )
                    return 2

                if opts.transform:
                    # If a transformation script was supplied, update the testcase path
                    # to point to the archive which includes both, the original and
                    # updated testcases
                    try:
                        testcase = apply_transform(opts.transform, testcase)
                    except Exception as exc:  # pylint: disable=broad-except
                        print(exc.args[1], file=sys.stderr)

                # If we run in local mode (no --fuzzmanager specified), then we just
                # continue after each crash
                if not opts.fuzzmanager:
                    continue

                crash_info = CrashInfo.fromRawCrashData(
                    [], stderr, configuration, auxCrashData=trace
                )

                (sigfile, metadata) = collector.search(crash_info)

                if sigfile is not None:
                    if last_signature == sigfile:
                        signature_repeat_count += 1
                    else:
                        last_signature = sigfile
                        signature_repeat_count = 0

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
                    collector.submit(crash_info, testcase)
                    print("Successfully submitted crash.", file=sys.stderr)
        finally:
            try:
                # Before doing anything, try to shutdown our monitors
                for monitor in monitors:
                    if monitor is not None:
                        monitor.terminate()
                        monitor.join(10)
            finally:
                if sys.exc_info()[0] is not None:
                    # We caught an exception, print it now when all our monitors are
                    # down
                    traceback.print_exc()

        return 0

    if opts.aflfuzz:
        if opts.firefox or opts.firefox_start_afl:
            if not HAVE_FFPUPPET:
                print(
                    "Error: --firefox and --firefox-start-afl require FFPuppet to be "
                    "installed",
                    file=sys.stderr,
                )
                return 2

            if opts.custom_cmdline_file:
                print(
                    "Error: --custom-cmdline-file is incompatible with firefox options",
                    file=sys.stderr,
                )
                return 2

            if not opts.firefox_prefs or not opts.firefox_testpath:
                print(
                    "Error: --firefox and --firefox-start-afl require --firefox-prefs"
                    "and --firefox-testpath to be specified",
                    file=sys.stderr,
                )
                return 2

        if opts.firefox_start_afl:
            if not opts.aflbindir:
                print(
                    "Error: Must specify --afl-binary-dir for starting AFL with "
                    "firefox",
                    file=sys.stderr,
                )
                return 2

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
                sync_dirs = os.listdir(opts.afloutdir)

                for sync_dir in sync_dirs:
                    if (Path(opts.afloutdir) / sync_dir / "crashes").exists():
                        afl_out_dirs.append(os.path.join(opts.afloutdir, sync_dir))

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
        if opts.s3_queue_upload or opts.fuzzmanager:
            if not opts.afloutdir:
                print(
                    "Error: Must specify AFL output directory using --afl-output-dir",
                    file=sys.stderr,
                )
                return 2

        if opts.fuzzmanager or opts.s3_queue_upload or opts.aflstats:
            last_queue_upload = 0

            # If we reach this point, we know that AFL will be running on this machine,
            # so do the local warning check
            warn_local()

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
