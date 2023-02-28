"""
AFL Management Daemon -- Tool to manage AFL queue and results

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
"""
import sys
from pathlib import Path

from Collector.Collector import Collector

from .afl import aflfuzz_main
from .args import parse_args
from .libfuzzer import libfuzzer_main
from .nyx import nyx_main
from .s3 import S3Manager, s3_main


def main(argv=None):
    """Command line options."""

    opts = parse_args(argv)

    # ## Begin generic S3 action handling ##

    if (
        opts.s3_build_download
        or opts.s3_build_upload
        or opts.s3_corpus_download
        or opts.s3_corpus_refresh
        or opts.s3_corpus_status
        or opts.s3_corpus_upload
        or opts.s3_queue_cleanup
        or opts.s3_queue_status
    ):
        return s3_main(opts)

    # ## End generic S3 action handling ##

    if opts.fuzzmanager:
        serverauthtoken = None
        if opts.serverauthtokenfile:
            serverauthtoken = (
                Path(opts.serverauthtokenfile).read_text(encoding="utf-8").rstrip()
            )

        collector = Collector(
            sigCacheDir=opts.sigdir,
            serverHost=opts.serverhost,
            serverPort=opts.serverport,
            serverProtocol=opts.serverproto,
            serverAuthToken=serverauthtoken,
            clientId=opts.clientid,
            tool=opts.tool,
        )

    s3m = None

    if opts.s3_queue_upload:
        s3m = S3Manager(
            opts.s3_bucket, opts.project, opts.build_project, opts.build_zip_name
        )

    if opts.mode == "libfuzzer":
        return libfuzzer_main(opts, collector, s3m)

    if opts.mode == "aflfuzz":
        return aflfuzz_main(opts, collector, s3m)

    if opts.mode == "nyx":
        return nyx_main(opts, collector, s3m)

    print("Error: Unhandled case", file=sys.stderr)
    return 2
