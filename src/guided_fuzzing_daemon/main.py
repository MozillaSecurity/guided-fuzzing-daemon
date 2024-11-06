# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""AFL Management Daemon -- Tool to manage AFL queue and results

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
"""
from __future__ import annotations

from logging import DEBUG, ERROR, INFO, WARNING, basicConfig, getLogger
from pathlib import Path

from Collector.Collector import Collector

from .afl import afl_main
from .args import parse_args
from .libfuzzer import libfuzzer_main
from .nyx import nyx_main
from .storage import (
    CloudStorageProvider,
    Corpus,
    CorpusSyncer,
    GoogleCloudStorage,
    S3Storage,
)

LOG = getLogger("gfd")


def main(argv: list[str] | None = None) -> int:
    """Command line options."""

    opts = parse_args(argv)

    if opts.debug:
        log_level = DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:  # pragma: no cover
        log_level = INFO
        log_fmt = "%(message)s"
    basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)
    getLogger("urllib3.connectionpool").setLevel(ERROR)
    getLogger("s3transfer").setLevel(WARNING)
    getLogger("botocore").setLevel(WARNING)
    getLogger("boto3").setLevel(WARNING)

    if opts.provider == "S3":
        storage: CloudStorageProvider = S3Storage(opts.bucket)
    elif opts.provider == "GCS":  # pragma: no cover
        storage = GoogleCloudStorage(opts.bucket)
    else:  # pragma: no cover
        LOG.error("error: Unhandled cloud storage provider: %s", opts.provider)
        return 2

    # ## Begin generic S3 action handling ##

    if opts.corpus_download:
        opts.corpus_download.mkdir(exist_ok=True, parents=True)
        syncer = CorpusSyncer(storage, Corpus(opts.corpus_download), opts.project)
        syncer.download_corpus(opts.corpus_download_size)
        return 0

    if opts.corpus_status:
        status_data = storage.get_corpus_status(opts.project)
        total_corpus_files = 0

        for status_dt, status_cnt in sorted(status_data.items()):
            LOG.info("Added %s: %d", status_dt, status_cnt)
            total_corpus_files += status_cnt
        LOG.info("Total corpus files: %d", total_corpus_files)
        return 0

    if opts.corpus_upload:
        syncer = CorpusSyncer(storage, Corpus(opts.corpus_upload), opts.project)
        syncer.upload_corpus(opts.corpus_replace)
        return 0

    if opts.list_projects:
        for project in storage.iter_projects(opts.project or ""):
            LOG.info(project)
        return 0

    if opts.queue_status:
        status_data = storage.get_queue_status(opts.project)
        total_queue_files = 0

        for queue_name, status in status_data.items():
            LOG.info("Queue %s: %d", queue_name, status)
            total_queue_files += status
        LOG.info("Total queue files: %d", total_queue_files)
        return 0

    # ## End generic S3 action handling ##

    collector = None
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

    if opts.mode == "afl":
        return afl_main(opts, collector, storage)

    if opts.mode == "libfuzzer":
        return libfuzzer_main(opts, collector, storage)

    if opts.mode == "nyx":
        return nyx_main(opts, collector, storage)

    LOG.error("error: Unhandled case")
    return 2
