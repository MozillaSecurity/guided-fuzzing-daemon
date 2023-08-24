# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import subprocess
from argparse import Namespace
from typing import Optional

from Collector.Collector import Collector

from .s3 import S3Manager


def nyx_main(
    opts: Namespace, _collector: Optional[Collector], _s3m: Optional[S3Manager]
) -> int:
    assert opts.sharedir
    assert opts.spec_fuzzer

    cargo_cmdline = [
        "cargo",
        "run",
        "--release",
        "--",
        "-s",
        str(opts.sharedir.resolve()),
    ]
    result = subprocess.run(cargo_cmdline, cwd=opts.spec_fuzzer)

    return result.returncode
