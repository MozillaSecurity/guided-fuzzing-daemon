# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import zipfile
from argparse import Namespace
from copy import copy
from math import log10
from pathlib import Path
from random import uniform
from typing import TextIO

from FTB.ProgramConfiguration import ProgramConfiguration


def apply_transform(script_path: Path, testcase_path: Path) -> Path:
    """Apply a post-crash transformation to the testcase

    Args:
        script_path: Path to the transformation script
        testcase_path: Path to the testcase

    Returns:
        Path to the archive containing the original and transformed testcase
    """

    with tempfile.TemporaryDirectory() as output_path:
        try:
            subprocess.run(
                [str(script_path), str(testcase_path), output_path], check=True
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "Failed to apply post crash transformation.  Aborting..."
            ) from exc

        if not any(Path(output_path).iterdir()):
            raise RuntimeError(
                "Transformation script did not generate any files.  Aborting..."
            )

        archive_path = f"{testcase_path}.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(str(testcase_path), Path(testcase_path).name)
            for file in Path(output_path).rglob("*.*"):
                archive.write(str(file), arcname=file.relative_to(output_path))

    return Path(archive_path)


def create_envs(
    env: dict[str, str], opts: Namespace, instances: int, cfg: ProgramConfiguration
) -> tuple[tuple[dict[str, str], ...], tuple[ProgramConfiguration, ...]]:
    """Create a list of environments and configurations for each fuzzing instance.

    Arguments:
        env: Base environment
        opts: Program arguments.
        instances: Number of fuzzing instances
        cfg: Common base program configuration

    Returns:
        2-tuple:
            instances length tuple of environment for each instance
            instances length tuple of ProgramConfiguration for each instance
    """
    # Copy the system environment variables by default and overwrite them
    # if they are specified through env.
    base_env = env.copy()
    base_cfg = copy(cfg)
    base_cfg.env = base_cfg.env.copy()

    if opts.env:
        base_env.update(opts.env)
        base_cfg.addEnvironmentVariables(opts.env)

    if opts.env_percent:
        envs = []
        cfgs = []

        for _ in range(instances):
            add_env = {}
            for key, value_pcts in opts.env_percent.items():
                rand_val = uniform(0.0, 100.0)
                for value, pct in value_pcts.items():
                    if rand_val <= pct:
                        add_env[key] = value
                        break
                    rand_val -= pct

            this_cfg = copy(base_cfg)
            this_cfg.env = this_cfg.env.copy()
            this_cfg.addEnvironmentVariables(add_env)

            this_env = base_env.copy()
            this_env.update(add_env)

            envs.append(this_env)
            cfgs.append(this_cfg)

        return (tuple(envs), tuple(cfgs))

    return ((base_env,) * instances, (base_cfg,) * instances)


def test_binary_asan(bin_path: Path) -> bool:
    result = subprocess.run(
        ["nm", "-g", str(bin_path)],
        capture_output=True,
    )

    if (
        result.stdout.find(b" __asan_init") >= 0
        or result.stdout.find(b"__ubsan_default_options") >= 0
    ):
        return True
    return False


def warn_local(opts: Namespace) -> None:
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


class LogFile:
    def __init__(self, handle: TextIO, prefix: str) -> None:
        self.handle = handle
        self.tee_buf = ""
        self.printed_pos = 0
        self.prefix = prefix

    def print(self, flush: bool = False) -> None:
        with Path(self.handle.name).open(encoding="utf-8") as read_file:
            read_file.seek(self.printed_pos)
            new_data = read_file.read()
            self.printed_pos = read_file.tell()
        lines_and_tail = new_data.rsplit("\n", 1)
        if len(lines_and_tail) == 1:
            self.tee_buf = f"{self.tee_buf}{lines_and_tail[0]}"
        else:
            lines, tail = lines_and_tail
            lines = f"{self.tee_buf}{lines}"
            self.tee_buf = tail
            for line in lines.splitlines():
                print(f"[{self.prefix}] {line}")
        if flush and self.tee_buf:
            print(f"[{self.prefix}] {self.tee_buf}")
            self.tee_buf = ""


class LogTee:
    def __init__(self, hide: bool, instances: int) -> None:
        self.open_files: list[LogFile] = []
        if instances > 1:
            self.instance_width = int(log10(instances - 1)) + 1
        else:
            self.instance_width = 1
        self.hide = hide

    def append(self, handle: TextIO) -> None:
        idx = len(self.open_files)
        prefix = f"{idx:{self.instance_width}}"
        self.open_files.append(LogFile(handle, prefix))

    def print(self) -> None:
        if not self.hide:
            for open_file in self.open_files:
                open_file.print()

    def close(self) -> None:
        for open_file in self.open_files:
            if not self.hide:
                open_file.print(flush=True)
            open_file.handle.close()
