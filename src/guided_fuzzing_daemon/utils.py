# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import subprocess
import sys
import time
import zipfile
from argparse import Namespace
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager
from copy import copy
from math import log10
from pathlib import Path
from random import uniform
from re import Match, Pattern
from shutil import rmtree
from tempfile import mkdtemp
from typing import Any, TextIO, TypeVar

from FTB.ProgramConfiguration import ProgramConfiguration

if sys.version_info[:2] < (3, 12):
    from itertools import islice

THREAD_WORKERS = 16


def apply_transform(script_path: Path, testcase_path: Path) -> Path:
    """Apply a post-crash transformation to the testcase

    Args:
        script_path: Path to the transformation script
        testcase_path: Path to the testcase

    Returns:
        Path to the archive containing the original and transformed testcase
    """

    with TempPath() as output_path:
        try:
            subprocess.run(
                [str(script_path), str(testcase_path), output_path], check=True
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "Failed to apply post crash transformation.  Aborting..."
            ) from exc

        if not any(output_path.iterdir()):
            raise RuntimeError(
                "Transformation script did not generate any files.  Aborting..."
            )

        archive_path = f"{testcase_path}.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(str(testcase_path), Path(testcase_path).name)
            for file in output_path.rglob("*.*"):
                archive.write(str(file), arcname=file.relative_to(output_path))

    return Path(archive_path)


if sys.version_info[:2] < (3, 12):
    # generic type for `batched` below
    _T = TypeVar("_T")

    # added to itertools in 3.12
    def batched(iterable: Iterable[_T], n: int) -> Iterator[tuple[_T, ...]]:
        # batched('ABCDEFG', 3) → ABC DEF G
        if n < 1:
            raise ValueError("n must be at least one")
        iterator = iter(iterable)
        while batch := tuple(islice(iterator, n)):
            yield batch


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


@contextmanager
def Executor() -> Iterator[ThreadPoolExecutor]:  # pylint: disable=invalid-name
    """ThreadPoolExecutor that cancels remaining tasks if an exception is raised"""
    jobs: list[Future[None]] = []

    def _check_jobs(final: bool = False) -> None:
        result = wait(jobs, return_when=FIRST_EXCEPTION, timeout=None if final else 0)
        for job in result.done:
            try:
                job.result()  # raises, if the job raised
            except:  # noqa pylint: disable=bare-except
                try:
                    for job in result.not_done:
                        job.cancel()
                finally:
                    raise

    class _Executor(ThreadPoolExecutor):
        # the typing for this is almost impossible until 3.10
        # see `typing.ParamSpec`
        # pylint: disable=arguments-differ
        def submit(self, fn, *args, **kwds):  # type: ignore
            job = super().submit(fn, *args, **kwds)
            jobs.append(job)
            _check_jobs()
            return job

    with _Executor(max_workers=THREAD_WORKERS) as executor:
        try:
            yield executor
        finally:
            _check_jobs(final=True)


class LogFile:
    def __init__(self, handle: TextIO, prefix: str) -> None:
        self.handle = handle
        self.tee_buf = ""
        self.printed_pos = 0
        self.prefix = prefix
        # pattern is matched against each line of output. on_match must be set
        self.pattern: Pattern[str] | None = None
        # on_match is called when pattern matches
        self.on_match: Callable[[str, Match[str]], None] | None = None

    def add_pattern(
        self, pattern: Pattern[str], on_match: Callable[[str, Match[str]], None]
    ) -> None:
        self.pattern = pattern
        self.on_match = on_match

    def check_match(self, line: str) -> None:
        if self.pattern is not None and self.on_match is not None:
            if (match := self.pattern.match(line)) is not None:
                self.on_match(line, match)

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
                self.check_match(line)
                print(f"[{self.prefix}] {line}")
        if flush and self.tee_buf:
            self.check_match(self.tee_buf)
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
        # pattern is matched against each line of output. on_match must be set
        self.pattern: Pattern[str] | None = None
        # on_match is called when pattern matches
        self.on_match: Callable[[str, Match[str]], None] | None = None

    def add_pattern(
        self, pattern: Pattern[str], on_match: Callable[[str, Match[str]], None]
    ) -> None:
        self.pattern = pattern
        self.on_match = on_match
        for open_file in self.open_files:
            open_file.add_pattern(pattern, on_match)

    def append(self, handle: TextIO) -> None:
        idx = len(self.open_files)
        prefix = f"{idx:{self.instance_width}}"
        lf = LogFile(handle, prefix)
        if self.pattern is not None and self.on_match is not None:
            lf.add_pattern(self.pattern, self.on_match)
        self.open_files.append(lf)

    def print(self) -> None:
        if not self.hide:
            for open_file in self.open_files:
                open_file.print()

    def __enter__(self) -> LogTee:
        return self

    def __exit__(self, _exc_type: Any, _exc_val: Any, _exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        for open_file in self.open_files:
            if not self.hide:
                open_file.print(flush=True)
            open_file.handle.close()


class TempPath(Path):

    def __init__(self) -> None:
        super().__init__(mkdtemp(prefix="gfd-"))  # type: ignore[call-arg]

    def __enter__(self) -> TempPath:
        return self

    def __exit__(self, _exc_type: Any, _exc_val: Any, _exc_tb: Any) -> None:
        rmtree(self)


def open_log_handle(pattern: str | None, tmp_base: Path, idx: int) -> TextIO:
    """
    Helper function for creating a log handle for the given index.

    Arguments:
        pattern: Log file pattern, possibly containing '%'.
        tmp_base: Temporary directory fallback.
        idx: Index of the instance.

    Returns:
        A writable text-mode file handle.
    """
    if pattern:
        if "%" in pattern:
            return open(pattern % idx, "w", encoding="utf-8", buffering=1)
        return open(pattern, "w", encoding="utf-8", buffering=1)
    return (tmp_base / f"screen{idx}.log").open("w", encoding="utf-8", buffering=1)
