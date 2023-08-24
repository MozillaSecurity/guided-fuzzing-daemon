# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import subprocess
import sys
import tempfile
import time
import zipfile
from argparse import Namespace
from pathlib import Path
from typing import Dict, List, Tuple

HAVE_FFPUPPET = True
try:
    from ffpuppet import FFPuppet
    from ffpuppet.helpers import prepare_environment
    from ffpuppet.profile import Profile
except ImportError:
    HAVE_FFPUPPET = False


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


def setup_firefox(
    bin_path: Path, prefs_path: Path, ext_paths: List[Path], test_path: Path
) -> Tuple["FFPuppet", List[str], Dict[str, str]]:
    ffp = FFPuppet(use_xvfb=True)
    ffp.profile = Profile(
        browser_bin=bin_path, extension=ext_paths, prefs_js=prefs_path
    )

    env = prepare_environment(bin_path.parent, bin_path.parent)
    cmd = ffp.build_launch_cmd(str(bin_path), additional_args=[str(test_path)])

    try:
        # Remove any custom ASan options passed by FFPuppet as they might
        # interfere with AFL. This should be removed once we can ensure
        # that options passed by FFPuppet work with AFL.
        del env["ASAN_OPTIONS"]
    except KeyError:
        pass

    return (ffp, cmd, env)


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
