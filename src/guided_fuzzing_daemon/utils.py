# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from fasteners import InterProcessLock

HAVE_FFPUPPET = True
try:
    from ffpuppet import FFPuppet
except ImportError:
    HAVE_FFPUPPET = False


def apply_transform(script_path, testcase_path):
    """
    Apply a post-crash transformation to the testcase

    @type script_path: String
    @param script_path: Path to the transformation script

    @type testcase_path: String
    @param testcase_path: Path to the testcase

    @rtype: String
    @return: Path to the archive containing the original and transformed testcase
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

    return archive_path


def setup_firefox(bin_path, prefs_path, ext_paths, test_path):
    ffp = FFPuppet(use_xvfb=True)

    # For now we support only one extension, but FFPuppet will handle
    # multiple extensions soon.
    ext_path = None
    if ext_paths:
        ext_path = ext_paths[0]

    ffp.profile = ffp.create_profile(extension=ext_path, prefs_js=prefs_path)

    env = ffp.get_environ(bin_path)
    cmd = ffp.build_launch_cmd(bin_path, additional_args=[test_path])

    try:
        # Remove any custom ASan options passed by FFPuppet as they might
        # interfere with AFL. This should be removed once we can ensure
        # that options passed by FFPuppet work with AFL.
        del env["ASAN_OPTIONS"]
    except KeyError:
        pass

    return (ffp, cmd, env)


def test_binary_asan(bin_path):
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


def warn_local(opts):
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


def write_stats_file(outfile, fields, stats, warnings):
    """
    Write the given stats data to the specified file

    @type outfile: str
    @param outfile: Output file for statistics

    @type fields: list
    @param fields: The list of fields to write out (defines the order as well)

    @type stats: dict
    @param stats: The dictionary containing the actual data

    @type warnings: list
    @param warnings: Any textual warnings to write in addition to stats
    """

    max_keylen = max(len(x) for x in fields)

    with InterProcessLock(outfile + ".lock"), open(
        outfile, "w", encoding="utf-8"
    ) as out_fp:
        for field in fields:
            if field not in stats:
                continue

            val = stats[field]

            if isinstance(val, list):
                val = " ".join(val)

            out_fp.write(f"{field}{' ' * (max_keylen + 1 - len(field))}: {val}\n")

        for warning in warnings:
            out_fp.write(warning)
