import subprocess


def nyx_main(opts, _collector, _s3m):
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
