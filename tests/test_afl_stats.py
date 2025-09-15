# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from guided_fuzzing_daemon.afl import AFLStats


def test_afl_stats_01(mocker, tmp_path):
    """afl stats calculation (positive)"""
    (tmp_path / "0").mkdir()
    (tmp_path / "0" / "fuzzer_stats").touch()
    mocker.patch.object(AFLStats, "add_sys_stats")
    stats = AFLStats(2)
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0"])
    assert not (tmp_path / "stats").exists()
    (tmp_path / "0" / "fuzzer_stats").write_text(
        "execs_done        : 77617\n"
        "execs_per_sec     : 22.64\n"
        "pending_favs      : 12\n"
        "pending_total     : 21\n"
        "corpus_variable   : 13\n"
        "saved_crashes     : 7\n"
        "saved_hangs       : 4\n"
        "exec_timeout      : 20000\n"
        "cycles_done       : 3\n"
        "bitmap_cvg        : 0.13%\n"
        "last_find         : 1696207996\n"
    )
    (tmp_path / "1").mkdir()
    (tmp_path / "1" / "fuzzer_stats").write_text(
        "execs_done        : 77617\n"
        "execs_per_sec     : 22.64\n"
        "pending_favs      : 24\n"
        "pending_total     : 21\n"
        "corpus_variable   : 13\n"
        "saved_crashes     : 1\n"
        "saved_hangs       : 9\n"
        "exec_timeout      : 30000\n"
        "cycles_done       : 1\n"
        "bitmap_cvg        : 0.04%\n"
        "last_find         : 1726207996\n"
        "random_crap       : who cares\n"
    )
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0", tmp_path / "1"])
    stat_lines = dict(
        map(str.strip, line.split(":", 1))
        for line in (tmp_path / "stats").read_text().splitlines()
    )
    assert stat_lines == {
        "execs_done": "155234 total (77617-77617 min/max)",
        "execs_per_sec": "45.28 total (22.64-22.64 min/max)",
        "pending_favs": "36",
        "pending_total": "42",
        "corpus_variable": "26",
        "saved_crashes": "8",
        "saved_hangs": "13",
        "stability": "0 total (nan-nan min/max)",
        "exec_timeout": "25000",
        "cycles_done": "1 (1×), 3 (1×)",  # noqa: RUF001
        "bitmap_cvg": "0.09% avg (0.04%-0.13% min/max)",
        "last_find": "2024-09-13T06:13:16Z",
        "instances": "0/2",
    }


def test_afl_stats_02(mocker, tmp_path):
    """afl stats calculation (negative)"""
    (tmp_path / "0").mkdir()
    (tmp_path / "0" / "fuzzer_stats").touch()
    mocker.patch.object(AFLStats, "add_sys_stats")
    stats = AFLStats(1)
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0"])
    assert not (tmp_path / "stats").exists()
    (tmp_path / "0" / "fuzzer_stats").write_text(
        "execs_done        : 7.76.17\n"
        "execs_per_sec     : 22.64\n"
        "bad data doesn't break parsing\n"
        "pending_favs      : 12\n"
        "pending_total     : 21\n"
        "corpus_variable   : 13\n"
        "saved_crashes     : 7\n"
        "saved_hangs       : 4\n"
        "stability         : 0 total (nan-nan min/max)\n"
        "cycles_done       : 3\n"
        "bitmap_cvg        : 0.13%\n"
        "last_find         : 1696207996\n"
    )
    stats.update_and_write(tmp_path / "stats", [tmp_path / "0"])
    stat_lines = dict(
        map(str.strip, line.split(":", 1))
        for line in (tmp_path / "stats").read_text().splitlines()
    )
    assert stat_lines == {
        "execs_done": "0 total (nan-nan min/max)",
        "execs_per_sec": "22.64 total (22.64-22.64 min/max)",
        "pending_favs": "12",
        "pending_total": "21",
        "corpus_variable": "13",
        "saved_crashes": "7",
        "saved_hangs": "4",
        "stability": "0 total (nan-nan min/max)",
        "exec_timeout": "nan",
        "cycles_done": "3 (1×)",  # noqa: RUF001
        "bitmap_cvg": "0.13% avg (0.13%-0.13% min/max)",
        "last_find": "2023-10-02T00:53:16Z",
        "instances": "0/1",
    }
