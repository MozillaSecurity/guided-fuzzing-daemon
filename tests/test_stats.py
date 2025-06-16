# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from collections import namedtuple
from math import isnan

import pytest

# from guided_fuzzing_daemon import stats as gfd_stats
from guided_fuzzing_daemon.stats import (
    Field,
    GeneratedField,
    JoinField,
    ListField,
    MaxField,
    MaxTimeField,
    MeanField,
    MeanMinMaxField,
    MinField,
    MinMaxField,
    StatAggregator,
    SumField,
    SumMinMaxField,
    ValueCounterField,
)


@pytest.mark.parametrize("loadavg", (True, False))
def test_stats_agg(loadavg, mocker, tmp_path):
    """aggregator formats multiple fields"""
    mocker.patch("guided_fuzzing_daemon.stats.InterProcessLock", autospec=True)
    mocker.patch("guided_fuzzing_daemon.stats.CPUField", autospec=True)
    mocker.patch("guided_fuzzing_daemon.stats.MemoryField", autospec=True)
    mocker.patch("guided_fuzzing_daemon.stats.DiskField", autospec=True)
    mocker.patch("guided_fuzzing_daemon.stats.TimeField", autospec=True)
    mocker.patch("guided_fuzzing_daemon.stats.HAVE_GETLOADAVG", loadavg)
    agg = StatAggregator()
    agg.add_field("a", mocker.Mock(__str__=lambda _: "blah", spec=Field, hidden=False))
    agg.add_field("b", mocker.Mock(spec=Field, hidden=True))
    agg.add_field("z", mocker.Mock(__str__=lambda _: "blzh", spec=Field, hidden=False))
    with pytest.raises(AssertionError):
        agg.add_field("a", mocker.Mock(spec=Field))
    agg.reset()
    for field in agg.fields.values():
        assert field.reset.call_count == 1
    agg.write_file(tmp_path / "stats.txt", ())
    assert (tmp_path / "stats.txt").read_text() == ("a : blah\nz : blzh\n")
    agg.write_file(tmp_path / "stats.txt", ["warning 1\n", "warning 2\n"])
    assert (tmp_path / "stats.txt").read_text() == (
        "a : blah\nz : blzh\nwarning 1\nwarning 2\n"
    )
    agg.add_field(
        "long field", mocker.Mock(__str__=lambda _: "bllh", spec=Field, hidden=False)
    )
    agg.write_file(tmp_path / "stats.txt", ())
    assert (tmp_path / "stats.txt").read_text() == (
        "a          : blah\nz          : blzh\nlong field : bllh\n"
    )
    agg.add_sys_stats()
    expected = (
        "a          : blah\n"
        "z          : blzh\n"
        "long field : bllh\n"
        "cpu        : cpuval\n"
        "memory     : memoryval\n"
        "disk       : diskval\n"
        "updated    : updatedval\n"
    )
    fields = ["memory", "disk", "updated"]
    if loadavg:
        expected = expected.replace("cpu     ", "cpu/load")
        expected = expected.replace(": cpu", ": cpu/load")
        fields.append("cpu/load")
    else:
        fields.append("cpu")
    for field in fields:

        def make_field_ret(_field):
            return lambda _: f"{_field}val"

        agg.fields[field].__str__ = make_field_ret(field)
        agg.fields[field].hidden = False
    agg.write_file(tmp_path / "stats.txt", ())
    assert (tmp_path / "stats.txt").read_text() == expected


def test_stats_sys(mocker, tmp_path):
    """system stats"""
    DiskUsage = namedtuple("disk_usage", ("free", "total"))
    VirtualMemory = namedtuple("virtual_memory", ["available", "total"])
    mocker.patch("guided_fuzzing_daemon.stats.InterProcessLock", autospec=True)
    mocker.patch("guided_fuzzing_daemon.stats.cpu_count", return_value=7)
    mocker.patch("guided_fuzzing_daemon.stats.time", return_value=1000)
    mocker.patch(
        "guided_fuzzing_daemon.stats.disk_usage",
        return_value=DiskUsage(24 * 2**30, 30 * 2**30),
    )
    mocker.patch("guided_fuzzing_daemon.stats.cpu_percent", return_value=24.0)
    mocker.patch(
        "guided_fuzzing_daemon.stats.getloadavg", return_value=(1.0, 7.3, 53.1)
    )
    mocker.patch(
        "guided_fuzzing_daemon.stats.virtual_memory",
        return_value=VirtualMemory(7 * 2**30, 14 * 2**30),
    )
    mocker.patch("guided_fuzzing_daemon.stats.HAVE_GETLOADAVG", None)
    agg = StatAggregator()
    agg.add_sys_stats()
    agg.write_file(tmp_path / "stats.txt", ())
    assert (tmp_path / "stats.txt").read_text() == (
        "cpu     : 7 (7) @ 24%\n"
        "memory  : 7.0GB of 14.0GB free\n"
        "disk    : 24.0GB of 30.0GB free\n"
        "updated : 1970-01-01T00:16:40Z\n"
    )

    mocker.patch(
        "guided_fuzzing_daemon.stats.disk_usage",
        return_value=DiskUsage(24 * 2**20, 30 * 2**30),
    )
    mocker.patch(
        "guided_fuzzing_daemon.stats.virtual_memory",
        return_value=VirtualMemory(7 * 2**20, 14 * 2**30),
    )
    mocker.patch("guided_fuzzing_daemon.stats.HAVE_GETLOADAVG", True)
    agg = StatAggregator()
    agg.add_sys_stats()
    agg.write_file(tmp_path / "stats.txt", ())
    expected = (
        "cpu/load : 7 (7) @ 24% (1.0, 7.3, 53.1)\n"
        "memory   : 7MB of 14.0GB free\n"
        "disk     : 24MB of 30.0GB free\n"
        "updated  : 1970-01-01T00:16:40Z\n"
    )
    assert (tmp_path / "stats.txt").read_text() == expected

    agg.reset()
    assert (tmp_path / "stats.txt").read_text() == expected
    for field in agg.fields.values():
        assert field.generated


@pytest.mark.parametrize(
    "field, inp, result",
    (
        (MinField, (1, 2, 3), (1, 1, 1)),
        (SumField, (1, 2, 3), (1, 3, 6)),
        (MaxField, (1, 2, 3), (1, 2, 3)),
        (MeanField, (1, 2, 3), (1, 1.5, 2)),
        (MinField, (2, 1.5), (2, 1.5)),
        (SumField, (1.5, 2.1), (1.5, 3.6)),
        (MaxField, (1, 2.5), (1, 2.5)),
        (MeanField, (2, 3), (2, 2.5)),
    ),
)
@pytest.mark.parametrize("suffix", ("", "%"))
def test_stats_math(field, inp, result, suffix):
    """math fields work as expected (min/max/sum)"""
    obj = field(suffix=suffix)
    for val, res in zip(inp, result):
        obj.update(val)
        assert obj.value == res
        if isinstance(obj.value, int) or obj.value.is_integer():
            assert str(obj) == f"{int(res)}{suffix}"
        else:
            assert str(obj) == f"{res:.2f}{suffix}"
    assert not obj.generated


def test_stats_sum_base():
    """sum field supports a base value to survive reset"""
    obj = SumField()
    obj.add_to_base(7)
    assert obj.value == 7
    obj.update(1)
    assert obj.value == 8
    obj.reset()
    assert obj.value == 7
    obj.add_to_base(1)
    assert obj.value == 8
    obj.update(1)
    assert obj.value == 9
    obj.reset()
    assert obj.value == 8


@pytest.mark.parametrize(
    "field, reset, result, value",
    (
        (MinMaxField, "nan{}-nan{} min/max", "1{}-3{} min/max", -1),
        (
            MeanMinMaxField,
            "nan{} avg (nan{}-nan{} min/max)",
            "2{} avg (1{}-3{} min/max)",
            2,
        ),
        (
            SumMinMaxField,
            "0{} total (nan{}-nan{} min/max)",
            "6{} total (1{}-3{} min/max)",
            6,
        ),
    ),
)
@pytest.mark.parametrize("suffix", ("", "%"))
def test_stats_minmax(field, reset, result, suffix, value):
    """*minmax track their value and min-max range too"""
    obj = field(suffix=suffix)
    for val in (1, 2, 3):
        obj.update(val)
    assert str(obj) == result.replace("{}", suffix)
    assert obj.value == value
    obj.reset()
    assert str(obj) == reset.replace("{}", suffix)
    assert not obj.generated


@pytest.mark.parametrize("field", (MinField, MaxField, MeanField))
def test_stats_nan(field):
    """math fields default to nan"""
    obj = field()
    assert isnan(obj.value)
    obj.update(1)
    assert obj.value == 1
    obj.reset()
    assert isnan(obj.value)
    obj.update(2)
    assert obj.value == 2
    obj.reset()
    obj.update(1)
    assert obj.value == 1


def test_stats_join():
    """join field joins sub-fields (comma sep)"""
    pt1 = MinField()
    pt2 = MinField()
    obj = JoinField((pt1, pt2))
    pt1.update(1)
    pt2.update(7)
    assert str(obj) == f"{pt1}, {pt2}"
    assert obj.value == -1
    obj.reset()
    assert str(obj) == "nan, nan"
    assert obj.generated


def test_stats_list():
    """list field outputs a list of str values passed to it (space sep)"""
    obj = ListField()
    obj.update("a")
    obj.update("b")
    obj.update("c")
    assert str(obj) == "a b c"
    obj.reset()
    assert str(obj) == ""
    assert not obj.generated
    assert obj.value == -1


@pytest.mark.parametrize("ignore_reset", (True, False))
def test_stats_maxtime(ignore_reset):
    """maxtime is a max timestamp output in ISO format"""
    obj = MaxTimeField(ignore_reset=ignore_reset)
    assert str(obj) == "never"
    obj.update(0)
    assert str(obj) == "1970-01-01T00:00:00Z"
    obj.update(1000)
    assert str(obj) == "1970-01-01T00:16:40Z"
    obj.update(0)
    assert str(obj) == "1970-01-01T00:16:40Z"
    obj.reset()
    if ignore_reset:
        assert str(obj) == "1970-01-01T00:16:40Z"
    else:
        assert str(obj) == "never"


@pytest.mark.parametrize("ignore_reset", (True, False))
@pytest.mark.parametrize("suffix", ("", "%"))
def test_stats_generated(ignore_reset, suffix):
    """generated field is a manual counter"""
    obj = GeneratedField(ignore_reset=ignore_reset, suffix=suffix)
    assert obj.value == 0
    obj += 1
    assert obj.value == 1
    obj -= 1
    assert obj.value == 0
    obj.update(7)
    assert obj.value == 7
    obj -= 1
    assert obj.value == 6
    assert str(obj) == f"6{suffix}"
    obj.reset()
    if ignore_reset:
        assert obj.value == 6
    else:
        assert obj.value == 0


def test_stats_value_count():
    """value counter field counts values passed to it"""
    obj = ValueCounterField()
    obj.update(1)
    obj.update(1)
    obj.update(6)
    obj.update(1)
    assert str(obj) == "1 (3×), 6 (1×)"  # noqa: RUF001
    assert obj.value == -1
    obj.reset()
    assert str(obj) == ""
