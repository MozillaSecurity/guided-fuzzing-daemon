# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABC, abstractmethod
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from fasteners import InterProcessLock
from psutil import cpu_count, cpu_percent, disk_usage, virtual_memory

HAVE_GETLOADAVG = True
try:
    from os import getloadavg
except ImportError:  # pragma: no cover
    # os.getloadavg() is not available on all platforms
    HAVE_GETLOADAVG = False

CPU_POLL_INTERVAL = 1


class Field(ABC):
    __slots__ = ("_hidden", "_generated", "_suffix")

    def __init__(
        self, hidden: bool = False, generated: bool = False, suffix: str = ""
    ) -> None:
        self._hidden = hidden
        self._generated = generated
        self._suffix = suffix

    @property
    @abstractmethod
    def value(self) -> Union[float, int]:
        pass

    @property
    def hidden(self) -> bool:
        return self._hidden

    @property
    def generated(self) -> bool:
        return self._generated

    def update(self, _value: Any) -> None:
        raise NotImplementedError()

    def reset(self) -> None:
        pass

    def __str__(self) -> str:
        val = self.value
        if isinstance(val, float):
            if val.is_integer():
                val = int(val)
            else:
                return f"{val:.2f}{self._suffix}"
        return f"{val}{self._suffix}"


class GeneratedField(Field):
    __slots__ = ("_value",)

    def __init__(self, hidden: bool = False, suffix: str = "") -> None:
        super().__init__(hidden=hidden, generated=True, suffix=suffix)
        self._value: int = 0

    def __iadd__(self, value: int) -> "GeneratedField":
        self._value += value
        return self

    def __isub__(self, value: int) -> "GeneratedField":
        self._value -= value
        return self

    def update(self, value: int) -> None:
        self._value = value

    @property
    def value(self) -> int:
        return self._value


class ListField(Field):
    __slots__ = ("_values",)

    def __init__(self) -> None:
        super().__init__()
        self._values: List[str] = []

    @property
    def value(self) -> int:
        return -1

    def update(self, value: str) -> None:
        self._values.append(value)

    def __str__(self) -> str:
        return " ".join(self._values)

    def reset(self) -> None:
        self._values.clear()


class ValueCounterField(Field):
    __slots__ = ("_values",)

    def __init__(self) -> None:
        super().__init__()
        self._values: Dict[Any, int] = {}

    @property
    def value(self) -> int:
        return -1

    def update(self, value: Any) -> None:
        self._values.setdefault(value, 0)
        self._values[value] += 1

    def __str__(self) -> str:
        values = []
        for value, count in sorted(self._values.items()):
            values.append(f"{value} ({count}×)")  # noqa: RUF001
        return ", ".join(values)

    def reset(self) -> None:
        self._values.clear()


class JoinField(Field):
    __slots__ = ("_fields",)

    def __init__(self, fields: Iterable[Field]) -> None:
        super().__init__(generated=True)
        self._fields: Tuple[Field, ...] = tuple(fields)

    @property
    def value(self) -> int:
        return -1

    def __str__(self) -> str:
        return ", ".join(str(field) for field in self._fields)


class SumField(Field):
    __slots__ = ("_base", "_total")

    def __init__(self, suffix: str = "") -> None:
        super().__init__(suffix=suffix)
        self._base = 0
        self._total = 0

    @property
    def value(self) -> int:
        return self._total

    def add_to_base(self, value: int) -> None:
        self._base += value

    def update(self, value: int) -> None:
        self._total += value

    def reset(self) -> None:
        super().reset()
        self._total = self._base


class MeanField(Field):
    __slots__ = ("_sum", "_count")

    def __init__(self, suffix: str = "") -> None:
        super().__init__(suffix=suffix)
        self._sum = SumField()
        self._count = 0

    @property
    def value(self) -> float:
        if not self._count:
            return float("nan")
        return self._sum.value / self._count

    def update(self, value: int) -> None:
        self._sum.update(value)
        self._count += 1

    def reset(self) -> None:
        super().reset()
        self._sum.reset()
        self._count = 0


class MaxField(Field):
    __slots__ = ("_value", "_ignore_reset")

    def __init__(self, ignore_reset: bool = False, suffix: str = "") -> None:
        super().__init__(suffix=suffix)
        self._value: Optional[int] = None
        self._ignore_reset = ignore_reset

    @property
    def value(self) -> Union[float, int]:
        if self._value is None:
            return float("nan")
        return self._value

    def update(self, value: int) -> None:
        if self._value is None:
            self._value = value
        else:
            self._value = max(self._value, value)

    def reset(self) -> None:
        super().reset()
        if not self._ignore_reset:
            self._value = None


class MaxTimeField(Field):
    __slots__ = ("_max",)

    def __init__(self, ignore_reset: bool = False) -> None:
        super().__init__()
        self._max = MaxField(ignore_reset)

    @property
    def value(self) -> Union[float, int]:
        return self._max.value

    def update(self, value: int) -> None:
        self._max.update(value)

    def __str__(self) -> str:
        return (
            datetime.fromtimestamp(self._max.value, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def reset(self) -> None:
        super().reset()
        self._max.reset()


class MinField(Field):
    __slots__ = ("_value",)

    def __init__(self, suffix: str = "") -> None:
        super().__init__(suffix=suffix)
        self._value: Optional[int] = None

    @property
    def value(self) -> Union[float, int]:
        if self._value is None:
            return float("nan")
        return self._value

    def update(self, value: int) -> None:
        if self._value is None:
            self._value = value
        else:
            self._value = min(self._value, value)

    def reset(self) -> None:
        super().reset()
        self._value = None


class MinMaxField(Field):
    __slots__ = ("_min", "_max")

    def __init__(self, suffix: str = "") -> None:
        super().__init__()
        self._min = MinField(suffix=suffix)
        self._max = MaxField(suffix=suffix)

    @property
    def value(self) -> int:
        return -1

    def update(self, value: int) -> None:
        self._min.update(value)
        self._max.update(value)

    def __str__(self) -> str:
        return f"{self._min}-{self._max} min/max"

    def reset(self) -> None:
        super().reset()
        self._min.reset()
        self._max.reset()


class SumMinMaxField(Field):
    __slots__ = ("_minmax", "_sum")

    def __init__(self) -> None:
        super().__init__()
        self._minmax = MinMaxField()
        self._sum = SumField()

    @property
    def value(self) -> int:
        return self._sum.value

    def update(self, value: int) -> None:
        self._minmax.update(value)
        self._sum.update(value)

    def __str__(self) -> str:
        return f"{self._sum} total ({self._minmax})"

    def reset(self) -> None:
        super().reset()
        self._minmax.reset()
        self._sum.reset()


class MeanMinMaxField(Field):
    __slots__ = ("_mean", "_minmax")

    def __init__(self, suffix: str = "") -> None:
        super().__init__()
        self._minmax = MinMaxField(suffix=suffix)
        self._mean = MeanField(suffix=suffix)

    @property
    def value(self) -> float:
        return self._mean.value

    def update(self, value: int) -> None:
        self._minmax.update(value)
        self._mean.update(value)

    def __str__(self) -> str:
        return f"{self._mean} avg ({self._minmax})"

    def reset(self) -> None:
        super().reset()
        self._minmax.reset()
        self._mean.reset()


class CPUField(Field):
    __slots__: Tuple[str, ...] = ()

    def __init__(self) -> None:
        super().__init__(generated=True)

    @property
    def value(self) -> int:
        return -1

    def __str__(self) -> str:
        # CPU and load
        disp = []
        disp.append(
            f"{cpu_count(logical=True)} ({cpu_count(logical=False)}) @ "
            f"{cpu_percent(interval=CPU_POLL_INTERVAL):0.0f}%"
        )
        if HAVE_GETLOADAVG is not None:
            disp.append(" (")
            # round the results of getloadavg(), precision varies across platforms
            disp.append(", ".join(f"{x:0.1f}" for x in getloadavg()))
            disp.append(")")
        return "".join(disp)


class MemoryField(Field):
    __slots__: Tuple[str, ...] = ()

    def __init__(self) -> None:
        super().__init__(generated=True)

    @property
    def value(self) -> int:
        return -1

    def __str__(self) -> str:
        # memory usage
        disp = []
        mem_usage = virtual_memory()
        if mem_usage.available < 1_073_741_824:  # < 1GB
            disp.append(f"{int(mem_usage.available / 1_048_576)}MB")
        else:
            disp.append(f"{mem_usage.available / 1_073_741_824:0.1f}GB")
        disp.append(f" of {mem_usage.total / 1_073_741_824:0.1f}GB free")
        return "".join(disp)


class DiskField(Field):
    __slots__: Tuple[str, ...] = ()

    def __init__(self) -> None:
        super().__init__(generated=True)

    @property
    def value(self) -> int:
        return -1

    def __str__(self) -> str:
        # disk usage
        disp = []
        usage = disk_usage("/")
        if usage.free < 1_073_741_824:  # < 1GB
            disp.append(f"{int(usage.free / 1_048_576)}MB")
        else:
            disp.append(f"{usage.free / 1_073_741_824:0.1f}GB")
        disp.append(f" of {usage.total / 1_073_741_824:0.1f}GB free")
        return "".join(disp)


class StatAggregator:
    __slots__ = ("fields",)

    def __init__(self) -> None:
        self.fields: "OrderedDict[str, Field]" = OrderedDict()

    def reset(self) -> None:
        for field in self.fields.values():
            field.reset()

    def add_field(self, name: str, field: Field) -> None:
        assert name not in self.fields
        self.fields[name] = field

    def add_sys_stats(self) -> None:
        self.add_field("cpu/load" if HAVE_GETLOADAVG else "cpu", CPUField())
        self.add_field("memory", MemoryField())
        self.add_field("disk", DiskField())

    def write_file(
        self,
        outfile: Path,
        warnings: Iterable[str],
    ) -> None:
        """Write the given stats data to the specified file

        Args:
            outfile: Output file for statistics
            warnings: Any textual warnings to write in addition to stats
        """
        max_keylen = max(
            len(name) for name, value in self.fields.items() if not value.hidden
        )

        with InterProcessLock(outfile.parent / f"{outfile.name}.lock"), open(
            outfile, "w", encoding="utf-8"
        ) as out_fp:
            for name, val in self.fields.items():
                if val.hidden:
                    continue

                out_fp.write(f"{name}{' ' * (max_keylen + 1 - len(name))}: {val}\n")

            for warning in warnings:
                out_fp.write(warning)
