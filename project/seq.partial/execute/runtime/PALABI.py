"""PAL architecture ABI runtime.

This module owns calling-convention state.  Numeric P-code semantics remain in
``PALhelpers.py``; PALABI only transports already-classified values between
physical ABI carriers, stack storage, TLS, and frozen ABI-D plans.

The executable emitter uses four narrow entry points:

``c_abi_context``
    Acquire the active invocation by function-entry plan id.
``c_abi_get``
    Read an ABI-D materialization from that invocation.
``c_abi_call``
    Execute a call-site plan using runtime values only.
``c_abi_return``
    Publish a return value to its declared physical carriers.

The standalone ``PALSysVAMD64CallFrame.build`` API is intentionally broader:
it classifies explicit harness values so tests and launchers can construct an
initial call.  Once PAL-emitted code is running, ``c_abi_call`` never repeats
that classification; it requires the frozen ``call_site_abi_plan``.
"""

from __future__ import annotations

import contextvars
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from PALhelpers import c_load, c_store


class PALABIError(RuntimeError):
    """Base class for deterministic PAL ABI failures."""


class PALABIValidationError(PALABIError):
    """An address, width, alignment, or value violates an ABI contract."""


class PALABIPlanError(PALABIError):
    """Frozen ABI metadata is absent, contradictory, or incomplete."""


class PALABIDispatchError(PALABIError):
    """A planned call has no registered runtime target."""


class PALABINoReturnViolation(PALABIError):
    """A function declared no-return returned to its caller."""


def _positive_width(width: Any, *, maximum: Optional[int] = None) -> int:
    try:
        value = int(width)
    except (TypeError, ValueError):
        raise PALABIValidationError("ABI width must be an integer: %r" % (width,))
    if value <= 0 or value % 8:
        raise PALABIValidationError(
            "ABI widths must be positive whole bytes: %r" % (width,)
        )
    if maximum is not None and value > maximum:
        raise PALABIValidationError(
            "ABI width %d exceeds carrier width %d" % (value, maximum)
        )
    return value


def _mask(width: int) -> int:
    return (1 << _positive_width(width)) - 1


def _bits(value: Any, width: int) -> int:
    if isinstance(value, bool):
        value = int(value)
    try:
        return int(value) & _mask(width)
    except (TypeError, ValueError):
        raise PALABIValidationError(
            "ABI bitvector value is not integral: %r" % (value,)
        )


def _align_up(value: int, alignment: int) -> int:
    alignment = int(alignment)
    if alignment <= 0 or alignment & (alignment - 1):
        raise PALABIValidationError(
            "ABI alignment must be a positive power of two: %r" % alignment
        )
    return (int(value) + alignment - 1) & -alignment


def _align_down(value: int, alignment: int) -> int:
    alignment = int(alignment)
    if alignment <= 0 or alignment & (alignment - 1):
        raise PALABIValidationError(
            "ABI alignment must be a positive power of two: %r" % alignment
        )
    return int(value) & -alignment


def _float_bits(value: float, width: int) -> int:
    width = _positive_width(width)
    if width == 32:
        return struct.unpack("<I", struct.pack("<f", float(value)))[0]
    if width == 64:
        return struct.unpack("<Q", struct.pack("<d", float(value)))[0]
    raise PALABIValidationError(
        "PAL SysV scalar floating carriers support 32 or 64 bits, got %d" % width
    )


def _bits_float(value: int, width: int) -> float:
    width = _positive_width(width)
    if width == 32:
        return struct.unpack("<f", struct.pack("<I", _bits(value, 32)))[0]
    if width == 64:
        return struct.unpack("<d", struct.pack("<Q", _bits(value, 64)))[0]
    raise PALABIValidationError(
        "PAL SysV scalar floating carriers support 32 or 64 bits, got %d" % width
    )


def _coerce_carrier_bits(value: Any, width: int, argument_class: str) -> int:
    width = _positive_width(width)
    if isinstance(value, float):
        if argument_class != "sse":
            raise PALABIValidationError(
                "Python float requires an explicit SSE argument contract"
            )
        return _float_bits(value, width)
    return _bits(value, width)


def _canonical_register(name: Any) -> str:
    text = str(name or "").upper()
    if text.endswith("_QA") or text.endswith("_QD"):
        text = text.rsplit("_", 1)[0]
    if text.startswith("ZMM") or text.startswith("YMM"):
        suffix = text[3:]
        if suffix.isdigit():
            return "XMM" + suffix
    return text


@dataclass(frozen=True)
class _PALArgument:
    value: Any
    argument_class: str
    width_bits: int
    parameter_region: str = "variadic"

    def __post_init__(self) -> None:
        if self.argument_class not in ("integer", "unknown_scalar", "sse"):
            raise PALABIValidationError(
                "unsupported scalar ABI class %r" % self.argument_class
            )
        maximum = 128 if self.argument_class == "sse" else 64
        _positive_width(self.width_bits, maximum=maximum)


class PALVariadicArguments:
    """Variadic argument builder and SysV ``va_list`` reader.

    Builder mode is used by launch harnesses.  Reader mode is returned by
    :meth:`from_frame` and advances the four in-memory ``__va_list_tag``
    fields exactly where generated code can observe them through shared MEM.
    """

    def __init__(self, records: Optional[Iterable[_PALArgument]] = None) -> None:
        self._records: List[_PALArgument] = list(records or [])
        self._frame: Optional[PALSysVAMD64CallFrame] = None

    @property
    def records(self) -> Tuple[_PALArgument, ...]:
        return tuple(self._records)

    def add_integer(self, value: Any, width: int = 64) -> "PALVariadicArguments":
        self._records.append(
            _PALArgument(value, "integer", _positive_width(width, maximum=64))
        )
        return self

    def add_float(self, value: Any, width: int = 64) -> "PALVariadicArguments":
        # C default argument promotions turn float varargs into double.  A
        # caller may still request width=32 explicitly for non-C harnesses.
        width = _positive_width(width, maximum=64)
        self._records.append(_PALArgument(value, "sse", width))
        return self

    def add_bits(
        self, value: Any, argument_class: str, width: int
    ) -> "PALVariadicArguments":
        self._records.append(
            _PALArgument(value, str(argument_class), _positive_width(width))
        )
        return self

    @classmethod
    def from_values(cls, *values: Any) -> "PALVariadicArguments":
        result = cls()
        for value in values:
            if isinstance(value, float):
                result.add_float(value, 64)
            else:
                result.add_integer(value, 64)
        return result

    @classmethod
    def from_frame(cls, frame: "PALSysVAMD64CallFrame") -> "PALVariadicArguments":
        result = cls()
        result._frame = frame
        return result

    def _bound_frame(self) -> "PALSysVAMD64CallFrame":
        if self._frame is None:
            raise PALABIValidationError(
                "va_arg reading requires PALVariadicArguments.from_frame(frame)"
            )
        return self._frame

    def next_integer(self, width: int = 64) -> int:
        frame = self._bound_frame()
        width = _positive_width(width, maximum=64)
        gp_offset = c_load(frame.memory, frame.va_list_address, 32)
        if gp_offset < PALRegisterSaveArea.GP_SIZE:
            address = frame.register_save_area.address + gp_offset
            c_store(frame.memory, frame.va_list_address, gp_offset + 8, 32)
        else:
            address = c_load(frame.memory, frame.va_list_address + 8, 64)
            step = max(8, width // 8)
            c_store(frame.memory, frame.va_list_address + 8, address + step, 64)
        return c_load(frame.memory, address, width)

    def next_float(self, width: int = 64) -> float:
        raw = self.next_float_bits(width)
        return _bits_float(raw, width)

    def next_float_bits(self, width: int = 64) -> int:
        frame = self._bound_frame()
        width = _positive_width(width, maximum=64)
        fp_offset = c_load(frame.memory, frame.va_list_address + 4, 32)
        if fp_offset < PALRegisterSaveArea.SIZE:
            address = frame.register_save_area.address + fp_offset
            c_store(frame.memory, frame.va_list_address + 4, fp_offset + 16, 32)
        else:
            address = c_load(frame.memory, frame.va_list_address + 8, 64)
            step = max(8, width // 8)
            c_store(frame.memory, frame.va_list_address + 8, address + step, 64)
        return c_load(frame.memory, address, width)


class PALRegisterSaveArea:
    """SysV AMD64 register-save area backed by the shared memory object."""

    GP_REGISTERS = ("RDI", "RSI", "RDX", "RCX", "R8", "R9")
    XMM_REGISTERS = tuple("XMM%d" % index for index in range(8))
    GP_SLOT_SIZE = 8
    XMM_SLOT_SIZE = 16
    GP_SIZE = 48
    FP_START = 48
    SIZE = 176

    def __init__(self, memory: Any, address: int) -> None:
        self.memory = memory
        self.address = int(address)
        if self.address % 16:
            raise PALABIValidationError(
                "SysV register-save area must be 16-byte aligned"
            )

    def materialize(self, registers: Mapping[str, int]) -> None:
        for index, register in enumerate(self.GP_REGISTERS):
            value = int(registers.get(register, 0))
            c_store(self.memory, self.address + index * 8, value, 64)
        for index, register in enumerate(self.XMM_REGISTERS):
            value = int(registers.get(register, 0))
            slot = self.address + self.FP_START + index * 16
            c_store(self.memory, slot, value, 64)
            c_store(self.memory, slot + 8, value >> 64, 64)

    def gp_address(self, index: int) -> int:
        if not 0 <= int(index) < len(self.GP_REGISTERS):
            raise PALABIValidationError("GP save-area index out of range")
        return self.address + int(index) * 8

    def xmm_address(self, index: int) -> int:
        if not 0 <= int(index) < len(self.XMM_REGISTERS):
            raise PALABIValidationError("XMM save-area index out of range")
        return self.address + self.FP_START + int(index) * 16

    def read_gp(self, index: int, width: int = 64) -> int:
        return c_load(self.memory, self.gp_address(index), _positive_width(width, maximum=64))

    def read_xmm(self, index: int, width: int = 64) -> int:
        return c_load(self.memory, self.xmm_address(index), _positive_width(width, maximum=128))


class PALThreadContext:
    """Shared memory, stack allocator, and TLS custody for one PAL thread."""

    def __init__(
        self,
        memory: Any,
        *,
        stack_top: int = 0x00007FFF00000000,
        tls_base: int = 0x0000700000000000,
        stack_canary: int = 0x50414C43414E4152,
        abi_arena_base: int = 0x0000600000000000,
    ) -> None:
        self.memory = memory
        self.stack_top = int(stack_top)
        self.tls_base = int(tls_base)
        self.stack_canary = _bits(stack_canary, 64)
        self.abi_arena_base = int(abi_arena_base)
        if self.stack_top % 16:
            raise PALABIValidationError("PAL call-site stack top must be 16-byte aligned")
        if self.tls_base % 8:
            raise PALABIValidationError("PAL TLS base must be 8-byte aligned")
        if self.abi_arena_base % 16:
            raise PALABIValidationError("PAL ABI arena must be 16-byte aligned")
        self._stack_cursor = self.stack_top
        self._abi_cursor = self.abi_arena_base
        c_store(self.memory, self.tls_base + 0x28, self.stack_canary, 64)

    def reserve_call_stack(self, overflow_size: int, frame_reserve: int = 0x1000) -> int:
        overflow_size = _align_up(max(0, int(overflow_size)), 8)
        minimum = overflow_size + 8 + 0x200
        frame_reserve = _align_up(max(int(frame_reserve), minimum), 16)
        high = self._stack_cursor
        low = high - frame_reserve
        # At SysV function entry, (RSP + 8) is 16-byte aligned because the
        # return address has just been pushed by CALL.
        entry_rsp = _align_down(high - overflow_size, 16) - 8
        if entry_rsp - low < 0x100:
            raise PALABIValidationError("reserved PAL stack slab is too small")
        self._stack_cursor = low
        c_store(self.memory, entry_rsp, 0, 64)  # synthetic return address
        return entry_rsp

    def allocate_abi_storage(self, size: int, alignment: int = 16) -> int:
        size = int(size)
        if size <= 0:
            raise PALABIValidationError("ABI storage allocation must be positive")
        address = _align_up(self._abi_cursor, alignment)
        self._abi_cursor = address + size
        return address

    @property
    def frame_base(self) -> int:
        return self._stack_cursor


class PALSysVAMD64CallFrame:
    """One SysV AMD64 invocation, materialized into registers and shared MEM."""

    BACKEND_NAME = "sysv_amd64"
    GP_REGISTERS = PALRegisterSaveArea.GP_REGISTERS
    XMM_REGISTERS = PALRegisterSaveArea.XMM_REGISTERS

    def __init__(
        self,
        thread: PALThreadContext,
        *,
        stack_pointer: int,
        registers: Mapping[str, int],
        al: int,
        overflow_stack_base: int,
        overflow_argument_area: int,
        register_save_area: PALRegisterSaveArea,
        va_list_address: int,
        entry_plan_id: Optional[str] = None,
        call_plan_id: Optional[str] = None,
    ) -> None:
        self.thread = thread
        self.memory = thread.memory
        self.stack_pointer = int(stack_pointer)
        self.frame_base = self.stack_pointer
        self.tls_base = thread.tls_base
        self.registers: Dict[str, int] = {
            _canonical_register(name): int(value)
            for name, value in dict(registers).items()
        }
        self.al = _bits(al, 8)
        self.overflow_stack_base = int(overflow_stack_base)
        self.overflow_argument_area = int(overflow_argument_area)
        self.register_save_area = register_save_area
        self.va_list_address = int(va_list_address)
        self.entry_plan_id = entry_plan_id
        self.call_plan_id = call_plan_id
        self.condition_flags: Dict[str, int] = {}
        self.machine_state: Dict[str, int] = {}
        self._write_al(self.al)
        self.validate()

    def _write_al(self, value: int) -> None:
        self.al = _bits(value, 8)
        rax = _bits(self.registers.get("RAX", 0), 64)
        self.registers["RAX"] = (rax & ~0xFF) | self.al
        self.registers["AL"] = self.al

    def validate(self) -> None:
        if (self.stack_pointer + 8) % 16:
            raise PALABIValidationError(
                "SysV entry RSP must satisfy (RSP + 8) %% 16 == 0"
            )
        if self.register_save_area.address % 16:
            raise PALABIValidationError("register-save area is misaligned")
        if self.va_list_address % 8:
            raise PALABIValidationError("va_list must be 8-byte aligned")
        if not 0 <= self.al <= 8:
            raise PALABIValidationError("SysV variadic AL must be in [0, 8]")
        for register in self.GP_REGISTERS:
            if register in self.registers:
                _bits(self.registers[register], 64)
        for register in self.XMM_REGISTERS:
            if register in self.registers:
                _bits(self.registers[register], 128)

    def get_register(self, name: Any, width: Optional[int] = None) -> int:
        canonical = _canonical_register(name)
        if canonical == "AL":
            value = self.al
            default_width = 8
        else:
            if canonical not in self.registers:
                raise PALABIValidationError(
                    "ABI register %r is absent from this call frame" % name
                )
            value = self.registers[canonical]
            default_width = 128 if canonical.startswith("XMM") else 64
        effective_width = default_width if width is None else _positive_width(
            width, maximum=default_width
        )
        return _bits(value, effective_width)

    def set_register(self, name: Any, value: Any, width: Optional[int] = None) -> None:
        canonical = _canonical_register(name)
        if canonical == "AL":
            self._write_al(_bits(value, 8))
            return
        maximum = 128 if canonical.startswith("XMM") else 64
        effective_width = maximum if width is None else _positive_width(width, maximum=maximum)
        self.registers[canonical] = _bits(value, effective_width)

    @staticmethod
    def _harness_argument(value: Any, region: str) -> _PALArgument:
        if isinstance(value, _PALArgument):
            return _PALArgument(
                value.value, value.argument_class, value.width_bits, region
            )
        if isinstance(value, Mapping):
            argument_class = str(value.get("argument_class") or "integer")
            width = value.get("width_bits") or (64 if argument_class != "sse" else 64)
            return _PALArgument(value.get("value"), argument_class, int(width), region)
        if isinstance(value, float):
            return _PALArgument(value, "sse", 64, region)
        return _PALArgument(value, "integer", 64, region)

    @classmethod
    def build(
        cls,
        thread: PALThreadContext,
        *,
        fixed_arguments: Sequence[Any] = (),
        variadic_arguments: Optional[PALVariadicArguments] = None,
        variadic: bool = False,
        entry_plan_id: Optional[str] = None,
        frame_reserve: int = 0x1000,
    ) -> "PALSysVAMD64CallFrame":
        """Build an initial harness frame using explicit scalar values.

        This is the only PALABI surface that performs scalar classification.
        Emitted calls use :meth:`from_call_plan` instead.
        """

        records = [cls._harness_argument(value, "fixed") for value in fixed_arguments]
        if variadic_arguments is not None:
            records.extend(
                _PALArgument(
                    item.value, item.argument_class, item.width_bits, "variadic"
                )
                for item in variadic_arguments.records
            )
            variadic = True

        gp_index = 0
        xmm_index = 0
        stack_slot = 0
        placements: List[Dict[str, Any]] = []
        for index, record in enumerate(records):
            placement: Dict[str, Any] = {
                "index": index,
                "record": record,
                "parameter_region": record.parameter_region,
            }
            if record.argument_class == "sse" and xmm_index < len(cls.XMM_REGISTERS):
                placement.update(carrier_kind="xmm_register", carrier=cls.XMM_REGISTERS[xmm_index])
                xmm_index += 1
            elif record.argument_class in ("integer", "unknown_scalar") and gp_index < len(cls.GP_REGISTERS):
                placement.update(carrier_kind="gp_register", carrier=cls.GP_REGISTERS[gp_index])
                gp_index += 1
            else:
                placement.update(
                    carrier_kind="stack_overflow_argument",
                    carrier="stack+%d" % (stack_slot * 8),
                    stack_slot=stack_slot,
                )
                stack_slot += max(1, _align_up(record.width_bits // 8, 8) // 8)
            placements.append(placement)

        al = xmm_index if variadic else 0
        return cls._materialize(
            thread,
            placements,
            al=al,
            entry_plan_id=entry_plan_id,
            call_plan_id=None,
            frame_reserve=frame_reserve,
        )

    @classmethod
    def from_call_plan(
        cls,
        thread: PALThreadContext,
        plan: Mapping[str, Any],
        values: Sequence[Any],
        *,
        entry_plan_id: Optional[str] = None,
        frame_reserve: int = 0x1000,
    ) -> "PALSysVAMD64CallFrame":
        """Materialize runtime values according to an authoritative ABI-D plan."""

        plan = dict(plan or {})
        if plan.get("plan_class") != "call_site_abi_plan":
            raise PALABIPlanError("c_abi_call requires a call_site_abi_plan")
        backend = dict(plan.get("abi_backend") or {})
        if backend.get("name") not in (None, "", cls.BACKEND_NAME):
            raise PALABIPlanError(
                "call plan backend %r is not SysV AMD64" % backend.get("name")
            )
        if plan.get("downstream_reinference_allowed") is not False:
            raise PALABIPlanError(
                "call plan must explicitly forbid downstream carrier reinference"
            )
        arguments = sorted(
            [dict(item) for item in list(plan.get("arguments") or [])],
            key=lambda item: (
                item.get("index") is None,
                item.get("index") if isinstance(item.get("index"), int) else 0,
            ),
        )
        if len(arguments) != len(values):
            raise PALABIPlanError(
                "call plan/value arity mismatch: %d planned, %d supplied"
                % (len(arguments), len(values))
            )

        target = dict(plan.get("target") or {})
        fixed_count = target.get("fixed_parameter_count")
        placements: List[Dict[str, Any]] = []
        for fallback_index, (argument, value) in enumerate(zip(arguments, values)):
            index = argument.get("index")
            if not isinstance(index, int):
                index = fallback_index
            carrier_kind = argument.get("carrier_kind")
            if carrier_kind not in (
                "gp_register", "xmm_register", "stack_overflow_argument"
            ):
                raise PALABIPlanError(
                    "argument %d has no executable carrier: %r"
                    % (index, carrier_kind)
                )
            argument_class = str(argument.get("argument_class") or "unknown_scalar")
            width = argument.get("source_width_bits") or 64
            region = argument.get("parameter_region")
            if region not in ("fixed", "variadic"):
                if isinstance(fixed_count, int):
                    region = "fixed" if index < fixed_count else "variadic"
                else:
                    region = "unspecified"
            record = _PALArgument(value, argument_class, int(width), region)
            placement = dict(argument)
            placement.update(index=index, record=record, parameter_region=region)
            placements.append(placement)

        al_contract = dict(plan.get("caller_variadic_al") or {})
        al = al_contract.get("value")
        if al_contract.get("required") is True and al is None:
            raise PALABIPlanError("variadic call plan does not provide authoritative AL")
        if al is None:
            al = 0
        return cls._materialize(
            thread,
            placements,
            al=int(al),
            entry_plan_id=entry_plan_id,
            call_plan_id=plan.get("plan_id"),
            frame_reserve=frame_reserve,
        )

    @classmethod
    def _materialize(
        cls,
        thread: PALThreadContext,
        placements: Sequence[Mapping[str, Any]],
        *,
        al: int,
        entry_plan_id: Optional[str],
        call_plan_id: Optional[str],
        frame_reserve: int,
    ) -> "PALSysVAMD64CallFrame":
        max_stack_end = 0
        for placement in placements:
            if placement.get("carrier_kind") != "stack_overflow_argument":
                continue
            record = placement.get("record")
            slot = placement.get("stack_slot")
            if not isinstance(slot, int) or slot < 0:
                raise PALABIPlanError("stack argument requires a non-negative stack_slot")
            size = _align_up(record.width_bits // 8, 8)
            max_stack_end = max(max_stack_end, slot * 8 + size)

        stack_pointer = thread.reserve_call_stack(max_stack_end, frame_reserve)
        overflow_stack_base = stack_pointer + 8
        registers: Dict[str, int] = {}
        fixed_gp = 0
        fixed_xmm = 0
        fixed_stack_end = 0

        for placement in placements:
            record: _PALArgument = placement["record"]
            kind = placement.get("carrier_kind")
            value = _coerce_carrier_bits(
                record.value, record.width_bits, record.argument_class
            )
            if kind == "gp_register":
                register = _canonical_register(placement.get("carrier"))
                if register not in cls.GP_REGISTERS:
                    raise PALABIPlanError("invalid SysV GP carrier %r" % register)
                registers[register] = _bits(value, 64)
                if placement.get("parameter_region") == "fixed":
                    fixed_gp += 1
            elif kind == "xmm_register":
                register = _canonical_register(placement.get("carrier"))
                if register not in cls.XMM_REGISTERS:
                    raise PALABIPlanError("invalid SysV XMM carrier %r" % register)
                registers[register] = _bits(value, 128)
                if placement.get("parameter_region") == "fixed":
                    fixed_xmm += 1
            elif kind == "stack_overflow_argument":
                slot = int(placement.get("stack_slot"))
                address = overflow_stack_base + slot * 8
                c_store(thread.memory, address, value, record.width_bits)
                if placement.get("parameter_region") == "fixed":
                    fixed_stack_end = max(
                        fixed_stack_end,
                        slot * 8 + _align_up(record.width_bits // 8, 8),
                    )
            else:
                raise PALABIPlanError("unsupported carrier kind %r" % kind)

        rsa_address = thread.allocate_abi_storage(PALRegisterSaveArea.SIZE, 16)
        rsa = PALRegisterSaveArea(thread.memory, rsa_address)
        rsa.materialize(registers)
        va_list_address = thread.allocate_abi_storage(24, 8)
        overflow_argument_area = overflow_stack_base + fixed_stack_end
        gp_offset = min(fixed_gp * 8, PALRegisterSaveArea.GP_SIZE)
        fp_offset = min(
            PALRegisterSaveArea.FP_START + fixed_xmm * 16,
            PALRegisterSaveArea.SIZE,
        )
        c_store(thread.memory, va_list_address, gp_offset, 32)
        c_store(thread.memory, va_list_address + 4, fp_offset, 32)
        c_store(thread.memory, va_list_address + 8, overflow_argument_area, 64)
        c_store(thread.memory, va_list_address + 16, rsa.address, 64)

        return cls(
            thread,
            stack_pointer=stack_pointer,
            registers=registers,
            al=al,
            overflow_stack_base=overflow_stack_base,
            overflow_argument_area=overflow_argument_area,
            register_save_area=rsa,
            va_list_address=va_list_address,
            entry_plan_id=entry_plan_id,
            call_plan_id=call_plan_id,
        )


class PALCallContext:
    """Architecture-neutral invocation and frozen-plan registry."""

    BACKENDS: Dict[str, Any] = {
        PALSysVAMD64CallFrame.BACKEND_NAME: PALSysVAMD64CallFrame,
    }

    def __init__(
        self,
        thread: PALThreadContext,
        frame: PALSysVAMD64CallFrame,
        *,
        entry_plan_id: Optional[str] = None,
        entry_plans: Optional[Mapping[str, Mapping[str, Any]]] = None,
        call_plans: Optional[Mapping[str, Mapping[str, Any]]] = None,
        internal_functions: Optional[Mapping[str, Callable[..., Any]]] = None,
        external_functions: Optional[Mapping[str, Callable[..., Any]]] = None,
        parent: Optional["PALCallContext"] = None,
    ) -> None:
        self.thread = thread
        self.memory = thread.memory
        self.frame = frame
        self.entry_plan_id = entry_plan_id or frame.entry_plan_id
        self.entry_plans: Dict[str, Dict[str, Any]] = {
            str(key): dict(value) for key, value in dict(entry_plans or {}).items()
        }
        self.call_plans: Dict[str, Dict[str, Any]] = {
            str(key): dict(value) for key, value in dict(call_plans or {}).items()
        }
        self.internal_functions: Dict[str, Callable[..., Any]] = dict(internal_functions or {})
        self.external_functions: Dict[str, Callable[..., Any]] = dict(external_functions or {})
        self.parent = parent
        self.return_value: Optional[int] = None
        self.return_carriers: Tuple[Tuple[Any, ...], ...] = ()

    @classmethod
    def register_backend(cls, name: str, frame_type: Any) -> None:
        if not name or not hasattr(frame_type, "from_call_plan"):
            raise PALABIValidationError("ABI backend must expose from_call_plan")
        cls.BACKENDS[str(name)] = frame_type

    @classmethod
    def for_sysv_amd64(
        cls,
        memory: Any,
        *,
        fixed_arguments: Sequence[Any] = (),
        variadic_arguments: Optional[PALVariadicArguments] = None,
        variadic: bool = False,
        entry_plan_id: Optional[str] = None,
        entry_plans: Optional[Mapping[str, Mapping[str, Any]]] = None,
        call_plans: Optional[Mapping[str, Mapping[str, Any]]] = None,
        internal_functions: Optional[Mapping[str, Callable[..., Any]]] = None,
        external_functions: Optional[Mapping[str, Callable[..., Any]]] = None,
        thread: Optional[PALThreadContext] = None,
    ) -> "PALCallContext":
        thread = thread or PALThreadContext(memory)
        frame = PALSysVAMD64CallFrame.build(
            thread,
            fixed_arguments=fixed_arguments,
            variadic_arguments=variadic_arguments,
            variadic=variadic,
            entry_plan_id=entry_plan_id,
        )
        return cls(
            thread,
            frame,
            entry_plan_id=entry_plan_id,
            entry_plans=entry_plans,
            call_plans=call_plans,
            internal_functions=internal_functions,
            external_functions=external_functions,
        )

    def register_entry_plan(self, plan: Mapping[str, Any]) -> None:
        plan = dict(plan or {})
        if plan.get("plan_class") != "function_entry_abi_plan" or not plan.get("plan_id"):
            raise PALABIPlanError("invalid function_entry_abi_plan")
        self.entry_plans[str(plan["plan_id"])] = plan

    def register_call_plan(self, plan: Mapping[str, Any]) -> None:
        plan = dict(plan or {})
        if plan.get("plan_class") != "call_site_abi_plan" or not plan.get("plan_id"):
            raise PALABIPlanError("invalid call_site_abi_plan")
        self.call_plans[str(plan["plan_id"])] = plan

    def register_metadata(self, metadata: Any) -> None:
        """Index ABI-D plans from a frozen icecube without interpreting them."""

        seen: set = set()

        def walk(value: Any) -> None:
            identity = id(value)
            if isinstance(value, (dict, list, tuple)):
                if identity in seen:
                    return
                seen.add(identity)
            if isinstance(value, Mapping):
                plan_class = value.get("plan_class")
                if plan_class == "function_entry_abi_plan":
                    self.register_entry_plan(value)
                elif plan_class == "call_site_abi_plan":
                    self.register_call_plan(value)
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    walk(nested)

        walk(metadata)

    def register_internal(self, name: str, function: Callable[..., Any]) -> None:
        self.internal_functions[str(name)] = function

    def register_external(self, name: str, function: Callable[..., Any]) -> None:
        self.external_functions[str(name)] = function

    @contextmanager
    def activate(self) -> Iterator["PALCallContext"]:
        token = _CURRENT_CONTEXT.set(self)
        try:
            yield self
        finally:
            _CURRENT_CONTEXT.reset(token)

    def invoke(self, function: Callable[..., Any], *logical_arguments: Any) -> Any:
        with self.activate():
            return function(*logical_arguments)

    def _entry_plan(self, plan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        key = str(plan_id or self.entry_plan_id or "")
        return self.entry_plans.get(key)

    def get(self, source_kind: str, source_key: Any, width: Any) -> Any:
        kind = str(source_kind)
        if kind == "registers":
            return self.frame.get_register(source_key, width)
        if kind == "stack_pointer":
            return _bits(self.frame.stack_pointer, width or 64)
        if kind == "frame_base":
            return _bits(self.frame.frame_base, width or 64)
        if kind == "tls_base":
            return _bits(self.frame.tls_base, width or 64)
        if kind == "variadic_xmm_count":
            return _bits(self.frame.al, width or 8)
        if kind == "overflow_argument_area":
            return self.frame.overflow_argument_area
        if kind == "register_save_area":
            if source_key:
                return self.frame.get_register(source_key, width)
            return self.frame.register_save_area.address
        if kind == "va_list":
            return self.frame.va_list_address
        if kind == "condition_flags":
            if source_key is None:
                return self.frame.condition_flags
            return self.frame.condition_flags.get(str(source_key), 0)
        if kind == "machine_state":
            if source_key is None:
                return self.frame.machine_state
            return self.frame.machine_state.get(str(source_key), 0)
        raise PALABIValidationError("unknown ABI materialization source %r" % kind)

    def _child_context(
        self, frame: PALSysVAMD64CallFrame, entry_plan_id: Optional[str]
    ) -> "PALCallContext":
        return PALCallContext(
            self.thread,
            frame,
            entry_plan_id=entry_plan_id,
            entry_plans=self.entry_plans,
            call_plans=self.call_plans,
            internal_functions=self.internal_functions,
            external_functions=self.external_functions,
            parent=self,
        )

    def call(self, target: Any, values: Sequence[Any], plan_id: str) -> Any:
        plan = self.call_plans.get(str(plan_id))
        if not isinstance(plan, dict):
            raise PALABIPlanError("unknown call-site ABI plan %r" % plan_id)
        if plan.get("plan_id") != plan_id:
            raise PALABIPlanError("call-site plan identity mismatch")
        backend_name = str((plan.get("abi_backend") or {}).get("name") or "")
        frame_type = self.BACKENDS.get(backend_name)
        if frame_type is None:
            raise PALABIPlanError("unavailable ABI backend %r" % backend_name)

        target_contract = dict(plan.get("target") or {})
        target_name = str(target_contract.get("name") or target)
        entry_plan_id = (
            target_contract.get("entry_plan_lookup_key")
            or (plan.get("target_compatibility") or {}).get("entry_plan_lookup_key")
        )
        child_frame = frame_type.from_call_plan(
            self.thread, plan, tuple(values), entry_plan_id=entry_plan_id
        )
        dispatch = str(plan.get("dispatch_policy") or "")

        if dispatch == "PAL_internal_dispatch":
            function = self.internal_functions.get(target_name)
            if function is None:
                raise PALABIDispatchError(
                    "internal PAL target %r is not registered" % target_name
                )
            entry_plan = self.entry_plans.get(str(entry_plan_id)) if entry_plan_id else None
            logical_count = int((entry_plan or {}).get("fixed_argument_count") or 0)
            logical_values = tuple(values[:logical_count])
            child = self._child_context(child_frame, entry_plan_id)
            with child.activate():
                result = function(*logical_values)
        else:
            function = self.external_functions.get(target_name)
            if function is None:
                raise PALABIDispatchError(
                    "external/thunk PAL target %r is not registered" % target_name
                )
            child = self._child_context(child_frame, entry_plan_id)
            with child.activate():
                result = function(*tuple(values))

        if plan.get("no_return") is True:
            raise PALABINoReturnViolation(
                "no-return ABI target %r returned" % target_name
            )
        width = plan.get("result_width_bits")
        if isinstance(width, int) and width > 0 and result is not None:
            return _bits(result, width)
        return result

    def publish_return(
        self,
        value: Any,
        width: Any,
        carriers: Sequence[Sequence[Any]],
        plan_id: Optional[str],
    ) -> int:
        if plan_id is not None and self.entry_plan_id is not None:
            if str(plan_id) != str(self.entry_plan_id):
                raise PALABIPlanError("return entry-plan identity mismatch")
        width = _positive_width(width)
        raw = _bits(value, width)
        carrier_records: List[Tuple[Any, ...]] = []
        bit_offset = 0
        for record in carriers:
            item = tuple(record)
            kind = item[0] if len(item) > 0 else None
            register = item[1] if len(item) > 1 else None
            carrier_width = item[2] if len(item) > 2 else None
            if kind == "register" and register:
                effective = int(carrier_width or width)
                piece = (raw >> bit_offset) & _mask(effective)
                self.frame.set_register(register, piece, effective)
                bit_offset += effective
            carrier_records.append(item)
        self.return_value = raw
        self.return_carriers = tuple(carrier_records)
        return raw


_CURRENT_CONTEXT: contextvars.ContextVar[Optional[PALCallContext]] = contextvars.ContextVar(
    "PAL_current_abi_context", default=None
)


def current_abi_context() -> PALCallContext:
    context = _CURRENT_CONTEXT.get()
    if context is None:
        raise PALABIError(
            "no active PALCallContext; invoke generated code through context.invoke()"
        )
    return context


def c_abi_context(plan_id: str) -> PALCallContext:
    context = current_abi_context()
    if context.entry_plan_id is not None and str(context.entry_plan_id) != str(plan_id):
        raise PALABIPlanError(
            "active entry plan %r does not match emitted plan %r"
            % (context.entry_plan_id, plan_id)
        )
    if context.entry_plan_id is None:
        context.entry_plan_id = str(plan_id)
        context.frame.entry_plan_id = str(plan_id)
    return context


def c_abi_get(
    context: PALCallContext, source_kind: str, source_key: Any, width: Any
) -> Any:
    if context is not current_abi_context():
        raise PALABIValidationError("c_abi_get context is not the active invocation")
    return context.get(source_kind, source_key, width)


def c_abi_call(
    context: PALCallContext,
    target: Any,
    values: Sequence[Any],
    *,
    plan_id: str,
) -> Any:
    if context is not current_abi_context():
        raise PALABIValidationError("c_abi_call context is not the active invocation")
    return context.call(target, tuple(values), plan_id)


def c_abi_return(
    context: PALCallContext,
    value: Any,
    width: Any,
    carriers: Sequence[Sequence[Any]],
    *,
    plan_id: Optional[str] = None,
) -> int:
    if context is not current_abi_context():
        raise PALABIValidationError("c_abi_return context is not the active invocation")
    return context.publish_return(value, width, carriers, plan_id)


__all__ = [
    "PALABIError",
    "PALABIValidationError",
    "PALABIPlanError",
    "PALABIDispatchError",
    "PALABINoReturnViolation",
    "PALCallContext",
    "PALSysVAMD64CallFrame",
    "PALVariadicArguments",
    "PALRegisterSaveArea",
    "PALThreadContext",
    "current_abi_context",
    "c_abi_context",
    "c_abi_get",
    "c_abi_call",
    "c_abi_return",
]
