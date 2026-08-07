"""Deterministic fixed-width helpers for PAL-emitted Python.

Values crossing SSA and function-return boundaries are raw unsigned
bitvectors.  Signedness is applied only by helpers whose P-code opcode demands
it (signed comparison, division, remainder, arithmetic shift, extension).
"""


def _width(width):
    width = int(width)
    if width <= 0:
        raise ValueError("PAL bit width must be positive")
    return width


def _mask(width):
    return (1 << _width(width)) - 1


def c_bits(value, width):
    return int(value) & _mask(width)


def c_signed(value, width):
    width = _width(width)
    raw = c_bits(value, width)
    sign = 1 << (width - 1)
    return raw - (1 << width) if raw & sign else raw


def c_return_bits(value, width):
    """Transport the raw return-register bitvector without type presentation."""
    return c_bits(value, width)


def c_add(a, b, width):
    return c_bits(c_bits(a, width) + c_bits(b, width), width)


def c_sub(a, b, width):
    return c_bits(c_bits(a, width) - c_bits(b, width), width)


def c_mul(a, b, width):
    return c_bits(c_bits(a, width) * c_bits(b, width), width)


def c_udiv(a, b, width):
    divisor = c_bits(b, width)
    if divisor == 0:
        raise ZeroDivisionError("PAL unsigned division by zero")
    return c_bits(a, width) // divisor


def c_urem(a, b, width):
    divisor = c_bits(b, width)
    if divisor == 0:
        raise ZeroDivisionError("PAL unsigned remainder by zero")
    return c_bits(a, width) % divisor


def _signed_quotient(a, b, width):
    dividend = c_signed(a, width)
    divisor = c_signed(b, width)
    if divisor == 0:
        raise ZeroDivisionError("PAL signed division by zero")
    magnitude = abs(dividend) // abs(divisor)
    return -magnitude if (dividend < 0) != (divisor < 0) else magnitude


def c_sdiv(a, b, width):
    """C/P-code signed division: truncate toward zero, then retain raw bits."""
    return c_bits(_signed_quotient(a, b, width), width)


def c_srem(a, b, width):
    """C/P-code signed remainder: result has the dividend's sign."""
    dividend = c_signed(a, width)
    divisor = c_signed(b, width)
    quotient = _signed_quotient(dividend, divisor, width)
    return c_bits(dividend - quotient * divisor, width)


def c_neg(value, width):
    return c_bits(-c_bits(value, width), width)


def c_not(value, width):
    return c_bits(~c_bits(value, width), width)


def c_and(a, b, width):
    return c_bits(a, width) & c_bits(b, width)


def c_or(a, b, width):
    return c_bits(a, width) | c_bits(b, width)


def c_xor(a, b, width):
    return c_bits(a, width) ^ c_bits(b, width)


def _shift_count(count):
    count = int(count)
    if count < 0:
        raise ValueError("PAL shift count must be non-negative")
    return count


def c_shl(value, count, width):
    width = _width(width)
    count = _shift_count(count)
    if count >= width:
        return 0
    return c_bits(c_bits(value, width) << count, width)


def c_lshr(value, count, width):
    width = _width(width)
    count = _shift_count(count)
    if count >= width:
        return 0
    return c_bits(value, width) >> count


def c_ashr(value, count, width):
    width = _width(width)
    count = _shift_count(count)
    signed = c_signed(value, width)
    if count >= width:
        return _mask(width) if signed < 0 else 0
    return c_bits(signed >> count, width)


def c_eq(a, b, width):
    return c_bits(a, width) == c_bits(b, width)


def c_ne(a, b, width):
    return c_bits(a, width) != c_bits(b, width)


def c_ult(a, b, width):
    return c_bits(a, width) < c_bits(b, width)


def c_ule(a, b, width):
    return c_bits(a, width) <= c_bits(b, width)


def c_slt(a, b, width):
    return c_signed(a, width) < c_signed(b, width)


def c_sle(a, b, width):
    return c_signed(a, width) <= c_signed(b, width)


def c_carry(a, b, width):
    width = _width(width)
    return c_bits(a, width) + c_bits(b, width) > _mask(width)


def c_scarry(a, b, width):
    width = _width(width)
    result = c_signed(a, width) + c_signed(b, width)
    lower = -(1 << (width - 1))
    upper = (1 << (width - 1)) - 1
    return result < lower or result > upper


def c_sborrow(a, b, width):
    width = _width(width)
    result = c_signed(a, width) - c_signed(b, width)
    lower = -(1 << (width - 1))
    upper = (1 << (width - 1)) - 1
    return result < lower or result > upper


def c_zext(value, source_width, output_width):
    return c_bits(c_bits(value, source_width), output_width)


def c_sext(value, source_width, output_width):
    return c_bits(c_signed(value, source_width), output_width)


def c_subpiece(value, byte_offset, source_width, output_width):
    shift = int(byte_offset) * 8
    if shift < 0:
        raise ValueError("PAL SUBPIECE offset must be non-negative")
    return c_bits(c_bits(value, source_width) >> shift, output_width)


def c_piece(high, low, high_width, low_width, output_width):
    joined = (c_bits(high, high_width) << _width(low_width)) | c_bits(low, low_width)
    return c_bits(joined, output_width)


def c_resize(value, source_width, output_width):
    return c_bits(c_bits(value, source_width), output_width)


def c_cast_bits(value, source_width, output_width):
    return c_resize(value, source_width, output_width)


def c_ptradd(base, index, element_size, width):
    return c_add(base, c_mul(index, element_size, width), width)


def c_ptrsub(base, offset, width):
    # P-code PTRSUB denotes a subcomponent address: base + byte offset.
    return c_add(base, offset, width)


def _memory_byte(memory, address):
    address = int(address)
    if isinstance(memory, (bytes, bytearray, memoryview)):
        return int(memory[address])
    if isinstance(memory, dict):
        return int(memory.get(address, 0))
    if hasattr(memory, "load_byte"):
        return int(memory.load_byte(address))
    raise TypeError("PAL memory must be bytes-like, dict-like, or expose load_byte")


def c_load(memory, address, width):
    width = _width(width)
    if width % 8:
        raise ValueError("PAL preliminary memory model requires byte widths")
    value = 0
    for index in range(width // 8):
        value |= (_memory_byte(memory, int(address) + index) & 0xff) << (index * 8)
    return c_bits(value, width)


def c_store(memory, address, value, width):
    width = _width(width)
    if width % 8:
        raise ValueError("PAL preliminary memory model requires byte widths")
    raw = c_bits(value, width)
    for index in range(width // 8):
        byte = (raw >> (index * 8)) & 0xff
        target = int(address) + index
        if isinstance(memory, bytearray):
            memory[target] = byte
        elif isinstance(memory, dict):
            memory[target] = byte
        elif hasattr(memory, "store_byte"):
            memory.store_byte(target, byte)
        else:
            raise TypeError("PAL writable memory must be bytearray, dict, or expose store_byte")
    return None
