# ============================================================
# PAL STATIC STRING PUBLISHER
# BUILD: static_strings_v1_defined_ghidra_data
# ============================================================
#
# Program-level producer for:
#
#     project/<program>/PAL_stdio_strings.json
#
# Ownership:
#   - Reads the live Ghidra Program once.
#   - Publishes deterministic initialized string data.
#   - Does not know about SGL, PHI, emitter syntax, ABI transport, or EXEC.
#   - PALemitter and PALExecInterface are consumers only.
# ============================================================

from __future__ import annotations

import ast
import json
import os
import tempfile


STATIC_STRING_BUILD = "static_strings_v1_defined_ghidra_data"
STATIC_STRING_FORMAT = "pal_stdio_string_overlay"
STATIC_STRING_SCHEMA_VERSION = 1


def _safe_call(obj, method, default=None, *args):
    if obj is None:
        return default
    function = getattr(obj, method, None)
    if not callable(function):
        return default
    try:
        return function(*args)
    except Exception:
        return default


def _safe_int(value, default=None):
    if value is None:
        return default
    try:
        getter = getattr(value, "getOffset", None)
        if callable(getter):
            value = getter()
        return int(value)
    except Exception:
        return default


def _java_iter(iterator):
    if iterator is None:
        return
    try:
        for item in iterator:
            yield item
        return
    except TypeError:
        pass

    has_next = getattr(iterator, "hasNext", None)
    next_item = getattr(iterator, "next", None)
    if not callable(has_next) or not callable(next_item):
        return

    while has_next():
        yield next_item()


def _datatype_name(data):
    datatype = _safe_call(data, "getDataType")
    name = _safe_call(datatype, "getName")
    return str(name or "").strip().lower()


def _is_string_data(data):
    has_string_value = _safe_call(data, "hasStringValue")
    if has_string_value is True:
        return True

    name = _datatype_name(data)
    return any(token in name for token in (
        "string", "unicode", "utf16", "utf-16", "utf32", "utf-32",
    ))


def _representation_text(data):
    representation = _safe_call(data, "getDefaultValueRepresentation")
    if not representation:
        return None

    text = str(representation).strip()
    if len(text) < 2 or text[0] not in ("'", '"'):
        return None

    try:
        value = ast.literal_eval(text)
    except Exception:
        return None

    return value if isinstance(value, str) else None


def _memory_bytes(program, data):
    memory = _safe_call(program, "getMemory")
    address = _safe_call(data, "getAddress")
    length = _safe_int(_safe_call(data, "getLength"), 0)

    if memory is None or address is None or length <= 0:
        return None

    raw = bytearray()

    for offset in range(length):
        current = _safe_call(address, "add", None, offset)
        if current is None:
            break
        value = _safe_call(memory, "getByte", None, current)
        if value is None:
            break
        raw.append(int(value) & 0xFF)

    return bytes(raw) if raw else None


def _decode_memory_string(program, data):
    raw = _memory_bytes(program, data)
    if not raw:
        return None

    name = _datatype_name(data)

    if any(token in name for token in ("unicode", "utf16", "utf-16")):
        terminator = raw.find(b"\0\0")
        if terminator >= 0:
            terminator -= terminator % 2
            raw = raw[:terminator]
        try:
            return raw.decode("utf-16-le", errors="replace")
        except Exception:
            return None

    if any(token in name for token in ("utf32", "utf-32")):
        terminator = raw.find(b"\0\0\0\0")
        if terminator >= 0:
            terminator -= terminator % 4
            raw = raw[:terminator]
        try:
            return raw.decode("utf-32-le", errors="replace")
        except Exception:
            return None

    raw = raw.split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _string_value(program, data):
    value = _safe_call(data, "getValue")

    if isinstance(value, str):
        return value

    if value is not None:
        # PyGhidra usually exposes java.lang.String through Python str().
        class_name = value.__class__.__name__.lower()
        if "string" in class_name:
            return str(value)

    representation = _representation_text(data)
    if representation is not None:
        return representation

    return _decode_memory_string(program, data)


def _atomic_write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)

    fd, temporary = tempfile.mkstemp(
        prefix=".PAL_stdio_strings.",
        suffix=".tmp",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "wt", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                indent=2,
                sort_keys=False,
                ensure_ascii=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def collect_defined_strings(program):
    """
    Collect Ghidra-defined string data by address.

    This deliberately does not scan arbitrary executable bytes for printable
    runs. Ghidra's defined-data model is the authority boundary, avoiding
    false strings from code, relocation tables, and packed binary data.
    """
    listing = _safe_call(program, "getListing")
    if listing is None:
        raise ValueError("Ghidra Program has no Listing")

    iterator = _safe_call(listing, "getDefinedData", None, True)
    if iterator is None:
        raise ValueError("Listing.getDefinedData(True) failed")

    strings = {}
    rejected = 0

    for data in _java_iter(iterator):
        if not _is_string_data(data):
            continue

        address = _safe_int(_safe_call(data, "getAddress"))
        if address is None:
            rejected += 1
            continue

        text = _string_value(program, data)
        if not isinstance(text, str):
            rejected += 1
            continue

        text = text.rstrip("\0")
        if not text:
            continue

        strings[address] = text

    return strings, rejected


def publish_static_strings(program, output_path):
    if program is None:
        raise ValueError("PAL static-string publisher requires a Ghidra Program")

    strings, rejected = collect_defined_strings(program)

    program_name = str(
        _safe_call(program, "getName", "unknown") or "unknown"
    )
    image_base = _safe_int(_safe_call(program, "getImageBase"))

    ordered = {
        hex(address): strings[address]
        for address in sorted(strings)
    }

    payload = {
        "format": STATIC_STRING_FORMAT,
        "schema_version": STATIC_STRING_SCHEMA_VERSION,
        "producer": "PALStaticStringPublisher",
        "producer_build": STATIC_STRING_BUILD,
        "program": program_name,
        "image_base": (
            hex(image_base) if isinstance(image_base, int) else None
        ),
        "source_policy": "ghidra_defined_string_data_only",
        "strings": ordered,
    }

    _atomic_write_json(output_path, payload)

    return {
        "status": "published",
        "producer": "PALStaticStringPublisher",
        "producer_build": STATIC_STRING_BUILD,
        "source_policy": "ghidra_defined_string_data_only",
        "strings": len(ordered),
        "rejected_string_records": int(rejected),
    }


__all__ = [
    "publish_static_strings",
    "collect_defined_strings",
    "STATIC_STRING_BUILD",
    "STATIC_STRING_FORMAT",
    "STATIC_STRING_SCHEMA_VERSION",
]
