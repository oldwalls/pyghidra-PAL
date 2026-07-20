# ============================================================
# PAL EXECUTION INTERFACE
# BUILD: pal_exec_interface_v1g_stdio_game_io
#
# Detached project publisher and controlled execution launcher.
# Run from the PAL repository root:
#
#     python PALExecInterface.py
#
# or non-interactively:
#
#     python PALExecInterface.py --project <name> --publish --run \
#         --function main --arg 1 --arg 2
# ============================================================

from __future__ import annotations

import argparse
import ast
import datetime as _datetime
import gzip
import hashlib
import importlib.util
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


PAL_EXEC_INTERFACE_BUILD = "pal_exec_interface_v1g_stdio_game_io"
PROJECT_DIRECTORY_NAMES = ("project", "projects")
PROJECT_MANIFEST = "PAL_function_manifest.json"
PROJECT_DISPATCH = "PAL_dispatch.py"
PROJECT_JUMP_TABLE = "PAL_jump_table.json"
PROJECT_ONCS = "PAL_ONCS.json"
EXECUTE_DIRECTORY = "execute"
EXEC_CONFIG = "config.exec.json"
ABI_PLAN_INDEX = "PAL_abi_plans.json"

_PRINT_SHIM_NAMES = {
    "printf",
    "__printf_chk",
    "fprintf",
    "__fprintf_chk",
    "puts",
    "fputs",
    "putchar",
    "fputc",
    "fputc_unlocked",
    "fputs_unlocked",
}

_STDIO_SHIM_NAMES = {
    "fgets",
    "strcmp",
    "strcspn",
}

_NORETURN_SHIM_NAMES = {
    "exit",
    "_exit",
    "abort",
    "__stack_chk_fail",
}


class PALExecInterfaceError(RuntimeError):
    """The clear-case project cannot be published or launched safely."""


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> Dict[str, Any]:
    opener = gzip.open if str(path).lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise PALExecInterfaceError("expected JSON object: %s" % path)
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp.%d" % os.getpid())
    try:
        with open(temp, "wt", encoding="utf-8", newline="\n") as handle:
            json.dump(
                value,
                handle,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp.%d" % os.getpid())
    try:
        with open(temp, "wt", encoding="utf-8", newline="\n") as handle:
            handle.write(str(text))
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _record_key_names(record: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in (
        "name", "qualified_name", "python_symbol", "active_name",
        "generated_name", "operator_name", "pal_name", "ssa_name",
        "function_id", "entry_hex",
    ):
        value = record.get(key)
        if value not in (None, ""):
            names.add(str(value))
    entry = record.get("entry")
    if isinstance(entry, int):
        names.add(str(entry))
        names.add(hex(entry))
    return names


def _safe_module_stem(record: Mapping[str, Any]) -> str:
    stem = record.get("module_stem")
    if not stem:
        module = str(record.get("module") or "")
        stem = module.rsplit(".", 1)[-1] if module else None
    if not stem:
        artifact = dict(record.get("artifacts") or {}).get("executable")
        artifact_path = str((artifact or {}).get("path") or "")
        name = os.path.basename(artifact_path)
        for suffix in (".exec.py", ".py"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        stem = name
    stem = re.sub(r"[^0-9A-Za-z_]+", "_", str(stem or "function"))
    if not stem or stem[0].isdigit():
        stem = "f_" + stem
    return stem


def _iter_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    seen: set[int] = set()

    def walk(item: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(item, (dict, list, tuple)):
            marker = id(item)
            if marker in seen:
                return
            seen.add(marker)
        if isinstance(item, dict):
            yield item
            for child in item.values():
                yield from walk(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                yield from walk(child)

    yield from walk(value)


def _extract_abi_plans(icecube: Mapping[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    entries: Dict[str, Any] = {}
    calls: Dict[str, Any] = {}
    for record in _iter_dicts(icecube):
        plan_class = record.get("plan_class")
        plan_id = record.get("plan_id")
        if not plan_id:
            continue
        if plan_class == "function_entry_abi_plan":
            table = entries
        elif plan_class == "call_site_abi_plan":
            table = calls
        else:
            continue
        key = str(plan_id)
        candidate = dict(record)
        previous = table.get(key)
        if previous is not None and _canonical_json(previous) != _canonical_json(candidate):
            raise PALExecInterfaceError(
                "conflicting frozen ABI plan identity: %s" % key
            )
        table[key] = candidate
    return entries, calls


def _python_imports(source: str) -> List[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".", 1)[0])
    return sorted(names)


def _function_parameters(source: str, symbol: Optional[str]) -> Optional[int]:
    if not symbol:
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
            return len(node.args.posonlyargs) + len(node.args.args)
    return None


def _source_uses_abi(source: str) -> bool:
    return bool(
        re.search(r"\bc_abi_context\s*\(", source)
        or re.search(r"\bfrom\s+PALABI\s+import\b", source)
        or re.search(r"\bimport\s+PALABI\b", source)
    )


def _entry_priority(record: Mapping[str, Any]) -> Tuple[int, int, str]:
    names = {
        str(record.get(key) or "")
        for key in (
            "name",
            "qualified_name",
            "python_symbol",
            "active_name",
            "generated_name",
            "operator_name",
            "pal_name",
            "ssa_name",
        )
    }
    lowered = {name.lower().split("::")[-1] for name in names if name}
    if "main" in lowered:
        score = 0
    elif "entry" in lowered:
        score = 1
    elif "_start" in lowered or "start" in lowered:
        score = 2
    else:
        score = 10
    return score, int(record.get("ordinal") or 0), str(record.get("name") or "")


def _parse_scalar(text: str) -> Any:
    raw = str(text).strip()
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw.lower() in {"none", "null"}:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


PALMEM_SOURCE = r'''# Generated by PALExecInterface.
# Minimal sparse byte-addressable memory for clear-case execution.

from __future__ import annotations

from collections.abc import MutableMapping


class PALMemory(MutableMapping):
    def __init__(self, initial=None, *, allocation_base=0x700000000000):
        self._bytes = {}
        self._next_allocation = int(allocation_base)
        if initial:
            for address, value in dict(initial).items():
                self[int(address)] = int(value)

    def __getitem__(self, address):
        return self._bytes.get(int(address), 0)

    def __setitem__(self, address, value):
        self._bytes[int(address)] = int(value) & 0xff

    def __delitem__(self, address):
        del self._bytes[int(address)]

    def __iter__(self):
        return iter(self._bytes)

    def __len__(self):
        return len(self._bytes)

    def get(self, address, default=0):
        return self._bytes.get(int(address), default)

    # PALhelpers memory protocol.  MutableMapping compatibility alone is not
    # sufficient because PALhelpers deliberately accepts only bytearray, an
    # actual dict, or an object exposing load_byte/store_byte.
    def load_byte(self, address):
        return self._bytes.get(int(address), 0) & 0xff

    def store_byte(self, address, value):
        byte_value = int(value) & 0xff
        self._bytes[int(address)] = byte_value
        return byte_value

    # Compatibility aliases for runtime components using read/write wording.
    read_byte = load_byte
    write_byte = store_byte

    def load(self, address, width_bits):
        width_bits = int(width_bits)
        if width_bits <= 0 or width_bits % 8:
            raise ValueError("memory load width must be whole bytes")
        value = 0
        for index in range(width_bits // 8):
            value |= (self[int(address) + index] & 0xff) << (index * 8)
        return value

    def store(self, address, value, width_bits):
        width_bits = int(width_bits)
        if width_bits <= 0 or width_bits % 8:
            raise ValueError("memory store width must be whole bytes")
        raw = int(value)
        for index in range(width_bits // 8):
            self[int(address) + index] = raw >> (index * 8)
        return raw & ((1 << width_bits) - 1)

    read_int = load
    write_int = store

    def map_bytes(self, address, data):
        raw = bytes(data)
        for index, value in enumerate(raw):
            self[int(address) + index] = value
        return int(address)

    def read_bytes(self, address, size):
        return bytes(self[int(address) + index] for index in range(int(size)))

    def read_c_string(self, address, *, limit=65536, encoding="utf-8"):
        data = bytearray()
        for index in range(int(limit)):
            value = self[int(address) + index]
            if value == 0:
                break
            data.append(value)
        return bytes(data).decode(encoding, errors="replace")

    def allocate(self, size, *, alignment=16, zero=True):
        size = max(int(size), 1)
        alignment = max(int(alignment), 1)
        address = (self._next_allocation + alignment - 1) & -alignment
        self._next_allocation = address + size
        if zero:
            for index in range(size):
                self[address + index] = 0
        return address

    def allocate_c_string(self, text, *, encoding="utf-8"):
        raw = str(text).encode(encoding) + b"\0"
        address = self.allocate(len(raw), alignment=1, zero=False)
        self.map_bytes(address, raw)
        return address
'''


PALSHIMS_SOURCE = r'''# Generated by PALExecInterface.
# Explicit modeled external boundaries. Unknown externals fail closed.

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


class PALUnimplementedShim(RuntimeError):
    pass


class PALProcessExit(SystemExit):
    pass


class PALPrintShims:
    def __init__(self, memory, stdin=None, stdout=None):
        self.memory = memory
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout
        self._load_stdio_literals()

    def _load_stdio_literals(self):
        path = Path(__file__).resolve().parent.parent / "PAL_stdio_strings.json"
        if not path.is_file():
            return
        try:
            with open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
            literals = payload.get("strings", payload)
            if not isinstance(literals, dict):
                return
            for raw_address, text in literals.items():
                address = int(str(raw_address), 0)
                data = str(text).encode("utf-8") + b"\0"
                self.memory.map_bytes(address, data)
        except Exception as exc:
            raise PALUnimplementedShim(
                "PAL stdio literal overlay failed: %s" % exc
            )

    def _write(self, text):
        self.stdout.write(str(text))
        self.stdout.flush()

    def _write_c_buffer(self, address, data, size):
        size = int(size)
        if size <= 0:
            return 0
        raw = bytes(data)[: max(size - 1, 0)]
        self.memory.map_bytes(int(address), raw + b"\0")
        return int(address)

    def _string(self, value):
        if isinstance(value, str):
            return value
        try:
            address = int(value)
        except (TypeError, ValueError):
            return str(value)
        try:
            text = self.memory.read_c_string(address)
        except Exception:
            text = ""
        return text if text else "<cstr@0x%x>" % address

    def _format(self, fmt, values):
        fmt = self._string(fmt)
        items = iter(values)
        out = []
        index = 0
        pattern = re.compile(r"%(?:[-+ #0]*)(?:\d+|\*)?(?:\.\d+|\.\*)?(?:hh|h|ll|l|j|z|t|L)?([diuoxXfFeEgGaAcsp%])")
        for match in pattern.finditer(fmt):
            out.append(fmt[index:match.start()])
            kind = match.group(1)
            token = match.group(0)
            if kind == "%":
                out.append("%")
                index = match.end()
                continue
            try:
                value = next(items)
            except StopIteration:
                out.append(token)
                index = match.end()
                continue
            try:
                if kind in "di":
                    rendered = str(int(value))
                elif kind == "u":
                    rendered = str(int(value) & ((1 << 64) - 1))
                elif kind in "xX":
                    rendered = format(int(value) & ((1 << 64) - 1), kind)
                elif kind == "o":
                    rendered = format(int(value) & ((1 << 64) - 1), "o")
                elif kind in "fFeEgGaA":
                    rendered = str(float(value))
                elif kind == "c":
                    rendered = chr(int(value) & 0xff)
                elif kind == "s":
                    rendered = self._string(value)
                elif kind == "p":
                    rendered = "0x%x" % int(value)
                else:
                    rendered = str(value)
            except Exception:
                rendered = str(value)
            out.append(rendered)
            index = match.end()
        out.append(fmt[index:])
        remaining = list(items)
        if remaining:
            out.append(" " + " ".join(str(value) for value in remaining))
        return "".join(out)

    def printf(self, fmt, *values):
        text = self._format(fmt, values)
        self._write(text)
        return len(text)

    def __printf_chk(self, flag, fmt, *values):
        return self.printf(fmt, *values)

    def fprintf(self, stream, fmt, *values):
        return self.printf(fmt, *values)

    def __fprintf_chk(self, stream, flag, fmt, *values):
        return self.printf(fmt, *values)

    def puts(self, value):
        text = self._string(value)
        self._write(text + "\n")
        return len(text) + 1

    def fputs(self, value, stream=None):
        text = self._string(value)
        self._write(text)
        return len(text)

    def putchar(self, value):
        char = chr(int(value) & 0xff)
        self._write(char)
        return int(value) & 0xff

    def fgets(self, destination, size, stream=None):
        self.stdout.flush()
        line = self.stdin.readline()
        if line == "":
            return 0
        return self._write_c_buffer(
            destination,
            line.encode("utf-8", errors="replace"),
            size,
        )

    def strcmp(self, left, right):
        left_text = self._string(left)
        right_text = self._string(right)
        if left_text == right_text:
            return 0
        return -1 if left_text < right_text else 1

    def strcspn(self, text, reject):
        text_value = self._string(text)
        reject_value = self._string(reject)
        # Bounded compatibility for clean_input(str, "\n") when the tiny
        # static reject literal is not yet present in the overlay.
        if reject_value.startswith("<cstr@"):
            reject_value = "\n"
        rejected = set(reject_value)
        for index, char in enumerate(text_value):
            if char in rejected:
                return index
        return len(text_value)

    def fputc(self, value, stream=None):
        return self.putchar(value)

    def exit(self, status=0):
        raise PALProcessExit(int(status))

    def abort(self, *unused):
        raise PALProcessExit(134)

    def stack_chk_fail(self, *unused):
        raise PALProcessExit("PAL __stack_chk_fail trap")

    def unresolved(self, name):
        def trap(*values):
            raise PALUnimplementedShim(
                "PAL external shim %r is not implemented; args=%r" % (name, values)
            )
        trap.__name__ = "pal_unimplemented_%s" % str(name).replace("-", "_")
        return trap

    def mapping(self, names=()):
        table = {
            "printf": self.printf,
            "__printf_chk": self.__printf_chk,
            "fprintf": self.fprintf,
            "__fprintf_chk": self.__fprintf_chk,
            "puts": self.puts,
            "fputs": self.fputs,
            "fputs_unlocked": self.fputs,
            "putchar": self.putchar,
            "fputc": self.fputc,
            "fputc_unlocked": self.fputc,
            "fgets": self.fgets,
            "strcmp": self.strcmp,
            "strcspn": self.strcspn,
            "exit": self.exit,
            "_exit": self.exit,
            "abort": self.abort,
            "__stack_chk_fail": self.stack_chk_fail,
        }
        for name in names:
            table.setdefault(str(name), self.unresolved(str(name)))
        return table
'''


PAL_PROJECT_RUNTIME_SOURCE = r'''# Generated by PALExecInterface.
# Controlled clear-case PAL project runtime.

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path

EXEC_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = EXEC_ROOT / "runtime"
SHIMS_ROOT = EXEC_ROOT / "shims"
FUNCTIONS_ROOT = EXEC_ROOT / "functions"
for _path in (str(RUNTIME_ROOT), str(SHIMS_ROOT), str(FUNCTIONS_ROOT), str(EXEC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from PALMEM import PALMemory
from PALShims import PALPrintShims, PALProcessExit


class PALPublishedRuntimeError(RuntimeError):
    pass


def _read_json(path):
    with open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def _key_names(record):
    names = set()
    for key in (
        "name", "qualified_name", "python_symbol", "active_name",
        "generated_name", "operator_name", "pal_name", "ssa_name",
        "function_id", "entry_hex",
    ):
        value = record.get(key)
        if value not in (None, ""):
            names.add(str(value))
    entry = record.get("entry")
    if isinstance(entry, int):
        names.add(str(entry))
        names.add(hex(entry))
    return names


def _abi_internal_target_names(index):
    """Derive internal target spellings from the published plan authority."""
    names = set()
    call_plans = dict((index or {}).get("call_plans") or {})
    for plan in call_plans.values():
        if not isinstance(plan, dict):
            continue
        compatibility = dict(plan.get("target_compatibility") or {})
        linkage = dict(plan.get("linkage_contract") or {})
        internal = bool(
            str(plan.get("dispatch_policy") or "") == "PAL_internal_dispatch"
            or compatibility.get("internal_target") is True
            or linkage.get("semantic_internal") is True
        )
        if not internal:
            continue
        target = dict(plan.get("target") or {})
        for key in (
            "name", "qualified_name", "python_symbol", "active_name",
            "generated_name", "operator_name", "pal_name", "ssa_name",
            "function_id", "entry_hex",
        ):
            value = target.get(key)
            if value not in (None, ""):
                names.add(str(value))
        entry = target.get("entry")
        if isinstance(entry, int):
            names.add(str(entry))
            names.add(hex(entry))
            names.add("function:%s" % hex(entry))
    return names


class PALProjectRuntime:
    def __init__(self, root=None):
        self.root = Path(root or EXEC_ROOT).resolve()
        self.config = _read_json(self.root / "config.exec.json")
        self.abi_plans = _read_json(self.root / "PAL_abi_plans.json")
        self.memory = PALMemory()
        self.records = list(self.config.get("functions") or [])
        self._record_index = {}
        self._module_cache = {}
        self._callable_cache = {}

        # Config is a useful publication summary, but the frozen ABI plan
        # index is the runtime dispatch authority.  Re-derive ownership here
        # so stale or incomplete publisher classifications cannot redirect an
        # internal call into shim city.
        self.internal_call_targets = set(
            str(name) for name in (self.config.get("internal_call_targets") or [])
        )
        self.internal_call_targets.update(
            _abi_internal_target_names(self.abi_plans)
        )

        # Every published executable artifact is available in the internal
        # namespace.  External shims live in a separate namespace; the same
        # spelling may validly exist in both and dispatch_policy chooses.
        self.internal_names = set()
        for record in self.records:
            names = _key_names(record)
            self.internal_names.update(names)
            for name in names:
                self._record_index.setdefault(name, []).append(record)

        external_names = set(self.config.get("external_targets") or [])
        external_names.update(self.config.get("thunk_targets") or [])
        self.shims = PALPrintShims(self.memory).mapping(sorted(external_names))

    def _record_identity(self, record):
        return str(
            record.get("function_id")
            or record.get("entry_hex")
            or record.get("name")
        )

    def _is_internal_record(self, record):
        # A published module is an internal callable regardless of stale
        # manifest external/thunk labeling.  Boundary metadata controls
        # top-level convenience behavior, not ABI dispatch ownership.
        return bool(record.get("published_module"))

    def _unique_records(self, name):
        unique = []
        seen = set()
        for record in list(self._record_index.get(str(name)) or []):
            identity = self._record_identity(record)
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(record)
        return unique

    def records_for(self, key):
        text = str(key)
        records = list(self._record_index.get(text) or [])
        if not records:
            try:
                number = int(text, 16) if text.lower().startswith("0x") else int(text)
            except ValueError:
                number = None
            if number is not None:
                records = [r for r in self.records if r.get("entry") == number]
        return records

    def resolve(self, key):
        records = self.records_for(key)
        if not records:
            raise PALPublishedRuntimeError("unknown published PAL function: %r" % key)
        if len(records) != 1:
            raise PALPublishedRuntimeError(
                "ambiguous published PAL function %r: %s"
                % (key, [record.get("entry_hex") for record in records])
            )
        return records[0]

    def _module_path(self, record):
        return self.root / str(record["published_module"])

    def _direct_shim_globals(self):
        return dict(self.shims)

    def _internal_wrapper(self, record):
        identity = str(record.get("function_id") or record.get("entry_hex") or record.get("name"))
        if identity in self._callable_cache:
            return self._callable_cache[identity]

        def invoke(*values):
            # Internal ABI dispatch must execute the published artifact.  It
            # must never re-enter top-level shim-boundary selection.
            function = self._published_callable(record)
            return self._invoke_adapted(function, values)

        invoke.__name__ = str(record.get("python_symbol") or record.get("name") or "pal_function")
        self._callable_cache[identity] = invoke
        return invoke

    def _all_internal_globals(self):
        table = {}
        for name in sorted(self._record_index):
            if not str(name).isidentifier():
                continue
            records = self._unique_records(name)
            if len(records) == 1:
                table[name] = self._internal_wrapper(records[0])
        return table

    def load_module(self, record_or_key):
        record = record_or_key if isinstance(record_or_key, dict) else self.resolve(record_or_key)
        identity = str(record.get("function_id") or record.get("entry_hex") or record.get("name"))
        cached = self._module_cache.get(identity)
        if cached is not None:
            return cached
        path = self._module_path(record)
        if not path.is_file():
            raise PALPublishedRuntimeError("published function module is missing: %s" % path)
        module_name = "palexec_%s" % str(record.get("module_stem") or path.stem)
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise PALPublishedRuntimeError("cannot load published module: %s" % path)
        module = importlib.util.module_from_spec(spec)
        module.MEM = self.memory
        # Inject published internal wrappers before shims.  Local definitions
        # in the module overwrite these during exec, while cross-function
        # direct calls retain internal ownership.
        module.__dict__.update(self._all_internal_globals())
        for _name, _value in self._direct_shim_globals().items():
            module.__dict__.setdefault(_name, _value)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        module.MEM = self.memory
        for _name, _value in self._all_internal_globals().items():
            module.__dict__.setdefault(_name, _value)
        for _name, _value in self._direct_shim_globals().items():
            module.__dict__.setdefault(_name, _value)
        self._module_cache[identity] = module
        return module

    def _published_callable(self, record):
        module = self.load_module(record)
        symbol = record.get("python_symbol")
        function = getattr(module, str(symbol), None)
        if not callable(function):
            raise PALPublishedRuntimeError(
                "published module %s has no callable %r"
                % (record.get("published_module"), symbol)
            )
        return function

    def load_callable(self, record_or_key):
        record = record_or_key if isinstance(record_or_key, dict) else self.resolve(record_or_key)
        # Direct user selection of a genuine boundary may use its shim, but
        # internal wrappers bypass this path and always execute published code.
        if record.get("is_shim_boundary"):
            for name in _key_names(record):
                if name in self.shims:
                    return self.shims[name]
        return self._published_callable(record)

    def _invoke_adapted(self, function, values):
        try:
            signature = inspect.signature(function)
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            varargs = any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            )
            if not positional and not varargs:
                return function()
            return function(*tuple(values))
        except (TypeError, ValueError):
            return function(*tuple(values))

    def _materialize_value(self, value):
        if isinstance(value, str) and value.startswith("str:"):
            return self.memory.allocate_c_string(value[4:])
        return value

    def _context(self, record, fixed_arguments, variadic_arguments):
        try:
            from PALABI import PALCallContext, PALVariadicArguments
        except ImportError as exc:
            raise PALPublishedRuntimeError("PALABI runtime is unavailable: %s" % exc)
        values = tuple(self._materialize_value(value) for value in fixed_arguments)
        var_values = tuple(self._materialize_value(value) for value in variadic_arguments)
        var_builder = PALVariadicArguments.from_values(*var_values) if var_values else None
        context = PALCallContext.for_sysv_amd64(
            self.memory,
            fixed_arguments=values,
            variadic_arguments=var_builder,
            variadic=bool(var_values),
            entry_plan_id=record.get("entry_plan_id"),
        )
        context.register_metadata(self.abi_plans)

        # Internal and external dispatch are independent namespaces.
        # Register every unambiguous published alias internally.
        for name in sorted(self._record_index):
            records = self._unique_records(name)
            if len(records) == 1:
                context.register_internal(name, self._internal_wrapper(records[0]))

        # Shims are external-only.  Never place a trap into internal_functions;
        # doing so converts a linker/classification error into a false external
        # execution path and masks the real ownership defect.
        for name, shim in self.shims.items():
            context.register_external(name, shim)

        missing = []
        ambiguous = []
        for name in sorted(self.internal_call_targets):
            records = self._unique_records(name)
            if len(records) == 1:
                context.register_internal(name, self._internal_wrapper(records[0]))
            elif not records:
                missing.append(name)
            else:
                ambiguous.append(
                    "%s -> %s"
                    % (name, [self._record_identity(record) for record in records])
                )
        if missing or ambiguous:
            parts = []
            if missing:
                parts.append("missing internal targets: %s" % ", ".join(missing))
            if ambiguous:
                parts.append("ambiguous internal targets: %s" % "; ".join(ambiguous))
            raise PALPublishedRuntimeError(
                "PAL ABI internal-dispatch preflight failed; " + " | ".join(parts)
            )
        return context, values

    def run(self, function_key=None, arguments=(), variadic_arguments=()):
        key = function_key or self.config.get("default_entry")
        if not key:
            raise PALPublishedRuntimeError("no execution entry was selected")
        record = self.resolve(key)
        function = self.load_callable(record)
        values = tuple(self._materialize_value(value) for value in arguments)
        if record.get("runtime_mode") == "abi_context":
            context, frame_values = self._context(record, values, variadic_arguments)
            with context.activate():
                return self._invoke_adapted(function, frame_values)
        return self._invoke_adapted(function, values)


def run(function=None, arguments=(), variadic_arguments=()):
    return PALProjectRuntime().run(function, arguments, variadic_arguments)
'''


STATE_MACHINE_SOURCE = r'''# Generated PAL executable state-machine entry.

from PAL_project_runtime import PALProjectRuntime


def run(function=None, arguments=(), variadic_arguments=()):
    runtime = PALProjectRuntime()
    return runtime.run(function, arguments, variadic_arguments)


def main():
    result = run()
    print("\nPAL RESULT:", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


PAL_RUNNER_SOURCE = r'''# Generated by PALExecInterface.

from __future__ import annotations

import argparse

from PAL_project_runtime import PALProcessExit, PALProjectRuntime


def parse_value(text):
    raw = str(text).strip()
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw.lower() in {"none", "null"}:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run a published PAL state machine")
    parser.add_argument("--function", "-f", help="name, function id, decimal address, or 0x address")
    parser.add_argument("--arg", action="append", default=[], help="fixed argument; use str:text for a C string")
    parser.add_argument("--vararg", action="append", default=[], help="variadic argument")
    parser.add_argument("--list", action="store_true", help="list published functions")
    args = parser.parse_args(argv)

    runtime = PALProjectRuntime()
    print("PAL EXEC BUILD:", runtime.config.get("build", "unknown"), flush=True)
    if args.list:
        for record in runtime.records:
            print(
                "%s  %-28s  %-12s %s"
                % (
                    record.get("entry_hex") or "-",
                    record.get("name") or "-",
                    record.get("runtime_mode") or "-",
                    "SHIM" if record.get("is_shim_boundary") else "",
                )
            )
        return 0

    values = [parse_value(value) for value in args.arg]
    varargs = [parse_value(value) for value in args.vararg]
    try:
        result = runtime.run(args.function, values, varargs)
    except PALProcessExit as exc:
        print("\nPAL PROCESS EXIT:", exc.code)
        return int(exc.code) if isinstance(exc.code, int) else 1
    print("\nPAL RESULT:", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


class PALExecPublisher:
    """Publish one frozen PAL project into a controlled execution workspace."""

    def __init__(self, pal_root: Path, project_root: Path) -> None:
        self.pal_root = Path(pal_root).resolve()
        self.project_root = Path(project_root).resolve()
        self.manifest_path = self.project_root / PROJECT_MANIFEST
        self.manifest = _read_json(self.manifest_path)
        self.records: List[Dict[str, Any]] = [
            dict(record) for record in list(self.manifest.get("functions") or [])
        ]
        self.warnings: List[str] = []
        self.entry_plans: Dict[str, Any] = {}
        self.call_plans: Dict[str, Any] = {}
        self.function_records: List[Dict[str, Any]] = []
        self.internal_call_targets: set[str] = set()
        self.external_targets: set[str] = set()
        self.thunk_targets: set[str] = set()

    def _artifact_path(self, record: Mapping[str, Any], kind: str) -> Optional[Path]:
        artifacts = dict(record.get("artifacts") or {})
        detail = dict(artifacts.get(kind) or {})
        relative = detail.get("path")
        if not relative:
            return None
        return (self.project_root / str(relative)).resolve()

    def _validate_project(self) -> None:
        if self.manifest.get("format") != "pal_function_bundle":
            self.warnings.append(
                "unexpected manifest format %r" % self.manifest.get("format")
            )
        if not self.records:
            raise PALExecInterfaceError("project manifest contains no functions")
        helpers = self.pal_root / "PALhelpers.py"
        abi = self.pal_root / "PALABI.py"
        missing = [str(path) for path in (helpers, abi) if not path.is_file()]
        if missing:
            raise PALExecInterfaceError(
                "live PAL runtime modules are missing: %s" % ", ".join(missing)
            )

    def _merge_plans(self, destination: Dict[str, Any], source: Mapping[str, Any]) -> None:
        for key, value in source.items():
            previous = destination.get(str(key))
            if previous is not None and _canonical_json(previous) != _canonical_json(value):
                raise PALExecInterfaceError("conflicting ABI plan identity: %s" % key)
            destination[str(key)] = value

    def _prepare_record(self, record: Mapping[str, Any], stage: Path) -> Optional[Dict[str, Any]]:
        if record.get("status") != "decompiled":
            return None
        executable_path = self._artifact_path(record, "executable")
        if executable_path is None or not executable_path.is_file():
            self.warnings.append(
                "%s: executable artifact missing" % (record.get("qualified_name") or record.get("name"))
            )
            return None
        source = executable_path.read_text(encoding="utf-8")
        compile(source, str(executable_path), "exec")
        module_stem = _safe_module_stem(record)
        published_relative = Path("functions") / (module_stem + ".py")
        published_path = stage / published_relative
        _write_text(published_path, source)
        py_compile.compile(str(published_path), doraise=True)

        imports = _python_imports(source)
        runtime_mode = "abi_context" if _source_uses_abi(source) else "legacy_direct"
        prepared = dict(record)
        prepared.update(
            {
                "module_stem": module_stem,
                "published_module": published_relative.as_posix(),
                "published_sha256": _sha256_file(published_path),
                "runtime_mode": runtime_mode,
                "python_parameter_count": _function_parameters(
                    source, record.get("python_symbol")
                ),
                "runtime_imports": imports,
            }
        )

        icecube_path = self._artifact_path(record, "icecube")
        entry_plan_id = None
        if icecube_path is not None and icecube_path.is_file():
            icecube = _read_json(icecube_path)
            entries, calls = _extract_abi_plans(icecube)
            self._merge_plans(self.entry_plans, entries)
            self._merge_plans(self.call_plans, calls)
            if len(entries) == 1:
                entry_plan_id = next(iter(entries))
            elif entries:
                expected = "function_entry:%s" % record.get("entry")
                if expected in entries:
                    entry_plan_id = expected
                else:
                    self.warnings.append(
                        "%s: multiple entry plans; no exact entry match"
                        % (record.get("qualified_name") or record.get("name"))
                    )
            icecube_target = stage / "icecubes" / icecube_path.name
            icecube_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(icecube_path, icecube_target)
            prepared["published_icecube"] = str(
                Path("icecubes") / icecube_path.name
            )
        elif runtime_mode == "abi_context":
            self.warnings.append(
                "%s: ABI-emitted function has no Icecube metadata"
                % (record.get("qualified_name") or record.get("name"))
            )

        prepared["entry_plan_id"] = entry_plan_id
        boundary = bool(
            record.get("external")
            or record.get("thunk")
            or str(record.get("namespace") or "") == "<EXTERNAL>"
        )
        prepared["is_shim_boundary"] = boundary
        if boundary:
            for key in ("name", "python_symbol", "active_name", "ssa_name"):
                value = record.get(key)
                if value:
                    self.thunk_targets.add(str(value))
        return prepared

    def _collect_call_targets(self) -> None:
        published_name_records: Dict[str, List[Dict[str, Any]]] = {}
        for record in self.function_records:
            for alias in _record_key_names(record):
                published_name_records.setdefault(alias, []).append(record)

        for plan in self.call_plans.values():
            target = dict(plan.get("target") or {})
            name = target.get("name")
            if not name:
                continue
            name = str(name)
            compatibility = dict(plan.get("target_compatibility") or {})
            linkage = dict(plan.get("linkage_contract") or {})
            internal = bool(
                str(plan.get("dispatch_policy") or "") == "PAL_internal_dispatch"
                or compatibility.get("internal_target") is True
                or linkage.get("semantic_internal") is True
            )
            if internal:
                self.internal_call_targets.add(name)
                matches = list(published_name_records.get(name) or [])
                unique = []
                seen = set()
                for record in matches:
                    identity = str(
                        record.get("function_id")
                        or record.get("entry_hex")
                        or record.get("name")
                    )
                    if identity not in seen:
                        seen.add(identity)
                        unique.append(record)
                if len(unique) == 1:
                    record = unique[0]
                    if record.get("is_shim_boundary"):
                        record["is_shim_boundary"] = False
                        record["boundary_overridden_by_abi_internal"] = True
                        self.warnings.append(
                            "ABI internal dispatch overrode stale shim boundary for %s"
                            % name
                        )
                elif not unique:
                    self.warnings.append(
                        "internal ABI target %s has no published function alias" % name
                    )
                else:
                    self.warnings.append(
                        "internal ABI target %s is ambiguous across published functions"
                        % name
                    )
                continue
            self.external_targets.add(name)

        # Exact internal target spellings cannot also be emitted as external
        # or thunk shims.  Runtime performs the same subtraction defensively.
        self.external_targets.difference_update(self.internal_call_targets)
        self.thunk_targets.difference_update(self.internal_call_targets)

    def _copy_runtime_dependencies(self, stage: Path) -> List[str]:
        runtime_root = stage / "runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        required = {"PALhelpers", "PALABI"}
        for record in self.function_records:
            for name in list(record.get("runtime_imports") or []):
                if name.startswith("PAL"):
                    required.add(name)

        copied: List[str] = []
        queue = list(sorted(required))
        seen: set[str] = set()
        while queue:
            module_name = queue.pop(0)
            if module_name in seen:
                continue
            seen.add(module_name)
            source_path = self.pal_root / (module_name + ".py")
            if not source_path.is_file():
                if module_name in {"PALhelpers", "PALABI"}:
                    raise PALExecInterfaceError(
                        "required runtime module is missing: %s" % source_path
                    )
                self.warnings.append(
                    "runtime import %s was not copied because no root module exists"
                    % module_name
                )
                continue
            target_path = runtime_root / source_path.name
            shutil.copy2(source_path, target_path)
            py_compile.compile(str(target_path), doraise=True)
            copied.append(module_name)
            try:
                source = source_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for dependency in _python_imports(source):
                if dependency.startswith("PAL") and dependency not in seen:
                    queue.append(dependency)

        _write_text(runtime_root / "PALMEM.py", PALMEM_SOURCE)
        py_compile.compile(str(runtime_root / "PALMEM.py"), doraise=True)
        copied.append("PALMEM")
        _write_text(runtime_root / "__init__.py", "# PAL published runtime package.\n")
        return sorted(set(copied))

    def _copy_project_authorities(self, stage: Path) -> None:
        for name in (
            PROJECT_MANIFEST,
            PROJECT_DISPATCH,
            PROJECT_JUMP_TABLE,
            PROJECT_ONCS,
            "PAL_stdio_strings.json",
        ):
            source = self.project_root / name
            if source.is_file():
                shutil.copy2(source, stage / name)
        _write_text(stage / "functions" / "__init__.py", "# Published PAL functions.\n")
        _write_text(stage / "shims" / "__init__.py", "# PAL explicit external shims.\n")

    def _default_entry(self) -> Optional[str]:
        candidates = [
            record
            for record in self.function_records
            if not record.get("is_shim_boundary")
        ]
        if not candidates:
            return None
        record = sorted(candidates, key=_entry_priority)[0]
        return str(
            record.get("function_id")
            or record.get("entry_hex")
            or record.get("name")
        )

    def _publish_config(self, stage: Path, runtime_modules: Sequence[str]) -> Dict[str, Any]:
        default_entry = self._default_entry()
        unresolved = sorted(
            name
            for name in self.external_targets | self.thunk_targets
            if name not in _PRINT_SHIM_NAMES
            and name not in _STDIO_SHIM_NAMES
            and name not in _NORETURN_SHIM_NAMES
        )
        config: Dict[str, Any] = {
            "format": "pal_execution_publish",
            "schema_version": 1,
            "build": PAL_EXEC_INTERFACE_BUILD,
            "published_at_utc": _utc_now(),
            "source_project": str(self.project_root),
            "source_manifest_sha256": _sha256_file(self.manifest_path),
            "program": dict(self.manifest.get("program") or {}),
            "default_entry": default_entry,
            "functions": self.function_records,
            "counts": {
                "manifest_functions": len(self.records),
                "published_functions": len(self.function_records),
                "entry_plans": len(self.entry_plans),
                "call_plans": len(self.call_plans),
            },
            "runtime_modules": list(runtime_modules),
            "internal_call_targets": sorted(self.internal_call_targets),
            "external_targets": sorted(self.external_targets),
            "thunk_targets": sorted(self.thunk_targets),
            "shim_policy": {
                "print_family": "python_stream_io_v2",
                "stdio_family": "python_fgets_string_v1",
                "no_return_family": "python_system_exit_v1",
                "unknown_external": "closed_runtime_trap",
                "shimmed_names": sorted(
                    _PRINT_SHIM_NAMES | _STDIO_SHIM_NAMES | _NORETURN_SHIM_NAMES
                ),
                "unresolved_known_targets": unresolved,
            },
            "known_limitations": [
                "clear-case proof-of-concept runtime, not native process emulation",
                "SysV AMD64 is the only ABI backend currently expected",
                "ELF data sections, relocations, globals, heap, TLS, and permissions are not fully mapped",
                "indirect calls and unresolved dynamic-linker behavior fail closed",
                "threads, signals, exceptions, and dynamic code generation are unsupported",
                "stdio formatting and line input are bounded Python shims, not full libc",
                "static C strings require an optional PAL_stdio_strings.json overlay until ELF data publication lands",
                "a published function may still fail when its frozen ABI plan is deferred",
            ],
            "warnings": list(self.warnings),
        }
        _write_json(stage / EXEC_CONFIG, config)
        _write_json(
            stage / ABI_PLAN_INDEX,
            {
                "format": "pal_abi_plan_index",
                "schema_version": 1,
                "entry_plans": self.entry_plans,
                "call_plans": self.call_plans,
            },
        )
        return config

    def publish(self) -> Tuple[Path, Dict[str, Any]]:
        self._validate_project()
        parent = self.project_root
        stage = Path(
            tempfile.mkdtemp(
                prefix=".%s.stage." % EXECUTE_DIRECTORY,
                dir=str(parent),
            )
        )
        target = parent / EXECUTE_DIRECTORY
        backup = parent / (EXECUTE_DIRECTORY + ".previous")
        try:
            (stage / "functions").mkdir(parents=True, exist_ok=True)
            (stage / "icecubes").mkdir(parents=True, exist_ok=True)
            (stage / "shims").mkdir(parents=True, exist_ok=True)

            for record in self.records:
                prepared = self._prepare_record(record, stage)
                if prepared is not None:
                    self.function_records.append(prepared)
            if not self.function_records:
                raise PALExecInterfaceError(
                    "no decompiled executable function could be published"
                )

            self._collect_call_targets()
            runtime_modules = self._copy_runtime_dependencies(stage)
            self._copy_project_authorities(stage)
            _write_text(stage / "shims" / "PALShims.py", PALSHIMS_SOURCE)
            _write_text(stage / "PAL_project_runtime.py", PAL_PROJECT_RUNTIME_SOURCE)
            _write_text(stage / "PAL_runner.py", PAL_RUNNER_SOURCE)
            _write_text(stage / "state_machine.py", STATE_MACHINE_SOURCE)
            for path in (
                stage / "shims" / "PALShims.py",
                stage / "PAL_project_runtime.py",
                stage / "PAL_runner.py",
                stage / "state_machine.py",
            ):
                py_compile.compile(str(path), doraise=True)

            config = self._publish_config(stage, runtime_modules)
            _write_text(
                stage / "PUBLISH_COMPLETE",
                "%s\n%s\n" % (PAL_EXEC_INTERFACE_BUILD, config["published_at_utc"]),
            )

            if backup.exists():
                shutil.rmtree(backup)
            if target.exists():
                os.replace(target, backup)
            os.replace(stage, target)
            if backup.exists():
                shutil.rmtree(backup)
            return target, config
        except Exception:
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            if not target.exists() and backup.exists():
                os.replace(backup, target)
            raise


class PALExecInterface:
    def __init__(self, pal_root: Optional[Path] = None) -> None:
        self.pal_root = Path(pal_root or Path(__file__).resolve().parent).resolve()

    def discover_projects(self) -> List[Path]:
        found: Dict[str, Path] = {}
        for dirname in PROJECT_DIRECTORY_NAMES:
            base = self.pal_root / dirname
            if not base.is_dir():
                continue
            for child in sorted(base.iterdir(), key=lambda path: path.name.lower()):
                if child.is_dir() and (child / PROJECT_MANIFEST).is_file():
                    found[str(child.resolve())] = child.resolve()
        return sorted(found.values(), key=lambda path: path.name.lower())

    def resolve_project(self, value: str) -> Path:
        raw = Path(str(value)).expanduser()
        candidates: List[Path] = []
        if raw.is_absolute() or raw.parent != Path("."):
            candidates.append(raw)
        candidates.append(self.pal_root / raw)
        for dirname in PROJECT_DIRECTORY_NAMES:
            candidates.append(self.pal_root / dirname / raw)
        for candidate in candidates:
            candidate = candidate.resolve()
            if candidate.is_dir() and (candidate / PROJECT_MANIFEST).is_file():
                return candidate
        matches = [path for path in self.discover_projects() if path.name == str(value)]
        if len(matches) == 1:
            return matches[0]
        raise PALExecInterfaceError("PAL project not found: %s" % value)

    def publish(self, project: Path) -> Tuple[Path, Dict[str, Any]]:
        return PALExecPublisher(self.pal_root, project).publish()

    def run_published(
        self,
        project: Path,
        function: Optional[str],
        arguments: Sequence[Any],
        variadic_arguments: Sequence[Any],
    ) -> int:
        execute = project / EXECUTE_DIRECTORY
        runner = execute / "PAL_runner.py"
        config_path = execute / EXEC_CONFIG
        complete_path = execute / "PUBLISH_COMPLETE"
        if not runner.is_file() or not config_path.is_file() or not complete_path.is_file():
            raise PALExecInterfaceError(
                "project is not published; run PUBLISH FOR EXEC first"
            )
        published_config = _read_json(config_path)
        published_build = str(published_config.get("build") or "")
        complete_build = complete_path.read_text(encoding="utf-8").splitlines()[0].strip()
        if (
            published_build != PAL_EXEC_INTERFACE_BUILD
            or complete_build != PAL_EXEC_INTERFACE_BUILD
        ):
            raise PALExecInterfaceError(
                "published execute workspace is stale (%s / %s); republish with %s"
                % (published_build or "unknown", complete_build or "unknown", PAL_EXEC_INTERFACE_BUILD)
            )
        command = [sys.executable, str(runner)]
        if function:
            command.extend(["--function", str(function)])
        for value in arguments:
            command.extend(["--arg", str(value)])
        for value in variadic_arguments:
            command.extend(["--vararg", str(value)])
        return subprocess.call(command, cwd=str(execute))

    def _choose_project(self) -> Optional[Path]:
        projects = self.discover_projects()
        if not projects:
            print("No PAL projects found beneath project/ or projects/.")
            return None
        print("\nPAL PROJECTS")
        for index, path in enumerate(projects, 1):
            published = " [PUBLISHED]" if (path / EXECUTE_DIRECTORY / "PUBLISH_COMPLETE").is_file() else ""
            print("  %2d. %s%s" % (index, path.name, published))
        while True:
            raw = input("Select project [q quits]: ").strip()
            if raw.lower() in {"q", "quit", "exit"}:
                return None
            try:
                index = int(raw)
            except ValueError:
                print("Enter a project number.")
                continue
            if 1 <= index <= len(projects):
                return projects[index - 1]
            print("Project number out of range.")

    def _published_functions(self, project: Path) -> List[Dict[str, Any]]:
        config_path = project / EXECUTE_DIRECTORY / EXEC_CONFIG
        if not config_path.is_file():
            return []
        return list(_read_json(config_path).get("functions") or [])

    def _choose_function(self, project: Path) -> Optional[str]:
        records = [
            record
            for record in self._published_functions(project)
            if not record.get("is_shim_boundary")
        ]
        if not records:
            print("No published executable functions.")
            return None
        records.sort(key=_entry_priority)
        default = records[0]
        print("\nPUBLISHED FUNCTIONS")
        visible = records[:60]
        for index, record in enumerate(visible, 1):
            print(
                "  %2d. %-26s %-12s %s"
                % (
                    index,
                    str(record.get("name") or "-")[:26],
                    record.get("entry_hex") or "-",
                    record.get("runtime_mode") or "-",
                )
            )
        if len(records) > len(visible):
            print("  ... %d more; enter a name/address directly" % (len(records) - len(visible)))
        raw = input(
            "Function [Enter=%s]: "
            % (default.get("name") or default.get("entry_hex"))
        ).strip()
        if not raw:
            return str(
                default.get("function_id")
                or default.get("entry_hex")
                or default.get("name")
            )
        try:
            index = int(raw)
        except ValueError:
            return raw
        if 1 <= index <= len(visible):
            record = visible[index - 1]
            return str(
                record.get("function_id")
                or record.get("entry_hex")
                or record.get("name")
            )
        return raw

    def interactive(self) -> int:
        print("PAL EXECUTION INTERFACE")
        print("BUILD:", PAL_EXEC_INTERFACE_BUILD)
        while True:
            project = self._choose_project()
            if project is None:
                return 0
            while True:
                published = (project / EXECUTE_DIRECTORY / "PUBLISH_COMPLETE").is_file()
                print("\nPROJECT:", project.name)
                print("  [P] PUBLISH FOR EXEC")
                print("  [R] RUN PUBLISHED STATE MACHINE%s" % ("" if published else " [not published]"))
                print("  [B] PUBLISH AND RUN")
                print("  [C] CHOOSE ANOTHER PROJECT")
                print("  [Q] QUIT")
                action = input("Action: ").strip().lower()
                if action in {"q", "quit", "exit"}:
                    return 0
                if action in {"c", "change", "back"}:
                    break
                if action not in {"p", "r", "b"}:
                    print("Unknown action.")
                    continue
                if action in {"p", "b"}:
                    print("\nPUBLISH FOR EXEC:", project)
                    target, config = self.publish(project)
                    print("Published:", target)
                    print(
                        "Functions=%d  entry-plans=%d  call-plans=%d"
                        % (
                            config["counts"]["published_functions"],
                            config["counts"]["entry_plans"],
                            config["counts"]["call_plans"],
                        )
                    )
                    unresolved = config["shim_policy"]["unresolved_known_targets"]
                    if unresolved:
                        print("Closed unresolved shims:", ", ".join(unresolved[:20]))
                    published = True
                if action in {"r", "b"}:
                    if not published:
                        print("Publish the project first.")
                        continue
                    function = self._choose_function(project)
                    if function is None:
                        continue
                    raw_args = input("Fixed args, comma separated [none]: ").strip()
                    arguments = [
                        _parse_scalar(value)
                        for value in raw_args.split(",")
                        if value.strip()
                    ]
                    raw_varargs = input("Variadic args, comma separated [none]: ").strip()
                    variadic = [
                        _parse_scalar(value)
                        for value in raw_varargs.split(",")
                        if value.strip()
                    ]
                    print("\nRUN:", function)
                    status = self.run_published(project, function, arguments, variadic)
                    print("PAL runner exit status:", status)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish a frozen PAL project for controlled execution and run it"
    )
    parser.add_argument("--root", help="PAL repository root; defaults to this module's directory")
    parser.add_argument("--project", help="project name or path")
    parser.add_argument("--publish", action="store_true", help="publish project into execute/")
    parser.add_argument("--run", action="store_true", help="run published project")
    parser.add_argument("--function", help="function name, id, or address")
    parser.add_argument("--arg", action="append", default=[], help="fixed argument")
    parser.add_argument("--vararg", action="append", default=[], help="variadic argument")
    parser.add_argument("--list-projects", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    interface = PALExecInterface(Path(args.root).expanduser() if args.root else None)

    if args.list_projects:
        for project in interface.discover_projects():
            print(project)
        return 0

    if not args.project and not args.publish and not args.run:
        return interface.interactive()
    if not args.project:
        parser.error("--project is required with --publish or --run")

    project = interface.resolve_project(args.project)
    if args.publish:
        target, config = interface.publish(project)
        print("Published:", target)
        print(json.dumps(config["counts"], sort_keys=True))
    if args.run:
        values = [_parse_scalar(value) for value in args.arg]
        varargs = [_parse_scalar(value) for value in args.vararg]
        return interface.run_published(
            project,
            args.function,
            values,
            varargs,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PALExecInterfaceError as exc:
        print("PAL EXEC ERROR:", exc, file=sys.stderr)
        raise SystemExit(2)
