# ============================================================
# PAL BATCH DECOMPILER
# BUILD: batch_v2h_final_abi_authority_publication
#
# Live PyGhidra orchestration layer.  The single-function PAL pipeline remains
# authoritative; this module only enumerates Ghidra functions, invokes that
# pipeline once per function, and freezes detached artifacts.
# ============================================================

import contextlib
import hashlib
import importlib
import json
import os
import pprint
import re
import sys
import threading
import time
import traceback

from PALHumanizer import (
    FUNCTION_REGISTRY_FILENAME,
    HUMANIZER_VERSION,
    PALFunctionNameRegistry,
)


BATCH_FORMAT = "pal_function_bundle"
BATCH_SCHEMA_VERSION = 1
BATCH_BUILD = "batch_v2h_final_abi_authority_publication"


def _safe_call(obj, method, default=None, *args):
    if obj is None:
        return default
    try:
        fn = getattr(obj, method, None)
        if fn is None:
            return default
        return fn(*args)
    except Exception:
        return default


def _safe_int(value, default=None):
    if value is None:
        return default
    try:
        if hasattr(value, "getOffset"):
            return int(value.getOffset())
        return int(value)
    except Exception:
        return default


def _safe_text(value, default=None):
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _portable_relpath(path, root):
    """
    Return a slash-normalized path relative to the PAL repository root.

    Absolute paths remain an internal file-I/O detail and must not cross the
    generated artifact boundary.
    """
    path = os.path.abspath(os.fspath(path))
    root = os.path.abspath(os.fspath(root))
    try:
        relative = os.path.relpath(path, root)
    except Exception:
        relative = os.path.basename(path)
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        relative = os.path.basename(path)
    return relative.replace(os.sep, "/")


def _portable_text(text, root):
    """
    Rewrite PAL-root absolute paths embedded in diagnostics as repository-
    relative paths. Other text is preserved verbatim.
    """
    if text is None:
        return text
    value = str(text)
    root = os.path.abspath(os.fspath(root))
    prefixes = {
        root.rstrip("/\\") + os.sep,
        root.rstrip("/\\") + "/",
        root.rstrip("/\\") + "\\",
    }
    for prefix in sorted(prefixes, key=len, reverse=True):
        value = value.replace(prefix, "")
    return value


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_text(path, text):
    path = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    temp = "%s.tmp.%d" % (path, os.getpid())
    try:
        with open(temp, "wt", encoding="utf-8", newline="\n") as handle:
            handle.write(str(text))
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return path


def _atomic_write_json(path, payload):
    text = json.dumps(
        payload,
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"
    return _atomic_write_text(path, text)


def _read_json_file(path):
    with open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def _plan_core_hashes(index):
    """Return deterministic plan_class/plan_id -> immutable-core SHA mapping."""
    out = {}
    if not isinstance(index, dict):
        return out
    for collection_name in ("entry_plans", "call_plans"):
        collection = index.get(collection_name) or {}
        if not isinstance(collection, dict):
            continue
        for plan_id, record in collection.items():
            if not isinstance(record, dict):
                continue
            plan_class = record.get("plan_class")
            digest = record.get("plan_core_sha256")
            if plan_class and digest:
                out[(str(plan_class), str(plan_id))] = str(digest)
    return out


def _authorized_plan_ids(report):
    out = []
    for contract in list((report or {}).get("contracts") or []):
        if not isinstance(contract, dict):
            continue
        if (
            (contract.get("repair") or {}).get(
                "emitter_repair_authorized"
            )
            is not True
        ):
            continue
        plan_id = (contract.get("call") or {}).get("plan_id")
        if plan_id is not None:
            out.append(str(plan_id))
    return sorted(set(out))


class _PALPipelineTee:
    """Mirror one Python text stream into per-stream and combined raw logs."""

    def __init__(
        self,
        stream_name,
        stream_handle,
        combined_handle,
        mirror_handle,
        lock,
    ):
        self.stream_name = str(stream_name)
        self.stream_handle = stream_handle
        self.combined_handle = combined_handle
        self.mirror_handle = mirror_handle
        self.lock = lock
        self.encoding = getattr(mirror_handle, "encoding", "utf-8")
        self.errors = getattr(mirror_handle, "errors", "replace")

    def write(self, value):
        text = str(value)
        if not text:
            return 0
        with self.lock:
            self.stream_handle.write(text)
            self.stream_handle.flush()
            self.combined_handle.write(text)
            self.combined_handle.flush()
            if self.mirror_handle is not None:
                try:
                    self.mirror_handle.write(text)
                    self.mirror_handle.flush()
                except Exception:
                    pass
        return len(text)

    def flush(self):
        with self.lock:
            for handle in (
                self.stream_handle,
                self.combined_handle,
                self.mirror_handle,
            ):
                if handle is None:
                    continue
                try:
                    handle.flush()
                except Exception:
                    pass

    def isatty(self):
        try:
            return bool(self.mirror_handle.isatty())
        except Exception:
            return False

    def fileno(self):
        if self.mirror_handle is None:
            raise OSError("PAL pipeline tee has no OS file descriptor")
        return self.mirror_handle.fileno()


def _atomic_promote_file(source, destination):
    source = os.path.abspath(os.fspath(source))
    destination = os.path.abspath(os.fspath(destination))
    parent = os.path.dirname(destination)
    if parent:
        os.makedirs(parent, exist_ok=True)
    os.replace(source, destination)
    return destination


def _slug(text, fallback="function"):
    value = re.sub(r"[^0-9A-Za-z_]+", "_", str(text or ""))
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        value = fallback
    if value[0].isdigit():
        value = "fn_" + value
    return value[:96]


def _module_stem(name, address, address_width=16):
    address = int(address)
    width = max(int(address_width), 8)
    return "f_%0*x_%s" % (width, address, _slug(name))


def _python_symbol(lines):
    pattern = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(")
    for line in list(lines or []):
        match = pattern.match(str(line))
        if match:
            return match.group(1)
    return None


def _normalize_lines(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value.splitlines()
    try:
        return [str(line) for line in list(value)]
    except Exception:
        return None


def _program_info(program, path_root=None):
    image_base = _safe_int(_safe_call(program, "getImageBase"))
    language = _safe_call(program, "getLanguage")
    compiler = _safe_call(program, "getCompilerSpec")
    language_id = _safe_call(language, "getLanguageID")
    compiler_id = _safe_call(compiler, "getCompilerSpecID")
    executable_path = _safe_text(
        _safe_call(program, "getExecutablePath")
    )
    if executable_path:
        if path_root:
            executable_path = _portable_relpath(
                executable_path, path_root
            )
        elif os.path.isabs(executable_path):
            executable_path = os.path.basename(executable_path)
        executable_path = executable_path.replace(os.sep, "/")
    executable_format = _safe_call(program, "getExecutableFormat")
    return {
        "name": _safe_text(_safe_call(program, "getName"), "unknown"),
        "executable_path": executable_path,
        "executable_path_policy": (
            "relative_to_pal_repository_root_or_basename"
        ),
        "executable_format": _safe_text(executable_format),
        "image_base": image_base,
        "image_base_hex": hex(image_base) if isinstance(image_base, int) else None,
        "language_id": _safe_text(language_id),
        "compiler_spec_id": _safe_text(compiler_id),
    }


def _function_info(function, ordinal, address_width=16):
    name = _safe_text(_safe_call(function, "getName"), "FUN_unknown")
    entry = _safe_int(_safe_call(function, "getEntryPoint"))
    body = _safe_call(function, "getBody")
    body_min = _safe_int(_safe_call(body, "getMinAddress"))
    body_max = _safe_int(_safe_call(body, "getMaxAddress"))
    namespace = _safe_text(_safe_call(function, "getParentNamespace"))
    calling_convention = _safe_text(
        _safe_call(function, "getCallingConventionName")
    )
    module_stem = (
        _module_stem(name, entry, address_width=address_width)
        if isinstance(entry, int) else
        "f_unknown_%06d_%s" % (int(ordinal), _slug(name))
    )
    return {
        "ordinal": int(ordinal),
        "name": name,
        "qualified_name": "%s::%s" % (namespace, name) if namespace else name,
        "entry": entry,
        "entry_hex": hex(entry) if isinstance(entry, int) else None,
        "body_min": body_min,
        "body_min_hex": hex(body_min) if isinstance(body_min, int) else None,
        "body_max": body_max,
        "body_max_hex": hex(body_max) if isinstance(body_max, int) else None,
        "namespace": namespace,
        "calling_convention": calling_convention,
        "external": bool(_safe_call(function, "isExternal", False)),
        "thunk": bool(_safe_call(function, "isThunk", False)),
        "inline": bool(_safe_call(function, "isInline", False)),
        "no_return": bool(_safe_call(function, "hasNoReturn", False)),
        "module_stem": module_stem,
        "module": "functions.%s" % module_stem,
        "python_symbol": None,
        "status": "pending",
        "warnings": [],
        "artifacts": {},
    }


def _address_width(program):
    pointer_size = _safe_int(_safe_call(program, "getDefaultPointerSize"))
    if isinstance(pointer_size, int) and pointer_size > 0:
        return max(8, pointer_size * 2)
    return 16


def _make_decompiler_interface():
    from ghidra.app.decompiler import DecompInterface
    return DecompInterface()


def _make_monitor():
    from ghidra.util.task import ConsoleTaskMonitor
    return ConsoleTaskMonitor()


def _pipeline_class():
    module = importlib.import_module("PALDecompilerPipeline")
    return module.PALDecompilerPipeline


def _extract_projection_lines(dispatcher, result):
    pal = getattr(dispatcher, "PAL", None)
    executable = _normalize_lines(getattr(pal, "pycode_executable", None))
    readable = _normalize_lines(getattr(pal, "pycode_readable", None))

    if isinstance(result, dict):
        executable = executable or _normalize_lines(
            result.get("executable") or result.get("exec")
        )
        readable = readable or _normalize_lines(result.get("readable"))
    elif executable is None:
        executable = _normalize_lines(result)

    # Backward-compatible single-stream PAL output is executable authority.
    if executable is None and pal is not None:
        executable = _normalize_lines(getattr(pal, "pycode", None))

    return pal, readable, executable


def _ensure_projection_pair(pal, readable, executable):
    """Use the active emitter's paired API only when run_all did not do so."""
    if pal is None:
        return readable, executable
    if readable is not None and executable is not None:
        return readable, executable

    emitter_module = importlib.import_module("PALemitter")
    emitter = emitter_module.PALemitter(pal)
    emit_pair = getattr(emitter, "emit_function_pair", None)
    if not callable(emit_pair):
        return readable, executable

    pair = emit_pair()
    if isinstance(pair, dict):
        readable = _normalize_lines(pair.get("readable")) or readable
        executable = _normalize_lines(pair.get("executable")) or executable
    readable = _normalize_lines(getattr(pal, "pycode_readable", None)) or readable
    executable = _normalize_lines(getattr(pal, "pycode_executable", None)) or executable
    return readable, executable


def _module_text(record, lines):
    header = [
        "# Generated by PAL %s" % BATCH_BUILD,
        "# Ghidra function: %s" % record.get("qualified_name"),
        "# Entry address: %s" % record.get("entry_hex"),
        "# This executable projection remains governed by its PAL icecube metadata.",
        "",
    ]
    return "\n".join(header + list(lines or [])) + "\n"


def _readable_text(record, lines):
    header = [
        "# PAL readable projection; this file is not execution authority.",
        "# Ghidra function: %s" % record.get("qualified_name"),
        "# Entry address: %s" % record.get("entry_hex"),
        "",
    ]
    return "\n".join(header + list(lines or [])) + "\n"


def _dispatch_source(
    records, manifest_name, jump_table_name, name_registry_name
):
    compact = []
    for record in records:
        compact.append({
            "name": record.get("name"),
            "qualified_name": record.get("qualified_name"),
            "address": record.get("entry"),
            "address_hex": record.get("entry_hex"),
            "module": record.get("module"),
            "python_symbol": record.get("python_symbol"),
            "status": record.get("status"),
            "external": bool(record.get("external")),
            "thunk": bool(record.get("thunk")),
            "function_id": record.get("function_id"),
            "generated_name": record.get("generated_name"),
            "operator_name": record.get("operator_name"),
            "active_name": record.get("active_name"),
        })

    literal = pprint.pformat(tuple(compact), width=100, sort_dicts=True)
    return '''# Generated by PAL batch_v1_function_modules_and_dispatch
# Deterministic function dispatch table.  Modules are loaded lazily.

import importlib
import json
import os

MANIFEST_PATH = %r
JUMP_TABLE_PATH = %r
NAME_REGISTRY_PATH = %r
FUNCTIONS = %s

FUNCTIONS_BY_ADDRESS = {
    record["address"]: record
    for record in FUNCTIONS
    if isinstance(record.get("address"), int)
}
FUNCTIONS_BY_ID = {
    record["function_id"]: record
    for record in FUNCTIONS
    if record.get("function_id")
}

FUNCTIONS_BY_NAME = {}
for _record in FUNCTIONS:
    FUNCTIONS_BY_NAME.setdefault(_record["name"], []).append(_record)
    qualified = _record.get("qualified_name")
    if qualified and qualified != _record["name"]:
        FUNCTIONS_BY_NAME.setdefault(qualified, []).append(_record)


def _registry_records():
    path = os.path.join(os.path.dirname(__file__), NAME_REGISTRY_PATH)
    try:
        with open(path, "rt", encoding="utf-8") as handle:
            return dict(json.load(handle).get("functions", {}) or {})
    except (OSError, ValueError, TypeError):
        return {}


def _address(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    return None


def records_for_name(name):
    name = str(name)
    matches = list(FUNCTIONS_BY_NAME.get(name, ()))
    if not matches:
        for function_id, contract in _registry_records().items():
            if name not in {
                contract.get("generated_name"), contract.get("operator_name"),
                contract.get("active_name"),
            }:
                continue
            record = FUNCTIONS_BY_ID.get(function_id)
            if record is not None and record not in matches:
                matches.append(record)
    return tuple(matches)


def resolve(key):
    address = _address(key)
    if address is not None:
        record = FUNCTIONS_BY_ADDRESS.get(address)
        if record is None:
            raise KeyError("unknown PAL function address: %%r" %% (key,))
        return record

    matches = records_for_name(key)
    if not matches:
        raise KeyError("unknown PAL function name: %%r" %% (key,))
    if len(matches) != 1:
        addresses = [record.get("address_hex") for record in matches]
        raise KeyError("ambiguous PAL function name %%r: %%s" %% (key, addresses))
    return matches[0]


def load_module(key):
    record = resolve(key)
    if record.get("status") != "decompiled":
        raise RuntimeError(
            "PAL function %%s is not decompiled (status=%%s)"
            %% (record.get("qualified_name"), record.get("status"))
        )
    return importlib.import_module(record["module"])


def load_callable(key):
    record = resolve(key)
    module = load_module(key)
    symbol = record.get("python_symbol")
    if not symbol:
        raise RuntimeError("PAL function has no emitted Python symbol")
    return getattr(module, symbol)
''' % (manifest_name, jump_table_name, name_registry_name, literal)


class PALBatchDecompiler:
    """
    Enumerate and decompile every internal Ghidra function independently.

    No cross-function semantic inference occurs here.  The manifest is the
    stable boundary for the future call-graph/linker layer.
    """

    def __init__(
        self,
        program,
        output_root=None,
        pipeline_class=None,
        decompiler_interface=None,
        monitor=None,
        include_external=False,
        ensure_projection_pair=True,
        freeze_icecubes=True,
        write_readable_files=False,
        keep_success_logs=False,
        mirror_pipeline_stdio=False,
        progress=True,
        pipeline_entrypoint="run_all",
    ):
        if program is None:
            raise ValueError("PAL batch decompiler requires a Ghidra Program")

        self.program = program

        # output_root is the PAL repository root.  Recover the Ghidra program
        # name and scope every batch artifact beneath project/<project_name>.
        project_name = _safe_text(
            _safe_call(self.program, "getName"), "unknown"
        ).strip() or "unknown"
        project_name = os.path.basename(project_name)
        pal_root = os.path.abspath(output_root or os.getcwd())
        self.pal_root = pal_root
        self.project_name = project_name
        self.output_root = os.path.join(
            pal_root, "project", project_name
        )
        self.output_root_relative = _portable_relpath(
            self.output_root, self.pal_root
        )
        self.functions_root = os.path.join(self.output_root, "functions")
        self.manifest_path = os.path.join(
            self.output_root, "PAL_function_manifest.json"
        )
        self.jump_table_path = os.path.join(
            self.output_root, "PAL_jump_table.json"
        )
        self.dispatch_path = os.path.join(self.output_root, "PAL_dispatch.py")
        self.name_registry_path = os.path.join(
            self.output_root, "PAL_ONCS.json"
        )
        self.stdio_strings_path = os.path.join(
            self.output_root, "PAL_stdio_strings.json"
        )
        self.static_string_report = {
            "status": "not_run",
            "artifact": os.path.basename(self.stdio_strings_path),
            "strings": 0,
        }
        self.abi_custody_path = os.path.join(
            self.output_root, "PAL_abi_custody.json"
        )
        self.abi_custody_report = {
            "status": "not_run",
            "version": None,
            "summary": {},
            "artifact": os.path.basename(self.abi_custody_path),
        }
        self.abi_plan_index_path = os.path.join(
            self.output_root, "PAL_abi_plan_index.json"
        )
        self.abi_plan_alias_audit_path = os.path.join(
            self.output_root, "PAL_abi_plan_alias_audit.json"
        )
        self.abi_final_authority_path = os.path.join(
            self.output_root, "PAL_abi_final_authority.json"
        )
        self.abi_pre_emitter_custody_path = os.path.join(
            self.output_root,
            "PAL_abi_custody.pre_emitter_v52.json",
        )
        self.abi_pre_emitter_plan_index_path = os.path.join(
            self.output_root,
            "PAL_abi_plan_index.pre_emitter_v52.json",
        )
        self.abi_pre_emitter_alias_audit_path = os.path.join(
            self.output_root,
            "PAL_abi_plan_alias_audit.pre_emitter_v52.json",
        )
        self.abi_pre_emitter_custody_report = None
        self.abi_pre_emitter_plan_index = None
        self.abi_pre_emitter_alias_audit = None
        self.abi_final_authority_report = {
            "status": "not_run",
            "build": "batch_v2h_final_abi_authority_publication",
            "phase": None,
            "failures": [],
        }
        self._live_pipeline_by_entry = {}
        self.holy_ghost_reemit_report = {
            "status": "not_run",
            "build": "batch_v2h_final_abi_authority_publication",
            "authorized_functions": 0,
            "re_emitted_functions": 0,
            "failures": [],
        }

        self.pipeline_class = pipeline_class or _pipeline_class()
        self.decompiler_interface = decompiler_interface
        self.monitor = monitor
        self.include_external = bool(include_external)
        self.ensure_projection_pair = bool(ensure_projection_pair)
        self.freeze_icecubes = bool(freeze_icecubes)
        self.write_readable_files = bool(write_readable_files)
        self.keep_success_logs = bool(keep_success_logs)
        self.mirror_pipeline_stdio = bool(mirror_pipeline_stdio)
        self.progress = bool(progress)
        self.pipeline_entrypoint = str(pipeline_entrypoint or "run_all")

        self._owns_decompiler_interface = decompiler_interface is None
        self.records = []
        self.excluded_external = []
        self.status = "created"
        self.address_width = _address_width(program)
        self.discovered_count = 0
        self.name_registry = None

    def _print(self, message):
        if self.progress:
            print(str(message))

    def _public_path(self, path):
        return _portable_relpath(path, self.pal_root)

    def _public_text(self, text):
        return _portable_text(text, self.pal_root)

    def _program_info_public(self):
        return _program_info(self.program, self.pal_root)

    def _preserve_pipeline_log(self, source_path, destination_path):
        """
        Persist pipeline diagnostics after removing the machine-local PAL root.
        """
        with open(source_path, "rt", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        return _atomic_write_text(
            destination_path,
            self._public_text(text),
        )

    def _publish_static_strings(self):
        """
        Publish initialized Ghidra string data before any function emitter runs.

        This is a program-level artifact boundary. The emitter and execution
        publisher remain consumers and never inspect the live Ghidra Program.
        """
        try:
            from PALStaticStringPublisher import publish_static_strings

            report = publish_static_strings(
                self.program,
                self.stdio_strings_path,
            )
            self.static_string_report = dict(report or {})
            self.static_string_report["artifact"] = os.path.basename(
                self.stdio_strings_path
            )
            self.static_string_report["path"] = self._public_path(
                self.stdio_strings_path
            )
            self._print(
                "PAL strings: %d published -> %s"
                % (
                    int(self.static_string_report.get("strings") or 0),
                    self._public_path(self.stdio_strings_path),
                )
            )
        except Exception as exc:
            self.static_string_report = {
                "status": "failed",
                "artifact": os.path.basename(self.stdio_strings_path),
                "path": self._public_path(self.stdio_strings_path),
                "strings": 0,
                "error": {
                    "type": type(exc).__name__,
                    "message": self._public_text(str(exc)),
                },
                "policy": (
                    "nonfatal_readable_projection_retains_pointer_arguments"
                ),
            }
            self._print(
                "PAL strings: FAILED (%s: %s)"
                % (
                    type(exc).__name__,
                    self._public_text(str(exc)),
                )
            )

    @contextlib.contextmanager
    def _stdio_overlay_environment(self):
        """
        Bind the exact current-project overlay while one function pipeline runs.

        PALemitter treats PAL_STDIO_STRINGS as explicit authority.  Scoping the
        value here prevents cross-project address collisions while preserving
        the caller's prior environment in a long-lived PyGhidra interpreter.
        """
        key = "PAL_STDIO_STRINGS"
        previous_present = key in os.environ
        previous_value = os.environ.get(key)

        if os.path.isfile(self.stdio_strings_path):
            os.environ[key] = self.stdio_strings_path
        else:
            os.environ.pop(key, None)

        try:
            yield
        finally:
            if previous_present:
                os.environ[key] = previous_value
            else:
                os.environ.pop(key, None)

    def _inspect_abi_custody(self):
        """Run the whole-project ABI custody join after all icecubes exist."""
        if not self.freeze_icecubes:
            self.abi_custody_report = {
                "status": "not_run",
                "reason": "icecube_freeze_disabled",
                "artifact": os.path.basename(self.abi_custody_path),
            }
            return self.abi_custody_report
        try:
            from PALABICustodyInspector import (
                PAL_ABI_CUSTODY_INSPECTOR_VERSION,
                inspect_project,
            )

            if PAL_ABI_CUSTODY_INSPECTOR_VERSION != (
                "v1b_canonical_project_plan_index"
            ):
                raise RuntimeError(
                    "PAL batch v2h requires PALABICustodyInspector "
                    "v1b_canonical_project_plan_index, loaded %r"
                    % PAL_ABI_CUSTODY_INSPECTOR_VERSION
                )

            report = inspect_project(
                self.output_root,
                records=self.records,
            )
            self.abi_custody_report = dict(report or {})
            self.abi_custody_report["artifact"] = os.path.basename(
                self.abi_custody_path
            )
            self._print(
                "PAL ABI custody: %s linked=%d unresolved=%d "
                "ghost-resolved=%d ghost-deferred=%d"
                % (
                    self.abi_custody_report.get("status"),
                    int(
                        (
                            self.abi_custody_report.get("summary")
                            or {}
                        ).get("internal_calls_linked")
                        or 0
                    ),
                    int(
                        (
                            self.abi_custody_report.get("summary")
                            or {}
                        ).get("internal_calls_unresolved")
                        or 0
                    ),
                    int(
                        (
                            self.abi_custody_report.get("summary")
                            or {}
                        ).get("ghost_repairs_resolved")
                        or 0
                    ),
                    int(
                        (
                            self.abi_custody_report.get("summary")
                            or {}
                        ).get("ghost_repairs_deferred")
                        or 0
                    ),
                )
            )
        except Exception as exc:
            self.abi_custody_report = {
                "status": "failed",
                "artifact": os.path.basename(self.abi_custody_path),
                "error": {
                    "type": type(exc).__name__,
                    "message": self._public_text(str(exc)),
                    "traceback": [
                        self._public_text(line)
                        for line in traceback.format_exc().splitlines()
                    ],
                },
                "summary": {},
                "policy": (
                    "cross_function_ABI_custody_failure_is_manifest_visible_"
                    "and_execution_publication_must_fail_closed"
                ),
            }
            self._print(
                "PAL ABI custody: FAILED (%s: %s)"
                % (
                    type(exc).__name__,
                    self._public_text(str(exc)),
                )
            )
        return self.abi_custody_report

    def _snapshot_pre_emitter_abi_authority(self):
        """Freeze the exact custody/index state used to authorize v52."""
        required = (
            self.abi_custody_path,
            self.abi_plan_index_path,
            self.abi_plan_alias_audit_path,
        )
        missing = [path for path in required if not os.path.isfile(path)]
        if missing:
            raise RuntimeError(
                "PAL batch v2h cannot snapshot pre-emitter ABI authority; "
                "missing: %s" % ", ".join(missing)
            )

        self.abi_pre_emitter_custody_report = _read_json_file(
            self.abi_custody_path
        )
        self.abi_pre_emitter_plan_index = _read_json_file(
            self.abi_plan_index_path
        )
        self.abi_pre_emitter_alias_audit = _read_json_file(
            self.abi_plan_alias_audit_path
        )

        if (
            self.abi_pre_emitter_custody_report.get("version")
            != "v1b_canonical_project_plan_index"
        ):
            raise RuntimeError(
                "pre-emitter custody report is not inspector v1b"
            )
        if (
            (
                self.abi_pre_emitter_plan_index.get("summary")
                or {}
            ).get("core_conflicts")
        ):
            raise RuntimeError(
                "pre-emitter ABI authority contains immutable-core conflicts"
            )

        _atomic_write_json(
            self.abi_pre_emitter_custody_path,
            self.abi_pre_emitter_custody_report,
        )
        _atomic_write_json(
            self.abi_pre_emitter_plan_index_path,
            self.abi_pre_emitter_plan_index,
        )
        _atomic_write_json(
            self.abi_pre_emitter_alias_audit_path,
            self.abi_pre_emitter_alias_audit,
        )
        self._print(
            "PAL ABI authority snapshot: %s"
            % self._public_path(
                self.abi_pre_emitter_plan_index_path
            )
        )

    def _refresh_record_icecube_hashes(self, custody_report):
        by_name = {
            str(item.get("icecube")): item
            for item in list(
                (custody_report or {}).get("icecubes") or []
            )
            if isinstance(item, dict) and item.get("icecube")
        }
        refreshed = 0
        for record in self.records:
            artifacts = record.get("artifacts") or {}
            descriptor = artifacts.get("icecube") or {}
            path_text = descriptor.get("path")
            if not path_text:
                continue
            matched = by_name.get(os.path.basename(path_text))
            if not isinstance(matched, dict):
                continue
            digest = matched.get("sha256")
            if not digest:
                continue
            descriptor["sha256"] = str(digest)
            artifacts["icecube"] = descriptor
            record["artifacts"] = artifacts
            refreshed += 1
        return refreshed

    def _publish_final_abi_authority(self):
        """Rejoin final cubes and publish post-v52 project ABI authority.

        PALemitter v52 may refreeze authorized caller icecubes. The first
        inspector pass therefore cannot remain the final runtime publication
        authority. This second inspector pass restores custody annotations and
        plan stamps to the final cubes, then Batch verifies immutable-core and
        repair-authorization continuity before publishing the final index.
        """
        from PALABICustodyInspector import (
            PAL_ABI_CUSTODY_INSPECTOR_VERSION,
            inspect_project,
        )
        from PALABIPlanCanonicalizer import (
            PAL_ABI_PLAN_CANONICALIZER_VERSION,
        )

        if PAL_ABI_CUSTODY_INSPECTOR_VERSION != (
            "v1b_canonical_project_plan_index"
        ):
            raise RuntimeError(
                "PAL batch v2h final authority requires inspector v1b"
            )
        if PAL_ABI_PLAN_CANONICALIZER_VERSION != (
            "v1_immutable_plan_identity"
        ):
            raise RuntimeError(
                "PAL batch v2h final authority requires canonicalizer v1"
            )
        if not isinstance(
            self.abi_pre_emitter_plan_index, dict
        ):
            raise RuntimeError(
                "PAL batch v2h has no frozen pre-emitter plan index"
            )

        pre_report = dict(
            self.abi_pre_emitter_custody_report or {}
        )
        pre_index = dict(
            self.abi_pre_emitter_plan_index or {}
        )
        pre_authorized = _authorized_plan_ids(pre_report)

        final_report = inspect_project(
            self.output_root,
            records=self.records,
        )
        final_index = _read_json_file(
            self.abi_plan_index_path
        )
        final_alias_audit = _read_json_file(
            self.abi_plan_alias_audit_path
        )
        final_authorized = _authorized_plan_ids(final_report)

        failures = []
        pre_core = _plan_core_hashes(pre_index)
        final_core = _plan_core_hashes(final_index)
        if pre_core != final_core:
            missing = sorted(
                "%s:%s" % key
                for key in set(pre_core) - set(final_core)
            )
            added = sorted(
                "%s:%s" % key
                for key in set(final_core) - set(pre_core)
            )
            changed = sorted(
                "%s:%s" % key
                for key in set(pre_core) & set(final_core)
                if pre_core[key] != final_core[key]
            )
            failures.append({
                "kind": "batch_v2h_plan_core_continuity_failure",
                "missing": missing,
                "added": added,
                "changed": changed,
            })

        if pre_authorized != final_authorized:
            failures.append({
                "kind": (
                    "batch_v2h_authorized_repair_identity_drift"
                ),
                "pre_emitter": pre_authorized,
                "final": final_authorized,
            })

        final_call_plans = dict(
            final_index.get("call_plans") or {}
        )
        absent_authorized = [
            plan_id for plan_id in final_authorized
            if plan_id not in final_call_plans
        ]
        if absent_authorized:
            failures.append({
                "kind": (
                    "batch_v2h_authorized_plan_missing_from_final_index"
                ),
                "plan_ids": absent_authorized,
            })

        reemit = dict(self.holy_ghost_reemit_report or {})
        expected_contracts = int(
            reemit.get("authorized_contracts") or 0
        )
        if expected_contracts != len(final_authorized):
            failures.append({
                "kind": (
                    "batch_v2h_reemit_authorized_contract_count_mismatch"
                ),
                "emitter_report": expected_contracts,
                "final_authority": len(final_authorized),
            })
        if (
            int(reemit.get("re_emitted_functions") or 0)
            != int(reemit.get("authorized_functions") or 0)
        ):
            failures.append({
                "kind": (
                    "batch_v2h_reemitted_function_count_mismatch"
                ),
                "authorized_functions": reemit.get(
                    "authorized_functions"
                ),
                "re_emitted_functions": reemit.get(
                    "re_emitted_functions"
                ),
            })
        if (
            (final_index.get("summary") or {}).get(
                "core_conflicts"
            )
        ):
            failures.append({
                "kind": "batch_v2h_final_index_core_conflict",
                "count": (
                    final_index.get("summary") or {}
                ).get("core_conflicts"),
            })

        if failures:
            receipt = {
                "format": "pal_abi_final_authority_receipt",
                "schema_version": 1,
                "build": BATCH_BUILD,
                "status": "failed",
                "phase": (
                    "post_emitter_v52_refreeze_"
                    "and_custody_refresh"
                ),
                "failures": failures,
            }
            self.abi_final_authority_report = receipt
            _atomic_write_json(
                self.abi_final_authority_path,
                receipt,
            )
            raise RuntimeError(
                "PAL batch v2h final ABI authority failed: %s"
                % failures
            )

        phase = (
            "post_emitter_v52_refreeze_and_custody_refresh"
        )
        final_index["phase"] = phase
        if isinstance(final_index.get("summary"), dict):
            final_index["summary"]["phase"] = phase
        final_alias_audit["phase"] = phase
        if isinstance(
            final_alias_audit.get("summary"), dict
        ):
            final_alias_audit["summary"]["phase"] = phase

        custody_health = {
            "status": final_report.get("status"),
            "summary": dict(
                final_report.get("summary") or {}
            ),
        }
        authority_overlay = {
            "kind": "pal_batch_final_abi_authority_v2h",
            "build": BATCH_BUILD,
            "phase": phase,
            "inspector_version": (
                PAL_ABI_CUSTODY_INSPECTOR_VERSION
            ),
            "canonicalizer_version": (
                PAL_ABI_PLAN_CANONICALIZER_VERSION
            ),
            "pre_emitter_plan_index": os.path.basename(
                self.abi_pre_emitter_plan_index_path
            ),
            "final_plan_index": os.path.basename(
                self.abi_plan_index_path
            ),
            "authorized_plan_ids": final_authorized,
            "emitter_v52_second_pass": reemit,
            "plan_core_continuity_verified": True,
            "authorized_repair_identity_verified": True,
            "final_custody_refresh_completed": True,
            "last_call_surface_inference_used": False,
            "target_name_inference_used": False,
        }
        final_index["custody_health"] = custody_health
        final_index["final_authority"] = authority_overlay
        final_index.setdefault(
            "acceptance_gates", {}
        ).update({
            "post_emitter_v52_refreeze_indexed": True,
            "final_custody_refresh_completed": True,
            "plan_core_continuity_verified": True,
            "authorized_repair_identity_verified": True,
            "authorized_repairs_present_in_final_index": True,
        })
        final_alias_audit["custody_health"] = custody_health
        final_alias_audit["final_authority"] = (
            authority_overlay
        )

        _atomic_write_json(
            self.abi_plan_index_path,
            final_index,
        )
        _atomic_write_json(
            self.abi_plan_alias_audit_path,
            final_alias_audit,
        )

        refreshed_records = self._refresh_record_icecube_hashes(
            final_report
        )
        final_icecube_hashes = {
            str(item.get("icecube")): str(item.get("sha256"))
            for item in list(final_report.get("icecubes") or [])
            if isinstance(item, dict)
            and item.get("icecube")
            and item.get("sha256")
        }
        icecube_set_digest = _sha256_bytes(
            json.dumps(
                final_icecube_hashes,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        )

        receipt = {
            "format": "pal_abi_final_authority_receipt",
            "schema_version": 1,
            "build": BATCH_BUILD,
            "status": "complete",
            "phase": phase,
            "project": self.project_name,
            "custody_health": custody_health,
            "inspector_version": (
                PAL_ABI_CUSTODY_INSPECTOR_VERSION
            ),
            "canonicalizer_version": (
                PAL_ABI_PLAN_CANONICALIZER_VERSION
            ),
            "pre_emitter": {
                "custody_report": os.path.basename(
                    self.abi_pre_emitter_custody_path
                ),
                "plan_index": os.path.basename(
                    self.abi_pre_emitter_plan_index_path
                ),
                "alias_audit": os.path.basename(
                    self.abi_pre_emitter_alias_audit_path
                ),
                "plan_core_hashes": len(pre_core),
                "authorized_plan_ids": pre_authorized,
            },
            "final": {
                "custody_report": os.path.basename(
                    self.abi_custody_path
                ),
                "plan_index": os.path.basename(
                    self.abi_plan_index_path
                ),
                "plan_index_sha256": _sha256_file(
                    self.abi_plan_index_path
                ),
                "alias_audit": os.path.basename(
                    self.abi_plan_alias_audit_path
                ),
                "alias_audit_sha256": _sha256_file(
                    self.abi_plan_alias_audit_path
                ),
                "plan_core_hashes": len(final_core),
                "authorized_plan_ids": final_authorized,
                "icecubes": len(final_icecube_hashes),
                "icecube_set_sha256": icecube_set_digest,
                "record_hashes_refreshed": refreshed_records,
            },
            "emitter_v52_second_pass": reemit,
            "acceptance_gates": {
                "plan_core_continuity_verified": True,
                "authorized_repair_identity_verified": True,
                "authorized_repairs_present_in_final_index": True,
                "emitter_reemit_counts_verified": True,
                "final_custody_refresh_completed": True,
                "final_index_postdates_emitter_refreeze": True,
                "generated_python_rewritten_by_finalizer": False,
                "cfg_rewritten_by_finalizer": False,
                "phi_rewritten_by_finalizer": False,
                "exec_tree_rewritten_by_finalizer": False,
            },
            "failures": [],
        }
        _atomic_write_json(
            self.abi_final_authority_path,
            receipt,
        )

        final_report = dict(final_report)
        final_report["emitter_v52_second_pass"] = reemit
        final_report["final_plan_index"] = {
            "artifact": os.path.basename(
                self.abi_plan_index_path
            ),
            "phase": phase,
            "sha256": _sha256_file(
                self.abi_plan_index_path
            ),
            "summary": final_index.get("summary"),
        }
        final_report["final_plan_alias_audit"] = {
            "artifact": os.path.basename(
                self.abi_plan_alias_audit_path
            ),
            "phase": phase,
            "sha256": _sha256_file(
                self.abi_plan_alias_audit_path
            ),
            "summary": final_alias_audit.get("summary"),
        }
        final_report["final_authority"] = {
            "artifact": os.path.basename(
                self.abi_final_authority_path
            ),
            "sha256": _sha256_file(
                self.abi_final_authority_path
            ),
            "status": receipt["status"],
            "phase": phase,
        }
        final_report.setdefault(
            "acceptance_gates", {}
        ).update({
            "final_post_emitter_plan_index_published": True,
            "plan_core_continuity_verified": True,
            "authorized_repair_identity_verified": True,
            "final_custody_refresh_completed": True,
        })
        _atomic_write_json(
            self.abi_custody_path,
            final_report,
        )

        self.abi_custody_report = final_report
        self.abi_final_authority_report = receipt
        self._print(
            "PAL final ABI authority: %s plans=%d authorized=%d health=%s"
            % (
                phase,
                len(final_core),
                len(final_authorized),
                final_report.get("status"),
            )
        )
        return receipt

    @staticmethod
    def _holy_ghost_contract_plan_id(contract):
        if not isinstance(contract, dict):
            return None
        call = contract.get("call") or {}
        value = call.get("plan_id")
        return str(value) if value is not None else None

    @staticmethod
    def _holy_ghost_contract_caller_entry(contract):
        if not isinstance(contract, dict):
            return None
        caller = contract.get("caller") or {}
        value = caller.get("entry")
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _publish_abi_custody_to_live_functions(self):
        """Attach exact inspector contracts to retained live PAL objects."""
        contracts = list(
            (self.abi_custody_report or {}).get("contracts") or []
        )
        by_entry = {}
        authorized_by_entry = {}
        failures = []

        for contract in contracts:
            if not isinstance(contract, dict):
                continue
            entry = self._holy_ghost_contract_caller_entry(contract)
            plan_id = self._holy_ghost_contract_plan_id(contract)
            if entry is None or plan_id is None:
                failures.append({
                    "kind": "batch_holy_ghost_contract_identity_incomplete_v2h",
                    "contract_id": contract.get("contract_id"),
                })
                continue
            by_entry.setdefault(entry, {})[plan_id] = contract
            if (
                (contract.get("repair") or {}).get(
                    "emitter_repair_authorized"
                ) is True
            ):
                authorized_by_entry.setdefault(entry, {})[
                    plan_id
                ] = contract

        for entry, contracts_by_plan in by_entry.items():
            live = self._live_pipeline_by_entry.get(entry)
            if live is None:
                if entry in authorized_by_entry:
                    failures.append({
                        "kind": "batch_holy_ghost_live_caller_missing_v2h",
                        "caller_entry": entry,
                        "plan_ids": sorted(authorized_by_entry[entry]),
                    })
                continue
            pal = live.get("pal")
            if pal is None:
                failures.append({
                    "kind": "batch_holy_ghost_live_pal_missing_v2h",
                    "caller_entry": entry,
                })
                continue
            pal.abi_custody_contracts_by_plan_id = dict(
                contracts_by_plan
            )
            pal.phi_abi_custody_contracts_by_plan_id = dict(
                contracts_by_plan
            )
            pal.abi_custody_inspector_version = (
                self.abi_custody_report.get("version")
            )
            pal.abi_custody_project_status = (
                self.abi_custody_report.get("status")
            )

        if failures:
            raise RuntimeError(
                "PAL batch v2h could not publish exact ABI custody to "
                "live functions: %s" % failures
            )
        return authorized_by_entry

    def _reemit_holy_ghost_functions(self):
        """Second emitter pass after exact cross-function custody exists.

        The first pass is required to freeze all functions for the inspector.
        The second pass is restricted to callers carrying an exact authorized
        repair contract. No pipeline layer before PALemitter is rerun.
        """
        report = {
            "status": "ready",
            "build": "batch_v2h_final_abi_authority_publication",
            "authority": (
                "PALABICustodyInspector_v1_exact_cross_function_contract"
            ),
            "authorized_functions": 0,
            "authorized_contracts": 0,
            "re_emitted_functions": 0,
            "re_emitted_entries": [],
            "failures": [],
            "pipeline_layers_rerun": ["PALemitter"],
            "upstream_layers_rerun": 0,
            "target_name_inference": 0,
            "last_call_inference": 0,
        }
        try:
            authorized = self._publish_abi_custody_to_live_functions()
            report["authorized_functions"] = len(authorized)
            report["authorized_contracts"] = sum(
                len(value) for value in authorized.values()
            )
            if not authorized:
                report["status"] = "not_required"
                self.holy_ghost_reemit_report = report
                self.abi_custody_report[
                    "emitter_v52_second_pass"
                ] = dict(report)
                _atomic_write_json(
                    self.abi_custody_path,
                    self.abi_custody_report,
                )
                return report

            emitter_module = importlib.import_module("PALemitter")
            emitter_class = getattr(emitter_module, "PALemitter")
            if getattr(emitter_class, "VERSION", None) != (
                "v52_holy_ghost_return_carrier_lowering"
            ):
                raise RuntimeError(
                    "PAL batch v2h requires PALemitter "
                    "v52_holy_ghost_return_carrier_lowering"
                )

            for entry in sorted(authorized):
                live = self._live_pipeline_by_entry.get(entry)
                if not isinstance(live, dict):
                    raise RuntimeError(
                        "retained live pipeline missing for caller 0x%x"
                        % entry
                    )
                dispatcher = live.get("dispatcher")
                pal = live.get("pal")
                record = live.get("record")
                if dispatcher is None or pal is None or record is None:
                    raise RuntimeError(
                        "incomplete retained live pipeline for caller 0x%x"
                        % entry
                    )

                emitter = emitter_class(pal)
                views = emitter.emit_function_pair()
                readable = _normalize_lines(views.get("readable"))
                executable = _normalize_lines(views.get("executable"))
                if not readable or not executable:
                    raise RuntimeError(
                        "PALemitter v52 produced incomplete projection pair "
                        "for caller 0x%x" % entry
                    )

                stem = record["module_stem"]
                executable_path = os.path.join(
                    self.functions_root, stem + ".exec.py"
                )
                executable_text = _module_text(record, executable)
                compile(executable_text, executable_path, "exec")
                _atomic_write_text(executable_path, executable_text)
                self._record_artifact(
                    record, "executable", executable_path
                )

                readable_path = os.path.join(
                    self.functions_root, stem + ".read.py"
                )
                _atomic_write_text(
                    readable_path,
                    _readable_text(record, readable),
                )
                self._record_artifact(
                    record, "readable", readable_path
                )

                record["python_symbol"] = _python_symbol(executable)
                record["holy_ghost_emitter_second_pass"] = {
                    "status": "re_emitted",
                    "emitter_version": emitter_class.VERSION,
                    "authorized_plan_ids": sorted(authorized[entry]),
                    "audit": dict(
                        getattr(
                            pal,
                            "emitter_holy_ghost_return_audit_v52",
                            {},
                        )
                        or {}
                    ),
                }
                self._freeze_icecube(dispatcher, pal, record)
                report["re_emitted_functions"] += 1
                report["re_emitted_entries"].append(entry)

            if report["re_emitted_functions"] != report[
                "authorized_functions"
            ]:
                raise RuntimeError(
                    "PAL batch v2h re-emission count mismatch"
                )
        except Exception as exc:
            report["status"] = "failed"
            report["failures"].append({
                "type": type(exc).__name__,
                "message": self._public_text(str(exc)),
                "traceback": [
                    self._public_text(line)
                    for line in traceback.format_exc().splitlines()
                ],
            })
            self.holy_ghost_reemit_report = report
            self.abi_custody_report[
                "emitter_v52_second_pass"
            ] = dict(report)
            _atomic_write_json(
                self.abi_custody_path,
                self.abi_custody_report,
            )
            raise

        self.holy_ghost_reemit_report = report
        self.abi_custody_report[
            "emitter_v52_second_pass"
        ] = dict(report)
        _atomic_write_json(
            self.abi_custody_path,
            self.abi_custody_report,
        )
        self._print(
            "PAL Holy Ghost emitter: %s functions=%d contracts=%d"
            % (
                report.get("status"),
                report.get("re_emitted_functions"),
                report.get("authorized_contracts"),
            )
        )
        return report

    def _cancelled(self):
        return bool(_safe_call(self.monitor, "isCancelled", False))

    def _functions(self):
        manager = _safe_call(self.program, "getFunctionManager")
        if manager is None:
            raise ValueError("Ghidra Program has no FunctionManager")
        iterator = _safe_call(manager, "getFunctions", None, True)
        if iterator is None:
            raise ValueError("FunctionManager.getFunctions(True) failed")
        try:
            functions = list(iterator)
        except TypeError:
            # Compatibility with Java iterators that expose hasNext/next but
            # are not surfaced as Python iterables by a particular bridge.
            functions = []
            has_next = getattr(iterator, "hasNext", None)
            next_item = getattr(iterator, "next", None)
            if not callable(has_next) or not callable(next_item):
                raise
            while has_next():
                functions.append(next_item())
        functions.sort(
            key=lambda fn: (
                _safe_int(_safe_call(fn, "getEntryPoint"), 1 << 127),
                _safe_text(_safe_call(fn, "getName"), ""),
            )
        )
        return functions

    def _base_manifest(self):
        decompiled = sum(r.get("status") == "decompiled" for r in self.records)
        failed = sum(r.get("status") == "failed" for r in self.records)
        skipped = sum(r.get("status") == "skipped_external" for r in self.records)
        return {
            "format": BATCH_FORMAT,
            "schema_version": BATCH_SCHEMA_VERSION,
            "build": BATCH_BUILD,
            "status": self.status,
            "program": self._program_info_public(),
            "output_root": self.output_root_relative,
            "output_root_base": "PAL_repository_root",
            "functions_directory": "functions",
            "directory_policy": (
                "portable_relative_non_destructive_manifest_authoritative"
            ),
            "pipeline_entrypoint": self.pipeline_entrypoint,
            "counts": {
                "discovered": self.discovered_count,
                "enumerated": len(self.records),
                "remaining_unprocessed": max(
                    sum(
                        record.get("status") == "pending"
                        for record in self.records
                    ),
                    0,
                ),
                "decompiled": decompiled,
                "failed": failed,
                "skipped_external": skipped,
            },
            "functions": list(self.records),
            "call_graph": {
                "status": "deferred_to_inter_function_relation_layer",
                "edges": [],
            },
            "abi_custody": dict(self.abi_custody_report or {}),
            "abi_final_authority": dict(
                self.abi_final_authority_report or {}
            ),
            "static_strings": dict(self.static_string_report or {}),
            "static_string_emitter_authority": {
                "transport": "scoped_environment",
                "key": "PAL_STDIO_STRINGS",
                "value_policy": (
                    "absolute_internal_path_to_current_project_overlay"
                ),
                "scope": "single_function_pipeline_run",
                "restoration": "restore_prior_environment_after_run",
                "cross_project_discovery_allowed": False,
            },
            "artifacts": {
                "dispatch": os.path.basename(self.dispatch_path),
                "jump_table": os.path.basename(self.jump_table_path),
                "manifest": os.path.basename(self.manifest_path),
                "name_registry": os.path.basename(self.name_registry_path),
                "stdio_strings": (
                    os.path.basename(self.stdio_strings_path)
                    if os.path.isfile(self.stdio_strings_path)
                    else None
                ),
                "abi_custody": (
                    os.path.basename(self.abi_custody_path)
                    if os.path.isfile(self.abi_custody_path)
                    else None
                ),
                "abi_plan_index": (
                    os.path.basename(self.abi_plan_index_path)
                    if os.path.isfile(self.abi_plan_index_path)
                    else None
                ),
                "abi_plan_alias_audit": (
                    os.path.basename(
                        self.abi_plan_alias_audit_path
                    )
                    if os.path.isfile(
                        self.abi_plan_alias_audit_path
                    )
                    else None
                ),
                "abi_final_authority": (
                    os.path.basename(
                        self.abi_final_authority_path
                    )
                    if os.path.isfile(
                        self.abi_final_authority_path
                    )
                    else None
                ),
                "abi_pre_emitter_custody": (
                    os.path.basename(
                        self.abi_pre_emitter_custody_path
                    )
                    if os.path.isfile(
                        self.abi_pre_emitter_custody_path
                    )
                    else None
                ),
                "abi_pre_emitter_plan_index": (
                    os.path.basename(
                        self.abi_pre_emitter_plan_index_path
                    )
                    if os.path.isfile(
                        self.abi_pre_emitter_plan_index_path
                    )
                    else None
                ),
                "abi_pre_emitter_alias_audit": (
                    os.path.basename(
                        self.abi_pre_emitter_alias_audit_path
                    )
                    if os.path.isfile(
                        self.abi_pre_emitter_alias_audit_path
                    )
                    else None
                ),
            },
            "name_registry": {
                "version": HUMANIZER_VERSION,
                "revision": (
                    self.name_registry.revision if self.name_registry else 0
                ),
                "identity_authority": (
                    "function_entry_address_or_stable_manifest_identity"
                ),
            },
        }

    def _write_manifest(self):
        return _atomic_write_json(self.manifest_path, self._base_manifest())

    def _write_name_registry(self):
        if self.name_registry is None:
            return None
        for record in self.records:
            function_id = self.name_registry.function_id_for_record(record)
            record.update(self.name_registry.manifest_fields(function_id))
        return _atomic_write_json(
            self.name_registry_path, self.name_registry.as_dict()
        )

    def _write_jump_table(self):
        table = []
        for record in self.records:
            table.append({
                "name": record.get("name"),
                "qualified_name": record.get("qualified_name"),
                "address": record.get("entry"),
                "address_hex": record.get("entry_hex"),
                "module": record.get("module"),
                "python_symbol": record.get("python_symbol"),
                "status": record.get("status"),
                "function_id": record.get("function_id"),
                "generated_name": record.get("generated_name"),
                "operator_name": record.get("operator_name"),
                "active_name": record.get("active_name"),
            })
        payload = {
            "kind": "pal_function_jump_table_v1",
            "program": self._program_info_public(),
            "functions": table,
        }
        return _atomic_write_json(self.jump_table_path, payload)

    def _write_dispatch(self):
        source = _dispatch_source(
            self.records,
            os.path.basename(self.manifest_path),
            os.path.basename(self.jump_table_path),
            os.path.basename(self.name_registry_path),
        )
        compile(source, self.dispatch_path, "exec")
        return _atomic_write_text(self.dispatch_path, source)

    def _write_package_init(self):
        path = os.path.join(self.functions_root, "__init__.py")
        text = (
            "# Generated PAL function-module package.\n"
            "# Use PAL_dispatch.resolve/load_module/load_callable for lookup.\n"
        )
        return _atomic_write_text(path, text)

    def _record_artifact(self, record, key, path):
        rel = os.path.relpath(path, self.output_root).replace(
            os.sep, "/"
        )
        record["artifacts"][key] = {
            "path": rel,
            "sha256": _sha256_file(path),
        }

    def _freeze_icecube(self, dispatcher, pal, record):
        if not self.freeze_icecubes or pal is None:
            return
        if getattr(pal, "code_document", None) is None:
            record["warnings"].append(
                "icecube unavailable: emitter produced no PALCodeDocument"
            )
            return
        try:
            try:
                icecube = importlib.import_module(
                    "PALIcecube_Humanizer_v3"
                )
            except ImportError:
                icecube = importlib.import_module("PALIcecube")
            path = os.path.join(
                self.functions_root,
                record["module_stem"] + ".icecube.json.gz",
            )
            # TEMPORARY EARLY-DEBUG POLICY:
            # Freeze any available PALCodeDocument even when readable and
            # executable projections are incomplete or their semantic
            # statement identities do not pair.  PALTermUI can still inspect
            # whichever projection survived.  Restore require_pair=True once
            # executable-wide artifact generation is stable.
            try:
                pal.project_function_name_registry = self.name_registry
            except Exception:
                pass
            try:
                icecube.freeze_pipeline(
                    dispatcher,
                    path,
                    require_pair=False,
                    function_registry=self.name_registry,
                )
            except TypeError as exc:
                if "function_registry" not in str(exc):
                    raise
                record["warnings"].append(
                    "legacy PALIcecube lacks project name registry custody"
                )
                icecube.freeze_pipeline(
                    dispatcher, path, require_pair=False
                )
            self._record_artifact(record, "icecube", path)
        except Exception as exc:
            record["warnings"].append("icecube freeze failed: %s" % exc)


    def _pipeline_capture_paths(self, stem):
        base = os.path.join(self.functions_root, stem)
        return {
            "combined": base + ".pipeline.log",
            "stdout": base + ".pipeline.stdout.log",
            "stderr": base + ".pipeline.stderr.log",
            "metadata": base + ".pipeline.capture.json",
        }

    def _pipeline_temp_paths(self, final_paths):
        suffix = ".tmp.%d" % os.getpid()
        return {
            key: value + suffix
            for key, value in final_paths.items()
            if key != "metadata"
        }

    def _append_pipeline_failure(self, temp_paths, failure_text):
        for key in ("stderr", "combined"):
            path = temp_paths.get(key)
            if not path:
                continue
            with open(path, "at", encoding="utf-8", newline="\n") as handle:
                handle.write(str(failure_text))
        if self.mirror_pipeline_stdio:
            try:
                sys.stderr.write(str(failure_text))
                sys.stderr.flush()
            except Exception:
                pass

    def _finalize_pipeline_capture(
        self,
        record,
        final_paths,
        temp_paths,
        *,
        outcome,
        started_ns,
        finished_ns,
    ):
        for key in ("stdout", "stderr", "combined"):
            _atomic_promote_file(temp_paths[key], final_paths[key])

        metadata = {
            "format": "pal_internal_pipeline_stream_capture",
            "schema_version": 1,
            "batch_build": BATCH_BUILD,
            "function": {
                "name": record.get("name"),
                "qualified_name": record.get("qualified_name"),
                "function_id": record.get("function_id"),
                "entry": record.get("entry"),
                "entry_hex": record.get("entry_hex"),
                "module_stem": record.get("module_stem"),
            },
            "outcome": str(outcome),
            "pipeline_entrypoint": self.pipeline_entrypoint,
            "keep_success_logs": self.keep_success_logs,
            "mirrored_to_process_stdio": self.mirror_pipeline_stdio,
            "started_time_ns": int(started_ns),
            "finished_time_ns": int(finished_ns),
            "elapsed_ns": max(int(finished_ns) - int(started_ns), 0),
            "raw_text_policy": (
                "exact_python_stdout_stderr_text_before_portability_rewrite"
            ),
            "streams": {},
        }
        for key in ("combined", "stdout", "stderr"):
            path = final_paths[key]
            metadata["streams"][key] = {
                "path": os.path.relpath(
                    path, self.output_root
                ).replace(os.sep, "/"),
                "bytes": os.path.getsize(path),
                "sha256": _sha256_file(path),
            }
        _atomic_write_json(final_paths["metadata"], metadata)

        self._record_artifact(
            record, "pipeline_log", final_paths["combined"]
        )
        self._record_artifact(
            record, "pipeline_stdout_log", final_paths["stdout"]
        )
        self._record_artifact(
            record, "pipeline_stderr_log", final_paths["stderr"]
        )
        self._record_artifact(
            record, "pipeline_capture", final_paths["metadata"]
        )

    def _remove_pipeline_capture(self, final_paths, temp_paths):
        for path in list(temp_paths.values()) + list(final_paths.values()):
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass

    def _decompile_one(self, function, record):
        stem = record["module_stem"]
        final_paths = self._pipeline_capture_paths(stem)
        temp_paths = self._pipeline_temp_paths(final_paths)
        dispatcher = None
        started_ns = time.time_ns()
        capture_finished_ns = started_ns
        original_stdout = sys.stdout
        original_stderr = sys.stderr

        # Remove incomplete temporary files from an interrupted prior run.
        for path in temp_paths.values():
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass

        try:
            with self._stdio_overlay_environment():
                with (
                    open(
                        temp_paths["stdout"],
                        "wt",
                        encoding="utf-8",
                        newline="\n",
                    ) as stdout_log,
                    open(
                        temp_paths["stderr"],
                        "wt",
                        encoding="utf-8",
                        newline="\n",
                    ) as stderr_log,
                    open(
                        temp_paths["combined"],
                        "wt",
                        encoding="utf-8",
                        newline="\n",
                    ) as combined_log,
                ):
                    lock = threading.RLock()
                    stdout_tee = _PALPipelineTee(
                        "stdout",
                        stdout_log,
                        combined_log,
                        (
                            original_stdout
                            if self.mirror_pipeline_stdio else None
                        ),
                        lock,
                    )
                    stderr_tee = _PALPipelineTee(
                        "stderr",
                        stderr_log,
                        combined_log,
                        (
                            original_stderr
                            if self.mirror_pipeline_stdio else None
                        ),
                        lock,
                    )
                    with (
                        contextlib.redirect_stdout(stdout_tee),
                        contextlib.redirect_stderr(stderr_tee),
                    ):
                        dispatcher = self.pipeline_class(
                            function,
                            self.program,
                            self.decompiler_interface,
                            self.monitor,
                        )
                        pipeline_run = getattr(
                            dispatcher, self.pipeline_entrypoint, None
                        )
                        if not callable(pipeline_run):
                            raise AttributeError(
                                "PAL pipeline has no callable entrypoint %r"
                                % self.pipeline_entrypoint
                            )
                        result = pipeline_run()
                        pal, readable, executable = (
                            _extract_projection_lines(
                                dispatcher, result
                            )
                        )
                        if self.ensure_projection_pair:
                            readable, executable = (
                                _ensure_projection_pair(
                                    pal, readable, executable
                                )
                            )

            if not executable:
                raise ValueError("PAL pipeline emitted no executable Python")
            if not readable:
                raise ValueError("PAL pipeline emitted no readable Python")

            executable_path = os.path.join(
                self.functions_root, stem + ".exec.py"
            )
            executable_text = _module_text(record, executable)
            compile(executable_text, executable_path, "exec")
            _atomic_write_text(executable_path, executable_text)
            self._record_artifact(record, "executable", executable_path)

            readable_path = os.path.join(
                self.functions_root, stem + ".read.py"
            )
            readable_text = _readable_text(record, readable)
            _atomic_write_text(readable_path, readable_text)
            self._record_artifact(record, "readable", readable_path)

            record["python_symbol"] = _python_symbol(executable)
            if record["python_symbol"] is None:
                record["warnings"].append(
                    "executable projection contains no top-level function definition"
                )

            live_pal = getattr(dispatcher, "PAL", None)
            self._freeze_icecube(
                dispatcher,
                live_pal,
                record,
            )
            entry = record.get("entry")
            call_result_candidates = list(
                getattr(
                    live_pal,
                    "compute_call_result_candidates",
                    [],
                )
                or []
            ) if live_pal is not None else []
            if (
                isinstance(entry, int)
                and live_pal is not None
                and call_result_candidates
            ):
                self._live_pipeline_by_entry[entry] = {
                    "dispatcher": dispatcher,
                    "pal": live_pal,
                    "record": record,
                    "candidate_plan_ids": sorted(
                        str(item.get("plan_id"))
                        for item in call_result_candidates
                        if isinstance(item, dict)
                        and item.get("plan_id") is not None
                    ),
                }

            capture_finished_ns = time.time_ns()
            if self.keep_success_logs:
                self._finalize_pipeline_capture(
                    record,
                    final_paths,
                    temp_paths,
                    outcome="decompiled",
                    started_ns=started_ns,
                    finished_ns=capture_finished_ns,
                )
            else:
                self._remove_pipeline_capture(
                    final_paths, temp_paths
                )

            record["status"] = "decompiled"
            return True

        except Exception as exc:
            capture_finished_ns = time.time_ns()
            failure_text = (
                "\n=== PAL BATCH FAILURE ===\n"
                + traceback.format_exc()
            )
            record["status"] = "failed"
            record["error"] = {
                "type": type(exc).__name__,
                "message": self._public_text(str(exc)),
                "traceback": [
                    self._public_text(line)
                    for line in traceback.format_exc().splitlines()
                ],
            }
            try:
                self._append_pipeline_failure(
                    temp_paths, failure_text
                )
                self._finalize_pipeline_capture(
                    record,
                    final_paths,
                    temp_paths,
                    outcome="failed",
                    started_ns=started_ns,
                    finished_ns=capture_finished_ns,
                )
            except Exception as log_exc:
                record["warnings"].append(
                    "could not preserve pipeline stream capture: %s"
                    % self._public_text(log_exc)
                )
            return False

        finally:
            for path in temp_paths.values():
                if os.path.exists(path):
                    try:
                        os.unlink(path)
                    except Exception:
                        pass

    def run(self):
        os.makedirs(self.output_root, exist_ok=True)
        os.makedirs(self.functions_root, exist_ok=True)
        self._write_package_init()

        # Program-wide static-data publication must precede the first
        # per-function pipeline/emitter pass.
        self._publish_static_strings()

        if self.decompiler_interface is None:
            self.decompiler_interface = _make_decompiler_interface()
        if self.monitor is None:
            self.monitor = _make_monitor()

        functions = self._functions()
        self.discovered_count = len(functions)
        self.records = [
            _function_info(
                function, ordinal, address_width=self.address_width
            )
            for ordinal, function in enumerate(functions)
        ]
        existing_registry = None
        if os.path.isfile(self.name_registry_path):
            try:
                with open(
                    self.name_registry_path, "rt", encoding="utf-8"
                ) as handle:
                    existing_registry = json.load(handle)
            except Exception as exc:
                self._print(
                    "PAL name registry ignored (unreadable): %s" % exc
                )
        self.name_registry = PALFunctionNameRegistry.from_manifest(
            self.records,
            program=self._program_info_public(),
            existing=existing_registry,
        )
        self._write_name_registry()
        self.status = "running"
        self._print(
            "PAL batch: %d Ghidra functions discovered in %s"
            % (len(functions), self._program_info_public().get("name"))
        )

        interrupted = False
        try:
            for ordinal, (function, record) in enumerate(
                zip(functions, self.records)
            ):
                if self._cancelled():
                    interrupted = True
                    break

                if record["external"] and not self.include_external:
                    record["status"] = "skipped_external"
                    self.excluded_external.append(record["entry"])
                    self._print(
                        "[%d/%d] skip external %s @ %s"
                        % (
                            ordinal + 1,
                            len(functions),
                            record["qualified_name"],
                            record["entry_hex"],
                        )
                    )
                    self._write_manifest()
                    self._write_name_registry()
                    continue

                self._print(
                    "[%d/%d] decompile %s @ %s"
                    % (
                        ordinal + 1,
                        len(functions),
                        record["qualified_name"],
                        record["entry_hex"],
                    )
                )
                ok = self._decompile_one(function, record)
                self._print(
                    "          %s -> %s"
                    % ("OK" if ok else "FAILED", record["module"])
                )
                self._write_manifest()
                self._write_name_registry()

        except KeyboardInterrupt:
            interrupted = True
            self._print("PAL batch interrupted by operator")
        finally:
            failed = any(r.get("status") == "failed" for r in self.records)
            self.status = (
                "interrupted" if interrupted else
                "partial" if failed else
                "complete"
            )
            # All per-function icecubes now exist.  The inspector joins
            # caller call-site plans to exact callee entry plans and refreshes
            # icecube hashes before the final project manifest is written.
            self._write_name_registry()
            self._write_manifest()
            self._inspect_abi_custody()
            if self.abi_custody_report.get("status") == "failed":
                raise RuntimeError(
                    "PAL ABI custody failed before emitter v52 second pass"
                )
            self._snapshot_pre_emitter_abi_authority()
            self._reemit_holy_ghost_functions()
            self._publish_final_abi_authority()

            self._write_jump_table()
            self._write_dispatch()
            self._write_name_registry()
            self._write_manifest()

            if self._owns_decompiler_interface:
                _safe_call(self.decompiler_interface, "dispose")

        manifest = self._base_manifest()
        self._print(
            "PAL batch %s: %d decompiled, %d failed, %d external skipped"
            % (
                self.status,
                manifest["counts"]["decompiled"],
                manifest["counts"]["failed"],
                manifest["counts"]["skipped_external"],
            )
        )
        self._print("Manifest: %s" % self._public_path(self.manifest_path))
        self._print("Dispatch: %s" % self._public_path(self.dispatch_path))
        return manifest


def decompile_program(program, output_root=None, **kwargs):
    """One-call PyGhidra integration entrypoint."""
    return PALBatchDecompiler(
        program,
        output_root=output_root,
        **kwargs
    ).run()


__all__ = [
    "PALBatchDecompiler",
    "decompile_program",
    "BATCH_BUILD",
    "BATCH_FORMAT",
    "BATCH_SCHEMA_VERSION",
]
