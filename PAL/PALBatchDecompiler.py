# ============================================================
# PAL BATCH DECOMPILER
# BUILD: batch_v2d_explicit_stdio_overlay_authority
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
import traceback

from PALHumanizer import (
    FUNCTION_REGISTRY_FILENAME,
    HUMANIZER_VERSION,
    PALFunctionNameRegistry,
)


BATCH_FORMAT = "pal_function_bundle"
BATCH_SCHEMA_VERSION = 1
BATCH_BUILD = "batch_v2d_explicit_stdio_overlay_authority"


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

        self.pipeline_class = pipeline_class or _pipeline_class()
        self.decompiler_interface = decompiler_interface
        self.monitor = monitor
        self.include_external = bool(include_external)
        self.ensure_projection_pair = bool(ensure_projection_pair)
        self.freeze_icecubes = bool(freeze_icecubes)
        self.write_readable_files = bool(write_readable_files)
        self.keep_success_logs = bool(keep_success_logs)
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

    def _decompile_one(self, function, record):
        stem = record["module_stem"]
        log_path = os.path.join(self.functions_root, stem + ".pipeline.log")
        temp_log = "%s.tmp.%d" % (log_path, os.getpid())
        dispatcher = None

        try:
            with self._stdio_overlay_environment():
                with open(
                    temp_log, "wt", encoding="utf-8", newline="\n"
                ) as log:
                    with (
                        contextlib.redirect_stdout(log),
                        contextlib.redirect_stderr(log),
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

            self._freeze_icecube(dispatcher, getattr(dispatcher, "PAL", None), record)

            if self.keep_success_logs:
                self._preserve_pipeline_log(temp_log, log_path)
                self._record_artifact(record, "pipeline_log", log_path)
            else:
                if os.path.exists(temp_log):
                    os.unlink(temp_log)
                # Remove a stale failure log left by an earlier batch run.
                # A successful public snapshot must not retain obsolete local
                # traceback paths merely because the function now decompiles.
                if os.path.exists(log_path):
                    os.unlink(log_path)

            record["status"] = "decompiled"
            return True

        except Exception as exc:
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
                with open(temp_log, "at", encoding="utf-8", newline="\n") as log:
                    log.write("\n=== PAL BATCH FAILURE ===\n")
                    traceback.print_exc(file=log)
                self._preserve_pipeline_log(temp_log, log_path)
                self._record_artifact(record, "pipeline_log", log_path)
            except Exception as log_exc:
                record["warnings"].append(
                    "could not preserve pipeline log: %s"
                    % self._public_text(log_exc)
                )
            return False

        finally:
            if os.path.exists(temp_log):
                try:
                    os.unlink(temp_log)
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
