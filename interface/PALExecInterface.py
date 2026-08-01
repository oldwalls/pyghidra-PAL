# ============================================================
# PAL EXECUTION INTERFACE
# BUILD: pal_exec_interface_v1u_exact_integral_subregister_projection
# UI BUILD: pal_exec_interface_ui_v1v_compact_project_desk
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
import copy
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

from PALStaticStringCompleter import (
    BUILD as PAL_STATIC_STRING_COMPLETER_BUILD,
    complete_project_static_strings,
)
from PALABIPlanCanonicalizer import (
    PAL_ABI_PLAN_CANONICALIZER_VERSION,
    canonicalize_plan,
    compare_plans,
    stamp_plan,
)


PAL_EXEC_INTERFACE_BUILD = "pal_exec_interface_v1u_exact_integral_subregister_projection"
PAL_EXEC_INTERFACE_UI_BUILD = "pal_exec_interface_ui_v1v_compact_project_desk"
PROJECT_DIRECTORY_NAMES = ("project", "projects")
PROJECT_MANIFEST = "PAL_function_manifest.json"
PROJECT_DISPATCH = "PAL_dispatch.py"
PROJECT_JUMP_TABLE = "PAL_jump_table.json"
PROJECT_ONCS = "PAL_ONCS.json"
EXECUTE_DIRECTORY = "execute"
EXEC_CONFIG = "config.exec.json"
ABI_PLAN_INDEX = "PAL_abi_plans.json"
ABI_CUSTODY_REPORT = "PAL_abi_custody.json"
PROJECT_ABI_PLAN_INDEX = "PAL_abi_plan_index.json"
PROJECT_ABI_ALIAS_AUDIT = "PAL_abi_plan_alias_audit.json"
ABI_FINAL_AUTHORITY = "PAL_abi_final_authority.json"
ABI_PARTIAL_PUBLICATION = "PAL_abi_partial_publication.json"
ABI_ARGUMENT_BRIDGE = "PAL_abi_argument_bridge.json"
ABI_FINAL_PHASE = "post_emitter_v52_refreeze_and_custody_refresh"
ABI_FINAL_BATCH_BUILD = "batch_v2h_final_abi_authority_publication"
ABI_CUSTODY_INSPECTOR_VERSION = "v1b_canonical_project_plan_index"
HOLY_GHOST_EMITTER_VERSION = "v52_holy_ghost_return_carrier_lowering"
PAL_PROJECT_RUNTIME_TEMPLATE_VERSION = "v11_x86_64_register_family_truth_runtime"
PAL_ABI_RUNTIME_REQUIRED_VERSION = "v1d_x86_64_register_family_alias_truth"

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


def _truthy_environment(name: str, default: bool = False) -> bool:
    value = os.environ.get(str(name))
    if value is None:
        return bool(default)
    return str(value).strip().lower() not in {
        "", "0", "false", "no", "off",
    }



def _python_string_constant(
    path: Path,
    name: str,
) -> Optional[str]:
    """Read one literal module constant without importing the module."""
    try:
        tree = ast.parse(
            Path(path).read_text(encoding="utf-8"),
            filename=str(path),
        )
    except Exception:
        return None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, str):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == name
            ):
                return str(node.value.value)
    return None



_INIT_TRUNK_POLICIES = {
    "abort",
    "prompt",
    "trunk-init",
    "trunk-all",
}

_ABI_ARGUMENT_POLICIES = {
    "abort",
    "prompt",
    "bridge-safe",
    "diagnostic",
}

_ELF_INIT_EXACT_NAMES = {
    "_init",
    "__libc_csu_init",
    "elf_init",
}

_ELF_LIFECYCLE_AUXILIARY_NAMES = {
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
}


def _normalized_function_names(
    record: Mapping[str, Any],
) -> set[str]:
    names: set[str] = set()
    for raw in _record_key_names(record):
        text = str(raw).strip()
        if not text:
            continue
        terminal = text.split("::")[-1].strip().lower()
        names.add(terminal)
        names.add(terminal.lstrip("."))
    return names


def _elf_init_family_classification(
    record: Mapping[str, Any],
) -> Optional[str]:
    """Recognize narrow ELF lifecycle functions eligible for a trunk."""
    names = _normalized_function_names(record)
    if names & _ELF_INIT_EXACT_NAMES:
        return "elf_init_entry"
    if any(
        re.fullmatch(r"_+init_+", name)
        for name in names
    ):
        return "elf_init_entry"
    if any(
        name.startswith("__libc_csu_init")
        for name in names
    ):
        return "elf_init_entry"
    if names & _ELF_LIFECYCLE_AUXILIARY_NAMES:
        return "elf_lifecycle_auxiliary"
    return None


def _incomplete_internal_records(
    records: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for raw in records:
        record = dict(raw)
        status = str(record.get("status") or "").lower()
        if status in {"decompiled", "skipped_external"}:
            continue
        if (
            record.get("external")
            or str(record.get("namespace") or "") == "<EXTERNAL>"
        ):
            continue
        record["init_family_classification"] = (
            _elf_init_family_classification(record)
        )
        out.append(record)
    return out


def _record_identity_token(
    record: Mapping[str, Any],
) -> str:
    return str(
        record.get("function_id")
        or record.get("entry_hex")
        or record.get("entry")
        or record.get("qualified_name")
        or record.get("name")
        or "unknown"
    )


def _identity_projection(
    value: Mapping[str, Any],
) -> Dict[str, set[Any]]:
    """Project exact function identity fields without recursive plan discovery."""
    if not isinstance(value, Mapping):
        return {
            "names": set(),
            "entries": set(),
            "plan_ids": set(),
            "function_ids": set(),
        }

    names = set(_normalized_function_names(value))
    for key in (
        "function_name",
        "target_name",
        "callee_name",
        "caller_name",
        "symbol",
    ):
        raw = value.get(key)
        if raw not in (None, ""):
            terminal = str(raw).strip().split("::")[-1].lower()
            if terminal:
                names.add(terminal)
                names.add(terminal.lstrip("."))

    entries: set[int] = set()
    for key in (
        "entry",
        "target_entry",
        "callee_entry",
        "caller_entry",
        "semantic_endpoint_entry",
    ):
        raw = value.get(key)
        if isinstance(raw, int):
            entries.add(int(raw))
        elif isinstance(raw, str):
            try:
                entries.add(int(raw, 0))
            except ValueError:
                pass

    plan_ids = {
        str(raw)
        for raw in (
            value.get("entry_plan_id"),
            value.get("target_entry_plan_id"),
            value.get("entry_plan_lookup_key"),
            value.get("plan_id"),
        )
        if raw not in (None, "")
    }
    compatibility = value.get("target_compatibility")
    if isinstance(compatibility, Mapping):
        raw = compatibility.get("entry_plan_lookup_key")
        if raw not in (None, ""):
            plan_ids.add(str(raw))

    function_ids = {
        str(raw)
        for raw in (
            value.get("function_id"),
            value.get("target_function_id"),
            value.get("callee_function_id"),
            value.get("caller_function_id"),
        )
        if raw not in (None, "")
    }
    return {
        "names": names,
        "entries": entries,
        "plan_ids": plan_ids,
        "function_ids": function_ids,
    }


def _match_trunk_identity(
    value: Mapping[str, Any],
    trunks: Sequence[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    projection = _identity_projection(value)
    for trunk in trunks:
        trunk_names = set(trunk.get("normalized_names") or [])
        trunk_entry = trunk.get("entry")
        trunk_plan_id = str(trunk.get("entry_plan_id") or "")
        trunk_function_id = str(trunk.get("function_id") or "")

        shared_names = sorted(projection["names"] & trunk_names)
        if shared_names:
            return {
                "trunk_identity": trunk.get("identity"),
                "match_kind": "function_name",
                "match_value": shared_names[0],
            }
        if isinstance(trunk_entry, int) and trunk_entry in projection["entries"]:
            return {
                "trunk_identity": trunk.get("identity"),
                "match_kind": "entry",
                "match_value": hex(trunk_entry),
            }
        if trunk_plan_id and trunk_plan_id in projection["plan_ids"]:
            return {
                "trunk_identity": trunk.get("identity"),
                "match_kind": "entry_plan_id",
                "match_value": trunk_plan_id,
            }
        if trunk_function_id and trunk_function_id in projection["function_ids"]:
            return {
                "trunk_identity": trunk.get("identity"),
                "match_kind": "function_id",
                "match_value": trunk_function_id,
            }
    return None


def _identity_matches_trunk(
    value: Mapping[str, Any],
    trunks: Sequence[Mapping[str, Any]],
) -> bool:
    return _match_trunk_identity(value, trunks) is not None


def _call_plan_trunk_match(
    plan: Mapping[str, Any],
    trunks: Sequence[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    target = dict(plan.get("target") or {})
    compatibility = dict(plan.get("target_compatibility") or {})
    probe = dict(target)
    probe.setdefault(
        "entry_plan_id",
        target.get("entry_plan_lookup_key")
        or compatibility.get("entry_plan_lookup_key"),
    )
    match = _match_trunk_identity(probe, trunks)
    if match is not None:
        match = dict(match)
        match["plan_id"] = plan.get("plan_id")
    return match


def _call_plan_targets_trunk(
    plan: Mapping[str, Any],
    trunks: Sequence[Mapping[str, Any]],
) -> bool:
    return _call_plan_trunk_match(plan, trunks) is not None


def _contract_trunk_match(
    contract: Mapping[str, Any],
    trunks: Sequence[Mapping[str, Any]],
    overlay_plan_ids: Sequence[str] = (),
) -> Optional[Dict[str, Any]]:
    """Attribute one custody contract by exact caller/callee/call identity."""
    if not isinstance(contract, Mapping):
        return None
    call = dict(contract.get("call") or {})
    plan_id = str(call.get("plan_id") or contract.get("plan_id") or "")
    if plan_id and plan_id in {str(value) for value in overlay_plan_ids}:
        return {
            "trunk_identity": None,
            "match_kind": "runtime_overlay_plan_id",
            "match_value": plan_id,
            "plan_id": plan_id,
        }

    probes = (
        ("callee", dict(contract.get("callee") or {})),
        ("call_target", dict(call.get("target") or {})),
        ("caller", dict(contract.get("caller") or {})),
    )
    for source, probe in probes:
        if source == "call_target":
            compatibility = dict(call.get("target_compatibility") or {})
            probe.setdefault(
                "entry_plan_id",
                probe.get("entry_plan_lookup_key")
                or compatibility.get("entry_plan_lookup_key"),
            )
        match = _match_trunk_identity(probe, trunks)
        if match is not None:
            match = dict(match)
            match.update({
                "contract_side": source,
                "plan_id": plan_id or None,
            })
            return match
    return None


_X86_64_RUNTIME_REGISTER_FAMILY_ALIASES = {
    "RAX": "RAX", "EAX": "RAX", "AX": "RAX",
    "RBX": "RBX", "EBX": "RBX", "BX": "RBX", "BL": "RBX", "BH": "RBX",
    "RCX": "RCX", "ECX": "RCX", "CX": "RCX", "CL": "RCX", "CH": "RCX",
    "RDX": "RDX", "EDX": "RDX", "DX": "RDX", "DL": "RDX", "DH": "RDX",
    "RSI": "RSI", "ESI": "RSI", "SI": "RSI", "SIL": "RSI",
    "RDI": "RDI", "EDI": "RDI", "DI": "RDI", "DIL": "RDI",
    "RBP": "RBP", "EBP": "RBP", "BP": "RBP", "BPL": "RBP",
    "RSP": "RSP", "ESP": "RSP", "SP": "RSP", "SPL": "RSP",
}
for _runtime_index in range(8, 16):
    _runtime_family = "R%d" % _runtime_index
    _X86_64_RUNTIME_REGISTER_FAMILY_ALIASES[
        _runtime_family
    ] = _runtime_family
    _X86_64_RUNTIME_REGISTER_FAMILY_ALIASES[
        "R%dD" % _runtime_index
    ] = _runtime_family
    _X86_64_RUNTIME_REGISTER_FAMILY_ALIASES[
        "R%dW" % _runtime_index
    ] = _runtime_family
    _X86_64_RUNTIME_REGISTER_FAMILY_ALIASES[
        "R%dB" % _runtime_index
    ] = _runtime_family


def _canonical_runtime_register(value: Any) -> str:
    """Canonical physical carrier identity; width remains separate."""
    text = str(value or "").upper()
    if text.endswith("_QA") or text.endswith("_QD"):
        text = text.rsplit("_", 1)[0]
    if text.startswith(("YMM", "ZMM")) and text[3:].isdigit():
        return "XMM" + text[3:]
    if text == "AL":
        return "AL"
    return _X86_64_RUNTIME_REGISTER_FAMILY_ALIASES.get(
        text,
        text,
    )


def _storage_width_bits_from_key(value: Any) -> Optional[int]:
    match = re.search(r":(\d+)\s*$", str(value or ""))
    if match is None:
        return None
    size = int(match.group(1))
    return size * 8 if size > 0 else None


def _entry_argument_binding(
    fixed_argument: Mapping[str, Any],
) -> Optional[Dict[str, Any]]:
    bindings = [
        dict(item)
        for item in list(
            dict(fixed_argument or {}).get(
                "physical_carrier_bindings"
            )
            or []
        )
        if isinstance(item, Mapping)
        and item.get("callable_argument") is not False
    ]
    if not bindings:
        return None
    bindings.sort(
        key=lambda item: (
            item.get("carrier_index") is None,
            item.get("carrier_index")
            if isinstance(item.get("carrier_index"), int)
            else 0,
            str(
                item.get("register")
                or item.get("storage_key")
                or ""
            ),
        )
    )
    return bindings[0]


def _entry_binding_carrier_kind(
    binding: Mapping[str, Any],
) -> Optional[str]:
    binding = dict(binding or {})
    register = binding.get("register")
    if register not in (None, ""):
        return (
            "xmm_register"
            if str(
                binding.get("carrier_bank") or ""
            ).lower()
            == "vector"
            else "gp_register"
        )
    if str(binding.get("storage_key") or "").startswith("stack:"):
        return "stack_overflow_argument"
    return None


def _contract_entry_plan_id(
    contract: Mapping[str, Any],
    call_plan: Mapping[str, Any],
) -> Optional[str]:
    call = dict(contract.get("call") or {})
    callee = dict(contract.get("callee") or {})
    target = dict(call.get("target") or {})
    call_compatibility = dict(
        call.get("target_compatibility") or {}
    )
    plan_target = dict(call_plan.get("target") or {})
    plan_compatibility = dict(
        call_plan.get("target_compatibility") or {}
    )
    for value in (
        contract.get("target_entry_plan_id"),
        callee.get("entry_plan_id"),
        target.get("entry_plan_lookup_key"),
        call_compatibility.get("entry_plan_lookup_key"),
        plan_target.get("entry_plan_lookup_key"),
        plan_compatibility.get("entry_plan_lookup_key"),
    ):
        if value not in (None, ""):
            return str(value)
    return None


def _load_partial_project_abi_authority(
    project_root: Path,
) -> Dict[str, Any]:
    """Explicit user-approved fallback for incomplete decompilation only."""
    project_root = Path(project_root).resolve()
    index_path = project_root / PROJECT_ABI_PLAN_INDEX
    alias_path = project_root / PROJECT_ABI_ALIAS_AUDIT
    custody_path = project_root / ABI_CUSTODY_REPORT
    receipt_path = project_root / ABI_FINAL_AUTHORITY

    entry_plans: Dict[str, Any] = {}
    call_plans: Dict[str, Any] = {}
    index: Dict[str, Any] = {}
    alias: Dict[str, Any] = {}
    custody: Dict[str, Any] = {}
    receipt: Dict[str, Any] = {}
    artifacts: Dict[str, Any] = {}
    warnings: List[str] = []

    if index_path.is_file():
        index = _read_json(index_path)
        if index.get("format") != "pal_abi_canonical_project_plan_index":
            raise PALExecInterfaceError(
                "partial ABI plan index format mismatch"
            )
        if (
            index.get("canonicalizer_version")
            != PAL_ABI_PLAN_CANONICALIZER_VERSION
        ):
            raise PALExecInterfaceError(
                "partial ABI plan index canonicalizer mismatch"
            )
        if list(index.get("core_conflicts") or []):
            raise PALExecInterfaceError(
                "partial ABI plan index contains immutable core conflicts"
            )
        entry_plans = _authority_plan_table(
            index,
            "entry_plans",
            "function_entry_abi_plan",
        )
        call_plans = _authority_plan_table(
            index,
            "call_plans",
            "call_site_abi_plan",
        )
        source_mode = "partial_project_plan_index"
        phase = str(index.get("phase") or "partial_index")
        artifacts["plan_index"] = {
            "name": PROJECT_ABI_PLAN_INDEX,
            "sha256": _sha256_file(index_path),
        }
    else:
        source_mode = "partial_direct_registry"
        phase = "partial_direct_registry"
        functions_root = project_root / "functions"
        for icecube_path in sorted(
            functions_root.glob("*.icecube.json*.gz")
        ):
            cube = _read_json(icecube_path)
            entries, calls = _extract_registry_owned_abi_plans(cube)
            for table, incoming in (
                (entry_plans, entries),
                (call_plans, calls),
            ):
                for plan_id, plan in incoming.items():
                    previous = table.get(plan_id)
                    if previous is not None:
                        comparison = compare_plans(previous, plan)
                        if comparison.get("classification") == "core_conflict":
                            raise PALExecInterfaceError(
                                "partial direct-registry ABI core conflict: %s"
                                % plan_id
                            )
                    table[plan_id] = dict(plan)
        warnings.append(
            "canonical project plan index absent; direct registry owners used"
        )

    if alias_path.is_file():
        alias = _read_json(alias_path)
        artifacts["alias_audit"] = {
            "name": PROJECT_ABI_ALIAS_AUDIT,
            "sha256": _sha256_file(alias_path),
        }
    if custody_path.is_file():
        custody = _read_json(custody_path)
        artifacts["custody_report"] = {
            "name": ABI_CUSTODY_REPORT,
            "sha256": _sha256_file(custody_path),
        }
    if receipt_path.is_file():
        receipt = _read_json(receipt_path)
        artifacts["final_authority"] = {
            "name": ABI_FINAL_AUTHORITY,
            "sha256": _sha256_file(receipt_path),
        }

    return {
        "entry_plans": entry_plans,
        "call_plans": call_plans,
        "plan_index": index,
        "alias_audit": alias,
        "custody_report": custody,
        "final_authority": receipt,
        "source_mode": source_mode,
        "phase": phase,
        "status": "partial_verified",
        "custody_health": str(
            custody.get("status") or "degraded"
        ).upper(),
        "artifacts": artifacts,
        "warnings": warnings,
        "acceptance_gates": {
            "recursive_whole_icecube_discovery_used": False,
            "whole_object_plan_equality_used": False,
            "canonical_project_index_consumed": bool(index),
            "final_authority_receipt_verified": False,
            "immutable_core_hashes_recomputed": True,
            "final_phase_verified": False,
            "partial_publication_user_approved": True,
        },
    }


def _authority_plan_table(
    index: Mapping[str, Any],
    field: str,
    expected_class: str,
) -> Dict[str, Dict[str, Any]]:
    raw = index.get(field)
    if not isinstance(raw, Mapping):
        raise PALExecInterfaceError(
            "canonical ABI plan index lacks mapping %s" % field
        )
    out: Dict[str, Dict[str, Any]] = {}
    for raw_plan_id, raw_record in raw.items():
        plan_id = str(raw_plan_id)
        if not isinstance(raw_record, Mapping):
            raise PALExecInterfaceError(
                "canonical ABI plan record is not a mapping: %s" % plan_id
            )
        record = dict(raw_record)
        plan = record.get("canonical_plan")
        if not isinstance(plan, Mapping):
            raise PALExecInterfaceError(
                "canonical ABI plan record lacks canonical_plan: %s" % plan_id
            )
        plan = dict(plan)
        if plan.get("plan_class") != expected_class:
            raise PALExecInterfaceError(
                "canonical ABI plan class mismatch: %s" % plan_id
            )
        if str(plan.get("plan_id") or "") != plan_id:
            raise PALExecInterfaceError(
                "canonical ABI plan id mismatch: %s" % plan_id
            )
        identity = canonicalize_plan(plan)
        expected_core = str(record.get("plan_core_sha256") or "")
        if not expected_core or identity["plan_core_sha256"] != expected_core:
            raise PALExecInterfaceError(
                "canonical ABI plan core hash mismatch: %s" % plan_id
            )
        stamped = dict(plan.get("abi_plan_identity") or {})
        if stamped:
            if str(stamped.get("plan_id") or "") != plan_id:
                raise PALExecInterfaceError(
                    "stamped ABI plan id mismatch: %s" % plan_id
                )
            if str(stamped.get("plan_core_sha256") or "") != expected_core:
                raise PALExecInterfaceError(
                    "stamped ABI plan core hash mismatch: %s" % plan_id
                )
        out[plan_id] = plan
    return out


def _load_project_final_abi_authority(project_root: Path) -> Dict[str, Any]:
    project_root = Path(project_root).resolve()
    paths = {
        "plan_index": project_root / PROJECT_ABI_PLAN_INDEX,
        "alias_audit": project_root / PROJECT_ABI_ALIAS_AUDIT,
        "custody_report": project_root / ABI_CUSTODY_REPORT,
        "final_authority": project_root / ABI_FINAL_AUTHORITY,
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise PALExecInterfaceError(
            "final ABI authority artifacts missing: %s" % ", ".join(missing)
        )

    index = _read_json(paths["plan_index"])
    alias = _read_json(paths["alias_audit"])
    custody = _read_json(paths["custody_report"])
    receipt = _read_json(paths["final_authority"])
    failures: List[str] = []

    if receipt.get("format") != "pal_abi_final_authority_receipt":
        failures.append("final_authority_format_mismatch")
    if int(receipt.get("schema_version") or 0) != 1:
        failures.append("final_authority_schema_mismatch")
    if receipt.get("status") != "complete":
        failures.append("final_authority_not_complete")
    if receipt.get("phase") != ABI_FINAL_PHASE:
        failures.append("final_authority_phase_mismatch")
    if receipt.get("build") != ABI_FINAL_BATCH_BUILD:
        failures.append("final_authority_batch_build_mismatch")
    if receipt.get("inspector_version") != ABI_CUSTODY_INSPECTOR_VERSION:
        failures.append("final_authority_inspector_version_mismatch")
    if receipt.get("canonicalizer_version") != PAL_ABI_PLAN_CANONICALIZER_VERSION:
        failures.append("final_authority_canonicalizer_version_mismatch")

    required_gates = (
        "plan_core_continuity_verified",
        "authorized_repair_identity_verified",
        "authorized_repairs_present_in_final_index",
        "emitter_reemit_counts_verified",
        "final_custody_refresh_completed",
        "final_index_postdates_emitter_refreeze",
    )
    gates = dict(receipt.get("acceptance_gates") or {})
    for gate in required_gates:
        if gates.get(gate) is not True:
            failures.append("final_authority_gate_failed:%s" % gate)

    if index.get("format") != "pal_abi_canonical_project_plan_index":
        failures.append("plan_index_format_mismatch")
    if int(index.get("schema_version") or 0) != 1:
        failures.append("plan_index_schema_mismatch")
    if index.get("version") != ABI_CUSTODY_INSPECTOR_VERSION:
        failures.append("plan_index_inspector_version_mismatch")
    if index.get("canonicalizer_version") != PAL_ABI_PLAN_CANONICALIZER_VERSION:
        failures.append("plan_index_canonicalizer_version_mismatch")
    if index.get("phase") != ABI_FINAL_PHASE:
        failures.append("plan_index_phase_mismatch")
    if list(index.get("core_conflicts") or []):
        failures.append("plan_index_contains_core_conflicts")
    index_summary = dict(index.get("summary") or {})
    if int(index_summary.get("core_conflicts") or 0) != 0:
        failures.append("plan_index_core_conflict_count_nonzero")

    if alias.get("format") != "pal_abi_plan_alias_audit":
        failures.append("alias_audit_format_mismatch")
    if alias.get("version") != ABI_CUSTODY_INSPECTOR_VERSION:
        failures.append("alias_audit_inspector_version_mismatch")
    if alias.get("canonicalizer_version") != PAL_ABI_PLAN_CANONICALIZER_VERSION:
        failures.append("alias_audit_canonicalizer_version_mismatch")
    if alias.get("phase") != ABI_FINAL_PHASE:
        failures.append("alias_audit_phase_mismatch")

    if custody.get("format") != "pal_abi_custody_project_report":
        failures.append("custody_report_format_mismatch")
    if custody.get("version") != ABI_CUSTODY_INSPECTOR_VERSION:
        failures.append("custody_report_inspector_version_mismatch")
    if custody.get("canonicalizer_version") != PAL_ABI_PLAN_CANONICALIZER_VERSION:
        failures.append("custody_report_canonicalizer_version_mismatch")

    final_record = dict(receipt.get("final") or {})
    observed_index_sha = _sha256_file(paths["plan_index"])
    observed_alias_sha = _sha256_file(paths["alias_audit"])
    observed_receipt_sha = _sha256_file(paths["final_authority"])
    observed_custody_sha = _sha256_file(paths["custody_report"])
    if final_record.get("plan_index") != PROJECT_ABI_PLAN_INDEX:
        failures.append("receipt_plan_index_name_mismatch")
    if str(final_record.get("plan_index_sha256") or "") != observed_index_sha:
        failures.append("receipt_plan_index_sha256_mismatch")
    if final_record.get("alias_audit") != PROJECT_ABI_ALIAS_AUDIT:
        failures.append("receipt_alias_audit_name_mismatch")
    if str(final_record.get("alias_audit_sha256") or "") != observed_alias_sha:
        failures.append("receipt_alias_audit_sha256_mismatch")
    custody_final = dict(custody.get("final_authority") or {})
    if str(custody_final.get("sha256") or "") != observed_receipt_sha:
        failures.append("custody_final_authority_sha256_mismatch")
    if custody_final.get("status") != "complete":
        failures.append("custody_final_authority_not_complete")
    if custody_final.get("phase") != ABI_FINAL_PHASE:
        failures.append("custody_final_authority_phase_mismatch")

    entry_plans = _authority_plan_table(
        index, "entry_plans", "function_entry_abi_plan"
    )
    call_plans = _authority_plan_table(
        index, "call_plans", "call_site_abi_plan"
    )
    if len(entry_plans) != int(index_summary.get("entry_plans") or 0):
        failures.append("entry_plan_count_mismatch")
    if len(call_plans) != int(index_summary.get("call_plans") or 0):
        failures.append("call_plan_count_mismatch")

    receipt_custody = dict(receipt.get("custody_health") or {})
    index_custody = dict(index.get("custody_health") or {})
    custody_status = str(custody.get("status") or "broken").lower()
    if str(receipt_custody.get("status") or "").lower() != custody_status:
        failures.append("receipt_custody_health_mismatch")
    if str(index_custody.get("status") or "").lower() != custody_status:
        failures.append("index_custody_health_mismatch")

    if failures:
        raise PALExecInterfaceError(
            "final ABI authority validation failed: %s" % ", ".join(failures)
        )

    return {
        "entry_plans": entry_plans,
        "call_plans": call_plans,
        "plan_index": index,
        "alias_audit": alias,
        "custody_report": custody,
        "final_authority": receipt,
        "source_mode": "final_project_plan_index",
        "phase": ABI_FINAL_PHASE,
        "status": "verified",
        "custody_health": custody_status.upper(),
        "artifacts": {
            "plan_index": {
                "name": PROJECT_ABI_PLAN_INDEX,
                "sha256": observed_index_sha,
            },
            "alias_audit": {
                "name": PROJECT_ABI_ALIAS_AUDIT,
                "sha256": observed_alias_sha,
            },
            "custody_report": {
                "name": ABI_CUSTODY_REPORT,
                "sha256": observed_custody_sha,
            },
            "final_authority": {
                "name": ABI_FINAL_AUTHORITY,
                "sha256": observed_receipt_sha,
            },
        },
        "acceptance_gates": {
            "recursive_whole_icecube_discovery_used": False,
            "whole_object_plan_equality_used": False,
            "canonical_project_index_consumed": True,
            "final_authority_receipt_verified": True,
            "immutable_core_hashes_recomputed": True,
            "final_phase_verified": True,
        },
    }


def _extract_registry_owned_abi_plans(
    icecube: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Explicit legacy fallback: direct metadata-registry owners only."""
    snapshot = icecube.get("snapshot") or {}
    document = snapshot.get("document") or {}
    registry = document.get("metadata_registry") or {}
    if not isinstance(registry, Mapping):
        raise PALExecInterfaceError("icecube has no metadata_registry")
    entries: Dict[str, Any] = {}
    calls: Dict[str, Any] = {}
    identities: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for registry_key, raw in registry.items():
        if not isinstance(raw, Mapping):
            continue
        plan_class = raw.get("plan_class")
        if plan_class not in {
            "function_entry_abi_plan", "call_site_abi_plan",
        }:
            continue
        plan_id = str(raw.get("plan_id") or "")
        if not plan_id:
            continue
        identity = canonicalize_plan(raw)
        key = (str(plan_class), plan_id)
        previous = identities.get(key)
        if previous is not None and previous["plan_core_sha256"] != identity["plan_core_sha256"]:
            raise PALExecInterfaceError(
                "legacy registry ABI core conflict: %s" % plan_id
            )
        identities[key] = identity
        table = entries if plan_class == "function_entry_abi_plan" else calls
        preferred = str(registry_key).startswith("abi:entry_plan") or str(registry_key).startswith("abi:call:")
        if plan_id not in table or preferred:
            table[plan_id] = dict(raw)
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


def _clip_text(value: Any, width: int) -> str:
    text = str(value if value not in (None, "") else "-")
    width = max(int(width), 1)
    if len(text) <= width:
        return text
    if width == 1:
        return "~"
    return text[: width - 1] + "~"


def _human_bytes(value: int) -> str:
    size = max(int(value or 0), 0)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(size)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024.0 or candidate == units[-1]:
            break
        amount /= 1024.0
    if unit == "B":
        return "%dB" % size
    if amount >= 100:
        return "%.0f%s" % (amount, unit)
    if amount >= 10:
        return "%.1f%s" % (amount, unit)
    return "%.2f%s" % (amount, unit)


def _format_signed_hex(value: Any) -> str:
    if value in (None, "", "-"):
        return "-"
    try:
        number = (
            int(str(value), 0)
            if not isinstance(value, int)
            else int(value)
        )
    except (TypeError, ValueError):
        return str(value)
    if number == 0:
        return "0"
    if number < 0:
        return "-0x%x" % abs(number)
    return "+0x%x" % number


def _directory_size(path: Path) -> int:
    root = Path(path)
    if not root.exists():
        return 0
    total = 0
    for candidate in root.rglob("*"):
        try:
            if candidate.is_file():
                total += candidate.stat().st_size
        except OSError:
            continue
    return total


def _ascii_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    right_align: Sequence[int] = (),
) -> str:
    normalized_headers = [str(value) for value in headers]
    normalized_rows = [
        [str(value) for value in row]
        for row in rows
    ]
    column_count = len(normalized_headers)
    if any(len(row) != column_count for row in normalized_rows):
        raise ValueError("ASCII table row width mismatch")

    widths = [
        max(
            [len(normalized_headers[index])]
            + [
                len(row[index])
                for row in normalized_rows
            ]
        )
        for index in range(column_count)
    ]
    right = {int(index) for index in right_align}

    def separator() -> str:
        return (
            "+"
            + "+".join(
                "-" * (width + 2)
                for width in widths
            )
            + "+"
        )

    def render_row(values: Sequence[str]) -> str:
        cells = []
        for index, value in enumerate(values):
            if index in right:
                cells.append(
                    " " + value.rjust(widths[index]) + " "
                )
            else:
                cells.append(
                    " " + value.ljust(widths[index]) + " "
                )
        return "|" + "|".join(cells) + "|"

    lines = [
        separator(),
        render_row(normalized_headers),
        separator(),
    ]
    lines.extend(
        render_row(row)
        for row in normalized_rows
    )
    lines.append(separator())
    return "\n".join(lines)


_TABLOID_WIDTH = 88


def _reason_text(value: Any) -> str:
    text = str(value if value not in (None, "") else "-").strip()
    if not text:
        return "-"
    head, separator, tail = text.partition(":")
    head = head.replace("_", " ").strip()
    if separator:
        tail = tail.replace("_", " ").strip()
        return "%s: %s" % (head, tail)
    return head


def _tabloid_banner(
    title: str,
    subtitle: Optional[str] = None,
    *,
    width: int = _TABLOID_WIDTH,
) -> str:
    width = max(int(width), 48)
    inner = width - 4
    lines = [
        "+" + "=" * (width - 2) + "+",
        "| " + _clip_text(str(title).upper(), inner).ljust(inner) + " |",
    ]
    if subtitle:
        lines.append(
            "| "
            + _clip_text(str(subtitle), inner).ljust(inner)
            + " |"
        )
    lines.append("+" + "=" * (width - 2) + "+")
    return "\n".join(lines)


def _tabloid_card(
    title: str,
    rows: Sequence[Tuple[Any, Any]],
    *,
    state: Optional[str] = None,
    width: int = _TABLOID_WIDTH,
) -> str:
    width = max(int(width), 48)
    label_width = max(12, min(28, max(
        [len(str(label)) for label, _ in rows] or [12]
    )))
    marker = "[%s]" % str(state or "INFO").upper()
    header = "%s %s" % (marker, str(title).upper())
    lines = [
        "+" + "-" * (width - 2) + "+",
        "| " + _clip_text(header, width - 4).ljust(width - 4) + " |",
        "+" + "-" * (width - 2) + "+",
    ]
    for label, value in rows:
        prefix = (str(label).upper() + " :").ljust(label_width + 2)
        available = max(width - 5 - len(prefix), 8)
        values = str(value if value not in (None, "") else "-").splitlines() or ["-"]
        for index, line in enumerate(values):
            left = prefix if index == 0 else " " * len(prefix)
            rendered = left + _clip_text(line, available)
            lines.append(
                "| " + rendered.ljust(width - 4) + " |"
            )
    lines.append("+" + "-" * (width - 2) + "+")
    return "\n".join(lines)


def _tabloid_issue_table(
    title: str,
    items: Sequence[Any],
    *,
    level: str = "WARN",
    width: int = _TABLOID_WIDTH,
    limit: int = 24,
) -> str:
    normalized = [
        _reason_text(item)
        for item in list(items or [])
        if str(item).strip()
    ]
    visible = normalized[: max(int(limit), 1)]
    rows = [
        [str(index), str(level).upper(), _clip_text(item, max(width - 26, 24))]
        for index, item in enumerate(visible, 1)
    ]
    if len(normalized) > len(visible):
        rows.append([
            "...",
            "MORE",
            "%d additional items retained in JSON authority"
            % (len(normalized) - len(visible)),
        ])
    if not rows:
        rows = [["-", "NONE", "No issues recorded"]]
    return (
        _tabloid_banner(title, "%s MATRIX" % str(level).upper(), width=width)
        + "\n"
        + _ascii_table(
            ("#", "LEVEL", "MESSAGE"),
            rows,
            right_align=(0,),
        )
    )


def _format_gate_block(
    title: str,
    reasons: Sequence[Any],
    *,
    report: Optional[Any] = None,
) -> str:
    rows: List[Tuple[Any, Any]] = [
        ("decision", "execution blocked"),
        ("reason count", len(list(reasons or []))),
    ]
    if report:
        rows.append(("authority", report))
    return (
        _tabloid_card(title, rows, state="BLOCKED")
        + "\n"
        + _tabloid_issue_table(
            "RUN GATE REASONS",
            reasons,
            level="ERROR",
        )
    )


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

    def has_byte(self, address):
        return int(address) in self._bytes

    def mapped_byte_count(self):
        return len(self._bytes)

    @property
    def root_token(self):
        return "PALMEM:%x" % id(self)

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

PAL_PROJECT_RUNTIME_VERSION = "v11_x86_64_register_family_truth_runtime"
PAL_ABI_RUNTIME_REQUIRED_VERSION = "v1d_x86_64_register_family_alias_truth"
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


def _truthy_environment(name, default=False):
    value = os.environ.get(str(name))
    if value is None:
        return bool(default)
    return str(value).strip().lower() not in {
        "",
        "0",
        "false",
        "no",
        "off",
    }


class PALRuntimeTrace:
    """Append-only internal-call and memory-custody trace."""

    def __init__(self, root, memory, *, enabled=False, stderr=False):
        self.root = Path(root)
        self.memory = memory
        self.enabled = bool(enabled)
        self.stderr = bool(stderr)
        self.path = self.root / "PAL_runtime_trace.jsonl"
        self.sequence = 0
        if self.enabled:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def _json_value(self, value):
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, (list, tuple)):
            return [self._json_value(item) for item in value]
        if isinstance(value, dict):
            return {
                str(key): self._json_value(item)
                for key, item in value.items()
            }
        return repr(value)

    def pointer_preview(self, value, *, limit=32):
        if not isinstance(value, int):
            return None
        address = int(value)
        if not hasattr(self.memory, "has_byte"):
            return None
        if not self.memory.has_byte(address):
            return None
        raw = self.memory.read_bytes(address, int(limit))
        nul = raw.find(b"\0")
        bounded = raw if nul < 0 else raw[: nul + 1]
        text = None
        try:
            payload = bounded[:-1] if bounded.endswith(b"\0") else bounded
            decoded = payload.decode("utf-8", errors="strict")
            if decoded and all(
                character.isprintable() or character in "\t\r\n"
                for character in decoded
            ):
                text = decoded
        except UnicodeDecodeError:
            text = None
        return {
            "address": hex(address),
            "hex": bounded.hex(),
            "cstring": text,
            "nul_terminated_within_preview": nul >= 0,
        }

    def describe_values(self, values):
        described = []
        for value in tuple(values):
            record = {"value": self._json_value(value)}
            preview = self.pointer_preview(value)
            if preview is not None:
                record["pointer"] = preview
            described.append(record)
        return described

    def emit(self, kind, **fields):
        if not self.enabled:
            return
        self.sequence += 1
        record = {
            "sequence": self.sequence,
            "kind": str(kind),
            "memory_id": id(self.memory),
            "memory_root_token": getattr(
                self.memory,
                "root_token",
                "PALMEM:%x" % id(self.memory),
            ),
        }
        record.update(
            {
                str(key): self._json_value(value)
                for key, value in fields.items()
            }
        )
        line = json.dumps(
            record,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        with open(self.path, "at", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
        if self.stderr:
            print("PAL TRACE", line, file=sys.stderr, flush=True)


def _carrier_value_records(context, carriers):
    records = []
    for raw in tuple(carriers or ()):
        if isinstance(raw, dict):
            kind = raw.get("kind") or raw.get("carrier_kind")
            register = raw.get("register") or raw.get("carrier")
            width = raw.get("carrier_width_bits") or raw.get("width_bits")
        else:
            item = tuple(raw)
            kind = item[0] if len(item) > 0 else None
            register = item[1] if len(item) > 1 else None
            width = item[2] if len(item) > 2 else None
        record = {
            "kind": kind,
            "register": register,
            "width_bits": width,
            "value": None,
        }
        if kind == "register" and register and isinstance(width, int):
            try:
                record["value"] = context.frame.get_register(
                    register,
                    width,
                )
            except Exception as exc:
                record["read_error"] = "%s: %s" % (
                    type(exc).__name__,
                    exc,
                )
        records.append(record)
    return records


def _install_abi_trace_hooks():
    """Observe PALABI v1c without replacing its custody decisions."""
    from PALABI import (
        PALCallContext,
        PALSysVAMD64CallFrame,
        current_abi_context,
    )

    marker = "_pal_exec_v1q_abi_trace_hooks"
    if getattr(PALCallContext, marker, False):
        return

    original_child_context = PALCallContext._child_context
    original_materialize = (
        PALSysVAMD64CallFrame.materialize_entry_arguments
    )
    original_complete_return = PALCallContext._complete_internal_return
    original_call = PALCallContext.call

    def traced_call(context, target, values, plan_id):
        plan = dict(
            context.call_plans.get(str(plan_id)) or {}
        )
        bridge = dict(
            plan.get("partial_argument_bridge") or {}
        )
        logical_values = list(values)
        if bridge.get("active") is True:
            expected = len(
                [
                    item
                    for item in list(plan.get("arguments") or [])
                    if isinstance(item, dict)
                ]
            )
            supplied = len(logical_values)
            if supplied < expected:
                logical_values.extend(
                    [0] * (expected - supplied)
                )
            trace = getattr(context, "_pal_exec_trace", None)
            if trace is not None:
                trace.emit(
                    "abi_argument_bridge",
                    call_plan_id=plan_id,
                    target=target,
                    supplied_argument_count=supplied,
                    runtime_argument_count=len(logical_values),
                    zero_filled=max(expected - supplied, 0),
                    actions=list(bridge.get("actions") or []),
                    contract_ids=list(
                        bridge.get("contract_ids") or []
                    ),
                    policy=bridge.get("policy"),
                )
        return original_call(
            context,
            target,
            tuple(logical_values),
            plan_id,
        )

    def traced_child_context(parent, frame, entry_plan_id):
        child = original_child_context(parent, frame, entry_plan_id)
        trace = getattr(parent, "_pal_exec_trace", None)
        if trace is not None:
            child._pal_exec_trace = trace
        return child

    def traced_materialize(
        frame,
        call_plan,
        entry_plan,
        *,
        original_values=(),
    ):
        materialized = original_materialize(
            frame,
            call_plan,
            entry_plan,
            original_values=original_values,
        )
        trace = None
        try:
            trace = getattr(
                current_abi_context(),
                "_pal_exec_trace",
                None,
            )
        except Exception:
            trace = None
        if trace is not None:
            arguments = []
            for item in sorted(
                [
                    dict(value)
                    for value in list(call_plan.get("arguments") or [])
                    if isinstance(value, dict)
                ],
                key=lambda value: (
                    value.get("index") is None,
                    value.get("index")
                    if isinstance(value.get("index"), int)
                    else 0,
                ),
            ):
                arguments.append({
                    "index": item.get("index"),
                    "source_sid": item.get("source_sid"),
                    "argument_class": item.get("argument_class"),
                    "source_width_bits": item.get("source_width_bits"),
                    "carrier_kind": item.get("carrier_kind"),
                    "carrier": item.get("carrier"),
                    "stack_slot": item.get("stack_slot"),
                    "parameter_region": item.get("parameter_region"),
                })
            trace.emit(
                "abi_child_frame_arguments",
                call_plan_id=call_plan.get("plan_id"),
                target_entry_plan_id=entry_plan.get("plan_id"),
                child_frame_entry_plan_id=getattr(
                    frame,
                    "entry_plan_id",
                    None,
                ),
                child_frame_call_plan_id=getattr(
                    frame,
                    "call_plan_id",
                    None,
                ),
                stack_pointer=getattr(frame, "stack_pointer", None),
                overflow_stack_base=getattr(
                    frame,
                    "overflow_stack_base",
                    None,
                ),
                carrier_plan=arguments,
                caller_values=trace.describe_values(original_values),
                materialized_values=trace.describe_values(materialized),
                argument_source="materialized_child_frame",
            )
        return materialized

    def traced_complete_return(
        parent,
        *,
        child,
        result,
        plan,
        entry_plan,
        target_name,
    ):
        trace = getattr(parent, "_pal_exec_trace", None)
        if trace is not None:
            trace.emit(
                "abi_callee_semantic_result",
                target=target_name,
                call_plan_id=plan.get("plan_id"),
                target_entry_plan_id=entry_plan.get("plan_id"),
                callee_semantic_result=result,
                child_return_value_before_completion=child.return_value,
                child_return_carriers_before_completion=(
                    _carrier_value_records(child, child.return_carriers)
                ),
            )
        try:
            caller_view = original_complete_return(
                parent,
                child=child,
                result=result,
                plan=plan,
                entry_plan=entry_plan,
                target_name=target_name,
            )
        except BaseException as exc:
            if trace is not None:
                trace.emit(
                    "abi_return_transfer_raise",
                    target=target_name,
                    call_plan_id=plan.get("plan_id"),
                    target_entry_plan_id=entry_plan.get("plan_id"),
                    exception_type=type(exc).__name__,
                    exception=str(exc),
                )
            raise
        if trace is not None:
            trace.emit(
                "abi_return_transfer",
                target=target_name,
                call_plan_id=plan.get("plan_id"),
                target_entry_plan_id=entry_plan.get("plan_id"),
                callee_semantic_result=result,
                child_return_value=child.return_value,
                child_return_carriers=(
                    _carrier_value_records(child, child.return_carriers)
                ),
                parent_return_carriers=(
                    _carrier_value_records(
                        parent,
                        parent.last_call_return_carriers,
                    )
                ),
                parent_last_call_result_raw=parent.last_call_result_raw,
                parent_last_call_result_width_bits=(
                    parent.last_call_result_width_bits
                ),
                parent_transfer_status=parent.last_call_transfer_status,
                caller_visible_result=caller_view,
            )
        return caller_view

    PALCallContext.call = traced_call
    PALCallContext._child_context = traced_child_context
    PALSysVAMD64CallFrame.materialize_entry_arguments = traced_materialize
    PALCallContext._complete_internal_return = traced_complete_return
    setattr(PALCallContext, marker, True)


def _audit_abi_chain_publication(root, config):
    publication = dict(config.get("abi_chain_publication") or {})
    authority = dict(config.get("abi_authority_loading") or {})
    partial = dict(config.get("abi_partial_publication") or {})
    health = str(publication.get("health") or "BROKEN").upper()
    failures = []
    if health not in {"READY", "DEGRADED", "BROKEN"}:
        failures.append({"kind": "invalid_abi_chain_health", "health": health})

    observed = {}
    import hashlib
    for key, record in dict(authority.get("artifacts") or {}).items():
        if not isinstance(record, dict):
            continue
        name = str(record.get("name") or "")
        expected = str(record.get("sha256") or "")
        path = Path(root) / name
        actual = None
        if path.is_file():
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            actual = digest.hexdigest()
            if expected and actual != expected:
                failures.append({
                    "kind": "abi_authority_sha256_mismatch",
                    "artifact": key,
                    "expected": expected,
                    "observed": actual,
                })
        else:
            failures.append({
                "kind": "abi_authority_artifact_missing",
                "artifact": key,
                "path": str(path),
            })
        observed[key] = {
            "path": str(path),
            "expected_sha256": expected or None,
            "observed_sha256": actual,
        }

    if partial.get("active"):
        partial_name = str(
            partial.get("artifact")
            or "PAL_abi_partial_publication.json"
        )
        partial_expected = str(partial.get("sha256") or "")
        partial_path = Path(root) / partial_name
        if not partial_path.is_file():
            failures.append({
                "kind": "abi_partial_publication_artifact_missing",
                "path": str(partial_path),
            })
        else:
            digest = hashlib.sha256()
            with open(partial_path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            partial_observed = digest.hexdigest()
            if (
                partial_expected
                and partial_observed != partial_expected
            ):
                failures.append({
                    "kind": "abi_partial_publication_sha256_mismatch",
                    "expected": partial_expected,
                    "observed": partial_observed,
                })
            observed["partial_publication"] = {
                "path": str(partial_path),
                "expected_sha256": partial_expected or None,
                "observed_sha256": partial_observed,
            }

        bridge_name = str(
            partial.get("argument_bridge_artifact") or ""
        )
        bridge_expected = str(
            partial.get("argument_bridge_sha256") or ""
        )
        if bridge_name:
            bridge_path = Path(root) / bridge_name
            if not bridge_path.is_file():
                failures.append({
                    "kind": "abi_argument_bridge_artifact_missing",
                    "path": str(bridge_path),
                })
            else:
                digest = hashlib.sha256()
                with open(bridge_path, "rb") as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                bridge_observed = digest.hexdigest()
                if (
                    bridge_expected
                    and bridge_observed != bridge_expected
                ):
                    failures.append({
                        "kind": "abi_argument_bridge_sha256_mismatch",
                        "expected": bridge_expected,
                        "observed": bridge_observed,
                    })
                observed["argument_bridge"] = {
                    "path": str(bridge_path),
                    "expected_sha256": bridge_expected or None,
                    "observed_sha256": bridge_observed,
                }

    runtime_index = _read_json(Path(root) / "PAL_abi_plans.json")
    source_index = dict(authority.get("artifacts") or {}).get("plan_index") or {}
    source_receipt = dict(authority.get("artifacts") or {}).get("final_authority") or {}
    if runtime_index.get("format") != "pal_runtime_abi_plan_index":
        failures.append({"kind": "runtime_abi_plan_index_format_mismatch"})
    if runtime_index.get("phase") != authority.get("phase"):
        failures.append({"kind": "runtime_abi_plan_index_phase_mismatch"})
    if runtime_index.get("source_plan_index_sha256") != source_index.get("sha256"):
        failures.append({"kind": "runtime_plan_index_source_hash_mismatch"})
    if runtime_index.get("source_final_authority_sha256") != source_receipt.get("sha256"):
        failures.append({"kind": "runtime_final_authority_source_hash_mismatch"})

    audit = {
        "active": bool(publication.get("active")),
        "health": health,
        "source_mode": authority.get("source_mode"),
        "phase": authority.get("phase"),
        "artifacts": observed,
        "counts": dict(publication.get("counts") or {}),
        "failures": failures,
    }
    if failures or health == "BROKEN":
        reasons = list(
            failures
            or publication.get("broken_reasons")
            or ["unspecified ABI authority failure"]
        )
        formatted = []
        for index, reason in enumerate(reasons, 1):
            if isinstance(reason, dict):
                detail = json.dumps(reason, sort_keys=True)
            else:
                detail = str(reason).replace("_", " ")
            formatted.append("  %02d | ERROR | %s" % (index, detail))
        raise PALPublishedRuntimeError(
            "PAL ABI AUTHORITY GATE // BROKEN\n"
            + "\n".join(formatted)
        )
    return audit


def _audit_static_string_helper_load(memory, root):
    """Verify required bytes through PALhelpers.c_load."""
    report_path = Path(root) / "PAL_static_string_completion.json"
    if not report_path.is_file():
        return {
            "active": False,
            "reason": "completion_report_not_present",
            "verified_strings": 0,
        }

    from PALhelpers import c_load

    report = _read_json(report_path)
    required = dict(report.get("required_strings") or {})
    failures = []
    for raw_address, value in required.items():
        address = int(str(raw_address), 0)
        expected = str(value).encode("utf-8") + b"\0"
        observed = bytes(
            c_load(memory, address + index, 8)
            for index in range(len(expected))
        )
        if observed != expected:
            failures.append({
                "address": hex(address),
                "expected_hex": expected.hex(),
                "observed_hex": observed.hex(),
            })

    audit = {
        "active": True,
        "verified_strings": len(required),
        "failures": failures,
        "rule": (
            "published_static_string_bytes_must_match_through_"
            "PALhelpers_c_load_on_the_runtime_root_memory"
        ),
    }
    if failures:
        raise PALPublishedRuntimeError(
            "PAL helper-load static-string audit failed: %s" % failures
        )
    return audit


def _audit_static_string_memory(memory, root):
    report_path = (
        Path(root)
        / "PAL_static_string_completion.json"
    )
    if not report_path.is_file():
        return {
            "active": False,
            "reason": "completion_report_not_present",
            "verified_strings": 0,
        }

    report = _read_json(report_path)
    required = dict(
        report.get("required_strings") or {}
    )
    counts = dict(report.get("counts") or {})
    translation = dict(
        report.get("address_translation") or {}
    )
    unresolved = int(
        counts.get(
            "unresolved_ptrsub_references",
            translation.get(
                "unresolved_references",
                0,
            ),
        )
        or 0
    )
    failures = []

    for raw_address, text in required.items():
        address = int(str(raw_address), 0)
        expected = (
            str(text).encode("utf-8")
            + b"\0"
        )
        actual = memory.read_bytes(
            address,
            len(expected),
        )
        if actual != expected:
            failures.append({
                "address": hex(address),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            })

    audit = {
        "active": True,
        "health": (
            "BROKEN"
            if failures
            else (
                "DEGRADED"
                if unresolved
                else "READY"
            )
        ),
        "report": str(report_path),
        "verified_strings": len(required),
        "direct_resolved_references": int(
            counts.get(
                "direct_resolved_references",
                translation.get(
                    "direct_resolved_references",
                    0,
                ),
            )
            or 0
        ),
        "rebased_resolved_references": int(
            counts.get(
                "rebased_resolved_references",
                translation.get(
                    "rebased_resolved_references",
                    0,
                ),
            )
            or 0
        ),
        "unresolved_references": unresolved,
        "address_translation": translation,
        "failures": failures,
        "rule": (
            "every_completed_static_string_must_"
            "be_byte_visible_through_the_same_"
            "PALMemory_seen_by_lifted_c_load"
        ),
    }

    if failures:
        raise PALPublishedRuntimeError(
            "PAL static-string memory audit "
            "failed: %s" % failures
        )

    return audit



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
        from PALABI import PAL_ABI_RUNTIME_VERSION
        if (
            PAL_ABI_RUNTIME_VERSION
            != PAL_ABI_RUNTIME_REQUIRED_VERSION
        ):
            raise PALPublishedRuntimeError(
                "PALABI runtime build mismatch; required=%s observed=%s"
                % (
                    PAL_ABI_RUNTIME_REQUIRED_VERSION,
                    PAL_ABI_RUNTIME_VERSION,
                )
            )
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
        self.trace = PALRuntimeTrace(
            self.root,
            self.memory,
            enabled=_truthy_environment("PAL_EXEC_TRACE"),
            stderr=_truthy_environment("PAL_EXEC_TRACE_STDERR"),
        )
        self.abi_chain_runtime_audit = _audit_abi_chain_publication(
            self.root,
            self.config,
        )
        self.trace.emit(
            "abi_chain_publication",
            audit=self.abi_chain_runtime_audit,
        )
        self.static_string_memory_audit = _audit_static_string_memory(
            self.memory,
            self.root,
        )
        self.static_string_helper_load_audit = (
            _audit_static_string_helper_load(
                self.memory,
                self.root,
            )
        )
        self.trace.emit(
            "runtime_memory_root",
            mapped_byte_count=(
                self.memory.mapped_byte_count()
                if hasattr(self.memory, "mapped_byte_count")
                else len(self.memory)
            ),
            static_memory_audit=self.static_string_memory_audit,
            static_helper_load_audit=self.static_string_helper_load_audit,
        )

    def _assert_module_memory(self, module, record, phase):
        observed = getattr(module, "MEM", None)
        if observed is not self.memory:
            raise PALPublishedRuntimeError(
                "PAL module memory-root custody failed; "
                "function=%s phase=%s expected=%s observed=%s"
                % (
                    self._record_identity(record),
                    phase,
                    id(self.memory),
                    id(observed) if observed is not None else None,
                )
            )
        self.trace.emit(
            "module_memory_custody",
            function=self._record_identity(record),
            name=record.get("name"),
            phase=phase,
            module_memory_id=id(observed),
            root_identity=True,
        )

    def _bind_module_memory(self, module, record, phase):
        module.MEM = self.memory
        self._assert_module_memory(module, record, phase)
        return module

    def _assert_context_memory(self, context, phase):
        context_memory = getattr(context, "memory", None)
        thread = getattr(context, "thread", None)
        thread_memory = getattr(thread, "memory", None)
        if (
            context_memory is not self.memory
            or thread_memory is not self.memory
        ):
            raise PALPublishedRuntimeError(
                "PAL ABI memory-root custody failed; "
                "phase=%s root=%s context=%s thread=%s"
                % (
                    phase,
                    id(self.memory),
                    id(context_memory) if context_memory is not None else None,
                    id(thread_memory) if thread_memory is not None else None,
                )
            )
        self.trace.emit(
            "abi_memory_custody",
            phase=phase,
            context_memory_id=id(context_memory),
            thread_memory_id=id(thread_memory),
            root_identity=True,
        )

    def _invoke_record(self, record, values):
        if record.get("runtime_mode") == "abi_trunk":
            result = int(record.get("trunk_return_value") or 0)
            self.trace.emit(
                "abi_trunk_call",
                function=self._record_identity(record),
                name=record.get("name"),
                reason=record.get("trunk_reason"),
                source_status=record.get("source_status"),
                arguments=self.trace.describe_values(values),
                result=result,
                policy="explicit_user_approved_void_zero_trunk",
            )
            return result
        module = self.load_module(record)
        self._bind_module_memory(
            module,
            record,
            "immediately_before_invocation",
        )
        symbol = record.get("python_symbol")
        function = getattr(module, str(symbol), None)
        if not callable(function):
            raise PALPublishedRuntimeError(
                "published module %s has no callable %r"
                % (record.get("published_module"), symbol)
            )

        identity = self._record_identity(record)
        self.trace.emit(
            "internal_call_enter",
            function=identity,
            name=record.get("name"),
            runtime_mode=record.get("runtime_mode"),
            arguments=self.trace.describe_values(values),
        )
        try:
            result = self._invoke_adapted(function, values)
        except BaseException as exc:
            self.trace.emit(
                "internal_call_raise",
                function=identity,
                name=record.get("name"),
                exception_type=type(exc).__name__,
                exception=str(exc),
            )
            raise
        self._assert_module_memory(
            module,
            record,
            "immediately_after_invocation",
        )
        self.trace.emit(
            "internal_call_exit",
            function=identity,
            name=record.get("name"),
            result=result,
            result_pointer=self.trace.pointer_preview(result),
        )
        return result

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
            # Internal ABI dispatch executes exactly one published artifact
            # under the shared PALMemory root and records the call boundary.
            return self._invoke_record(record, values)

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
            return self._bind_module_memory(
                cached,
                record,
                "cached_module_return",
            )
        path = self._module_path(record)
        if not path.is_file():
            raise PALPublishedRuntimeError("published function module is missing: %s" % path)
        module_name = "palexec_%s" % str(record.get("module_stem") or path.stem)
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise PALPublishedRuntimeError("cannot load published module: %s" % path)
        module = importlib.util.module_from_spec(spec)
        self._bind_module_memory(
            module,
            record,
            "before_module_exec",
        )
        # Inject published internal wrappers before shims.  Local definitions
        # in the module overwrite these during exec, while cross-function
        # direct calls retain internal ownership.
        module.__dict__.update(self._all_internal_globals())
        for _name, _value in self._direct_shim_globals().items():
            module.__dict__.setdefault(_name, _value)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        self._bind_module_memory(
            module,
            record,
            "after_module_exec",
        )
        for _name, _value in self._all_internal_globals().items():
            module.__dict__.setdefault(_name, _value)
        for _name, _value in self._direct_shim_globals().items():
            module.__dict__.setdefault(_name, _value)
        self._module_cache[identity] = module
        self.trace.emit(
            "module_loaded",
            function=identity,
            name=record.get("name"),
            module_name=module_name,
            module_path=str(path),
            module_memory_id=id(module.MEM),
        )
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
        return self._internal_wrapper(record)

    def _invoke_adapted(self, function, values):
        """
        Bind arguments before invocation and execute the callable exactly once.

        The former implementation caught ``TypeError`` around the function
        call itself and retried it.  A TypeError raised inside published PAL
        code was therefore misclassified as a signature-adaptation failure,
        duplicating side effects and obscuring the original stack.
        """
        values = tuple(values)
        try:
            signature = inspect.signature(function)
        except (TypeError, ValueError):
            # Some extension/builtin callables do not expose a signature.
            # There is no safe adaptation available; call exactly once.
            return function(*values)

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
        call_values = () if not positional and not varargs else values

        try:
            signature.bind(*call_values)
        except TypeError as exc:
            raise PALPublishedRuntimeError(
                "published PAL function argument binding failed; "
                "function=%r signature=%s supplied_positional=%d error=%s"
                % (
                    getattr(function, "__name__", repr(function)),
                    signature,
                    len(call_values),
                    exc,
                )
            ) from exc

        # Do not catch TypeError here.  Any exception raised after function
        # entry belongs to the published function/runtime and must propagate
        # without a second invocation.
        return function(*call_values)

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
        entry_plans = dict(
            self.abi_plans.get("entry_plans") or {}
        )
        call_plans = dict(
            self.abi_plans.get("call_plans") or {}
        )
        for plan_id, plan in entry_plans.items():
            if not isinstance(plan, dict):
                raise PALPublishedRuntimeError(
                    "runtime entry-plan record is not a mapping: %s"
                    % plan_id
                )
            context.register_entry_plan(plan)
        for plan_id, plan in call_plans.items():
            if not isinstance(plan, dict):
                raise PALPublishedRuntimeError(
                    "runtime call-plan record is not a mapping: %s"
                    % plan_id
                )
            context.register_call_plan(plan)
        _install_abi_trace_hooks()
        context._pal_exec_trace = self.trace
        self._assert_context_memory(
            context,
            "top_level_context_constructed",
        )

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
import os

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
    parser.add_argument(
        "--trace",
        action="store_true",
        help="write generic internal-call trace to PAL_runtime_trace.jsonl",
    )
    parser.add_argument(
        "--trace-stderr",
        action="store_true",
        help="also mirror runtime trace records to stderr",
    )
    args = parser.parse_args(argv)

    if args.trace or args.trace_stderr:
        os.environ["PAL_EXEC_TRACE"] = "1"
    if args.trace_stderr:
        os.environ["PAL_EXEC_TRACE_STDERR"] = "1"

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
        self.abi_custody_report: Dict[str, Any] = {}
        self.abi_plan_index_report: Dict[str, Any] = {}
        self.abi_alias_audit_report: Dict[str, Any] = {}
        self.abi_final_authority_report: Dict[str, Any] = {}
        self.abi_authority_loading: Dict[str, Any] = {}
        self.abi_chain_publication: Dict[str, Any] = {}

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
        if (
            str(PAL_STATIC_STRING_COMPLETER_BUILD)
            != "static_strings_v3_rebased_elf_address_truth"
        ):
            raise PALExecInterfaceError(
                "PALStaticStringCompleter build mismatch; "
                "required=static_strings_v3_rebased_elf_address_truth observed=%s"
                % PAL_STATIC_STRING_COMPLETER_BUILD
            )
        helpers = self.pal_root / "PALhelpers.py"
        abi = self.pal_root / "PALABI.py"
        canonicalizer = self.pal_root / "PALABIPlanCanonicalizer.py"
        missing = [
            str(path) for path in (helpers, abi, canonicalizer)
            if not path.is_file()
        ]
        if missing:
            raise PALExecInterfaceError(
                "live PAL runtime/authority modules are missing: %s"
                % ", ".join(missing)
            )

        try:
            authority = _load_project_final_abi_authority(self.project_root)
        except PALExecInterfaceError:
            if not _truthy_environment(
                "PAL_EXEC_ALLOW_LEGACY_ABI_INDEX", False
            ):
                raise
            authority = {
                "entry_plans": {},
                "call_plans": {},
                "source_mode": "legacy_direct_registry_fallback",
                "phase": "legacy_pre_final_authority",
                "status": "degraded",
                "custody_health": "DEGRADED",
                "artifacts": {},
                "acceptance_gates": {
                    "recursive_whole_icecube_discovery_used": False,
                    "whole_object_plan_equality_used": False,
                    "canonical_project_index_consumed": False,
                    "legacy_fallback_explicitly_enabled": True,
                },
            }
            self.warnings.append(
                "legacy ABI registry fallback enabled; final project authority absent"
            )

        self.abi_authority_loading = dict(authority)
        self.entry_plans = dict(authority.get("entry_plans") or {})
        self.call_plans = dict(authority.get("call_plans") or {})
        self.abi_plan_index_report = dict(authority.get("plan_index") or {})
        self.abi_alias_audit_report = dict(authority.get("alias_audit") or {})
        self.abi_custody_report = dict(authority.get("custody_report") or {})
        self.abi_final_authority_report = dict(
            authority.get("final_authority") or {}
        )


    def _merge_plans(self, destination: Dict[str, Any], source: Mapping[str, Any]) -> None:
        for key, value in source.items():
            key = str(key)
            previous = destination.get(key)
            if previous is not None:
                comparison = compare_plans(previous, value)
                if comparison.get("classification") == "core_conflict":
                    raise PALExecInterfaceError(
                        "conflicting immutable ABI plan core: %s" % key
                    )
            destination[key] = dict(value)


    def _prepare_record(self, record: Mapping[str, Any], stage: Path) -> Optional[Dict[str, Any]]:
        if record.get("status") != "decompiled":
            return None
        executable_path = self._artifact_path(record, "executable")
        if executable_path is None or not executable_path.is_file():
            self.warnings.append(
                "%s: executable artifact missing"
                % (record.get("qualified_name") or record.get("name"))
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
        prepared.update({
            "module_stem": module_stem,
            "published_module": published_relative.as_posix(),
            "published_sha256": _sha256_file(published_path),
            "runtime_mode": runtime_mode,
            "python_parameter_count": _function_parameters(
                source, record.get("python_symbol")
            ),
            "runtime_imports": imports,
        })

        entry_plan_id = None
        entry = record.get("entry")
        if isinstance(entry, int):
            expected = "function_entry:%d" % entry
            if expected in self.entry_plans:
                entry_plan_id = expected
        if entry_plan_id is None:
            matches = [
                plan_id for plan_id, plan in self.entry_plans.items()
                if isinstance(plan, Mapping)
                and (
                    plan.get("entry") == entry
                    or str(plan.get("function_id") or "")
                    == str(record.get("function_id") or "")
                )
            ]
            if len(matches) == 1:
                entry_plan_id = matches[0]
            elif len(matches) > 1:
                raise PALExecInterfaceError(
                    "%s: canonical plan index contains ambiguous entry ownership"
                    % (record.get("qualified_name") or record.get("name"))
                )

        icecube_path = self._artifact_path(record, "icecube")
        if icecube_path is not None and icecube_path.is_file():
            if self.abi_authority_loading.get("source_mode") == "legacy_direct_registry_fallback":
                icecube = _read_json(icecube_path)
                entries, calls = _extract_registry_owned_abi_plans(icecube)
                self._merge_plans(self.entry_plans, entries)
                self._merge_plans(self.call_plans, calls)
                if entry_plan_id is None and len(entries) == 1:
                    entry_plan_id = next(iter(entries))
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

        if runtime_mode == "abi_context" and entry_plan_id is None:
            raise PALExecInterfaceError(
                "%s: ABI-emitted function has no canonical entry plan"
                % (record.get("qualified_name") or record.get("name"))
            )
        prepared["entry_plan_id"] = entry_plan_id
        prepared["abi_plan_authority"] = self.abi_authority_loading.get(
            "source_mode"
        )

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


    @staticmethod
    def _abi_conflict_status(value: Any) -> bool:
        text = str(value or "").strip().lower()
        return any(
            token in text
            for token in (
                "conflict",
                "incompatible",
                "ambiguous",
                "mismatch",
            )
        )


    def _analyze_abi_custody_report(self, stage: Path) -> Dict[str, Any]:
        """Project final authority is the only normal ABI publication source."""
        active = bool(self.call_plans or self.entry_plans)
        report = dict(self.abi_custody_report or {})
        receipt = dict(self.abi_final_authority_report or {})
        index = dict(self.abi_plan_index_report or {})
        summary = dict(report.get("summary") or {})
        second_pass = dict(report.get("emitter_v52_second_pass") or {})
        if not second_pass:
            second_pass = dict(receipt.get("emitter_v52_second_pass") or {})

        if not second_pass:
            emitter_second_pass_status = "MISSING"
        elif list(second_pass.get("failures") or []):
            emitter_second_pass_status = "FAILED"
        elif int(second_pass.get("authorized_contracts") or 0) == 0:
            emitter_second_pass_status = "NOT_REQUIRED"
        elif int(second_pass.get("re_emitted_functions") or 0) > 0:
            emitter_second_pass_status = "COMPLETE"
        else:
            emitter_second_pass_status = "INCOMPLETE"

        counts = {
            "internal_calls_linked": int(summary.get("internal_calls_linked") or 0),
            "unresolved_target_plans": int(summary.get("internal_calls_unresolved") or 0),
            "argument_chains_incompatible": int(summary.get("argument_chains_incompatible") or 0),
            "carrier_disagreements": int(summary.get("carrier_disagreements") or 0),
            "return_carriers_deferred": int(summary.get("return_carriers_deferred") or 0),
            "result_width_conflicts": int(summary.get("result_width_conflicts") or 0),
            "result_widths_deferred": int(summary.get("result_widths_deferred") or 0),
            "plan_core_conflicts": int(summary.get("plan_core_conflicts") or 0),
            "ghosts_resolved": int(summary.get("ghost_repairs_resolved") or 0),
            "ghosts_deferred": int(summary.get("ghost_repairs_deferred") or 0),
            "ghosts_conflicting": int(summary.get("ghost_repairs_conflicting") or 0),
            "emitter_repairs_authorized": int(second_pass.get("authorized_contracts") or 0),
            "emitter_repairs_re_emitted": int(second_pass.get("re_emitted_functions") or 0),
        }

        hard = {
            "immutable_plan_core_conflict": counts["plan_core_conflicts"],
            "argument_chain_incompatibility": counts["argument_chains_incompatible"],
            "carrier_disagreement": counts["carrier_disagreements"],
            "result_width_conflict": counts["result_width_conflicts"],
            "conflicting_ghost_contract": counts["ghosts_conflicting"],
        }
        deferred = {
            "unresolved_target_entry_plans": counts["unresolved_target_plans"],
            "return_carriers_deferred": counts["return_carriers_deferred"],
            "result_widths_deferred": counts["result_widths_deferred"],
            "ghost_repairs_deferred": counts["ghosts_deferred"],
        }
        broken_reasons = [name for name, value in hard.items() if value]
        degraded_reasons = [name for name, value in deferred.items() if value]

        structural_failures = []
        if self.abi_authority_loading.get("status") != "verified":
            degraded_reasons.append("legacy_or_unverified_plan_authority")
        if index and index.get("phase") != ABI_FINAL_PHASE:
            structural_failures.append("final_plan_index_phase_mismatch")
        if receipt and receipt.get("status") != "complete":
            structural_failures.append("final_authority_receipt_incomplete")
        if structural_failures:
            broken_reasons.extend(structural_failures)

        declared = str(report.get("status") or "broken").upper()
        computed = (
            "BROKEN" if broken_reasons
            else "DEGRADED" if degraded_reasons
            else "READY"
        )
        if declared not in {"READY", "DEGRADED", "BROKEN"}:
            broken_reasons.append("custody_report_status_invalid")
            computed = "BROKEN"
        elif declared != computed:
            broken_reasons.append(
                "custody_report_health_schema_disagreement:%s!=%s"
                % (declared, computed)
            )
            computed = "BROKEN"

        publication = {
            "active": active,
            "health": computed,
            "artifact": ABI_CUSTODY_REPORT,
            "sha256": (
                self.abi_authority_loading.get("artifacts", {})
                .get("custody_report", {})
                .get("sha256")
            ),
            "inspector_version": report.get("version"),
            "canonicalizer_version": report.get("canonicalizer_version"),
            "report_status": report.get("status"),
            "final_authority": {
                "artifact": ABI_FINAL_AUTHORITY,
                "sha256": (
                    self.abi_authority_loading.get("artifacts", {})
                    .get("final_authority", {})
                    .get("sha256")
                ),
                "status": receipt.get("status"),
                "phase": receipt.get("phase"),
                "build": receipt.get("build"),
            },
            "plan_index": {
                "artifact": PROJECT_ABI_PLAN_INDEX,
                "sha256": (
                    self.abi_authority_loading.get("artifacts", {})
                    .get("plan_index", {})
                    .get("sha256")
                ),
                "phase": index.get("phase"),
                "status": index.get("status"),
                "entry_plans": len(self.entry_plans),
                "call_plans": len(self.call_plans),
            },
            "alias_audit": {
                "artifact": PROJECT_ABI_ALIAS_AUDIT,
                "sha256": (
                    self.abi_authority_loading.get("artifacts", {})
                    .get("alias_audit", {})
                    .get("sha256")
                ),
            },
            "source_mode": self.abi_authority_loading.get("source_mode"),
            "emitter_second_pass_status": emitter_second_pass_status,
            "counts": counts,
            "broken_reasons": broken_reasons,
            "degraded_reasons": degraded_reasons,
            "acceptance_gates": dict(
                self.abi_authority_loading.get("acceptance_gates") or {}
            ),
            "rule": (
                "project_final_plan_index_is_runtime_plan_authority;_"
                "BROKEN_health_blocks_execution;_DEGRADED_is_diagnostic_"
                "and_runs_with_warning;_recursive_icecube_plan_discovery_"
                "is_not_used"
            ),
        }
        self.abi_chain_publication = publication
        return publication

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
            ABI_CUSTODY_REPORT,
            PROJECT_ABI_PLAN_INDEX,
            PROJECT_ABI_ALIAS_AUDIT,
            ABI_FINAL_AUTHORITY,
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

    def _classify_non_string_ptrsub_references(
        self,
        stage: Path,
    ) -> Dict[str, Any]:
        """Exclude manifest-owned code pointers from string health."""
        report = dict(
            getattr(
                self,
                "static_string_completion_report",
                {},
            )
            or {}
        )
        unresolved = list(report.get("unresolved") or [])

        entries: Dict[int, Dict[str, Any]] = {}
        body_ranges: List[Tuple[int, int, Dict[str, Any]]] = []
        for record in self.records:
            entry = record.get("entry")
            if isinstance(entry, int):
                entries[int(entry)] = dict(record)
            body_min = record.get("body_min")
            body_max = record.get("body_max")
            if isinstance(body_min, int) and isinstance(body_max, int):
                body_ranges.append(
                    (
                        int(body_min),
                        int(body_max),
                        dict(record),
                    )
                )

        remaining = []
        function_pointers = []
        code_pointers = []
        for item in unresolved:
            raw_address = (
                item.get("generated_address")
                or item.get("address")
            )
            try:
                address = int(str(raw_address), 0)
            except (TypeError, ValueError):
                remaining.append(item)
                continue

            owner = entries.get(address)
            if owner is not None:
                function_pointers.append({
                    "generated_address": hex(address),
                    "classification": "manifest_function_entry_pointer",
                    "function_id": owner.get("function_id"),
                    "function_name": owner.get("name"),
                    "entry_hex": owner.get("entry_hex") or hex(address),
                    "reasons": list(item.get("reasons") or []),
                })
                continue

            range_owner = None
            for body_min, body_max, candidate in body_ranges:
                if body_min <= address <= body_max:
                    range_owner = candidate
                    break
            if range_owner is not None:
                code_pointers.append({
                    "generated_address": hex(address),
                    "classification": "manifest_function_body_pointer",
                    "function_id": range_owner.get("function_id"),
                    "function_name": range_owner.get("name"),
                    "body_min_hex": range_owner.get("body_min_hex"),
                    "body_max_hex": range_owner.get("body_max_hex"),
                    "reasons": list(item.get("reasons") or []),
                })
                continue

            remaining.append(item)

        counts = dict(report.get("counts") or {})
        counts["unresolved_ptrsub_references"] = len(remaining)
        counts["function_pointer_references"] = len(function_pointers)
        counts["code_pointer_references"] = len(code_pointers)
        report["counts"] = counts
        report["unresolved"] = remaining
        report["function_pointer_references"] = function_pointers
        report["code_pointer_references"] = code_pointers

        translation = dict(
            report.get("address_translation") or {}
        )
        translation["unresolved_references"] = len(remaining)
        translation["function_pointer_references"] = len(function_pointers)
        translation["code_pointer_references"] = len(code_pointers)
        report["address_translation"] = translation

        classification = {
            "build": (
                "ptrsub_reference_classifier_v1_"
                "manifest_code_authority"
            ),
            "function_pointer_references": len(function_pointers),
            "code_pointer_references": len(code_pointers),
            "remaining_unresolved_references": len(remaining),
            "function_pointers": function_pointers,
            "code_pointers": code_pointers,
            "rule": (
                "manifest_function_entry_or_body_ownership_"
                "excludes_address_from_static_string_health"
            ),
        }
        report["non_string_reference_classification"] = classification

        self.static_string_completion_report = report
        _write_json(
            self.project_root / "PAL_static_string_completion.json",
            report,
        )
        _write_json(
            stage / "PAL_static_string_completion.json",
            report,
        )
        return classification

    def _record_static_string_completion_warnings(
        self,
    ) -> None:
        report = dict(
            getattr(
                self,
                "static_string_completion_report",
                {},
            )
            or {}
        )
        unresolved = list(
            report.get("unresolved") or []
        )
        for record in unresolved:
            address = str(
                record.get("generated_address")
                or record.get("address")
                or "unknown"
            )
            direct_address = str(
                record.get("direct_elf_address")
                or "-"
            )
            rebased_address = str(
                record.get("rebased_elf_address")
                or "-"
            )
            message = (
                "static-string PTRSUB unresolved: "
                "generated=%s direct=%s rebased=%s"
                % (
                    address,
                    direct_address,
                    rebased_address,
                )
            )
            if message not in self.warnings:
                self.warnings.append(message)

        for warning in list(
            report.get("parse_warnings") or []
        ):
            message = (
                "static-string source scan warning: %s"
                % warning
            )
            if message not in self.warnings:
                self.warnings.append(message)

    def _audit_static_string_stage(
        self,
        stage: Path,
    ) -> Dict[str, Any]:
        report = dict(
            getattr(
                self,
                "static_string_completion_report",
                {},
            )
            or {}
        )
        if not report.get("active", True):
            return {
                "active": False,
                "health": "INACTIVE",
                "reason": report.get(
                    "reason",
                    "completion_not_active",
                ),
                "required_strings": 0,
                "overlay_strings": 0,
                "direct_resolved_references": 0,
                "rebased_resolved_references": 0,
                "ambiguous_references": 0,
                "unresolved_references": 0,
                "address_translation": {},
                "failures": [],
            }

        overlay_path = stage / "PAL_stdio_strings.json"
        if not overlay_path.is_file():
            raise PALExecInterfaceError(
                "static-string completion was active but "
                "the published overlay is missing: %s"
                % overlay_path
            )

        payload = _read_json(overlay_path)
        raw_strings = payload.get("strings", payload)
        if not isinstance(raw_strings, dict):
            raise PALExecInterfaceError(
                "published PAL_stdio_strings.json lacks "
                "a string table"
            )

        strings = {
            hex(int(str(raw_address), 0)): str(value)
            for raw_address, value in raw_strings.items()
        }
        required = {
            hex(int(str(raw_address), 0)): str(value)
            for raw_address, value in dict(
                report.get("required_strings") or {}
            ).items()
        }

        failures = []
        for address, expected in sorted(
            required.items(),
            key=lambda item: int(item[0], 0),
        ):
            observed = strings.get(address)
            if observed != expected:
                failures.append({
                    "address": address,
                    "expected": expected,
                    "observed": observed,
                })

        counts = dict(report.get("counts") or {})
        translation = dict(
            report.get("address_translation") or {}
        )
        unresolved = int(
            counts.get(
                "unresolved_ptrsub_references",
                translation.get(
                    "unresolved_references",
                    0,
                ),
            )
            or 0
        )
        ambiguous = int(
            counts.get(
                "ambiguous_references",
                translation.get(
                    "ambiguous_references",
                    0,
                ),
            )
            or 0
        )

        if ambiguous:
            failures.append({
                "kind": (
                    "static_string_ambiguous_address_"
                    "mapping_reached_stage"
                ),
                "count": ambiguous,
            })

        health = (
            "BROKEN"
            if failures
            else (
                "DEGRADED"
                if unresolved
                else "READY"
            )
        )
        audit = {
            "active": True,
            "health": health,
            "overlay": str(overlay_path),
            "required_strings": len(required),
            "overlay_strings": len(strings),
            "direct_resolved_references": int(
                counts.get(
                    "direct_resolved_references",
                    translation.get(
                        "direct_resolved_references",
                        0,
                    ),
                )
                or 0
            ),
            "rebased_resolved_references": int(
                counts.get(
                    "rebased_resolved_references",
                    translation.get(
                        "rebased_resolved_references",
                        0,
                    ),
                )
                or 0
            ),
            "ambiguous_references": ambiguous,
            "unresolved_references": unresolved,
            "address_translation": translation,
            "failures": failures,
            "rule": (
                "every_resolved_completer_string_must_exist_"
                "exactly_in_the_published_overlay; unresolved_"
                "strong_PTRSUB_references_publish_as_DEGRADED"
            ),
        }
        if failures:
            raise PALExecInterfaceError(
                "published static-string overlay audit "
                "failed: %s" % failures
            )
        return audit


    def _publish_config(self, stage: Path, runtime_modules: Sequence[str]) -> Dict[str, Any]:
        default_entry = self._default_entry()
        completion_report = dict(
            getattr(
                self,
                "static_string_completion_report",
                {},
            )
            or {}
        )
        completion_counts = dict(
            completion_report.get("counts") or {}
        )
        stage_audit = dict(
            getattr(
                self,
                "static_string_stage_audit",
                {},
            )
            or {}
        )
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
                "abi_internal_calls_linked": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "internal_calls_linked", 0
                    ) or 0
                ),
                "abi_unresolved_target_plans": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "unresolved_target_plans", 0
                    ) or 0
                ),
                "abi_argument_chains_incompatible": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "argument_chains_incompatible", 0
                    ) or 0
                ),
                "abi_plan_core_conflicts": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "plan_core_conflicts", 0
                    ) or 0
                ),
                "abi_carrier_disagreements": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "carrier_disagreements", 0
                    ) or 0
                ),
                "abi_result_width_conflicts": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "result_width_conflicts", 0
                    ) or 0
                ),
                "abi_ghosts_resolved": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "ghosts_resolved", 0
                    ) or 0
                ),
                "abi_ghosts_deferred": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "ghosts_deferred", 0
                    ) or 0
                ),
                "abi_ghosts_conflicting": int(
                    (self.abi_chain_publication.get("counts") or {}).get(
                        "ghosts_conflicting", 0
                    ) or 0
                ),
                "static_strings_original": int(
                    completion_counts.get(
                        "original_strings",
                        0,
                    )
                    or 0
                ),
                "static_strings_completed": int(
                    completion_counts.get(
                        "completed_strings",
                        0,
                    )
                    or 0
                ),
                "static_strings_final": int(
                    completion_counts.get(
                        "final_strings",
                        stage_audit.get(
                            "overlay_strings",
                            0,
                        ),
                    )
                    or 0
                ),
                "static_strings_required": int(
                    completion_counts.get(
                        "required_runtime_strings",
                        stage_audit.get(
                            "required_strings",
                            0,
                        ),
                    )
                    or 0
                ),
                "static_strings_direct_resolved": int(
                    completion_counts.get(
                        "direct_resolved_references",
                        0,
                    )
                    or 0
                ),
                "static_strings_rebased_resolved": int(
                    completion_counts.get(
                        "rebased_resolved_references",
                        0,
                    )
                    or 0
                ),
                "static_strings_ambiguous": int(
                    completion_counts.get(
                        "ambiguous_references",
                        0,
                    )
                    or 0
                ),
                "static_strings_function_pointers": int(
                    completion_counts.get(
                        "function_pointer_references",
                        0,
                    )
                    or 0
                ),
                "static_strings_code_pointers": int(
                    completion_counts.get(
                        "code_pointer_references",
                        0,
                    )
                    or 0
                ),
                "static_strings_unresolved_ptrsub": int(
                    completion_counts.get(
                        "unresolved_ptrsub_references",
                        0,
                    )
                    or 0
                ),
            },
            "abi_authority_loading": {
                "source_mode": self.abi_authority_loading.get("source_mode"),
                "phase": self.abi_authority_loading.get("phase"),
                "status": self.abi_authority_loading.get("status"),
                "artifacts": dict(self.abi_authority_loading.get("artifacts") or {}),
                "acceptance_gates": dict(
                    self.abi_authority_loading.get("acceptance_gates") or {}
                ),
            },
            "abi_chain_publication": dict(
                self.abi_chain_publication or {}
            ),
            "runtime_modules": list(runtime_modules),
            "runtime_templates": {
                "PAL_project_runtime.py": {
                    "authority": (
                        "PALExecInterface.PAL_PROJECT_RUNTIME_SOURCE"
                    ),
                    "version": PAL_PROJECT_RUNTIME_TEMPLATE_VERSION,
                    "sha256": hashlib.sha256(
                        PAL_PROJECT_RUNTIME_SOURCE.encode("utf-8")
                    ).hexdigest(),
                },
            },
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
                "static strings referenced through base-zero PTRSUB are completed from readable ELF PT_LOAD bytes into PAL_stdio_strings.json; non-string ELF data remains outside this clear-case mapper",
                "a published function may still fail when its frozen ABI plan is deferred",
                "explicit init trunks return a zero sentinel and are diagnostic substitutes, not recovered semantics",
            ],
            "warnings": list(self.warnings),
            "static_string_completion": completion_report,
            "runtime_trace": {
                "version": "runtime_trace_v1_internal_call_memory_custody",
                "default_enabled": False,
                "enable_environment": "PAL_EXEC_TRACE=1",
                "stderr_environment": "PAL_EXEC_TRACE_STDERR=1",
                "artifact": "PAL_runtime_trace.jsonl",
                "captures": [
                    "module_memory_root_identity",
                    "ABI_context_memory_root_identity",
                    "internal_call_arguments",
                    "mapped_pointer_previews",
                    "internal_call_results",
                    "child_frame_materialized_arguments",
                    "callee_semantic_results",
                    "child_return_carriers",
                    "parent_return_carriers",
                    "caller_visible_result_views",
                    "ABI_chain_publication_health",
                    "guarded_ABI_argument_bridge_events",
                    "exceptions",
                ],
            },
            "static_string_memory_publication": {
                "completion_build": completion_report.get(
                    "build"
                ),
                "health": stage_audit.get(
                    "health",
                    "UNKNOWN",
                ),
                "address_translation": dict(
                    completion_report.get(
                        "address_translation"
                    )
                    or {}
                ),
                "transport": "PAL_stdio_strings.json",
                "publisher_stage_audit": stage_audit,
                "runtime_mapper": (
                    "PALShims.PALPrintShims."
                    "_load_stdio_literals"
                ),
                "runtime_memory": "PALMEM.PALMemory",
                "runtime_audit": (
                    "v5_internal_call_memory_custody_trace"
                ),
                "lifted_load_consumer": (
                    "PALhelpers.c_load"
                ),
                "non_string_reference_classification": dict(
                    completion_report.get(
                        "non_string_reference_classification"
                    )
                    or {}
                ),
            },
        }
        _write_json(stage / EXEC_CONFIG, config)
        _write_json(
            stage / ABI_PLAN_INDEX,
            {
                "format": "pal_runtime_abi_plan_index",
                "schema_version": 2,
                "source_authority": "PAL_abi_plan_index.json",
                "source_plan_index_sha256": (
                    self.abi_authority_loading.get("artifacts", {})
                    .get("plan_index", {})
                    .get("sha256")
                ),
                "source_final_authority_sha256": (
                    self.abi_authority_loading.get("artifacts", {})
                    .get("final_authority", {})
                    .get("sha256")
                ),
                "phase": self.abi_authority_loading.get("phase"),
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
            self._analyze_abi_custody_report(stage)
            runtime_modules = self._copy_runtime_dependencies(stage)
            self._copy_project_authorities(stage)
            self.static_string_completion_report = complete_project_static_strings(
                pal_root=self.pal_root,
                project_root=self.project_root,
                stage_root=stage,
                manifest=self.manifest,
            )
            self.static_non_string_reference_classification = (
                self._classify_non_string_ptrsub_references(stage)
            )
            self._record_static_string_completion_warnings()
            self.static_string_stage_audit = (
                self._audit_static_string_stage(stage)
            )
            _write_text(stage / "shims" / "PALShims.py", PALSHIMS_SOURCE)
            project_runtime_path = stage / "PAL_project_runtime.py"
            _write_text(project_runtime_path, PAL_PROJECT_RUNTIME_SOURCE)
            expected_runtime_sha256 = hashlib.sha256(
                PAL_PROJECT_RUNTIME_SOURCE.encode("utf-8")
            ).hexdigest()
            observed_runtime_sha256 = _sha256_file(project_runtime_path)
            if observed_runtime_sha256 != expected_runtime_sha256:
                raise PALExecInterfaceError(
                    "published PAL_project_runtime.py diverged from "
                    "PALExecInterface steel template; expected=%s observed=%s"
                    % (
                        expected_runtime_sha256,
                        observed_runtime_sha256,
                    )
                )
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



class PALExecPublisherV1s(PALExecPublisher):
    """Opt-in triage trunks plus guarded runtime ABI argument bridges."""

    def __init__(
        self,
        pal_root: Path,
        project_root: Path,
        *,
        incomplete_policy: str = "abort",
        argument_policy: str = "abort",
    ) -> None:
        super().__init__(pal_root, project_root)
        policy = str(incomplete_policy or "abort").strip().lower()
        if policy not in _INIT_TRUNK_POLICIES:
            raise PALExecInterfaceError(
                "unknown incomplete-function policy: %s" % policy
            )
        argument_policy = str(
            argument_policy or "abort"
        ).strip().lower()
        if argument_policy not in _ABI_ARGUMENT_POLICIES:
            raise PALExecInterfaceError(
                "unknown ABI argument policy: %s"
                % argument_policy
            )
        self.incomplete_policy = policy
        self.argument_policy = argument_policy
        self.partial_publication_report: Dict[str, Any] = {
            "format": "pal_abi_partial_publication",
            "schema_version": 1,
            "build": PAL_EXEC_INTERFACE_BUILD,
            "active": False,
            "requested_policy": policy,
            "requested_argument_policy": argument_policy,
            "publication_class": "complete",
            "effective_policy": "complete_project",
            "effective_argument_policy": "not_required",
            "trunked_functions": [],
            "blocked_functions": [],
            "runtime_plan_overlays": [],
            "runtime_argument_bridges": [],
            "argument_bridge_rejections": [],
            "waivers": {},
            "rule": (
                "abort_by_default; explicit user approval is required; "
                "trunks preserve internal dispatch identity and return zero "
                "without claiming successful decompilation"
            ),
        }
        self._trunk_by_identity: Dict[str, Dict[str, Any]] = {}

    def _resolve_incomplete_policy(self) -> None:
        incomplete = _incomplete_internal_records(self.records)
        if not incomplete:
            return

        init_records = [
            record
            for record in incomplete
            if record.get("init_family_classification")
        ]
        non_init = [
            record
            for record in incomplete
            if not record.get("init_family_classification")
        ]
        policy = self.incomplete_policy

        if policy == "prompt":
            if not sys.stdin.isatty():
                raise PALExecInterfaceError(
                    "incomplete internal decompilation requires an "
                    "interactive triage choice or an explicit "
                    "--incomplete-policy trunk-init/trunk-all"
                )
            module_rows = []
            for record in incomplete:
                module_rows.append(
                    (
                        str(
                            record.get("qualified_name")
                            or record.get("name")
                            or _record_identity_token(record)
                        ),
                        str(record.get("entry_hex") or record.get("entry") or "-"),
                        str(record.get("status") or "not_compiled"),
                        str(
                            record.get("init_family_classification")
                            or "ordinary_internal"
                        ),
                    )
                )
            print(
                "\n"
                + _tabloid_banner(
                    "UNCOMPILED MODULES // TRIAGE REQUIRED",
                    "%d INTERNAL FUNCTION%s HAVE NO EXECUTABLE MODULE"
                    % (
                        len(incomplete),
                        "" if len(incomplete) == 1 else "S",
                    ),
                )
            )
            print(
                _ascii_table(
                    ("FUNCTION", "ENTRY", "SOURCE STATUS", "CLASS"),
                    module_rows,
                )
            )
            print(
                _tabloid_card(
                    "TRIAGED PUBLICATION OPTION",
                    (
                        (
                            "T",
                            "publish compiled modules plus explicit "
                            "void/zero ABI trunks",
                        ),
                        (
                            "preview contract",
                            "valid only for paths that do not depend on "
                            "sidelined-function semantics",
                        ),
                        (
                            "trunk call result",
                            "observable diagnostic zero sentinel",
                        ),
                        (
                            "workspace class",
                            "TRIAGED / DEGRADED",
                        ),
                    ),
                    state="WARN",
                )
            )
            while True:
                choice = input(
                    "[A] abort publication\n"
                    "[T] publish TRIAGED version with void/zero ABI trunks\n"
                    "Choice [A/T]: "
                ).strip().lower()
                if choice in {"a", "abort", ""}:
                    raise PALExecInterfaceError(
                        "publication aborted by operator after incomplete "
                        "internal-module detection"
                    )
                if choice in {"t", "trunk", "publish"}:
                    policy = (
                        "trunk-init"
                        if init_records and not non_init
                        else "trunk-all"
                    )
                    self.partial_publication_report[
                        "operator_approval_source"
                    ] = "interactive_T"
                    break
                print("Enter A or T.")

        if policy == "abort":
            names = ", ".join(
                str(
                    record.get("qualified_name")
                    or record.get("name")
                    or _record_identity_token(record)
                )
                for record in incomplete
            )
            raise PALExecInterfaceError(
                "project contains non-decompiled internal functions: %s; "
                "use interactive publication or "
                "--incomplete-policy trunk-init for recognized ELF init "
                "failures" % names
            )

        if policy == "trunk-init":
            selected = init_records
            blocked = non_init
        elif policy == "trunk-all":
            selected = incomplete
            blocked = []
        else:
            raise PALExecInterfaceError(
                "incomplete publication policy did not resolve"
            )

        if blocked:
            names = ", ".join(
                _record_identity_token(record)
                for record in blocked
            )
            raise PALExecInterfaceError(
                "trunk-init policy cannot waive non-init decompilation "
                "failures: %s" % names
            )
        if not selected:
            raise PALExecInterfaceError(
                "trunk policy selected but no eligible failed functions exist"
            )

        descriptors = []
        for record in selected:
            entry = record.get("entry")
            if not isinstance(entry, int):
                raise PALExecInterfaceError(
                    "cannot install an ABI trunk without a function entry: %s"
                    % _record_identity_token(record)
                )
            plan_id = "function_entry:%d" % entry
            descriptor = {
                "identity": _record_identity_token(record),
                "function_id": record.get("function_id"),
                "name": record.get("name"),
                "qualified_name": record.get("qualified_name"),
                "entry": entry,
                "entry_hex": record.get("entry_hex") or hex(entry),
                "entry_plan_id": plan_id,
                "source_status": record.get("status"),
                "classification": (
                    record.get("init_family_classification")
                    or "operator_approved_non_init"
                ),
                "normalized_names": sorted(
                    _normalized_function_names(record)
                ),
                "trunk_return_value": 0,
                "trunk_return_policy": "void_zero_sentinel",
                "triage_role": "abi_sidelined_function",
                "preview_contract": (
                    "call_path_must_not_depend_on_sidelined_semantics"
                ),
            }
            descriptors.append(descriptor)
            self._trunk_by_identity[
                descriptor["identity"]
            ] = descriptor

        self.partial_publication_report.update({
            "active": True,
            "publication_class": "triaged",
            "effective_policy": policy,
            "trunked_functions": descriptors,
            "blocked_functions": [],
            "operator_approval_required": True,
            "operator_approval_source": (
                self.partial_publication_report.get(
                    "operator_approval_source"
                )
                or "explicit_policy:%s" % policy
            ),
            "runtime_health_floor": "DEGRADED",
            "preview_contract": (
                "execution_paths_must_not_depend_on_trunked_function_semantics"
            ),
        })

    def _validate_project(self) -> None:
        if self.manifest.get("format") != "pal_function_bundle":
            self.warnings.append(
                "unexpected manifest format %r"
                % self.manifest.get("format")
            )
        if not self.records:
            raise PALExecInterfaceError(
                "project manifest contains no functions"
            )
        if (
            str(PAL_STATIC_STRING_COMPLETER_BUILD)
            != "static_strings_v3_rebased_elf_address_truth"
        ):
            raise PALExecInterfaceError(
                "PALStaticStringCompleter build mismatch; "
                "required=static_strings_v3_rebased_elf_address_truth "
                "observed=%s"
                % PAL_STATIC_STRING_COMPLETER_BUILD
            )
        missing = [
            str(path)
            for path in (
                self.pal_root / "PALhelpers.py",
                self.pal_root / "PALABI.py",
                self.pal_root / "PALABIPlanCanonicalizer.py",
            )
            if not path.is_file()
        ]
        if missing:
            raise PALExecInterfaceError(
                "live PAL runtime/authority modules are missing: %s"
                % ", ".join(missing)
            )

        observed_palabi = _python_string_constant(
            self.pal_root / "PALABI.py",
            "PAL_ABI_RUNTIME_VERSION",
        )
        if observed_palabi != PAL_ABI_RUNTIME_REQUIRED_VERSION:
            raise PALExecInterfaceError(
                "PALABI runtime build mismatch; required=%s observed=%s"
                % (
                    PAL_ABI_RUNTIME_REQUIRED_VERSION,
                    observed_palabi or "unknown",
                )
            )

        self._resolve_incomplete_policy()

        try:
            authority = _load_project_final_abi_authority(
                self.project_root
            )
        except PALExecInterfaceError as strict_error:
            if self.partial_publication_report.get("active"):
                authority = _load_partial_project_abi_authority(
                    self.project_root
                )
                authority["strict_authority_error"] = str(strict_error)
                self.warnings.append(
                    "final ABI authority unavailable; explicit partial "
                    "init-trunk authority engaged: %s" % strict_error
                )
            elif _truthy_environment(
                "PAL_EXEC_ALLOW_LEGACY_ABI_INDEX",
                False,
            ):
                authority = {
                    "entry_plans": {},
                    "call_plans": {},
                    "source_mode": (
                        "legacy_direct_registry_fallback"
                    ),
                    "phase": "legacy_pre_final_authority",
                    "status": "degraded",
                    "custody_health": "DEGRADED",
                    "artifacts": {},
                    "acceptance_gates": {
                        "recursive_whole_icecube_discovery_used": False,
                        "whole_object_plan_equality_used": False,
                        "canonical_project_index_consumed": False,
                        "legacy_fallback_explicitly_enabled": True,
                    },
                }
                self.warnings.append(
                    "legacy ABI registry fallback enabled; final project "
                    "authority absent"
                )
            else:
                raise

        self.abi_authority_loading = dict(authority)
        self.entry_plans = copy.deepcopy(
            dict(authority.get("entry_plans") or {})
        )
        self.call_plans = copy.deepcopy(
            dict(authority.get("call_plans") or {})
        )
        self.abi_plan_index_report = dict(
            authority.get("plan_index") or {}
        )
        self.abi_alias_audit_report = dict(
            authority.get("alias_audit") or {}
        )
        self.abi_custody_report = dict(
            authority.get("custody_report") or {}
        )
        self.abi_final_authority_report = dict(
            authority.get("final_authority") or {}
        )
        self._install_trunk_abi_overlays()

    def _related_trunk_call_plans(
        self,
        descriptor: Mapping[str, Any],
    ) -> List[Dict[str, Any]]:
        return [
            dict(plan)
            for plan in self.call_plans.values()
            if isinstance(plan, Mapping)
            and _call_plan_targets_trunk(
                plan,
                [descriptor],
            )
        ]

    def _synthetic_trunk_entry_plan(
        self,
        record: Mapping[str, Any],
        descriptor: Mapping[str, Any],
    ) -> Dict[str, Any]:
        related = self._related_trunk_call_plans(descriptor)
        fixed_count = 0
        if related:
            fixed_count = max(
                len(list(plan.get("arguments") or []))
                for plan in related
            )
        fixed_arguments = []
        representative = related[0] if related else {}
        arguments = sorted(
            [
                dict(item)
                for item in list(
                    representative.get("arguments") or []
                )
                if isinstance(item, Mapping)
            ],
            key=lambda item: int(item.get("index") or 0),
        )
        for index in range(fixed_count):
            argument = (
                arguments[index]
                if index < len(arguments)
                else {}
            )
            carrier_kind = str(
                argument.get("carrier_kind")
                or "gp_register"
            )
            register = argument.get("carrier")
            width = int(
                argument.get("source_width_bits")
                or 64
            )
            if carrier_kind == "xmm_register":
                register = register or "XMM%d" % index
                carrier_bank = "vector"
                carrier_class = (
                    argument.get("argument_class")
                    or "sse"
                )
            elif carrier_kind == "stack_overflow_argument":
                register = None
                carrier_bank = "stack"
                carrier_class = (
                    argument.get("argument_class")
                    or "integer"
                )
            else:
                gp = ("RDI", "RSI", "RDX", "RCX", "R8", "R9")
                register = register or gp[min(index, len(gp) - 1)]
                carrier_kind = "gp_register"
                carrier_bank = "general"
                carrier_class = (
                    argument.get("argument_class")
                    or "integer"
                )
            binding = {
                "carrier_index": index,
                "register": register,
                "storage_key": (
                    "stack:%d:%d"
                    % (
                        int(argument.get("stack_slot") or 0),
                        max(width // 8, 1),
                    )
                    if carrier_kind == "stack_overflow_argument"
                    else "register:trunk:%d"
                    % max(width // 8, 1)
                ),
                "carrier_class": carrier_class,
                "carrier_bank": carrier_bank,
                "callable_argument": True,
                "stack_slot": argument.get("stack_slot"),
            }
            fixed_arguments.append({
                "ordinal": index,
                "source_sid": argument.get("source_sid"),
                "name": "trunk_arg_%d" % index,
                "physical_carrier_bindings": [binding],
            })

        plan = {
            "plan_class": "function_entry_abi_plan",
            "plan_id": descriptor["entry_plan_id"],
            "kind": "pal_exec_triage_trunk_entry_plan_v2",
            "entry": descriptor["entry"],
            "function": (
                record.get("qualified_name")
                or record.get("name")
            ),
            "function_id": record.get("function_id"),
            "fixed_argument_count": fixed_count,
            "fixed_arguments": fixed_arguments,
            "return_contract": {
                "declared_void": True,
                "logical_result_width_bits": None,
                "effective_result_width_bits": None,
                "no_return": False,
                "trunk_return_policy": "void_zero_sentinel",
            },
            "abi_backend": {
                "name": "sysv_amd64",
                "authority": (
                    "PALExecInterface_v1s_explicit_triage_trunk"
                ),
            },
            "downstream_reinference_allowed": False,
            "partial_trunk_overlay": {
                "active": True,
                "classification": descriptor["classification"],
                "source_status": descriptor["source_status"],
                "operator_approved": True,
            },
        }
        return stamp_plan(plan)

    def _install_trunk_abi_overlays(self) -> None:
        if not self.partial_publication_report.get("active"):
            return
        descriptors = list(
            self.partial_publication_report.get(
                "trunked_functions"
            )
            or []
        )
        records_by_identity = {
            _record_identity_token(record): record
            for record in self.records
        }
        for descriptor in descriptors:
            plan_id = str(descriptor["entry_plan_id"])
            if plan_id not in self.entry_plans:
                record = records_by_identity[
                    descriptor["identity"]
                ]
                self.entry_plans[plan_id] = (
                    self._synthetic_trunk_entry_plan(
                        record,
                        descriptor,
                    )
                )
                descriptor["entry_plan_source"] = "synthetic_trunk"
            else:
                descriptor["entry_plan_source"] = (
                    "project_authority"
                )

        overlays = []
        for plan_id, raw_plan in list(
            self.call_plans.items()
        ):
            if not _call_plan_targets_trunk(
                raw_plan,
                descriptors,
            ):
                continue
            plan = copy.deepcopy(raw_plan)
            target = dict(plan.get("target") or {})
            matched = next(
                descriptor
                for descriptor in descriptors
                if _call_plan_targets_trunk(
                    plan,
                    [descriptor],
                )
            )
            target["entry_plan_lookup_key"] = (
                matched["entry_plan_id"]
            )
            plan["target"] = target
            compatibility = dict(
                plan.get("target_compatibility") or {}
            )
            compatibility["entry_plan_lookup_key"] = (
                matched["entry_plan_id"]
            )
            plan["target_compatibility"] = compatibility
            original_identity = canonicalize_plan(raw_plan)
            plan["result_width_bits"] = None
            result = dict(
                plan.get("result_contract") or {}
            )
            for key in (
                "output_sid",
                "output_width_bits",
                "effective_result_width_bits",
                "candidate_result_width_bits",
            ):
                result[key] = None
            result["call_result_candidate"] = {
                "candidate": False,
                "status": "suppressed_by_explicit_triage_trunk",
            }
            plan["result_contract"] = result
            plan.pop("call_result_candidate", None)
            plan.pop("abi_custody_contract", None)
            plan.pop("abi_custody_contract_ref", None)
            plan.pop("abi_plan_identity", None)
            plan["partial_trunk_overlay"] = {
                "active": True,
                "target_identity": matched["identity"],
                "source_plan_core_sha256": (
                    original_identity["plan_core_sha256"]
                ),
                "result_policy": "void_zero_sentinel",
                "operator_approved": True,
            }
            plan = stamp_plan(plan)
            self.call_plans[str(plan_id)] = plan
            overlays.append({
                "plan_id": str(plan_id),
                "target_identity": matched["identity"],
                "source_plan_core_sha256": (
                    original_identity["plan_core_sha256"]
                ),
                "runtime_plan_core_sha256": (
                    canonicalize_plan(plan)[
                        "plan_core_sha256"
                    ]
                ),
                "result_policy": "void_zero_sentinel",
            })
        self.partial_publication_report[
            "runtime_plan_overlays"
        ] = overlays

    def _trunk_descriptor_for_record(
        self,
        record: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        return self._trunk_by_identity.get(
            _record_identity_token(record)
        )

    def _prepare_trunk_record(
        self,
        record: Mapping[str, Any],
        descriptor: Mapping[str, Any],
        stage: Path,
    ) -> Dict[str, Any]:
        module_stem = _safe_module_stem(record) + "_abi_trunk"
        symbol = str(
            record.get("python_symbol")
            or record.get("name")
            or "pal_abi_trunk"
        )
        symbol = re.sub(r"[^0-9A-Za-z_]+", "_", symbol)
        if not symbol or symbol[0].isdigit():
            symbol = "pal_abi_trunk_" + symbol
        published_relative = (
            Path("functions") / (module_stem + ".py")
        )
        published_path = stage / published_relative
        source = (
            "# Generated PAL TRIAGED ABI trunk; source function did not compile.\n"
            "# Preview paths must not depend on this sidelined function's semantics.\n"
            "PAL_ABI_TRUNK = %r\n\n"
            "def %s(*values):\n"
            "    return 0\n"
            % (dict(descriptor), symbol)
        )
        compile(source, str(published_path), "exec")
        _write_text(published_path, source)
        py_compile.compile(str(published_path), doraise=True)

        prepared = dict(record)
        prepared.update({
            "status": "trunked_incomplete",
            "source_status": record.get("status"),
            "module_stem": module_stem,
            "published_module": published_relative.as_posix(),
            "published_sha256": _sha256_file(published_path),
            "python_symbol": symbol,
            "runtime_mode": "abi_trunk",
            "python_parameter_count": 0,
            "runtime_imports": [],
            "entry_plan_id": descriptor["entry_plan_id"],
            "abi_plan_authority": (
                "explicit_user_approved_triage_trunk"
            ),
            "is_shim_boundary": False,
            "abi_trunk": True,
            "trunk_reason": descriptor["classification"],
            "trunk_return_value": 0,
            "trunk_return_policy": "void_zero_sentinel",
        })
        icecube_path = self._artifact_path(record, "icecube")
        if icecube_path is not None and icecube_path.is_file():
            target = stage / "icecubes" / icecube_path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(icecube_path, target)
            prepared["published_icecube"] = str(
                Path("icecubes") / icecube_path.name
            )
        return prepared

    def _prepare_record(
        self,
        record: Mapping[str, Any],
        stage: Path,
    ) -> Optional[Dict[str, Any]]:
        descriptor = self._trunk_descriptor_for_record(record)
        if descriptor is not None:
            return self._prepare_trunk_record(
                record,
                descriptor,
                stage,
            )
        return super()._prepare_record(record, stage)

    def _partial_waivers(
        self,
        report: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Waive only custody defects exactly attributable to approved trunks."""
        trunks = list(
            self.partial_publication_report.get(
                "trunked_functions"
            )
            or []
        )
        overlays = list(
            self.partial_publication_report.get(
                "runtime_plan_overlays"
            )
            or []
        )
        overlay_plan_ids = {
            str(item.get("plan_id"))
            for item in overlays
            if isinstance(item, Mapping)
            and item.get("plan_id") not in (None, "")
        }
        waivers: Dict[str, Any] = {
            "unresolved_target_plans": 0,
            "argument_chains_incompatible": 0,
            "return_carriers_deferred": 0,
            "result_widths_deferred": 0,
            "ghosts_deferred": 0,
            "records": [],
            "unmatched_incompatible_contracts": [],
            "attribution_rule": (
                "exact trunk function name, entry, function_id, "
                "entry_plan_id, target entry_plan_lookup_key, or "
                "runtime overlay plan_id"
            ),
        }
        if not trunks:
            return waivers

        unresolved_ids: set[str] = set()
        argument_ids: set[str] = set()
        return_ids: set[str] = set()
        width_ids: set[str] = set()
        ghost_ids: set[str] = set()

        for ordinal, raw_item in enumerate(
            list(report.get("unresolved_internal_calls") or [])
        ):
            if not isinstance(raw_item, Mapping):
                continue
            item = dict(raw_item)
            target = dict(item.get("target") or {})
            compatibility = dict(
                item.get("target_compatibility") or {}
            )
            target.setdefault(
                "entry_plan_id",
                target.get("entry_plan_lookup_key")
                or compatibility.get("entry_plan_lookup_key"),
            )
            match = _match_trunk_identity(target, trunks)
            plan_id = str(item.get("plan_id") or "")
            if match is None and plan_id in overlay_plan_ids:
                match = {
                    "trunk_identity": None,
                    "match_kind": "runtime_overlay_plan_id",
                    "match_value": plan_id,
                }
            if match is None:
                continue
            key = plan_id or "unresolved:%d" % ordinal
            unresolved_ids.add(key)
            waivers["records"].append({
                "kind": "unresolved_target_plan",
                "plan_id": plan_id or None,
                "target": target,
                "attribution": match,
            })

        for ordinal, raw_contract in enumerate(
            list(report.get("contracts") or [])
        ):
            if not isinstance(raw_contract, Mapping):
                continue
            contract = dict(raw_contract)
            contract_id = str(
                contract.get("contract_id")
                or "contract:%d" % ordinal
            )
            call = dict(contract.get("call") or {})
            plan_id = str(call.get("plan_id") or "")
            match = _contract_trunk_match(
                contract,
                trunks,
                sorted(overlay_plan_ids),
            )
            argument_chain = dict(
                contract.get("argument_chain") or {}
            )
            incompatible = (
                str(argument_chain.get("status") or "").lower()
                == "incompatible"
            )
            if match is None:
                if incompatible:
                    waivers[
                        "unmatched_incompatible_contracts"
                    ].append({
                        "contract_id": contract_id,
                        "plan_id": plan_id or None,
                        "caller": dict(contract.get("caller") or {}),
                        "callee": dict(contract.get("callee") or {}),
                        "target": dict(call.get("target") or {}),
                        "failures": list(argument_chain.get("failures") or []),
                    })
                continue

            waived_kinds = []
            if incompatible:
                argument_ids.add(contract_id)
                waived_kinds.append("argument_chain_incompatible")

            return_chain = dict(contract.get("return_chain") or {})
            physical = dict(return_chain.get("physical_carrier") or {})
            if str(physical.get("status") or "").lower() == "deferred":
                return_ids.add(contract_id)
                waived_kinds.append("return_carrier_deferred")

            candidate = dict(return_chain.get("candidate") or {})
            repair = dict(contract.get("repair") or {})
            candidate_status = str(candidate.get("status") or "").lower()
            if (
                "deferred" in candidate_status
                or (
                    candidate.get("candidate") is True
                    and repair.get("emitter_repair_authorized") is not True
                )
            ):
                ghost_ids.add(contract_id)
                waived_kinds.append("ghost_repair_deferred")

            width_statuses = [
                str(return_chain.get("status") or "").lower(),
                str(candidate.get("width_status") or "").lower(),
                str(candidate.get("result_width_status") or "").lower(),
            ]
            if any("width" in value and "deferred" in value for value in width_statuses):
                width_ids.add(contract_id)
                waived_kinds.append("result_width_deferred")

            waivers["records"].append({
                "kind": "custody_contract",
                "contract_id": contract_id,
                "plan_id": plan_id or None,
                "waived_kinds": waived_kinds,
                "attribution": match,
            })

        waivers.update({
            "unresolved_target_plans": len(unresolved_ids),
            "argument_chains_incompatible": len(argument_ids),
            "return_carriers_deferred": len(return_ids),
            "result_widths_deferred": len(width_ids),
            "ghosts_deferred": len(ghost_ids),
            "waived_contract_ids": sorted(
                argument_ids | return_ids | width_ids | ghost_ids
            ),
            "waived_plan_ids": sorted(
                {
                    str(item.get("plan_id"))
                    for item in waivers["records"]
                    if item.get("plan_id") not in (None, "")
                }
            ),
        })
        return waivers

    def _bridge_candidate(
        self,
        contract: Mapping[str, Any],
    ) -> Dict[str, Any]:
        contract = dict(contract or {})
        call = dict(contract.get("call") or {})
        plan_id = str(call.get("plan_id") or "")
        contract_id = str(
            contract.get("contract_id") or plan_id or "unknown"
        )
        base = {
            "contract_id": contract_id,
            "plan_id": plan_id or None,
            "status": "rejected",
            "reasons": [],
            "actions": [],
        }
        call_plan = self.call_plans.get(plan_id)
        if not isinstance(call_plan, Mapping):
            base["reasons"].append("call_plan_missing")
            return base
        call_plan = copy.deepcopy(dict(call_plan))
        entry_plan_id = _contract_entry_plan_id(
            contract,
            call_plan,
        )
        if not entry_plan_id:
            base["reasons"].append("target_entry_plan_id_missing")
            return base
        entry_plan = self.entry_plans.get(entry_plan_id)
        if not isinstance(entry_plan, Mapping):
            base["reasons"].append("target_entry_plan_missing")
            base["entry_plan_id"] = entry_plan_id
            return base
        entry_plan = copy.deepcopy(dict(entry_plan))

        argument_chain = dict(
            contract.get("argument_chain") or {}
        )
        failures = [
            dict(item)
            for item in list(
                argument_chain.get("failures") or []
            )
            if isinstance(item, Mapping)
        ]
        target_arguments = sorted(
            [
                dict(item)
                for item in list(
                    entry_plan.get("fixed_arguments") or []
                )
                if isinstance(item, Mapping)
            ],
            key=lambda item: (
                item.get("ordinal") is None,
                item.get("ordinal")
                if isinstance(item.get("ordinal"), int)
                else 0,
            ),
        )
        call_arguments = sorted(
            [
                dict(item)
                for item in list(
                    call_plan.get("arguments") or []
                )
                if isinstance(item, Mapping)
            ],
            key=lambda item: (
                item.get("index") is None,
                item.get("index")
                if isinstance(item.get("index"), int)
                else 0,
            ),
        )

        true_carrier_mismatches = []
        for failure in failures:
            agreement = dict(failure.get("agreement") or {})
            if agreement.get("carrier") is not False:
                continue
            caller = dict(failure.get("caller") or {})
            callee = dict(failure.get("callee") or {})
            caller_present = any(
                caller.get(key) not in (None, "")
                for key in (
                    "source_sid",
                    "carrier_kind",
                    "carrier",
                    "source_width_bits",
                )
            )
            callee_present = any(
                callee.get(key) not in (None, "")
                for key in (
                    "source_sid",
                    "ordinal",
                    "carrier_kind",
                    "carrier",
                    "storage_key",
                )
            )
            if caller_present and callee_present:
                true_carrier_mismatches.append(failure)
        if true_carrier_mismatches:
            base["reasons"].append(
                "physical_carrier_mismatch_not_bridge_safe"
            )
            return base

        bridged_entry = copy.deepcopy(entry_plan)
        declared_count = bridged_entry.get(
            "fixed_argument_count"
        )
        materialized_count = len(target_arguments)
        if declared_count != materialized_count:
            bridged_entry["fixed_argument_count"] = (
                materialized_count
            )
            base["actions"].append({
                "kind": "normalize_entry_fixed_argument_count",
                "from": declared_count,
                "to": materialized_count,
            })

        bridged_arguments: List[Dict[str, Any]] = []
        zero_fill_indices: List[int] = []
        for index, target_argument in enumerate(
            target_arguments
        ):
            binding = _entry_argument_binding(
                target_argument
            )
            if binding is None:
                base["reasons"].append(
                    "target_argument_binding_missing:%d" % index
                )
                return base
            carrier_kind = _entry_binding_carrier_kind(
                binding
            )
            if carrier_kind is None:
                base["reasons"].append(
                    "target_argument_carrier_unknown:%d" % index
                )
                return base

            if index < len(call_arguments):
                argument = copy.deepcopy(call_arguments[index])
            else:
                argument = {
                    "source_sid": (
                        "pal_bridge_zero_arg_%d" % index
                    ),
                    "source_name": None,
                }
                zero_fill_indices.append(index)
                base["actions"].append({
                    "kind": "zero_fill_missing_argument",
                    "index": index,
                })

            argument["index"] = index
            argument["parameter_region"] = "fixed"
            argument["carrier_kind"] = carrier_kind
            target_class = str(
                binding.get("carrier_class")
                or argument.get("argument_class")
                or "unknown_scalar"
            )
            if (
                str(argument.get("argument_class") or "")
                != target_class
            ):
                base["actions"].append({
                    "kind": "normalize_argument_class",
                    "index": index,
                    "from": argument.get("argument_class"),
                    "to": target_class,
                })
            argument["argument_class"] = target_class

            target_width = _storage_width_bits_from_key(
                binding.get("storage_key")
            )
            source_width = argument.get(
                "source_width_bits"
            )
            if (
                isinstance(target_width, int)
                and (
                    not isinstance(source_width, int)
                    or source_width <= 0
                    or source_width > target_width
                )
            ):
                base["actions"].append({
                    "kind": "clamp_argument_width",
                    "index": index,
                    "from": source_width,
                    "to": target_width,
                })
                argument["source_width_bits"] = target_width
            elif not isinstance(source_width, int):
                argument["source_width_bits"] = (
                    target_width or 64
                )

            if carrier_kind in (
                "gp_register",
                "xmm_register",
            ):
                target_register = binding.get("register")
                if (
                    _canonical_runtime_register(
                        argument.get("carrier")
                    )
                    != _canonical_runtime_register(
                        target_register
                    )
                ):
                    base["actions"].append({
                        "kind": "align_argument_register",
                        "index": index,
                        "from": argument.get("carrier"),
                        "to": target_register,
                    })
                argument["carrier"] = (
                    _canonical_runtime_register(target_register)
                    or target_register
                )
                argument["stack_slot"] = None
            else:
                slot = binding.get("stack_slot")
                if not isinstance(slot, int):
                    storage = str(
                        binding.get("storage_key") or ""
                    )
                    match = re.match(
                        r"stack:(\d+):",
                        storage,
                    )
                    slot = (
                        int(match.group(1))
                        if match is not None
                        else index
                    )
                argument["carrier"] = (
                    "stack+%d" % (slot * 8)
                )
                argument["stack_slot"] = slot
            bridged_arguments.append(argument)

        # Extra caller arguments are retained. PALABI materializes only the
        # target's fixed arguments, while from_call_plan still receives one
        # plan record per supplied runtime value.
        for index in range(
            len(target_arguments),
            len(call_arguments),
        ):
            argument = copy.deepcopy(
                call_arguments[index]
            )
            argument["index"] = index
            bridged_arguments.append(argument)
            base["actions"].append({
                "kind": "retain_ignored_extra_argument",
                "index": index,
            })

        bridged_call = copy.deepcopy(call_plan)
        bridged_call["arguments"] = bridged_arguments
        target = dict(bridged_call.get("target") or {})
        target["entry_plan_lookup_key"] = entry_plan_id
        target["fixed_parameter_count"] = (
            materialized_count
        )
        bridged_call["target"] = target
        compatibility = dict(
            bridged_call.get("target_compatibility") or {}
        )
        compatibility["entry_plan_lookup_key"] = (
            entry_plan_id
        )
        bridged_call["target_compatibility"] = compatibility

        source_call_identity = canonicalize_plan(
            call_plan
        )
        source_entry_identity = canonicalize_plan(
            entry_plan
        )
        bridge_record = {
            "active": True,
            "policy": "explicit_operator_guarded_bridge_safe",
            "contract_ids": [contract_id],
            "entry_plan_id": entry_plan_id,
            "source_call_plan_core_sha256": (
                source_call_identity["plan_core_sha256"]
            ),
            "source_entry_plan_core_sha256": (
                source_entry_identity["plan_core_sha256"]
            ),
            "zero_fill_indices": zero_fill_indices,
            "actions": list(base["actions"]),
        }
        bridged_call.pop("abi_plan_identity", None)
        bridged_entry.pop("abi_plan_identity", None)
        bridged_call["partial_argument_bridge"] = (
            bridge_record
        )
        bridged_entry["partial_argument_bridge"] = {
            "active": True,
            "policy": bridge_record["policy"],
            "contract_ids": [contract_id],
            "actions": [
                item
                for item in base["actions"]
                if item.get("kind")
                == "normalize_entry_fixed_argument_count"
            ],
        }
        bridged_call = stamp_plan(bridged_call)
        bridged_entry = stamp_plan(bridged_entry)

        carrier_failure = any(
            dict(item.get("agreement") or {}).get(
                "carrier"
            )
            is False
            for item in failures
        )
        base.update({
            "status": "bridgeable",
            "entry_plan_id": entry_plan_id,
            "source_call_plan_core_sha256": (
                source_call_identity["plan_core_sha256"]
            ),
            "runtime_call_plan_core_sha256": (
                canonicalize_plan(bridged_call)[
                    "plan_core_sha256"
                ]
            ),
            "source_entry_plan_core_sha256": (
                source_entry_identity["plan_core_sha256"]
            ),
            "runtime_entry_plan_core_sha256": (
                canonicalize_plan(bridged_entry)[
                    "plan_core_sha256"
                ]
            ),
            "zero_fill_indices": zero_fill_indices,
            "bridged_call_plan": bridged_call,
            "bridged_entry_plan": bridged_entry,
            "carrier_disagreement_bridged": (
                1 if carrier_failure else 0
            ),
            "argument_chain_bridged": 1,
        })
        return base

    def _exact_constant_subregister_bridge_v1t(
        self,
        candidate: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Admit only exact zero-fitting constant width contractions.

        This compatibility lane is intentionally narrower than the existing
        explicit partial-publication bridge. It is used for complete projects
        whose frozen custody report calls a same-register-family constant
        transport incompatible only because the caller records the literal at
        a wider width than the callee's physical subregister binding.

        No variable value, signed contraction, carrier mismatch, argument
        reorder, arity repair, or inferred constant is admitted.
        """
        result = copy.deepcopy(dict(candidate or {}))
        result.setdefault("reasons", [])
        result["complete_project_exact_constant_bridge_v1t"] = False
        if result.get("status") != "bridgeable":
            result["reasons"].append(
                "base_argument_bridge_candidate_not_bridgeable"
            )
            return result

        contract = result.get("contract_snapshot")
        if not isinstance(contract, Mapping):
            result["status"] = "rejected"
            result["reasons"].append("contract_snapshot_missing")
            return result
        contract = dict(contract)
        argument_chain = dict(contract.get("argument_chain") or {})
        failures = [
            dict(item)
            for item in list(argument_chain.get("failures") or [])
            if isinstance(item, Mapping)
        ]
        if (
            argument_chain.get("arity_compatible") is not True
            or not failures
        ):
            result["status"] = "rejected"
            result["reasons"].append(
                "exact_constant_bridge_requires_compatible_arity_"
                "and_explicit_failures"
            )
            return result

        plan_id = str(result.get("plan_id") or "")
        call_plan = self.call_plans.get(plan_id)
        if not isinstance(call_plan, Mapping):
            result["status"] = "rejected"
            result["reasons"].append("call_plan_missing_for_exact_bridge")
            return result
        arguments_by_index = {
            int(item.get("index")): dict(item)
            for item in list(call_plan.get("arguments") or [])
            if (
                isinstance(item, Mapping)
                and isinstance(item.get("index"), int)
            )
        }

        proofs: List[Dict[str, Any]] = []
        for failure in failures:
            index = failure.get("index")
            caller = dict(failure.get("caller") or {})
            callee = dict(failure.get("callee") or {})
            agreement = dict(failure.get("agreement") or {})
            argument = (
                arguments_by_index.get(index)
                if isinstance(index, int)
                else None
            )
            source_width = caller.get("source_width_bits")
            target_width = callee.get("carrier_width_bits")
            constant_value = (
                argument.get("constant_value")
                if isinstance(argument, Mapping) else None
            )
            caller_family = _canonical_runtime_register(
                caller.get("carrier")
            )
            callee_family = _canonical_runtime_register(
                callee.get("carrier")
            )
            argument_family = _canonical_runtime_register(
                argument.get("carrier")
                if isinstance(argument, Mapping) else None
            )
            max_value = (
                (1 << target_width) - 1
                if isinstance(target_width, int)
                and 0 < target_width <= 128
                else None
            )
            gates = {
                "failure_status_incompatible": (
                    str(failure.get("status") or "").lower()
                    == "incompatible"
                ),
                "only_width_disagrees": bool(
                    agreement.get("carrier") is True
                    and agreement.get("class") is True
                    and agreement.get("order") is True
                    and agreement.get("width") is False
                ),
                "argument_index_exact": isinstance(index, int),
                "call_argument_present": isinstance(argument, Mapping),
                "gp_register_transport": bool(
                    caller.get("carrier_kind") == "gp_register"
                    and callee.get("carrier_kind") == "gp_register"
                    and isinstance(argument, Mapping)
                    and argument.get("carrier_kind") == "gp_register"
                ),
                "same_physical_register_family": bool(
                    caller_family
                    and caller_family == callee_family
                    and caller_family == argument_family
                ),
                "source_width_exact": bool(
                    isinstance(argument, Mapping)
                    and argument.get("source_width_bits") == source_width
                ),
                "strict_width_contraction": bool(
                    isinstance(source_width, int)
                    and isinstance(target_width, int)
                    and source_width > target_width > 0
                ),
                "literal_authority_exact": bool(
                    isinstance(argument, Mapping)
                    and argument.get("constant") is True
                    and isinstance(constant_value, int)
                    and not isinstance(constant_value, bool)
                ),
                "constant_zero_fits_target_width": bool(
                    isinstance(constant_value, int)
                    and not isinstance(constant_value, bool)
                    and isinstance(max_value, int)
                    and 0 <= constant_value <= max_value
                ),
                "source_sid_exact": bool(
                    isinstance(argument, Mapping)
                    and str(argument.get("source_sid"))
                    == str(caller.get("source_sid"))
                ),
            }
            failed = [
                name for name, passed in gates.items() if not passed
            ]
            proof = {
                "kind": (
                    "pal_exec_exact_constant_subregister_"
                    "compatibility_v1t"
                ),
                "index": index,
                "source_sid": caller.get("source_sid"),
                "constant_value": constant_value,
                "source_width_bits": source_width,
                "target_width_bits": target_width,
                "physical_register_family": caller_family,
                "caller_register": caller.get("carrier"),
                "callee_register": callee.get("carrier"),
                "gates": gates,
                "failed_gates": failed,
                "runtime_projection": (
                    "mask_literal_to_exact_callee_subregister_width"
                ),
                "upstream_authority_mutated": False,
            }
            proofs.append(proof)
            if failed:
                result["status"] = "rejected"
                result["reasons"].append(
                    "not_exact_zero_fit_constant_subregister_bridge:"
                    + ",".join(failed)
                )

        result[
            "exact_constant_subregister_proofs_v1t"
        ] = proofs
        if result.get("status") == "rejected":
            return result
        result[
            "complete_project_exact_constant_bridge_v1t"
        ] = True
        result["bridge_profile"] = (
            "exact_zero_fit_constant_subregister_v1t"
        )
        return result


    def _exact_integral_subregister_bridge_v1u(
        self,
        candidate: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Admit exact same-family integral subregister projections.

        PALABI v1d materializes an integral call value by masking it to the
        call-plan ``source_width_bits`` and reconstructs the callee argument
        from that same physical register family.  A wider caller view and a
        narrower callee subregister view are therefore compatible when the
        low-order bit projection is explicit, edge-local to one argument, and
        width is the only custody disagreement.

        This lane performs no value inference.  It is valid for constants and
        runtime variables alike because the runtime operation is the x86-64
        subregister projection ``value mod 2**target_width``.  Carrier, class,
        order, arity, target binding, and source identity must all be proven.
        """
        result = copy.deepcopy(dict(candidate or {}))
        result.setdefault("reasons", [])
        result[
            "complete_project_exact_integral_subregister_bridge_v1u"
        ] = False

        if result.get("status") != "bridgeable":
            result["reasons"].append(
                "base_argument_bridge_candidate_not_bridgeable"
            )
            return result

        contract = result.get("contract_snapshot")
        if not isinstance(contract, Mapping):
            result["status"] = "rejected"
            result["reasons"].append("contract_snapshot_missing")
            return result
        contract = dict(contract)
        argument_chain = dict(contract.get("argument_chain") or {})
        failures = [
            dict(item)
            for item in list(argument_chain.get("failures") or [])
            if isinstance(item, Mapping)
        ]
        chain_arguments = {
            int(item.get("index")): dict(item)
            for item in list(argument_chain.get("arguments") or [])
            if (
                isinstance(item, Mapping)
                and isinstance(item.get("index"), int)
            )
        }
        if (
            argument_chain.get("arity_compatible") is not True
            or not failures
        ):
            result["status"] = "rejected"
            result["reasons"].append(
                "integral_subregister_projection_requires_"
                "compatible_arity_and_explicit_failures"
            )
            return result

        plan_id = str(result.get("plan_id") or "")
        entry_plan_id = str(result.get("entry_plan_id") or "")
        call_plan = self.call_plans.get(plan_id)
        entry_plan = self.entry_plans.get(entry_plan_id)
        if not isinstance(call_plan, Mapping):
            result["status"] = "rejected"
            result["reasons"].append(
                "call_plan_missing_for_integral_subregister_projection"
            )
            return result
        if not isinstance(entry_plan, Mapping):
            result["status"] = "rejected"
            result["reasons"].append(
                "entry_plan_missing_for_integral_subregister_projection"
            )
            return result
        call_plan = copy.deepcopy(dict(call_plan))
        entry_plan = copy.deepcopy(dict(entry_plan))

        call_arguments = {
            int(item.get("index")): dict(item)
            for item in list(call_plan.get("arguments") or [])
            if (
                isinstance(item, Mapping)
                and isinstance(item.get("index"), int)
            )
        }
        target_arguments = {
            int(item.get("ordinal")): dict(item)
            for item in list(entry_plan.get("fixed_arguments") or [])
            if (
                isinstance(item, Mapping)
                and isinstance(item.get("ordinal"), int)
            )
        }
        fixed_count = entry_plan.get("fixed_argument_count")
        caller_count = argument_chain.get("caller_argument_count")
        callee_count = argument_chain.get(
            "callee_materialized_argument_count"
        )
        cardinality_gates = {
            "entry_fixed_count_exact": bool(
                isinstance(fixed_count, int)
                and fixed_count == len(target_arguments)
            ),
            "custody_callee_count_exact": bool(
                isinstance(callee_count, int)
                and callee_count == len(target_arguments)
            ),
            "custody_caller_count_exact": bool(
                isinstance(caller_count, int)
                and caller_count == len(call_arguments)
            ),
            "call_and_entry_arity_equal": bool(
                len(call_arguments) == len(target_arguments)
            ),
            "no_zero_fill": not list(
                result.get("zero_fill_indices") or []
            ),
            "no_carrier_disagreement_bridge": int(
                result.get("carrier_disagreement_bridged") or 0
            ) == 0,
            "entry_plan_identity_exact": bool(
                _contract_entry_plan_id(contract, call_plan)
                == entry_plan_id
            ),
        }
        failed_cardinality = [
            name
            for name, passed in cardinality_gates.items()
            if not passed
        ]
        if failed_cardinality:
            result["status"] = "rejected"
            result["reasons"].append(
                "integral_subregister_cardinality_or_identity_failure:"
                + ",".join(failed_cardinality)
            )

        proofs: List[Dict[str, Any]] = []
        failure_indices: set[int] = set()
        failure_widths: Dict[int, Tuple[int, int]] = {}
        for failure in failures:
            index = failure.get("index")
            caller = dict(failure.get("caller") or {})
            callee = dict(failure.get("callee") or {})
            agreement = dict(failure.get("agreement") or {})
            argument = (
                call_arguments.get(index)
                if isinstance(index, int)
                else None
            )
            target_argument = (
                target_arguments.get(index)
                if isinstance(index, int)
                else None
            )
            binding = (
                _entry_argument_binding(target_argument)
                if isinstance(target_argument, Mapping)
                else None
            )
            chain_argument = (
                chain_arguments.get(index)
                if isinstance(index, int)
                else None
            )

            source_width = caller.get("source_width_bits")
            target_width = callee.get("carrier_width_bits")
            binding_width = (
                _storage_width_bits_from_key(
                    binding.get("storage_key")
                )
                if isinstance(binding, Mapping)
                else None
            )
            caller_family = _canonical_runtime_register(
                caller.get("carrier")
            )
            callee_family = _canonical_runtime_register(
                callee.get("carrier")
            )
            argument_family = _canonical_runtime_register(
                argument.get("carrier")
                if isinstance(argument, Mapping)
                else None
            )
            binding_family = _canonical_runtime_register(
                binding.get("register")
                if isinstance(binding, Mapping)
                else None
            )
            argument_class = str(
                argument.get("argument_class")
                if isinstance(argument, Mapping)
                else ""
            ).lower()
            caller_class = str(
                caller.get("argument_class") or ""
            ).lower()
            callee_class = str(
                callee.get("carrier_class") or ""
            ).lower()
            binding_class = str(
                binding.get("carrier_class")
                if isinstance(binding, Mapping)
                else ""
            ).lower()
            target_sid = (
                target_argument.get("source_sid")
                if isinstance(target_argument, Mapping)
                else None
            )
            binding_sid = (
                binding.get("sid")
                if isinstance(binding, Mapping)
                else None
            )

            gates = {
                "failure_status_incompatible": (
                    str(failure.get("status") or "").lower()
                    == "incompatible"
                ),
                "only_width_disagrees": bool(
                    agreement.get("carrier") is True
                    and agreement.get("class") is True
                    and agreement.get("order") is True
                    and agreement.get("width") is False
                ),
                "argument_index_exact": isinstance(index, int),
                "call_argument_present": isinstance(argument, Mapping),
                "target_argument_present": isinstance(
                    target_argument, Mapping
                ),
                "custody_argument_present": isinstance(
                    chain_argument, Mapping
                ),
                "target_binding_present": isinstance(binding, Mapping),
                "target_ordinal_exact": bool(
                    isinstance(target_argument, Mapping)
                    and target_argument.get("ordinal") == index
                ),
                "gp_register_transport": bool(
                    caller.get("carrier_kind") == "gp_register"
                    and callee.get("carrier_kind") == "gp_register"
                    and isinstance(argument, Mapping)
                    and argument.get("carrier_kind") == "gp_register"
                    and isinstance(binding, Mapping)
                    and _entry_binding_carrier_kind(binding)
                    == "gp_register"
                ),
                "integral_scalar_class": bool(
                    argument_class in {"integer", "unknown_scalar"}
                    and caller_class in {"integer", "unknown_scalar"}
                    and callee_class == "integer"
                    and binding_class == "integer"
                ),
                "same_physical_register_family": bool(
                    caller_family
                    and caller_family == callee_family
                    and caller_family == argument_family
                    and caller_family == binding_family
                ),
                "source_width_exact": bool(
                    isinstance(argument, Mapping)
                    and argument.get("source_width_bits")
                    == source_width
                ),
                "target_width_exact": bool(
                    binding_width == target_width
                ),
                "byte_aligned_integral_widths": bool(
                    isinstance(source_width, int)
                    and isinstance(target_width, int)
                    and source_width % 8 == 0
                    and target_width % 8 == 0
                ),
                "strict_supported_width_contraction": bool(
                    isinstance(source_width, int)
                    and isinstance(target_width, int)
                    and 64 >= source_width > target_width > 0
                ),
                "source_sid_exact": bool(
                    isinstance(argument, Mapping)
                    and str(argument.get("source_sid"))
                    == str(caller.get("source_sid"))
                ),
                "target_sid_exact": bool(
                    str(target_sid) == str(callee.get("source_sid"))
                    and str(binding_sid) == str(callee.get("source_sid"))
                ),
                "custody_argument_continuity": bool(
                    isinstance(chain_argument, Mapping)
                    and dict(
                        chain_argument.get("agreement") or {}
                    ) == agreement
                    and str(
                        dict(
                            chain_argument.get("caller") or {}
                        ).get("source_sid")
                    ) == str(caller.get("source_sid"))
                    and str(
                        dict(
                            chain_argument.get("callee") or {}
                        ).get("source_sid")
                    ) == str(callee.get("source_sid"))
                ),
            }
            failed = [
                name for name, passed in gates.items() if not passed
            ]
            proof = {
                "kind": (
                    "pal_exec_exact_integral_subregister_"
                    "compatibility_v1u"
                ),
                "index": index,
                "source_sid": caller.get("source_sid"),
                "target_sid": callee.get("source_sid"),
                "source_width_bits": source_width,
                "target_width_bits": target_width,
                "physical_register_family": caller_family,
                "caller_register": caller.get("carrier"),
                "callee_register": callee.get("carrier"),
                "target_binding_register": (
                    binding.get("register")
                    if isinstance(binding, Mapping)
                    else None
                ),
                "source_is_constant": bool(
                    isinstance(argument, Mapping)
                    and argument.get("constant") is True
                ),
                "constant_value": (
                    argument.get("constant_value")
                    if isinstance(argument, Mapping)
                    else None
                ),
                "gates": gates,
                "failed_gates": failed,
                "runtime_projection": (
                    "mask_integral_value_to_exact_callee_"
                    "subregister_width_modulo_2_pow_n"
                ),
                "value_inference_used": False,
                "upstream_authority_mutated": False,
            }
            proofs.append(proof)
            if isinstance(index, int):
                failure_indices.add(index)
            if (
                isinstance(index, int)
                and isinstance(source_width, int)
                and isinstance(target_width, int)
            ):
                failure_widths[index] = (
                    source_width,
                    target_width,
                )
            if failed:
                result["status"] = "rejected"
                result["reasons"].append(
                    "not_exact_integral_subregister_projection:"
                    + ",".join(failed)
                )

        action_proofs: List[Dict[str, Any]] = []
        for raw_action in list(result.get("actions") or []):
            action = dict(raw_action or {})
            kind = str(action.get("kind") or "")
            index = action.get("index")
            allowed = False
            reason = None

            if kind == "clamp_argument_width":
                expected = (
                    failure_widths.get(index)
                    if isinstance(index, int)
                    else None
                )
                allowed = bool(
                    expected is not None
                    and action.get("from") == expected[0]
                    and action.get("to") == expected[1]
                )
                reason = (
                    "exact_failed_argument_width_projection"
                    if allowed
                    else "width_action_not_bound_to_exact_failure"
                )
            elif kind == "normalize_argument_class":
                chain_argument = (
                    chain_arguments.get(index)
                    if isinstance(index, int)
                    else None
                )
                class_agreement = dict(
                    chain_argument.get("agreement") or {}
                ) if isinstance(chain_argument, Mapping) else {}
                allowed = bool(
                    action.get("from") == "unknown_scalar"
                    and action.get("to") == "integer"
                    and class_agreement.get("class") is True
                )
                reason = (
                    "custody_proven_integral_class_alias"
                    if allowed
                    else "class_action_not_proven_by_custody"
                )
            elif kind == "align_argument_register":
                allowed = bool(
                    _canonical_runtime_register(action.get("from"))
                    == _canonical_runtime_register(action.get("to"))
                    and _canonical_runtime_register(action.get("from"))
                    not in {"", None}
                )
                reason = (
                    "same_physical_register_family_spelling"
                    if allowed
                    else "register_action_changes_physical_family"
                )
            else:
                reason = "action_kind_not_allowed_for_automatic_projection"

            action_proofs.append({
                "action": action,
                "allowed": allowed,
                "reason": reason,
            })
            if not allowed:
                result["status"] = "rejected"
                result["reasons"].append(
                    "automatic_integral_subregister_action_rejected:"
                    + kind
                )

        result[
            "exact_integral_subregister_proofs_v1u"
        ] = proofs
        result[
            "exact_integral_subregister_action_proofs_v1u"
        ] = action_proofs
        result[
            "exact_integral_subregister_cardinality_gates_v1u"
        ] = cardinality_gates

        if result.get("status") == "rejected":
            return result

        policy = (
            "exact_same_family_integral_subregister_auto_v1u"
        )
        bridged_call = copy.deepcopy(
            dict(result.get("bridged_call_plan") or {})
        )
        bridged_entry = copy.deepcopy(
            dict(result.get("bridged_entry_plan") or {})
        )
        if not bridged_call or not bridged_entry:
            result["status"] = "rejected"
            result["reasons"].append(
                "bridged_runtime_plan_missing_after_exact_proof"
            )
            return result

        call_bridge = dict(
            bridged_call.get("partial_argument_bridge") or {}
        )
        call_bridge.update({
            "active": True,
            "policy": policy,
            "profile": (
                "exact_same_family_integral_subregister_v1u"
            ),
            "contract_ids": [
                str(result.get("contract_id") or "")
            ],
            "failure_indices": sorted(failure_indices),
            "proofs": copy.deepcopy(proofs),
            "value_inference_used": False,
            "upstream_authority_mutated": False,
        })
        bridged_call["partial_argument_bridge"] = call_bridge
        bridged_call.pop("abi_plan_identity", None)
        bridged_call = stamp_plan(bridged_call)

        entry_bridge = dict(
            bridged_entry.get("partial_argument_bridge") or {}
        )
        entry_bridge.update({
            "active": True,
            "policy": policy,
            "profile": (
                "exact_same_family_integral_subregister_v1u"
            ),
            "contract_ids": [
                str(result.get("contract_id") or "")
            ],
            "failure_indices": sorted(failure_indices),
            "upstream_authority_mutated": False,
        })
        bridged_entry["partial_argument_bridge"] = entry_bridge
        bridged_entry.pop("abi_plan_identity", None)
        bridged_entry = stamp_plan(bridged_entry)

        result["bridged_call_plan"] = bridged_call
        result["bridged_entry_plan"] = bridged_entry
        result[
            "complete_project_exact_integral_subregister_bridge_v1u"
        ] = True
        result["bridge_profile"] = (
            "exact_same_family_integral_subregister_v1u"
        )
        return result


    def _argument_bridge_candidates(
        self,
        report: Mapping[str, Any],
        waivers: Mapping[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        waived_ids = {
            str(value)
            for value in list(
                waivers.get("waived_contract_ids") or []
            )
        }
        candidates: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        for raw_contract in list(
            report.get("contracts") or []
        ):
            if not isinstance(raw_contract, Mapping):
                continue
            contract = dict(raw_contract)
            contract_id = str(
                contract.get("contract_id") or ""
            )
            if contract_id in waived_ids:
                continue
            argument_chain = dict(
                contract.get("argument_chain") or {}
            )
            if (
                str(
                    argument_chain.get("status") or ""
                ).lower()
                != "incompatible"
            ):
                continue
            result = self._bridge_candidate(
                contract
            )
            result["contract_snapshot"] = contract
            if result.get("status") == "bridgeable":
                candidates.append(result)
            else:
                rejected.append(result)
        return candidates, rejected

    def _resolve_argument_policy(
        self,
        *,
        remaining: int,
        candidates: Sequence[Mapping[str, Any]],
        rejected: Sequence[Mapping[str, Any]],
    ) -> str:
        if remaining <= 0:
            return "not_required"
        policy = self.argument_policy
        if policy == "prompt":
            if not sys.stdin.isatty():
                raise PALExecInterfaceError(
                    "remaining ABI argument incompatibilities require an "
                    "interactive decision or "
                    "--argument-policy bridge-safe"
                )
            while True:
                choice = input(
                    "\nPAL detected %d ABI argument contract(s) outside "
                    "the init trunk waiver.\n"
                    "Bridgeable=%d  not-bridgeable=%d\n"
                    "[A] abort publication\n"
                    "[G] publish with guarded runtime ABI argument bridges\n"
                    "[D] publish diagnostic workspace and keep run blocked\n"
                    "Choice [A/G/D]: "
                    % (
                        remaining,
                        len(candidates),
                        len(rejected),
                    )
                ).strip().lower()
                if choice in {"a", "abort", ""}:
                    raise PALExecInterfaceError(
                        "publication aborted by operator after ABI "
                        "argument incompatibility detection"
                    )
                if choice in {"g", "guard", "bridge"}:
                    return "bridge-safe"
                if choice in {"d", "diagnostic", "blocked"}:
                    return "diagnostic"
                print("Enter A, G, or D.")
        if policy == "abort":
            raise PALExecInterfaceError(
                "project contains %d remaining ABI argument "
                "incompatibility contract(s); use "
                "--argument-policy bridge-safe for guarded runtime "
                "normalization or diagnostic to publish blocked"
                % remaining
            )
        return policy

    def _normalize_runtime_register_families(
        self,
    ) -> Dict[str, Any]:
        """Normalize safe x86-64 subregister aliases across all runtime plans.

        This is a runtime-projection pass.  It does not rewrite project-level
        canonical authority.  Width remains in source_width_bits/storage_key.
        """
        records: List[Dict[str, Any]] = []
        conflicts: List[Dict[str, Any]] = []

        for plan_id, raw_call in list(self.call_plans.items()):
            if not isinstance(raw_call, Mapping):
                continue
            call_plan = copy.deepcopy(dict(raw_call))
            target = dict(call_plan.get("target") or {})
            compatibility = dict(
                call_plan.get("target_compatibility") or {}
            )
            entry_plan_id = str(
                target.get("entry_plan_lookup_key")
                or compatibility.get("entry_plan_lookup_key")
                or ""
            )
            if not entry_plan_id:
                continue
            raw_entry = self.entry_plans.get(entry_plan_id)
            if not isinstance(raw_entry, Mapping):
                continue
            entry_plan = copy.deepcopy(dict(raw_entry))

            call_arguments = sorted(
                [
                    dict(item)
                    for item in list(
                        call_plan.get("arguments") or []
                    )
                    if isinstance(item, Mapping)
                ],
                key=lambda item: (
                    item.get("index") is None,
                    item.get("index")
                    if isinstance(item.get("index"), int)
                    else 0,
                ),
            )
            target_arguments = sorted(
                [
                    dict(item)
                    for item in list(
                        entry_plan.get("fixed_arguments") or []
                    )
                    if isinstance(item, Mapping)
                ],
                key=lambda item: (
                    item.get("ordinal") is None,
                    item.get("ordinal")
                    if isinstance(item.get("ordinal"), int)
                    else 0,
                ),
            )

            call_changed = False
            entry_changed = False
            for index in range(
                min(len(call_arguments), len(target_arguments))
            ):
                call_argument = call_arguments[index]
                target_argument = target_arguments[index]
                binding = _entry_argument_binding(
                    target_argument
                )
                if binding is None:
                    continue
                target_register = binding.get("register")
                call_register = call_argument.get("carrier")
                if not target_register or not call_register:
                    continue

                call_family = _canonical_runtime_register(
                    call_register
                )
                target_family = _canonical_runtime_register(
                    target_register
                )
                if call_family != target_family:
                    conflicts.append({
                        "plan_id": str(plan_id),
                        "entry_plan_id": entry_plan_id,
                        "index": index,
                        "call_register": call_register,
                        "call_family": call_family,
                        "entry_register": target_register,
                        "entry_family": target_family,
                        "kind": (
                            "physical_register_family_conflict"
                        ),
                    })
                    continue

                if str(call_register).upper() != call_family:
                    call_argument["carrier"] = call_family
                    call_changed = True
                if str(target_register).upper() != target_family:
                    bindings = [
                        dict(item)
                        for item in list(
                            target_argument.get(
                                "physical_carrier_bindings"
                            )
                            or []
                        )
                        if isinstance(item, Mapping)
                    ]
                    for binding_record in bindings:
                        if (
                            binding_record.get("register")
                            == target_register
                        ):
                            binding_record["register"] = (
                                target_family
                            )
                    target_argument[
                        "physical_carrier_bindings"
                    ] = bindings
                    entry_changed = True

                if (
                    str(call_register).upper() != call_family
                    or str(target_register).upper()
                    != target_family
                ):
                    records.append({
                        "plan_id": str(plan_id),
                        "entry_plan_id": entry_plan_id,
                        "index": index,
                        "call_register": call_register,
                        "entry_register": target_register,
                        "physical_family": call_family,
                        "width_authority": (
                            "source_width_bits_and_storage_key"
                        ),
                    })

            if call_changed:
                call_plan["arguments"] = call_arguments
                call_plan.pop("abi_plan_identity", None)
                call_plan[
                    "runtime_register_family_normalization"
                ] = {
                    "active": True,
                    "policy": (
                        "x86_64_physical_register_family_truth"
                    ),
                }
                self.call_plans[str(plan_id)] = stamp_plan(
                    call_plan
                )

            if entry_changed:
                entry_plan["fixed_arguments"] = (
                    target_arguments
                )
                entry_plan.pop("abi_plan_identity", None)
                entry_plan[
                    "runtime_register_family_normalization"
                ] = {
                    "active": True,
                    "policy": (
                        "x86_64_physical_register_family_truth"
                    ),
                }
                self.entry_plans[entry_plan_id] = stamp_plan(
                    entry_plan
                )

        report = {
            "format": (
                "pal_runtime_register_family_normalization"
            ),
            "schema_version": 1,
            "build": PAL_EXEC_INTERFACE_BUILD,
            "palabi_required_version": (
                PAL_ABI_RUNTIME_REQUIRED_VERSION
            ),
            "normalized_pairs": len(records),
            "conflicts": conflicts,
            "records": records,
            "rule": (
                "RDI/EDI and equivalent x86_64 subregister "
                "spellings share one physical carrier; width "
                "remains independently governed"
            ),
        }
        self.partial_publication_report[
            "runtime_register_family_normalization"
        ] = report
        return report

    def _install_argument_bridges(
        self,
        candidates: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        bridged_contracts = 0
        bridged_carrier_disagreements = 0
        for raw in candidates:
            item = dict(raw)
            plan_id = str(item.get("plan_id") or "")
            entry_plan_id = str(
                item.get("entry_plan_id") or ""
            )
            if not plan_id or not entry_plan_id:
                continue
            self.call_plans[plan_id] = copy.deepcopy(
                item["bridged_call_plan"]
            )
            self.entry_plans[entry_plan_id] = copy.deepcopy(
                item["bridged_entry_plan"]
            )
            bridged_contracts += int(
                item.get("argument_chain_bridged") or 0
            )
            bridged_carrier_disagreements += int(
                item.get(
                    "carrier_disagreement_bridged"
                )
                or 0
            )
            records.append({
                key: value
                for key, value in item.items()
                if key not in {
                    "bridged_call_plan",
                    "bridged_entry_plan",
                    "contract_snapshot",
                }
            })
        report = {
            "format": "pal_guarded_abi_argument_bridge",
            "schema_version": 1,
            "build": PAL_EXEC_INTERFACE_BUILD,
            "active": bool(records),
            "policy": "bridge-safe",
            "bridged_contracts": bridged_contracts,
            "bridged_carrier_disagreements": (
                bridged_carrier_disagreements
            ),
            "records": records,
            "rule": (
                "runtime-only call and entry projections normalize "
                "declared fixed counts, argument class/order/width, "
                "and zero-fill missing fixed arguments; true physical "
                "carrier mismatches are never bridge-safe"
            ),
        }
        self.partial_publication_report[
            "runtime_argument_bridges"
        ] = records
        self.partial_publication_report[
            "effective_argument_policy"
        ] = "bridge-safe"
        return report

    def _analyze_abi_custody_report(
        self,
        stage: Path,
    ) -> Dict[str, Any]:
        """Apply trunks and exact runtime argument compatibility independently."""
        publication = super()._analyze_abi_custody_report(
            stage
        )
        partial_active = bool(
            self.partial_publication_report.get("active")
        )
        report = dict(self.abi_custody_report or {})
        counts = dict(publication.get("counts") or {})
        raw_counts = dict(counts)

        if partial_active:
            waivers = self._partial_waivers(report)
        else:
            waivers = {
                "unresolved_target_plans": 0,
                "argument_chains_incompatible": 0,
                "return_carriers_deferred": 0,
                "result_widths_deferred": 0,
                "ghosts_deferred": 0,
                "waived_contract_ids": [],
                "waived_plan_ids": [],
                "records": [],
            }

        for key, waiver_key in (
            ("unresolved_target_plans", "unresolved_target_plans"),
            (
                "argument_chains_incompatible",
                "argument_chains_incompatible",
            ),
            (
                "return_carriers_deferred",
                "return_carriers_deferred",
            ),
            (
                "result_widths_deferred",
                "result_widths_deferred",
            ),
            ("ghosts_deferred", "ghosts_deferred"),
        ):
            counts[key] = max(
                int(counts.get(key) or 0)
                - int(waivers.get(waiver_key) or 0),
                0,
            )

        remaining_arguments = int(
            counts.get("argument_chains_incompatible") or 0
        )
        candidates, rejected = self._argument_bridge_candidates(
            report,
            waivers,
        )
        automatic_exact_bridge = False

        if not partial_active:
            exact_candidates: List[Dict[str, Any]] = []
            complete_rejected: List[Dict[str, Any]] = list(rejected)
            for candidate in candidates:
                checked = self._exact_integral_subregister_bridge_v1u(
                    candidate
                )
                if checked.get(
                    "complete_project_exact_integral_subregister_bridge_v1u"
                ) is True:
                    exact_candidates.append(checked)
                else:
                    complete_rejected.append(checked)
            candidates = exact_candidates
            rejected = complete_rejected
            automatic_exact_bridge = bool(
                self.argument_policy != "diagnostic"
                and remaining_arguments > 0
                and len(candidates) == remaining_arguments
                and not rejected
            )

        if automatic_exact_bridge:
            selected_policy = (
                "exact-integral-subregister-auto-v1u"
            )
        else:
            selected_policy = self._resolve_argument_policy(
                remaining=remaining_arguments,
                candidates=candidates,
                rejected=rejected,
            )

        bridge_report = {
            "format": "pal_guarded_abi_argument_bridge",
            "schema_version": 1,
            "build": PAL_EXEC_INTERFACE_BUILD,
            "active": False,
            "policy": selected_policy,
            "bridged_contracts": 0,
            "bridged_carrier_disagreements": 0,
            "records": [],
            "rejected": [
                {
                    key: value
                    for key, value in dict(item).items()
                    if key not in {
                        "bridged_call_plan",
                        "bridged_entry_plan",
                        "contract_snapshot",
                    }
                }
                for item in rejected
            ],
        }
        if selected_policy in {
            "bridge-safe",
            "exact-integral-subregister-auto-v1u",
        }:
            bridge_report = self._install_argument_bridges(
                candidates
            )
            bridge_report["rejected"] = [
                {
                    key: value
                    for key, value in dict(item).items()
                    if key not in {
                        "bridged_call_plan",
                        "bridged_entry_plan",
                        "contract_snapshot",
                    }
                }
                for item in rejected
            ]
            if automatic_exact_bridge:
                bridge_report.update({
                    "policy": (
                        "exact-integral-subregister-auto-v1u"
                    ),
                    "automatic_exact_subregister_compatibility": True,
                    "complete_project": True,
                    "rule": (
                        "same physical GP-register family plus exact call/entry "
                        "identity and width-only custody permits runtime-only "
                        "low-bit subregister projection for constants or "
                        "variables; no value inference, carrier, order, "
                        "or arity repair"
                    ),
                })
                self.partial_publication_report[
                    "effective_argument_policy"
                ] = bridge_report["policy"]
        else:
            self.partial_publication_report[
                "effective_argument_policy"
            ] = selected_policy
            self.partial_publication_report[
                "argument_bridge_rejections"
            ] = bridge_report["rejected"]

        family_report = self._normalize_runtime_register_families()
        family_conflicts = len(
            list(family_report.get("conflicts") or [])
        )
        counts["runtime_register_family_conflicts"] = (
            family_conflicts
        )

        counts["argument_chains_incompatible"] = max(
            remaining_arguments
            - int(bridge_report.get("bridged_contracts") or 0),
            0,
        )
        counts["carrier_disagreements"] = max(
            int(counts.get("carrier_disagreements") or 0)
            - int(
                bridge_report.get(
                    "bridged_carrier_disagreements"
                )
                or 0
            ),
            0,
        )
        counts.update({
            "argument_chains_incompatible_raw": int(
                raw_counts.get("argument_chains_incompatible") or 0
            ),
            "argument_chains_incompatible_waived": int(
                waivers.get("argument_chains_incompatible") or 0
            ),
            "argument_chains_incompatible_bridged": int(
                bridge_report.get("bridged_contracts") or 0
            ),
            "unresolved_target_plans_raw": int(
                raw_counts.get("unresolved_target_plans") or 0
            ),
            "unresolved_target_plans_waived": int(
                waivers.get("unresolved_target_plans") or 0
            ),
            "return_carriers_deferred_raw": int(
                raw_counts.get("return_carriers_deferred") or 0
            ),
            "return_carriers_deferred_waived": int(
                waivers.get("return_carriers_deferred") or 0
            ),
            "result_widths_deferred_raw": int(
                raw_counts.get("result_widths_deferred") or 0
            ),
            "result_widths_deferred_waived": int(
                waivers.get("result_widths_deferred") or 0
            ),
            "ghosts_deferred_raw": int(
                raw_counts.get("ghosts_deferred") or 0
            ),
            "ghosts_deferred_waived": int(
                waivers.get("ghosts_deferred") or 0
            ),
        })

        hard = {
            "immutable_plan_core_conflict":
                counts.get("plan_core_conflicts", 0),
            "argument_chain_incompatibility":
                counts.get("argument_chains_incompatible", 0),
            "carrier_disagreement":
                counts.get("carrier_disagreements", 0),
            "result_width_conflict":
                counts.get("result_width_conflicts", 0),
            "conflicting_ghost_contract":
                counts.get("ghosts_conflicting", 0),
            "runtime_register_family_conflict":
                counts.get("runtime_register_family_conflicts", 0),
        }
        deferred = {
            "unresolved_target_entry_plans":
                counts.get("unresolved_target_plans", 0),
            "return_carriers_deferred":
                counts.get("return_carriers_deferred", 0),
            "result_widths_deferred":
                counts.get("result_widths_deferred", 0),
            "ghost_repairs_deferred":
                counts.get("ghosts_deferred", 0),
        }
        broken = [
            name for name, value in hard.items() if value
        ]
        index = dict(self.abi_plan_index_report or {})
        receipt = dict(self.abi_final_authority_report or {})
        if index and index.get("phase") != ABI_FINAL_PHASE:
            broken.append("final_plan_index_phase_mismatch")
        if receipt and receipt.get("status") != "complete":
            broken.append("final_authority_receipt_incomplete")

        degraded = [
            name for name, value in deferred.items() if value
        ]
        if partial_active:
            degraded.append(
                "explicit_user_approved_incomplete_function_trunks"
            )
        if bridge_report.get("active"):
            degraded.append(
                "exact_runtime_ABI_integral_subregister_projection"
                if automatic_exact_bridge else
                "explicit_operator_guarded_abi_argument_bridges"
            )
        if self.abi_authority_loading.get("status") != "verified":
            degraded.append(
                "partial_or_unverified_project_abi_authority"
            )

        health = (
            "BROKEN" if broken
            else "DEGRADED" if degraded
            else "READY"
        )
        publication.update({
            "health": health,
            "counts": counts,
            "broken_reasons": sorted(set(broken)),
            "degraded_reasons": sorted(set(degraded)),
            "source_report_status": report.get("status"),
            "partial_publication": {
                "active": partial_active,
                "policy": self.partial_publication_report.get(
                    "effective_policy"
                ),
                "argument_policy": selected_policy,
                "trunked_functions": len(
                    self.partial_publication_report.get(
                        "trunked_functions"
                    )
                    or []
                ),
                "waivers": waivers,
                "argument_bridge": bridge_report,
                "waived_argument_contracts": int(
                    waivers.get("argument_chains_incompatible") or 0
                ),
                "bridged_argument_contracts": int(
                    bridge_report.get("bridged_contracts") or 0
                ),
                "unmatched_argument_contracts": len(
                    bridge_report.get("rejected") or []
                ),
            },
            "argument_bridge": copy.deepcopy(bridge_report),
            "complete_project_exact_integral_subregister_bridge_v1u": bool(
                not partial_active
                and automatic_exact_bridge
                and bridge_report.get("active")
            ),
            "rule": (
                "trunk waivers and runtime argument compatibility are "
                "independent; complete projects may automatically project "
                "only exact same-family integral subregister projections "
                "with width as the sole disagreement; no value inference, "
                "carrier repair, order repair, or arity repair is allowed"
            ),
        })
        self.partial_publication_report["waivers"] = waivers
        self.partial_publication_report[
            "argument_bridge"
        ] = bridge_report
        self.partial_publication_report[
            "argument_bridge_rejections"
        ] = list(bridge_report.get("rejected") or [])
        self.partial_publication_report[
            "effective_abi_health"
        ] = health
        self.abi_argument_bridge_report_v1t = copy.deepcopy(
            bridge_report
        )
        self.abi_chain_publication = publication
        return publication

    def _copy_project_authorities(
        self,
        stage: Path,
    ) -> None:
        super()._copy_project_authorities(stage)
        if self.partial_publication_report.get("active"):
            _write_json(
                stage / ABI_PARTIAL_PUBLICATION,
                self.partial_publication_report,
            )
        bridge = dict(
            self.partial_publication_report.get(
                "argument_bridge"
            )
            or {}
        )
        if bridge.get("active"):
            _write_json(
                stage / ABI_ARGUMENT_BRIDGE,
                bridge,
            )

    def _publish_config(
        self,
        stage: Path,
        runtime_modules: Sequence[str],
    ) -> Dict[str, Any]:
        config = super()._publish_config(
            stage,
            runtime_modules,
        )
        partial = dict(self.partial_publication_report)
        if partial.get("active"):
            partial_path = stage / ABI_PARTIAL_PUBLICATION
            partial["artifact"] = ABI_PARTIAL_PUBLICATION
            partial["sha256"] = _sha256_file(partial_path)
            partial["trunked_function_count"] = len(
                partial.get("trunked_functions") or []
            )
            bridge = dict(
                partial.get("argument_bridge") or {}
            )
            if bridge.get("active"):
                bridge_path = stage / ABI_ARGUMENT_BRIDGE
                partial["argument_bridge_artifact"] = (
                    ABI_ARGUMENT_BRIDGE
                )
                partial["argument_bridge_sha256"] = (
                    _sha256_file(bridge_path)
                )
                partial["argument_bridge_count"] = int(
                    bridge.get("bridged_contracts") or 0
                )
            else:
                partial["argument_bridge_count"] = 0
            config["abi_partial_publication"] = partial
            config["publication_class"] = "TRIAGED"
            config["counts"]["trunked_functions"] = (
                partial["trunked_function_count"]
            )
            config["known_limitations"].append(
                "one or more failed functions are explicit void/zero ABI "
                "trunks; calls are observable in PAL_runtime_trace.jsonl"
            )
            config["known_limitations"].append(
                "triaged preview is semantically trustworthy only along "
                "execution paths that do not depend on a trunked function"
            )
        else:
            config["abi_partial_publication"] = {
                "active": False,
                "publication_class": "complete",
                "effective_policy": "complete_project",
                "trunked_function_count": 0,
            }
            config["publication_class"] = "COMPLETE"
            config["counts"]["trunked_functions"] = 0

        bridge = dict(
            partial.get("argument_bridge")
            or getattr(
                self,
                "abi_argument_bridge_report_v1t",
                {},
            )
            or {}
        )
        runtime_index_path = stage / ABI_PLAN_INDEX
        runtime_index = _read_json(runtime_index_path)
        if bridge.get("active"):
            bridge_path = stage / ABI_ARGUMENT_BRIDGE
            bridge_summary = {
                "active": True,
                "artifact": ABI_ARGUMENT_BRIDGE,
                "sha256": _sha256_file(bridge_path),
                "policy": bridge.get("policy"),
                "bridged_contracts": int(
                    bridge.get("bridged_contracts") or 0
                ),
                "automatic_exact_compatibility": bool(
                    bridge.get("automatic_exact_compatibility")
                ),
                "complete_project": bool(
                    bridge.get("complete_project")
                ),
                "rule": bridge.get("rule"),
            }
            config["abi_argument_bridge"] = bridge_summary
            runtime_index["argument_bridge"] = copy.deepcopy(
                bridge_summary
            )
            limitation = (
                "runtime ABI plan projection narrows only exact "
                "zero-fitting constants to an accepted callee "
                "subregister width"
            )
            if limitation not in config["known_limitations"]:
                config["known_limitations"].append(limitation)
        else:
            config["abi_argument_bridge"] = {
                "active": False,
                "bridged_contracts": 0,
            }

        if partial.get("active"):
            runtime_index["partial_publication"] = {
                "active": True,
                "artifact": ABI_PARTIAL_PUBLICATION,
                "sha256": partial["sha256"],
                "trunked_function_count": (
                    partial["trunked_function_count"]
                ),
                "runtime_plan_overlay_count": len(
                    partial.get("runtime_plan_overlays")
                    or []
                ),
                "argument_bridge_count": int(
                    partial.get("argument_bridge_count")
                    or 0
                ),
                "argument_bridge_artifact": (
                    partial.get("argument_bridge_artifact")
                ),
                "argument_bridge_sha256": (
                    partial.get("argument_bridge_sha256")
                ),
                "result_policy": "void_zero_sentinel",
            }

        _write_json(runtime_index_path, runtime_index)
        _write_json(stage / EXEC_CONFIG, config)
        return config


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

    def _project_stats(
        self,
        project: Path,
    ) -> Dict[str, Any]:
        project = Path(project).resolve()
        manifest_path = project / PROJECT_MANIFEST
        execute = project / EXECUTE_DIRECTORY
        config_path = execute / EXEC_CONFIG
        complete_path = execute / "PUBLISH_COMPLETE"

        stats: Dict[str, Any] = {
            "project": project,
            "project_name": project.name,
            "manifest_functions": 0,
            "decompiled_functions": 0,
            "failed_functions": 0,
            "publish_status": "NONE",
            "workspace_state": "NONE",
            "workspace_present": False,
            "workspace_current": False,
            "run_gate": "NOT_PUBLISHED",
            "run_allowed": False,
            "run_block_reasons": [],
            "publication_class": "-",
            "published_functions": 0,
            "trunked_functions": 0,
            "partial_publication_active": False,
            "partial_publication_policy": "-",
            "entry_plans": 0,
            "call_plans": 0,
            "abi_health": "UNKNOWN",
            "abi_linked": 0,
            "abi_unresolved": 0,
            "abi_argument_incompatible": 0,
            "abi_argument_incompatible_raw": 0,
            "abi_argument_incompatible_waived": 0,
            "abi_argument_incompatible_bridged": 0,
            "abi_core_conflicts": 0,
            "abi_carrier_disagreements": 0,
            "abi_result_width_conflicts": 0,
            "abi_authority_phase": "-",
            "abi_authority_status": "-",
            "abi_ghosts_resolved": 0,
            "abi_ghosts_deferred": 0,
            "abi_ghosts_conflicting": 0,
            "abi_broken_reasons": [],
            "abi_degraded_reasons": [],
            "static_strings_original": 0,
            "static_strings_completed": 0,
            "static_strings_final": 0,
            "static_strings_required": 0,
            "direct_resolved": 0,
            "rebased_resolved": 0,
            "ambiguous_ptrsub": 0,
            "function_ptrsub": 0,
            "code_ptrsub": 0,
            "unresolved_ptrsub": 0,
            "program_image_base": None,
            "elf_link_base": None,
            "load_bias": None,
            "unresolved_ptr_addresses": [],
            "unresolved_shims": 0,
            "warnings": 0,
            "warning_messages": [],
            "execute_bytes": _directory_size(execute),
            "published_at_utc": "-",
            "error": None,
        }

        try:
            manifest = _read_json(manifest_path)
            records = list(manifest.get("functions") or [])
            stats["manifest_functions"] = len(records)
            stats["decompiled_functions"] = sum(
                1
                for record in records
                if record.get("status") == "decompiled"
            )
            stats["failed_functions"] = sum(
                1
                for record in records
                if record.get("status") == "failed"
            )
            manifest_sha = _sha256_file(manifest_path)
        except Exception as exc:
            stats["publish_status"] = "BROKEN"
            stats["workspace_state"] = "BROKEN"
            stats["run_gate"] = "BROKEN_WORKSPACE"
            stats["error"] = (
                "manifest: %s" % exc
            )
            return stats

        config = {}
        if config_path.is_file():
            try:
                config = _read_json(config_path)
            except Exception as exc:
                stats["publish_status"] = "BROKEN"
                stats["workspace_state"] = "BROKEN"
                stats["run_gate"] = "BROKEN_WORKSPACE"
                stats["error"] = (
                    "config: %s" % exc
                )
                return stats

        complete_build = ""
        if complete_path.is_file():
            try:
                lines = complete_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                complete_build = (
                    lines[0].strip()
                    if lines
                    else ""
                )
            except OSError as exc:
                stats["publish_status"] = "BROKEN"
                stats["workspace_state"] = "BROKEN"
                stats["run_gate"] = "BROKEN_WORKSPACE"
                stats["error"] = (
                    "completion marker: %s" % exc
                )
                return stats

        if not config and not complete_path.is_file():
            workspace_state = "NONE"
        elif not config or not complete_path.is_file():
            workspace_state = "INCOMPLETE"
        else:
            current = bool(
                str(config.get("build") or "")
                == PAL_EXEC_INTERFACE_BUILD
                and complete_build
                == PAL_EXEC_INTERFACE_BUILD
                and str(
                    config.get(
                        "source_manifest_sha256"
                    )
                    or ""
                )
                == manifest_sha
            )
            workspace_state = "CURRENT" if current else "STALE"

        stats["workspace_state"] = workspace_state
        stats["publish_status"] = workspace_state
        stats["workspace_present"] = workspace_state in {
            "CURRENT", "STALE", "INCOMPLETE"
        }
        stats["workspace_current"] = workspace_state == "CURRENT"

        counts = dict(config.get("counts") or {})
        stats["published_functions"] = int(
            counts.get("published_functions", 0)
            or 0
        )
        stats["trunked_functions"] = int(
            counts.get("trunked_functions", 0)
            or 0
        )
        partial_publication = dict(
            config.get("abi_partial_publication") or {}
        )
        stats["partial_publication_active"] = bool(
            partial_publication.get("active")
        )
        stats["partial_publication_policy"] = str(
            partial_publication.get("effective_policy") or "-"
        )
        stats["publication_class"] = str(
            config.get("publication_class")
            or partial_publication.get("publication_class")
            or (
                "TRIAGED"
                if stats["partial_publication_active"]
                else "COMPLETE"
                if config
                else "-"
            )
        ).upper()
        stats["entry_plans"] = int(
            counts.get("entry_plans", 0)
            or 0
        )
        stats["call_plans"] = int(
            counts.get("call_plans", 0)
            or 0
        )

        abi_publication = dict(
            config.get("abi_chain_publication") or {}
        )
        abi_counts = dict(abi_publication.get("counts") or {})
        stats["abi_health"] = str(
            abi_publication.get("health") or "BROKEN"
        ).upper()
        stats["abi_linked"] = int(
            abi_counts.get(
                "internal_calls_linked",
                counts.get("abi_internal_calls_linked", 0),
            ) or 0
        )
        stats["abi_unresolved"] = int(
            abi_counts.get(
                "unresolved_target_plans",
                counts.get("abi_unresolved_target_plans", 0),
            ) or 0
        )
        stats["abi_argument_incompatible"] = int(
            abi_counts.get(
                "argument_chains_incompatible",
                counts.get("abi_argument_chains_incompatible", 0),
            ) or 0
        )
        stats["abi_argument_incompatible_raw"] = int(
            abi_counts.get(
                "argument_chains_incompatible_raw",
                stats["abi_argument_incompatible"],
            ) or 0
        )
        stats["abi_argument_incompatible_waived"] = int(
            abi_counts.get(
                "argument_chains_incompatible_waived",
                0,
            ) or 0
        )
        stats["abi_argument_incompatible_bridged"] = int(
            abi_counts.get(
                "argument_chains_incompatible_bridged",
                0,
            ) or 0
        )
        stats["abi_core_conflicts"] = int(
            abi_counts.get(
                "plan_core_conflicts",
                counts.get("abi_plan_core_conflicts", 0),
            ) or 0
        )
        stats["abi_carrier_disagreements"] = int(
            abi_counts.get(
                "carrier_disagreements",
                counts.get("abi_carrier_disagreements", 0),
            ) or 0
        )
        stats["abi_result_width_conflicts"] = int(
            abi_counts.get(
                "result_width_conflicts",
                counts.get("abi_result_width_conflicts", 0),
            ) or 0
        )
        stats["abi_ghosts_resolved"] = int(
            abi_counts.get(
                "ghosts_resolved",
                counts.get("abi_ghosts_resolved", 0),
            ) or 0
        )
        stats["abi_ghosts_deferred"] = int(
            abi_counts.get(
                "ghosts_deferred",
                counts.get("abi_ghosts_deferred", 0),
            ) or 0
        )
        stats["abi_ghosts_conflicting"] = int(
            abi_counts.get(
                "ghosts_conflicting",
                counts.get("abi_ghosts_conflicting", 0),
            ) or 0
        )
        stats["abi_broken_reasons"] = list(
            abi_publication.get("broken_reasons") or []
        )
        stats["abi_degraded_reasons"] = list(
            abi_publication.get("degraded_reasons") or []
        )
        authority_loading = dict(config.get("abi_authority_loading") or {})
        stats["abi_authority_phase"] = str(
            authority_loading.get("phase") or "-"
        )
        stats["abi_authority_status"] = str(
            authority_loading.get("status") or "-"
        )

        if not abi_publication:
            try:
                project_authority = _load_project_final_abi_authority(project)
                project_custody = dict(
                    project_authority.get("custody_report") or {}
                )
                project_summary = dict(project_custody.get("summary") or {})
                stats["entry_plans"] = len(project_authority["entry_plans"])
                stats["call_plans"] = len(project_authority["call_plans"])
                stats["abi_health"] = str(
                    project_custody.get("status") or "BROKEN"
                ).upper()
                stats["abi_linked"] = int(project_summary.get("internal_calls_linked") or 0)
                stats["abi_unresolved"] = int(project_summary.get("internal_calls_unresolved") or 0)
                stats["abi_argument_incompatible"] = int(project_summary.get("argument_chains_incompatible") or 0)
                stats["abi_core_conflicts"] = int(project_summary.get("plan_core_conflicts") or 0)
                stats["abi_carrier_disagreements"] = int(project_summary.get("carrier_disagreements") or 0)
                stats["abi_result_width_conflicts"] = int(project_summary.get("result_width_conflicts") or 0)
                stats["abi_ghosts_resolved"] = int(project_summary.get("ghost_repairs_resolved") or 0)
                stats["abi_ghosts_deferred"] = int(project_summary.get("ghost_repairs_deferred") or 0)
                stats["abi_ghosts_conflicting"] = int(project_summary.get("ghost_repairs_conflicting") or 0)
                stats["abi_authority_phase"] = str(project_authority.get("phase") or "-")
                stats["abi_authority_status"] = str(project_authority.get("status") or "-")
                hard = []
                if stats["abi_core_conflicts"]:
                    hard.append("immutable_plan_core_conflict")
                if stats["abi_argument_incompatible"]:
                    hard.append("argument_chain_incompatibility")
                if stats["abi_carrier_disagreements"]:
                    hard.append("carrier_disagreement")
                if stats["abi_result_width_conflicts"]:
                    hard.append("result_width_conflict")
                if stats["abi_ghosts_conflicting"]:
                    hard.append("conflicting_ghost_contract")
                stats["abi_broken_reasons"] = hard
                deferred = []
                if stats["abi_unresolved"]:
                    deferred.append("unresolved_target_entry_plans")
                if int(project_summary.get("return_carriers_deferred") or 0):
                    deferred.append("return_carriers_deferred")
                if stats["abi_ghosts_deferred"]:
                    deferred.append("ghost_repairs_deferred")
                stats["abi_degraded_reasons"] = deferred
            except Exception as exc:
                stats["abi_health"] = "BROKEN"
                stats["abi_broken_reasons"] = [
                    "final_authority_unavailable:%s" % exc
                ]

        completion = dict(
            config.get(
                "static_string_completion"
            )
            or {}
        )
        completion_counts = dict(
            completion.get("counts") or {}
        )
        stats["static_strings_original"] = int(
            counts.get(
                "static_strings_original",
                completion_counts.get(
                    "original_strings",
                    0,
                ),
            )
            or 0
        )
        stats["static_strings_completed"] = int(
            counts.get(
                "static_strings_completed",
                completion_counts.get(
                    "completed_strings",
                    0,
                ),
            )
            or 0
        )
        stats["static_strings_final"] = int(
            counts.get(
                "static_strings_final",
                completion_counts.get(
                    "final_strings",
                    0,
                ),
            )
            or 0
        )
        stats["static_strings_required"] = int(
            counts.get(
                "static_strings_required",
                completion_counts.get(
                    "required_runtime_strings",
                    0,
                ),
            )
            or 0
        )
        stats["unresolved_ptrsub"] = int(
            counts.get(
                "static_strings_unresolved_ptrsub",
                completion_counts.get(
                    "unresolved_ptrsub_references",
                    0,
                ),
            )
            or 0
        )

        stats["direct_resolved"] = int(
            counts.get(
                "static_strings_direct_resolved",
                completion_counts.get(
                    "direct_resolved_references",
                    0,
                ),
            )
            or 0
        )
        stats["rebased_resolved"] = int(
            counts.get(
                "static_strings_rebased_resolved",
                completion_counts.get(
                    "rebased_resolved_references",
                    0,
                ),
            )
            or 0
        )
        stats["ambiguous_ptrsub"] = int(
            counts.get(
                "static_strings_ambiguous",
                completion_counts.get(
                    "ambiguous_references",
                    0,
                ),
            )
            or 0
        )
        stats["function_ptrsub"] = int(
            counts.get(
                "static_strings_function_pointers",
                completion_counts.get(
                    "function_pointer_references",
                    0,
                ),
            )
            or 0
        )
        stats["code_ptrsub"] = int(
            counts.get(
                "static_strings_code_pointers",
                completion_counts.get(
                    "code_pointer_references",
                    0,
                ),
            )
            or 0
        )
        translation = dict(
            completion.get(
                "address_translation"
            )
            or {}
        )
        stats["program_image_base"] = (
            translation.get("program_image_base")
        )
        stats["elf_link_base"] = (
            translation.get("elf_link_base")
        )
        stats["load_bias"] = (
            translation.get("load_bias")
        )
        stats["unresolved_ptr_addresses"] = [
            str(
                record.get("generated_address")
                or record.get("address")
                or "unknown"
            )
            for record in list(
                completion.get("unresolved") or []
            )
        ]

        shim_policy = dict(
            config.get("shim_policy") or {}
        )
        stats["unresolved_shims"] = len(
            list(
                shim_policy.get(
                    "unresolved_known_targets"
                )
                or []
            )
        )
        warning_messages = [
            str(value)
            for value in list(
                config.get("warnings") or []
            )
        ]
        stats["warning_messages"] = warning_messages
        non_ptr_warnings = [
            value
            for value in warning_messages
            if not value.startswith(
                "static-string PTRSUB unresolved:"
            )
        ]
        stats["warnings"] = (
            len(non_ptr_warnings)
            + stats["unresolved_ptrsub"]
        )
        stats["published_at_utc"] = str(
            config.get("published_at_utc") or "-"
        )

        run_block_reasons: List[str] = []
        if not stats["workspace_present"]:
            run_gate = "NOT_PUBLISHED"
            run_block_reasons.append("execute workspace is absent")
        elif not stats["workspace_current"]:
            run_gate = "STALE" if stats["workspace_state"] == "STALE" else "BROKEN_WORKSPACE"
            run_block_reasons.append(
                "execute workspace is %s" % stats["workspace_state"].lower()
            )
        elif stats["abi_health"] == "BROKEN":
            run_gate = "BLOCKED"
            run_block_reasons.extend(
                list(stats.get("abi_broken_reasons") or [])
                or ["ABI custody health is BROKEN"]
            )
        elif (
            stats["abi_health"] == "DEGRADED"
            or stats["unresolved_ptrsub"] > 0
            or stats["ambiguous_ptrsub"] > 0
        ):
            run_gate = "DEGRADED"
        else:
            run_gate = "READY"

        stats["run_gate"] = run_gate
        stats["run_allowed"] = run_gate in {"READY", "DEGRADED"}
        stats["run_block_reasons"] = run_block_reasons

        # Before the first v1k publication, show the current project overlay
        # rather than an empty string count.
        if stats["static_strings_final"] == 0:
            overlay_path = (
                project
                / "PAL_stdio_strings.json"
            )
            if overlay_path.is_file():
                try:
                    payload = _read_json(
                        overlay_path
                    )
                    strings = payload.get(
                        "strings",
                        payload,
                    )
                    if isinstance(strings, dict):
                        overlay_count = len(strings)
                        stats[
                            "static_strings_original"
                        ] = overlay_count
                        stats[
                            "static_strings_final"
                        ] = overlay_count
                except Exception:
                    pass

        return stats

    def _project_table_rows(
        self,
        projects: Sequence[Path],
    ) -> Tuple[List[Dict[str, Any]], List[List[str]]]:
        """Build the selected-project summary table.

        The old nineteen-column matrix is intentionally retired from the
        normal console path. Full authority remains in each project's JSON
        artifacts and can be surfaced explicitly through the details action.
        """
        stats = [self._project_stats(project) for project in projects]
        rows: List[List[str]] = []
        for index, item in enumerate(stats, 1):
            rows.append([
                str(index),
                _clip_text(item.get("project_name") or "-", 34),
                "%d/%d" % (
                    int(item.get("manifest_functions") or 0),
                    int(item.get("decompiled_functions") or 0),
                ),
                str(item.get("workspace_state") or "NONE"),
                str(item.get("run_gate") or "NOT_PUBLISHED"),
                str(item.get("publication_class") or "-"),
                str(item.get("abi_health") or "UNKNOWN"),
                str(int(item.get("warnings") or 0)),
            ])
        return stats, rows

    def print_project_table(
        self,
        projects: Optional[Sequence[Path]] = None,
        *,
        title: str = "PROJECT SUMMARY",
        diagnostics: bool = False,
    ) -> List[Dict[str, Any]]:
        """Print a compact state summary for already-selected projects."""
        selected = list(
            projects if projects is not None else self.discover_projects()
        )
        if not selected:
            print("No PAL projects found beneath project/ or projects/.")
            return []

        stats, rows = self._project_table_rows(selected)
        print("\n" + _tabloid_banner(str(title), "COMPACT PROJECT STATE"))
        print(
            _ascii_table(
                (
                    "#",
                    "PROJECT",
                    "MAN/DEC",
                    "WORKSPACE",
                    "RUN",
                    "PUBLICATION",
                    "ABI",
                    "WARN",
                ),
                rows,
                right_align=(0, 2, 7),
            )
        )
        if diagnostics:
            self._print_project_diagnostics(stats)
        return stats

    def print_project_list(
        self,
        projects: Optional[Sequence[Path]] = None,
        *,
        title: str = "PAL PROJECTS",
    ) -> List[Path]:
        """Print only project identities; do not scan or dump diagnostics."""
        selected = list(
            projects if projects is not None else self.discover_projects()
        )
        if not selected:
            print("No PAL projects found beneath project/ or projects/.")
            return []
        print("\n%s (%d)" % (str(title), len(selected)))
        for index, project in enumerate(selected, 1):
            print("  [%02d] %s" % (index, project.name))
        return selected

    def print_project_details(self, project: Path) -> Dict[str, Any]:
        """Show one selected project's useful state, with bounded issues."""
        item = self._project_stats(project)
        project_name = str(item.get("project_name") or Path(project).name)
        error = item.get("error")
        if error:
            print(
                "\n"
                + _tabloid_issue_table(
                    "%s // WORKSPACE ERROR" % project_name,
                    [error],
                    level="ERROR",
                    limit=8,
                )
            )
            return item

        print(
            "\n"
            + _tabloid_card(
                "PROJECT DETAILS",
                (
                    ("project", project_name),
                    (
                        "manifest",
                        "%d functions / %d decompiled / %d failed"
                        % (
                            int(item.get("manifest_functions") or 0),
                            int(item.get("decompiled_functions") or 0),
                            int(item.get("failed_functions") or 0),
                        ),
                    ),
                    (
                        "workspace",
                        "%s / %s"
                        % (
                            item.get("workspace_state") or "NONE",
                            item.get("publication_class") or "-",
                        ),
                    ),
                    (
                        "run / ABI",
                        "%s / %s"
                        % (
                            item.get("run_gate") or "NOT_PUBLISHED",
                            item.get("abi_health") or "UNKNOWN",
                        ),
                    ),
                    (
                        "published",
                        "%d functions / %d trunks / %s"
                        % (
                            int(item.get("published_functions") or 0),
                            int(item.get("trunked_functions") or 0),
                            _human_bytes(item.get("execute_bytes") or 0),
                        ),
                    ),
                    (
                        "ABI plans / links",
                        "%d/%d plans  %d/%d linked/unresolved"
                        % (
                            int(item.get("entry_plans") or 0),
                            int(item.get("call_plans") or 0),
                            int(item.get("abi_linked") or 0),
                            int(item.get("abi_unresolved") or 0),
                        ),
                    ),
                    (
                        "ABI I/C/W",
                        "%d/%d/%d"
                        % (
                            int(item.get("abi_argument_incompatible") or 0),
                            int(item.get("abi_core_conflicts") or 0)
                            + int(item.get("abi_carrier_disagreements") or 0),
                            int(item.get("abi_result_width_conflicts") or 0),
                        ),
                    ),
                    (
                        "ghost R/D/C",
                        "%d/%d/%d"
                        % (
                            int(item.get("abi_ghosts_resolved") or 0),
                            int(item.get("abi_ghosts_deferred") or 0),
                            int(item.get("abi_ghosts_conflicting") or 0),
                        ),
                    ),
                    (
                        "strings",
                        "%d+%d=%d  PTR? %d"
                        % (
                            int(item.get("static_strings_original") or 0),
                            int(item.get("static_strings_completed") or 0),
                            int(item.get("static_strings_final") or 0),
                            int(item.get("unresolved_ptrsub") or 0),
                        ),
                    ),
                    (
                        "warnings / shims",
                        "%d / %d"
                        % (
                            int(item.get("warnings") or 0),
                            int(item.get("unresolved_shims") or 0),
                        ),
                    ),
                ),
                state=(
                    "BLOCKED"
                    if str(item.get("run_gate") or "").upper()
                    in {"BLOCKED", "BROKEN_WORKSPACE"}
                    else "STALE"
                    if str(item.get("run_gate") or "").upper() == "STALE"
                    else "WARN"
                    if str(item.get("run_gate") or "").upper() == "DEGRADED"
                    else "OK"
                    if str(item.get("run_gate") or "").upper() == "READY"
                    else "INFO"
                ),
            )
        )

        issue_groups = (
            (
                "RUN GATE",
                list(item.get("run_block_reasons") or []),
                "ERROR",
            ),
            (
                "ABI REASONS",
                list(item.get("abi_broken_reasons") or [])
                or list(item.get("abi_degraded_reasons") or []),
                "ERROR"
                if str(item.get("abi_health") or "").upper() == "BROKEN"
                else "WARN",
            ),
            (
                "WARNINGS",
                [
                    str(value)
                    for value in list(item.get("warning_messages") or [])
                    if not str(value).startswith(
                        "static-string PTRSUB unresolved:"
                    )
                ],
                "WARN",
            ),
            (
                "UNRESOLVED PTRSUB",
                list(item.get("unresolved_ptr_addresses") or []),
                "WARN",
            ),
        )
        for label, values, level in issue_groups:
            if values:
                print(
                    _tabloid_issue_table(
                        "%s // %s" % (project_name, label),
                        values,
                        level=level,
                        limit=8,
                    )
                )
        return item

    def _print_project_diagnostics(
        self,
        stats: Sequence[Mapping[str, Any]],
    ) -> None:
        for item in stats:
            project_name = str(item.get("project_name") or "-")
            project = item.get("project")
            error = item.get("error")
            if error:
                print(
                    "\n"
                    + _tabloid_issue_table(
                        "%s // WORKSPACE ERROR" % project_name,
                        [error],
                        level="ERROR",
                    )
                )
                continue

            partial_active = bool(
                item.get("partial_publication_active")
            )
            abi_health = str(
                item.get("abi_health") or "UNKNOWN"
            ).upper()
            run_gate = str(
                item.get("run_gate") or "UNKNOWN"
            ).upper()
            interesting = bool(
                partial_active
                or abi_health in {"DEGRADED", "BROKEN"}
                or run_gate not in {"READY", "NOT_PUBLISHED"}
                or int(item.get("unresolved_ptrsub") or 0)
                or int(item.get("ambiguous_ptrsub") or 0)
                or list(item.get("warning_messages") or [])
            )
            if not interesting:
                continue

            print(
                "\n"
                + _tabloid_banner(
                    "%s // PROJECT DESK" % project_name,
                    "WORKSPACE %s // RUN %s // ABI %s"
                    % (
                        item.get("workspace_state") or "-",
                        run_gate,
                        abi_health,
                    ),
                )
            )

            if partial_active:
                print(
                    _tabloid_card(
                        "PARTIAL PUBLICATION",
                        (
                            ("policy", item.get("partial_publication_policy")),
                            ("trunks", int(item.get("trunked_functions") or 0)),
                            (
                                "ABI incompatible raw",
                                int(
                                    item.get(
                                        "abi_argument_incompatible_raw"
                                    )
                                    or 0
                                ),
                            ),
                            (
                                "trunk-waived",
                                int(
                                    item.get(
                                        "abi_argument_incompatible_waived"
                                    )
                                    or 0
                                ),
                            ),
                            (
                                "guard-bridged",
                                int(
                                    item.get(
                                        "abi_argument_incompatible_bridged"
                                    )
                                    or 0
                                ),
                            ),
                            (
                                "remaining hard",
                                int(
                                    item.get(
                                        "abi_argument_incompatible"
                                    )
                                    or 0
                                ),
                            ),
                        ),
                        state=(
                            "OK"
                            if run_gate in {"READY", "DEGRADED"}
                            else "BLOCKED"
                        ),
                    )
                )

            if abi_health in {"DEGRADED", "BROKEN"}:
                print(
                    _tabloid_card(
                        "ABI CUSTODY",
                        (
                            ("health", abi_health),
                            (
                                "linked / unresolved",
                                "%d / %d"
                                % (
                                    int(item.get("abi_linked") or 0),
                                    int(item.get("abi_unresolved") or 0),
                                ),
                            ),
                            (
                                "argument I raw/trunk/bridge/live",
                                "%d / %d / %d / %d"
                                % (
                                    int(
                                        item.get(
                                            "abi_argument_incompatible_raw"
                                        )
                                        or 0
                                    ),
                                    int(
                                        item.get(
                                            "abi_argument_incompatible_waived"
                                        )
                                        or 0
                                    ),
                                    int(
                                        item.get(
                                            "abi_argument_incompatible_bridged"
                                        )
                                        or 0
                                    ),
                                    int(
                                        item.get(
                                            "abi_argument_incompatible"
                                        )
                                        or 0
                                    ),
                                ),
                            ),
                            (
                                "core / carrier / width",
                                "%d / %d / %d"
                                % (
                                    int(item.get("abi_core_conflicts") or 0),
                                    int(
                                        item.get(
                                            "abi_carrier_disagreements"
                                        )
                                        or 0
                                    ),
                                    int(
                                        item.get(
                                            "abi_result_width_conflicts"
                                        )
                                        or 0
                                    ),
                                ),
                            ),
                            (
                                "ghost R / D / C",
                                "%d / %d / %d"
                                % (
                                    int(item.get("abi_ghosts_resolved") or 0),
                                    int(item.get("abi_ghosts_deferred") or 0),
                                    int(
                                        item.get(
                                            "abi_ghosts_conflicting"
                                        )
                                        or 0
                                    ),
                                ),
                            ),
                            ("run gate", run_gate),
                        ),
                        state=(
                            "BLOCKED"
                            if abi_health == "BROKEN"
                            else "WARN"
                        ),
                    )
                )
                reasons = (
                    list(item.get("abi_broken_reasons") or [])
                    if abi_health == "BROKEN"
                    else list(item.get("abi_degraded_reasons") or [])
                )
                if reasons:
                    print(
                        _tabloid_issue_table(
                            "%s // ABI REASONS" % project_name,
                            reasons,
                            level=(
                                "ERROR"
                                if abi_health == "BROKEN"
                                else "WARN"
                            ),
                        )
                    )
                if project:
                    print(
                        _ascii_table(
                            ("AUTHORITY", "PATH"),
                            (
                                (
                                    "custody",
                                    str(Path(project) / ABI_CUSTODY_REPORT),
                                ),
                                (
                                    "plan index",
                                    str(
                                        Path(project)
                                        / PROJECT_ABI_PLAN_INDEX
                                    ),
                                ),
                                (
                                    "final receipt",
                                    str(Path(project) / ABI_FINAL_AUTHORITY),
                                ),
                            ),
                        )
                    )

            run_block = list(item.get("run_block_reasons") or [])
            if run_gate in {
                "BLOCKED",
                "STALE",
                "BROKEN_WORKSPACE",
            } and run_block:
                print(
                    _tabloid_issue_table(
                        "%s // RUN GATE" % project_name,
                        run_block,
                        level="ERROR",
                    )
                )

            unresolved = int(item.get("unresolved_ptrsub") or 0)
            ambiguous = int(item.get("ambiguous_ptrsub") or 0)
            if unresolved or ambiguous:
                print(
                    _tabloid_card(
                        "STATIC ADDRESS MAP",
                        (
                            ("direct / rebased", "%d / %d" % (
                                int(item.get("direct_resolved") or 0),
                                int(item.get("rebased_resolved") or 0),
                            )),
                            ("ambiguous / unresolved", "%d / %d" % (
                                ambiguous, unresolved,
                            )),
                            ("PAL base", item.get("program_image_base") or "-"),
                            ("ELF base", item.get("elf_link_base") or "-"),
                            ("bias", _format_signed_hex(item.get("load_bias"))),
                        ),
                        state="WARN",
                    )
                )
                addresses = list(
                    item.get("unresolved_ptr_addresses") or []
                )
                if addresses:
                    print(
                        _tabloid_issue_table(
                            "%s // UNRESOLVED PTRSUB" % project_name,
                            addresses,
                            level="WARN",
                        )
                    )

            messages = [
                str(value)
                for value in list(item.get("warning_messages") or [])
                if not str(value).startswith(
                    "static-string PTRSUB unresolved:"
                )
            ]
            if messages:
                print(
                    _tabloid_issue_table(
                        "%s // WARNINGS" % project_name,
                        messages,
                        level="WARN",
                    )
                )

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

    def publish(
        self,
        project: Path,
        *,
        incomplete_policy: str = "abort",
        argument_policy: str = "abort",
    ) -> Tuple[Path, Dict[str, Any]]:
        return PALExecPublisherV1s(
            self.pal_root,
            project,
            incomplete_policy=incomplete_policy,
            argument_policy=argument_policy,
        ).publish()

    def run_published(
        self,
        project: Path,
        function: Optional[str],
        arguments: Sequence[Any],
        variadic_arguments: Sequence[Any],
        *,
        trace_runtime: bool = False,
        trace_stderr: bool = False,
    ) -> int:
        execute = project / EXECUTE_DIRECTORY
        runner = execute / "PAL_runner.py"
        config_path = execute / EXEC_CONFIG
        complete_path = execute / "PUBLISH_COMPLETE"
        if not runner.is_file() or not config_path.is_file() or not complete_path.is_file():
            raise PALExecInterfaceError(
                _format_gate_block(
                    "WORKSPACE NOT PUBLISHED",
                    [
                        "execute/PAL_runner.py, config.exec.json, and "
                        "PUBLISH_COMPLETE must all exist"
                    ],
                    report=execute,
                )
            )
        published_config = _read_json(config_path)
        published_build = str(published_config.get("build") or "")
        complete_build = complete_path.read_text(encoding="utf-8").splitlines()[0].strip()
        current_manifest = project / PROJECT_MANIFEST
        current_manifest_sha256 = (
            _sha256_file(current_manifest)
            if current_manifest.is_file()
            else ""
        )
        published_manifest_sha256 = str(
            published_config.get(
                "source_manifest_sha256"
            )
            or ""
        )
        if (
            published_build != PAL_EXEC_INTERFACE_BUILD
            or complete_build != PAL_EXEC_INTERFACE_BUILD
            or published_manifest_sha256
            != current_manifest_sha256
        ):
            raise PALExecInterfaceError(
                _tabloid_card(
                    "STALE EXECUTE WORKSPACE",
                    (
                        ("config build", published_build or "unknown"),
                        ("marker build", complete_build or "unknown"),
                        ("published manifest", published_manifest_sha256 or "unknown"),
                        ("current manifest", current_manifest_sha256 or "missing"),
                        ("required build", PAL_EXEC_INTERFACE_BUILD),
                        ("decision", "republish before execution"),
                    ),
                    state="STALE",
                )
            )
        abi_publication = dict(
            published_config.get("abi_chain_publication") or {}
        )
        abi_health = str(
            abi_publication.get("health") or "BROKEN"
        ).upper()
        if abi_health == "BROKEN":
            raise PALExecInterfaceError(
                _format_gate_block(
                    "PUBLISHED WORKSPACE // ABI RUN GATE",
                    list(abi_publication.get("broken_reasons") or [])
                    or ["ABI custody health is BROKEN"],
                    report=execute / ABI_CUSTODY_REPORT,
                )
            )
        if abi_health == "DEGRADED":
            abi_counts = dict(abi_publication.get("counts") or {})
            print(
                _tabloid_card(
                    "ABI RUN GATE",
                    (
                        ("decision", "run allowed with diagnostics"),
                        ("health", "DEGRADED"),
                        (
                            "linked / unresolved",
                            "%d / %d"
                            % (
                                int(abi_counts.get("internal_calls_linked") or 0),
                                int(abi_counts.get("unresolved_target_plans") or 0),
                            ),
                        ),
                        (
                            "argument raw/trunk/bridge/live",
                            "%d / %d / %d / %d"
                            % (
                                int(
                                    abi_counts.get(
                                        "argument_chains_incompatible_raw"
                                    )
                                    or abi_counts.get(
                                        "argument_chains_incompatible"
                                    )
                                    or 0
                                ),
                                int(
                                    abi_counts.get(
                                        "argument_chains_incompatible_waived"
                                    )
                                    or 0
                                ),
                                int(
                                    abi_counts.get(
                                        "argument_chains_incompatible_bridged"
                                    )
                                    or 0
                                ),
                                int(
                                    abi_counts.get(
                                        "argument_chains_incompatible"
                                    )
                                    or 0
                                ),
                            ),
                        ),
                        (
                            "ghost R / D / C",
                            "%d / %d / %d"
                            % (
                                int(abi_counts.get("ghosts_resolved") or 0),
                                int(abi_counts.get("ghosts_deferred") or 0),
                                int(abi_counts.get("ghosts_conflicting") or 0),
                            ),
                        ),
                    ),
                    state="WARN",
                ),
                file=sys.stderr,
            )
        partial_publication = dict(
            published_config.get("abi_partial_publication") or {}
        )
        if partial_publication.get("active"):
            print(
                _tabloid_card(
                    "TRIAGED RUN WARNING",
                    (
                        ("decision", "preview run allowed with diagnostics"),
                        (
                            "trunked functions",
                            int(
                                partial_publication.get(
                                    "trunked_function_count"
                                )
                                or len(
                                    partial_publication.get(
                                        "trunked_functions"
                                    )
                                    or []
                                )
                            ),
                        ),
                        (
                            "trunk behavior",
                            "void/zero sentinel if a sidelined function is called",
                        ),
                        (
                            "preview contract",
                            "path must not depend on sidelined-function semantics",
                        ),
                        (
                            "trace",
                            "use internal-call trace to detect trunk execution",
                        ),
                    ),
                    state="WARN",
                ),
                file=sys.stderr,
            )
        counts = dict(
            published_config.get("counts") or {}
        )
        unresolved_ptrsub = int(
            counts.get(
                "static_strings_unresolved_ptrsub",
                0,
            )
            or 0
        )
        if unresolved_ptrsub:
            translation = dict(
                (
                    published_config.get(
                        "static_string_memory_publication"
                    )
                    or {}
                ).get(
                    "address_translation"
                )
                or {}
            )
            print(
                _tabloid_card(
                    "STATIC ADDRESS RUN WARNING",
                    (
                        ("decision", "run allowed with diagnostics"),
                        ("unresolved PTRSUB", unresolved_ptrsub),
                        ("load bias", _format_signed_hex(translation.get("load_bias"))),
                    ),
                    state="WARN",
                ),
                file=sys.stderr,
            )
        command = [sys.executable, str(runner)]
        if trace_runtime or trace_stderr:
            command.append("--trace")
        if trace_stderr:
            command.append("--trace-stderr")
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

        self.print_project_list(projects)
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
        print(
            "\n"
            + _tabloid_banner(
                "PUBLISHED FUNCTIONS",
                "%s // SELECT EXECUTION ENTRY" % project.name,
            )
        )
        visible = records[:60]
        function_rows = [
            [
                str(index),
                _clip_text(record.get("name") or "-", 34),
                record.get("entry_hex") or "-",
                record.get("runtime_mode") or "-",
                "TRUNK" if record.get("runtime_mode") == "abi_trunk" else "-",
            ]
            for index, record in enumerate(visible, 1)
        ]
        print(
            _ascii_table(
                ("#", "FUNCTION", "ENTRY", "MODE", "NOTE"),
                function_rows,
                right_align=(0,),
            )
        )
        if len(records) > len(visible):
            print(
                _tabloid_card(
                    "FUNCTION LIST",
                    ((
                        "additional",
                        "%d more; enter a name or address directly"
                        % (len(records) - len(visible)),
                    ),),
                    state="INFO",
                )
            )
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

    def _print_publish_receipt(
        self,
        project: Path,
        target: Path,
        config: Mapping[str, Any],
    ) -> None:
        """Print one bounded publication receipt; details stay in JSON."""
        counts = dict(config.get("counts") or {})
        abi = dict(config.get("abi_chain_publication") or {})
        abi_counts = dict(abi.get("counts") or {})
        partial = dict(config.get("abi_partial_publication") or {})
        abi_health = str(abi.get("health") or "BROKEN").upper()

        print(
            "\n"
            + _tabloid_card(
                "PUBLISH COMPLETE",
                (
                    ("project", project.name),
                    ("workspace", target),
                    (
                        "class / run",
                        "%s / %s"
                        % (
                            config.get("publication_class") or "COMPLETE",
                            abi_health,
                        ),
                    ),
                    (
                        "functions",
                        "%d published / %d trunks"
                        % (
                            int(counts.get("published_functions") or 0),
                            int(counts.get("trunked_functions") or 0),
                        ),
                    ),
                    (
                        "ABI",
                        "%d/%d plans  %d/%d linked/unresolved"
                        % (
                            int(counts.get("entry_plans") or 0),
                            int(counts.get("call_plans") or 0),
                            int(abi_counts.get("internal_calls_linked") or 0),
                            int(abi_counts.get("unresolved_target_plans") or 0),
                        ),
                    ),
                    (
                        "ABI I/C/W",
                        "%d/%d/%d"
                        % (
                            int(abi_counts.get("argument_chains_incompatible") or 0),
                            int(abi_counts.get("plan_core_conflicts") or 0)
                            + int(abi_counts.get("carrier_disagreements") or 0),
                            int(abi_counts.get("result_width_conflicts") or 0),
                        ),
                    ),
                    (
                        "strings",
                        "%d+%d=%d  unresolved PTRSUB=%d"
                        % (
                            int(counts.get("static_strings_original") or 0),
                            int(counts.get("static_strings_completed") or 0),
                            int(counts.get("static_strings_final") or 0),
                            int(counts.get("static_strings_unresolved_ptrsub") or 0),
                        ),
                    ),
                    (
                        "details",
                        str(Path(target) / EXEC_CONFIG),
                    ),
                ),
                state=(
                    "BLOCKED"
                    if abi_health == "BROKEN"
                    else "WARN"
                    if abi_health == "DEGRADED"
                    else "TRIAGED"
                    if partial.get("active")
                    else "OK"
                ),
            )
        )

        reasons = (
            list(abi.get("broken_reasons") or [])
            if abi_health == "BROKEN"
            else list(abi.get("degraded_reasons") or [])
        )
        if reasons:
            print(
                _tabloid_issue_table(
                    "ABI DECISION REASONS",
                    reasons,
                    level="ERROR" if abi_health == "BROKEN" else "WARN",
                    limit=8,
                )
            )
        unresolved_shims = list(
            (config.get("shim_policy") or {}).get(
                "unresolved_known_targets"
            )
            or []
        )
        if unresolved_shims:
            print(
                "Closed external shims: %d (see %s)"
                % (len(unresolved_shims), Path(target) / EXEC_CONFIG)
            )

    def interactive(self) -> int:
        print(
            _tabloid_banner(
                "PAL EXECUTION INTERFACE",
                "RUNTIME %s // UI %s"
                % (PAL_EXEC_INTERFACE_BUILD, PAL_EXEC_INTERFACE_UI_BUILD),
            )
        )
        while True:
            project = self._choose_project()
            if project is None:
                return 0
            while True:
                project_stats = self._project_stats(project)
                workspace_state = str(
                    project_stats.get("workspace_state") or "NONE"
                ).upper()
                run_gate = str(
                    project_stats.get("run_gate") or "NOT_PUBLISHED"
                ).upper()
                run_allowed = bool(project_stats.get("run_allowed"))

                print("\nPROJECT  %s" % project.name)
                print(
                    "  workspace=%s  publication=%s  run=%s  ABI=%s"
                    % (
                        workspace_state,
                        project_stats.get("publication_class") or "-",
                        run_gate,
                        project_stats.get("abi_health") or "UNKNOWN",
                    )
                )
                print(
                    "  functions=%d/%d  published=%d  size=%s  warnings=%d"
                    % (
                        int(project_stats.get("decompiled_functions") or 0),
                        int(project_stats.get("manifest_functions") or 0),
                        int(project_stats.get("published_functions") or 0),
                        _human_bytes(project_stats.get("execute_bytes") or 0),
                        int(project_stats.get("warnings") or 0),
                    )
                )
                print(
                    "  [P] Publish  [R] Run  [T] Trace  [B] Publish+Run  "
                    "[D] Details  [C] Change  [Q] Quit"
                )
                action = input("Action: ").strip().lower()
                if action in {"q", "quit", "exit"}:
                    return 0
                if action in {"c", "change", "back"}:
                    break
                if action in {"d", "details", "info"}:
                    self.print_project_details(project)
                    continue
                if action not in {"p", "r", "t", "b"}:
                    print("Unknown action: %s" % (action or "<empty>"))
                    continue

                if action in {"p", "b"}:
                    try:
                        target, config = self.publish(
                            project,
                            incomplete_policy="prompt",
                            argument_policy="prompt",
                        )
                    except PALExecInterfaceError as exc:
                        print(
                            "\n"
                            + _tabloid_issue_table(
                                "PUBLICATION FAILED",
                                str(exc).splitlines(),
                                level="ERROR",
                                limit=12,
                            )
                        )
                        continue
                    self._print_publish_receipt(project, target, config)

                if action in {"r", "t", "b"}:
                    project_stats = self._project_stats(project)
                    workspace_current = bool(
                        project_stats.get("workspace_current")
                    )
                    run_allowed = bool(project_stats.get("run_allowed"))
                    run_gate = str(
                        project_stats.get("run_gate") or "UNKNOWN"
                    ).upper()
                    if not workspace_current:
                        print(
                            "\n"
                            + _format_gate_block(
                                "EXECUTE WORKSPACE NOT CURRENT",
                                list(
                                    project_stats.get("run_block_reasons")
                                    or [
                                        "workspace state is %s"
                                        % project_stats.get("workspace_state")
                                    ]
                                ),
                                report=project / EXECUTE_DIRECTORY,
                            )
                        )
                        continue
                    if not run_allowed:
                        print(
                            "\n"
                            + _format_gate_block(
                                "WORKSPACE PUBLISHED // RUN BLOCKED",
                                list(
                                    project_stats.get("run_block_reasons")
                                    or project_stats.get("abi_broken_reasons")
                                    or ["execution clearance was not granted"]
                                ),
                                report=(
                                    project
                                    / EXECUTE_DIRECTORY
                                    / ABI_CUSTODY_REPORT
                                ),
                            )
                        )
                        continue

                    function = self._choose_function(project)
                    if function is None:
                        continue
                    raw_args = input(
                        "Fixed args, comma separated [none]: "
                    ).strip()
                    arguments = [
                        _parse_scalar(value)
                        for value in raw_args.split(",")
                        if value.strip()
                    ]
                    raw_varargs = input(
                        "Variadic args, comma separated [none]: "
                    ).strip()
                    variadic = [
                        _parse_scalar(value)
                        for value in raw_varargs.split(",")
                        if value.strip()
                    ]
                    trace_runtime = action == "t"
                    print(
                        "\nRUN  project=%s  function=%s  gate=%s  trace=%s"
                        % (project.name, function, run_gate, trace_runtime)
                    )
                    try:
                        status = self.run_published(
                            project,
                            function,
                            arguments,
                            variadic,
                            trace_runtime=trace_runtime,
                            trace_stderr=trace_runtime,
                        )
                    except PALExecInterfaceError as exc:
                        print(str(exc))
                        continue
                    if trace_runtime:
                        print(
                            "TRACE  %s"
                            % (
                                project
                                / EXECUTE_DIRECTORY
                                / "PAL_runtime_trace.jsonl"
                            )
                        )
                    print("RUN COMPLETE  status=%s" % status)



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
    parser.add_argument(
        "--incomplete-policy",
        choices=sorted(_INIT_TRUNK_POLICIES),
        default="abort",
        help=(
            "handling for failed internal decompilations: abort (default), "
            "prompt, trunk-init, or trunk-all"
        ),
    )
    parser.add_argument(
        "--argument-policy",
        choices=sorted(_ABI_ARGUMENT_POLICIES),
        default="abort",
        help=(
            "handling for remaining ABI argument incompatibilities: "
            "abort (default), prompt, bridge-safe, or diagnostic"
        ),
    )
    parser.add_argument(
        "--trace-runtime",
        action="store_true",
        help="trace internal calls, pointer previews, and memory custody",
    )
    parser.add_argument(
        "--trace-stderr",
        action="store_true",
        help="mirror runtime trace records to stderr",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    interface = PALExecInterface(Path(args.root).expanduser() if args.root else None)

    if args.list_projects:
        interface.print_project_list()
        return 0

    if not args.project and not args.publish and not args.run:
        return interface.interactive()
    if not args.project:
        parser.error("--project is required with --publish or --run")

    project = interface.resolve_project(args.project)
    if args.publish:
        target, config = interface.publish(
            project,
            incomplete_policy=args.incomplete_policy,
            argument_policy=args.argument_policy,
        )
        interface._print_publish_receipt(
            project,
            target,
            config,
        )
    if args.run:
        values = [_parse_scalar(value) for value in args.arg]
        varargs = [_parse_scalar(value) for value in args.vararg]
        return interface.run_published(
            project,
            args.function,
            values,
            varargs,
            trace_runtime=args.trace_runtime,
            trace_stderr=args.trace_stderr,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PALExecInterfaceError as exc:
        text = str(exc)
        if text.startswith("+") and "\n" in text:
            print(text, file=sys.stderr)
        else:
            print(
                _tabloid_issue_table(
                    "PAL EXEC ERROR",
                    text.splitlines() or [text],
                    level="ERROR",
                ),
                file=sys.stderr,
            )
        raise SystemExit(2)
