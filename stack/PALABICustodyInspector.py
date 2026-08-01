"""PAL cross-function ABI custody inspection.

This module joins frozen caller call-site plans to exact callee entry plans.
It publishes detached custody contracts into existing PAL icecubes and a
project-level report. It does not rewrite generated Python, CFG, PHI state,
ExecTrees, or HighFunction SSA.
"""

from __future__ import annotations

PAL_ABI_CUSTODY_INSPECTOR_VERSION = (
    "v1b_canonical_project_plan_index"
)

import gzip
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from PALABIPlanCanonicalizer import (
    PAL_ABI_PLAN_CANONICALIZER_VERSION,
    PALABIPlanCoreConflict,
    canonicalize_plan,
    compare_plans,
    stamp_plan,
)


class PALABICustodyError(RuntimeError):
    """Base failure for deterministic ABI-custody inspection."""


class PALABICustodyIntegrityError(PALABICustodyError):
    """A frozen icecube failed its existing integrity contract."""


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, bytes):
        return {"kind": "bytes", "hex": value.hex()}
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in sorted(
                value.items(), key=lambda pair: str(pair[0])
            )
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted((_json_safe(item) for item in value), key=str)
    return str(value)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _json_safe(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: os.PathLike, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        path.name + ".tmp.%d" % os.getpid()
    )
    try:
        with open(
            temporary,
            "wt",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                payload,
                handle,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_write_gzip_json(path: os.PathLike, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        path.name + ".tmp.%d" % os.getpid()
    )
    try:
        with gzip.open(
            temporary,
            "wt",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                payload,
                handle,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_icecube(path: os.PathLike) -> Dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    _verify_icecube(payload)
    return payload


def _snapshot_unsigned(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "format": snapshot.get("format"),
        "schema_version": snapshot.get("schema_version"),
        "document": snapshot.get("document"),
    }


def _outer_unsigned(cube: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "format": cube.get("format"),
        "schema_version": cube.get("schema_version"),
        "manifest": cube.get("manifest"),
        "snapshot": cube.get("snapshot"),
    }


def _verify_icecube(cube: Mapping[str, Any]) -> None:
    if cube.get("format") != "pal_icecube":
        raise PALABICustodyIntegrityError(
            "unsupported PAL icecube format"
        )
    snapshot = cube.get("snapshot")
    if not isinstance(snapshot, Mapping):
        raise PALABICustodyIntegrityError(
            "PAL icecube has no frozen document snapshot"
        )
    nested_integrity = dict(snapshot.get("integrity") or {})
    nested_expected = _sha256_json(_snapshot_unsigned(snapshot))
    if nested_integrity.get("digest") != nested_expected:
        raise PALABICustodyIntegrityError(
            "PAL frozen document integrity mismatch"
        )
    outer_integrity = dict(cube.get("integrity") or {})
    outer_expected = _sha256_json(_outer_unsigned(cube))
    if outer_integrity.get("digest") != outer_expected:
        raise PALABICustodyIntegrityError(
            "PAL icecube envelope integrity mismatch"
        )


def _refresh_icecube_integrity(cube: Dict[str, Any]) -> None:
    snapshot = cube["snapshot"]
    nested_digest = _sha256_json(_snapshot_unsigned(snapshot))
    snapshot["integrity"] = {
        "algorithm": "sha256",
        "digest": nested_digest,
        "scope": "format+schema_version+document",
    }
    manifest = dict(cube.get("manifest") or {})
    manifest["document_sha256"] = nested_digest
    cube["manifest"] = manifest
    cube["integrity"] = {
        "algorithm": "sha256",
        "digest": _sha256_json(_outer_unsigned(cube)),
        "scope": "format+schema_version+manifest+snapshot",
    }


def _registry(cube: Mapping[str, Any]) -> Dict[str, Any]:
    snapshot = cube.get("snapshot") or {}
    document = snapshot.get("document") or {}
    registry = document.get("metadata_registry")
    if not isinstance(registry, dict):
        raise PALABICustodyError(
            "icecube document has no mutable metadata registry"
        )
    return registry


def _registry_key_rank(plan_class: str, registry_key: str) -> Tuple[int, str]:
    """Prefer producer-owned registry keys without changing plan semantics."""
    key = str(registry_key)
    if plan_class == "function_entry_abi_plan":
        if key == "abi:entry_plan":
            return (0, key)
        if key.startswith("abi:entry"):
            return (1, key)
    elif plan_class == "call_site_abi_plan":
        if key.startswith("abi:call:"):
            return (0, key)
        if key.startswith("abi:call_op:"):
            return (1, key)
    return (2, key)


def _unique_plans(
    registry: Mapping[str, Any],
    plan_class: str,
) -> List[Dict[str, Any]]:
    """Collapse registry aliases by immutable core, never by whole JSON."""
    groups: Dict[str, List[Tuple[str, Dict[str, Any], Dict[str, Any]]]] = {}
    for key, value in registry.items():
        if not isinstance(value, Mapping):
            continue
        if value.get("plan_class") != plan_class:
            continue
        plan_id = value.get("plan_id")
        if plan_id is None:
            continue
        plan = dict(value)
        identity = canonicalize_plan(
            plan,
            source={"registry_key": str(key)},
        )
        groups.setdefault(str(plan_id), []).append(
            (str(key), plan, identity)
        )

    out = []
    for plan_id in sorted(groups):
        records = groups[plan_id]
        core_hashes = {
            item[2]["plan_core_sha256"] for item in records
        }
        if len(core_hashes) != 1:
            first = records[0]
            differences = []
            for other in records[1:]:
                comparison = compare_plans(first[1], other[1])
                if comparison["classification"] == "core_conflict":
                    differences.append({
                        "left_registry_key": first[0],
                        "right_registry_key": other[0],
                        "core_differences": comparison[
                            "core_differences"
                        ],
                    })
            raise PALABIPlanCoreConflict(
                "registry ABI plan core conflict for %s: %s"
                % (plan_id, differences)
            )
        records.sort(
            key=lambda item: _registry_key_rank(
                plan_class, item[0]
            )
        )
        out.append(dict(records[0][1]))
    return out


def _entry_plan(cube: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    plans = _unique_plans(
        _registry(cube),
        "function_entry_abi_plan",
    )
    if not plans:
        value = _registry(cube).get("abi:entry_plan")
        return dict(value) if isinstance(value, Mapping) else None
    if len(plans) != 1:
        raise PALABICustodyError(
            "one function icecube contains multiple entry plans"
        )
    return plans[0]


def _function_identity(
    path: Path,
    cube: Mapping[str, Any],
    entry_plan: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    manifest = dict(cube.get("manifest") or {})
    name_provenance = dict(
        manifest.get("name_provenance") or {}
    )
    entry = (
        entry_plan.get("entry")
        if isinstance(entry_plan, Mapping)
        else None
    )
    return {
        "function_name": (
            (entry_plan or {}).get("function")
            if isinstance(entry_plan, Mapping)
            else manifest.get("function_name")
        )
        or manifest.get("function_name"),
        "function_id": name_provenance.get("function_id"),
        "entry": entry,
        "entry_hex": hex(entry) if isinstance(entry, int) else None,
        "entry_plan_id": (
            entry_plan.get("plan_id")
            if isinstance(entry_plan, Mapping)
            else None
        ),
        "icecube": path.name,
    }



def _canonical_project_plan_index(
    cube_records: Sequence[Dict[str, Any]],
    *,
    project_root: str,
    phase: str,
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[Tuple[str, str], Dict[str, Any]]]:
    """Build one project authority from direct metadata-registry owners."""
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for cube_record in cube_records:
        registry = cube_record["registry"]
        identity = cube_record["identity"]
        for registry_key, value in registry.items():
            if not isinstance(value, Mapping):
                continue
            plan_class = value.get("plan_class")
            plan_id = value.get("plan_id")
            if plan_class not in (
                "function_entry_abi_plan",
                "call_site_abi_plan",
            ) or plan_id in (None, ""):
                continue
            source = {
                "icecube": cube_record["path"].name,
                "registry_key": str(registry_key),
                "json_pointer": (
                    "/snapshot/document/metadata_registry/"
                    + str(registry_key)
                    .replace("~", "~0")
                    .replace("/", "~1")
                ),
                "function_id": identity.get("function_id"),
                "function_name": identity.get("function_name"),
                "function_entry": identity.get("entry"),
            }
            plan = dict(value)
            canonical = canonicalize_plan(plan, source=source)
            groups.setdefault(
                (canonical["plan_class"], canonical["plan_id"]),
                [],
            ).append({
                "source": source,
                "plan": plan,
                "canonical": canonical,
                "cube_record": cube_record,
            })

    internal_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    index_entry_plans: Dict[str, Any] = {}
    index_call_plans: Dict[str, Any] = {}
    audit_groups: List[Dict[str, Any]] = []
    core_conflicts: List[Dict[str, Any]] = []
    annotation_variant_groups = 0
    exact_duplicate_groups = 0
    alias_groups = 0
    total_occurrences = 0

    for group_key in sorted(groups):
        plan_class, plan_id = group_key
        occurrences = groups[group_key]
        total_occurrences += len(occurrences)
        occurrences.sort(
            key=lambda item: (
                _registry_key_rank(
                    plan_class,
                    item["source"]["registry_key"],
                ),
                item["source"]["icecube"],
            )
        )
        authoritative = occurrences[0]
        core_hashes = sorted({
            item["canonical"]["plan_core_sha256"]
            for item in occurrences
        })
        annotation_hashes = sorted({
            item["canonical"]["plan_annotation_sha256"]
            for item in occurrences
        })
        if len(occurrences) > 1:
            alias_groups += 1
        if len(core_hashes) > 1:
            classification = "core_conflict"
            conflict_differences = []
            for occurrence in occurrences[1:]:
                comparison = compare_plans(
                    authoritative["plan"],
                    occurrence["plan"],
                )
                if comparison["classification"] == "core_conflict":
                    conflict_differences.append({
                        "left_source": authoritative["source"],
                        "right_source": occurrence["source"],
                        "left_core_sha256": comparison[
                            "left_core_sha256"
                        ],
                        "right_core_sha256": comparison[
                            "right_core_sha256"
                        ],
                        "core_differences": comparison[
                            "core_differences"
                        ],
                    })
            conflict = {
                "plan_class": plan_class,
                "plan_id": plan_id,
                "core_hashes": core_hashes,
                "occurrences": [
                    item["source"] for item in occurrences
                ],
                "differences": conflict_differences,
            }
            core_conflicts.append(conflict)
        elif len(annotation_hashes) > 1:
            classification = "annotation_variants"
            annotation_variant_groups += 1
        else:
            classification = "exact_duplicates"
            exact_duplicate_groups += 1

        annotation_variants = []
        for annotation_hash in annotation_hashes:
            matching = [
                item for item in occurrences
                if item["canonical"][
                    "plan_annotation_sha256"
                ] == annotation_hash
            ]
            annotation_variants.append({
                "plan_annotation_sha256": annotation_hash,
                "annotations": matching[0]["canonical"][
                    "annotations"
                ],
                "sources": [item["source"] for item in matching],
            })

        public_record = {
            "kind": "pal_abi_canonical_project_plan_record_v1",
            "plan_class": plan_class,
            "plan_id": plan_id,
            "classification": classification,
            "plan_core_sha256": authoritative["canonical"][
                "plan_core_sha256"
            ],
            "immutable_core": authoritative["canonical"]["core"],
            "canonical_plan": authoritative["plan"],
            "authoritative_source": authoritative["source"],
            "occurrence_count": len(occurrences),
            "occurrences": [
                item["source"] for item in occurrences
            ],
            "annotation_variant_count": len(annotation_hashes),
            "annotation_variants": annotation_variants,
            "downstream_reinference_allowed": False,
        }
        if plan_class == "function_entry_abi_plan":
            index_entry_plans[plan_id] = public_record
        else:
            index_call_plans[plan_id] = public_record

        audit_groups.append({
            "plan_class": plan_class,
            "plan_id": plan_id,
            "classification": classification,
            "core_hashes": core_hashes,
            "annotation_hashes": annotation_hashes,
            "authoritative_source": authoritative["source"],
            "occurrences": [
                {
                    "source": item["source"],
                    "plan_core_sha256": item["canonical"][
                        "plan_core_sha256"
                    ],
                    "plan_annotation_sha256": item[
                        "canonical"
                    ]["plan_annotation_sha256"],
                }
                for item in occurrences
            ],
        })
        internal_groups[group_key] = {
            "authoritative": authoritative,
            "occurrences": occurrences,
            "classification": classification,
            "core_hashes": core_hashes,
            "annotation_hashes": annotation_hashes,
        }

    index_status = "broken" if core_conflicts else "ready"
    summary = {
        "kind": "pal_abi_canonical_project_plan_index_summary_v1",
        "status": index_status,
        "phase": str(phase),
        "entry_plans": len(index_entry_plans),
        "call_plans": len(index_call_plans),
        "plan_identities": len(groups),
        "plan_occurrences": total_occurrences,
        "alias_groups": alias_groups,
        "annotation_variant_groups": annotation_variant_groups,
        "exact_duplicate_groups": exact_duplicate_groups,
        "core_conflicts": len(core_conflicts),
    }
    index = {
        "format": "pal_abi_canonical_project_plan_index",
        "schema_version": 1,
        "version": PAL_ABI_CUSTODY_INSPECTOR_VERSION,
        "canonicalizer_version": PAL_ABI_PLAN_CANONICALIZER_VERSION,
        "project_root": str(project_root),
        "phase": str(phase),
        "status": index_status,
        "summary": summary,
        "entry_plans": index_entry_plans,
        "call_plans": index_call_plans,
        "core_conflicts": core_conflicts,
        "authority": {
            "identity": (
                "PALABIPlanCanonicalizer_v1_immutable_plan_core"
            ),
            "occurrence_scope": (
                "direct_PALCodeDocument_metadata_registry_owners_only"
            ),
            "selection": (
                "producer_registry_key_rank_then_icecube_name"
            ),
        },
        "acceptance_gates": {
            "recursive_whole_icecube_discovery_used": False,
            "whole_object_equality_used": False,
            "annotation_only_variants_are_conflicts": False,
            "core_conflicts_fail_closed": True,
        },
    }
    audit = {
        "format": "pal_abi_plan_alias_audit",
        "schema_version": 1,
        "version": PAL_ABI_CUSTODY_INSPECTOR_VERSION,
        "canonicalizer_version": PAL_ABI_PLAN_CANONICALIZER_VERSION,
        "project_root": str(project_root),
        "phase": str(phase),
        "status": index_status,
        "summary": summary,
        "groups": audit_groups,
        "core_conflicts": core_conflicts,
    }
    return index, audit, internal_groups


def _stamp_registry_plan_occurrences(
    cube_records: Sequence[Dict[str, Any]],
) -> int:
    stamped = 0
    for cube_record in cube_records:
        registry = cube_record["registry"]
        for key, value in list(registry.items()):
            if not isinstance(value, Mapping):
                continue
            if value.get("plan_class") not in (
                "function_entry_abi_plan",
                "call_site_abi_plan",
            ) or value.get("plan_id") in (None, ""):
                continue
            registry[key] = stamp_plan(value)
            stamped += 1
    return stamped


def _health_status(summary: Mapping[str, Any]) -> str:
    hard_conflicts = sum(int(summary.get(key) or 0) for key in (
        "plan_core_conflicts",
        "argument_chains_incompatible",
        "carrier_disagreements",
        "result_width_conflicts",
        "ghost_repairs_conflicting",
    ))
    if hard_conflicts:
        return "broken"
    deferred = sum(int(summary.get(key) or 0) for key in (
        "internal_calls_unresolved",
        "return_carriers_deferred",
        "ghost_repairs_deferred",
    ))
    return "degraded" if deferred else "ready"


def _parse_storage_width(storage_key: Any) -> Optional[int]:
    text = str(storage_key or "")
    match = re.search(r":(\d+)\s*$", text)
    if not match:
        return None
    size = int(match.group(1))
    return size * 8 if size > 0 else None


def _canonical_register(name: Any) -> Optional[str]:
    text = str(name or "").upper()
    aliases = {
        "AL": "RAX", "AH": "RAX", "AX": "RAX", "EAX": "RAX",
        "BL": "RBX", "BH": "RBX", "BX": "RBX", "EBX": "RBX",
        "CL": "RCX", "CH": "RCX", "CX": "RCX", "ECX": "RCX",
        "DL": "RDX", "DH": "RDX", "DX": "RDX", "EDX": "RDX",
        "DIL": "RDI", "DI": "RDI", "EDI": "RDI",
        "SIL": "RSI", "SI": "RSI", "ESI": "RSI",
        "BPL": "RBP", "BP": "RBP", "EBP": "RBP",
        "SPL": "RSP", "SP": "RSP", "ESP": "RSP",
    }
    if text in aliases:
        return aliases[text]
    if re.fullmatch(r"R(?:8|9|1[0-5])[DWB]?", text):
        return re.sub(r"[DWB]$", "", text)
    if text.startswith(("YMM", "ZMM")):
        return "XMM" + text[3:]
    return text or None


def _carrier_kind_from_binding(binding: Mapping[str, Any]) -> Optional[str]:
    bank = str(binding.get("carrier_bank") or "").lower()
    if binding.get("register"):
        if bank == "vector":
            return "xmm_register"
        return "gp_register"
    storage_key = str(binding.get("storage_key") or "")
    if storage_key.startswith("stack:"):
        return "stack_overflow_argument"
    return None


def _binding_for_fixed_argument(
    fixed_argument: Mapping[str, Any],
) -> Optional[Dict[str, Any]]:
    bindings = [
        dict(item)
        for item in list(
            fixed_argument.get("physical_carrier_bindings") or []
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
            str(item.get("register") or item.get("storage_key") or ""),
        )
    )
    return bindings[0]


def _argument_chain(
    call_plan: Mapping[str, Any],
    entry_plan: Mapping[str, Any],
) -> Dict[str, Any]:
    caller_arguments = sorted(
        [
            dict(item)
            for item in list(call_plan.get("arguments") or [])
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
            for item in list(entry_plan.get("fixed_arguments") or [])
            if isinstance(item, Mapping)
        ],
        key=lambda item: (
            item.get("ordinal") is None,
            item.get("ordinal")
            if isinstance(item.get("ordinal"), int)
            else 0,
        ),
    )
    target_count = entry_plan.get("fixed_argument_count")
    if not isinstance(target_count, int):
        target_count = len(target_arguments)

    argument_records: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    count = max(len(caller_arguments), len(target_arguments))
    for index in range(count):
        caller = (
            caller_arguments[index]
            if index < len(caller_arguments)
            else None
        )
        target = (
            target_arguments[index]
            if index < len(target_arguments)
            else None
        )
        binding = (
            _binding_for_fixed_argument(target)
            if target is not None
            else None
        )
        caller_kind = (
            caller.get("carrier_kind")
            if caller is not None
            else None
        )
        target_kind = (
            _carrier_kind_from_binding(binding)
            if binding is not None
            else None
        )
        caller_register = _canonical_register(
            (caller or {}).get("carrier")
        )
        target_register = _canonical_register(
            (binding or {}).get("register")
        )
        caller_width = (caller or {}).get("source_width_bits")
        target_carrier_width = _parse_storage_width(
            (binding or {}).get("storage_key")
        )
        caller_class = str(
            (caller or {}).get("argument_class") or ""
        )
        target_class = str(
            (binding or {}).get("carrier_class") or ""
        )
        class_compatible = bool(
            caller is not None
            and target is not None
            and (
                caller_class == target_class
                or {
                    caller_class,
                    target_class,
                } <= {"integer", "unknown_scalar"}
            )
        )
        width_compatible = bool(
            isinstance(caller_width, int)
            and caller_width > 0
            and (
                target_carrier_width is None
                or caller_width <= target_carrier_width
            )
        )
        carrier_compatible = bool(
            caller is not None
            and target is not None
            and caller_kind == target_kind
            and (
                caller_register == target_register
                if caller_kind in ("gp_register", "xmm_register")
                else (
                    (caller or {}).get("stack_slot")
                    == (binding or {}).get("stack_slot")
                    if (binding or {}).get("stack_slot") is not None
                    else True
                )
            )
        )
        order_compatible = bool(
            caller is not None
            and target is not None
            and int(caller.get("index", index)) == index
            and int(target.get("ordinal", index)) == index
        )
        status = (
            "ready"
            if (
                class_compatible
                and width_compatible
                and carrier_compatible
                and order_compatible
            )
            else "incompatible"
        )
        record = {
            "index": index,
            "status": status,
            "caller": {
                "source_sid": (caller or {}).get("source_sid"),
                "source_name": (caller or {}).get("source_name"),
                "argument_class": caller_class or None,
                "source_width_bits": caller_width,
                "carrier_kind": caller_kind,
                "carrier": (caller or {}).get("carrier"),
                "canonical_carrier": caller_register,
                "stack_slot": (caller or {}).get("stack_slot"),
            },
            "callee": {
                "source_sid": (target or {}).get("source_sid"),
                "name": (target or {}).get("name"),
                "ordinal": (target or {}).get("ordinal"),
                "carrier_kind": target_kind,
                "carrier": (binding or {}).get("register"),
                "canonical_carrier": target_register,
                "carrier_class": target_class or None,
                "carrier_width_bits": target_carrier_width,
                "storage_key": (binding or {}).get("storage_key"),
            },
            "agreement": {
                "order": order_compatible,
                "class": class_compatible,
                "width": width_compatible,
                "carrier": carrier_compatible,
            },
        }
        argument_records.append(record)
        if status != "ready":
            failures.append(record)

    arity_compatible = bool(
        len(caller_arguments)
        == len(target_arguments)
        == target_count
    )
    status = (
        "ready"
        if arity_compatible and not failures
        else "incompatible"
    )
    return {
        "kind": "pal_abi_argument_custody_chain_v1",
        "status": status,
        "caller_argument_count": len(caller_arguments),
        "callee_fixed_argument_count": target_count,
        "callee_materialized_argument_count": len(target_arguments),
        "arity_compatible": arity_compatible,
        "arguments": argument_records,
        "failures": failures,
        "materialization_authority": (
            "call_site_carriers_joined_to_exact_entry_plan_bindings"
        ),
    }


def _asm_blocks(registry: Mapping[str, Any]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    aggregate = registry.get("asm:blocks")
    values: Iterable[Any]
    if isinstance(aggregate, Mapping):
        values = aggregate.values()
    else:
        values = [
            value
            for key, value in registry.items()
            if str(key).startswith("asm:block:")
        ]
    for value in values:
        if not isinstance(value, Mapping):
            continue
        address = value.get("block_addr_int")
        if not isinstance(address, int):
            raw = value.get("block_addr")
            try:
                address = int(str(raw), 0)
            except (TypeError, ValueError):
                continue
        out[int(address)] = dict(value)
    return out


def _successors(
    block: Mapping[str, Any],
    known_blocks: Mapping[int, Any],
) -> List[int]:
    out = []
    for raw in list(block.get("terminal_successors") or []):
        try:
            address = int(str(raw), 0)
        except (TypeError, ValueError):
            continue
        if address in known_blocks and address not in out:
            out.append(address)
    next_block = block.get("next_block_start")
    try:
        next_address = int(str(next_block), 0)
    except (TypeError, ValueError):
        next_address = None
    if (
        next_address in known_blocks
        and next_address not in out
        and not out
    ):
        out.append(next_address)
    return out


def _instruction_register_writes(
    instruction: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    out = []
    for operation in list(instruction.get("raw_pcode") or []):
        if not isinstance(operation, Mapping):
            continue
        output = operation.get("output")
        if not isinstance(output, Mapping):
            continue
        if output.get("is_register") is not True:
            continue
        offset = output.get("offset")
        size = output.get("size")
        if not isinstance(offset, int) or not isinstance(size, int):
            continue
        out.append({
            "offset": offset,
            "size_bytes": size,
            "width_bits": size * 8,
            "repr": output.get("repr"),
            "pcode": operation.get("repr"),
        })
    return out


def _assembly_register_tokens(assembly: Any) -> List[str]:
    text = str(assembly or "").upper()
    names = re.findall(
        r"\b(?:RAX|EAX|AX|AH|AL|RBX|EBX|BX|BH|BL|"
        r"RCX|ECX|CX|CH|CL|RDX|EDX|DX|DH|DL|"
        r"RDI|EDI|DI|DIL|RSI|ESI|SI|SIL|"
        r"RBP|EBP|BP|BPL|RSP|ESP|SP|SPL|"
        r"R(?:8|9|1[0-5])(?:D|W|B)?|"
        r"(?:XMM|YMM|ZMM)\d+)\b",
        text,
    )
    return [_canonical_register(name) for name in names]


def _return_carrier_evidence(
    target_registry: Mapping[str, Any],
    entry_plan: Mapping[str, Any],
    logical_width: Optional[int],
) -> Dict[str, Any]:
    backend = str(
        (entry_plan.get("abi_backend") or {}).get("name") or ""
    )
    blocks = _asm_blocks(target_registry)
    return_blocks = {
        int(item.get("block_addr"))
        for item in list(
            entry_plan.get("reachable_return_boundaries") or []
        )
        if isinstance(item, Mapping)
        and isinstance(item.get("block_addr"), int)
    }
    predecessors: Dict[int, List[int]] = {
        address: [] for address in blocks
    }
    for address, block in blocks.items():
        for successor in _successors(block, blocks):
            predecessors.setdefault(successor, []).append(address)

    evidence_paths: List[Dict[str, Any]] = []
    candidate_families: List[str] = []
    candidate_offsets: List[int] = []
    raw_widths: List[int] = []

    def last_eligible_write(
        block_address: int,
        visited: Tuple[int, ...],
    ) -> List[Dict[str, Any]]:
        if block_address in visited:
            return []
        block = blocks.get(block_address)
        if block is None:
            return []
        instructions = list(block.get("instructions") or [])
        for instruction in reversed(instructions):
            writes = _instruction_register_writes(instruction)
            eligible = []
            tokens = _assembly_register_tokens(
                instruction.get("assembly")
            )
            for write in writes:
                family = None
                if write["offset"] == 0:
                    family = "RAX"
                elif any(
                    token and token.startswith("XMM")
                    for token in tokens
                ):
                    family = next(
                        token
                        for token in tokens
                        if token and token.startswith("XMM")
                    )
                if family in ("RAX", "XMM0"):
                    eligible.append({
                        "block_addr": block_address,
                        "instruction_addr": instruction.get("addr_int"),
                        "instruction": instruction.get("assembly"),
                        "register": family,
                        **write,
                    })
            if eligible:
                return eligible
        results = []
        for predecessor in predecessors.get(block_address, []):
            results.extend(
                last_eligible_write(
                    predecessor,
                    visited + (block_address,),
                )
            )
        return results

    for return_block in sorted(return_blocks):
        records = last_eligible_write(return_block, ())
        evidence_paths.append({
            "return_block_addr": return_block,
            "writes": records,
        })
        for record in records:
            if record["register"] not in candidate_families:
                candidate_families.append(record["register"])
            if record["offset"] not in candidate_offsets:
                candidate_offsets.append(record["offset"])
            raw_widths.append(record["width_bits"])

    if (
        backend == "sysv_amd64"
        and candidate_families == ["RAX"]
        and candidate_offsets == [0]
        and evidence_paths
        and all(item["writes"] for item in evidence_paths)
    ):
        register = "RAX"
        carrier_width = max(raw_widths + [64])
        status = "resolved"
        reason = (
            "all_reachable_raw_return_paths_write_RAX_family_"
            "under_sysv_amd64"
        )
    elif (
        backend == "sysv_amd64"
        and candidate_families == ["XMM0"]
        and evidence_paths
        and all(item["writes"] for item in evidence_paths)
    ):
        register = "XMM0"
        carrier_width = max(raw_widths + [128])
        status = "resolved"
        reason = (
            "all_reachable_raw_return_paths_write_XMM0_family_"
            "under_sysv_amd64"
        )
    else:
        register = None
        carrier_width = None
        status = "deferred"
        reason = "no_single_raw_return_carrier_family_proven"

    return {
        "kind": "pal_abi_return_carrier_evidence_v1",
        "status": status,
        "backend": backend or None,
        "register": register,
        "carrier_width_bits": carrier_width,
        "logical_width_bits": logical_width,
        "register_offsets": candidate_offsets,
        "raw_path_evidence": evidence_paths,
        "reason": reason,
        "reinference_allowed": False,
    }


def _call_address(plan: Mapping[str, Any]) -> Optional[int]:
    for source in (
        plan.get("call_address"),
        (plan.get("source_call_site_abi_contract") or {}).get(
            "call_address"
        ),
        plan.get("op_id"),
    ):
        if isinstance(source, int):
            return source
        match = re.search(r"0x[0-9a-fA-F]+", str(source or ""))
        if match:
            return int(match.group(0), 16)
    return None


def _carrier_offset(register: Any) -> Optional[int]:
    canonical = _canonical_register(register)
    if canonical == "RAX":
        return 0
    return None


def _return_liveness(
    caller_registry: Mapping[str, Any],
    caller_entry: Mapping[str, Any],
    call_plan: Mapping[str, Any],
    carrier: Mapping[str, Any],
) -> Dict[str, Any]:
    blocks = _asm_blocks(caller_registry)
    call_block = call_plan.get("block_addr")
    call_address = _call_address(call_plan)
    register = carrier.get("register")
    offset = _carrier_offset(register)
    return_blocks = {
        int(item.get("block_addr"))
        for item in list(
            caller_entry.get("reachable_return_boundaries") or []
        )
        if isinstance(item, Mapping)
        and isinstance(item.get("block_addr"), int)
    }
    boundary_records = [
        dict(item)
        for item in list(
            caller_entry.get("reachable_return_boundaries") or []
        )
        if isinstance(item, Mapping)
    ]
    if (
        not isinstance(call_block, int)
        or call_block not in blocks
        or not isinstance(call_address, int)
        or offset is None
        or not return_blocks
    ):
        return {
            "kind": "pal_abi_return_carrier_liveness_v1",
            "status": "deferred",
            "carrier_live_to_return": None,
            "call_address": call_address,
            "call_block_addr": call_block,
            "return_boundaries": boundary_records,
            "intervening_carrier_writes": [],
            "reason": "insufficient_call_block_carrier_or_return_metadata",
        }

    paths_to_return = 0
    writes: List[Dict[str, Any]] = []
    seen_states = set()

    def walk(
        block_address: int,
        after_address: Optional[int],
        path: Tuple[int, ...],
    ) -> None:
        nonlocal paths_to_return
        state = (block_address, after_address)
        if state in seen_states or block_address in path:
            return
        seen_states.add(state)
        block = blocks.get(block_address)
        if block is None:
            return
        instructions = list(block.get("instructions") or [])
        for instruction in instructions:
            address = instruction.get("addr_int")
            if (
                after_address is not None
                and isinstance(address, int)
                and address <= after_address
            ):
                continue
            for write in _instruction_register_writes(instruction):
                if write.get("offset") == offset:
                    writes.append({
                        "block_addr": block_address,
                        "instruction_addr": address,
                        "instruction": instruction.get("assembly"),
                        "register": register,
                        **write,
                    })
        if block_address in return_blocks:
            paths_to_return += 1
            return
        for successor in _successors(block, blocks):
            walk(successor, None, path + (block_address,))

    walk(call_block, call_address, ())
    unique_writes = []
    seen_writes = set()
    for record in writes:
        key = (
            record.get("block_addr"),
            record.get("instruction_addr"),
            record.get("offset"),
            record.get("width_bits"),
        )
        if key in seen_writes:
            continue
        seen_writes.add(key)
        unique_writes.append(record)

    if paths_to_return == 0:
        status = "deferred"
        live = None
        reason = "call_has_no_path_to_reachable_return_boundary"
    elif unique_writes:
        status = "overwritten"
        live = False
        reason = "physical_return_carrier_written_before_function_return"
    else:
        status = "live"
        live = True
        reason = "no_raw_write_to_return_carrier_on_reachable_return_paths"

    constant_boundaries = [
        item
        for item in boundary_records
        if str(item.get("return_value_sid") or "").startswith("c_")
    ]
    return {
        "kind": "pal_abi_return_carrier_liveness_v1",
        "status": status,
        "carrier_live_to_return": live,
        "call_address": call_address,
        "call_block_addr": call_block,
        "reachable_return_paths": paths_to_return,
        "return_boundaries": boundary_records,
        "constant_or_unrelated_return_boundaries": constant_boundaries,
        "intervening_carrier_writes": unique_writes,
        "reason": reason,
        "raw_machine_authority": (
            "PALlibrary.PALLifter.raw_machine_image"
        ),
    }


def _candidate_from_plan(plan: Mapping[str, Any]) -> Dict[str, Any]:
    candidate = plan.get("call_result_candidate")
    if isinstance(candidate, Mapping):
        return dict(candidate)
    result = plan.get("result_contract") or {}
    nested = (
        result.get("call_result_candidate")
        if isinstance(result, Mapping)
        else None
    )
    return dict(nested) if isinstance(nested, Mapping) else {}


def _logical_result_width(
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    entry_plan: Mapping[str, Any],
) -> Tuple[Optional[int], str]:
    result = dict(plan.get("result_contract") or {})
    for key, authority in (
        ("output_width_bits", "caller_output_ssa_width"),
        (
            "candidate_result_width_bits",
            "PALCompute_v23c_candidate_width",
        ),
        (
            "effective_result_width_bits",
            "caller_effective_result_width",
        ),
    ):
        value = (
            candidate.get(key)
            if key == "candidate_result_width_bits"
            else result.get(key)
        )
        if isinstance(value, int) and value > 0:
            return value, authority
    target_result = dict(entry_plan.get("return_contract") or {})
    value = target_result.get("logical_result_width_bits")
    if isinstance(value, int) and value > 0:
        return value, "callee_reachable_return_transport"
    return None, "deferred"


def _repair_contract(
    call_plan: Mapping[str, Any],
    entry_plan: Mapping[str, Any],
    argument_chain: Mapping[str, Any],
    carrier: Mapping[str, Any],
    liveness: Mapping[str, Any],
    candidate: Mapping[str, Any],
    logical_width: Optional[int],
    width_authority: str,
) -> Dict[str, Any]:
    output_sid = (
        (call_plan.get("result_contract") or {}).get("output_sid")
    )
    is_candidate = candidate.get("candidate") is True
    if not is_candidate:
        status = (
            "linked"
            if (
                argument_chain.get("status") == "ready"
                and carrier.get("status") == "resolved"
            )
            else "deferred"
        )
        repair_status = "not_required"
        emitter_authorized = False
    else:
        blockers = []
        if argument_chain.get("status") != "ready":
            blockers.append("argument_chain_not_ready")
        if carrier.get("status") != "resolved":
            blockers.append("return_carrier_not_resolved")
        if not isinstance(logical_width, int):
            blockers.append("logical_result_width_not_resolved")
        if liveness.get("carrier_live_to_return") is not True:
            blockers.append("carrier_not_proven_live_to_return")
        if candidate.get("status") == (
            "outputless_nonvoid_result_width_conflict"
        ):
            blockers.append("candidate_width_conflict")
        if blockers:
            status = "deferred"
            repair_status = "deferred_outputless_call_result"
            emitter_authorized = False
        else:
            status = "resolved"
            repair_status = (
                "abi_implicit_call_result_live_to_return_v1"
            )
            emitter_authorized = True
    return {
        "status": status,
        "repair_status": repair_status,
        "inspector_metadata_only": True,
        "emitter_repair_authorized": emitter_authorized,
        "repair_authority": (
            "PALABICustodyInspector_v1_exact_cross_function_contract"
        ),
        "output_sid": output_sid,
        "logical_result_width_bits": logical_width,
        "width_authority": width_authority,
        "physical_return_register": carrier.get("register"),
        "carrier_width_bits": carrier.get("carrier_width_bits"),
        "carrier_live_to_return": liveness.get(
            "carrier_live_to_return"
        ),
        "intervening_carrier_writes": list(
            liveness.get("intervening_carrier_writes") or []
        ),
        "rule": (
            "authorize_only_exact_call_entry_carrier_width_liveness_"
            "agreement_never_last_call_surface_inference"
        ),
    }


def _contract_id(plan_id: Any, entry_plan_id: Any) -> str:
    payload = (
        str(plan_id) + "\0" + str(entry_plan_id)
    ).encode("utf-8")
    return "abi_custody:" + hashlib.sha256(payload).hexdigest()[:24]


def _patch_plan_duplicates(
    registry: Dict[str, Any],
    plan_id: str,
    contract: Mapping[str, Any],
) -> int:
    changed = 0
    for key, value in list(registry.items()):
        if (
            isinstance(value, dict)
            and value.get("plan_class") == "call_site_abi_plan"
            and str(value.get("plan_id")) == str(plan_id)
        ):
            value["abi_custody_contract_ref"] = contract["contract_id"]
            value["abi_custody_contract"] = dict(contract)
            registry[key] = value
            changed += 1
    return changed


class PALABICustodyInspector:
    """Inspect and publish whole-project cross-function ABI custody."""

    REPORT_FILENAME = "PAL_abi_custody.json"
    PLAN_INDEX_FILENAME = "PAL_abi_plan_index.json"
    ALIAS_AUDIT_FILENAME = "PAL_abi_plan_alias_audit.json"

    def __init__(
        self,
        project_root: os.PathLike,
        *,
        records: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> None:
        self.project_root = Path(project_root)
        self.functions_root = self.project_root / "functions"
        self.records = records
        self.report_path = self.project_root / self.REPORT_FILENAME
        self.plan_index_path = (
            self.project_root / self.PLAN_INDEX_FILENAME
        )
        self.alias_audit_path = (
            self.project_root / self.ALIAS_AUDIT_FILENAME
        )

    def _icecube_paths(self) -> List[Path]:
        return sorted(
            self.functions_root.glob("*.icecube.json*.gz")
        )

    def run(self) -> Dict[str, Any]:
        cube_records = []
        for path in self._icecube_paths():
            cube = _read_icecube(path)
            entry = _entry_plan(cube)
            identity = _function_identity(path, cube, entry)
            cube_records.append({
                "path": path,
                "cube": cube,
                "registry": _registry(cube),
                "entry_plan": entry,
                "identity": identity,
            })

        initial_index, initial_alias_audit, plan_groups = (
            _canonical_project_plan_index(
                cube_records,
                project_root=self.project_root.name,
                phase="pre_custody_join",
            )
        )
        if initial_index["summary"]["core_conflicts"]:
            _atomic_write_json(self.plan_index_path, initial_index)
            _atomic_write_json(
                self.alias_audit_path,
                initial_alias_audit,
            )
            raise PALABIPlanCoreConflict(
                "project ABI plan index contains immutable-core conflicts; "
                "inspect %s" % self.alias_audit_path
            )

        entries_by_id: Dict[str, Dict[str, Any]] = {}
        entries_by_address: Dict[int, Dict[str, Any]] = {}
        call_plans_by_icecube: Dict[str, List[Dict[str, Any]]] = {}
        for (plan_class, plan_id), group in plan_groups.items():
            authoritative = group["authoritative"]
            source_record = authoritative["cube_record"]
            plan = authoritative["plan"]
            if plan_class == "function_entry_abi_plan":
                entries_by_id[str(plan_id)] = source_record
                address = plan.get("entry")
                if isinstance(address, int):
                    entries_by_address[address] = source_record
                # Use the exact canonical occurrence for all joins.
                source_record["entry_plan"] = plan
            elif plan_class == "call_site_abi_plan":
                call_plans_by_icecube.setdefault(
                    source_record["path"].name,
                    [],
                ).append(plan)

        for values in call_plans_by_icecube.values():
            values.sort(key=lambda item: str(item.get("plan_id") or ""))

        contracts: List[Dict[str, Any]] = []
        unresolved: List[Dict[str, Any]] = []
        inbound: Dict[str, List[str]] = {}
        for caller in cube_records:
            plans = call_plans_by_icecube.get(
                caller["path"].name,
                [],
            )
            for call_plan in plans:
                if (
                    call_plan.get("dispatch_policy")
                    != "PAL_internal_dispatch"
                ):
                    continue
                target = dict(call_plan.get("target") or {})
                compatibility = dict(
                    call_plan.get("target_compatibility") or {}
                )
                lookup = (
                    target.get("entry_plan_lookup_key")
                    or compatibility.get("entry_plan_lookup_key")
                )
                callee = (
                    entries_by_id.get(str(lookup))
                    if lookup is not None
                    else None
                )
                if callee is None and isinstance(
                    target.get("entry"), int
                ):
                    callee = entries_by_address.get(target["entry"])
                if callee is None:
                    unresolved.append({
                        "caller": caller["identity"],
                        "plan_id": call_plan.get("plan_id"),
                        "target": target,
                        "status": "target_entry_plan_missing",
                    })
                    continue

                entry_plan = callee["entry_plan"]
                candidate = _candidate_from_plan(call_plan)
                logical_width, width_authority = _logical_result_width(
                    call_plan,
                    candidate,
                    entry_plan,
                )
                arguments = _argument_chain(
                    call_plan,
                    entry_plan,
                )
                carrier = _return_carrier_evidence(
                    callee["registry"],
                    entry_plan,
                    logical_width,
                )
                if candidate.get("candidate") is True:
                    liveness = _return_liveness(
                        caller["registry"],
                        caller["entry_plan"] or {},
                        call_plan,
                        carrier,
                    )
                else:
                    liveness = {
                        "kind": (
                            "pal_abi_return_carrier_liveness_v1"
                        ),
                        "status": "not_required",
                        "carrier_live_to_return": None,
                        "intervening_carrier_writes": [],
                        "reason": (
                            "call_result_has_explicit_SSA_or_no_candidate"
                        ),
                    }
                repair = _repair_contract(
                    call_plan,
                    entry_plan,
                    arguments,
                    carrier,
                    liveness,
                    candidate,
                    logical_width,
                    width_authority,
                )
                contract_id = _contract_id(
                    call_plan.get("plan_id"),
                    entry_plan.get("plan_id"),
                )
                contract = {
                    "kind": "pal_abi_custody_chain_contract_v1",
                    "version": (
                        PAL_ABI_CUSTODY_INSPECTOR_VERSION
                    ),
                    "contract_id": contract_id,
                    "status": repair["status"],
                    "caller": caller["identity"],
                    "call": {
                        "plan_id": call_plan.get("plan_id"),
                        "op_key": call_plan.get("op_key"),
                        "op_id": call_plan.get("op_id"),
                        "block_addr": call_plan.get("block_addr"),
                        "call_address": _call_address(call_plan),
                        "dispatch_class": call_plan.get(
                            "dispatch_class"
                        ),
                        "target": target,
                    },
                    "callee": callee["identity"],
                    "target_entry_plan_id": entry_plan.get(
                        "plan_id"
                    ),
                    "argument_chain": arguments,
                    "return_chain": {
                        "candidate": candidate or None,
                        "logical_result_width_bits": logical_width,
                        "width_authority": width_authority,
                        "callee_return_contract": dict(
                            entry_plan.get("return_contract") or {}
                        ),
                        "physical_carrier": carrier,
                        "liveness": liveness,
                    },
                    "repair": repair,
                    "downstream_reinference_allowed": False,
                    "metadata_only": True,
                }
                caller["registry"][contract_id] = contract
                changed = _patch_plan_duplicates(
                    caller["registry"],
                    str(call_plan.get("plan_id")),
                    contract,
                )
                if changed == 0:
                    raise PALABICustodyError(
                        "authoritative call plan disappeared during patch"
                    )
                contracts.append(contract)
                inbound.setdefault(
                    str(entry_plan.get("plan_id")),
                    [],
                ).append(contract_id)

        # Publish inbound summaries into exact target entry icecubes.
        for entry_plan_id, contract_ids in inbound.items():
            callee = entries_by_id.get(entry_plan_id)
            if callee is None:
                continue
            summary = {
                "kind": "pal_abi_entry_inbound_custody_summary_v1",
                "version": PAL_ABI_CUSTODY_INSPECTOR_VERSION,
                "entry_plan_id": entry_plan_id,
                "inbound_contract_ids": sorted(contract_ids),
                "inbound_calls": len(contract_ids),
                "metadata_only": True,
            }
            reference = "abi_custody:entry:" + entry_plan_id
            callee["registry"][reference] = summary
            for key, value in list(callee["registry"].items()):
                if (
                    isinstance(value, dict)
                    and value.get("plan_class")
                    == "function_entry_abi_plan"
                    and str(value.get("plan_id"))
                    == entry_plan_id
                ):
                    value["abi_custody_inbound_summary_ref"] = reference
                    value["abi_custody_inbound_summary"] = summary
                    callee["registry"][key] = value

        stamped_plan_occurrences = _stamp_registry_plan_occurrences(
            cube_records
        )
        final_index, final_alias_audit, unused_final_groups = (
            _canonical_project_plan_index(
                cube_records,
                project_root=self.project_root.name,
                phase="post_custody_join",
            )
        )
        if final_index["summary"]["core_conflicts"]:
            _atomic_write_json(self.plan_index_path, final_index)
            _atomic_write_json(
                self.alias_audit_path,
                final_alias_audit,
            )
            raise PALABIPlanCoreConflict(
                "custody enrichment changed immutable ABI plan core; "
                "inspect %s" % self.alias_audit_path
            )

        argument_chains_incompatible = sum(
            item["argument_chain"].get("status")
            == "incompatible"
            for item in contracts
        )
        carrier_disagreements = sum(
            any(
                failure.get("agreement", {}).get("carrier")
                is False
                for failure in item["argument_chain"].get(
                    "failures", []
                )
            )
            for item in contracts
        )
        result_width_conflicts = sum(
            (
                item["return_chain"].get("candidate") or {}
            ).get("status")
            == "outputless_nonvoid_result_width_conflict"
            for item in contracts
        )
        return_carriers_resolved = sum(
            item["return_chain"]["physical_carrier"].get(
                "status"
            )
            == "resolved"
            for item in contracts
        )
        return_carriers_deferred = sum(
            item["return_chain"]["physical_carrier"].get(
                "status"
            )
            != "resolved"
            and (
                item["repair"].get("output_sid") is not None
                or (
                    item["return_chain"].get("candidate") or {}
                ).get("candidate") is True
            )
            for item in contracts
        )
        summary = {
            "kind": "pal_abi_custody_project_summary_v1b",
            "version": PAL_ABI_CUSTODY_INSPECTOR_VERSION,
            "canonicalizer_version": (
                PAL_ABI_PLAN_CANONICALIZER_VERSION
            ),
            "icecubes": len(cube_records),
            "entry_plans": len(entries_by_id),
            "call_plans": final_index["summary"]["call_plans"],
            "plan_occurrences": final_index["summary"][
                "plan_occurrences"
            ],
            "plan_alias_groups": final_index["summary"][
                "alias_groups"
            ],
            "plan_annotation_variant_groups": final_index[
                "summary"
            ]["annotation_variant_groups"],
            "plan_core_conflicts": final_index["summary"][
                "core_conflicts"
            ],
            "stamped_plan_occurrences": stamped_plan_occurrences,
            "internal_calls_linked": len(contracts),
            "internal_calls_unresolved": len(unresolved),
            "argument_chains_ready": sum(
                item["argument_chain"].get("status") == "ready"
                for item in contracts
            ),
            "argument_chains_incompatible": (
                argument_chains_incompatible
            ),
            "carrier_disagreements": carrier_disagreements,
            "result_width_conflicts": result_width_conflicts,
            "return_carriers_resolved": return_carriers_resolved,
            "return_carriers_deferred": return_carriers_deferred,
            "outputless_candidates": sum(
                bool(
                    (
                        item["return_chain"].get("candidate")
                        or {}
                    ).get("candidate")
                )
                for item in contracts
            ),
            "ghost_repairs_resolved": sum(
                item["repair"].get("emitter_repair_authorized")
                is True
                for item in contracts
            ),
            "ghost_repairs_deferred": sum(
                (
                    item["return_chain"].get("candidate")
                    or {}
                ).get("candidate")
                is True
                and item["repair"].get(
                    "emitter_repair_authorized"
                )
                is not True
                for item in contracts
            ),
            "ghost_repairs_conflicting": 0,
            "metadata_only": True,
            "generated_code_rewrites": 0,
            "runtime_helpers": 0,
        }
        status = _health_status(summary)
        summary["status"] = status
        final_index["custody_health"] = {
            "status": status,
            "summary": summary,
        }
        final_alias_audit["custody_health"] = {
            "status": status,
            "summary": summary,
        }
        _atomic_write_json(self.plan_index_path, final_index)
        _atomic_write_json(
            self.alias_audit_path,
            final_alias_audit,
        )

        # Stamp every touched cube and refresh both integrity layers.
        for record in cube_records:
            manifest = dict(record["cube"].get("manifest") or {})
            capabilities = list(
                manifest.get("capabilities") or []
            )
            capability = "abi_custody_cross_function_contracts"
            if capability not in capabilities:
                capabilities.append(capability)
            manifest["capabilities"] = capabilities
            manifest["abi_custody_provenance"] = {
                "version": PAL_ABI_CUSTODY_INSPECTOR_VERSION,
                "canonicalizer_version": (
                    PAL_ABI_PLAN_CANONICALIZER_VERSION
                ),
                "project_report": self.REPORT_FILENAME,
                "plan_index": self.PLAN_INDEX_FILENAME,
                "alias_audit": self.ALIAS_AUDIT_FILENAME,
                "status": status,
                "contracts_owned": sum(
                    item["caller"].get("icecube")
                    == record["path"].name
                    for item in contracts
                ),
                "inbound_contracts": len(
                    inbound.get(
                        str(
                            (record["entry_plan"] or {}).get(
                                "plan_id"
                            )
                        ),
                        [],
                    )
                ),
                "generated_code_rewrites": 0,
            }
            record["cube"]["manifest"] = manifest
            _refresh_icecube_integrity(record["cube"])
            _atomic_write_gzip_json(
                record["path"],
                record["cube"],
            )

        report = {
            "format": "pal_abi_custody_project_report",
            "schema_version": 1,
            "version": PAL_ABI_CUSTODY_INSPECTOR_VERSION,
            "canonicalizer_version": (
                PAL_ABI_PLAN_CANONICALIZER_VERSION
            ),
            "project_root": self.project_root.name,
            "status": status,
            "summary": summary,
            "plan_index": {
                "artifact": self.PLAN_INDEX_FILENAME,
                "status": final_index.get("status"),
                "summary": final_index.get("summary"),
            },
            "plan_alias_audit": {
                "artifact": self.ALIAS_AUDIT_FILENAME,
                "status": final_alias_audit.get("status"),
                "summary": final_alias_audit.get("summary"),
            },
            "contracts": contracts,
            "unresolved_internal_calls": unresolved,
            "icecubes": [
                {
                    **record["identity"],
                    "sha256": _sha256_file(record["path"]),
                }
                for record in cube_records
            ],
            "authority": {
                "caller": "PALCompute_v23c_call_site_plans",
                "callee": "PALCompute_function_entry_abi_plans",
                "machine_liveness": (
                    "PALlibrary.PALLifter.raw_machine_image"
                ),
                "publication": (
                    "PALCodeDocument.metadata_registry_frozen_icecube"
                ),
                "plan_identity": (
                    "PALABIPlanCanonicalizer_v1_immutable_plan_core"
                ),
                "project_index": self.PLAN_INDEX_FILENAME,
            },
            "acceptance_gates": {
                "generated_python_rewritten": False,
                "cfg_rewritten": False,
                "phi_rewritten": False,
                "exec_tree_rewritten": False,
                "last_call_surface_inference_used": False,
                "integrity_refreshed": True,
                "recursive_whole_icecube_plan_discovery_used": False,
                "whole_plan_object_equality_used": False,
                "annotation_aliases_collapsed": True,
                "core_conflicts_fail_closed": True,
            },
        }
        _atomic_write_json(self.report_path, report)

        if self.records is not None:
            by_name = {
                item["path"].name: item
                for item in cube_records
            }
            for function_record in self.records:
                artifacts = function_record.get("artifacts") or {}
                icecube_artifact = artifacts.get("icecube") or {}
                path_text = icecube_artifact.get("path")
                if not path_text:
                    continue
                name = Path(path_text).name
                matched = by_name.get(name)
                if matched is None:
                    continue
                icecube_artifact["sha256"] = _sha256_file(
                    matched["path"]
                )
                artifacts["icecube"] = icecube_artifact
                function_record["artifacts"] = artifacts
                owned = [
                    item
                    for item in contracts
                    if item["caller"].get("icecube") == name
                ]
                function_record["abi_custody"] = {
                    "contracts": len(owned),
                    "ghost_repairs_resolved": sum(
                        item["repair"].get(
                            "emitter_repair_authorized"
                        )
                        is True
                        for item in owned
                    ),
                    "status": (
                        "ready"
                        if all(
                            item.get("status") in (
                                "linked",
                                "resolved",
                            )
                            for item in owned
                        )
                        else "degraded"
                    ),
                }
        return report


def index_project_plans(
    project_root: os.PathLike,
    *,
    write: bool = False,
) -> Dict[str, Any]:
    """Build the registry-scoped project plan index without custody joins."""
    inspector = PALABICustodyInspector(project_root)
    cube_records = []
    for path in inspector._icecube_paths():
        cube = _read_icecube(path)
        entry = _entry_plan(cube)
        cube_records.append({
            "path": path,
            "cube": cube,
            "registry": _registry(cube),
            "entry_plan": entry,
            "identity": _function_identity(path, cube, entry),
        })
    index, audit, unused_groups = _canonical_project_plan_index(
        cube_records,
        project_root=Path(project_root).name,
        phase="diagnostic_index_only",
    )
    if write:
        _atomic_write_json(inspector.plan_index_path, index)
        _atomic_write_json(inspector.alias_audit_path, audit)
    return {
        "index": index,
        "alias_audit": audit,
    }


def inspect_project(
    project_root: os.PathLike,
    *,
    records: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return PALABICustodyInspector(
        project_root,
        records=records,
    ).run()


__all__ = [
    "PALABICustodyError",
    "PALABICustodyIntegrityError",
    "PALABICustodyInspector",
    "PAL_ABI_CUSTODY_INSPECTOR_VERSION",
    "index_project_plans",
    "inspect_project",
]
