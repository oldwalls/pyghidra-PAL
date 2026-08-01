"""Canonical immutable identity for PAL ABI plans.

PAL ABI plans are copied into several frozen metadata locations. Later stages
may attach custody, candidate, emitter, audit, and publication annotations to
those copies. This module separates the executable/transport plan core from
that mutable annotation envelope and gives both layers deterministic hashes.

The module is metadata-only. It does not rewrite a plan unless ``stamp_plan``
is called explicitly, and even then it adds only an annotation record.
"""

from __future__ import annotations

PAL_ABI_PLAN_CANONICALIZER_VERSION = "v1_immutable_plan_identity"
PAL_ABI_PLAN_IDENTITY_SCHEMA = "pal_abi_plan_immutable_identity_v1"

import argparse
import gzip
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


SUPPORTED_PLAN_CLASSES = frozenset({
    "function_entry_abi_plan",
    "call_site_abi_plan",
})

# These fields describe how or where a plan was produced, validated, enriched,
# repaired, published, or observed. They do not choose runtime carriers,
# argument ordering, target identity, result width, or control behavior.
_ANNOTATION_EXACT_KEYS = frozenset({
    "abi_custody_contract",
    "abi_custody_contract_ref",
    "abi_custody_inbound_summary",
    "abi_custody_inbound_summary_ref",
    "abi_plan_identity",
    "call_result_candidate",
    "source_call_site_abi_contract",
    "authority",
    "reason",
    "rule",
    "policy",
    "provenance",
    "warnings",
    "warning",
    "events",
    "event",
    "diagnostic",
    "diagnostics",
    "metadata_only",
    "status",
    "declared_width_authoritative",
    "version",
    "build",
    "revision",
    "timestamp",
    "created_at",
    "updated_at",
    "published_at",
    "argument_count",
    "observed_argument_sids",
    "gp_registers_used",
    "xmm_registers_used",
    "stack_slots_used",
    "argument_sid_match",
    "target_compatible",
    "external_call_abi_classification",
    "outputless_nonvoid_candidate",
    "implicit_return_carrier_candidate",
    "emission_allowed",
    "candidate_width_is_executable",
    "sibling_result_widths",
    "sibling_result_width_records",
    "call_result_evidence_status",
})

_ANNOTATION_PREFIXES = (
    "abi_custody_",
    "abi_plan_identity_",
    "emitter_",
    "holy_ghost_",
    "audit_",
    "debug_",
    "publication_",
    "published_",
    "candidate_",
    "sibling_result_",
    "repair_",
)

_ANNOTATION_SUFFIXES = (
    "_authority",
    "_reason",
    "_policy",
    "_provenance",
    "_diagnostic",
    "_diagnostics",
    "_warnings",
    "_events",
    "_status",
    "_compatible",
    "_match",
)


class PALABIPlanCanonicalizationError(RuntimeError):
    """Base error for invalid or contradictory ABI-plan identity."""


class PALABIPlanShapeError(PALABIPlanCanonicalizationError):
    """The supplied object is not a supported PAL ABI plan."""


class PALABIPlanCoreConflict(PALABIPlanCanonicalizationError):
    """Two occurrences share an identity but disagree in immutable core."""


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise PALABIPlanShapeError(
                "ABI plan identity cannot contain NaN or infinity"
            )
        return value
    if isinstance(value, bytes):
        return {"kind": "bytes", "hex": value.hex()}
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in sorted(
                value.items(),
                key=lambda pair: str(pair[0]),
            )
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted(
            (_json_safe(item) for item in value),
            key=lambda item: canonical_json_text(item),
        )
    return str(value)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _json_safe(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("ascii")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _json_pointer_escape(value: Any) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _annotation_key(key: Any) -> bool:
    text = str(key)
    lowered = text.lower()
    if lowered in _ANNOTATION_EXACT_KEYS:
        return True
    if any(lowered.startswith(prefix) for prefix in _ANNOTATION_PREFIXES):
        return True
    if any(lowered.endswith(suffix) for suffix in _ANNOTATION_SUFFIXES):
        return True
    return False


def _split_value(
    value: Any,
    pointer: str,
    annotations: Dict[str, Any],
) -> Any:
    if isinstance(value, Mapping):
        core: Dict[str, Any] = {}
        for raw_key, raw_item in sorted(
            value.items(),
            key=lambda pair: str(pair[0]),
        ):
            key = str(raw_key)
            child_pointer = pointer + "/" + _json_pointer_escape(key)
            if _annotation_key(key):
                annotations[child_pointer] = _json_safe(raw_item)
                continue
            core[key] = _split_value(
                raw_item,
                child_pointer,
                annotations,
            )
        return core
    if isinstance(value, (list, tuple)):
        return [
            _split_value(
                item,
                pointer + "/" + str(index),
                annotations,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, set):
        values = sorted(
            value,
            key=lambda item: canonical_json_text(_json_safe(item)),
        )
        return [
            _split_value(
                item,
                pointer + "/" + str(index),
                annotations,
            )
            for index, item in enumerate(values)
        ]
    return _json_safe(value)


def validate_plan(plan: Mapping[str, Any]) -> Tuple[str, str]:
    if not isinstance(plan, Mapping):
        raise PALABIPlanShapeError("ABI plan must be a mapping")
    plan_class = str(plan.get("plan_class") or "")
    plan_id = str(plan.get("plan_id") or "")
    if plan_class not in SUPPORTED_PLAN_CLASSES:
        raise PALABIPlanShapeError(
            "unsupported ABI plan_class %r" % plan_class
        )
    if not plan_id:
        raise PALABIPlanShapeError("ABI plan has no plan_id")
    return plan_class, plan_id


def split_plan(
    plan: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return immutable core and JSON-pointer keyed annotation envelope."""

    validate_plan(plan)
    annotations: Dict[str, Any] = {}
    core = _split_value(plan, "", annotations)
    if not isinstance(core, dict):
        raise PALABIPlanShapeError("canonical ABI plan core is not a mapping")

    # The two identity anchors must never be removable by annotation policy.
    plan_class, plan_id = validate_plan(plan)
    core["plan_class"] = plan_class
    core["plan_id"] = plan_id
    return core, {
        key: annotations[key]
        for key in sorted(annotations)
    }


def canonicalize_plan(
    plan: Mapping[str, Any],
    *,
    source: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a detached identity record for one ABI plan occurrence."""

    plan_class, plan_id = validate_plan(plan)
    core, annotations = split_plan(plan)
    record = {
        "format": "pal_abi_plan_identity_record",
        "schema_version": 1,
        "canonicalizer_version": PAL_ABI_PLAN_CANONICALIZER_VERSION,
        "identity_schema": PAL_ABI_PLAN_IDENTITY_SCHEMA,
        "plan_class": plan_class,
        "plan_id": plan_id,
        "plan_core_sha256": sha256_json(core),
        "plan_annotation_sha256": sha256_json(annotations),
        "core": core,
        "annotations": annotations,
        "annotation_count": len(annotations),
        "downstream_reinference_allowed": False,
    }
    if source:
        record["source"] = _json_safe(dict(source))
    return record


def stamp_plan(
    plan: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return a copy carrying a non-core canonical identity annotation."""

    unstamped = dict(plan)
    unstamped.pop("abi_plan_identity", None)
    record = canonicalize_plan(unstamped)
    stamped = dict(unstamped)
    stamped["abi_plan_identity"] = {
        "schema": PAL_ABI_PLAN_IDENTITY_SCHEMA,
        "canonicalizer_version": PAL_ABI_PLAN_CANONICALIZER_VERSION,
        "plan_class": record["plan_class"],
        "plan_id": record["plan_id"],
        "plan_core_sha256": record["plan_core_sha256"],
        "plan_annotation_sha256_before_stamp": (
            record["plan_annotation_sha256"]
        ),
        "identity_authority": (
            "PALABIPlanCanonicalizer_v1_immutable_plan_core"
        ),
        "downstream_reinference_allowed": False,
    }
    return stamped


def _diff_values(
    left: Any,
    right: Any,
    pointer: str = "",
    out: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    if out is None:
        out = []
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        for key in sorted(set(left) | set(right), key=str):
            child = pointer + "/" + _json_pointer_escape(key)
            if key not in left:
                out.append({
                    "path": child,
                    "left": {"missing": True},
                    "right": _json_safe(right[key]),
                })
            elif key not in right:
                out.append({
                    "path": child,
                    "left": _json_safe(left[key]),
                    "right": {"missing": True},
                })
            else:
                _diff_values(left[key], right[key], child, out)
        return out
    if isinstance(left, list) and isinstance(right, list):
        count = max(len(left), len(right))
        for index in range(count):
            child = pointer + "/" + str(index)
            if index >= len(left):
                out.append({
                    "path": child,
                    "left": {"missing": True},
                    "right": _json_safe(right[index]),
                })
            elif index >= len(right):
                out.append({
                    "path": child,
                    "left": _json_safe(left[index]),
                    "right": {"missing": True},
                })
            else:
                _diff_values(left[index], right[index], child, out)
        return out
    if _json_safe(left) != _json_safe(right):
        out.append({
            "path": pointer or "/",
            "left": _json_safe(left),
            "right": _json_safe(right),
        })
    return out


def compare_plans(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> Dict[str, Any]:
    """Classify two plan occurrences as duplicate, variant, or conflict."""

    left_record = canonicalize_plan(left)
    right_record = canonicalize_plan(right)

    identity_matches = (
        left_record["plan_class"] == right_record["plan_class"]
        and left_record["plan_id"] == right_record["plan_id"]
    )
    if not identity_matches:
        classification = "identity_mismatch"
    elif (
        left_record["plan_core_sha256"]
        != right_record["plan_core_sha256"]
    ):
        classification = "core_conflict"
    elif (
        left_record["plan_annotation_sha256"]
        != right_record["plan_annotation_sha256"]
    ):
        classification = "annotation_variant"
    else:
        classification = "exact_duplicate"

    return {
        "kind": "pal_abi_plan_comparison_v1",
        "classification": classification,
        "identity_matches": identity_matches,
        "plan_class": (
            left_record["plan_class"]
            if identity_matches else None
        ),
        "plan_id": (
            left_record["plan_id"]
            if identity_matches else None
        ),
        "left_core_sha256": left_record["plan_core_sha256"],
        "right_core_sha256": right_record["plan_core_sha256"],
        "left_annotation_sha256": (
            left_record["plan_annotation_sha256"]
        ),
        "right_annotation_sha256": (
            right_record["plan_annotation_sha256"]
        ),
        "core_differences": _diff_values(
            left_record["core"],
            right_record["core"],
        ),
        "annotation_differences": _diff_values(
            left_record["annotations"],
            right_record["annotations"],
        ),
    }


def iter_plan_occurrences(
    value: Any,
) -> Iterator[Dict[str, Any]]:
    """Yield every ABI-plan-shaped occurrence with its JSON pointer."""

    seen: set = set()

    def walk(item: Any, pointer: str) -> Iterator[Dict[str, Any]]:
        if isinstance(item, (dict, list, tuple)):
            marker = id(item)
            if marker in seen:
                return
            seen.add(marker)
        if isinstance(item, Mapping):
            if (
                item.get("plan_class") in SUPPORTED_PLAN_CLASSES
                and item.get("plan_id") not in (None, "")
            ):
                yield {
                    "json_pointer": pointer or "/",
                    "plan_class": str(item.get("plan_class")),
                    "plan_id": str(item.get("plan_id")),
                    "plan": dict(item),
                }
            for key, child in item.items():
                yield from walk(
                    child,
                    pointer + "/" + _json_pointer_escape(key),
                )
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                yield from walk(
                    child,
                    pointer + "/" + str(index),
                )

    yield from walk(value, "")


def audit_plan_aliases(
    value: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Audit all recursively visible plan aliases without changing input."""

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for occurrence in iter_plan_occurrences(value):
        source = {
            "source_name": source_name,
            "json_pointer": occurrence["json_pointer"],
        }
        record = canonicalize_plan(
            occurrence["plan"],
            source=source,
        )
        groups[
            (record["plan_class"], record["plan_id"])
        ].append(record)

    plan_records: List[Dict[str, Any]] = []
    core_conflicts = 0
    annotation_variant_groups = 0
    exact_duplicate_groups = 0

    for (plan_class, plan_id), records in sorted(groups.items()):
        core_hashes = sorted({
            item["plan_core_sha256"]
            for item in records
        })
        annotation_hashes = sorted({
            item["plan_annotation_sha256"]
            for item in records
        })
        if len(core_hashes) > 1:
            classification = "core_conflict"
            core_conflicts += 1
        elif len(annotation_hashes) > 1:
            classification = "annotation_variants"
            annotation_variant_groups += 1
        else:
            classification = "exact_duplicates"
            exact_duplicate_groups += 1

        plan_records.append({
            "plan_class": plan_class,
            "plan_id": plan_id,
            "classification": classification,
            "occurrence_count": len(records),
            "core_fingerprints": core_hashes,
            "annotation_fingerprints": annotation_hashes,
            "occurrences": [
                {
                    "source": item.get("source"),
                    "plan_core_sha256": item["plan_core_sha256"],
                    "plan_annotation_sha256": (
                        item["plan_annotation_sha256"]
                    ),
                    "annotation_count": item["annotation_count"],
                }
                for item in records
            ],
        })

    return {
        "format": "pal_abi_plan_alias_audit",
        "schema_version": 1,
        "canonicalizer_version": PAL_ABI_PLAN_CANONICALIZER_VERSION,
        "identity_schema": PAL_ABI_PLAN_IDENTITY_SCHEMA,
        "source_name": source_name,
        "status": "conflict" if core_conflicts else "clean",
        "summary": {
            "plan_identities": len(plan_records),
            "plan_occurrences": sum(
                item["occurrence_count"]
                for item in plan_records
            ),
            "core_conflicts": core_conflicts,
            "annotation_variant_groups": annotation_variant_groups,
            "exact_duplicate_groups": exact_duplicate_groups,
        },
        "plans": plan_records,
        "metadata_only": True,
        "generated_code_rewrites": 0,
    }


def _read_json(path: Path) -> Any:
    opener = gzip.open if str(path).lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit immutable PAL ABI-plan identity and annotation aliases."
        )
    )
    parser.add_argument("json_path")
    parser.add_argument(
        "--output",
        help="Write audit JSON to this path.",
    )
    parser.add_argument(
        "--fail-on-core-conflict",
        action="store_true",
    )
    args = parser.parse_args(argv)

    source = Path(args.json_path).resolve()
    payload = _read_json(source)
    report = audit_plan_aliases(
        payload,
        source_name=source.name,
    )
    text = json.dumps(
        report,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"

    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(
            output.name + ".tmp.%d" % os.getpid()
        )
        try:
            temporary.write_text(text, encoding="utf-8")
            os.replace(temporary, output)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    else:
        print(text, end="")

    conflicts = int(
        (report.get("summary") or {}).get("core_conflicts") or 0
    )
    return 2 if args.fail_on_core_conflict and conflicts else 0


__all__ = [
    "PAL_ABI_PLAN_CANONICALIZER_VERSION",
    "PAL_ABI_PLAN_IDENTITY_SCHEMA",
    "SUPPORTED_PLAN_CLASSES",
    "PALABIPlanCanonicalizationError",
    "PALABIPlanShapeError",
    "PALABIPlanCoreConflict",
    "canonical_json_bytes",
    "canonical_json_text",
    "sha256_json",
    "validate_plan",
    "split_plan",
    "canonicalize_plan",
    "stamp_plan",
    "compare_plans",
    "iter_plan_occurrences",
    "audit_plan_aliases",
]


if __name__ == "__main__":
    raise SystemExit(main())
