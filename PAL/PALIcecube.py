# ============================================================
# PAL ICECUBE
# BUILD: icecube_v4_source_machine_c_asm_provenance
# Deterministic bridge from live PyGhidra PAL state to a frozen UI artifact
# ============================================================

import argparse
import gzip
import hashlib
import json
import os
import sys

PAL_EXEC_ROOT = os.path.dirname(os.path.abspath(__file__))
if PAL_EXEC_ROOT not in sys.path:
    sys.path.insert(0, PAL_EXEC_ROOT)

from PALCodeDocument import PALCodeDocument
from PALHumanizer import (
    HUMANIZER_VERSION,
    PALFunctionNameRegistry,
    build_variable_alias_contracts,
    function_identity,
)


ICECUBE_FORMAT = "pal_icecube"
ICECUBE_SCHEMA_VERSION = 2
ICECUBE_SUPPORTED_SCHEMA_VERSIONS = (1, 2)
ABI_J_VERSION = "abi_j_v1_logical_physical_provenance"
HUMANIZER_ICECUBE_VERSION = "icecube_v3_cognitive_name_provenance"
SOURCE_MACHINE_VERSION = "source_machine_v1_c_and_block_asm"


def _canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _dict(value):
    return dict(value) if isinstance(value, dict) else {}


def _list(value):
    return list(value) if isinstance(value, (list, tuple)) else []


def _first_attr(owner, names, default=None):
    if owner is None:
        return default
    for name in names:
        value = getattr(owner, name, None)
        if value not in (None, {}, []):
            return value
    return default


def _register(document, reference, value):
    document.metadata.register(
        reference, document.freeze_metadata_value(value)
    )
    return reference


def _register_name(value):
    if isinstance(value, dict):
        return value.get("name") or value.get("register_name") or value.get("repr")
    return value


def _register_width_bits(value):
    value = _dict(value)
    width = value.get("width_bits")
    if isinstance(width, int) and width > 0:
        return width
    size = value.get("size_bytes")
    return size * 8 if isinstance(size, int) and size > 0 else None


def _declared_parameters(signature):
    signature = _dict(signature)
    for key in ("parameters", "params", "fixed_parameters"):
        records = signature.get(key)
        if isinstance(records, (list, tuple)):
            return [dict(item) for item in records if isinstance(item, dict)]
    return []


def _compact_logical_signature(document, entry_plan, pal_function=None):
    """Freeze the callable namespace without deriving it from carrier order."""
    entry_plan = _dict(entry_plan)
    signature = _dict(document.metadata.resolve("function:signature", {}))
    callable_order = _list(_first_attr(
        pal_function, ("callable_parameter_order",), []
    ))
    fixed_source = _list(entry_plan.get("fixed_arguments")) or callable_order
    declared = _declared_parameters(signature)

    fixed = []
    for fallback_ordinal, raw in enumerate(fixed_source):
        item = _dict(raw)
        ordinal = item.get("ordinal")
        if not isinstance(ordinal, int):
            ordinal = fallback_ordinal
        declaration = declared[ordinal] if ordinal < len(declared) else {}
        bindings = [
            _dict(value)
            for value in _list(item.get("physical_carrier_bindings"))
        ]
        fixed.append({
            "ordinal": ordinal,
            "name": item.get("name") or declaration.get("name"),
            "logical_name": item.get("logical_name"),
            "logical_ordinal": item.get("logical_ordinal"),
            "source_sid": item.get("source_sid"),
            "physical_sids": [
                str(sid) for sid in _list(item.get("physical_sids"))
                if sid is not None
            ],
            "declared_type": (
                declaration.get("datatype")
                or declaration.get("type")
                or declaration.get("data_type")
            ),
            "declared_width_bits": (
                declaration.get("width_bits")
                or declaration.get("size_bits")
            ),
            "binding_status": item.get("binding_status") or item.get("status"),
            "physical_binding_count": len(bindings),
            "authority": item.get("authority") or item.get("selection_source"),
        })

    variadic_contract = _dict(_first_attr(
        pal_function, ("variadic_contract",), {}
    ))
    al_plan = _dict(entry_plan.get("variadic_al"))
    save_area = _dict(entry_plan.get("variadic_register_save_area"))
    if variadic_contract:
        declared_variadic = variadic_contract.get("declared_variadic")
        effective_variadic = variadic_contract.get("effective_variadic")
        machine_evidence = variadic_contract.get("machine_variadic_evidence")
        variadic_status = variadic_contract.get("status")
        variadic_authority = variadic_contract.get("authority")
    else:
        declared_variadic = None
        effective_variadic = bool(
            al_plan.get("required") or save_area.get("required")
        )
        machine_evidence = True if effective_variadic else None
        variadic_status = (
            "entry_plan_requires_variadic_context"
            if effective_variadic else "not_required_by_entry_plan"
        )
        variadic_authority = (
            al_plan.get("authority") or save_area.get("authority")
        )

    return_contract = _dict(entry_plan.get("return_contract"))
    return {
        "kind": "pal_logical_function_signature_abi_j",
        "version": ABI_J_VERSION,
        "function": entry_plan.get("function") or document.function_name,
        "entry": entry_plan.get("entry"),
        "entry_plan_id": entry_plan.get("plan_id"),
        "entry_plan_status": entry_plan.get("status"),
        "prototype_authority": _dict(entry_plan.get("prototype_authority")),
        "callable_signature_status": entry_plan.get(
            "callable_signature_status"
        ),
        "fixed_parameters": fixed,
        "fixed_parameter_count": len(fixed),
        "fixed_parameter_materialization": entry_plan.get(
            "fixed_argument_materialization"
        ),
        "variadic": {
            "declared": declared_variadic,
            "machine_evidence": machine_evidence,
            "effective": effective_variadic,
            "status": variadic_status,
            "fixed_parameter_count_status": variadic_contract.get(
                "fixed_parameter_count_inference_status"
            ),
            "python_interface_policy": variadic_contract.get(
                "python_interface_policy"
            ),
            "authority": variadic_authority,
        },
        "return": {
            "status": return_contract.get("status"),
            "no_return": bool(
                return_contract.get("no_return")
                or entry_plan.get("no_return")
            ),
            "declared_return": return_contract.get("declared_return"),
            "declared_width_bits": return_contract.get("declared_width_bits"),
            "effective_result_width_bits": return_contract.get(
                "effective_result_width_bits"
            ),
            "authority": return_contract.get("authority"),
        },
        "namespace_policy": (
            "logical_callable_identity_is_independent_of_physical_carrier_order"
        ),
        "authority": entry_plan.get("authority"),
    }


def _compact_physical_binding(binding, logical_by_sid=None):
    binding = _dict(binding)
    logical_by_sid = logical_by_sid or {}
    sid = binding.get("sid") or binding.get("source_sid")
    sid_text = str(sid) if sid is not None else None
    owner = _dict(binding.get("owner"))
    return {
        "sid": sid_text,
        "logical_name": logical_by_sid.get(sid_text),
        "bank": binding.get("bank") or binding.get("carrier_bank"),
        "index": binding.get("index") if binding.get("index") is not None
        else binding.get("carrier_index"),
        "carrier_kind": binding.get("carrier_kind"),
        "register": _register_name(binding.get("register")),
        "stack_slot": binding.get("stack_slot"),
        "width_bits": binding.get("width_bits") or binding.get(
            "source_width_bits"
        ),
        "canonical_alias": binding.get("canonical_alias"),
        "owner_namespace": binding.get("owner_namespace") or owner.get(
            "namespace"
        ),
        "owner_role": binding.get("owner_role") or owner.get("role"),
        "owner_resolved": owner.get("resolved"),
        "authority": binding.get("authority"),
    }


def _compact_physical_map(document, entry_plan, logical_signature):
    """Freeze register/stack custody exactly as declared by ABI-C/D."""
    entry_plan = _dict(entry_plan)
    logical_by_sid = {}
    for parameter in _list(logical_signature.get("fixed_parameters")):
        for sid in _list(parameter.get("physical_sids")):
            logical_by_sid[str(sid)] = parameter.get("name")

    bindings = []
    seen = set()

    def append_binding(value):
        compact = _compact_physical_binding(value, logical_by_sid)
        key = (
            compact.get("sid"), compact.get("bank"),
            compact.get("register"), compact.get("stack_slot"),
        )
        if key in seen:
            return
        seen.add(key)
        bindings.append(compact)

    save_area = _dict(entry_plan.get("variadic_register_save_area"))
    for slot in _list(save_area.get("slots")):
        append_binding(slot)
    for parameter in _list(entry_plan.get("fixed_arguments")):
        for binding in _list(_dict(parameter).get("physical_carrier_bindings")):
            append_binding(binding)
    overflow = _dict(entry_plan.get("overflow_argument_area"))
    for binding in _list(overflow.get("observed_stack_carriers")):
        append_binding(binding)

    implicit_inputs = []
    for item in _list(entry_plan.get("implicit_inputs")):
        item = _dict(item)
        register = item.get("register")
        implicit_inputs.append({
            "sid": item.get("sid"),
            "canonical_alias": item.get("canonical_alias"),
            "role": item.get("role"),
            "custody_class": item.get("custody_class"),
            "register": _register_name(register),
            "width_bits": item.get("width_bits") or _register_width_bits(
                register
            ),
            "source": item.get("source"),
            "status": item.get("status"),
            "callable_argument": False,
            "authority": item.get("authority"),
        })

    al_plan = _dict(entry_plan.get("variadic_al"))
    al_inputs = _list(al_plan.get("inputs"))
    al_input = next((
        _dict(item) for item in implicit_inputs
        if item.get("role") == "variadic_xmm_register_count"
    ), None)
    if al_input is None and al_inputs:
        raw = _dict(al_inputs[0])
        al_input = {
            "sid": raw.get("sid"),
            "canonical_alias": raw.get("canonical_alias"),
            "role": raw.get("role"),
            "register": _register_name(raw.get("register")),
            "width_bits": raw.get("width_bits"),
            "authority": raw.get("authority"),
        }

    return_contract = _dict(entry_plan.get("return_contract"))
    return {
        "kind": "pal_physical_abi_carrier_map_abi_j",
        "version": ABI_J_VERSION,
        "function": entry_plan.get("function") or document.function_name,
        "entry_plan_id": entry_plan.get("plan_id"),
        "backend": _dict(entry_plan.get("abi_backend")),
        "incoming_assignments": bindings,
        "incoming_assignment_count": len(bindings),
        "implicit_inputs": implicit_inputs,
        "implicit_al": {
            "present": al_input is not None,
            "required": bool(al_plan.get("required")),
            "status": al_plan.get("status"),
            "source": al_plan.get("source"),
            "sid": (al_input or {}).get("sid"),
            "canonical_alias": (al_input or {}).get("canonical_alias"),
            "register": (al_input or {}).get("register") or "AL",
            "width_bits": (al_input or {}).get("width_bits") or 8,
            "authority": al_plan.get("authority") or (
                al_input or {}
            ).get("authority"),
        },
        "register_save_area": {
            "required": bool(save_area.get("required")),
            "status": save_area.get("status"),
            "gp_slot_count": len(_list(save_area.get("gp_slots"))),
            "sse_slot_count": len(_list(save_area.get("sse_slots"))),
            "source": save_area.get("source"),
            "authority": save_area.get("authority"),
        },
        "overflow_argument_area": {
            "required": bool(overflow.get("required")),
            "status": overflow.get("status"),
            "source": overflow.get("source"),
            "observed_stack_carrier_count": len(_list(
                overflow.get("observed_stack_carriers")
            )),
            "offset_inference_allowed": overflow.get(
                "offset_inference_allowed"
            ),
            "authority": overflow.get("authority"),
        },
        "frame_base": _dict(entry_plan.get("frame_base")),
        "tls_base": _dict(entry_plan.get("tls_base")),
        "return_carrier": {
            "status": return_contract.get("status"),
            "no_return": bool(return_contract.get("no_return")),
            "effective_result_width_bits": return_contract.get(
                "effective_result_width_bits"
            ),
            "carrier_pieces": _list(return_contract.get("carrier_pieces")),
            "return_storage": return_contract.get("return_storage"),
            "authority": return_contract.get("authority"),
        },
        "reinference_allowed": False,
        "authority": entry_plan.get("authority"),
    }


def _compact_call_plan(plan):
    plan = _dict(plan)
    target = _dict(plan.get("target"))
    al = _dict(plan.get("caller_variadic_al"))
    result = _dict(plan.get("return_carrier_contract")) or _dict(
        plan.get("result_contract")
    )
    arguments = []
    for item in _list(plan.get("arguments")):
        item = _dict(item)
        arguments.append({
            "index": item.get("index"),
            "source_sid": item.get("source_sid"),
            "source_name": item.get("source_name"),
            "source_width_bits": item.get("source_width_bits"),
            "argument_class": item.get("argument_class"),
            "parameter_region": item.get("parameter_region"),
            "carrier_kind": item.get("carrier_kind"),
            "carrier": _register_name(item.get("carrier")),
            "stack_slot": item.get("stack_slot"),
            "constant": item.get("constant"),
            "constant_value": item.get("constant_value"),
            "authority": item.get("authority") or item.get(
                "classification_authority"
            ),
        })
    return {
        "kind": "pal_call_site_argument_plan_abi_j",
        "version": ABI_J_VERSION,
        "plan_id": plan.get("plan_id"),
        "op_key": plan.get("op_key"),
        "op_id": plan.get("op_id"),
        "block_addr": plan.get("block_addr"),
        "status": plan.get("status"),
        "dispatch_class": plan.get("dispatch_class"),
        "dispatch_policy": plan.get("dispatch_policy"),
        "target": {
            "name": target.get("name"),
            "entry": target.get("entry"),
            "resolved": target.get("resolved"),
            "external": target.get("external"),
            "thunk": target.get("thunk"),
            "variadic": target.get("variadic"),
            "fixed_parameter_count": target.get("fixed_parameter_count"),
            "calling_convention": target.get("calling_convention"),
            "entry_plan_lookup_key": target.get("entry_plan_lookup_key"),
        },
        "arguments": arguments,
        "argument_count": len(arguments),
        "carrier_allocation_status": plan.get("carrier_allocation_status"),
        "caller_variadic_al": {
            "required": bool(al.get("required")),
            "value": al.get("value"),
            "destination": al.get("destination"),
            "authority": al.get("authority"),
        },
        "target_compatibility_status": plan.get(
            "target_compatibility_status"
        ),
        "result": {
            "status": result.get("status"),
            "width_bits": result.get("effective_result_width_bits"),
            "output_sid": result.get("output_sid"),
            "carrier_pieces": _list(result.get("carrier_pieces")),
            "no_return": bool(result.get("no_return") or plan.get("no_return")),
            "authority": result.get("authority"),
        },
        "external_call_classification": _dict(
            plan.get("external_call_abi_classification")
        ),
        "reinference_allowed": False,
        "authority": plan.get("authority"),
    }


def publish_abi_j_provenance(document, pal_function=None):
    """
    Publish compact F3 records from frozen ABI-C/D/F truth.

    This function consumes plans only.  It never examines emitted text, legacy
    parameter names, or expression spelling to recover carrier placement.
    """
    if not isinstance(document, PALCodeDocument):
        raise TypeError("ABI-J provenance requires a PALCodeDocument")

    entry_plan = _dict(document.metadata.resolve("abi:entry_plan", {}))
    if not entry_plan:
        entry_plan = _dict(_first_attr(pal_function, (
            "phi_function_entry_abi_plan", "function_entry_abi_plan"
        ), {}))

    call_plans = {}
    for reference, value in document.metadata.items():
        if str(reference).startswith("abi:call:") and isinstance(value, dict):
            plan = dict(value)
            key = plan.get("plan_id") or reference[len("abi:call:"):]
            call_plans[str(key)] = plan
    live_calls = _first_attr(pal_function, (
        "phi_call_site_abi_plans_by_op", "call_site_abi_plans_by_op"
    ), {})
    if isinstance(live_calls, dict):
        for value in live_calls.values():
            if not isinstance(value, dict):
                continue
            key = value.get("plan_id") or value.get("op_key")
            if key is not None:
                call_plans[str(key)] = dict(value)

    warnings = []
    if not entry_plan:
        warnings.append({
            "kind": "icecube_abi_j_missing_entry_plan",
            "function": document.function_name,
            "reason": "ABI_D_entry_plan_not_present_in_frozen_metadata",
        })

    logical = _compact_logical_signature(
        document, entry_plan, pal_function=pal_function
    )
    physical = _compact_physical_map(document, entry_plan, logical)
    logical_ref = _register(document, "abi_j:logical_signature", logical)
    physical_ref = _register(document, "abi_j:physical_carrier_map", physical)

    call_refs = []
    call_refs_by_op = {}
    call_refs_by_plan = {}
    for key in sorted(call_plans):
        compact = _compact_call_plan(call_plans[key])
        plan_id = compact.get("plan_id") or key
        reference = "abi_j:call:%s" % str(plan_id)
        _register(document, reference, compact)
        call_refs.append(reference)
        call_refs_by_plan[str(plan_id)] = reference
        op_key = compact.get("op_key")
        if op_key is not None:
            alias = "abi_j:call_op:%s" % str(op_key)
            _register(document, alias, compact)
            call_refs_by_op[str(op_key)] = reference

    index = {
        "kind": "pal_abi_provenance_index_abi_j",
        "version": ABI_J_VERSION,
        "active": bool(entry_plan),
        "function": document.function_name,
        "entry_plan_id": entry_plan.get("plan_id"),
        "logical_signature_ref": logical_ref,
        "physical_carrier_map_ref": physical_ref,
        "call_site_refs": call_refs,
        "call_site_refs_by_plan_id": call_refs_by_plan,
        "call_site_refs_by_op_key": call_refs_by_op,
        "fixed_parameters": logical.get("fixed_parameter_count"),
        "effective_variadic": _dict(logical.get("variadic")).get("effective"),
        "incoming_assignments": physical.get("incoming_assignment_count"),
        "implicit_al_present": _dict(physical.get("implicit_al")).get("present"),
        "call_site_plans": len(call_refs),
        "warnings": warnings,
        "acceptance_gates": {
            "logical_function_signature_frozen": bool(logical_ref),
            "physical_abi_carrier_map_frozen": bool(physical_ref),
            "all_call_site_plans_indexed": len(call_refs) == len(call_plans),
            "implicit_al_explicitly_represented": (
                not bool(entry_plan) or "implicit_al" in physical
            ),
            "return_carrier_explicitly_represented": (
                not bool(entry_plan) or "return_carrier" in physical
            ),
            "carrier_placement_text_reinference": False,
            "readable_projection_mutated": False,
        },
        "rule": (
            "freeze_logical_signature_and_physical_carriers_as_parallel_"
            "inspectable_provenance_without_readable_code_pollution"
        ),
    }
    _register(document, "abi_j:index", index)
    return index


def _coerce_function_registry(value):
    if isinstance(value, PALFunctionNameRegistry):
        return value
    if isinstance(value, dict):
        return PALFunctionNameRegistry(value)
    return None


def publish_humanizer_provenance(
    document, pal_function=None, function_registry=None
):
    """Freeze name projections while leaving every PAL identity untouched."""
    if not isinstance(document, PALCodeDocument):
        raise TypeError("humanizer provenance requires a PALCodeDocument")

    registry = _coerce_function_registry(function_registry)
    if registry is None:
        registry = _coerce_function_registry(_first_attr(pal_function, (
            "function_name_registry", "project_function_name_registry",
        ), None))
    if registry is None:
        registry = _coerce_function_registry(document.metadata.resolve(
            "humanizer:function_registry", None
        ))

    entry_plan = _dict(document.metadata.resolve("abi:entry_plan", {}))
    entry = entry_plan.get("entry")
    function_record = {
        "name": document.function_name,
        "qualified_name": document.function_name,
        "entry": entry if isinstance(entry, int) else None,
        "entry_hex": hex(entry) if isinstance(entry, int) else None,
        "external": False,
    }
    registry_scope = "project_global"
    if registry is None:
        # Detached legacy icecubes have no manifest.  Give them a complete but
        # explicitly provisional one-function registry; TermUI replaces it
        # with the project registry as soon as the manifest is available.
        registry = PALFunctionNameRegistry.from_manifest(
            [function_record],
            program={"name": "detached:%s" % document.function_name},
        )
        registry_scope = "detached_provisional"
    else:
        existing_id, unused_existing = registry.find(
            entry=function_record.get("entry"), name=document.function_name
        )
        if existing_id is None:
            registry.reconcile([function_record])

    function_id, function_contract = registry.find(
        entry=function_record.get("entry"), name=document.function_name
    )
    if function_id is None:
        function_id = function_identity(
            function_record, registry.program_identity
        )
        function_contract = registry.record(function_id) or {}

    variables = []
    for reference, value in document.metadata.items():
        if not str(reference).startswith("variable:"):
            continue
        if not isinstance(value, dict):
            continue
        sid = str(reference).split(":", 1)[1]
        variable = dict(value)
        variable.setdefault("sid", sid)
        variables.append(variable)

    reserved_function_names = set()
    for record in registry.records.values():
        reserved_function_names.update(
            str(value) for value in (
                record.get("original_name"), record.get("generated_name"),
                record.get("operator_name"), record.get("active_name"),
            ) if value
        )
    contracts, inventory = build_variable_alias_contracts(
        variables,
        function_id=function_id,
        operator_aliases=getattr(document, "operator_aliases", {}),
        reserved_names=reserved_function_names,
    )
    quarantined_aliases = []
    for conflict in list(inventory.get("operator_alias_conflicts", []) or []):
        sid = str(conflict.get("sid") or "")
        alias = getattr(document, "operator_aliases", {}).pop(sid, None)
        item = dict(conflict)
        item["quarantined_alias"] = alias
        item["ground_truth_mutated"] = False
        quarantined_aliases.append(item)
    if quarantined_aliases:
        _register(
            document,
            "humanizer:quarantined_operator_aliases",
            quarantined_aliases,
        )

    for sid, contract in contracts.items():
        _register(document, "alias:variable:%s" % sid, contract)
        reference = "variable:%s" % sid
        variable = document.metadata.resolve(reference, None)
        if isinstance(variable, dict):
            variable = dict(variable)
            variable["human_alias_contract"] = contract
            _register(document, reference, variable)

    function_contract = dict(function_contract or {})
    function_contract.update({
        "registry_scope": registry_scope,
        "registry_program_identity": registry.program_identity,
        "registry_revision": registry.revision,
        "immutable_function_id": function_id,
        "identity_mutated": False,
    })
    _register(document, "humanizer:function", function_contract)
    _register(document, "humanizer:variables", inventory)
    _register(document, "humanizer:function_registry", registry.as_dict())
    index = {
        "kind": "pal_humanizer_provenance_index_v1",
        "version": HUMANIZER_VERSION,
        "function_id": function_id,
        "function_ref": "humanizer:function",
        "variable_inventory_ref": "humanizer:variables",
        "function_registry_ref": "humanizer:function_registry",
        "registry_scope": registry_scope,
        "variable_contracts": len(contracts),
        "eligible_variables": inventory.get("eligible", 0),
        "excluded_semantic_variables": inventory.get("excluded", 0),
        "generated_collisions_resolved": inventory.get(
            "generated_collisions_resolved", 0
        ),
        "operator_alias_conflicts": len(
            inventory.get("operator_alias_conflicts", []) or []
        ),
        "quarantined_operator_aliases": len(quarantined_aliases),
        "acceptance_gates": {
            "function_identity_immutable": True,
            "ssa_identities_immutable": True,
            "generated_names_unique": bool(
                inventory.get("acceptance_gates", {}).get(
                    "generated_aliases_unique", False
                )
            ),
            "semantic_names_excluded": bool(
                inventory.get("acceptance_gates", {}).get(
                    "semantic_names_not_humanized", False
                )
            ),
            "operator_collisions_quarantined": (
                len(quarantined_aliases) == len(
                    inventory.get("operator_alias_conflicts", []) or []
                )
            ),
        },
        "rule": (
            "freeze_name_views_over_function_entry_and_SSA_identity"
        ),
    }
    _register(document, "humanizer:index", index)
    return index


def debug_dump_abi_j_provenance(
    document, pal_function=None, include_calls=True, include_details=False
):
    """Development-side proof that the frozen ABI-J views are complete."""
    index = publish_abi_j_provenance(
        document, pal_function=pal_function
    )
    logical = document.metadata.resolve("abi_j:logical_signature", {}) or {}
    physical = document.metadata.resolve(
        "abi_j:physical_carrier_map", {}
    ) or {}
    inventory = {
        "kind": "pal_icecube_abi_j_inventory",
        "version": ABI_J_VERSION,
        "active": index.get("active"),
        "function": index.get("function"),
        "entry_plan_id": index.get("entry_plan_id"),
        "fixed_parameters": index.get("fixed_parameters"),
        "effective_variadic": index.get("effective_variadic"),
        "incoming_assignments": index.get("incoming_assignments"),
        "implicit_al_present": index.get("implicit_al_present"),
        "call_site_plans": index.get("call_site_plans"),
        "acceptance_gates": index.get("acceptance_gates"),
        "warnings": len(index.get("warnings", []) or []),
    }
    print("===== PAL ICECUBE ABI-J PROVENANCE =====")
    print(json.dumps(inventory, indent=2, sort_keys=True))
    if include_details:
        print("\n[LOGICAL FUNCTION SIGNATURE]")
        print(json.dumps(logical, indent=2, sort_keys=True))
        print("\n[PHYSICAL ABI CARRIER MAP]")
        print(json.dumps(physical, indent=2, sort_keys=True))
    if include_calls:
        print("\n[CALL-SITE ARGUMENT PLANS]")
        for reference in list(index.get("call_site_refs", []) or []):
            plan = document.metadata.resolve(reference, {}) or {}
            if include_details:
                print(json.dumps(plan, indent=2, sort_keys=True))
            else:
                print(json.dumps({
                    "plan_id": plan.get("plan_id"),
                    "op_key": plan.get("op_key"),
                    "target": _dict(plan.get("target")).get("name"),
                    "arguments": plan.get("argument_count"),
                    "caller_variadic_al": _dict(
                        plan.get("caller_variadic_al")
                    ).get("value"),
                    "return_status": _dict(plan.get("result")).get("status"),
                    "no_return": _dict(plan.get("result")).get("no_return"),
                }, sort_keys=True))
    print("\n[WARNINGS]")
    print(json.dumps(index.get("warnings", []), indent=2, sort_keys=True))
    print("===== END PAL ICECUBE ABI-J PROVENANCE =====")
    return inventory


def debug_dump_humanizer_provenance(
    document, pal_function=None, function_registry=None,
    include_contracts=False,
):
    index = publish_humanizer_provenance(
        document,
        pal_function=pal_function,
        function_registry=function_registry,
    )
    function = document.metadata.resolve("humanizer:function", {}) or {}
    variables = document.metadata.resolve("humanizer:variables", {}) or {}
    inventory = {
        "kind": "pal_icecube_humanizer_inventory_v1",
        "version": HUMANIZER_VERSION,
        "function_id": index.get("function_id"),
        "registry_scope": index.get("registry_scope"),
        "original_function_name": function.get("original_name"),
        "generated_function_name": function.get("generated_name"),
        "operator_function_name": function.get("operator_name"),
        "active_function_name": function.get("active_name"),
        "vocabulary_size": variables.get("vocabulary_size"),
        "variable_contracts": index.get("variable_contracts"),
        "eligible_variables": index.get("eligible_variables"),
        "excluded_semantic_variables": index.get(
            "excluded_semantic_variables"
        ),
        "generated_collisions_resolved": index.get(
            "generated_collisions_resolved"
        ),
        "operator_alias_conflicts": index.get(
            "operator_alias_conflicts"
        ),
        "acceptance_gates": index.get("acceptance_gates"),
    }
    print("===== PAL ICECUBE COGNITIVE NAME PROVENANCE =====")
    print(json.dumps(inventory, indent=2, sort_keys=True))
    if include_contracts:
        print("\n[VARIABLE CONTRACTS]")
        for reference, contract in sorted(document.metadata.items()):
            if not str(reference).startswith("alias:variable:"):
                continue
            print(json.dumps(contract, indent=2, sort_keys=True))
    print("===== END PAL ICECUBE COGNITIVE NAME PROVENANCE =====")
    return inventory


# ============================================================================
# PAL SOURCE / MACHINE PROVENANCE
# ============================================================================


def _source_machine_addr(value):
    """Return a stable integer address when the PALlibrary image supplies one."""
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        try:
            text = value.strip()
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except Exception:
            return None
    try:
        return int(value)
    except Exception:
        return None


def _source_machine_addr_text(value):
    integer = _source_machine_addr(value)
    if integer is not None:
        return "0x%x" % integer
    return str(value) if value not in (None, "") else None


def _source_machine_instruction(raw):
    """Compact one PALlibrary raw-instruction image without reinference."""
    raw = _dict(raw)
    address = raw.get("addr_int")
    if address is None:
        address = _source_machine_addr(raw.get("addr"))
    assembly = raw.get("assembly") or raw.get("repr")
    return {
        "addr": _source_machine_addr_text(address or raw.get("addr")),
        "addr_int": address,
        "assembly": str(assembly) if assembly is not None else None,
        "mnemonic": raw.get("mnemonic"),
        "fallthrough": raw.get("fallthrough"),
        "fallthrough_int": raw.get("fallthrough_int"),
        "flows": list(raw.get("flows", []) or []),
        "flow_ints": list(raw.get("flow_ints", []) or []),
        "raw_pcode": list(raw.get("raw_pcode", []) or []),
    }


def _source_machine_block(block_addr, raw_block):
    """Compact one PALlibrary raw-machine block into frozen digest metadata."""
    raw_block = _dict(raw_block)
    address = _source_machine_addr(block_addr)
    if address is None:
        address = _source_machine_addr(raw_block.get("block_start_int"))
    instructions = [
        _source_machine_instruction(item)
        for item in _list(raw_block.get("instructions"))
        if isinstance(item, dict)
    ]
    lines = []
    for item in instructions:
        address_text = item.get("addr") or "?"
        assembly = item.get("assembly") or "<unavailable instruction text>"
        lines.append("%-18s %s" % (address_text, assembly))
    return {
        "kind": "pal_block_assembly_source_machine_v1",
        "version": SOURCE_MACHINE_VERSION,
        "block_addr": _source_machine_addr_text(address),
        "block_addr_int": address,
        "next_block_start": raw_block.get("next_block_start"),
        "instructions": instructions,
        "instruction_count": len(instructions),
        "lines": lines,
        "terminal": _dict(raw_block.get("terminal")),
        "terminal_successors": list(
            raw_block.get("terminal_successors", []) or []
        ),
        "authority": "PALlibrary.PALLifter.raw_machine_image",
        "reinference_allowed": False,
    }


def _source_machine_blocks_from_pal(pal_function):
    """Read existing PALlibrary raw-machine fields; never inspect emitted text."""
    raw_machine = getattr(pal_function, "raw_machine_image", None)
    if not isinstance(raw_machine, dict):
        raw_machine = _dict(
            _dict(getattr(pal_function, "pow_image", {})).get(
                "raw_machine_image"
            )
        )

    blocks = {}
    for key, value in raw_machine.items():
        if not isinstance(value, dict):
            continue
        block = _source_machine_block(key, value)
        canonical = block.get("block_addr")
        if canonical:
            blocks[canonical] = block

    # Compatibility fallback for a PALlibrary build that populated the block
    # objects but did not publish the aggregate raw_machine_image dictionary.
    if not blocks:
        for block_object in list(getattr(pal_function, "blocks", []) or []):
            address = getattr(block_object, "addr", None)
            instructions = list(
                getattr(block_object, "raw_instruction_image", []) or []
            )
            if not instructions:
                continue
            raw_block = {
                "block_start_int": address,
                "instructions": instructions,
                "terminal": getattr(block_object, "raw_terminal_image", None),
                "terminal_successors": list(
                    getattr(block_object, "raw_successors", []) or []
                ),
            }
            block = _source_machine_block(address, raw_block)
            canonical = block.get("block_addr")
            if canonical:
                blocks[canonical] = block
    return blocks


def _source_machine_c_from_pal(pal_function):
    """Read the function-wide C image already captured by PALlibrary."""
    value = getattr(pal_function, "decompiled_c_image", None)
    if value in (None, ""):
        value = _dict(getattr(pal_function, "pow_image", {})).get(
            "decompiled_c"
        )
    if value in (None, ""):
        return None
    text = str(value)
    return {
        "kind": "pal_function_c_source_machine_v1",
        "version": SOURCE_MACHINE_VERSION,
        "function": getattr(pal_function, "func_name", None),
        "entry": getattr(pal_function, "function_address", None),
        "text": text,
        "lines": text.splitlines(),
        "line_count": len(text.splitlines()),
        "authority": "PALlibrary.PALLifter.decompiled_c_image",
        "reinference_allowed": False,
    }


def publish_source_machine_provenance(document, pal_function=None):
    """
    Freeze PALlibrary's existing function-wide C and block assembly images.

    This is an isolated metadata publisher.  It performs no listing scan, no
    decompilation, and no text-to-address inference.  Missing evidence remains
    absent so the detached UI can distinguish truth from a simulation shim.
    """
    if not isinstance(document, PALCodeDocument):
        raise TypeError(
            "source/machine provenance requires a PALCodeDocument"
        )

    # Re-saving a detached document must preserve the source/machine records
    # already frozen into it.  Only a live PAL function may publish/replace
    # these records.
    if pal_function is None:
        metadata = getattr(document, "metadata", None)
        resolver = getattr(metadata, "resolve", None)
        if callable(resolver):
            try:
                existing = resolver("source_machine:index", None)
            except TypeError:
                existing = resolver("source_machine:index")
            except Exception:
                existing = None
        elif isinstance(metadata, dict):
            existing = metadata.get("source_machine:index")
        else:
            existing = None
        if isinstance(existing, dict):
            return dict(existing)

    c_payload = (
        _source_machine_c_from_pal(pal_function)
        if pal_function is not None else None
    )
    blocks = (
        _source_machine_blocks_from_pal(pal_function)
        if pal_function is not None else {}
    )

    c_ref = None
    if c_payload:
        c_ref = _register(document, "source:c_code", c_payload)

    block_refs = {}
    for canonical in sorted(
        blocks,
        key=lambda value: (
            _source_machine_addr(value) is None,
            _source_machine_addr(value) or 0,
            value,
        ),
    ):
        reference = "asm:block:%s" % canonical
        _register(document, reference, blocks[canonical])
        block_refs[canonical] = reference

    blocks_ref = None
    if blocks:
        blocks_ref = _register(document, "asm:blocks", blocks)

    index = {
        "kind": "pal_source_machine_provenance_index_v1",
        "version": SOURCE_MACHINE_VERSION,
        "function": (
            getattr(pal_function, "func_name", None)
            if pal_function is not None
            else getattr(document, "function_name", None)
        ),
        "entry": (
            getattr(pal_function, "function_address", None)
            if pal_function is not None else None
        ),
        "c_code_ref": c_ref,
        "asm_blocks_ref": blocks_ref,
        "asm_block_refs": block_refs,
        "c_code_present": bool(c_payload),
        "asm_blocks": len(blocks),
        "asm_instructions": sum(
            int(block.get("instruction_count", 0) or 0)
            for block in blocks.values()
        ),
        "authority": {
            "c_code": (
                "PALlibrary.PALLifter.decompiled_c_image"
                if c_payload else None
            ),
            "asm": (
                "PALlibrary.PALLifter.raw_machine_image"
                if blocks else None
            ),
        },
        "acceptance_gates": {
            "c_code_not_reinferred_from_python": True,
            "asm_not_reinferred_from_pcode_or_python": True,
            "live_java_objects_serialized": False,
            "block_addresses_preserved": all(
                block.get("block_addr_int") is not None
                for block in blocks.values()
            ) if blocks else True,
        },
        "rule": (
            "freeze_existing_PALlibrary_C_and_raw_machine_images_only"
        ),
    }
    _register(document, "source_machine:index", index)
    return index


def debug_dump_source_machine_provenance(document):
    """Print the compact frozen C/ASM inventory for dev-box verification."""
    metadata = getattr(document, "metadata", None)
    resolver = getattr(metadata, "resolve", None)
    if callable(resolver):
        try:
            index = _dict(resolver("source_machine:index", {}))
        except TypeError:
            index = _dict(resolver("source_machine:index"))
        except Exception:
            index = {}
    elif isinstance(metadata, dict):
        index = _dict(metadata.get("source_machine:index", {}))
    else:
        index = {}
    print("===== PAL ICECUBE SOURCE/MACHINE PROVENANCE =====")
    print(json.dumps(index, indent=2, sort_keys=True))
    print("===== END PAL ICECUBE SOURCE/MACHINE PROVENANCE =====")
    return index

def _unsigned_payload(document_bundle):
    document_payload = dict(document_bundle.get("document", {}) or {})
    projections = dict(document_payload.get("projections", {}) or {})
    metadata = dict(document_payload.get("metadata_registry", {}) or {})
    abi_index = dict(metadata.get("abi_j:index", {}) or {})
    humanizer_index = dict(metadata.get("humanizer:index", {}) or {})
    source_machine_index = dict(
        metadata.get("source_machine:index", {}) or {}
    )
    return {
        "format": ICECUBE_FORMAT,
        "schema_version": ICECUBE_SCHEMA_VERSION,
        "manifest": {
            "kind": "pal_icecube_manifest_v2",
            "function_name": document_payload.get("function_name"),
            "document_version": document_payload.get("document_version"),
            "document_bundle_schema": document_bundle.get("schema_version"),
            "document_sha256": (
                dict(document_bundle.get("integrity", {}) or {}).get("digest")
            ),
            "projections": sorted(projections),
            "capabilities": [
                "detached_cursor_lookup",
                "f1_projection_sync",
                "f2_alias_projection",
                "f3_metadata_description",
                "abi_j_logical_function_signature",
                "abi_j_physical_carrier_map",
                "abi_j_call_site_argument_plan",
                "cognitive_one_word_variable_names",
                "project_global_function_name_identity",
                "operator_name_collision_quarantine",
                "revisioned_operator_aliases",
                "revisioned_edit_sidecars",
                "explicit_ascii_export",
                "function_wide_decompiled_c_metadata",
                "block_addressed_raw_assembly_metadata",
            ],
            "abi_provenance": {
                "version": abi_index.get("version"),
                "active": abi_index.get("active"),
                "entry_plan_id": abi_index.get("entry_plan_id"),
                "logical_signature_ref": abi_index.get(
                    "logical_signature_ref"
                ),
                "physical_carrier_map_ref": abi_index.get(
                    "physical_carrier_map_ref"
                ),
                "call_site_plans": abi_index.get("call_site_plans", 0),
                "acceptance_gates": abi_index.get("acceptance_gates", {}),
            },
            "name_provenance": {
                "version": humanizer_index.get("version"),
                "function_id": humanizer_index.get("function_id"),
                "registry_scope": humanizer_index.get("registry_scope"),
                "variable_contracts": humanizer_index.get(
                    "variable_contracts", 0
                ),
                "acceptance_gates": humanizer_index.get(
                    "acceptance_gates", {}
                ),
            },
            "source_machine_provenance": {
                "version": source_machine_index.get("version"),
                "c_code_present": source_machine_index.get(
                    "c_code_present", False
                ),
                "asm_blocks": source_machine_index.get("asm_blocks", 0),
                "asm_instructions": source_machine_index.get(
                    "asm_instructions", 0
                ),
                "acceptance_gates": source_machine_index.get(
                    "acceptance_gates", {}
                ),
            },
            "live_runtime_dependencies": [],
        },
        "snapshot": document_bundle,
    }


def make_icecube(document, pal_function=None, function_registry=None):
    if not isinstance(document, PALCodeDocument):
        raise TypeError("icecube requires a PALCodeDocument")
    publish_abi_j_provenance(document, pal_function=pal_function)
    publish_humanizer_provenance(
        document,
        pal_function=pal_function,
        function_registry=function_registry,
    )
    publish_source_machine_provenance(
        document, pal_function=pal_function
    )
    document.validate_frozen_snapshot()
    payload = _unsigned_payload(document.to_bundle())
    digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    payload["integrity"] = {
        "algorithm": "sha256",
        "digest": digest,
        "scope": "format+schema_version+manifest+snapshot",
    }
    return payload


def verify_icecube(payload):
    if not isinstance(payload, dict):
        raise ValueError("PAL icecube must be a JSON object")
    if payload.get("format") != ICECUBE_FORMAT:
        raise ValueError("unsupported PAL icecube format")
    if int(payload.get("schema_version", -1)) not in (
        ICECUBE_SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ValueError("unsupported PAL icecube schema")
    integrity = dict(payload.get("integrity", {}) or {})
    if integrity.get("algorithm") != "sha256":
        raise ValueError("PAL icecube has no SHA-256 integrity")
    unsigned = {
        key: value for key, value in payload.items() if key != "integrity"
    }
    expected = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    if str(integrity.get("digest") or "") != expected:
        raise ValueError("PAL icecube integrity mismatch")
    snapshot = payload.get("snapshot")
    PALCodeDocument.verify_bundle(snapshot)
    manifest_digest = dict(payload.get("manifest", {}) or {}).get(
        "document_sha256"
    )
    snapshot_digest = dict(snapshot.get("integrity", {}) or {}).get("digest")
    if manifest_digest != snapshot_digest:
        raise ValueError("PAL icecube manifest/document digest mismatch")
    return expected


def save_icecube(
    document, path, indent=2, compress=None, pal_function=None,
    function_registry=None,
):
    path = os.fspath(path)
    if compress is None:
        compress = path.lower().endswith(".gz")
    payload = make_icecube(
        document,
        pal_function=pal_function,
        function_registry=function_registry,
    )
    temp_path = "%s.tmp.%d" % (path, os.getpid())
    opener = gzip.open if compress else open
    try:
        with opener(temp_path, "wt", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                sort_keys=True,
                indent=indent,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return payload["integrity"]["digest"]


def load_icecube(path, verify=True, compress=None):
    path = os.fspath(path)
    if compress is None:
        compress = path.lower().endswith(".gz")
    opener = gzip.open if compress else open
    with opener(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    if verify:
        verify_icecube(payload)
    return PALCodeDocument.from_bundle(payload.get("snapshot"), verify=verify)


def load_document_or_icecube(path, verify=True):
    """Load either an icecube wrapper or a raw PALCodeDocument bundle."""
    path = os.fspath(path)
    opener = gzip.open if path.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("format") == ICECUBE_FORMAT:
        if verify:
            verify_icecube(payload)
        return PALCodeDocument.from_bundle(payload.get("snapshot"), verify=verify)
    return PALCodeDocument.from_bundle(payload, verify=verify)


def freeze_pal_function(
    pal_function, path, require_pair=True, function_registry=None
):
    """
    PyGhidra-side integration point.

    Call only after PALemitter.emit_function_pair(). The function accepts the
    PAL function object, not Ghidra program objects, and serializes no live JVM
    references. The returned artifact can be opened by a normal CPython process.
    """
    document = getattr(pal_function, "code_document", None)
    if not isinstance(document, PALCodeDocument):
        raise ValueError(
            "PAL function has no completed code_document; run paired emission first"
        )
    if require_pair:
        missing = [
            mode for mode in ("readable", "executable")
            if document.projection(mode) is None
        ]
        if missing:
            raise ValueError(
                "PAL icecube requires paired projections; missing %s"
                % ", ".join(missing)
            )
        pairing = document.pairing_summary()
        if not pairing.get("semantic_statement_ids_match"):
            raise ValueError(
                "PAL icecube refused divergent readable/executable statement identities"
            )
    digest = save_icecube(
        document,
        path,
        pal_function=pal_function,
        function_registry=function_registry,
    )
    try:
        pal_function.icecube_path = os.fspath(path)
        pal_function.icecube_sha256 = digest
        pal_function.icecube_version = (
            HUMANIZER_ICECUBE_VERSION
        )
    except Exception:
        pass
    return digest


def freeze_pipeline(
    dispatcher, path, require_pair=True, function_registry=None
):
    """Convenience hook for PALDecompilerPipeline instances (dispatcher.PAL)."""
    pal_function = getattr(dispatcher, "PAL", None)
    if pal_function is None:
        raise ValueError(
            "PAL pipeline has no completed PAL function; run the pipeline first"
        )
    return freeze_pal_function(
        pal_function,
        path,
        require_pair=require_pair,
        function_registry=function_registry,
    )


def _cli(argv=None):
    parser = argparse.ArgumentParser(
        description="Inspect or verify a frozen PAL icecube"
    )
    parser.add_argument("path", help=".icecube.json or .icecube.json.gz")
    parser.add_argument(
        "--no-verify", action="store_true", help="skip integrity verification"
    )
    parser.add_argument(
        "--summary", action="store_true", help="print detached document summary"
    )
    parser.add_argument(
        "--abi-j", action="store_true",
        help="print frozen logical/physical ABI-J provenance inventory",
    )
    parser.add_argument(
        "--humanizer", action="store_true",
        help="print frozen function/variable name provenance inventory",
    )
    parser.add_argument(
        "--source-machine", action="store_true",
        help="print frozen function C and block ASM provenance inventory",
    )
    args = parser.parse_args(argv)
    document = load_document_or_icecube(args.path, verify=not args.no_verify)
    if args.abi_j:
        debug_dump_abi_j_provenance(document, include_calls=True)
    if args.humanizer:
        debug_dump_humanizer_provenance(document)
    if args.source_machine:
        debug_dump_source_machine_provenance(document)
    elif args.summary:
        print(json.dumps(document.summary(), indent=2, sort_keys=True))
    else:
        print("PAL icecube OK: %s" % args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())


# ============================================================================
# PALTERMUI TRUTH-DIGEST METADATA ADAPTER
# ============================================================================


def _metadata_items(document):
    metadata = getattr(document, "metadata", None)
    if metadata is None:
        return []
    items = getattr(metadata, "items", None)
    if callable(items):
        try:
            return list(items())
        except Exception:
            pass
    for attr in ("records", "entries", "data", "_records", "_entries"):
        value = getattr(metadata, attr, None)
        if isinstance(value, dict):
            return list(value.items())
    if isinstance(metadata, dict):
        return list(metadata.items())
    return []


def _metadata_resolve(document, reference, default=None):
    metadata = getattr(document, "metadata", None)
    resolver = getattr(metadata, "resolve", None)
    if callable(resolver):
        try:
            return resolver(reference, default)
        except TypeError:
            try:
                value = resolver(reference)
                return default if value is None else value
            except Exception:
                return default
        except Exception:
            return default
    if isinstance(metadata, dict):
        return metadata.get(reference, default)
    return default


def _digest_lines(value):
    if value is None:
        return []
    if isinstance(value, str):
        return value.splitlines() or [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if isinstance(value, dict):
        for key in ("lines", "text", "code", "c_code", "asm", "body"):
            if key in value:
                return _digest_lines(value.get(key))
        return json.dumps(value, indent=2, sort_keys=True).splitlines()
    return [str(value)]


class IcecubeMetadataView:
    """Terse, read-only metadata projections for PALTermUI Truth Digest Daily."""

    C_CODE_REFS = (
        "source:c_code", "function:c_code", "decompiler:c_code",
        "ghidra:c_code", "c_code",
    )
    SIGNATURE_REFS = (
        "function:signature", "abi_j:logical_signature", "abi:entry_plan",
    )

    def __init__(self, document, function_record=None):
        self.document = document
        self.function_record = dict(function_record or {})

    def _first(self, references):
        for reference in references:
            value = _metadata_resolve(self.document, reference, None)
            if value not in (None, {}, []):
                return value, reference
        return None, None

    def c_code(self):
        value, reference = self._first(self.C_CODE_REFS)
        if value is None:
            for attr in ("function_c_code", "c_code", "ghidra_c_code"):
                value = getattr(self.document, attr, None)
                if value not in (None, {}, []):
                    reference = "document.%s" % attr
                    break
        lines = _digest_lines(value)
        if not lines:
            lines = ["icecube sim shim C-CODE"]
            reference = "shim:c_code"
        return {"source": reference, "lines": lines, "shim": reference.startswith("shim:")}

    def function_definition(self):
        signature, signature_ref = self._first(self.SIGNATURE_REFS)
        signature = _dict(signature)
        human = _dict(_metadata_resolve(self.document, "humanizer:function", {}))
        function_name = (
            human.get("active_name") or human.get("pal_name")
            or self.function_record.get("active_name")
            or self.function_record.get("name")
            or getattr(self.document, "function_name", "function")
        )
        lines = [
            "function: %s" % function_name,
            "entry: %s" % (
                self.function_record.get("entry_hex")
                or self.function_record.get("entry")
                or signature.get("entry") or "-"
            ),
            "signature source: %s" % (signature_ref or "shim:function_definition"),
        ]
        parameters = (
            signature.get("fixed_parameters") or signature.get("parameters")
            or signature.get("fixed_arguments") or []
        )
        if parameters:
            lines.append("parameters:")
            for ordinal, raw in enumerate(parameters):
                item = _dict(raw)
                lines.append("  #%s %-20s sid=%s type=%s" % (
                    item.get("ordinal", ordinal),
                    item.get("name") or item.get("logical_name") or "<unnamed>",
                    item.get("source_sid") or item.get("sid") or "-",
                    item.get("declared_type") or item.get("type") or "-",
                ))
        else:
            lines.append("parameters: none frozen")

        variables = []
        for reference, value in _metadata_items(self.document):
            if not str(reference).startswith("variable:") or not isinstance(value, dict):
                continue
            variables.append((str(reference).split(":", 1)[1], dict(value)))
        lines.append("variables: %d frozen" % len(variables))
        for sid, item in sorted(variables)[:200]:
            contract = _dict(item.get("human_alias_contract"))
            lines.append("  %-14s PAL=%-18s active=%s" % (
                sid,
                contract.get("pal_name") or item.get("display_name") or item.get("name") or sid,
                contract.get("active_name") or "-",
            ))
        return {
            "source": signature_ref or "shim:function_definition",
            "lines": lines,
            "shim": signature_ref is None,
            "signature": signature,
            "variables": variables,
        }

    def called_functions(self):
        index = _dict(_metadata_resolve(self.document, "abi_j:index", {}))
        references = list(index.get("call_site_refs", []) or [])
        if not references:
            references = [
                str(reference) for reference, unused in _metadata_items(self.document)
                if str(reference).startswith("abi_j:call:")
            ]
        plans = []
        for reference in references:
            value = _metadata_resolve(self.document, reference, None)
            if isinstance(value, dict):
                plans.append(dict(value))
        lines = []
        for ordinal, plan in enumerate(plans):
            target = _dict(plan.get("target"))
            lines.append("#%d %-28s dispatch=%-18s args=%s status=%s" % (
                ordinal,
                target.get("name") or "<unresolved>",
                plan.get("dispatch_policy") or plan.get("dispatch_class") or "-",
                plan.get("argument_count", len(_list(plan.get("arguments")))),
                plan.get("status") or "-",
            ))
        if not lines:
            lines = ["icecube sim shim CALLED FUNCTION LIST"]
        return {
            "source": "abi_j:call:*" if plans else "shim:called_functions",
            "lines": lines,
            "shim": not bool(plans),
            "plans": plans,
        }

    def abi_custody(self):
        logical = _dict(_metadata_resolve(self.document, "abi_j:logical_signature", {}))
        physical = _dict(_metadata_resolve(self.document, "abi_j:physical_carrier_map", {}))
        lines = []
        if logical or physical:
            lines.extend([
                "callable status: %s" % logical.get("callable_signature_status", "-"),
                "fixed parameters: %s" % logical.get("fixed_parameter_count", 0),
                "variadic: %s" % _dict(logical.get("variadic")).get("effective", "-"),
                "incoming assignments: %s" % physical.get("incoming_assignment_count", 0),
            ])
            for item in _list(physical.get("incoming_assignments")):
                item = _dict(item)
                carrier = item.get("register")
                if carrier is None and item.get("stack_slot") is not None:
                    carrier = "stack[%s]" % item.get("stack_slot")
                lines.append("  %-18s -> %-14s %s-bit owner=%s/%s" % (
                    item.get("logical_name") or item.get("canonical_alias") or item.get("sid") or "-",
                    carrier or item.get("bank") or "unassigned",
                    item.get("width_bits") or "?",
                    item.get("owner_namespace") or "-",
                    item.get("owner_role") or "-",
                ))
            implicit = _dict(physical.get("implicit_al"))
            lines.append("implicit AL: present=%s required=%s sid=%s" % (
                implicit.get("present", False), implicit.get("required", False),
                implicit.get("sid") or "-",
            ))
            result = _dict(physical.get("return_carrier"))
            lines.append("return: status=%s width=%s no-return=%s" % (
                result.get("status") or "-",
                result.get("effective_result_width_bits") or "?",
                result.get("no_return", False),
            ))
        else:
            lines = ["icecube sim shim ABI CUSTODY"]
        return {
            "source": "abi_j" if logical or physical else "shim:abi_custody",
            "lines": lines,
            "shim": not bool(logical or physical),
            "logical": logical,
            "physical": physical,
        }

    def asm(self, block_addr=None):
        exact_candidates = []
        canonical = None
        if block_addr is not None:
            canonical = _source_machine_addr_text(block_addr)
            if canonical:
                exact_candidates.extend((
                    "asm:block:%s" % canonical,
                    "block:%s:asm" % canonical,
                    "asm:%s" % canonical,
                ))
            exact_candidates.extend((
                "asm:block:%s" % str(block_addr),
                "block:%s:asm" % str(block_addr),
                "asm:%s" % str(block_addr),
            ))

        value, reference = self._first(exact_candidates)
        blocks = _dict(_metadata_resolve(self.document, "asm:blocks", {}))

        if value is None and blocks and canonical:
            value = blocks.get(canonical)
            if value is not None:
                reference = "asm:blocks[%s]" % canonical

        if value is not None:
            lines = _digest_lines(value)
            return {
                "source": reference,
                "lines": lines,
                "shim": False,
                "block_addr": canonical,
                "blocks": 1,
                "instruction_count": len(_list(_dict(value).get("instructions"))),
            }

        if blocks:
            lines = []
            instruction_count = 0
            ordered = sorted(
                blocks.items(),
                key=lambda pair: (
                    _source_machine_addr(pair[0]) is None,
                    _source_machine_addr(pair[0]) or 0,
                    pair[0],
                ),
            )
            for block_key, block in ordered:
                block = _dict(block)
                block_lines = _digest_lines(block)
                instruction_count += int(
                    block.get("instruction_count", 0) or 0
                )
                lines.append("[%s]" % block_key)
                lines.extend("  %s" % line for line in block_lines)
                lines.append("")
            if lines and not lines[-1]:
                lines.pop()
            return {
                "source": "asm:blocks",
                "lines": lines,
                "shim": False,
                "block_addr": None,
                "blocks": len(blocks),
                "instruction_count": instruction_count,
            }

        return {
            "source": "shim:asm",
            "lines": ["icecube sim shim ASM"],
            "shim": True,
            "block_addr": canonical,
            "blocks": 0,
            "instruction_count": 0,
        }

    def raw(self):
        metadata = {}
        for reference, value in _metadata_items(self.document):
            try:
                metadata[str(reference)] = self.document.freeze_metadata_value(value)
            except Exception:
                metadata[str(reference)] = value
        return {
            "function_record": dict(self.function_record),
            "source_machine_index": _dict(
                _metadata_resolve(
                    self.document, "source_machine:index", {}
                )
            ),
            "document_summary": (
                self.document.summary() if callable(getattr(self.document, "summary", None))
                else {"function_name": getattr(self.document, "function_name", None)}
            ),
            "metadata": metadata,
        }

    def digest_bundle(self, block_addr=None):
        return {
            "kind": "pal_truth_digest_daily_v2",
            "c_code": self.c_code(),
            "function_definition": self.function_definition(),
            "called_functions": self.called_functions(),
            "abi_custody": self.abi_custody(),
            "asm": self.asm(block_addr),
            "raw": self.raw(),
        }
