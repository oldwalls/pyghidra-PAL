# ======================================
# PALCompute.py
# v23b ABI-D thunk/compatibility/return hardening + v22d C-compute custody
#
# Purpose:
#   - consume PALLifter width evidence and PALSymbolResolver numeric contracts
#   - classify every SSA-producing P-code operation independently
#   - make C/Python divergence explicit before PHI folding or emission
#   - preserve raw fixed-width storage separately from signed/unsigned views
#   - publish deterministic per-op and per-output-SID compute plans
#   - bind INDIRECT SSA states to resolver storage families and effect owners
#   - consume ABI-C namespaces without re-inferring argument placement
#   - publish one function-entry plan and one plan for every CALL boundary
#   - distinguish physical thunk bodies from semantic external endpoints
#   - keep carrier, prototype, and aggregate target compatibility separate
#   - cut return reachability at proven no-return call boundaries
#   - reconcile reachable return transports without trusting default undefined
#
# This module is metadata-only.  It does not rewrite formulas, PHI nodes,
# ExecTrees, or emitted Python.
# ======================================


class PALComputeAnalyzer:

    VERSION = "v23b_abi_thunk_compatibility_return_reconciliation"
    REPRESENTATION = "raw_unsigned_bitvector_at_ssa_boundaries"

    SIGNED_INPUT_OPS = {
        "INT_SDIV", "INT_SREM", "INT_SLESS", "INT_SLESSEQUAL",
        "INT_SRIGHT", "INT_SCARRY", "INT_SBORROW",
    }

    UNSIGNED_INPUT_OPS = {
        "INT_DIV", "INT_REM", "INT_LESS", "INT_LESSEQUAL",
        "INT_RIGHT", "INT_CARRY",
    }

    COMPARISON_OPS = {
        "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL",
        "INT_SLESS", "INT_SLESSEQUAL",
        "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
    }

    BOOLEAN_OPS = {"BOOL_AND", "BOOL_OR", "BOOL_XOR", "BOOL_NEGATE"}

    FLOAT_OPS = {
        "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
        "FLOAT_NAN", "FLOAT_ADD", "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB",
        "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_INT2FLOAT",
        "FLOAT_FLOAT2FLOAT", "FLOAT_TRUNC", "FLOAT_CEIL", "FLOAT_FLOOR",
        "FLOAT_ROUND",
    }

    CONVERSION_OPS = {"COPY", "CAST", "SUBPIECE", "PIECE", "INT_ZEXT", "INT_SEXT"}

    INTEGER_ARITHMETIC_OPS = {
        "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
        "INT_REM", "INT_SREM", "INT_2COMP",
    }

    INTEGER_BITWISE_OPS = {"INT_AND", "INT_OR", "INT_XOR", "INT_NEGATE"}
    INTEGER_SHIFT_OPS = {"INT_LEFT", "INT_RIGHT", "INT_SRIGHT"}
    PHI_OPS = {"MULTIEQUAL"}
    MEMORY_OPS = {"LOAD", "STORE"}
    CALL_OPS = {"CALL", "CALLIND", "CALLOTHER"}
    POINTER_OPS = {"PTRADD", "PTRSUB"}
    CUSTODY_OPS = {"INDIRECT"}

    HELPER_BY_OPCODE = {
        "SUBPIECE": "c_subpiece",
        "PIECE": "c_piece",
        "INT_ZEXT": "c_zext",
        "INT_SEXT": "c_sext",
        "INT_ADD": "c_add",
        "INT_SUB": "c_sub",
        "INT_MULT": "c_mul",
        "INT_DIV": "c_udiv",
        "INT_SDIV": "c_sdiv",
        "INT_REM": "c_urem",
        "INT_SREM": "c_srem",
        "INT_2COMP": "c_neg",
        "INT_NEGATE": "c_not",
        "INT_AND": "c_and",
        "INT_OR": "c_or",
        "INT_XOR": "c_xor",
        "INT_LEFT": "c_shl",
        "INT_RIGHT": "c_lshr",
        "INT_SRIGHT": "c_ashr",
        "INT_EQUAL": "c_eq",
        "INT_NOTEQUAL": "c_ne",
        "INT_LESS": "c_ult",
        "INT_LESSEQUAL": "c_ule",
        "INT_SLESS": "c_slt",
        "INT_SLESSEQUAL": "c_sle",
        "INT_CARRY": "c_carry",
        "INT_SCARRY": "c_scarry",
        "INT_SBORROW": "c_sborrow",
        "PTRADD": "c_ptradd",
        "PTRSUB": "c_ptrsub",
        "LOAD": "c_load",
        "STORE": "c_store",
    }

    def __init__(self, pal_function, strict=False):
        self.func = pal_function
        self.strict = bool(strict)

        self.target = dict(getattr(pal_function, "target_numeric_model", {}) or {})
        self.resolver_contracts = dict(
            getattr(pal_function, "numeric_contracts_by_sid", {}) or {}
        )

        # Resolver v22c custody evidence.  These are consumed as immutable
        # contracts: PALCompute may bind and validate them, but must not infer a
        # different HighVariable family or effect owner.
        self.resolver_indirect_transitions = list(
            getattr(pal_function, "indirect_custody_transitions", []) or []
        )
        self.resolver_indirect_by_output_sid = dict(
            getattr(
                pal_function,
                "indirect_custody_transitions_by_output_sid",
                {},
            ) or {}
        )
        self.resolver_storage_family_by_sid = dict(
            getattr(pal_function, "indirect_storage_family_by_sid", {}) or {}
        )
        self.resolver_storage_families = dict(
            getattr(pal_function, "indirect_storage_families_by_key", {}) or {}
        )
        self.resolver_parameter_initializers = list(
            getattr(pal_function, "indirect_parameter_initializers", []) or []
        )
        self.resolver_parameter_initializer_by_output_sid = {
            str(record.get("output_sid")): record
            for record in self.resolver_parameter_initializers
            if isinstance(record, dict) and record.get("output_sid") is not None
        }
        self.resolver_escape_barrier_sids = set(
            str(sid)
            for sid in (
                getattr(pal_function, "indirect_escape_barrier_sids", []) or []
            )
        )

        # ABI-D consumes ABI-A/B lifter evidence plus ABI-C namespace outputs.
        # None of these plans is allowed to derive carriers from parameter
        # names, expression text, or emitter surface syntax.
        self.lifter_function_abi_contract = dict(
            getattr(pal_function, "function_abi_contract", {}) or {}
        )
        self.lifter_call_site_abi_contracts = list(
            getattr(pal_function, "call_site_abi_contracts", []) or []
        )
        self.lifter_call_site_abi_by_op = dict(
            getattr(pal_function, "call_site_abi_by_op", {}) or {}
        )
        self.resolver_callable_parameter_order = list(
            getattr(pal_function, "callable_parameter_order", []) or []
        )
        self.resolver_physical_carrier_bindings = dict(
            getattr(pal_function, "physical_carrier_bindings", {}) or {}
        )
        self.resolver_implicit_inputs = dict(
            getattr(pal_function, "implicit_inputs", {}) or {}
        )
        self.resolver_variadic_contract = dict(
            getattr(pal_function, "variadic_contract", {}) or {}
        )
        self.resolver_abi_namespace_inventory = dict(
            getattr(pal_function, "abi_namespace_inventory", {}) or {}
        )

        self.compute_plans_by_sid = {}
        self.compute_contracts_by_op = {}
        self.compute_contracts_by_block = {}
        self.control_contracts_by_block = {}
        self.compute_storage_bindings_by_sid = {}
        self.compute_indirect_contracts_by_op = {}
        self.compute_indirect_contracts_by_output_sid = {}
        self.compute_indirect_contracts_by_owner_op_id = {}
        self.compute_indirect_contracts_by_family_id = {}
        self.compute_effect_owner_bindings_by_op = {}
        self.function_entry_abi_plan = {}
        self.call_site_abi_plans_by_op = {}
        self.call_site_abi_plans_by_raw_op_id = {}
        self.no_return_call_op_keys = []
        self.return_boundary_reconciliation = {}
        self.abi_plan_events = []
        self.abi_plan_warnings = []
        self.abi_plan_inventory = {}
        self.events = []
        self.warnings = []

    # -------------------------------------------------
    # BASIC ACCESSORS
    # -------------------------------------------------

    def _iter_vars(self):
        vars_in = getattr(self.func, "vars", {})
        if isinstance(vars_in, dict):
            return list(vars_in.values())
        return list(vars_in or [])

    def _iter_blocks(self):
        return list(getattr(self.func, "blocks", []) or [])

    def _sid(self, var):
        return getattr(var, "ssa_id", None) if var is not None else None

    @staticmethod
    def _sid_text(value):
        return str(value) if value is not None else None

    def _width(self, var):
        if var is None:
            return None

        width = getattr(var, "width_bits", None)
        if isinstance(width, int) and width > 0:
            return width

        size = getattr(var, "size", None)
        if isinstance(size, int) and size > 0:
            return size * 8

        return None

    def _mask_for_width(self, width_bits):
        if not isinstance(width_bits, int) or width_bits <= 0:
            return None
        return (1 << width_bits) - 1

    def _block_addr(self, block):
        return getattr(block, "addr", None)

    def _op_id(self, op):
        return getattr(op, "op_id", None) or getattr(op, "hf_seqnum", None)

    def _op_key(self, block, op, ordinal):
        return "%s:%s:%s" % (
            self._block_addr(block),
            self._op_id(op),
            ordinal,
        )

    def _view_for_var(self, var):
        sid = self._sid(var)
        contract = None
        if sid is not None:
            contract = self.resolver_contracts.get(str(sid))
        if contract is None:
            contract = getattr(var, "numeric_contract", None) if var is not None else None

        if isinstance(contract, dict):
            return {
                "sid": sid,
                "width_bits": contract.get("storage_width_bits"),
                "domain": contract.get("domain") or "unknown",
                "signedness": contract.get("default_signedness"),
                "canonical_type": contract.get("canonical_type"),
                "declared_type": contract.get("declared_type_name"),
                "source": "resolver_contract",
            }

        width = self._width(var)
        return {
            "sid": sid,
            "width_bits": width,
            "domain": getattr(var, "normalized_domain", None) or "unknown" if var is not None else "unknown",
            "signedness": getattr(var, "normalized_signedness", None) if var is not None else None,
            "canonical_type": getattr(var, "normalized_type_name", None) if var is not None else None,
            "declared_type": getattr(var, "declared_type_name", None) if var is not None else None,
            "source": "variable_fallback",
        }

    def _compact_view(self, view):
        return {
            "sid": view.get("sid"),
            "width_bits": view.get("width_bits"),
            "domain": view.get("domain"),
            "signedness": view.get("signedness"),
            "canonical_type": view.get("canonical_type"),
        }

    def _var_for_sid(self, sid):
        if sid is None:
            return None
        for var in self._iter_vars():
            if str(self._sid(var)) == str(sid):
                return var
        return None

    @staticmethod
    def _datatype_width_bits(image):
        image = image if isinstance(image, dict) else {}
        width = image.get("width_bits")
        if isinstance(width, int) and width > 0:
            return width
        size = image.get("size_bytes")
        if isinstance(size, int) and size > 0:
            return size * 8
        base = image.get("base_type")
        if isinstance(base, dict):
            width = base.get("width_bits")
            if isinstance(width, int) and width > 0:
                return width
        return None

    @staticmethod
    def _abi_storage_pieces(storage):
        storage = storage if isinstance(storage, dict) else {}
        return [
            dict(piece) for piece in list(storage.get("pieces") or [])
            if isinstance(piece, dict)
        ]

    def _return_carrier_contract(
        self, signature, output_sid=None, output_width_bits=None, no_return=None
    ):
        signature = signature if isinstance(signature, dict) else {}
        declared = signature.get("return")
        declared = dict(declared) if isinstance(declared, dict) else {}
        storage = signature.get("return_storage")
        storage = dict(storage) if isinstance(storage, dict) else {}
        pieces = self._abi_storage_pieces(storage)
        declared_width = self._datatype_width_bits(declared)
        no_return_value = (
            bool(signature.get("no_return"))
            if no_return is None else bool(no_return)
        )

        if no_return_value:
            status = "no_return"
        elif storage.get("flags", {}).get("void"):
            status = "void_return"
        elif pieces:
            status = "physical_return_carrier_proven"
        elif output_sid is not None or declared_width is not None:
            status = "return_carrier_deferred"
        else:
            status = "no_return_value_observed"

        return {
            "kind": "pal_compute_return_carrier_contract_abi_d",
            "version": self.VERSION,
            "status": status,
            "no_return": no_return_value,
            "output_sid": output_sid,
            "output_width_bits": output_width_bits,
            "declared_width_bits": declared_width,
            "effective_result_width_bits": (
                output_width_bits
                if isinstance(output_width_bits, int) and output_width_bits > 0
                else declared_width
            ),
            "declared_return": declared or None,
            "return_storage": storage or None,
            "carrier_pieces": pieces,
            "normalization": (
                {
                    "mode": "mask_to_output_width",
                    "width_bits": output_width_bits,
                    "mask": self._mask_for_width(output_width_bits),
                }
                if (
                    not no_return_value
                    and isinstance(output_width_bits, int)
                    and output_width_bits > 0
                ) else None
            ),
            "runtime_helper": None,
            "runtime_helper_authority": "no_ABI_runtime_helper_assigned",
            "authority": "PALlibrary_function_signature_return_storage",
        }

    def _legacy_callable_parameter_order(self):
        records = list(getattr(self.func, "parameter_records", []) or [])
        if records:
            return [{
                "kind": "pal_compute_legacy_callable_parameter_abi_d",
                "ordinal": record.get("index"),
                "name": record.get("name"),
                "source_sid": record.get("sid"),
                "physical_sids": (
                    [str(record.get("sid"))]
                    if record.get("sid") is not None else []
                ),
                "selection_source": "legacy_parameter_records_fallback",
            } for record in records]

        parameters = list(getattr(self.func, "parameters", []) or [])
        return [{
            "kind": "pal_compute_legacy_callable_parameter_abi_d",
            "ordinal": index,
            "name": getattr(var, "name", None),
            "source_sid": self._sid(var),
            "physical_sids": (
                [str(self._sid(var))] if self._sid(var) is not None else []
            ),
            "selection_source": "legacy_PALFunction_parameters_fallback",
        } for index, var in enumerate(parameters)]

    def _implicit_materialization(self, sid, contract):
        contract = contract if isinstance(contract, dict) else {}
        role = str(contract.get("role") or "machine_live_in")
        destinations = {
            "stack_pointer": "abi_context.stack_pointer",
            "frame_pointer": "abi_context.frame_base",
            "thread_local_storage_base": "abi_context.tls_base",
            "variadic_xmm_register_count": "abi_context.variadic_xmm_count",
            "vector_argument_register_live_in": "abi_context.register_save_area",
            "condition_flags": "abi_context.condition_flags",
            "machine_live_in": "abi_context.machine_state",
        }
        destination = destinations.get(role, "abi_context.machine_state")
        return {
            "kind": "pal_compute_implicit_input_materialization_abi_d",
            "version": self.VERSION,
            "sid": str(sid),
            "canonical_alias": contract.get("canonical_alias"),
            "role": role,
            "custody_class": contract.get("custody_class") or "machine_state",
            "width_bits": contract.get("width_bits"),
            "register": contract.get("register"),
            "destination": destination,
            "materialization": "read_from_runtime_abi_context",
            "status": "runtime_context_required",
            "unsupported": False,
            "runtime_helper": None,
            "authority": "PALSymbolResolver_ABI_C_implicit_input_contract",
        }

    def _build_function_entry_abi_plan(self):
        function_abi = dict(self.lifter_function_abi_contract or {})
        namespace_inventory = dict(self.resolver_abi_namespace_inventory or {})
        namespace_active = bool(namespace_inventory.get("active"))
        callable_order = list(self.resolver_callable_parameter_order or [])

        # Older/non-ABI specimens receive an explicit compatibility plan.  An
        # active ABI-C contract is never replaced by this fallback: a deliberate
        # empty callable list (unresolved variadic fixed arity) must stay empty.
        if not namespace_active and not callable_order:
            callable_order = self._legacy_callable_parameter_order()

        fixed_arguments = []
        for fallback_ordinal, item in enumerate(callable_order):
            item = dict(item)
            ordinal = item.get("ordinal")
            if not isinstance(ordinal, int):
                ordinal = fallback_ordinal
            physical_sids = [
                str(sid) for sid in list(item.get("physical_sids") or [])
                if sid is not None
            ]
            carrier_bindings = [
                dict(self.resolver_physical_carrier_bindings[sid])
                for sid in physical_sids
                if sid in self.resolver_physical_carrier_bindings
            ]
            fixed_arguments.append({
                "kind": "pal_compute_fixed_argument_entry_plan_abi_d",
                "version": self.VERSION,
                "ordinal": ordinal,
                "name": item.get("name"),
                "logical_ordinal": item.get("logical_ordinal"),
                "logical_name": item.get("logical_name"),
                "source_sid": item.get("source_sid"),
                "physical_sids": physical_sids,
                "physical_carrier_bindings": carrier_bindings,
                "python_source": {
                    "kind": "positional_argument",
                    "index": ordinal,
                    "name": item.get("name"),
                },
                "materialization": "bind_argument_bits_to_logical_identity",
                "status": "ready",
                "runtime_helper": None,
                "authority": item.get("selection_source")
                or "PALSymbolResolver_ABI_C_callable_order",
            })

        implicit_materializations = [
            self._implicit_materialization(sid, contract)
            for sid, contract in sorted(
                self.resolver_implicit_inputs.items(), key=lambda pair: str(pair[0])
            )
        ]

        register_save_slots = []
        for sid, binding in sorted(
            self.resolver_physical_carrier_bindings.items(),
            key=lambda pair: (
                str((pair[1] or {}).get("carrier_bank") or ""),
                (pair[1] or {}).get("carrier_index") is None,
                (pair[1] or {}).get("carrier_index")
                if isinstance((pair[1] or {}).get("carrier_index"), int) else 0,
                str(pair[0]),
            ),
        ):
            binding = dict(binding or {})
            bank = binding.get("carrier_bank")
            if bank not in ("gp", "sse"):
                continue
            var = self._var_for_sid(sid)
            owner = dict(binding.get("owner") or {})
            register_save_slots.append({
                "sid": str(sid),
                "bank": bank,
                "index": binding.get("carrier_index"),
                "register": binding.get("register"),
                "width_bits": self._width(var),
                "canonical_alias": binding.get("canonical_alias"),
                "owner_namespace": owner.get("namespace"),
                "owner_role": owner.get("role"),
                "materialization": "capture_entry_register_bits",
                "source": "abi_context.registers",
                "runtime_helper": None,
                "authority": "PALSymbolResolver_ABI_C_physical_carrier_binding",
            })

        stack_carriers = [
            dict(binding) for binding in self.resolver_physical_carrier_bindings.values()
            if (binding or {}).get("carrier_bank") == "stack"
        ]
        variadic = dict(self.resolver_variadic_contract or {})
        effective_variadic = bool(
            variadic.get("effective_variadic")
            or function_abi.get("effective_variadic")
        )
        xmm_count_inputs = [
            item for item in implicit_materializations
            if item.get("role") == "variadic_xmm_register_count"
        ]
        frame_inputs = [
            item for item in implicit_materializations
            if item.get("custody_class") == "frame_state"
        ]
        tls_inputs = [
            item for item in implicit_materializations
            if item.get("custody_class") == "tls_state"
        ]

        callable_status = (
            variadic.get("callable_signature_status")
            or namespace_inventory.get("callable_signature_status")
            or "legacy_callable_signature"
        )
        if callable_status == "deferred_unresolved_variadic_fixed_arity":
            plan_status = "deferred_unresolved_callable_signature"
        elif namespace_active:
            plan_status = "ready"
        else:
            plan_status = "legacy_compatibility_ready"

        signature = dict(getattr(self.func, "function_signature", {}) or {})
        if not signature:
            signature = function_abi
        entry = getattr(self.func, "function_address", None)
        backend = dict(function_abi.get("abi_backend") or {})
        entry_plan = {
            "kind": "pal_compute_function_entry_abi_plan_v23",
            "plan_class": "function_entry_abi_plan",
            "version": self.VERSION,
            "plan_id": "function_entry:%s" % entry,
            "function": getattr(self.func, "func_name", None),
            "entry": entry,
            "status": plan_status,
            "abi_backend": backend,
            "prototype_authority": dict(
                function_abi.get("prototype_authority") or {}
            ),
            "callable_signature_status": callable_status,
            "fixed_arguments": fixed_arguments,
            "fixed_argument_count": len(fixed_arguments),
            "fixed_argument_materialization": (
                "deferred_until_logical_arity_proven"
                if plan_status == "deferred_unresolved_callable_signature"
                else "bind_positional_arguments_in_callable_order"
            ),
            "variadic_register_save_area": {
                "required": effective_variadic,
                "status": (
                    "runtime_abi_context_required"
                    if effective_variadic else "not_required"
                ),
                "slots": register_save_slots,
                "gp_slots": [
                    item for item in register_save_slots if item.get("bank") == "gp"
                ],
                "sse_slots": [
                    item for item in register_save_slots if item.get("bank") == "sse"
                ],
                "fixed_variadic_partition_status": variadic.get(
                    "fixed_parameter_count_inference_status"
                ),
                "source": "abi_context.registers",
                "authority": "ABI_C_carriers_plus_variadic_contract",
            },
            "overflow_argument_area": {
                "required": effective_variadic or bool(stack_carriers),
                "status": (
                    "runtime_abi_context_required"
                    if effective_variadic or stack_carriers else "not_required"
                ),
                "source": "abi_context.overflow_argument_area",
                "observed_stack_carriers": stack_carriers,
                "materialization": "consume_preclassified_overflow_slots",
                "offset_inference_allowed": False,
                "authority": "ABI_C_stack_carriers_or_variadic_protocol",
            },
            "variadic_al": {
                "required": effective_variadic,
                "status": (
                    "runtime_abi_context_required"
                    if effective_variadic else "not_required"
                ),
                "source": "abi_context.variadic_xmm_count",
                "inputs": xmm_count_inputs,
                "default_allowed": False,
                "authority": "ABI_C_variadic_xmm_count_contract",
            },
            "frame_base": {
                "required": bool(frame_inputs),
                "status": (
                    "runtime_abi_context_required"
                    if frame_inputs else "not_observed"
                ),
                "source": "abi_context.frame_base",
                "inputs": frame_inputs,
                "derive_from_parameter_names": False,
                "authority": "ABI_C_frame_state_custody",
            },
            "tls_base": {
                "required": bool(tls_inputs),
                "status": (
                    "runtime_abi_context_required"
                    if tls_inputs else "not_observed"
                ),
                "source": "abi_context.tls_base",
                "inputs": tls_inputs,
                "derive_from_expression_names": False,
                "authority": "ABI_C_tls_state_custody",
            },
            "implicit_inputs": implicit_materializations,
            "implicit_input_count": len(implicit_materializations),
            "return_contract": self._return_carrier_contract(
                signature,
                no_return=function_abi.get("no_return"),
            ),
            "no_return": bool(function_abi.get("no_return")),
            "runtime_helper": None,
            "runtime_helper_authority": "no_ABI_runtime_helper_assigned",
            "downstream_reinference_allowed": False,
            "authority": "PALlibrary_ABI_A_B_plus_PALSymbolResolver_ABI_C",
        }
        return entry_plan

    def _lifter_call_site_abi_contract_for(self, op):
        contract = getattr(op, "call_site_abi_contract", None)
        if isinstance(contract, dict):
            return dict(contract)

        evidence = getattr(op, "numeric_evidence", None)
        if isinstance(evidence, dict):
            contract = evidence.get("call_site_abi")
            if isinstance(contract, dict):
                return dict(contract)

        op_id = self._op_id(op)
        if op_id is not None:
            contract = self.lifter_call_site_abi_by_op.get(str(op_id))
            if isinstance(contract, dict):
                return dict(contract)

        for candidate in self.lifter_call_site_abi_contracts:
            if not isinstance(candidate, dict):
                continue
            if op_id is not None and str(candidate.get("op_id")) == str(op_id):
                return dict(candidate)
        return None

    @staticmethod
    def _signature_source_class(signature, prototype_authority=None):
        """Return normalized linkage evidence without consulting a name."""
        signature = signature if isinstance(signature, dict) else {}
        prototype_authority = (
            prototype_authority
            if isinstance(prototype_authority, dict) else {}
        )
        source = (
            signature.get("signature_source_class")
            or signature.get("signature_source")
            or prototype_authority.get("signature_source_class")
            or prototype_authority.get("signature_source")
        )
        return str(source or "").strip().lower()

    @staticmethod
    def _thunk_endpoint_signature(signature):
        """
        Accept richer future PALlibrary contracts while remaining compatible
        with v23b, which only records the physical Function's thunk flag.
        """
        signature = signature if isinstance(signature, dict) else {}
        for key in (
            "thunk_target_signature", "thunked_function_signature",
            "semantic_target_signature", "external_target_signature",
        ):
            value = signature.get(key)
            if isinstance(value, dict):
                return dict(value)
        return {}

    @classmethod
    def _call_linkage_contract(cls, lifter):
        """
        Classify the physical call target separately from its semantic
        endpoint.  A resolved PLT/thunk body is never silently counted as an
        ordinary internal function merely because Function.isExternal() is
        false for the body resident in the program address space.
        """
        lifter = lifter if isinstance(lifter, dict) else {}
        signature = lifter.get("target_signature")
        signature = dict(signature) if isinstance(signature, dict) else {}
        prototype = lifter.get("target_prototype_authority")
        prototype = dict(prototype) if isinstance(prototype, dict) else {}
        endpoint = cls._thunk_endpoint_signature(signature)

        direct = lifter.get("direct")
        resolved = lifter.get("target_resolved")
        physical_external = lifter.get("target_external")
        physical_thunk = bool(
            lifter.get("target_thunk") is True
            or signature.get("thunk") is True
        )
        source_class = cls._signature_source_class(signature, prototype)
        imported_source = source_class in {
            "imported", "import", "external", "dynamic", "library",
        }

        endpoint_external = endpoint.get("external")
        endpoint_resolved = bool(endpoint) or endpoint_external is not None
        endpoint_name = endpoint.get("name")
        endpoint_entry = endpoint.get("entry")

        semantic_external = None
        semantic_internal = None
        endpoint_status = "not_a_thunk"
        authority = "PALlibrary_target_Function_linkage"

        if direct is False:
            dispatch = "indirect_runtime_target"
            endpoint_status = "runtime_target_required"
        elif resolved is True and physical_external is True:
            dispatch = "external_resolved"
            semantic_external = True
            semantic_internal = False
            endpoint_status = "physical_target_is_external"
            endpoint_resolved = True
            endpoint_name = endpoint_name or lifter.get("target_name")
            endpoint_entry = endpoint_entry or lifter.get("target_entry")
        elif resolved is True and physical_thunk:
            semantic_internal = False
            if endpoint_external is True:
                dispatch = "external_via_thunk"
                semantic_external = True
                endpoint_status = "external_thunk_endpoint_proven"
                endpoint_resolved = True
                authority = "PALlibrary_thunk_endpoint_external_flag"
            elif endpoint_external is False:
                dispatch = "internal_via_thunk"
                semantic_external = False
                semantic_internal = True
                endpoint_status = "internal_thunk_endpoint_proven"
                endpoint_resolved = True
                authority = "PALlibrary_thunk_endpoint_external_flag"
            elif imported_source:
                dispatch = "external_via_import_thunk"
                semantic_external = True
                endpoint_status = "imported_thunk_endpoint_proven"
                endpoint_resolved = True
                endpoint_name = endpoint_name or lifter.get("target_name")
                authority = (
                    "PALlibrary_Function_thunk_plus_imported_signature_source"
                )
            else:
                dispatch = "resolved_thunk_endpoint_deferred"
                endpoint_status = "thunk_endpoint_unavailable"
                authority = "PALlibrary_Function_thunk_flag"
        elif resolved is True and physical_external is False:
            dispatch = "internal_resolved"
            semantic_external = False
            semantic_internal = True
            endpoint_status = "physical_non_thunk_internal_target"
        elif resolved is True:
            dispatch = "resolved_unknown_linkage"
            endpoint_status = "physical_linkage_unknown"
        elif direct is True:
            dispatch = "direct_unresolved_target"
            endpoint_status = "target_unresolved"
        else:
            dispatch = "unclassified_call_target"
            endpoint_status = "call_target_unclassified"

        return {
            "kind": "pal_compute_call_linkage_contract_abi_d_v23b",
            "version": cls.VERSION,
            "dispatch_class": dispatch,
            "physical_target_resolved": resolved,
            "physical_target_external": physical_external,
            "physical_target_thunk": physical_thunk,
            "semantic_external": semantic_external,
            "semantic_internal": semantic_internal,
            "semantic_endpoint_status": endpoint_status,
            "semantic_endpoint_resolved": endpoint_resolved,
            "semantic_endpoint_name": endpoint_name,
            "semantic_endpoint_entry": endpoint_entry,
            "signature_source_class": source_class or None,
            "downstream_may_treat_as_internal": semantic_internal is True,
            "authority": authority,
        }

    @classmethod
    def _call_dispatch_class(cls, lifter):
        return cls._call_linkage_contract(lifter).get("dispatch_class")

    @staticmethod
    def _call_materialization_for_carrier(carrier_kind):
        return {
            "gp_register": "write_abi_gp_register",
            "xmm_register": "write_abi_vector_register",
            "stack_overflow_argument": "write_overflow_argument_slot",
            "deferred_complex_classification": "deferred_complex_argument",
        }.get(str(carrier_kind or ""), "deferred_unclassified_carrier")

    def _build_call_site_abi_plan(self, op_key, op, compute_contract):
        lifter = self._lifter_call_site_abi_contract_for(op)
        input_sids = list(compute_contract.get("input_sids") or [])
        observed_argument_sids = [
            str(sid) for sid in input_sids[1:] if sid is not None
        ]
        output_sid = compute_contract.get("output_sid")
        output_width = compute_contract.get("output_width_bits")

        if not isinstance(lifter, dict):
            plan = {
                "kind": "pal_compute_call_site_abi_plan_v23",
                "plan_class": "call_site_abi_plan",
                "version": self.VERSION,
                "plan_id": "call_site:%s" % op_key,
                "op_key": op_key,
                "op_id": self._op_id(op),
                "block_addr": compute_contract.get("block_addr"),
                "opcode": compute_contract.get("opcode"),
                "status": "deferred_missing_lifter_call_abi_contract",
                "dispatch_class": "unclassified_call_target",
                "target_compatible": False,
                "arguments": [],
                "observed_argument_sids": observed_argument_sids,
                "result_contract": self._return_carrier_contract(
                    {}, output_sid=output_sid, output_width_bits=output_width
                ),
                "no_return": False,
                "runtime_helper": None,
                "runtime_helper_authority": "no_ABI_runtime_helper_assigned",
                "downstream_reinference_allowed": False,
                "authority": "missing_PALlibrary_call_site_ABI_contract",
            }
            warning = {
                "kind": "compute_call_abi_plan_warning_v23",
                "reason": "lifter_call_site_abi_contract_missing",
                "op_key": op_key,
                "op_id": self._op_id(op),
            }
            self.abi_plan_warnings.append(warning)
            if self.strict:
                raise ValueError(
                    "Missing PAL call-site ABI contract: %s" % self._op_id(op)
                )
            return plan

        allocation = lifter.get("carrier_allocation")
        allocation = dict(allocation) if isinstance(allocation, dict) else None
        allocations = list((allocation or {}).get("allocations") or [])
        argument_plans = []
        for fallback_index, item in enumerate(allocations):
            item = dict(item or {})
            index = item.get("index")
            if not isinstance(index, int):
                index = fallback_index
            carrier_kind = item.get("carrier_kind")
            argument_plans.append({
                "kind": "pal_compute_call_argument_plan_abi_d",
                "version": self.VERSION,
                "index": index,
                "source_sid": self._sid_text(item.get("sid")),
                "source_name": item.get("name"),
                "source_width_bits": item.get("width_bits"),
                "argument_class": item.get("argument_class"),
                "classification_authority": item.get("class_authority"),
                "parameter_region": item.get("parameter_region"),
                "carrier_kind": carrier_kind,
                "carrier": item.get("carrier"),
                "stack_slot": item.get("stack_slot"),
                "materialization": self._call_materialization_for_carrier(
                    carrier_kind
                ),
                "constant": bool(item.get("constant")),
                "constant_value": item.get("constant_value"),
                "runtime_helper": None,
                "authority": (allocation or {}).get("authority"),
            })

        allocated_sids = [
            item.get("source_sid") for item in argument_plans
            if item.get("source_sid") is not None
        ]
        argument_sid_match = allocated_sids == observed_argument_sids
        deferred_complex = int(
            (allocation or {}).get("deferred_complex_arguments") or 0
        )
        allocation_complete = bool(
            allocation is not None
            and len(argument_plans) == len(observed_argument_sids)
            and argument_sid_match
            and deferred_complex == 0
            and all(
                item.get("carrier_kind")
                in ("gp_register", "xmm_register", "stack_overflow_argument")
                for item in argument_plans
            )
        )

        linkage = self._call_linkage_contract(lifter)
        dispatch_class = linkage.get("dispatch_class")
        arity_status = lifter.get("arity_status")
        arity_valid = arity_status not in (
            "missing_fixed_arguments", "fixed_arity_mismatch"
        )
        prototype_deferred = arity_status in (
            "target_unresolved", "target_prototype_unresolved",
            "target_prototype_conflicting", None,
        )
        prototype_compatibility = (
            "incompatible" if not arity_valid
            else "deferred" if prototype_deferred
            else "compatible"
        )
        internal = linkage.get("semantic_internal") is True
        external = linkage.get("semantic_external") is True
        target_transport_compatible = bool(
            allocation_complete and arity_valid
        )
        dispatch_deferred = dispatch_class in (
            "direct_unresolved_target", "indirect_runtime_target",
            "resolved_unknown_linkage", "unclassified_call_target",
            "resolved_thunk_endpoint_deferred",
        )
        if not target_transport_compatible or prototype_compatibility == "incompatible":
            target_compatibility_status = "incompatible"
            target_compatible = False
        elif dispatch_deferred or prototype_compatibility == "deferred":
            target_compatibility_status = "deferred"
            target_compatible = None
        else:
            target_compatibility_status = "compatible"
            target_compatible = True

        if not allocation_complete:
            status = "deferred_incomplete_lifter_carrier_allocation"
        elif not arity_valid:
            status = "invalid_target_arity"
        elif dispatch_deferred:
            status = "deferred_target_dispatch"
        else:
            status = "ready"

        target_signature = lifter.get("target_signature")
        target_signature = (
            dict(target_signature) if isinstance(target_signature, dict) else {}
        )
        no_return = bool(
            lifter.get("target_no_return") is True
            or target_signature.get("no_return") is True
        )
        target_entry = lifter.get("target_entry")
        backend = dict(lifter.get("abi_backend") or {})
        result_contract = self._return_carrier_contract(
            target_signature,
            output_sid=output_sid,
            output_width_bits=output_width,
            no_return=no_return,
        )

        plan = {
            "kind": "pal_compute_call_site_abi_plan_v23",
            "plan_class": "call_site_abi_plan",
            "version": self.VERSION,
            "plan_id": "call_site:%s" % op_key,
            "op_key": op_key,
            "op_id": self._op_id(op),
            "block_addr": compute_contract.get("block_addr"),
            "opcode": compute_contract.get("opcode"),
            "status": status,
            "dispatch_class": dispatch_class,
            "dispatch_policy": (
                "PAL_internal_dispatch"
                if internal else "external_ABI_dispatch"
                if external else "thunk_endpoint_dispatch"
                if linkage.get("physical_target_thunk")
                else "runtime_target_dispatch"
            ),
            "linkage_contract": linkage,
            "external_call_abi_classification": {
                "external": linkage.get("semantic_external"),
                "classification": dispatch_class,
                "target_resolved": lifter.get("target_resolved"),
                "physical_target_external": lifter.get("target_external"),
                "physical_target_thunk": linkage.get(
                    "physical_target_thunk"
                ),
                "semantic_endpoint_status": linkage.get(
                    "semantic_endpoint_status"
                ),
                "authority": linkage.get("authority"),
            },
            "target": {
                "name": lifter.get("target_name"),
                "entry": target_entry,
                "resolved": lifter.get("target_resolved"),
                "external": linkage.get("semantic_external"),
                "physical_external": lifter.get("target_external"),
                "thunk": linkage.get("physical_target_thunk"),
                "semantic_endpoint_status": linkage.get(
                    "semantic_endpoint_status"
                ),
                "semantic_endpoint_name": linkage.get(
                    "semantic_endpoint_name"
                ),
                "semantic_endpoint_entry": linkage.get(
                    "semantic_endpoint_entry"
                ),
                "calling_convention": lifter.get("target_calling_convention"),
                "prototype_authority": dict(
                    lifter.get("target_prototype_authority") or {}
                ),
                "variadic": lifter.get("target_variadic"),
                "fixed_parameter_count": lifter.get(
                    "target_fixed_parameter_count"
                ),
                "entry_plan_lookup_key": (
                    "function_entry:%s" % target_entry
                    if target_entry is not None else None
                ),
            },
            "abi_backend": backend,
            "arguments": argument_plans,
            "argument_count": len(argument_plans),
            "observed_argument_sids": observed_argument_sids,
            "argument_sid_match": argument_sid_match,
            "carrier_allocation_status": (
                "complete" if allocation_complete else "deferred"
            ),
            "carrier_allocation_authority": (allocation or {}).get("authority"),
            "gp_registers_used": (allocation or {}).get("gp_registers_used"),
            "xmm_registers_used": (allocation or {}).get("xmm_registers_used"),
            "stack_slots_used": (allocation or {}).get("stack_slots_used"),
            "caller_variadic_al": {
                "required": lifter.get("target_variadic") is True,
                "value": (allocation or {}).get("variadic_al_value"),
                "destination": "abi_context.variadic_xmm_count",
                "materialization": "write_AL_before_call",
                "authority": "PALlibrary_carrier_allocation",
            },
            "arity_status": arity_status,
            "arity_authority": lifter.get("arity_authority"),
            "target_compatibility": {
                "internal_target": internal,
                "carrier_transport_compatible": target_transport_compatible,
                "prototype_compatibility": prototype_compatibility,
                "aggregate_status": target_compatibility_status,
                "entry_plan_lookup_required": internal,
                "entry_plan_lookup_key": (
                    "function_entry:%s" % target_entry
                    if internal and target_entry is not None else None
                ),
                "authority": "lifter_carrier_allocation_plus_target_arity_contract",
            },
            "target_compatibility_status": target_compatibility_status,
            "target_compatible": target_compatible,
            "result_contract": result_contract,
            "result_width_bits": result_contract.get(
                "effective_result_width_bits"
            ),
            "return_carrier_contract": result_contract,
            "no_return": no_return,
            "control_effect": "terminates_path" if no_return else "returns_to_caller",
            "runtime_helper": None,
            "runtime_helper_authority": "no_ABI_runtime_helper_assigned",
            "downstream_reinference_allowed": False,
            "source_call_site_abi_contract": lifter,
            "authority": "PALlibrary_call_site_ABI_contract_only",
        }

        if not argument_sid_match:
            self.abi_plan_warnings.append({
                "kind": "compute_call_abi_plan_warning_v23",
                "reason": "call_argument_sid_disagreement",
                "op_key": op_key,
                "observed_argument_sids": observed_argument_sids,
                "allocated_argument_sids": allocated_sids,
            })
        if not arity_valid:
            self.abi_plan_warnings.append({
                "kind": "compute_call_abi_plan_warning_v23",
                "reason": "target_arity_incompatible",
                "op_key": op_key,
                "target": lifter.get("target_name"),
                "arity_status": arity_status,
            })
        if internal and not target_transport_compatible:
            self.abi_plan_warnings.append({
                "kind": "compute_call_abi_plan_warning_v23",
                "reason": "internal_target_transport_plan_incompatible",
                "op_key": op_key,
                "target": lifter.get("target_name"),
                "allocation_complete": allocation_complete,
                "arity_status": arity_status,
            })
        if dispatch_class == "resolved_thunk_endpoint_deferred":
            self.abi_plan_events.append({
                "kind": "compute_thunk_endpoint_deferred_v23b",
                "op_key": op_key,
                "target": lifter.get("target_name"),
                "target_entry": target_entry,
                "physical_target_thunk": True,
                "reason": "PALlibrary_has_thunk_flag_but_no_semantic_endpoint",
                "authority": "PALlibrary_Function_thunk_flag",
            })
        if self.strict and plan.get("status") not in ("ready",):
            raise ValueError(
                "Unresolved PAL call-site ABI plan: %s" % self._op_id(op)
            )
        return plan

    def _count_abi_runtime_helper_assignments(self, value):
        if isinstance(value, dict):
            count = 0
            for key, child in value.items():
                if key == "runtime_helper" and child is not None:
                    count += 1
                else:
                    count += self._count_abi_runtime_helper_assignments(child)
            return count
        if isinstance(value, (list, tuple)):
            return sum(
                self._count_abi_runtime_helper_assignments(item)
                for item in value
            )
        return 0

    @staticmethod
    def _block_address_value(value):
        if isinstance(value, int):
            return value
        address = getattr(value, "addr", None)
        return address if isinstance(address, int) else None

    def _block_successor_addresses(self, block):
        addresses = []
        for successor in list(getattr(block, "successors", []) or []):
            address = self._block_address_value(successor)
            if address is not None and address not in addresses:
                addresses.append(address)
        return addresses

    def _entry_block_address(self, blocks_by_addr):
        function_entry = getattr(self.func, "function_address", None)
        if function_entry in blocks_by_addr:
            return function_entry

        roots = []
        for address, block in blocks_by_addr.items():
            predecessors = list(getattr(block, "predecessors", []) or [])
            if not predecessors:
                roots.append(address)
        return roots[0] if len(roots) == 1 else None

    def _reachable_block_addresses(
        self, blocks_by_addr, entry_addr, terminal_blocks=None
    ):
        if entry_addr not in blocks_by_addr:
            return set()
        terminal_blocks = set(terminal_blocks or [])
        reached = set()
        pending = [entry_addr]
        while pending:
            address = pending.pop()
            if address in reached or address not in blocks_by_addr:
                continue
            reached.add(address)
            if address in terminal_blocks:
                continue
            for successor in self._block_successor_addresses(
                blocks_by_addr[address]
            ):
                if successor not in reached:
                    pending.append(successor)
        return reached

    @staticmethod
    def _return_transport_width(contract):
        contract = contract if isinstance(contract, dict) else {}
        width = contract.get("return_transport_width_bits")
        if not isinstance(width, int) or width <= 0:
            width = contract.get("return_value_width_bits")
        return width if isinstance(width, int) and width > 0 else None

    @staticmethod
    def _return_boundary_view(contract):
        return {
            "block_addr": contract.get("block_addr"),
            "return_value_sid": contract.get("return_value_sid"),
            "return_value_width_bits": contract.get(
                "return_value_width_bits"
            ),
            "return_transport_width_bits": contract.get(
                "return_transport_width_bits"
            ),
            "return_logical_width_bits": contract.get(
                "return_logical_width_bits"
            ),
            "return_declared_view": contract.get("return_declared_view"),
            "return_boundary_authority": contract.get(
                "return_boundary_authority"
            ),
            "return_reachability": contract.get("return_reachability"),
            "reachable_return": contract.get("reachable_return"),
            "execution_suppressed": bool(
                contract.get("execution_suppressed")
            ),
            "emission_policy": contract.get("emission_policy"),
            "cut_by_no_return_blocks": list(
                contract.get("cut_by_no_return_blocks") or []
            ),
            "cut_by_no_return_call_op_keys": list(
                contract.get("cut_by_no_return_call_op_keys") or []
            ),
        }

    @staticmethod
    def _declared_return_is_default_unknown(return_contract):
        return_contract = (
            return_contract if isinstance(return_contract, dict) else {}
        )
        declared = return_contract.get("declared_return")
        declared = declared if isinstance(declared, dict) else {}
        name = str(
            declared.get("name") or declared.get("display_name") or ""
        ).strip().lower()
        class_name = str(declared.get("class_name") or "").strip().lower()
        return (
            name in ("", "undefined", "undefined1", "default")
            or "defaultdatatype" in class_name
            or "undefined" in class_name
        )

    def _suppress_unreachable_return_boundary(
        self, contract, reason, cut_blocks, cut_op_keys
    ):
        contract["original_status_before_reachability"] = contract.get(
            "status"
        )
        contract["original_runtime_helper_before_reachability"] = (
            contract.get("runtime_helper")
        )
        contract["return_reachability"] = reason
        contract["reachable_return"] = False
        contract["execution_suppressed"] = True
        contract["status"] = "metadata_only"
        contract["runtime_helper"] = None
        contract["emits_runtime_helper"] = False
        contract["c_compute_filter"] = False
        contract["emission_policy"] = (
            "suppress_unreachable_return_after_no_return"
            if "no_return" in str(reason)
            else "suppress_cfg_unreachable_return"
        )
        contract["cut_by_no_return_blocks"] = sorted(set(cut_blocks or []))
        contract["cut_by_no_return_call_op_keys"] = sorted(
            set(str(key) for key in list(cut_op_keys or []))
        )
        contract["hazards"] = list(dict.fromkeys(
            list(contract.get("hazards") or [])
            + ["unreachable_return_boundary_suppressed"]
        ))

    def _reconcile_function_return_boundaries(self):
        """
        Determine which raw RETURN transports remain executable after proven
        no-return calls.  Width reconciliation consumes only those reachable
        boundaries; synthetic continuations remain visible as metadata but can
        no longer become emitted returns.
        """
        boundaries = [
            contract
            for contracts in self.control_contracts_by_block.values()
            for contract in list(contracts or [])
            if contract.get("category") == "return_boundary"
        ]
        blocks_by_addr = {
            self._block_addr(block): block
            for block in self._iter_blocks()
            if self._block_addr(block) is not None
        }
        entry_addr = self._entry_block_address(blocks_by_addr)
        no_return_plans = [
            plan for plan in self.call_site_abi_plans_by_op.values()
            if plan.get("no_return") is True
        ]
        no_return_blocks = set(
            plan.get("block_addr") for plan in no_return_plans
            if plan.get("block_addr") is not None
        )
        no_return_keys_by_block = {}
        for plan in no_return_plans:
            block_addr = plan.get("block_addr")
            if block_addr is None:
                continue
            no_return_keys_by_block.setdefault(block_addr, []).append(
                plan.get("op_key")
            )

        cfg_evidence_available = entry_addr is not None
        raw_reachable = self._reachable_block_addresses(
            blocks_by_addr, entry_addr, terminal_blocks=set()
        ) if cfg_evidence_available else set()
        executable_reachable = self._reachable_block_addresses(
            blocks_by_addr, entry_addr, terminal_blocks=no_return_blocks
        ) if cfg_evidence_available else set()

        reachable = []
        unreachable = []
        deferred = []
        for contract in boundaries:
            block_addr = contract.get("block_addr")
            same_block_no_return = block_addr in no_return_blocks
            cut_blocks = []
            cut_op_keys = []

            if same_block_no_return:
                cut_blocks = [block_addr]
                cut_op_keys = no_return_keys_by_block.get(block_addr, [])
                reason = "unreachable_after_no_return_in_same_block"
                self._suppress_unreachable_return_boundary(
                    contract, reason, cut_blocks, cut_op_keys
                )
                unreachable.append(contract)
                continue

            if cfg_evidence_available and block_addr not in raw_reachable:
                reason = "unreachable_in_raw_cfg"
                self._suppress_unreachable_return_boundary(
                    contract, reason, [], []
                )
                unreachable.append(contract)
                continue

            if (
                cfg_evidence_available
                and block_addr in raw_reachable
                and block_addr not in executable_reachable
            ):
                for no_return_block in sorted(no_return_blocks):
                    downstream = self._reachable_block_addresses(
                        blocks_by_addr, no_return_block, terminal_blocks=set()
                    )
                    if block_addr in downstream:
                        cut_blocks.append(no_return_block)
                        cut_op_keys.extend(
                            no_return_keys_by_block.get(no_return_block, [])
                        )
                reason = "unreachable_after_no_return_cfg_cut"
                self._suppress_unreachable_return_boundary(
                    contract, reason, cut_blocks, cut_op_keys
                )
                unreachable.append(contract)
                continue

            if cfg_evidence_available:
                contract["return_reachability"] = "reachable"
                contract["reachable_return"] = True
                contract["execution_suppressed"] = False
                contract["emission_policy"] = "emit_reachable_return_boundary"
                contract["cut_by_no_return_blocks"] = []
                contract["cut_by_no_return_call_op_keys"] = []
                reachable.append(contract)
            else:
                contract["return_reachability"] = "deferred_cfg_unavailable"
                contract["reachable_return"] = None
                contract["execution_suppressed"] = False
                contract["emission_policy"] = (
                    "preserve_return_pending_reachability"
                )
                deferred.append(contract)

        reachable_widths = sorted(set(
            width for width in (
                self._return_transport_width(contract)
                for contract in reachable
            ) if width is not None
        ))
        entry_plan = self.function_entry_abi_plan
        return_contract = dict(entry_plan.get("return_contract") or {})
        prototype = dict(entry_plan.get("prototype_authority") or {})
        prototype_status = prototype.get("status")
        default_unknown = self._declared_return_is_default_unknown(
            return_contract
        )
        declared_authoritative = bool(
            not default_unknown
            and prototype_status in ("authoritative_zero", "authoritative_n")
        )
        reported_declared_width = return_contract.get("declared_width_bits")
        return_contract["reported_declared_width_bits"] = (
            reported_declared_width
        )
        return_contract["declared_width_authoritative"] = (
            declared_authoritative
        )
        if not declared_authoritative:
            return_contract["declared_width_bits"] = None
            return_contract["declared_return_evidence_status"] = (
                "non_authoritative_default_or_unresolved_prototype"
            )
        else:
            return_contract["declared_return_evidence_status"] = (
                "authoritative_function_prototype"
            )

        carrier_pieces = list(return_contract.get("carrier_pieces") or [])
        if return_contract.get("no_return") is True:
            return_contract["status"] = "no_return"
            return_contract["effective_result_width_bits"] = None
            return_contract["logical_result_width_bits"] = None
            return_contract["transport_width_bits"] = None
            return_contract["normalization"] = None
        elif len(reachable_widths) == 1:
            transport_width = reachable_widths[0]
            logical_width = (
                reported_declared_width
                if declared_authoritative
                and isinstance(reported_declared_width, int)
                and reported_declared_width > 0
                else transport_width
            )
            return_contract["transport_width_bits"] = transport_width
            return_contract["logical_result_width_bits"] = logical_width
            return_contract["effective_result_width_bits"] = logical_width
            return_contract["reachable_return_widths"] = reachable_widths
            return_contract["normalization"] = {
                "mode": "mask_to_output_width",
                "width_bits": logical_width,
                "mask": self._mask_for_width(logical_width),
            }
            return_contract["status"] = (
                "physical_return_carrier_proven"
                if carrier_pieces
                else "return_width_proven_carrier_deferred"
            )
            return_contract["authority"] = (
                "reachable_raw_return_transport_plus_authoritative_prototype"
                if declared_authoritative
                else "reachable_raw_return_transport"
            )
        elif len(reachable_widths) > 1:
            return_contract["status"] = "reachable_return_width_conflict"
            return_contract["transport_width_bits"] = None
            return_contract["logical_result_width_bits"] = (
                reported_declared_width if declared_authoritative else None
            )
            return_contract["effective_result_width_bits"] = (
                reported_declared_width if declared_authoritative else None
            )
            return_contract["reachable_return_widths"] = reachable_widths
            return_contract["normalization"] = None
            self.abi_plan_warnings.append({
                "kind": "compute_return_boundary_warning_v23b",
                "reason": "reachable_return_width_conflict",
                "function": getattr(self.func, "func_name", None),
                "reachable_return_widths": reachable_widths,
            })
        elif not deferred:
            return_contract["status"] = "no_reachable_return_boundary"
            return_contract["transport_width_bits"] = None
            return_contract["logical_result_width_bits"] = (
                reported_declared_width if declared_authoritative else None
            )
            return_contract["effective_result_width_bits"] = (
                reported_declared_width if declared_authoritative else None
            )
            return_contract["reachable_return_widths"] = []
            return_contract["normalization"] = None
        else:
            return_contract["status"] = "return_reachability_deferred"
            return_contract["reachable_return_widths"] = []

        return_contract["reachable_return_boundary_count"] = len(reachable)
        return_contract["unreachable_return_boundary_count"] = len(
            unreachable
        )
        return_contract["deferred_return_boundary_count"] = len(deferred)
        entry_plan["return_contract"] = return_contract

        all_views = [self._return_boundary_view(item) for item in boundaries]
        reachable_views = [
            self._return_boundary_view(item) for item in reachable
        ]
        unreachable_views = [
            self._return_boundary_view(item) for item in unreachable
        ]
        deferred_views = [
            self._return_boundary_view(item) for item in deferred
        ]
        entry_plan["return_boundaries"] = all_views
        entry_plan["return_boundary_count"] = len(all_views)
        entry_plan["reachable_return_boundaries"] = reachable_views
        entry_plan["reachable_return_boundary_count"] = len(reachable_views)
        entry_plan["unreachable_return_boundaries"] = unreachable_views
        entry_plan["unreachable_return_boundary_count"] = len(
            unreachable_views
        )
        entry_plan["deferred_return_boundaries"] = deferred_views
        entry_plan["deferred_return_boundary_count"] = len(deferred_views)

        reconciliation = {
            "kind": "pal_compute_return_boundary_reconciliation_v23b",
            "version": self.VERSION,
            "function": getattr(self.func, "func_name", None),
            "entry_block_addr": entry_addr,
            "cfg_evidence_available": cfg_evidence_available,
            "no_return_terminating_blocks": sorted(no_return_blocks),
            "no_return_call_op_keys": sorted(
                str(plan.get("op_key")) for plan in no_return_plans
                if plan.get("op_key") is not None
            ),
            "return_boundaries": len(boundaries),
            "reachable_return_boundaries": len(reachable),
            "unreachable_return_boundaries": len(unreachable),
            "deferred_return_boundaries": len(deferred),
            "reachable_return_widths": reachable_widths,
            "width_reconciled": len(reachable_widths) <= 1,
            "synthetic_no_return_continuations_suppressed": sum(
                1 for item in unreachable
                if "no_return" in str(item.get("return_reachability"))
            ),
            "rule": (
                "traverse_CFG_with_no_return_blocks_as_terminal_then_"
                "reconcile_reachable_raw_return_transports_only"
            ),
        }
        self.return_boundary_reconciliation = reconciliation
        self.abi_plan_events.append(reconciliation)
        return reconciliation

    def _finalize_abi_plan_inventory(self):
        entry = dict(self.function_entry_abi_plan or {})
        calls = list(self.call_site_abi_plans_by_op.values())
        call_statuses = {}
        dispatch_classes = {}
        for plan in calls:
            status = str(plan.get("status") or "unknown")
            dispatch = str(plan.get("dispatch_class") or "unknown")
            call_statuses[status] = call_statuses.get(status, 0) + 1
            dispatch_classes[dispatch] = dispatch_classes.get(dispatch, 0) + 1

        internal = [
            plan for plan in calls
            if (plan.get("linkage_contract") or {}).get(
                "semantic_internal"
            ) is True
        ]
        incompatible_internal = [
            plan for plan in internal if plan.get("target_compatible") is False
        ]
        deferred_internal = [
            plan for plan in internal if plan.get("target_compatible") is None
        ]
        transport_incompatible_internal = [
            plan for plan in internal
            if (plan.get("target_compatibility") or {}).get(
                "carrier_transport_compatible"
            ) is not True
        ]
        thunk_calls = [
            plan for plan in calls
            if (plan.get("linkage_contract") or {}).get(
                "physical_target_thunk"
            ) is True
        ]
        thunk_misclassified_internal = [
            plan for plan in thunk_calls
            if plan.get("dispatch_class") == "internal_resolved"
        ]
        compatibility_overclaims = [
            plan for plan in calls
            if plan.get("target_compatible") is True
            and plan.get("target_compatibility_status") != "compatible"
        ]
        implicit = list(entry.get("implicit_inputs") or [])
        unsupported_implicit = [
            item for item in implicit
            if item.get("unsupported") is True
            or str(item.get("status") or "").startswith("unsupported")
        ]
        helper_assignments = (
            self._count_abi_runtime_helper_assignments(entry)
            + self._count_abi_runtime_helper_assignments(calls)
        )
        call_compute_contracts = [
            contract for contract in self.compute_contracts_by_op.values()
            if contract.get("opcode") in self.CALL_OPS
        ]
        missing_call_plans = [
            contract.get("op_key") for contract in call_compute_contracts
            if contract.get("op_key") not in self.call_site_abi_plans_by_op
        ]

        inventory = {
            "kind": "pal_compute_abi_plan_inventory_v23",
            "version": self.VERSION,
            "function": getattr(self.func, "func_name", None),
            "entry_plan_present": bool(entry),
            "entry_plan_status": entry.get("status"),
            "fixed_arguments": len(entry.get("fixed_arguments", []) or []),
            "implicit_inputs": len(implicit),
            "implicit_inputs_unsupported": len(unsupported_implicit),
            "call_compute_contracts": len(call_compute_contracts),
            "call_site_plans": len(calls),
            "call_sites_without_plan": len(missing_call_plans),
            "call_statuses": call_statuses,
            "dispatch_classes": dispatch_classes,
            "internal_calls": len(internal),
            "internal_calls_with_target_compatible_plan": sum(
                1 for plan in internal if plan.get("target_compatible") is True
            ),
            "internal_calls_without_target_compatible_plan": len(
                incompatible_internal + deferred_internal
            ),
            "internal_calls_with_deferred_target_compatibility": len(
                deferred_internal
            ),
            "internal_calls_with_incompatible_target": len(
                incompatible_internal
            ),
            "internal_calls_without_transport_plan": len(
                transport_incompatible_internal
            ),
            "external_calls": sum(
                1 for plan in calls
                if (plan.get("linkage_contract") or {}).get(
                    "semantic_external"
                ) is True
            ),
            "thunk_calls": len(thunk_calls),
            "external_via_thunk_calls": sum(
                1 for plan in thunk_calls
                if (plan.get("linkage_contract") or {}).get(
                    "semantic_external"
                ) is True
            ),
            "thunk_endpoint_deferred_calls": sum(
                1 for plan in thunk_calls
                if plan.get("dispatch_class")
                == "resolved_thunk_endpoint_deferred"
            ),
            "thunk_calls_misclassified_internal": len(
                thunk_misclassified_internal
            ),
            "target_compatibility_overclaims": len(
                compatibility_overclaims
            ),
            "no_return_calls": sum(
                1 for plan in calls if plan.get("no_return") is True
            ),
            "result_carrier_contracts": sum(
                1 for plan in calls
                if isinstance(plan.get("result_contract"), dict)
            ),
            "abi_runtime_helper_assignments": helper_assignments,
            "warnings": len(self.abi_plan_warnings),
            "acceptance_gates": {
                "every_emitted_function_has_entry_plan": bool(entry),
                "every_call_has_call_site_plan": not missing_call_plans,
                "every_internal_call_has_target_compatible_plan": not (
                    incompatible_internal or deferred_internal
                ),
                "every_internal_call_has_carrier_transport_plan": not (
                    transport_incompatible_internal
                ),
                "no_resolved_thunk_misclassified_internal": not (
                    thunk_misclassified_internal
                ),
                "no_target_compatibility_overclaim": not (
                    compatibility_overclaims
                ),
                "no_implicit_input_is_unsupported": not unsupported_implicit,
                "no_runtime_helper_assigned_by_ABI_guesswork": helper_assignments == 0,
            },
            "return_boundary_reconciliation": dict(
                self.return_boundary_reconciliation or {}
            ),
            "rule": (
                "ABI_A_B_C_authority_only_thunk_endpoint_and_compatibility_"
                "tri_state_no_downstream_argument_reinference"
            ),
        }
        self.abi_plan_inventory = inventory
        self.abi_plan_events.append(inventory)
        return inventory

    # -------------------------------------------------
    # RESOLVER STORAGE-CUSTODY ACCESSORS
    # -------------------------------------------------

    def _family_for_key_or_id(self, value):
        if value is None:
            return None

        family = self.resolver_storage_families.get(value)
        if isinstance(family, dict):
            return family

        family = self.resolver_storage_families.get(str(value))
        if isinstance(family, dict):
            return family

        for candidate in self.resolver_storage_families.values():
            if not isinstance(candidate, dict):
                continue
            if str(candidate.get("family_id")) == str(value):
                return candidate
        return None

    def _storage_family_for_sid(self, sid):
        if sid is None:
            return None
        key = self.resolver_storage_family_by_sid.get(str(sid))
        if key is None:
            return None
        return self._family_for_key_or_id(key)

    def _storage_binding_for_sid(self, sid, role=None):
        family = self._storage_family_for_sid(sid)
        if not isinstance(family, dict):
            return None

        member_sids = list(family.get("member_sids", []) or [])
        entry_sids = list(family.get("entry_sids", []) or [])
        transition_outputs = list(
            family.get("transition_output_sids", []) or []
        )
        initializer = self.resolver_parameter_initializer_by_output_sid.get(
            str(sid)
        )

        if role is None:
            if sid in transition_outputs:
                role = "custody_transition_output"
            elif initializer is not None:
                role = "parameter_storage_initializer"
            elif sid in entry_sids:
                role = "storage_family_entry"
            elif sid in member_sids:
                role = "storage_family_state"
            else:
                role = "storage_family_reference"

        return {
            "kind": "pal_compute_storage_binding_v22d",
            "version": self.VERSION,
            "sid": sid,
            "family_id": family.get("family_id"),
            "high_identity_key": family.get("high_identity_key"),
            "high_name": family.get("high_name"),
            "classification": family.get("classification"),
            "role": role,
            "address_tied": bool(family.get("address_tied")),
            "persistent": bool(family.get("persistent")),
            "address_escape_barrier": bool(
                family.get("address_escape_barrier")
                or str(sid) in self.resolver_escape_barrier_sids
            ),
            "ordinary_c_local_candidate": bool(
                family.get("ordinary_c_local_candidate")
            ),
            "entry_state": sid in entry_sids,
            "custody_transition_output": sid in transition_outputs,
            "parameter_initializer": initializer is not None,
            "runtime_representation": self.REPRESENTATION,
            "authority": "PALSymbolResolver_storage_family_v22c",
        }

    def _resolver_indirect_transition_for(self, op, output):
        transition = getattr(op, "resolver_indirect_transition", None)
        if isinstance(transition, dict):
            return transition

        output_sid = self._sid(output)
        if output_sid is not None:
            transition = self.resolver_indirect_by_output_sid.get(str(output_sid))
            if transition is None:
                transition = self.resolver_indirect_by_output_sid.get(output_sid)
            if isinstance(transition, dict):
                return transition

        op_id = self._op_id(op)
        for candidate in self.resolver_indirect_transitions:
            if not isinstance(candidate, dict):
                continue
            if op_id is not None and str(candidate.get("transition_id")) == str(op_id):
                return candidate
            if (
                output_sid is not None
                and str(candidate.get("output_sid")) == str(output_sid)
            ):
                return candidate
        return None

    def _lifter_indirect_contract_for(self, op, output):
        contract = getattr(op, "indirect_custody_contract", None)
        if isinstance(contract, dict):
            return contract

        evidence = getattr(op, "numeric_evidence", None)
        if isinstance(evidence, dict):
            contract = evidence.get("indirect_custody")
            if isinstance(contract, dict):
                return contract

        contract = getattr(output, "indirect_custody_contract", None)
        return contract if isinstance(contract, dict) else None

    def _effect_owner_binding(self, transition, lifter_contract):
        transition = transition if isinstance(transition, dict) else {}
        lifter_contract = (
            lifter_contract if isinstance(lifter_contract, dict) else {}
        )
        return {
            "kind": "pal_compute_indirect_effect_owner_binding_v22d",
            "version": self.VERSION,
            "owner_ref_id": transition.get("owner_ref_id", lifter_contract.get("owner_ref_id")),
            "owner_ref_hex": transition.get("owner_ref_hex", lifter_contract.get("owner_ref_hex")),
            "owner_resolved": transition.get("owner_resolved", lifter_contract.get("owner_resolved")),
            "owner_op_id": transition.get("owner_op_id", lifter_contract.get("owner_op_id")),
            "owner_opcode": transition.get("owner_opcode", lifter_contract.get("owner_opcode")),
            "owner_category": transition.get("owner_category", lifter_contract.get("owner_category")),
            "owner_block_addr": transition.get("owner_block_addr", lifter_contract.get("owner_block_addr")),
            "owner_input_sids": list(lifter_contract.get("owner_input_sids", []) or []),
            "owner_output_sid": lifter_contract.get("owner_output_sid"),
            "owner_details": dict(lifter_contract.get("owner_details") or {}),
            "owner_compute_op_key": None,
            "authority": "PALlibrary_getOpRef_v22",
        }

    def _declared_return_view(self, value_var):
        """Normalize PALLifter's function return type for the ABI boundary."""
        signature = getattr(self.func, "function_signature", {}) or {}
        image = signature.get("return") if isinstance(signature, dict) else None
        if not isinstance(image, dict):
            return None

        # Typedef images retain their base type.  Prefer explicit outer facts,
        # then fill missing axes from the base image without changing evidence.
        base = image.get("base_type")
        base = base if isinstance(base, dict) else {}

        name = str(
            image.get("display_name")
            or image.get("name")
            or base.get("display_name")
            or base.get("name")
            or ""
        ).strip()
        name_lower = name.lower()

        kind = image.get("kind_hint") or base.get("kind_hint")
        width = image.get("width_bits") or base.get("width_bits")
        signed = image.get("signed")
        if not isinstance(signed, bool):
            signed = base.get("signed")

        if not isinstance(width, int) or width <= 0:
            return None

        if kind == "pointer":
            domain = "pointer"
            signedness = "unsigned"
            canonical = "ptr%s" % width
        elif kind == "boolean":
            domain = "boolean"
            signedness = "unsigned"
            canonical = "bool%s" % width
        elif kind == "integer":
            domain = "integer"
            if isinstance(signed, bool):
                signedness = "signed" if signed else "unsigned"
            elif "unsigned" in name_lower or name_lower.startswith("uint"):
                signedness = "unsigned"
            elif name_lower and "undefined" not in name_lower:
                signedness = "signed"
            else:
                return None
            canonical = ("s" if signedness == "signed" else "u") + str(width)
        else:
            # Do not promote Ghidra undefinedN placeholders into ABI truth.
            return None

        return {
            "sid": self._sid(value_var),
            "width_bits": width,
            "domain": domain,
            "signedness": signedness,
            "canonical_type": canonical,
            "declared_type": name or None,
            "source": "function_signature_return_type",
        }

    # -------------------------------------------------
    # INPUT VIEW REQUIREMENTS
    # -------------------------------------------------

    def _required_interpretations(self, opcode, input_count):
        required = ["raw_bits"] * input_count

        if opcode in ("INT_SDIV", "INT_SREM", "INT_SLESS", "INT_SLESSEQUAL"):
            return ["signed"] * input_count

        if opcode in ("INT_DIV", "INT_REM", "INT_LESS", "INT_LESSEQUAL"):
            return ["unsigned"] * input_count

        if opcode == "INT_SRIGHT":
            if input_count >= 1:
                required[0] = "signed"
            if input_count >= 2:
                required[1] = "shift_count"
            return required

        if opcode == "INT_RIGHT":
            if input_count >= 1:
                required[0] = "unsigned"
            if input_count >= 2:
                required[1] = "shift_count"
            return required

        if opcode == "INT_LEFT":
            if input_count >= 1:
                required[0] = "raw_bits"
            if input_count >= 2:
                required[1] = "shift_count"
            return required

        if opcode == "INT_SEXT":
            if input_count:
                required[0] = "signed"
            return required

        if opcode == "INT_ZEXT":
            if input_count:
                required[0] = "unsigned"
            return required

        if opcode == "SUBPIECE":
            if input_count >= 1:
                required[0] = "raw_bits"
            if input_count >= 2:
                required[1] = "byte_offset"
            return required

        if opcode == "PIECE":
            return ["raw_bits"] * input_count

        if opcode in ("INT_EQUAL", "INT_NOTEQUAL"):
            return ["raw_bits"] * input_count

        if opcode in self.BOOLEAN_OPS:
            return ["boolean"] * input_count

        if opcode == "LOAD":
            if input_count >= 1:
                required[0] = "address_space_id"
            if input_count >= 2:
                required[1] = "pointer"
            return required

        if opcode == "STORE":
            if input_count >= 1:
                required[0] = "address_space_id"
            if input_count >= 2:
                required[1] = "pointer"
            if input_count >= 3:
                required[2] = "raw_bits"
            return required

        if opcode == "INDIRECT":
            if input_count >= 1:
                required[0] = "storage_state_before_effect"
            if input_count >= 2:
                required[1] = "effect_owner_iop_reference_metadata"
            return required

        if opcode in self.CALL_OPS:
            if input_count:
                required[0] = "call_target"
            for index in range(1, input_count):
                required[index] = "declared_view"
            return required

        if opcode in self.POINTER_OPS:
            if input_count:
                required[0] = "pointer"
            for index in range(1, input_count):
                required[index] = "signed_or_unsigned_index_by_opcode"
            return required

        if opcode in self.FLOAT_OPS:
            return ["float"] * input_count

        return required

    def _input_requirements(self, opcode, inputs, input_widths):
        interpretations = self._required_interpretations(opcode, len(inputs))
        records = []

        for index, var in enumerate(inputs):
            view = self._view_for_var(var)
            width = input_widths[index] if index < len(input_widths) else view.get("width_bits")
            required = interpretations[index] if index < len(interpretations) else "raw_bits"
            default_signedness = view.get("signedness")

            override = False
            if required == "signed":
                override = default_signedness != "signed"
            elif required == "unsigned":
                override = default_signedness != "unsigned"
            elif required == "pointer":
                override = view.get("domain") != "pointer"
            elif required == "boolean":
                override = view.get("domain") != "boolean"

            records.append({
                "index": index,
                "sid": self._sid(var),
                "width_bits": width,
                "resolver_view": self._compact_view(view),
                "required_interpretation": required,
                "use_site_override": override,
                "authority": "pcode_opcode" if required not in ("raw_bits", "declared_view") else "raw_storage",
            })

        return records

    # -------------------------------------------------
    # OPCODE POLICY
    # -------------------------------------------------

    def _policy_for(self, opcode, resolver_flow):
        policy = {
            "category": "unknown",
            "semantic_class": "unsupported_opcode",
            "status": "unsupported",
            "runtime_helper": None,
            "result_representation": "raw_bitvector",
            "normalize_result": False,
            "hazards": ["unsupported_opcode"],
        }

        if opcode == "COPY":
            classification = resolver_flow.get("classification")
            if classification in ("narrowing_copy", "widening_copy"):
                return {
                    "category": "conversion",
                    "semantic_class": "copy_resize",
                    "status": "helper_required",
                    "runtime_helper": "c_resize",
                    "result_representation": "raw_bitvector",
                    "normalize_result": True,
                    "hazards": ["width_change", "python_unbounded_integer"],
                }
            return {
                "category": "transport",
                "semantic_class": "copy_with_declared_view_transport",
                "status": "metadata_only",
                "runtime_helper": None,
                "result_representation": "raw_bitvector",
                "normalize_result": False,
                "hazards": ["view_boundary"] if resolver_flow.get("view_change") else [],
            }

        if opcode == "CAST":
            width_relation = resolver_flow.get("width_relation")
            if width_relation in ("narrowing", "widening"):
                return {
                    "category": "conversion",
                    "semantic_class": "width_changing_cast",
                    "status": "helper_required",
                    "runtime_helper": "c_cast_bits",
                    "result_representation": "raw_bitvector",
                    "normalize_result": True,
                    "hazards": ["width_change", "view_boundary"],
                }
            return {
                "category": "conversion",
                "semantic_class": "same_width_view_reinterpretation",
                "status": "metadata_only",
                "runtime_helper": None,
                "result_representation": "raw_bitvector",
                "normalize_result": False,
                "hazards": ["view_boundary"],
            }

        if opcode in ("SUBPIECE", "PIECE", "INT_ZEXT", "INT_SEXT"):
            semantic = {
                "SUBPIECE": "subpiece_extraction",
                "PIECE": "bitvector_concatenation",
                "INT_ZEXT": "zero_extension",
                "INT_SEXT": "sign_extension",
            }[opcode]
            hazards = {
                # SUBPIECE offsets count from the least-significant end of the
                # abstract bit-vector; memory endianness is not consulted.
                "SUBPIECE": ["narrowing", "least_significant_byte_offset"],
                "PIECE": ["bitvector_concatenation", "python_unbounded_integer"],
                "INT_ZEXT": ["zero_extension", "python_has_no_fixed_width"],
                "INT_SEXT": ["sign_extension", "python_has_no_fixed_width"],
            }[opcode]
            return {
                "category": "conversion",
                "semantic_class": semantic,
                "status": "helper_required",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "raw_bitvector",
                "normalize_result": True,
                "hazards": hazards,
            }

        if opcode in self.INTEGER_ARITHMETIC_OPS:
            hazards = ["python_unbounded_integer", "fixed_width_result"]
            if opcode == "INT_SDIV":
                hazards.extend(["python_floor_division_differs", "signed_overflow_edge"])
            elif opcode == "INT_SREM":
                hazards.append("python_modulo_sign_differs")
            elif opcode in ("INT_DIV", "INT_REM"):
                hazards.append("unsigned_operand_view")
            return {
                "category": "integer_arithmetic",
                "semantic_class": opcode.lower(),
                "status": "helper_required",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "raw_bitvector",
                "normalize_result": True,
                "hazards": hazards,
            }

        if opcode in self.INTEGER_BITWISE_OPS:
            hazards = ["fixed_width_result"]
            if opcode == "INT_NEGATE":
                hazards.append("python_bitwise_not_is_unbounded")
            return {
                "category": "integer_bitwise",
                "semantic_class": opcode.lower(),
                "status": "helper_required",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "raw_bitvector",
                "normalize_result": True,
                "hazards": hazards,
            }

        if opcode in self.INTEGER_SHIFT_OPS:
            hazards = ["fixed_width_result", "shift_count_semantics"]
            if opcode == "INT_SRIGHT":
                hazards.append("arithmetic_right_shift")
            elif opcode == "INT_RIGHT":
                hazards.append("logical_right_shift")
            else:
                hazards.append("left_shift_overflow")
            return {
                "category": "integer_shift",
                "semantic_class": opcode.lower(),
                "status": "helper_required",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "raw_bitvector",
                "normalize_result": True,
                "hazards": hazards,
            }

        if opcode in self.COMPARISON_OPS and opcode not in self.FLOAT_OPS:
            signed = opcode.startswith("INT_S")
            unsigned = opcode in ("INT_LESS", "INT_LESSEQUAL")
            hazards = ["operand_view_is_opcode_authoritative"]
            if signed:
                hazards.append("signed_comparison")
            elif unsigned:
                hazards.append("unsigned_comparison")
            else:
                hazards.append("bitpattern_equality")
            return {
                "category": "comparison",
                "semantic_class": opcode.lower(),
                "status": "helper_required",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "python_bool",
                "normalize_result": False,
                "hazards": hazards,
            }

        if opcode in ("INT_CARRY", "INT_SCARRY", "INT_SBORROW"):
            return {
                "category": "overflow_predicate",
                "semantic_class": opcode.lower(),
                "status": "helper_required",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "python_bool",
                "normalize_result": False,
                "hazards": ["fixed_width_overflow_predicate"],
            }

        if opcode in self.BOOLEAN_OPS:
            return {
                "category": "boolean",
                "semantic_class": opcode.lower(),
                "status": "python_safe",
                "runtime_helper": None,
                "result_representation": "python_bool",
                "normalize_result": False,
                "hazards": [],
            }

        if opcode in self.PHI_OPS:
            return {
                "category": "phi_merge",
                "semantic_class": "raw_bitvector_phi_merge",
                "status": "metadata_only",
                "runtime_helper": None,
                "result_representation": "raw_bitvector",
                "normalize_result": False,
                "hazards": ["phi_contract_must_survive_folding"],
            }

        if opcode in self.CUSTODY_OPS:
            return {
                "category": "storage_custody",
                "semantic_class": "indirect_storage_state_transition",
                "status": "metadata_only",
                "runtime_helper": None,
                "result_representation": "raw_bitvector_storage_state",
                "normalize_result": False,
                "hazards": [
                    "address_escape_mutation_barrier",
                    "effect_owner_must_remain_ordered",
                    "indirect_iop_input_is_not_runtime_integer",
                    "custody_contract_must_survive_phi_folding",
                ],
            }

        if opcode in self.MEMORY_OPS:
            return {
                "category": "memory",
                "semantic_class": opcode.lower(),
                "status": "deferred_memory",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "raw_bitvector",
                "normalize_result": opcode == "LOAD",
                "hazards": ["memory_model_required", "pointer_domain", "endianness"],
            }

        if opcode in self.CALL_OPS:
            return {
                "category": "call_boundary",
                "semantic_class": opcode.lower(),
                "status": "deferred_external",
                "runtime_helper": None,
                "result_representation": "raw_bitvector",
                # A call result is normalized from the individual op's output
                # width later; the function object has no single call width.
                "normalize_result": False,
                "hazards": ["call_contract_required", "calling_convention_boundary"],
            }

        if opcode in self.POINTER_OPS:
            return {
                "category": "pointer_arithmetic",
                "semantic_class": opcode.lower(),
                "status": "deferred_memory",
                "runtime_helper": self.HELPER_BY_OPCODE.get(opcode),
                "result_representation": "raw_bitvector",
                "normalize_result": True,
                "hazards": ["pointer_model_required", "scaled_index"],
            }

        if opcode in self.FLOAT_OPS:
            return {
                "category": "floating_point",
                "semantic_class": opcode.lower(),
                "status": "deferred_float",
                "runtime_helper": None,
                "result_representation": "float_or_bool",
                "normalize_result": False,
                "hazards": ["floating_point_model_not_implemented"],
            }

        return policy

    # -------------------------------------------------
    # CONTRACT CONSTRUCTION
    # -------------------------------------------------

    def _resolver_flow_for_op(self, op):
        flow = getattr(op, "resolver_numeric_flow", None)
        if isinstance(flow, dict):
            return flow

        evidence = getattr(op, "numeric_evidence", None)
        if isinstance(evidence, dict):
            flow = evidence.get("resolver_type_flow_v21")
            if isinstance(flow, dict):
                return flow

        return {}

    def _effective_widths(self, op, inputs, output):
        input_widths = list(getattr(op, "input_widths", []) or [])
        while len(input_widths) < len(inputs):
            input_widths.append(self._width(inputs[len(input_widths)]))

        input_widths = [
            width if isinstance(width, int) and width > 0 else self._width(inputs[index])
            for index, width in enumerate(input_widths)
        ]

        output_width = getattr(op, "output_width", None)
        if not isinstance(output_width, int) or output_width <= 0:
            output_width = self._width(output)

        return input_widths, output_width

    def _phi_validation(self, contract):
        if contract.get("category") != "phi_merge":
            return

        output_width = contract.get("output_width_bits")
        widths = [
            record.get("width_bits")
            for record in contract.get("input_requirements", [])
            if record.get("width_bits") is not None
        ]
        mismatched = sorted(set(widths + ([output_width] if output_width is not None else [])))
        contract["phi_input_widths"] = widths
        contract["phi_width_consistent"] = len(mismatched) <= 1
        contract["phi_merge_policy"] = "select_predecessor_raw_bits_then_preserve_output_view"

        if len(mismatched) > 1:
            self.warnings.append({
                "kind": "compute_phi_width_conflict_v22",
                "op_key": contract.get("op_key"),
                "output_sid": contract.get("output_sid"),
                "widths": mismatched,
            })

    def _indirect_warning(self, contract, reason, **details):
        warning = {
            "kind": "compute_indirect_custody_warning_v22d",
            "reason": reason,
            "op_key": contract.get("op_key"),
            "op_id": contract.get("op_id"),
            "block_addr": contract.get("block_addr"),
            "output_sid": contract.get("output_sid"),
        }
        warning.update(details)
        self.warnings.append(warning)
        return warning

    def _validate_indirect_contract(self, contract, inputs, output):
        """Fail closed when an INDIRECT loses resolver/owner custody.

        A valid INDIRECT remains metadata_only.  Missing essential evidence is
        represented as deferred_storage_custody rather than being mistaken for
        a runnable P-code helper or a harmless COPY.
        """

        transition = contract.get("indirect_custody_transition")
        lifter = contract.get("lifter_indirect_custody_contract")
        owner = contract.get("effect_owner_binding") or {}
        output_binding = contract.get("output_storage_binding")
        unresolved = False

        if len(inputs) != 2:
            unresolved = True
            self._indirect_warning(
                contract,
                "legacy_two_input_INDIRECT_shape_lost",
                input_count=len(inputs),
                expected_input_count=2,
            )

        if not isinstance(transition, dict):
            unresolved = True
            self._indirect_warning(
                contract,
                "resolver_indirect_transition_missing",
            )

        if not isinstance(lifter, dict):
            unresolved = True
            self._indirect_warning(
                contract,
                "lifter_getOpRef_custody_contract_missing",
            )

        if not isinstance(output_binding, dict):
            unresolved = True
            self._indirect_warning(
                contract,
                "resolver_storage_family_binding_missing",
            )

        if owner.get("owner_resolved") is not True:
            unresolved = True
            self._indirect_warning(
                contract,
                "effect_owner_unresolved",
                owner_ref_id=owner.get("owner_ref_id"),
                owner_op_id=owner.get("owner_op_id"),
            )

        if isinstance(transition, dict):
            prior_sid = self._sid(inputs[0]) if inputs else None
            if str(transition.get("prior_sid")) != str(prior_sid):
                unresolved = True
                self._indirect_warning(
                    contract,
                    "prior_sid_disagrees_with_resolver_transition",
                    op_prior_sid=prior_sid,
                    resolver_prior_sid=transition.get("prior_sid"),
                )

            output_sid = self._sid(output)
            if str(transition.get("output_sid")) != str(output_sid):
                unresolved = True
                self._indirect_warning(
                    contract,
                    "output_sid_disagrees_with_resolver_transition",
                    op_output_sid=output_sid,
                    resolver_output_sid=transition.get("output_sid"),
                )

        input_widths = list(contract.get("input_widths_bits", []) or [])
        prior_width = input_widths[0] if input_widths else None
        output_width = contract.get("output_width_bits")
        if (
            isinstance(prior_width, int)
            and isinstance(output_width, int)
            and prior_width != output_width
        ):
            unresolved = True
            self._indirect_warning(
                contract,
                "storage_state_width_changed_across_INDIRECT",
                prior_width_bits=prior_width,
                output_width_bits=output_width,
            )

        contract["custody_resolved"] = not unresolved
        contract["status"] = (
            "metadata_only" if not unresolved else "deferred_storage_custody"
        )
        contract["c_compute_filter"] = True
        contract["runtime_helper"] = None
        contract["emits_runtime_helper"] = False
        contract["normalize_result_to_output_width"] = False
        contract["preserve_boundary_through_phi_folding"] = True
        contract["indirect_validation"] = {
            "legacy_two_input_shape": len(inputs) == 2,
            "resolver_transition_present": isinstance(transition, dict),
            "lifter_contract_present": isinstance(lifter, dict),
            "storage_family_present": isinstance(output_binding, dict),
            "effect_owner_resolved": owner.get("owner_resolved") is True,
            "width_consistent": not (
                isinstance(prior_width, int)
                and isinstance(output_width, int)
                and prior_width != output_width
            ),
            "custody_resolved": not unresolved,
        }

        if unresolved and self.strict:
            raise ValueError(
                "Unresolved PAL INDIRECT custody: %s" % contract.get("op_id")
            )

    def _link_indirect_effect_owners(self):
        """Bind each custody transition to the exact owner compute contract."""

        contracts_by_raw_op_id = {}
        for op_key, contract in self.compute_contracts_by_op.items():
            raw_op_id = contract.get("op_id")
            if raw_op_id is None:
                continue
            contracts_by_raw_op_id.setdefault(str(raw_op_id), []).append(
                (op_key, contract)
            )

        for op_key, contract in list(self.compute_indirect_contracts_by_op.items()):
            owner = contract.get("effect_owner_binding") or {}
            owner_op_id = owner.get("owner_op_id")
            candidates = (
                contracts_by_raw_op_id.get(str(owner_op_id), [])
                if owner_op_id is not None
                else []
            )

            if len(candidates) == 1:
                owner_op_key, owner_contract = candidates[0]
                owner["owner_compute_op_key"] = owner_op_key
                contract["effect_owner_compute_op_key"] = owner_op_key
                contract["effect_owner_compute_status"] = owner_contract.get("status")
                contract["effect_owner_compute_category"] = owner_contract.get("category")

                reverse = {
                    "kind": "pal_compute_effect_owner_reverse_custody_v22d",
                    "version": self.VERSION,
                    "owner_compute_op_key": owner_op_key,
                    "indirect_compute_op_key": op_key,
                    "transition_id": (
                        (contract.get("indirect_custody_transition") or {}).get(
                            "transition_id"
                        )
                    ),
                    "prior_sid": (
                        (contract.get("indirect_custody_transition") or {}).get(
                            "prior_sid"
                        )
                    ),
                    "output_sid": contract.get("output_sid"),
                    "family_id": contract.get("storage_family_id"),
                    "owner_opcode": owner.get("owner_opcode"),
                    "owner_category": owner.get("owner_category"),
                    "authority": "exact_owner_op_id_match",
                }
                owner_contract.setdefault(
                    "indirect_custody_effects_owned", []
                ).append(reverse)
                owner_contract["indirect_custody_effect_count"] = len(
                    owner_contract["indirect_custody_effects_owned"]
                )
                owner_contract["owns_indirect_storage_effects"] = True
                owner_contract["storage_custody_related"] = True
                owner_contract["storage_custody_role"] = "effect_owner"
                owner_contract["preserve_boundary_through_phi_folding"] = True
                owner_contract["c_compute_filter"] = True
                family_ids = owner_contract.setdefault(
                    "indirect_storage_family_ids_owned", []
                )
                family_id = contract.get("storage_family_id")
                if family_id is not None and family_id not in family_ids:
                    family_ids.append(family_id)
                self.compute_effect_owner_bindings_by_op.setdefault(
                    owner_op_key, []
                ).append(reverse)

            else:
                contract["custody_resolved"] = False
                contract["status"] = "deferred_storage_custody"
                contract["effect_owner_compute_op_key"] = None
                self._indirect_warning(
                    contract,
                    (
                        "effect_owner_compute_contract_missing"
                        if not candidates
                        else "effect_owner_compute_contract_ambiguous"
                    ),
                    owner_op_id=owner_op_id,
                    candidate_op_keys=[item[0] for item in candidates],
                )
                if self.strict:
                    raise ValueError(
                        "PAL INDIRECT owner compute binding failed: %s"
                        % owner_op_id
                    )

    def _analyze_op(self, block, op, ordinal):
        opcode = str(getattr(op, "opcode", "") or "").upper()
        inputs = list(getattr(op, "inputs", []) or [])
        output = getattr(op, "output", None)
        input_widths, output_width = self._effective_widths(op, inputs, output)
        resolver_flow = self._resolver_flow_for_op(op)
        policy = self._policy_for(opcode, resolver_flow)
        if opcode in self.CALL_OPS and output_width is not None:
            # External semantics remain deferred, but a returned bit-vector
            # must eventually be normalized to this call site's output width.
            policy["normalize_result"] = True
        input_requirements = self._input_requirements(opcode, inputs, input_widths)
        output_view = self._view_for_var(output) if output is not None else None

        input_storage_bindings = []
        for index, var in enumerate(inputs):
            binding = self._storage_binding_for_sid(
                self._sid(var), role="storage_state_input"
            )
            if binding is not None:
                binding["input_index"] = index
                input_storage_bindings.append(binding)

        output_storage_binding = self._storage_binding_for_sid(
            self._sid(output), role=None
        ) if output is not None else None
        parameter_initializer = self.resolver_parameter_initializer_by_output_sid.get(
            str(self._sid(output))
        ) if output is not None else None

        indirect_transition = None
        lifter_indirect_contract = None
        effect_owner_binding = None
        if opcode in self.CUSTODY_OPS:
            indirect_transition = self._resolver_indirect_transition_for(op, output)
            lifter_indirect_contract = self._lifter_indirect_contract_for(op, output)
            effect_owner_binding = self._effect_owner_binding(
                indirect_transition, lifter_indirect_contract
            )

        storage_custody_related = bool(
            opcode in self.CUSTODY_OPS
            or input_storage_bindings
            or output_storage_binding
            or parameter_initializer
        )

        overrides = [
            record for record in input_requirements
            if record.get("use_site_override")
        ]
        view_change = bool(resolver_flow.get("view_change"))
        preserve_boundary = bool(
            view_change
            or opcode in ("INT_ZEXT", "INT_SEXT", "SUBPIECE", "PIECE")
            or opcode in self.PHI_OPS
            or storage_custody_related
        )

        status = policy.get("status")
        c_filter = bool(
            status in (
                "helper_required", "deferred_memory", "deferred_external",
                "deferred_float", "unsupported",
            )
            or overrides
            or preserve_boundary
        )

        hazards = list(policy.get("hazards", []) or [])
        if overrides:
            hazards.append("resolver_default_view_overridden_at_use_site")
        if view_change and "view_boundary" not in hazards:
            hazards.append("view_boundary")
        if input_storage_bindings:
            hazards.append("consumes_versioned_storage_family_state")
        if output_storage_binding:
            hazards.append("defines_versioned_storage_family_state")
        if parameter_initializer:
            hazards.append("parameter_equivalence_limited_to_initializer_copy")
        hazards = list(dict.fromkeys(hazards))

        conversion_parameters = None
        if opcode == "SUBPIECE":
            conversion_parameters = {
                "byte_offset": resolver_flow.get("subpiece_byte_offset"),
                "offset_origin": "least_significant_byte",
                "source_width_bits": input_widths[0] if input_widths else None,
                "output_width_bits": output_width,
            }
        elif opcode in ("INT_ZEXT", "INT_SEXT"):
            conversion_parameters = {
                "extension": "zero" if opcode == "INT_ZEXT" else "sign",
                "source_width_bits": input_widths[0] if input_widths else None,
                "output_width_bits": output_width,
            }
        elif opcode == "PIECE":
            conversion_parameters = {
                "input_widths_bits": list(input_widths),
                "output_width_bits": output_width,
                "input_order": "most_significant_piece_then_least_significant_piece",
            }
        elif opcode in ("COPY", "CAST"):
            conversion_parameters = {
                "width_relation": resolver_flow.get("width_relation"),
                "view_change": view_change,
                "changed_axes": list(resolver_flow.get("changed_axes", []) or []),
            }

        if opcode in self.CUSTODY_OPS:
            result_normalization = {
                "mode": "observe_storage_family_state_after_effect_owner",
                "width_bits": output_width,
                "mask": None,
            }
        elif policy.get("result_representation") == "python_bool":
            result_normalization = {
                "mode": "canonical_python_bool",
                "width_bits": output_width,
                "mask": None,
            }
        elif policy.get("normalize_result") and output_width is not None:
            result_normalization = {
                "mode": "mask_to_output_width",
                "width_bits": output_width,
                "mask": self._mask_for_width(output_width),
            }
        else:
            result_normalization = {
                "mode": "preserve_raw_bits",
                "width_bits": output_width,
                "mask": None,
            }

        op_key = self._op_key(block, op, ordinal)
        contract = {
            "kind": "pal_compute_contract_v22",
            "version": self.VERSION,
            "op_key": op_key,
            "op_id": self._op_id(op),
            "block_addr": self._block_addr(block),
            "opcode": opcode,
            "category": policy.get("category"),
            "semantic_class": policy.get("semantic_class"),
            "status": status,
            "c_compute_filter": c_filter,
            "runtime_helper": policy.get("runtime_helper"),
            "emits_runtime_helper": status == "helper_required",
            "input_sids": [self._sid(var) for var in inputs],
            "output_sid": self._sid(output),
            "input_widths_bits": input_widths,
            "output_width_bits": output_width,
            "input_requirements": input_requirements,
            "output_view": self._compact_view(output_view) if output_view else None,
            "runtime_representation": self.REPRESENTATION,
            "result_representation": policy.get("result_representation"),
            "normalize_result_to_output_width": bool(policy.get("normalize_result")),
            "result_normalization": result_normalization,
            "conversion_parameters": conversion_parameters,
            "preserve_boundary_through_phi_folding": preserve_boundary,
            "resolver_flow_classification": resolver_flow.get("classification"),
            "resolver_view_change": view_change,
            "resolver_changed_axes": list(resolver_flow.get("changed_axes", []) or []),
            "use_site_override_count": len(overrides),
            "storage_custody_related": storage_custody_related,
            "storage_custody_role": (
                "indirect_transition"
                if opcode in self.CUSTODY_OPS
                else "parameter_storage_initializer"
                if parameter_initializer
                else "storage_family_definition"
                if output_storage_binding
                else "storage_family_consumer"
                if input_storage_bindings
                else None
            ),
            "input_storage_bindings": input_storage_bindings,
            "output_storage_binding": output_storage_binding,
            "storage_family_id": (
                output_storage_binding.get("family_id")
                if isinstance(output_storage_binding, dict)
                else indirect_transition.get("family_id")
                if isinstance(indirect_transition, dict)
                else None
            ),
            "parameter_storage_initializer": (
                dict(parameter_initializer)
                if isinstance(parameter_initializer, dict)
                else None
            ),
            "indirect_custody_transition": (
                dict(indirect_transition)
                if isinstance(indirect_transition, dict)
                else None
            ),
            "lifter_indirect_custody_contract": (
                dict(lifter_indirect_contract)
                if isinstance(lifter_indirect_contract, dict)
                else None
            ),
            "effect_owner_binding": effect_owner_binding,
            "indirect_runtime_operation": False if opcode in self.CUSTODY_OPS else None,
            "indirect_emission_policy": (
                "do_not_render_INDIRECT_observe_family_state_after_owner"
                if opcode in self.CUSTODY_OPS
                else None
            ),
            "hazards": hazards,
            "authority": (
                "PALlibrary_getOpRef_plus_PALSymbolResolver_storage_family"
                if opcode in self.CUSTODY_OPS
                else "pcode_opcode_and_widths"
            ),
        }

        if opcode in self.CUSTODY_OPS:
            self._validate_indirect_contract(contract, inputs, output)

        self._phi_validation(contract)

        if opcode in self.CALL_OPS:
            call_plan = self._build_call_site_abi_plan(
                op_key, op, contract
            )
            contract["call_site_abi_plan"] = call_plan
            contract["call_site_abi_plan_id"] = call_plan.get("plan_id")
            contract["call_dispatch_class"] = call_plan.get("dispatch_class")
            contract["external_call_abi_classification"] = dict(
                call_plan.get("external_call_abi_classification") or {}
            )
            contract["call_result_contract"] = dict(
                call_plan.get("result_contract") or {}
            )
            contract["call_no_return"] = bool(call_plan.get("no_return"))
            contract["call_control_effect"] = call_plan.get("control_effect")
            contract["preserve_boundary_through_phi_folding"] = True
            contract["c_compute_filter"] = True
            if call_plan.get("no_return"):
                contract["hazards"] = list(dict.fromkeys(
                    list(contract.get("hazards") or [])
                    + ["no_return_call_terminates_control_path"]
                ))
                self.no_return_call_op_keys.append(op_key)

            op.call_site_abi_plan = call_plan
            self.call_site_abi_plans_by_op[op_key] = call_plan
            raw_op_id = self._op_id(op)
            if raw_op_id is not None:
                self.call_site_abi_plans_by_raw_op_id[
                    str(raw_op_id)
                ] = call_plan

        op.compute_contract = contract
        if output is not None:
            output.compute_plan = contract

        self.compute_contracts_by_op[op_key] = contract
        self.compute_contracts_by_block.setdefault(self._block_addr(block), []).append(contract)

        output_sid = contract.get("output_sid")
        if output_sid is not None:
            sid_key = str(output_sid)
            previous = self.compute_plans_by_sid.get(sid_key)
            if previous is not None and previous.get("op_key") != op_key:
                self.warnings.append({
                    "kind": "compute_duplicate_ssa_definition_v22",
                    "sid": output_sid,
                    "first_op_key": previous.get("op_key"),
                    "second_op_key": op_key,
                })
            self.compute_plans_by_sid[sid_key] = contract

        if opcode in self.CUSTODY_OPS:
            self.compute_indirect_contracts_by_op[op_key] = contract
            if output_sid is not None:
                self.compute_indirect_contracts_by_output_sid[
                    str(output_sid)
                ] = contract

            owner = contract.get("effect_owner_binding") or {}
            owner_op_id = owner.get("owner_op_id")
            if owner_op_id is not None:
                self.compute_indirect_contracts_by_owner_op_id.setdefault(
                    str(owner_op_id), []
                ).append(contract)

            family_id = contract.get("storage_family_id")
            if family_id is not None:
                self.compute_indirect_contracts_by_family_id.setdefault(
                    str(family_id), []
                ).append(contract)

        if status == "unsupported":
            warning = {
                "kind": "compute_unsupported_opcode_v22",
                "opcode": opcode,
                "op_key": op_key,
                "output_sid": output_sid,
            }
            self.warnings.append(warning)
            if self.strict:
                raise ValueError("Unsupported PAL compute opcode: %s" % opcode)

        return contract

    # -------------------------------------------------
    # CONTROL / RETURN CONTRACTS
    # -------------------------------------------------

    def _analyze_terminator(self, block, term):
        if term is None:
            return None

        opcode = str(getattr(term, "opcode", "") or "").upper()
        inputs = list(getattr(term, "inputs", []) or [])
        condition = getattr(term, "condition", None)
        block_addr = self._block_addr(block)

        contract = {
            "kind": "pal_compute_control_contract_v22",
            "version": self.VERSION,
            "block_addr": block_addr,
            "opcode": opcode,
            "input_sids": [self._sid(var) for var in inputs],
            "condition_sid": self._sid(condition),
            "condition_width_bits": getattr(term, "condition_width", None) or self._width(condition),
            "runtime_representation": self.REPRESENTATION,
            "authority": "pcode_control_opcode_and_widths",
        }

        if opcode == "CBRANCH":
            contract.update({
                "category": "control_condition",
                "status": "python_safe",
                "condition_interpretation": "nonzero_boolean",
                "c_compute_filter": False,
                "hazards": [],
            })
        elif opcode == "RETURN":
            value_var = inputs[1] if len(inputs) > 1 else inputs[-1] if inputs else None
            ssa_value_view = self._view_for_var(value_var) if value_var is not None else None
            declared_return_view = (
                self._declared_return_view(value_var)
                if value_var is not None
                else None
            )
            observation_view = declared_return_view
            transport_width = self._width(value_var)
            logical_width = (
                declared_return_view.get("width_bits")
                if isinstance(declared_return_view, dict)
                else transport_width
            )
            value_view = {
                "sid": self._sid(value_var),
                "width_bits": logical_width,
                "domain": "integer",
                "signedness": "raw",
                "canonical_type": "bits%s" % logical_width,
                "source": (
                    "function_signature_logical_return_width"
                    if isinstance(declared_return_view, dict)
                    else "raw_return_register_transport"
                ),
            } if value_var is not None else None
            value_width = (
                value_view.get("width_bits")
                if isinstance(value_view, dict)
                else self._width(value_var)
            )
            observation_view_mismatch = bool(
                isinstance(declared_return_view, dict)
                and isinstance(ssa_value_view, dict)
                and any(
                    declared_return_view.get(axis) != ssa_value_view.get(axis)
                    for axis in ("width_bits", "domain", "signedness")
                )
            )
            hazards = ["function_return_width_boundary"] if value_var is not None else []
            if observation_view_mismatch:
                hazards.append("declared_return_view_differs_from_ssa_view")
            contract.update({
                "category": "return_boundary",
                "status": "helper_required" if value_var is not None else "metadata_only",
                "runtime_helper": "c_return_bits" if value_var is not None else None,
                "return_value_sid": self._sid(value_var),
                "return_value_width_bits": value_width,
                "return_transport_width_bits": transport_width,
                "return_logical_width_bits": logical_width,
                "return_value_view": self._compact_view(value_view) if value_view else None,
                "return_ssa_value_view": self._compact_view(ssa_value_view) if ssa_value_view else None,
                "return_declared_view": self._compact_view(declared_return_view) if declared_return_view else None,
                "return_observation_view": self._compact_view(observation_view) if observation_view else None,
                "return_observation_view_mismatch": observation_view_mismatch,
                "return_boundary_authority": (
                    "function_signature_logical_width_plus_raw_transport"
                    if isinstance(declared_return_view, dict)
                    else "raw_return_register_transport"
                ),
                "return_observation_authority": (
                    "function_signature_return_type"
                    if declared_return_view is not None
                    else "unavailable"
                ),
                "c_compute_filter": value_var is not None,
                "hazards": hazards,
            })
            if observation_view_mismatch:
                self.events.append({
                    "kind": "compute_return_observation_view_mismatch_v22c",
                    "block_addr": block_addr,
                    "return_value_sid": self._sid(value_var),
                    "ssa_view": self._compact_view(ssa_value_view),
                    "declared_view": self._compact_view(declared_return_view),
                    "authority": "function_signature_return_type",
                })
        else:
            contract.update({
                "category": "control_transfer",
                "status": "metadata_only",
                "c_compute_filter": False,
                "hazards": [],
            })

        term.compute_contract = contract
        self.control_contracts_by_block.setdefault(block_addr, []).append(contract)
        return contract

    # -------------------------------------------------
    # PUBLIC RUN / EXPORT
    # -------------------------------------------------

    def run(self):
        self.compute_plans_by_sid = {}
        self.compute_contracts_by_op = {}
        self.compute_contracts_by_block = {}
        self.control_contracts_by_block = {}
        self.compute_storage_bindings_by_sid = {}
        self.compute_indirect_contracts_by_op = {}
        self.compute_indirect_contracts_by_output_sid = {}
        self.compute_indirect_contracts_by_owner_op_id = {}
        self.compute_indirect_contracts_by_family_id = {}
        self.compute_effect_owner_bindings_by_op = {}
        self.function_entry_abi_plan = {}
        self.call_site_abi_plans_by_op = {}
        self.call_site_abi_plans_by_raw_op_id = {}
        self.no_return_call_op_keys = []
        self.return_boundary_reconciliation = {}
        self.abi_plan_events = []
        self.abi_plan_warnings = []
        self.abi_plan_inventory = {}
        self.events = []
        self.warnings = []

        for sid in sorted(self.resolver_storage_family_by_sid, key=str):
            binding = self._storage_binding_for_sid(sid)
            if binding is not None:
                self.compute_storage_bindings_by_sid[str(sid)] = binding

        for block in self._iter_blocks():
            for ordinal, op in enumerate(list(getattr(block, "ops", []) or [])):
                self._analyze_op(block, op, ordinal)
            self._analyze_terminator(block, getattr(block, "terminator", None))

        self.function_entry_abi_plan = self._build_function_entry_abi_plan()
        self._reconcile_function_return_boundaries()

        # All CALL/STORE contracts now exist, so exact raw owner op IDs can be
        # bound without depending on traversal order.
        self._link_indirect_effect_owners()

        status_counts = {}
        category_counts = {}
        helper_counts = {}
        opcode_counts = {}
        filtered = 0
        view_overrides = 0
        storage_custody_related = 0

        for contract in self.compute_contracts_by_op.values():
            status = contract.get("status") or "unknown"
            category = contract.get("category") or "unknown"
            opcode = contract.get("opcode") or "unknown"
            helper = contract.get("runtime_helper")

            status_counts[status] = status_counts.get(status, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            opcode_counts[opcode] = opcode_counts.get(opcode, 0) + 1
            if helper:
                helper_counts[helper] = helper_counts.get(helper, 0) + 1
            if contract.get("c_compute_filter"):
                filtered += 1
            view_overrides += int(contract.get("use_site_override_count") or 0)
            if contract.get("storage_custody_related"):
                storage_custody_related += 1

        indirect_resolved = sum(
            1 for contract in self.compute_indirect_contracts_by_op.values()
            if contract.get("custody_resolved") is True
            and contract.get("effect_owner_compute_op_key") is not None
        )
        indirect_deferred = (
            len(self.compute_indirect_contracts_by_op) - indirect_resolved
        )
        indirect_owner_categories = {}
        for contract in self.compute_indirect_contracts_by_op.values():
            category = (
                (contract.get("effect_owner_binding") or {}).get(
                    "owner_category"
                )
                or "unknown"
            )
            indirect_owner_categories[category] = (
                indirect_owner_categories.get(category, 0) + 1
            )

        indirect_summary = {
            "kind": "pal_compute_indirect_custody_inventory_v22d",
            "version": self.VERSION,
            "resolver_transitions": len(self.resolver_indirect_transitions),
            "compute_indirect_contracts": len(
                self.compute_indirect_contracts_by_op
            ),
            "resolved_custody": indirect_resolved,
            "deferred_custody": indirect_deferred,
            "effect_owner_compute_bindings": sum(
                len(records)
                for records in self.compute_effect_owner_bindings_by_op.values()
            ),
            "effect_owner_compute_ops": len(
                self.compute_effect_owner_bindings_by_op
            ),
            "owner_categories": indirect_owner_categories,
            "storage_families": len(self.resolver_storage_families),
            "storage_sid_bindings": len(self.compute_storage_bindings_by_sid),
            "address_escape_barrier_sids": len(
                self.resolver_escape_barrier_sids
            ),
            "parameter_storage_initializers": len(
                self.resolver_parameter_initializers
            ),
            "runtime_helpers": 0,
            "warnings": sum(
                1 for warning in self.warnings
                if warning.get("kind") == "compute_indirect_custody_warning_v22d"
            ),
            "rule": "INDIRECT_is_metadata_only_owner_bound_storage_transition",
        }
        self.events.append(indirect_summary)

        abi_plan_summary = self._finalize_abi_plan_inventory()
        self.events.extend(self.abi_plan_events)
        self.warnings.extend(self.abi_plan_warnings)

        summary = {
            "kind": "pal_compute_inventory_v22",
            "version": self.VERSION,
            "runtime_representation": self.REPRESENTATION,
            "operations": len(self.compute_contracts_by_op),
            "output_plans": len(self.compute_plans_by_sid),
            "control_contracts": sum(len(v) for v in self.control_contracts_by_block.values()),
            "c_compute_filtered": filtered,
            "use_site_overrides": view_overrides,
            "return_observation_view_mismatches": sum(
                1 for event in self.events
                if event.get("kind") == "compute_return_observation_view_mismatch_v22c"
            ),
            "storage_custody_related_ops": storage_custody_related,
            "indirect_custody_contracts": len(
                self.compute_indirect_contracts_by_op
            ),
            "indirect_custody_resolved": indirect_resolved,
            "indirect_custody_deferred": indirect_deferred,
            "indirect_effect_owner_compute_ops": len(
                self.compute_effect_owner_bindings_by_op
            ),
            "storage_family_bindings": len(
                self.compute_storage_bindings_by_sid
            ),
            "function_entry_abi_plan": bool(self.function_entry_abi_plan),
            "call_site_abi_plans": len(self.call_site_abi_plans_by_op),
            "internal_call_plan_failures": abi_plan_summary.get(
                "internal_calls_without_target_compatible_plan", 0
            ),
            "unsupported_implicit_inputs": abi_plan_summary.get(
                "implicit_inputs_unsupported", 0
            ),
            "abi_runtime_helper_assignments": abi_plan_summary.get(
                "abi_runtime_helper_assignments", 0
            ),
            "no_return_calls": abi_plan_summary.get("no_return_calls", 0),
            "reachable_return_boundaries": (
                self.return_boundary_reconciliation.get(
                    "reachable_return_boundaries", 0
                )
            ),
            "unreachable_return_boundaries": (
                self.return_boundary_reconciliation.get(
                    "unreachable_return_boundaries", 0
                )
            ),
            "synthetic_no_return_continuations_suppressed": (
                self.return_boundary_reconciliation.get(
                    "synthetic_no_return_continuations_suppressed", 0
                )
            ),
            "statuses": status_counts,
            "categories": category_counts,
            "helpers": helper_counts,
            "opcodes": opcode_counts,
            "warnings": len(self.warnings),
        }
        self.events.append(summary)

        self.func.compute_plans_by_sid = dict(self.compute_plans_by_sid)
        self.func.compute_contracts_by_op = dict(self.compute_contracts_by_op)
        self.func.compute_contracts_by_block = dict(self.compute_contracts_by_block)
        self.func.compute_control_contracts_by_block = dict(self.control_contracts_by_block)
        self.func.compute_storage_bindings_by_sid = dict(
            self.compute_storage_bindings_by_sid
        )
        self.func.compute_indirect_contracts_by_op = dict(
            self.compute_indirect_contracts_by_op
        )
        self.func.compute_indirect_contracts_by_output_sid = dict(
            self.compute_indirect_contracts_by_output_sid
        )
        self.func.compute_indirect_contracts_by_owner_op_id = dict(
            self.compute_indirect_contracts_by_owner_op_id
        )
        self.func.compute_indirect_contracts_by_family_id = dict(
            self.compute_indirect_contracts_by_family_id
        )
        self.func.compute_indirect_effect_owner_bindings_by_op = dict(
            self.compute_effect_owner_bindings_by_op
        )
        self.func.compute_indirect_parameter_initializers = list(
            self.resolver_parameter_initializers
        )
        self.func.compute_indirect_custody_inventory = dict(indirect_summary)
        self.func.function_entry_abi_plan = dict(
            self.function_entry_abi_plan
        )
        self.func.call_site_abi_plans_by_op = dict(
            self.call_site_abi_plans_by_op
        )
        self.func.call_site_abi_plans_by_raw_op_id = dict(
            self.call_site_abi_plans_by_raw_op_id
        )
        self.func.no_return_call_op_keys = list(self.no_return_call_op_keys)
        self.func.compute_return_boundary_reconciliation = dict(
            self.return_boundary_reconciliation
        )
        self.func.compute_abi_plan_inventory = dict(abi_plan_summary)
        self.func.compute_abi_plan_warnings = list(self.abi_plan_warnings)
        self.func.compute_abi_plan_version = self.VERSION
        self.func.compute_events = list(self.events)
        self.func.compute_warnings = list(self.warnings)
        self.func.compute_analyzer_version = self.VERSION
        self.func.compute_runtime_representation = self.REPRESENTATION
        self.func.compute_debug = {
            "summary": summary,
            "warnings": list(self.warnings),
            "helper_required": [
                contract for contract in self.compute_contracts_by_op.values()
                if contract.get("status") == "helper_required"
            ],
            "metadata_boundaries": [
                contract for contract in self.compute_contracts_by_op.values()
                if contract.get("status") == "metadata_only"
                and contract.get("c_compute_filter")
            ],
            "deferred": [
                contract for contract in self.compute_contracts_by_op.values()
                if str(contract.get("status", "")).startswith("deferred_")
            ],
            "phi_merges": [
                contract for contract in self.compute_contracts_by_op.values()
                if contract.get("category") == "phi_merge"
            ],
            "indirect_custody_summary": dict(indirect_summary),
            "indirect_custody": list(
                self.compute_indirect_contracts_by_op.values()
            ),
            "indirect_effect_owners": dict(
                self.compute_effect_owner_bindings_by_op
            ),
            "storage_bindings_by_sid": dict(
                self.compute_storage_bindings_by_sid
            ),
            "parameter_storage_initializers": list(
                self.resolver_parameter_initializers
            ),
            "function_entry_abi_plan": dict(
                self.function_entry_abi_plan
            ),
            "call_site_abi_plans": list(
                self.call_site_abi_plans_by_op.values()
            ),
            "return_boundary_reconciliation": dict(
                self.return_boundary_reconciliation
            ),
            "abi_plan_summary": dict(abi_plan_summary),
            "abi_plan_warnings": list(self.abi_plan_warnings),
        }

        return self.compute_plans_by_sid

    analyze = run

    def debug_print(self):
        try:
            from pprint import pprint
        except Exception:
            pprint = print

        debug = getattr(self.func, "compute_debug", {}) or {}
        print("\n===== PAL COMPUTE ANALYZER =====")
        pprint(debug.get("summary", {}), sort_dicts=False)

        print("\n[WARNINGS]")
        pprint(debug.get("warnings", []), sort_dicts=False)

        print("\n[METADATA-ONLY COMPUTE BOUNDARIES]")
        for contract in debug.get("metadata_boundaries", []):
            print(
                "%s %s %s -> %s classification=%s"
                % (
                    hex(contract.get("block_addr")) if isinstance(contract.get("block_addr"), int) else contract.get("block_addr"),
                    contract.get("opcode"),
                    contract.get("input_sids"),
                    contract.get("output_sid"),
                    contract.get("resolver_flow_classification"),
                )
            )

        print("\n[HELPER-REQUIRED CONTRACTS]")
        for contract in debug.get("helper_required", []):
            print(
                "%s %s %s helper=%s widths=%s->%s overrides=%s"
                % (
                    hex(contract.get("block_addr")) if isinstance(contract.get("block_addr"), int) else contract.get("block_addr"),
                    contract.get("opcode"),
                    contract.get("output_sid"),
                    contract.get("runtime_helper"),
                    contract.get("input_widths_bits"),
                    contract.get("output_width_bits"),
                    contract.get("use_site_override_count"),
                )
            )

        print("\n[INDIRECT STORAGE-CUSTODY CONTRACTS]")
        for contract in debug.get("indirect_custody", []):
            owner = contract.get("effect_owner_binding") or {}
            print(
                "%s %s -> %s family=%s owner=%s/%s owner_compute=%s status=%s"
                % (
                    hex(contract.get("block_addr"))
                    if isinstance(contract.get("block_addr"), int)
                    else contract.get("block_addr"),
                    (contract.get("indirect_custody_transition") or {}).get(
                        "prior_sid"
                    ),
                    contract.get("output_sid"),
                    contract.get("storage_family_id"),
                    owner.get("owner_opcode"),
                    owner.get("owner_ref_hex"),
                    contract.get("effect_owner_compute_op_key"),
                    contract.get("status"),
                )
            )

        print("\n[INDIRECT CUSTODY INVENTORY]")
        pprint(debug.get("indirect_custody_summary", {}), sort_dicts=False)

        print("\n[ABI-D ENTRY/CALL PLAN INVENTORY]")
        pprint(debug.get("abi_plan_summary", {}), sort_dicts=False)

        entry = debug.get("function_entry_abi_plan", {}) or {}
        print("\n[FUNCTION ENTRY ABI PLAN]")
        pprint({
            "plan_id": entry.get("plan_id"),
            "status": entry.get("status"),
            "callable_signature_status": entry.get(
                "callable_signature_status"
            ),
            "fixed_argument_count": entry.get("fixed_argument_count"),
            "implicit_input_count": entry.get("implicit_input_count"),
            "variadic_register_save_area": entry.get(
                "variadic_register_save_area"
            ),
            "overflow_argument_area": entry.get("overflow_argument_area"),
            "variadic_al": entry.get("variadic_al"),
            "frame_base": entry.get("frame_base"),
            "tls_base": entry.get("tls_base"),
            "return_contract": entry.get("return_contract"),
            "reachable_return_boundaries": entry.get(
                "reachable_return_boundaries"
            ),
            "unreachable_return_boundaries": entry.get(
                "unreachable_return_boundaries"
            ),
        }, sort_dicts=False)

        print("\n[RETURN BOUNDARY RECONCILIATION]")
        pprint(
            debug.get("return_boundary_reconciliation", {}),
            sort_dicts=False,
        )

        print("\n[CALL SITE ABI PLANS]")
        for plan in debug.get("call_site_abi_plans", []) or []:
            pprint({
                "op_key": plan.get("op_key"),
                "target": (plan.get("target") or {}).get("name"),
                "dispatch_class": plan.get("dispatch_class"),
                "status": plan.get("status"),
                "argument_count": plan.get("argument_count"),
                "carrier_allocation_status": plan.get(
                    "carrier_allocation_status"
                ),
                "target_compatibility_status": plan.get(
                    "target_compatibility_status"
                ),
                "target_compatible": plan.get("target_compatible"),
                "no_return": plan.get("no_return"),
                "result_width_bits": plan.get("result_width_bits"),
            }, sort_dicts=False)

        print("===== END PAL COMPUTE ANALYZER =====\n")


# Concise public alias used by the future pipeline integration.
PALCompute = PALComputeAnalyzer


def debug_dump_compute(pal_function):
    """Print an existing PALCompute result without rerunning analysis."""
    analyzer = PALComputeAnalyzer(pal_function)
    analyzer.debug_print()


def debug_dump_compute_abi_plans(
    pal_function, include_calls=True, include_arguments=False
):
    """Print ABI-D plans already attached to a PALFunction."""

    from pprint import pprint

    print("===== PAL COMPUTE ABI-D ENTRY/CALL PLANS =====")
    print("\n[INVENTORY]")
    pprint(
        dict(getattr(pal_function, "compute_abi_plan_inventory", {}) or {}),
        sort_dicts=False,
    )

    print("\n[FUNCTION ENTRY PLAN]")
    entry = dict(getattr(pal_function, "function_entry_abi_plan", {}) or {})
    pprint(entry, sort_dicts=False)

    print("\n[RETURN BOUNDARY RECONCILIATION]")
    pprint(
        dict(
            getattr(
                pal_function,
                "compute_return_boundary_reconciliation",
                {},
            ) or {}
        ),
        sort_dicts=False,
    )

    if include_calls:
        print("\n[CALL SITE PLANS]")
        calls = dict(getattr(pal_function, "call_site_abi_plans_by_op", {}) or {})
        for op_key in sorted(calls, key=str):
            plan = dict(calls[op_key])
            if not include_arguments:
                plan["arguments"] = [
                    {
                        "index": item.get("index"),
                        "source_sid": item.get("source_sid"),
                        "argument_class": item.get("argument_class"),
                        "carrier_kind": item.get("carrier_kind"),
                        "carrier": item.get("carrier"),
                        "stack_slot": item.get("stack_slot"),
                    }
                    for item in list(plan.get("arguments") or [])
                ]
                plan.pop("source_call_site_abi_contract", None)
            pprint(plan, sort_dicts=False)

    print("\n[WARNINGS]")
    pprint(
        list(getattr(pal_function, "compute_abi_plan_warnings", []) or []),
        sort_dicts=False,
    )
    print("===== END PAL COMPUTE ABI-D ENTRY/CALL PLANS =====")
