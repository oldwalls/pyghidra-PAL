# ============================================================
# PAL PHI FOLDER / EXECUTION-AWARE SSA TRANSITION PLANNER v23 / ABI-F
# Truth-oriented PHI transitions + condition/storage/ABI-entry custody
# ============================================================
#
# Purpose:
#   Do not destructively fold PHIs.
#   Instead, produce:
#       1. PHI transition drop-ins
#       2. Presentation metadata for the emitter
#
# Main products:
#   func.var_map
#   func.phi_dropins
#   func.phi_dropins_by_pred
#   func.phi_dropins_by_join
#   func.phi_condition_custody_bindings
#   func.phi_condition_custody_bindings_by_ref
#
# Presentation products:
#   func.inline_only_sidsa
#   func.suppress_assign_sids
#   func.materialize_sids
#   func.local_target_sids
#   func.preferred_expr_by_sid
#   func.phi_source_foldable_sids
#
# Emitter contract:
#   - If sid in suppress_assign_sids: do not emit normal "sid = expr".
#   - If sid in materialize_sids: emit assignment, especially reused CALL results.
#   - For PHI drop-ins, render source formula directly when source sid is
#     foldable or pure inline-only.
#   - Never inline CALL/CALLIND unless sid is explicitly foldable because it
#     feeds a direct local-target PHI and has no other meaningful uses.
# ============================================================


import re


class PALPHIfolder:

    COMPUTE_CONSUMER_VERSION = "v21_compute_contract_consumers"
    CONDITION_CUSTODY_VERSION = "v22_condition_storage_custody_sidecars"
    ABI_ENTRY_CUSTODY_VERSION = "v23_abi_f_entry_state_convergence_custody"

    CALL_OPS = {"CALL", "CALLIND"}

    PURE_INLINE_OPS = {
        "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC",
        "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
        "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
        "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
        "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
        "INT_LESSEQUAL", "INT_SLESSEQUAL",
        "BOOL_NEGATE", "INT_NEGATE", "INT_2COMP",
        "SUBPIECE",
    }

    COMPARE_OPS = {
        "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
        "INT_LESSEQUAL", "INT_SLESSEQUAL",
    }

    TRANSPARENT_OPS = {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC"}
    PHI_OPS = {"MULTIEQUAL"}

    def __init__(self, pal_function):

        self.phi_dropin_post_update_promotion_events = []

        # v20k: used selector PHIs may have an incoming transparent COPY/CAST
        # whose leaf is already-existing concrete storage, e.g.
        #     COPY [local_18] -> v_4146
        #     MULTIEQUAL [v_4146, v_4147, v_4148] -> v_4149
        # Such an arm must be owned by an explicit predecessor-local PHI
        # drop-in.  Treating v_4146 as a normal source alias is unsafe because
        # transparent source ops are legitimately suppressible by the emitter;
        # after SGL emits the join only once this can leave v_4149 undefined.
        self.selector_passthrough_dropin_sids = set()
        self.selector_passthrough_dropin_ids = set()
        self.selector_passthrough_dropin_records = []
        self.selector_passthrough_events = []

        self.func = pal_function
        self.cfg = getattr(pal_function, "cfg", None)

        self.nodes, self.phi_nodes = self._load_semantic_graph(pal_function)

        self.condition_vars = list(getattr(pal_function, "condition_vars", []))
        self.return_vars = list(getattr(pal_function, "return_vars", []))

        # Compatibility only. Transition PHIs are not union-folded.
        self.parent = {}
        self.groups = {}
        self.var_map = {}

        # PHI transition products.
        self.phi_dropins = []
        self.phi_dropins_by_pred = {}
        self.phi_dropins_by_join = {}

        # Presentation metadata.
        self.inline_only_sids = set()
        self.suppress_assign_sids = set()
        self.materialize_sids = set()
        self.local_target_sids = set()
        self.preferred_expr_by_sid = {}

        # v8 explicit presentation policy. This is the layer-level answer to
        # "SSA assignment ghosts": decide here whether a formula SID is a real
        # executable value, an inline bridge, or a suppressed presentation-only
        # artifact. The emitter should eventually just obey this table.
        self.ssa_policy_by_sid = {}
        self.presentation_class_by_sid = {}

        # Direct PHI sources that can be folded into target assignment.
        self.phi_source_foldable_sids = set()

        # Diagnostics.
        self.pure_bridge_sids = set()
        self.copy_bridge_sids = set()
        self.compare_bridge_sids = set()
        self.identity_phi_nodes = []
        self.transition_phi_nodes = []
        self.skipped_phi_nodes = []
        self.no_inline_nodes = []
        self.use_counts = {}
        self.phi_source_counts = {}
        self.synthesized_phi_nodes = []
        self.synthesized_phi_sids = set()

        # Source SIDs renamed to a used temp-PHI target name.
        # Example: v_2697/v_2690 are one-shot sources for v_5848, so the
        # emitter can directly write:
        #     v_5848 = transform_b(...)
        #     v_5848 = transform_a(...)
        self.temp_phi_source_alias_sids = set()
        self.temp_phi_source_aliases = {}

        # v3/v7 diagnostics / policy.
        # Temp PHI outputs that are used after the join must be materialized
        # via branch-local PHI drop-ins, e.g. v_5848 = transform_b(acc).
        self.used_temp_phi_target_sids = set()

        # Precomputed before PHI classification. These are semantic selector
        # PHIs, not identity PHIs, even when their storage metadata is blank.
        self.used_temp_phi_output_sids = set()
        self.value_selector_phi_nodes = []

        self.phi_join_discovery_events = []

        # v18c: generalized PHI source aliasing.  A one-shot SSA source that
        # feeds a PHI target can be renamed to the target so the normal block
        # op becomes the transition assignment directly:
        #     v_1728 = mutate(...)      + PHI -> local_20
        # becomes:
        #     local_20 = mutate(...)
        # This generalizes the older temp-only v_5848 handling.
        self.phi_source_alias_sids = set()
        self.phi_source_aliases = {}

        # v18c: protected snapshot COPY temps, e.g.
        #     v_4658 = local_20
        #     local_20 = local_1c
        #     local_1c = v_4658
        # These are not transparent bridges; suppressing them breaks swaps.
        self.protected_copy_temp_sids = set()
        self.protected_copy_temp_info = {}

        # v18c: local-to-local COPY/MULTIEQUAL transitions that must be treated
        # as real executable assignments, not blank SSA ghosts.
        self.real_local_copy_sids = set()
        self.real_local_copy_info = {}

        # v18c: output SIDs of local state writes that must be emitted at their
        # owning ExecBlock location. This includes real local copies and
        # source->target PHI aliases.
        self.must_emit_state_write_sids = set()
        self.state_write_info = {}

        # v18c: PHI drop-ins attached to shared branch-tail predecessors must
        # be treated as path-local. The same pred block may be projected into
        # multiple SGL branch arms; emitter must not globally suppress these
        # records after first emission.
        self.path_local_phi_dropin_ids = set()
        self.path_local_phi_dropin_records = []

        # v18c: CALL/temp aliases accepted specifically to eliminate duplicate
        # PHI transition assignments where the remaining temp use is a local
        # same-block condition/test.
        self.duplicate_phi_cleanup_alias_sids = set()
        self.duplicate_phi_cleanup_alias_info = {}

        # v18c: temp expression SIDs whose normal defining op should emit under
        # a different target name, e.g. v_1728 -> local_20.
        self.state_transition_alias_sids = set()
        self.state_transition_aliases = {}

        # v18c: PHI source aliases make the normal op assignment sufficient; a
        # presentation-aware emitter may skip the matching drop-in.
        self.dropin_suppressed_by_source_alias = set()

        # v19/PALRAW: post-update aliases.  These are SSA temporaries that
        # represent the freshly-written value of a local state variable.
        # Canonical example from alpha_four:
        #     INT_ADD [local_14, 1] -> v_367
        #     MULTIEQUAL [..., v_367, ...] -> local_14
        # After emitter prints local_14 += 1, later conditions must refer to
        # local_14, not re-expand v_367 as local_14 + 1.
        self.post_update_alias_sids = set()
        self.post_update_aliases = {}
        self.post_update_consumer_sids = set()
        self.post_update_consumer_aliases = {}
        self.prefer_var_expr_sids = set()

        # v19 bookkeeping-only execution contracts.  These are not printer
        # prettification rules.  They identify SSA values/drop-ins that are
        # required for programmatic truth and must not be suppressed merely as
        # presentation bridges.
        self.condition_dependency_sids = set()
        self.required_call_result_sids = set()
        self.protected_condition_value_sids = set()
        self.required_phi_dropin_ids = set()
        self.required_phi_dropin_records = []
        self.non_suppressible_dropin_ids = set()
        self.non_suppressible_dropin_records = []
        self.executable_dropin_source_sids = set()
        self.state_alias_debug_events = []

        # v20 / ALPHA_SIX metadata-closure products.
        # These consume frozen SGL condition-consumer records and export exact
        # SID/node-backed facts for emitter use.  They are not text rewrite
        # instructions by themselves.
        sgl_handoff = getattr(pal_function, "sgl_metadata_handoff", {}) or {}
        self.sgl_condition_consumers = list(
            getattr(pal_function, "sgl_condition_consumers", None)
            or sgl_handoff.get("condition_consumers", [])
            or []
        )
        self.sgl_condition_provenance_sidecars = list(
            getattr(pal_function, "sgl_condition_provenance_sidecars", None)
            or sgl_handoff.get("condition_provenance_sidecars", [])
            or []
        )
        self.condition_temp_defs = []
        self.condition_temp_def_sids = set()
        self.post_update_condition_aliases = []
        self.post_update_condition_alias_sids = set()
        self.metadata_closure_events = []

        # v20b diagnostics for alias classification.  These are especially
        # useful when a generic PHI source alias is accepted but not promoted
        # to post-update state alias.
        self.post_update_alias_detection_events = []
        self.post_update_alias_reject_events = []

        # v20j: explicit promotion of executable PHI dropins whose source is a
        # pure stack-local update of the target, e.g.
        #     source_sid=v_367 target_name=local_14
        #     source_node=INT_ADD [local_14, 1] -> v_367
        self.phi_dropin_post_update_promotion_events = []

        # v20c: SGL-adjacent alias closure.  Some SGL RawCond conditions are
        # not represented as formula-node consumers of the update SID.  Example:
        #     block emits local_14 = local_14 + 1
        #     next SGL if uses condition text 4 < (local_14 + 1)
        # This pass records the adjacency-derived alias without touching SGL.
        self.sgl_adjacent_post_update_alias_events = []

        # v20d: same-address RawCond closure.  Sample Y has:
        #     block [0x10129b]
        #     if [cond=(4 < (local_14 + 1))]
        # where the state-write op and conditional branch share the same block
        # address.  This catches that shape without relying on ExecTree sibling
        # traversal.
        self.sgl_same_block_post_update_alias_events = []

        # v20e: fallback RawCond local-update closure. When formula linkage is
        # lost, infer only simple local +/- constant update expressions from
        # RawCond text, gated by a same-address state-write contract.
        self.sgl_rawcond_local_update_alias_events = []

        # v20f: exact block-local temp/update/compare closure.
        # Sample Y block:
        #     INT_ADD [local_14, 0x1] -> v_367
        #     INT_SLESS [0x4, v_367] -> v_436
        #     CBRANCH cond=v_436
        # If v_367 is already mapped to local_14, emit the post-update alias
        # from v_367 to local_14 for this condition block.
        self.block_local_temp_post_update_alias_events = []

        # v20g: transition-source consumed-by-condition closure.
        # Uses PHI/drop-in transition metadata as the authority for
        # v_367 -> local_14, then checks whether a same-block compare consumes
        # source_sid 367. This avoids depending on var_map[source_sid].
        self.transition_source_condition_alias_events = []

        # v20i: stack-mutating temp closure.
        # Ghidra/HF can represent an in-place stack update:
        #     ADD dword ptr [RBP-0xc], 1
        # as:
        #     INT_ADD [local_14, 0x1] -> v_367
        #     INT_SLESS [0x4, v_367] -> v_436
        # with no explicit local_14 PHI/writeback path.  This pass treats the
        # temp as the post-update value of the stack input when the same-block
        # branch condition consumes the temp.
        self.stack_update_temp_condition_alias_events = []

        # v21 / Inning M: consume PALCompute's immutable per-SSA contracts.
        #
        # PHIfolder is deliberately not allowed to rediscover numeric
        # semantics.  Its responsibility is narrower: bind an already-proven
        # compute plan to each execution form selected by PHI folding
        # (ordinary materialization, source->target alias, or predecessor-local
        # PHI drop-in), and prove that no width/helper boundary was lost.
        self.compute_input_plans_by_sid = dict(
            getattr(pal_function, "compute_plans_by_sid", {}) or {}
        )
        self.compute_input_contracts_by_op = dict(
            getattr(pal_function, "compute_contracts_by_op", {}) or {}
        )
        self.compute_input_control_contracts_by_block = dict(
            getattr(pal_function, "compute_control_contracts_by_block", {}) or {}
        )
        self.compute_input_storage_bindings_by_sid = dict(
            getattr(pal_function, "compute_storage_bindings_by_sid", {}) or {}
        )
        self.compute_input_indirect_contracts_by_output_sid = dict(
            getattr(pal_function, "compute_indirect_contracts_by_output_sid", {}) or {}
        )
        self.compute_input_indirect_contracts_by_op = dict(
            getattr(pal_function, "compute_indirect_contracts_by_op", {}) or {}
        )
        self.compute_consumer_active = bool(
            self.compute_input_plans_by_sid or self.compute_input_contracts_by_op
        )
        self.compute_contracts_by_op_forwarded = {}
        self.compute_outputless_contracts_by_op = {}
        self.compute_bindings_by_sid = {}
        self.compute_alias_bindings_by_sid = {}
        self.compute_phi_merge_contracts_by_sid = {}
        self.compute_phi_transition_contracts = []
        self.compute_phi_transition_contracts_by_pred = {}
        self.compute_phi_transition_contracts_by_join = {}
        self.compute_boundary_preservation_sids = set()
        self.compute_boundary_preservation_op_keys = set()
        self.compute_helper_preservation_sids = set()
        self.compute_helper_preservation_op_keys = set()
        self.compute_deferred_preservation_sids = set()
        self.compute_deferred_preservation_op_keys = set()
        self.compute_consumer_events = []
        self.compute_consumer_warnings = []

        # v22: bind SGL's frozen condition/formula provenance to PALCompute's
        # versioned storage families.  These products are execution-planning
        # metadata only.  They never turn INDIRECT into COPY, never introduce
        # a runtime INDIRECT helper, and never alter SSA presentation policy.
        self.condition_custody_bindings = []
        self.condition_custody_bindings_by_ref = {}
        self.condition_custody_bindings_by_addr = {}
        self.condition_storage_observation_sids = set()
        self.condition_storage_family_ids = set()
        self.condition_custody_owner_op_keys = set()
        self.condition_custody_indirect_op_keys = set()
        self.condition_custody_events = []
        self.condition_custody_warnings = []

        # ABI-F: PALCompute owns ABI classification.  PHIfolder consumes that
        # authority and records where every entry value is executed after
        # control-flow structuring.  This is deliberately separate from the
        # presentation suppressor: only predecessor-local PHI assignments
        # proven necessary receive a narrow must-print override.
        self.abi_function_entry_plan = dict(
            getattr(pal_function, "function_entry_abi_plan", {}) or {}
        )
        self.abi_call_site_plans_by_op = dict(
            getattr(pal_function, "call_site_abi_plans_by_op", {}) or {}
        )
        self.abi_return_boundary_reconciliation = dict(
            getattr(pal_function, "compute_return_boundary_reconciliation", {}) or {}
        )
        self.abi_entry_roots_by_sid = {}
        self.abi_entry_lineage_by_sid = {}
        self.abi_entry_execution_owners_by_sid = {}
        self.abi_entry_storage_owners_by_family = {}
        self.abi_entry_convergence_contracts = []
        self.abi_entry_convergence_by_target_sid = {}
        self.abi_entry_convergence_by_join = {}
        self.abi_entry_convergence_by_pred = {}
        self.abi_entry_must_print_dropin_ids = set()
        self.abi_entry_must_print_dropin_records = []
        self.abi_entry_path_unbound_records = []
        self.abi_entry_custody_events = []
        self.abi_entry_custody_warnings = []
        self.abi_entry_custody_inventory = {}
        self.abi_entry_root_sids = set()
        self.abi_entry_source_alias_rejections = []

    # ---------------------------------------------------------
    # Loading / run
    # ---------------------------------------------------------

    def _load_semantic_graph(self, func):
        formula_nodes = getattr(func, "formula_nodes", None)
        phi_nodes = getattr(func, "phi_nodes", None)

        if formula_nodes is not None:
            return formula_nodes or {}, phi_nodes or []

        raw = getattr(func, "var_nodes", None)

        if isinstance(raw, tuple):
            nodes = raw[0] if len(raw) >= 1 else {}
            phis = raw[1] if len(raw) >= 2 else []
            return nodes or {}, phis or []

        if isinstance(raw, dict):
            return raw, phi_nodes or []

        return {}, phi_nodes or []

    def run(self):
        # Some MULTIEQUAL ops, especially temp PHIs such as v_5848, can exist
        # in PAL block.ops but be absent from func.phi_nodes.  Synthesize them
        # before all analysis so drop-ins are planned for every real PHI op.
        self._synthesize_missing_phi_nodes_from_blocks()

        self._init_sets()
        self._prime_abi_entry_root_sids_v23()

        self._compute_use_counts()
        self._precompute_used_temp_phi_outputs()
        self._classify_phi_nodes()
        self._build_phi_dropins()

        self._mark_materialization_policy()
        self._protect_condition_dependency_materialization()

        self._build_groups_without_phi_union()
        self._protect_selector_passthrough_dropins_v20k()
        self._build_var_map()

        # v18 execution-policy passes. These must happen after var_map exists
        # and before presentation classification.
        self._apply_used_temp_phi_source_aliases()
        self._propagate_post_update_alias_consumers()
        self._protect_snapshot_copy_temps()
        self._protect_real_local_copy_state_writes()
        self._mark_path_local_phi_dropins()
        self._mark_required_executable_phi_dropins()
        self._suppress_duplicate_alias_dropins()
        self._finalize_state_write_policy()

        # v20j: promote executable PHI dropins that are real post-update
        # source writes before SGL condition metadata is consumed.
        self._promote_phi_dropin_post_update_aliases()

        # v20 / ALPHA_SIX: consume frozen SGL condition-consumer facts and
        # produce exact condition temp / post-update alias metadata.
        self._consume_sgl_condition_consumers()

        self._build_presentation_metadata()
        self._consume_abi_entry_convergence_custody_v23()
        self._consume_compute_contracts_v21()
        self._consume_condition_custody_sidecars_v22()
        self._expose()
        
        self.debug_dump_dropins()
        
        """
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        print(self.func.phi_folder_debug["sgl_adjacent_post_update_alias_events"])
        print(self.func.phi_folder_debug["post_update_condition_aliases"])
        print(self.func.phi_folder_debug["metadata_closure_events"])
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        """

        return self.var_map

    # ---------------------------------------------------------
    # PALCOMPUTE CONTRACT CONSUMPTION (v21 / Inning M)
    # ---------------------------------------------------------

    def _compute_plan_for_sid_v21(self, sid):
        """Return PALCompute's authoritative plan without rewriting it."""

        if sid is None:
            return None

        plans = self.compute_input_plans_by_sid
        if sid in plans:
            return plans.get(sid)

        text_sid = str(sid)
        if text_sid in plans:
            return plans.get(text_sid)

        return None

    def _refresh_compute_inputs_v21(self):
        """Refresh at run time so construction order cannot stale metadata."""

        self.compute_input_plans_by_sid = dict(
            getattr(self.func, "compute_plans_by_sid", {}) or {}
        )
        self.compute_input_contracts_by_op = dict(
            getattr(self.func, "compute_contracts_by_op", {}) or {}
        )
        self.compute_input_control_contracts_by_block = dict(
            getattr(self.func, "compute_control_contracts_by_block", {}) or {}
        )
        self.compute_input_storage_bindings_by_sid = dict(
            getattr(self.func, "compute_storage_bindings_by_sid", {}) or {}
        )
        self.compute_input_indirect_contracts_by_output_sid = dict(
            getattr(self.func, "compute_indirect_contracts_by_output_sid", {}) or {}
        )
        self.compute_input_indirect_contracts_by_op = dict(
            getattr(self.func, "compute_indirect_contracts_by_op", {}) or {}
        )
        self.compute_consumer_active = bool(
            self.compute_input_plans_by_sid or self.compute_input_contracts_by_op
        )

    def _compute_width_for_value_v21(self, value):
        var = self.to_var(value)
        if var is None:
            return None

        width = getattr(var, "width_bits", None)
        if isinstance(width, int) and width > 0:
            return width

        size = getattr(var, "size", None)
        if isinstance(size, int) and size > 0:
            return size * 8

        return None

    def _compute_contract_requires_preservation_v21(self, plan):
        if not isinstance(plan, dict):
            return False

        status = str(plan.get("status") or "")
        return bool(
            plan.get("c_compute_filter")
            or plan.get("preserve_boundary_through_phi_folding")
            or plan.get("runtime_helper")
            or status.startswith("deferred_")
            or status == "unsupported"
        )

    def _compute_execution_mode_for_sid_v21(self, sid, plan):
        if sid in self.state_transition_alias_sids:
            return "state_transition_alias"

        if isinstance(plan, dict) and plan.get("category") == "phi_merge":
            return "phi_transition_target"

        policy = self.ssa_policy_by_sid.get(sid, {}) or {}
        if policy.get("emit"):
            return "materialized_assignment"
        if policy.get("expr_mode") == "inline" or sid in self.inline_only_sids:
            return "inline_expression"
        if sid in self.suppress_assign_sids:
            return "suppressed_assignment_with_formula_consumer"
        return "visible_assignment"

    def _bind_compute_plan_v21(self, sid, plan):
        if not isinstance(plan, dict):
            return None

        execution_mode = self._compute_execution_mode_for_sid_v21(sid, plan)
        alias = self.state_transition_aliases.get(sid, {}) or {}
        preserve = self._compute_contract_requires_preservation_v21(plan)
        status = str(plan.get("status") or "")

        binding = {
            "kind": "phi_compute_execution_binding_v21",
            "version": self.COMPUTE_CONSUMER_VERSION,
            "source_sid": sid,
            "source_op_key": plan.get("op_key"),
            "source_opcode": plan.get("opcode"),
            "source_status": plan.get("status"),
            "source_category": plan.get("category"),
            "runtime_helper": plan.get("runtime_helper"),
            "output_width_bits": plan.get("output_width_bits"),
            "result_normalization": plan.get("result_normalization"),
            "execution_mode": execution_mode,
            "effective_target_sid": alias.get("target_sid", sid),
            "effective_target_name": (
                alias.get("target_name")
                or self.var_map.get(sid)
                or self.name_for_var(self.to_var(self.nodes.get(sid)))
            ),
            "preserve_compute_contract": preserve,
            "preserve_runtime_helper": bool(plan.get("runtime_helper")),
            "preserve_result_normalization": bool(
                plan.get("normalize_result_to_output_width")
                or plan.get("result_normalization")
            ),
            "compute_contract": plan,
            "authority": "PALCompute_contract_plus_PHIfolder_execution_ownership",
        }

        self.compute_bindings_by_sid[sid] = binding

        if preserve:
            self.compute_boundary_preservation_sids.add(sid)
        if plan.get("runtime_helper"):
            self.compute_helper_preservation_sids.add(sid)
        if status.startswith("deferred_"):
            self.compute_deferred_preservation_sids.add(sid)

        node = self.nodes.get(sid)
        if node is not None:
            node.phi_compute_binding = binding
            var = self.to_var(node)
            if var is not None:
                var.phi_compute_binding = binding

        return binding

    def _bind_compute_alias_v21(self, source_sid, alias_info):
        source_plan = self._compute_plan_for_sid_v21(source_sid)
        target_sid = alias_info.get("target_sid")
        target_plan = self._compute_plan_for_sid_v21(target_sid)

        if source_plan is None:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_alias_missing_source_contract_v21",
                "source_sid": source_sid,
                "target_sid": target_sid,
                "target_name": alias_info.get("target_name"),
            })
            return None

        source_width = source_plan.get("output_width_bits")
        target_width = target_plan.get("output_width_bits") if isinstance(target_plan, dict) else None
        width_consistent = bool(
            source_width is None or target_width is None or source_width == target_width
        )

        binding = {
            "kind": "phi_compute_state_alias_binding_v21",
            "version": self.COMPUTE_CONSUMER_VERSION,
            "source_sid": source_sid,
            "target_sid": target_sid,
            "target_name": alias_info.get("target_name"),
            "pred_addr": alias_info.get("pred_addr"),
            "join_addr": alias_info.get("join_addr"),
            "source_compute_contract": source_plan,
            "target_phi_compute_contract": target_plan,
            "runtime_helper": source_plan.get("runtime_helper"),
            "source_status": source_plan.get("status"),
            "source_width_bits": source_width,
            "target_width_bits": target_width,
            "width_consistent": width_consistent,
            "assignment_semantics": "evaluate_source_contract_once_then_write_raw_bits_to_target",
            "preserve_source_result_normalization": True,
            "preserve_target_phi_view": True,
            "authority": "PALCompute_source_contract;PHIfolder_alias_ownership",
        }

        self.compute_alias_bindings_by_sid[source_sid] = binding
        alias_info["compute_binding"] = binding

        state_info = self.state_write_info.get(source_sid)
        if isinstance(state_info, dict):
            state_info["compute_binding"] = binding

        if not width_consistent:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_alias_width_mismatch_v21",
                "source_sid": source_sid,
                "target_sid": target_sid,
                "source_width_bits": source_width,
                "target_width_bits": target_width,
            })

        if target_plan is None:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_alias_missing_target_phi_contract_v21",
                "source_sid": source_sid,
                "target_sid": target_sid,
                "target_name": alias_info.get("target_name"),
            })
        elif target_plan.get("category") != "phi_merge":
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_alias_target_not_phi_contract_v21",
                "source_sid": source_sid,
                "target_sid": target_sid,
                "target_category": target_plan.get("category"),
                "target_opcode": target_plan.get("opcode"),
            })

        return binding

    def _phi_compute_transition_contract_v21(self, rec):
        source_sid = rec.get("source_sid")
        target_sid = rec.get("target_sid")
        source_plan = self._compute_plan_for_sid_v21(source_sid)
        target_plan = self._compute_plan_for_sid_v21(target_sid)

        source_width = (
            source_plan.get("output_width_bits")
            if isinstance(source_plan, dict)
            else self._compute_width_for_value_v21(rec.get("source") or rec.get("source_var"))
        )
        target_width = (
            target_plan.get("output_width_bits")
            if isinstance(target_plan, dict)
            else self._compute_width_for_value_v21(rec.get("target"))
        )
        width_consistent = bool(
            source_width is None or target_width is None or source_width == target_width
        )

        source_alias_owns = bool(
            rec.get("source_aliased_to_target")
            or rec.get("accounted_for_by_state_alias")
            or source_sid in self.state_transition_alias_sids
        )
        execution_owner = "source_state_alias" if source_alias_owns else "predecessor_phi_dropin"

        preserve_source = self._compute_contract_requires_preservation_v21(source_plan)
        preserve_target = self._compute_contract_requires_preservation_v21(target_plan)

        contract = {
            "kind": "phi_compute_transition_contract_v21",
            "version": self.COMPUTE_CONSUMER_VERSION,
            "transition_id": self._phi_record_id(rec),
            "pred_addr": rec.get("pred_addr"),
            "join_addr": rec.get("join_addr"),
            "source_sid": source_sid,
            "source_name": rec.get("source_name"),
            "target_sid": target_sid,
            "target_name": rec.get("target_name"),
            "source_width_bits": source_width,
            "target_width_bits": target_width,
            "width_consistent": width_consistent,
            "source_compute_contract": source_plan,
            "target_phi_compute_contract": target_plan,
            "runtime_helper": source_plan.get("runtime_helper") if isinstance(source_plan, dict) else None,
            "source_status": source_plan.get("status") if isinstance(source_plan, dict) else "storage_or_constant_value",
            "execution_owner": execution_owner,
            "dropin_required": bool(rec.get("dropin_required")),
            "dropin_scope": rec.get("dropin_scope"),
            "preserve_source_compute_boundary": preserve_source,
            "preserve_target_phi_boundary": preserve_target,
            "transition_semantics": "select_predecessor_raw_bits_without_implicit_python_cast",
            "authority": "PALCompute_contracts_plus_PHIfolder_predecessor_mapping",
        }

        rec["compute_transition_contract"] = contract
        self.compute_phi_transition_contracts.append(contract)
        self.compute_phi_transition_contracts_by_pred.setdefault(
            rec.get("pred_addr"), []
        ).append(contract)
        self.compute_phi_transition_contracts_by_join.setdefault(
            rec.get("join_addr"), []
        ).append(contract)

        if not width_consistent:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_dropin_width_mismatch_v21",
                "transition_id": contract.get("transition_id"),
                "source_sid": source_sid,
                "target_sid": target_sid,
                "source_width_bits": source_width,
                "target_width_bits": target_width,
            })

        source_node = rec.get("source_node")
        source_opcode = getattr(source_node, "opcode", None) if source_node is not None else None
        if source_sid is not None and source_opcode and source_plan is None:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_dropin_missing_source_contract_v21",
                "transition_id": contract.get("transition_id"),
                "source_sid": source_sid,
                "source_opcode": source_opcode,
                "target_sid": target_sid,
            })

        if target_plan is None:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_dropin_missing_target_phi_contract_v21",
                "transition_id": contract.get("transition_id"),
                "source_sid": source_sid,
                "target_sid": target_sid,
            })
        elif target_plan.get("category") != "phi_merge":
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_dropin_target_not_phi_contract_v21",
                "transition_id": contract.get("transition_id"),
                "target_sid": target_sid,
                "target_category": target_plan.get("category"),
                "target_opcode": target_plan.get("opcode"),
            })

        return contract

    def _consume_compute_contracts_v21(self):
        """
        Bind PALCompute contracts to PHIfolder's final execution ownership.

        This pass is intentionally additive.  It does not alter var_map,
        drop-in suppression, source aliases, formulas, or presentation policy.
        It gives the emitter an authoritative recipe for whichever execution
        form PHIfolder already selected.
        """

        self._refresh_compute_inputs_v21()

        self.compute_bindings_by_sid = {}
        self.compute_contracts_by_op_forwarded = dict(self.compute_input_contracts_by_op)
        self.compute_outputless_contracts_by_op = {}
        self.compute_alias_bindings_by_sid = {}
        self.compute_phi_merge_contracts_by_sid = {}
        self.compute_phi_transition_contracts = []
        self.compute_phi_transition_contracts_by_pred = {}
        self.compute_phi_transition_contracts_by_join = {}
        self.compute_boundary_preservation_sids = set()
        self.compute_boundary_preservation_op_keys = set()
        self.compute_helper_preservation_sids = set()
        self.compute_helper_preservation_op_keys = set()
        self.compute_deferred_preservation_sids = set()
        self.compute_deferred_preservation_op_keys = set()
        self.compute_consumer_events = []
        self.compute_consumer_warnings = []

        if not self.compute_consumer_active:
            self.compute_consumer_events.append({
                "kind": "phi_compute_consumer_inactive_v21",
                "version": self.COMPUTE_CONSUMER_VERSION,
                "reason": "PALCompute_metadata_not_present",
            })
            return

        # Preserve contracts that have no SSA output (STORE and any future
        # outputless semantic operation).  They cannot be represented in the
        # SID-indexed plan map but remain mandatory emitter/runtime facts.
        for op_key, contract in self.compute_input_contracts_by_op.items():
            if not isinstance(contract, dict):
                self.compute_consumer_warnings.append({
                    "kind": "phi_compute_invalid_op_contract_v21",
                    "op_key": op_key,
                    "contract_type": type(contract).__name__,
                })
                continue

            output_sid = contract.get("output_sid")
            if output_sid is None:
                self.compute_outputless_contracts_by_op[op_key] = contract
                if self._compute_contract_requires_preservation_v21(contract):
                    self.compute_boundary_preservation_op_keys.add(op_key)
                if contract.get("runtime_helper"):
                    self.compute_helper_preservation_op_keys.add(op_key)
                if str(contract.get("status") or "").startswith("deferred_"):
                    self.compute_deferred_preservation_op_keys.add(op_key)
                continue

            if self._compute_plan_for_sid_v21(output_sid) is None:
                self.compute_consumer_warnings.append({
                    "kind": "phi_compute_op_output_missing_sid_plan_v21",
                    "op_key": op_key,
                    "output_sid": output_sid,
                    "opcode": contract.get("opcode"),
                })

        # First bind every output plan.  This inventory is deliberately
        # complete, including Python-safe plans, so later layers can audit that
        # no SSA producer disappeared during presentation folding.
        for key, plan in self.compute_input_plans_by_sid.items():
            if not isinstance(plan, dict):
                self.compute_consumer_warnings.append({
                    "kind": "phi_compute_invalid_plan_v21",
                    "sid": key,
                    "plan_type": type(plan).__name__,
                })
                continue

            sid = plan.get("output_sid")
            if sid is None:
                sid = key

            binding = self._bind_compute_plan_v21(sid, plan)
            if binding is None:
                continue

            if plan.get("category") == "phi_merge":
                self.compute_phi_merge_contracts_by_sid[sid] = plan

        accounted_op_keys = set(self.compute_outputless_contracts_by_op)
        for plan in self.compute_bindings_by_sid.values():
            op_key = plan.get("source_op_key")
            if op_key is not None:
                accounted_op_keys.add(op_key)

        missing_op_keys = sorted(
            set(self.compute_input_contracts_by_op) - accounted_op_keys,
            key=str,
        )
        if missing_op_keys:
            self.compute_consumer_warnings.append({
                "kind": "phi_compute_unaccounted_op_contracts_v21",
                "op_keys": missing_op_keys,
                "count": len(missing_op_keys),
            })

        # State aliases retain the source operation's helper/normalization;
        # only the assignment destination changes.
        for source_sid, alias_info in list(self.state_transition_aliases.items()):
            if not isinstance(alias_info, dict):
                self.compute_consumer_warnings.append({
                    "kind": "phi_compute_invalid_state_alias_v21",
                    "source_sid": source_sid,
                    "alias_type": type(alias_info).__name__,
                })
                continue
            self._bind_compute_alias_v21(source_sid, alias_info)

        # Every predecessor-local PHI transition receives an explicit compute
        # transport contract, even when its execution is owned by a source
        # alias and the redundant textual drop-in is suppressed.
        for rec in list(self.phi_dropins or []):
            if isinstance(rec, dict):
                self._phi_compute_transition_contract_v21(rec)

        # Audit all real PHI nodes, including identity PHIs that legitimately
        # require no drop-in records.
        for phi in list(self.phi_nodes or []):
            target_sid = self.sid_of(getattr(phi, "output", None))
            if target_sid is None:
                continue
            plan = self._compute_plan_for_sid_v21(target_sid)
            if plan is None:
                self.compute_consumer_warnings.append({
                    "kind": "phi_compute_missing_phi_contract_v21",
                    "target_sid": target_sid,
                })
                continue
            if plan.get("category") != "phi_merge":
                self.compute_consumer_warnings.append({
                    "kind": "phi_compute_wrong_phi_contract_v21",
                    "target_sid": target_sid,
                    "category": plan.get("category"),
                    "opcode": plan.get("opcode"),
                })
            try:
                phi.phi_compute_contract = plan
            except Exception:
                pass

        owner_counts = {}
        for contract in self.compute_phi_transition_contracts:
            owner = contract.get("execution_owner") or "unknown"
            owner_counts[owner] = owner_counts.get(owner, 0) + 1

        summary = {
            "kind": "phi_compute_consumer_inventory_v21",
            "version": self.COMPUTE_CONSUMER_VERSION,
            "active": True,
            "input_op_contracts": len(self.compute_input_contracts_by_op),
            "input_plans": len(self.compute_input_plans_by_sid),
            "bound_plans": len(self.compute_bindings_by_sid),
            "outputless_contracts_forwarded": len(self.compute_outputless_contracts_by_op),
            "phi_merge_contracts": len(self.compute_phi_merge_contracts_by_sid),
            "state_alias_bindings": len(self.compute_alias_bindings_by_sid),
            "phi_transition_contracts": len(self.compute_phi_transition_contracts),
            "transition_owners": owner_counts,
            "preserved_compute_boundaries": len(self.compute_boundary_preservation_sids),
            "preserved_outputless_boundaries": len(self.compute_boundary_preservation_op_keys),
            "preserved_runtime_helpers": len(self.compute_helper_preservation_sids),
            "preserved_outputless_helpers": len(self.compute_helper_preservation_op_keys),
            "preserved_deferred_contracts": len(self.compute_deferred_preservation_sids),
            "preserved_outputless_deferred_contracts": len(
                self.compute_deferred_preservation_op_keys
            ),
            "control_contracts_forwarded": sum(
                len(records or [])
                for records in self.compute_input_control_contracts_by_block.values()
            ),
            "warnings": len(self.compute_consumer_warnings),
            "rule": "preserve_PALCompute_authority_remap_execution_destination_only",
        }
        self.compute_consumer_events.append(summary)

    # ---------------------------------------------------------
    # SGL CONDITION / INDIRECT STORAGE CUSTODY (v22)
    # ---------------------------------------------------------

    def _sid_lookup_keys_v22(self, sid):
        if sid is None:
            return []

        keys = [sid, str(sid)]
        text = str(sid)
        if text.startswith("v_") and text[2:].isdigit():
            keys.extend([text[2:], int(text[2:])])
        elif text.isdigit():
            keys.extend(["v_%s" % text, int(text)])

        out = []
        seen = set()
        for key in keys:
            marker = (type(key).__name__, str(key))
            if marker in seen:
                continue
            seen.add(marker)
            out.append(key)
        return out

    def _lookup_sid_map_v22(self, mapping, sid):
        if not isinstance(mapping, dict):
            return None
        for key in self._sid_lookup_keys_v22(sid):
            if key in mapping:
                return mapping.get(key)
        return None

    def _canonical_sid_v22(self, sid):
        if sid is None:
            return None
        text = str(sid)
        if text.startswith("v_") or text.startswith("c_"):
            return text
        if text.isdigit():
            return "v_%s" % text
        return sid

    def _condition_storage_binding_for_sid_v22(self, sid):
        return self._lookup_sid_map_v22(
            self.compute_input_storage_bindings_by_sid, sid
        )

    def _condition_indirect_contract_for_sid_v22(self, sid):
        return self._lookup_sid_map_v22(
            self.compute_input_indirect_contracts_by_output_sid, sid
        )

    def _condition_compute_plan_for_sid_v22(self, sid):
        return self._lookup_sid_map_v22(self.compute_input_plans_by_sid, sid)

    def _condition_sidecar_input_v22(self):
        handoff = getattr(self.func, "sgl_metadata_handoff", {}) or {}
        return list(
            getattr(self.func, "sgl_condition_provenance_sidecars", None)
            or handoff.get("condition_provenance_sidecars", [])
            or self.sgl_condition_provenance_sidecars
            or []
        )

    def _condition_consumer_input_v22(self):
        handoff = getattr(self.func, "sgl_metadata_handoff", {}) or {}
        return list(
            getattr(self.func, "sgl_condition_consumers", None)
            or handoff.get("condition_consumers", [])
            or self.sgl_condition_consumers
            or []
        )

    def _condition_storage_custody_chain_v22(self, observed_sid, provenance_ref):
        """Return owner-ordered transitions from family entry to observation."""

        newest_to_oldest = []
        warnings = []
        seen = set()
        current_sid = self._canonical_sid_v22(observed_sid)
        observed_binding = self._condition_storage_binding_for_sid_v22(current_sid)
        observed_family = (
            observed_binding.get("family_id")
            if isinstance(observed_binding, dict)
            else None
        )

        while current_sid is not None:
            marker = str(current_sid)
            if marker in seen:
                warnings.append({
                    "kind": "phi_condition_storage_custody_cycle_v22",
                    "provenance_ref": provenance_ref,
                    "observed_sid": observed_sid,
                    "cycle_sid": current_sid,
                })
                break
            seen.add(marker)

            contract = self._condition_indirect_contract_for_sid_v22(current_sid)
            if not isinstance(contract, dict):
                break

            transition = contract.get("indirect_custody_transition") or {}
            owner = contract.get("effect_owner_binding") or {}
            prior_sid = self._canonical_sid_v22(transition.get("prior_sid"))
            output_sid = self._canonical_sid_v22(
                contract.get("output_sid") or transition.get("output_sid")
            )
            family_id = (
                contract.get("storage_family_id")
                or transition.get("family_id")
                or (contract.get("output_storage_binding") or {}).get("family_id")
            )

            transition_record = {
                "kind": "phi_condition_storage_custody_transition_v22",
                "version": self.CONDITION_CUSTODY_VERSION,
                "transition_id": transition.get("transition_id"),
                "prior_sid": prior_sid,
                "output_sid": output_sid,
                "family_id": family_id,
                "indirect_op_key": contract.get("op_key"),
                "indirect_op_id": contract.get("op_id"),
                "indirect_status": contract.get("status"),
                "custody_resolved": contract.get("custody_resolved"),
                "owner_compute_op_key": contract.get("effect_owner_compute_op_key"),
                "owner_op_id": owner.get("owner_op_id"),
                "owner_opcode": owner.get("owner_opcode"),
                "owner_category": owner.get("owner_category"),
                "owner_block_addr": owner.get("owner_block_addr"),
                "runtime_operation": contract.get("indirect_runtime_operation"),
                "emission_policy": contract.get("indirect_emission_policy"),
                "authority": contract.get("authority"),
            }
            newest_to_oldest.append(transition_record)

            if str(output_sid) != str(current_sid):
                warnings.append({
                    "kind": "phi_condition_indirect_output_sid_mismatch_v22",
                    "provenance_ref": provenance_ref,
                    "observed_sid": observed_sid,
                    "walk_sid": current_sid,
                    "contract_output_sid": output_sid,
                    "indirect_op_key": contract.get("op_key"),
                })
            if contract.get("custody_resolved") is not True:
                warnings.append({
                    "kind": "phi_condition_indirect_custody_unresolved_v22",
                    "provenance_ref": provenance_ref,
                    "observed_sid": observed_sid,
                    "output_sid": output_sid,
                    "indirect_op_key": contract.get("op_key"),
                    "status": contract.get("status"),
                })
            if contract.get("runtime_helper") is not None or contract.get("indirect_runtime_operation") is not False:
                warnings.append({
                    "kind": "phi_condition_indirect_runtime_policy_violation_v22",
                    "provenance_ref": provenance_ref,
                    "observed_sid": observed_sid,
                    "output_sid": output_sid,
                    "runtime_helper": contract.get("runtime_helper"),
                    "indirect_runtime_operation": contract.get("indirect_runtime_operation"),
                })
            if contract.get("effect_owner_compute_op_key") is None:
                warnings.append({
                    "kind": "phi_condition_indirect_owner_compute_binding_missing_v22",
                    "provenance_ref": provenance_ref,
                    "observed_sid": observed_sid,
                    "output_sid": output_sid,
                    "owner_op_id": owner.get("owner_op_id"),
                })
            if observed_family is not None and family_id is not None and str(observed_family) != str(family_id):
                warnings.append({
                    "kind": "phi_condition_storage_family_chain_mismatch_v22",
                    "provenance_ref": provenance_ref,
                    "observed_sid": observed_sid,
                    "observed_family_id": observed_family,
                    "transition_family_id": family_id,
                    "output_sid": output_sid,
                })

            current_sid = prior_sid

        return list(reversed(newest_to_oldest)), warnings

    def _active_condition_storage_observations_v22(self, sidecar):
        """
        Walk PALCompute contracts from the condition root to active storage.

        Encountering a versioned storage SID is a terminal observation point.
        Its pre-owner versions are recovered separately through the INDIRECT
        custody chain; they are not treated as simultaneously-live operands.
        """

        provenance_ref = sidecar.get("provenance_ref")
        root_sid = self._canonical_sid_v22(sidecar.get("effective_condition_sid"))
        observations = []
        traversal = []
        warnings = []
        visited = set()

        if root_sid is None:
            return observations, traversal, warnings

        stack = [(root_sid, None, 0)]
        while stack:
            sid, parent_sid, depth = stack.pop()
            sid = self._canonical_sid_v22(sid)
            marker = str(sid)
            if marker in visited:
                continue
            visited.add(marker)

            storage_binding = self._condition_storage_binding_for_sid_v22(sid)
            plan = self._condition_compute_plan_for_sid_v22(sid)
            traversal.append({
                "sid": sid,
                "parent_sid": parent_sid,
                "depth": depth,
                "compute_op_key": plan.get("op_key") if isinstance(plan, dict) else None,
                "compute_opcode": plan.get("opcode") if isinstance(plan, dict) else None,
                "storage_bound": isinstance(storage_binding, dict),
            })

            if isinstance(storage_binding, dict):
                chain, chain_warnings = self._condition_storage_custody_chain_v22(
                    sid, provenance_ref
                )
                warnings.extend(chain_warnings)
                indirect_contract = self._condition_indirect_contract_for_sid_v22(sid)
                observation = {
                    "kind": "phi_condition_storage_observation_v22",
                    "version": self.CONDITION_CUSTODY_VERSION,
                    "sid": sid,
                    "parent_formula_sid": parent_sid,
                    "formula_depth": depth,
                    "family_id": storage_binding.get("family_id"),
                    "high_name": storage_binding.get("high_name"),
                    "classification": storage_binding.get("classification"),
                    "storage_role": storage_binding.get("role"),
                    "address_tied": bool(storage_binding.get("address_tied")),
                    "persistent": bool(storage_binding.get("persistent")),
                    "entry_state": bool(storage_binding.get("entry_state")),
                    "custody_transition_output": bool(storage_binding.get("custody_transition_output")),
                    "storage_binding": storage_binding,
                    "indirect_contract": indirect_contract,
                    "custody_chain": chain,
                    "custody_chain_length": len(chain),
                    "observation_semantics": "read_latest_storage_family_state_reaching_condition_formula",
                    "authority": "PALCompute_storage_binding_plus_INDIRECT_owner_chain",
                }

                if observation.get("custody_transition_output") and not isinstance(indirect_contract, dict):
                    warnings.append({
                        "kind": "phi_condition_transition_output_missing_indirect_contract_v22",
                        "provenance_ref": provenance_ref,
                        "sid": sid,
                        "family_id": observation.get("family_id"),
                    })

                observations.append(observation)
                continue

            if not isinstance(plan, dict):
                continue

            input_sids = list(plan.get("input_sids", []) or [])
            for input_sid in reversed(input_sids):
                if input_sid is None or str(input_sid).startswith("c_"):
                    continue
                stack.append((input_sid, sid, depth + 1))

        if self._condition_compute_plan_for_sid_v22(root_sid) is None:
            warnings.append({
                "kind": "phi_condition_root_compute_contract_missing_v22",
                "provenance_ref": provenance_ref,
                "root_sid": root_sid,
                "source_op_key": sidecar.get("source_op_key"),
            })

        return observations, traversal, warnings

    def _consume_condition_custody_sidecars_v22(self):
        """
        Bind SGL condition provenance to PALCompute storage custody.

        This pass is non-rewriting and fail-closed.  It exports condition
        observation plans for the emitter/runtime layer but deliberately does
        not modify var_map, formulas, materialization, suppression, aliases,
        drop-ins, or the SGL predicate text.
        """

        self.sgl_condition_provenance_sidecars = self._condition_sidecar_input_v22()
        self.sgl_condition_consumers = self._condition_consumer_input_v22()
        self.condition_custody_bindings = []
        self.condition_custody_bindings_by_ref = {}
        self.condition_custody_bindings_by_addr = {}
        self.condition_storage_observation_sids = set()
        self.condition_storage_family_ids = set()
        self.condition_custody_owner_op_keys = set()
        self.condition_custody_indirect_op_keys = set()
        self.condition_custody_events = []
        self.condition_custody_warnings = []

        consumers_by_ref = {
            rec.get("provenance_ref"): rec
            for rec in self.sgl_condition_consumers
            if isinstance(rec, dict) and rec.get("provenance_ref")
        }

        for sidecar in self.sgl_condition_provenance_sidecars:
            if not isinstance(sidecar, dict):
                self.condition_custody_warnings.append({
                    "kind": "phi_condition_sidecar_not_mapping_v22",
                    "record_type": type(sidecar).__name__,
                })
                continue

            provenance_ref = sidecar.get("provenance_ref")
            consumer = consumers_by_ref.get(provenance_ref)
            authority = sidecar.get("dependency_authority")
            root_sid = self._canonical_sid_v22(sidecar.get("effective_condition_sid"))
            root_plan = self._condition_compute_plan_for_sid_v22(root_sid)

            observations = []
            traversal = []
            local_warnings = []
            text_storage_candidates = []

            if consumer is None:
                local_warnings.append({
                    "kind": "phi_condition_sidecar_consumer_missing_v22",
                    "provenance_ref": provenance_ref,
                })

            if authority == "formula_structure":
                observations, traversal, walk_warnings = (
                    self._active_condition_storage_observations_v22(sidecar)
                )
                local_warnings.extend(walk_warnings)

                reached = {str(rec.get("sid")) for rec in observations}
                custody_ancestry = set(reached)
                for observation in observations:
                    for transition in list(observation.get("custody_chain", []) or []):
                        for key in ("prior_sid", "output_sid"):
                            transition_sid = self._canonical_sid_v22(
                                transition.get(key)
                            )
                            if transition_sid is not None:
                                custody_ancestry.add(str(transition_sid))
                flat_storage = []
                for sid in list(sidecar.get("formula_dependency_sids", []) or []):
                    binding = self._condition_storage_binding_for_sid_v22(sid)
                    if isinstance(binding, dict):
                        flat_storage.append(self._canonical_sid_v22(sid))
                unreachable = [
                    sid for sid in flat_storage
                    if str(sid) not in custody_ancestry
                ]
                if unreachable:
                    local_warnings.append({
                        "kind": "phi_condition_flat_storage_dependencies_not_reachable_from_compute_root_v22",
                        "provenance_ref": provenance_ref,
                        "root_sid": root_sid,
                        "unreachable_storage_sids": unreachable,
                    })
            else:
                for sid in list(sidecar.get("text_dependency_sids", []) or []):
                    binding = self._condition_storage_binding_for_sid_v22(sid)
                    if isinstance(binding, dict):
                        text_storage_candidates.append({
                            "sid": self._canonical_sid_v22(sid),
                            "storage_binding": binding,
                        })
                if text_storage_candidates:
                    local_warnings.append({
                        "kind": "phi_condition_text_only_storage_custody_deferred_v22",
                        "provenance_ref": provenance_ref,
                        "candidate_sids": [
                            rec.get("sid") for rec in text_storage_candidates
                        ],
                    })

            storage_families = []
            indirect_transition_count = 0
            owner_op_keys = []
            indirect_op_keys = []
            for observation in observations:
                sid = observation.get("sid")
                family_id = observation.get("family_id")
                if sid is not None:
                    self.condition_storage_observation_sids.add(sid)
                if family_id is not None:
                    self.condition_storage_family_ids.add(family_id)
                    if family_id not in storage_families:
                        storage_families.append(family_id)

                for transition in list(observation.get("custody_chain", []) or []):
                    indirect_transition_count += 1
                    indirect_key = transition.get("indirect_op_key")
                    owner_key = transition.get("owner_compute_op_key")
                    if indirect_key is not None and indirect_key not in indirect_op_keys:
                        indirect_op_keys.append(indirect_key)
                        self.condition_custody_indirect_op_keys.add(indirect_key)
                    if owner_key is not None and owner_key not in owner_op_keys:
                        owner_op_keys.append(owner_key)
                        self.condition_custody_owner_op_keys.add(owner_key)

            if local_warnings or text_storage_candidates:
                status = "deferred_condition_storage_custody"
            elif observations:
                status = "bound_condition_storage_custody"
            else:
                status = "no_storage_custody_required"

            binding = {
                "kind": "phi_condition_storage_custody_binding_v22",
                "version": self.CONDITION_CUSTODY_VERSION,
                "provenance_ref": provenance_ref,
                "consumer_kind": sidecar.get("consumer_kind") or (consumer or {}).get("kind"),
                "consumer_addr": sidecar.get("consumer_addr") or (consumer or {}).get("addr"),
                "consumer_role": sidecar.get("consumer_role") or (consumer or {}).get("role"),
                "condition_expr": sidecar.get("condition_expr"),
                "condition_representation": sidecar.get("condition_representation"),
                "dependency_authority": authority,
                "root_condition_sid": root_sid,
                "root_compute_contract": root_plan,
                "storage_observations": observations,
                "storage_observation_sids": [rec.get("sid") for rec in observations],
                "storage_family_ids": storage_families,
                "indirect_transition_count": indirect_transition_count,
                "indirect_op_keys": indirect_op_keys,
                "effect_owner_compute_op_keys": owner_op_keys,
                "formula_traversal": traversal,
                "text_storage_candidates": text_storage_candidates,
                "status": status,
                "condition_truth_authority": "SGL_RawCond_or_formula_sidecar",
                "numeric_execution_authority": "PALCompute_root_condition_contract",
                "storage_execution_authority": "PALCompute_INDIRECT_storage_family_contracts",
                "execution_policy": (
                    "execute_effect_owners_in_CFG_order_then_observe_latest_storage_family_state_at_condition"
                    if observations
                    else "ordinary_condition_compute_contract"
                ),
                "indirect_emission_policy": "do_not_render_INDIRECT_as_runtime_expression",
                "presentation_policy_mutated": False,
                "warnings": local_warnings,
            }

            self.condition_custody_bindings.append(binding)
            if provenance_ref is not None:
                self.condition_custody_bindings_by_ref[provenance_ref] = binding
            addr = binding.get("consumer_addr")
            self.condition_custody_bindings_by_addr.setdefault(addr, []).append(binding)
            self.condition_custody_warnings.extend(local_warnings)

        bound = sum(
            1 for rec in self.condition_custody_bindings
            if rec.get("status") == "bound_condition_storage_custody"
        )
        deferred = sum(
            1 for rec in self.condition_custody_bindings
            if str(rec.get("status") or "").startswith("deferred_")
        )
        no_storage = sum(
            1 for rec in self.condition_custody_bindings
            if rec.get("status") == "no_storage_custody_required"
        )
        summary = {
            "kind": "phi_condition_storage_custody_inventory_v22",
            "version": self.CONDITION_CUSTODY_VERSION,
            "active": bool(self.sgl_condition_provenance_sidecars),
            "input_sidecars": len(self.sgl_condition_provenance_sidecars),
            "condition_bindings": len(self.condition_custody_bindings),
            "bound_storage_conditions": bound,
            "no_storage_conditions": no_storage,
            "deferred_conditions": deferred,
            "storage_observations": sum(
                len(rec.get("storage_observations", []) or [])
                for rec in self.condition_custody_bindings
            ),
            "storage_families": len(self.condition_storage_family_ids),
            "indirect_transitions": sum(
                int(rec.get("indirect_transition_count") or 0)
                for rec in self.condition_custody_bindings
            ),
            "effect_owner_compute_ops": len(self.condition_custody_owner_op_keys),
            "indirect_compute_ops": len(self.condition_custody_indirect_op_keys),
            "warnings": len(self.condition_custody_warnings),
            "presentation_policy_mutations": 0,
            "runtime_indirect_helpers": 0,
            "rule": "SGL_condition_truth_plus_PALCompute_latest_storage_observation",
        }
        self.condition_custody_events.append(summary)

    # ---------------------------------------------------------
    # ABI-F ENTRY STATE / CONVERGENCE CUSTODY (v23)
    # ---------------------------------------------------------

    @staticmethod
    def _abi_sid_v23(value):
        if value is None:
            return None
        return str(value)

    def _prime_abi_entry_root_sids_v23(self):
        """Identify ABI-D live-ins before any PHI source-alias optimizer.

        Entry-owned SSA identities are immutable roots.  They may be copied
        into a PHI target on each predecessor, but the source identity itself
        must never be globally renamed to that target.
        """

        entry = dict(getattr(self.func, "function_entry_abi_plan", {}) or {})
        roots = set()
        self.abi_entry_source_alias_rejections = []
        for item in list(entry.get("fixed_arguments", []) or []):
            if not isinstance(item, dict):
                continue
            values = [item.get("source_sid")]
            values.extend(list(item.get("physical_sids", []) or []))
            roots.update(
                self._abi_sid_v23(value)
                for value in values if value is not None
            )
        for item in list(entry.get("implicit_inputs", []) or []):
            if isinstance(item, dict) and item.get("sid") is not None:
                roots.add(self._abi_sid_v23(item.get("sid")))
        save_area = dict(entry.get("variadic_register_save_area") or {})
        for item in list(save_area.get("slots", []) or []):
            if isinstance(item, dict) and item.get("sid") is not None:
                roots.add(self._abi_sid_v23(item.get("sid")))
        self.abi_entry_root_sids = roots
        return roots

    def _refresh_abi_inputs_v23(self):
        """Refresh ABI-D products without re-inferring any ABI fact."""

        self.abi_function_entry_plan = dict(
            getattr(self.func, "function_entry_abi_plan", {}) or {}
        )
        self.abi_call_site_plans_by_op = dict(
            getattr(self.func, "call_site_abi_plans_by_op", {}) or {}
        )
        self.abi_return_boundary_reconciliation = dict(
            getattr(self.func, "compute_return_boundary_reconciliation", {}) or {}
        )

        # PALCompute metadata can be refreshed independently of PHIfolder.
        # Keep the existing v21 input maps synchronized for ABI-F too.
        self._refresh_compute_inputs_v21()

    def _abi_var_for_sid_v23(self, sid):
        sid = self._abi_sid_v23(sid)
        if sid is None:
            return None

        node = self.nodes.get(sid)
        if node is not None:
            var = self.to_var(node)
            if var is not None:
                return var

        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                values = [getattr(op, "output", None)]
                values.extend(list(getattr(op, "inputs", []) or []))
                for value in values:
                    if self._abi_sid_v23(self.sid_of(value)) == sid:
                        return self.to_var(value)
            term = getattr(block, "terminator", None)
            if term is not None:
                values = [getattr(term, "output", None)]
                values.extend(list(getattr(term, "inputs", []) or []))
                for value in values:
                    if self._abi_sid_v23(self.sid_of(value)) == sid:
                        return self.to_var(value)
        return None

    def _abi_name_for_sid_v23(self, sid, fallback=None):
        var = self._abi_var_for_sid_v23(sid)
        name = self.name_for_var(var) if var is not None else None
        return name or self.var_map.get(str(sid)) or fallback or str(sid)

    def _register_abi_entry_root_v23(self, sid, record):
        sid = self._abi_sid_v23(sid)
        if sid is None:
            return None

        record = dict(record or {})
        root_id = record.get("root_id") or "abi_entry:%s" % sid
        record.update({
            "kind": "phi_abi_entry_root_contract_v23",
            "version": self.ABI_ENTRY_CUSTODY_VERSION,
            "root_id": root_id,
            "sid": sid,
            "execution_name": self._abi_name_for_sid_v23(
                sid,
                record.get("canonical_alias") or record.get("name"),
            ),
            "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            "execution_owner": "function_entry_abi_plan",
            "owner_status": "owned_at_function_entry",
            "downstream_reinference_allowed": False,
            "authority": "PALCompute_function_entry_abi_plan",
        })

        existing = self.abi_entry_roots_by_sid.get(sid)
        if isinstance(existing, dict):
            # Prefer the more semantic implicit/fixed-argument record over a
            # register-save fallback for the same physical SID.
            if existing.get("root_class") != "physical_carrier":
                return existing
            old_root_id = existing.get("root_id")
            if old_root_id is not None:
                self._abi_lineage_sets.setdefault(sid, set()).discard(
                    old_root_id
                )

        self.abi_entry_roots_by_sid[sid] = record
        self._abi_lineage_sets.setdefault(sid, set()).add(root_id)
        self.abi_entry_execution_owners_by_sid[sid] = {
            "kind": "phi_abi_entry_execution_owner_v23",
            "version": self.ABI_ENTRY_CUSTODY_VERSION,
            "sid": sid,
            "root_id": root_id,
            "root_sid": sid,
            "execution_name": record.get("execution_name"),
            "owner_class": "entry_materialization",
            "execution_owner": "function_entry_abi_plan",
            "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            "materialization": record.get("materialization"),
            "destination": record.get("destination"),
            "authority": "PALCompute_function_entry_abi_plan",
        }
        return record

    def _collect_abi_entry_roots_v23(self):
        entry = self.abi_function_entry_plan

        for item in list(entry.get("fixed_arguments", []) or []):
            if not isinstance(item, dict):
                continue
            logical_sid = self._abi_sid_v23(item.get("source_sid"))
            physical_sids = [
                self._abi_sid_v23(value)
                for value in list(item.get("physical_sids", []) or [])
                if value is not None
            ]
            root_sid = logical_sid or (physical_sids[0] if physical_sids else None)
            root_id = "abi_fixed_argument:%s:%s" % (
                item.get("ordinal"), root_sid,
            )
            base = {
                "root_id": root_id,
                "root_class": "fixed_argument",
                "ordinal": item.get("ordinal"),
                "name": item.get("name") or item.get("logical_name"),
                "role": "fixed_argument",
                "custody_class": "logical_parameter",
                "materialization": item.get("materialization"),
                "destination": item.get("python_source"),
            }
            if logical_sid is not None:
                self._register_abi_entry_root_v23(logical_sid, base)
            for physical_sid in physical_sids:
                physical = dict(base)
                physical["root_class"] = "physical_carrier"
                physical["logical_root_sid"] = logical_sid
                self._register_abi_entry_root_v23(physical_sid, physical)

        for item in list(entry.get("implicit_inputs", []) or []):
            if not isinstance(item, dict):
                continue
            sid = self._abi_sid_v23(item.get("sid"))
            self._register_abi_entry_root_v23(sid, {
                "root_id": "abi_implicit:%s:%s" % (item.get("role"), sid),
                "root_class": "implicit_machine_input",
                "canonical_alias": item.get("canonical_alias"),
                "role": item.get("role"),
                "custody_class": item.get("custody_class"),
                "width_bits": item.get("width_bits"),
                "register": item.get("register"),
                "materialization": item.get("materialization"),
                "destination": item.get("destination"),
            })

        # Some compatibility entry plans expose physical carriers only in the
        # register-save area.  They remain entry-owned, but this fallback never
        # promotes them to logical Python parameters.
        save_area = dict(entry.get("variadic_register_save_area") or {})
        for item in list(save_area.get("slots", []) or []):
            if not isinstance(item, dict):
                continue
            sid = self._abi_sid_v23(item.get("sid"))
            if sid in self.abi_entry_roots_by_sid:
                continue
            self._register_abi_entry_root_v23(sid, {
                "root_id": "abi_physical_carrier:%s" % sid,
                "root_class": "physical_carrier",
                "canonical_alias": item.get("canonical_alias"),
                "role": item.get("owner_role") or "register_live_in",
                "custody_class": item.get("owner_namespace"),
                "width_bits": item.get("width_bits"),
                "register": item.get("register"),
                "materialization": item.get("materialization"),
                "destination": item.get("source"),
            })

    def _iter_dataflow_nodes_v23(self):
        seen = set()
        for node in list(self.nodes.values()):
            sid = self._abi_sid_v23(self.sid_of(node))
            marker = (sid, id(node))
            if marker in seen:
                continue
            seen.add(marker)
            yield node

        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                sid = self._abi_sid_v23(self.sid_of(getattr(op, "output", None)))
                marker = (sid, id(op))
                if marker in seen:
                    continue
                seen.add(marker)
                yield op

    def _storage_binding_v23(self, sid):
        sid = self._abi_sid_v23(sid)
        for key in self._sid_lookup_keys_v22(sid):
            value = self.compute_input_storage_bindings_by_sid.get(key)
            if isinstance(value, dict):
                return value
        return None

    def _collect_abi_storage_owners_v23(self):
        """Bind address-tied entry values to existing compute owners."""

        contracts_by_output = {}

        # A storage family can begin directly at an ABI live-in even when no
        # explicit parameter-initializer COPY survived high-p-code cleanup.
        for key, binding in self.compute_input_storage_bindings_by_sid.items():
            if not isinstance(binding, dict) or not binding.get("entry_state"):
                continue
            sid = self._abi_sid_v23(binding.get("sid") or key)
            roots = set(self._abi_lineage_sets.get(sid, set()))
            family_id = binding.get("family_id")
            if not roots or family_id is None:
                continue
            owner = {
                "kind": "phi_abi_entry_storage_owner_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "family_id": family_id,
                "source_sid": sid,
                "output_sid": sid,
                "root_ids": sorted(roots, key=str),
                "owner_class": "storage_family_entry",
                "execution_owner": "PALCompute_storage_family_entry",
                "owner_op_key": None,
                "address_tied": bool(binding.get("address_tied")),
                "emission_policy": "entry_identity_already_materialized",
                "must_print_override": False,
                "authority": "PALCompute_storage_binding_entry_state",
            }
            self.abi_entry_storage_owners_by_family[family_id] = owner
            self.abi_entry_execution_owners_by_sid.setdefault(sid, owner)

        for op_key, contract in self.compute_input_contracts_by_op.items():
            if not isinstance(contract, dict):
                continue
            output_sid = self._abi_sid_v23(contract.get("output_sid"))
            if output_sid is not None:
                contracts_by_output.setdefault(output_sid, []).append((op_key, contract))

            initializer = contract.get("parameter_storage_initializer")
            if not isinstance(initializer, dict):
                continue
            source_sid = self._abi_sid_v23(initializer.get("source_sid"))
            output_sid = self._abi_sid_v23(
                initializer.get("output_sid") or contract.get("output_sid")
            )
            source_roots = set(self._abi_lineage_sets.get(source_sid, set()))
            if source_roots and output_sid is not None:
                self._abi_lineage_sets.setdefault(output_sid, set()).update(source_roots)

            family_id = initializer.get("family_id") or contract.get("storage_family_id")
            owner = {
                "kind": "phi_abi_entry_storage_owner_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "family_id": family_id,
                "source_sid": source_sid,
                "output_sid": output_sid,
                "root_ids": sorted(source_roots, key=str),
                "owner_class": "address_tied_entry_initializer",
                "execution_owner": "PALCompute_parameter_storage_initializer",
                "owner_op_key": op_key,
                "address_tied": bool(
                    (contract.get("output_storage_binding") or {}).get("address_tied")
                ),
                "emission_policy": "preserve_existing_compute_storage_write_through",
                "must_print_override": False,
                "authority": "PALCompute_parameter_storage_initializer",
            }
            if family_id is not None:
                self.abi_entry_storage_owners_by_family[family_id] = owner
            if output_sid is not None:
                self.abi_entry_execution_owners_by_sid[output_sid] = owner

        # Carry each versioned family forward through INDIRECT effect owners.
        # INDIRECT itself remains metadata-only; ownership belongs to the
        # CALL/STORE contract selected by PALCompute.
        for output_sid, records in contracts_by_output.items():
            roots = set(self._abi_lineage_sets.get(output_sid, set()))
            for op_key, contract in records:
                binding = contract.get("output_storage_binding")
                transition = contract.get("indirect_custody_transition")
                family_id = (
                    (binding or {}).get("family_id")
                    or (transition or {}).get("family_id")
                    or contract.get("storage_family_id")
                )
                if family_id is None:
                    continue

                family_owner = self.abi_entry_storage_owners_by_family.get(family_id)
                if family_owner and not roots:
                    roots.update(family_owner.get("root_ids", []) or [])
                    self._abi_lineage_sets.setdefault(output_sid, set()).update(roots)

                if contract.get("opcode") != "INDIRECT":
                    continue
                owner_binding = dict(contract.get("effect_owner_binding") or {})
                owner = {
                    "kind": "phi_abi_entry_storage_owner_v23",
                    "version": self.ABI_ENTRY_CUSTODY_VERSION,
                    "family_id": family_id,
                    "output_sid": output_sid,
                    "root_ids": sorted(roots, key=str),
                    "owner_class": "versioned_storage_after_effect_owner",
                    "execution_owner": "PALCompute_effect_owner",
                    "owner_op_key": owner_binding.get("owner_compute_op_key"),
                    "indirect_op_key": op_key,
                    "emission_policy": "execute_owner_once_then_observe_storage_family",
                    "must_print_override": False,
                    "authority": "PALCompute_INDIRECT_effect_owner_binding",
                }
                self.abi_entry_execution_owners_by_sid[output_sid] = owner

    def _propagate_abi_entry_lineage_v23(self):
        """Propagate identity custody, never numeric or ABI placement."""

        transport_ops = set(self.TRANSPARENT_OPS) | {
            "SUBPIECE", "PIECE", "INDIRECT", "MULTIEQUAL",
        }
        nodes = list(self._iter_dataflow_nodes_v23())
        limit = max(2, len(nodes) + 1)

        for _ in range(limit):
            changed = False
            for node in nodes:
                opcode = str(getattr(node, "opcode", "") or "").upper()
                if opcode not in transport_ops:
                    continue
                out = getattr(node, "output", None)
                if out is None and hasattr(node, "var"):
                    out = getattr(node, "var", None)
                output_sid = self._abi_sid_v23(
                    self.sid_of(out if out is not None else node)
                )
                if output_sid is None:
                    continue

                roots = set()
                inputs = list(getattr(node, "inputs", []) or [])
                if opcode == "INDIRECT" and inputs:
                    # Input 1 is an IOP owner reference, not value lineage.
                    inputs = inputs[:1]
                for value in inputs:
                    input_sid = self._abi_sid_v23(self.sid_of(value))
                    roots.update(self._abi_lineage_sets.get(input_sid, set()))

                binding = self._storage_binding_v23(output_sid)
                family_id = (binding or {}).get("family_id")
                family_owner = self.abi_entry_storage_owners_by_family.get(family_id)
                if family_owner:
                    roots.update(family_owner.get("root_ids", []) or [])

                if not roots:
                    continue
                target = self._abi_lineage_sets.setdefault(output_sid, set())
                before = len(target)
                target.update(roots)
                if output_sid not in self.abi_entry_execution_owners_by_sid:
                    plan = self._compute_plan_for_sid_v21(output_sid)
                    self.abi_entry_execution_owners_by_sid[output_sid] = {
                        "kind": "phi_abi_entry_execution_owner_v23",
                        "version": self.ABI_ENTRY_CUSTODY_VERSION,
                        "sid": output_sid,
                        "root_ids": sorted(target, key=str),
                        "execution_name": self._abi_name_for_sid_v23(output_sid),
                        "owner_class": (
                            "phi_transport_pending_convergence_proof"
                            if opcode == "MULTIEQUAL"
                            else "identity_transport_compute"
                        ),
                        "execution_owner": (
                            "PALCompute_contract"
                            if isinstance(plan, dict)
                            else "semantic_graph_transport_node"
                        ),
                        "owner_op_key": (
                            plan.get("op_key") if isinstance(plan, dict) else None
                        ),
                        "opcode": opcode,
                        "authority": (
                            "PALCompute_transport_contract"
                            if isinstance(plan, dict)
                            else "formula_structure_transport_only"
                        ),
                    }
                if len(target) != before:
                    changed = True
            if not changed:
                break

        self.abi_entry_lineage_by_sid = {
            sid: sorted(roots, key=str)
            for sid, roots in self._abi_lineage_sets.items()
            if roots
        }

    def _abi_root_record_by_id_v23(self, root_id):
        for record in self.abi_entry_roots_by_sid.values():
            if record.get("root_id") == root_id:
                return record
        return None

    def _abi_no_return_blocks_v23(self):
        blocks = set(
            self.abi_return_boundary_reconciliation.get(
                "no_return_terminating_blocks", []
            ) or []
        )
        for plan in self.abi_call_site_plans_by_op.values():
            if isinstance(plan, dict) and plan.get("no_return"):
                addr = plan.get("block_addr")
                if addr is not None:
                    blocks.add(addr)
        return blocks

    def _abi_phi_existing_dropin_v23(self, join_addr, pred_addr, target_sid):
        target_sid = self._abi_sid_v23(target_sid)
        for rec in self.phi_dropins_by_pred.get(pred_addr, []) or []:
            if (
                rec.get("join_addr") == join_addr
                and self._abi_sid_v23(rec.get("target_sid")) == target_sid
            ):
                return rec
        return None

    def _abi_source_for_root_v23(self, root_id, phi_inputs):
        for value in list(phi_inputs or []):
            sid = self._abi_sid_v23(self.sid_of(value))
            if root_id in self._abi_lineage_sets.get(sid, set()):
                return value
        root = self._abi_root_record_by_id_v23(root_id) or {}
        sid = root.get("sid")
        var = self._abi_var_for_sid_v23(sid)
        return var

    def _synthesize_abi_phi_dropin_v23(
        self, phi, join_node, pred_node, incoming, root_id,
    ):
        out = getattr(phi, "output", None)
        target_sid = self._abi_sid_v23(self.sid_of(out))
        pred_addr = getattr(pred_node, "addr", None)
        join_addr = getattr(join_node, "addr", None)
        source_var = self.to_var(incoming)
        source_sid = self._abi_sid_v23(self.sid_of(incoming))
        root = self._abi_root_record_by_id_v23(root_id) or {}

        rec = {
            "kind": "phi_assignment",
            "phi": phi,
            "join_node": join_node,
            "join_addr": join_addr,
            "pred_node": pred_node,
            "pred_addr": pred_addr,
            "target": out,
            "target_sid": target_sid,
            "target_name": self.name_for_var(out),
            "source": incoming,
            "source_node": self.to_node(incoming),
            "source_var": source_var,
            "source_sid": source_sid,
            "source_name": self.name_for_var(source_var)
            or root.get("execution_name")
            or source_sid,
            "target_is_used_temp_phi": bool(
                target_sid in self.used_temp_phi_target_sids
            ),
            "target_is_value_selector_phi": bool(
                target_sid in self.used_temp_phi_output_sids
            ),
            "reason": "abi_entry_convergence_passthrough",
            "synthetic_abi_entry_transition": True,
        }
        self.phi_dropins.append(rec)
        self.phi_dropins_by_pred.setdefault(pred_addr, []).append(rec)
        self.phi_dropins_by_join.setdefault(join_addr, []).append(rec)
        return rec

    def _register_abi_must_print_dropin_v23(self, rec, root_id, inferred=False):
        rid = self._phi_record_id(rec)
        rec["abi_entry_custody"] = True
        rec["abi_entry_root_id"] = root_id
        rec["dropin_required"] = True
        rec["dropin_scope"] = "abi_entry_predecessor_convergence"
        rec["required_reason"] = (
            "ABI entry value requires predecessor-local convergence definition"
        )
        rec["must_print_override"] = True
        rec["must_print_reason"] = "prevent_path_sensitive_unbound_ABI_value"
        rec["abi_source_inferred_from_unique_root"] = bool(inferred)
        rec.pop("dropin_suppressed_reason", None)

        self.required_phi_dropin_ids.add(rid)
        self.non_suppressible_dropin_ids.add(rid)
        self.abi_entry_must_print_dropin_ids.add(rid)
        source_sid = rec.get("source_sid")
        if source_sid is not None:
            self.executable_dropin_source_sids.add(source_sid)

        compact = {
            "id": rid,
            "root_id": root_id,
            "join_addr": rec.get("join_addr"),
            "pred_addr": rec.get("pred_addr"),
            "target_sid": rec.get("target_sid"),
            "target_name": rec.get("target_name"),
            "source_sid": rec.get("source_sid"),
            "source_name": rec.get("source_name"),
            "inferred_from_unique_root": bool(inferred),
            "reason": rec.get("must_print_reason"),
        }
        if rid not in {
            item.get("id") for item in self.abi_entry_must_print_dropin_records
        }:
            self.abi_entry_must_print_dropin_records.append(compact)

        if rid not in {item.get("id") for item in self.required_phi_dropin_records}:
            self.required_phi_dropin_records.append(dict(compact))
        if rid not in {item.get("id") for item in self.non_suppressible_dropin_records}:
            ns = dict(compact)
            ns["reason"] = "ABI entry convergence cannot be presentation-suppressed"
            self.non_suppressible_dropin_records.append(ns)

        return rid

    def _build_abi_entry_convergence_contracts_v23(self):
        no_return_blocks = self._abi_no_return_blocks_v23()

        for phi in list(self.phi_nodes or []):
            out = getattr(phi, "output", None)
            inputs = list(getattr(phi, "inputs", []) or [])
            target_sid = self._abi_sid_v23(self.sid_of(out))
            if out is None or target_sid is None or not inputs:
                continue

            input_lineages = []
            for value in inputs:
                sid = self._abi_sid_v23(self.sid_of(value))
                input_lineages.append(set(self._abi_lineage_sets.get(sid, set())))

            # ABI-F may infer a pass-through only when every observed incoming
            # value has one and the same authoritative entry root.
            if not input_lineages or any(not roots for roots in input_lineages):
                continue
            union = set().union(*input_lineages)
            if len(union) != 1:
                continue
            root_id = next(iter(union))
            root = self._abi_root_record_by_id_v23(root_id)
            if root is None:
                continue

            join_node = self.cfg_node_for_phi(phi)
            join_addr = getattr(join_node, "addr", None) if join_node is not None else None
            preds = [
                pred for pred in self.pred_nodes_for_join(join_node)
                if getattr(pred, "addr", None) not in no_return_blocks
            ]
            if not preds:
                continue

            assignments = self._match_phi_inputs_to_predecessors(phi, preds)
            by_pred = {
                getattr(pred, "addr", None): incoming
                for pred, incoming in assignments
                if pred is not None and incoming is not None
            }
            source_fallback = self._abi_source_for_root_v23(root_id, inputs)
            target_name = self.name_for_var(out) or self.var_map.get(target_sid) or target_sid
            target_used = bool(
                self.use_counts.get(target_sid, 0) > 0
                or target_sid in self.condition_use_sids
                or target_sid in self.return_use_sids
            )
            path_contracts = []
            covered = 0

            for ordinal, pred in enumerate(preds):
                pred_addr = getattr(pred, "addr", None)
                incoming = by_pred.get(pred_addr)
                inferred = incoming is None
                if incoming is None:
                    incoming = source_fallback

                source_sid = self._abi_sid_v23(self.sid_of(incoming))
                source_roots = set(self._abi_lineage_sets.get(source_sid, set()))
                source_name = self._abi_name_for_sid_v23(
                    source_sid, root.get("execution_name")
                )
                same_storage = False
                try:
                    same_storage = self.same_storage(out, incoming)
                except Exception:
                    same_storage = False
                same_execution_name = bool(target_name and target_name == source_name)
                transition_needed = bool(
                    target_used and not same_storage and not same_execution_name
                )

                rec = self._abi_phi_existing_dropin_v23(
                    join_addr, pred_addr, target_sid
                )
                owner_class = None
                owner_id = None

                alias_owns = bool(
                    rec
                    and (
                        rec.get("source_aliased_to_target")
                        or rec.get("accounted_for_by_state_alias")
                        or rec.get("source_sid") in self.state_transition_alias_sids
                    )
                )

                if not transition_needed:
                    owner_class = "identity_passthrough"
                    owner_id = root.get("entry_plan_id")
                elif alias_owns:
                    owner_class = "source_state_alias"
                    owner_id = rec.get("source_sid")
                else:
                    if rec is None and incoming is not None:
                        rec = self._synthesize_abi_phi_dropin_v23(
                            phi, join_node, pred, incoming, root_id
                        )
                    if rec is not None:
                        owner_class = "predecessor_phi_dropin"
                        owner_id = self._register_abi_must_print_dropin_v23(
                            rec, root_id, inferred=inferred
                        )

                owned = bool(owner_class)
                if owned:
                    covered += 1
                else:
                    unbound = {
                        "kind": "phi_abi_path_sensitive_unbound_v23",
                        "version": self.ABI_ENTRY_CUSTODY_VERSION,
                        "root_id": root_id,
                        "root_sid": root.get("sid"),
                        "target_sid": target_sid,
                        "target_name": target_name,
                        "join_addr": join_addr,
                        "pred_addr": pred_addr,
                        "source_sid": source_sid,
                        "reason": "no_execution_owner_for_required_ABI_convergence",
                    }
                    self.abi_entry_path_unbound_records.append(unbound)
                    self.abi_entry_custody_warnings.append(unbound)

                path_contracts.append({
                    "path_ordinal": ordinal,
                    "pred_addr": pred_addr,
                    "source_sid": source_sid,
                    "source_name": source_name,
                    "source_root_ids": sorted(source_roots, key=str),
                    "source_matches_unique_root": root_id in source_roots,
                    "source_inferred_from_unique_root": bool(inferred),
                    "transition_required": transition_needed,
                    "execution_owner_class": owner_class,
                    "execution_owner_id": owner_id,
                    "owned": owned,
                })

            contract = {
                "kind": "phi_abi_entry_convergence_contract_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "root_id": root_id,
                "root_sid": root.get("sid"),
                "root_role": root.get("role"),
                "root_custody_class": root.get("custody_class"),
                "root_execution_name": root.get("execution_name"),
                "target_sid": target_sid,
                "target_name": target_name,
                "join_addr": join_addr,
                "target_used_after_join": target_used,
                "predecessor_count": len(preds),
                "owned_predecessor_count": covered,
                "all_predecessors_owned": covered == len(preds),
                "paths": path_contracts,
                "execution_policy": (
                    "predecessor_local_assignment_only_when_distinct_execution_name_required"
                ),
                "presentation_policy": "narrow_must_print_override_no_global_unsuppression",
                "authority": "PALCompute_entry_plan_plus_CFG_phi_predecessor_mapping",
            }
            self.abi_entry_convergence_contracts.append(contract)
            self.abi_entry_convergence_by_target_sid[target_sid] = contract
            self.abi_entry_convergence_by_join.setdefault(join_addr, []).append(contract)
            for path in path_contracts:
                self.abi_entry_convergence_by_pred.setdefault(
                    path.get("pred_addr"), []
                ).append({
                    "target_sid": target_sid,
                    "join_addr": join_addr,
                    "root_id": root_id,
                    "path": path,
                })

            self._abi_lineage_sets.setdefault(target_sid, set()).add(root_id)
            self.abi_entry_execution_owners_by_sid[target_sid] = {
                "kind": "phi_abi_entry_execution_owner_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "sid": target_sid,
                "root_id": root_id,
                "root_sid": root.get("sid"),
                "execution_name": target_name,
                "owner_class": "phi_convergence",
                "execution_owner": "predecessor_coverage_contract",
                "join_addr": join_addr,
                "all_predecessors_owned": covered == len(preds),
                "authority": "phi_abi_entry_convergence_contract_v23",
            }

    def _consume_abi_entry_convergence_custody_v23(self):
        """Consume ABI-D entry plans and bind their structured execution."""

        self._refresh_abi_inputs_v23()
        self.abi_entry_roots_by_sid = {}
        self.abi_entry_lineage_by_sid = {}
        self.abi_entry_execution_owners_by_sid = {}
        self.abi_entry_storage_owners_by_family = {}
        self.abi_entry_convergence_contracts = []
        self.abi_entry_convergence_by_target_sid = {}
        self.abi_entry_convergence_by_join = {}
        self.abi_entry_convergence_by_pred = {}
        self.abi_entry_must_print_dropin_ids = set()
        self.abi_entry_must_print_dropin_records = []
        self.abi_entry_path_unbound_records = []
        self.abi_entry_custody_events = []
        self.abi_entry_custody_warnings = []
        self.abi_entry_custody_inventory = {}
        self._abi_lineage_sets = {}

        suppress_before = set(self.suppress_assign_sids)
        if not self.abi_function_entry_plan:
            self.abi_entry_custody_inventory = {
                "kind": "phi_abi_entry_custody_inventory_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "active": False,
                "reason": "PALCompute_function_entry_abi_plan_missing",
                "warnings": 0,
            }
            self.abi_entry_custody_events.append(
                dict(self.abi_entry_custody_inventory)
            )
            return

        self._collect_abi_entry_roots_v23()
        self._collect_abi_storage_owners_v23()
        self._propagate_abi_entry_lineage_v23()
        self._build_abi_entry_convergence_contracts_v23()
        self._propagate_abi_entry_lineage_v23()

        root_sids = set(self.abi_entry_roots_by_sid)
        owner_sids = set(self.abi_entry_execution_owners_by_sid)
        roots_without_owner = sorted(root_sids - owner_sids, key=str)
        for sid in roots_without_owner:
            warning = {
                "kind": "phi_abi_entry_root_without_execution_owner_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "sid": sid,
                "reason": "entry_root_has_no_execution_owner",
            }
            self.abi_entry_custody_warnings.append(warning)

        lineage_sids = set(self.abi_entry_lineage_by_sid)
        lineage_without_owner = sorted(lineage_sids - owner_sids, key=str)
        for sid in lineage_without_owner:
            warning = {
                "kind": "phi_abi_entry_lineage_without_execution_owner_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "sid": sid,
                "root_ids": self.abi_entry_lineage_by_sid.get(sid, []),
                "reason": "entry_derived_value_has_no_execution_owner",
            }
            self.abi_entry_custody_warnings.append(warning)

        unnecessary = []
        for record in self.abi_entry_must_print_dropin_records:
            target_name = record.get("target_name")
            source_name = record.get("source_name")
            if target_name and source_name and target_name == source_name:
                unnecessary.append(record.get("id"))

        suppress_after = set(self.suppress_assign_sids)
        inventory = {
            "kind": "phi_abi_entry_custody_inventory_v23",
            "version": self.ABI_ENTRY_CUSTODY_VERSION,
            "active": True,
            "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            "entry_plan_status": self.abi_function_entry_plan.get("status"),
            "entry_roots": len(self.abi_entry_roots_by_sid),
            "entry_roots_with_execution_owner": len(root_sids & owner_sids),
            "entry_roots_without_execution_owner": len(roots_without_owner),
            "lineage_sids": len(self.abi_entry_lineage_by_sid),
            "lineage_sids_with_execution_owner": len(
                lineage_sids & owner_sids
            ),
            "lineage_sids_without_execution_owner": len(
                lineage_without_owner
            ),
            "address_tied_storage_families": len(
                self.abi_entry_storage_owners_by_family
            ),
            "call_site_plans_forwarded": len(self.abi_call_site_plans_by_op),
            "no_return_blocks_excluded_from_convergence": len(
                self._abi_no_return_blocks_v23()
            ),
            "convergence_contracts": len(
                self.abi_entry_convergence_contracts
            ),
            "convergence_predecessors": sum(
                rec.get("predecessor_count", 0)
                for rec in self.abi_entry_convergence_contracts
            ),
            "owned_convergence_predecessors": sum(
                rec.get("owned_predecessor_count", 0)
                for rec in self.abi_entry_convergence_contracts
            ),
            "must_print_dropin_overrides": len(
                self.abi_entry_must_print_dropin_ids
            ),
            "entry_root_source_alias_rejections": len(
                self.abi_entry_source_alias_rejections
            ),
            "unnecessary_must_print_overrides": len(unnecessary),
            "path_sensitive_unbound_names": len(
                self.abi_entry_path_unbound_records
            ),
            "suppression_policy_mutations": len(
                suppress_before.symmetric_difference(suppress_after)
            ),
            "warnings": len(self.abi_entry_custody_warnings),
            "acceptance_gates": {
                "no_path_sensitive_unbound_names": not bool(
                    self.abi_entry_path_unbound_records
                ),
                "all_ABI_entry_values_have_execution_owner": not bool(
                    roots_without_owner or lineage_without_owner
                ),
                "no_unnecessary_SSA_traffic": not bool(unnecessary),
                "suppression_policy_unchanged": suppress_before == suppress_after,
            },
            "rule": (
                "consume_ABI_D_entry_authority_preserve_storage_and_calls_"
                "prove_each_phi_predecessor_then_apply_narrow_must_print_only"
            ),
        }
        self.abi_entry_custody_inventory = inventory
        self.abi_entry_custody_events.append(dict(inventory))

    def _expose(self):
        self.func.var_map = self.var_map
        self.func.phi_groups = self.groups

        self.func.formula_nodes = self.nodes
        self.func.phi_nodes = self.phi_nodes
        self.func.var_nodes = (self.nodes, self.phi_nodes)

        self.func.phi_dropins = self.phi_dropins
        self.func.phi_dropins_by_pred = self.phi_dropins_by_pred
        self.func.phi_dropins_by_join = self.phi_dropins_by_join

        # Presentation metadata for emitter.
        self.func.inline_only_sids = set(self.inline_only_sids)
        self.func.suppress_assign_sids = set(self.suppress_assign_sids)
        self.func.materialize_sids = set(self.materialize_sids)
        self.func.local_target_sids = set(self.local_target_sids)
        self.func.preferred_expr_by_sid = dict(self.preferred_expr_by_sid)
        self.func.ssa_policy_by_sid = dict(self.ssa_policy_by_sid)
        self.func.presentation_class_by_sid = dict(self.presentation_class_by_sid)
        self.func.phi_source_foldable_sids = set(self.phi_source_foldable_sids)
        self.func.phi_source_alias_sids = set(self.phi_source_alias_sids)
        self.func.phi_source_aliases = dict(self.phi_source_aliases)
        self.func.protected_copy_temp_sids = set(self.protected_copy_temp_sids)
        self.func.protected_copy_temp_info = dict(self.protected_copy_temp_info)
        self.func.real_local_copy_sids = set(self.real_local_copy_sids)
        self.func.real_local_copy_info = dict(self.real_local_copy_info)
        self.func.must_emit_state_write_sids = set(self.must_emit_state_write_sids)
        self.func.state_write_info = dict(self.state_write_info)
        self.func.state_transition_alias_sids = set(self.state_transition_alias_sids)
        self.func.state_transition_aliases = dict(self.state_transition_aliases)
        self.func.dropin_suppressed_by_source_alias = set(self.dropin_suppressed_by_source_alias)
        self.func.post_update_alias_sids = set(self.post_update_alias_sids)
        self.func.post_update_aliases = dict(self.post_update_aliases)
        self.func.post_update_consumer_sids = set(self.post_update_consumer_sids)
        self.func.post_update_consumer_aliases = dict(self.post_update_consumer_aliases)
        self.func.prefer_var_expr_sids = set(self.prefer_var_expr_sids)
        self.func.condition_dependency_sids = set(self.condition_dependency_sids)
        self.func.required_call_result_sids = set(self.required_call_result_sids)
        self.func.protected_condition_value_sids = set(self.protected_condition_value_sids)
        self.func.required_phi_dropin_ids = set(self.required_phi_dropin_ids)
        self.func.required_phi_dropin_records = list(self.required_phi_dropin_records)
        self.func.non_suppressible_dropin_ids = set(self.non_suppressible_dropin_ids)
        self.func.non_suppressible_dropin_records = list(self.non_suppressible_dropin_records)
        self.func.executable_dropin_source_sids = set(self.executable_dropin_source_sids)
        self.func.state_alias_debug_events = list(self.state_alias_debug_events)
        self.func.condition_temp_defs = list(self.condition_temp_defs)
        self.func.condition_temp_def_sids = set(self.condition_temp_def_sids)
        self.func.post_update_condition_aliases = list(self.post_update_condition_aliases)
        self.func.post_update_condition_alias_sids = set(self.post_update_condition_alias_sids)
        self.func.metadata_closure_events = list(self.metadata_closure_events)
        self.func.post_update_alias_detection_events = list(self.post_update_alias_detection_events)
        self.func.post_update_alias_reject_events = list(self.post_update_alias_reject_events)
        self.func.phi_dropin_post_update_promotion_events = list(self.phi_dropin_post_update_promotion_events)
        self.func.sgl_adjacent_post_update_alias_events = list(self.sgl_adjacent_post_update_alias_events)
        self.func.sgl_same_block_post_update_alias_events = list(self.sgl_same_block_post_update_alias_events)
        self.func.sgl_rawcond_local_update_alias_events = list(self.sgl_rawcond_local_update_alias_events)
        self.func.block_local_temp_post_update_alias_events = list(self.block_local_temp_post_update_alias_events)
        self.func.transition_source_condition_alias_events = list(self.transition_source_condition_alias_events)
        self.func.stack_update_temp_condition_alias_events = list(self.stack_update_temp_condition_alias_events)
        self.func.path_local_phi_dropin_ids = set(self.path_local_phi_dropin_ids)
        self.func.path_local_phi_dropin_records = list(self.path_local_phi_dropin_records)
        self.func.duplicate_phi_cleanup_alias_sids = set(self.duplicate_phi_cleanup_alias_sids)
        self.func.duplicate_phi_cleanup_alias_info = dict(self.duplicate_phi_cleanup_alias_info)
        self.func.selector_passthrough_dropin_sids = set(self.selector_passthrough_dropin_sids)
        self.func.selector_passthrough_dropin_ids = set(self.selector_passthrough_dropin_ids)
        self.func.selector_passthrough_dropin_records = list(self.selector_passthrough_dropin_records)
        self.func.selector_passthrough_events = list(self.selector_passthrough_events)

        # v21 / Inning M compute-consumer products.  PALCompute's original
        # maps remain untouched on func; these are PHIfolder's execution-owner
        # bindings for the future emitter.
        self.func.phi_compute_consumer_version = self.COMPUTE_CONSUMER_VERSION
        self.func.phi_compute_consumer_active = bool(self.compute_consumer_active)
        self.func.phi_compute_contracts_by_op = dict(self.compute_contracts_by_op_forwarded)
        self.func.phi_compute_outputless_contracts_by_op = dict(
            self.compute_outputless_contracts_by_op
        )
        self.func.phi_compute_bindings_by_sid = dict(self.compute_bindings_by_sid)
        self.func.phi_compute_alias_bindings_by_sid = dict(self.compute_alias_bindings_by_sid)
        self.func.phi_compute_merge_contracts_by_sid = dict(self.compute_phi_merge_contracts_by_sid)
        self.func.phi_compute_transition_contracts = list(self.compute_phi_transition_contracts)
        self.func.phi_compute_transition_contracts_by_pred = dict(
            self.compute_phi_transition_contracts_by_pred
        )
        self.func.phi_compute_transition_contracts_by_join = dict(
            self.compute_phi_transition_contracts_by_join
        )
        self.func.phi_compute_boundary_preservation_sids = set(
            self.compute_boundary_preservation_sids
        )
        self.func.phi_compute_boundary_preservation_op_keys = set(
            self.compute_boundary_preservation_op_keys
        )
        self.func.phi_compute_helper_preservation_sids = set(
            self.compute_helper_preservation_sids
        )
        self.func.phi_compute_helper_preservation_op_keys = set(
            self.compute_helper_preservation_op_keys
        )
        self.func.phi_compute_deferred_preservation_sids = set(
            self.compute_deferred_preservation_sids
        )
        self.func.phi_compute_deferred_preservation_op_keys = set(
            self.compute_deferred_preservation_op_keys
        )
        self.func.phi_compute_control_contracts_by_block = dict(
            self.compute_input_control_contracts_by_block
        )
        self.func.phi_compute_consumer_events = list(self.compute_consumer_events)
        self.func.phi_compute_consumer_warnings = list(self.compute_consumer_warnings)

        # v23 / ABI-F entry-state custody.  ABI-D plans are forwarded exactly;
        # PHIfolder adds execution ownership and convergence proof, never a
        # new ABI classification.
        self.func.phi_abi_entry_custody_version = self.ABI_ENTRY_CUSTODY_VERSION
        self.func.phi_function_entry_abi_plan = dict(
            self.abi_function_entry_plan
        )
        self.func.phi_call_site_abi_plans_by_op = dict(
            self.abi_call_site_plans_by_op
        )
        self.func.phi_return_boundary_reconciliation = dict(
            self.abi_return_boundary_reconciliation
        )
        self.func.phi_abi_entry_roots_by_sid = dict(
            self.abi_entry_roots_by_sid
        )
        self.func.phi_abi_entry_lineage_by_sid = dict(
            self.abi_entry_lineage_by_sid
        )
        self.func.phi_abi_entry_execution_owners_by_sid = dict(
            self.abi_entry_execution_owners_by_sid
        )
        self.func.phi_abi_entry_storage_owners_by_family = dict(
            self.abi_entry_storage_owners_by_family
        )
        self.func.phi_abi_entry_convergence_contracts = list(
            self.abi_entry_convergence_contracts
        )
        self.func.phi_abi_entry_convergence_by_target_sid = dict(
            self.abi_entry_convergence_by_target_sid
        )
        self.func.phi_abi_entry_convergence_by_join = dict(
            self.abi_entry_convergence_by_join
        )
        self.func.phi_abi_entry_convergence_by_pred = dict(
            self.abi_entry_convergence_by_pred
        )
        self.func.phi_abi_entry_must_print_dropin_ids = set(
            self.abi_entry_must_print_dropin_ids
        )
        self.func.phi_abi_entry_must_print_dropin_records = list(
            self.abi_entry_must_print_dropin_records
        )
        self.func.phi_abi_entry_source_alias_rejections = list(
            self.abi_entry_source_alias_rejections
        )
        self.func.phi_abi_entry_path_unbound_records = list(
            self.abi_entry_path_unbound_records
        )
        self.func.phi_abi_entry_custody_events = list(
            self.abi_entry_custody_events
        )
        self.func.phi_abi_entry_custody_warnings = list(
            self.abi_entry_custody_warnings
        )
        self.func.phi_abi_entry_custody_inventory = dict(
            self.abi_entry_custody_inventory
        )
        self.func.phi_abi_entry_custody_debug = {
            "summary": dict(self.abi_entry_custody_inventory),
            "entry_roots": list(self.abi_entry_roots_by_sid.values()),
            "execution_owners": list(
                self.abi_entry_execution_owners_by_sid.values()
            ),
            "storage_owners": list(
                self.abi_entry_storage_owners_by_family.values()
            ),
            "convergence_contracts": list(
                self.abi_entry_convergence_contracts
            ),
            "must_print_dropins": list(
                self.abi_entry_must_print_dropin_records
            ),
            "source_alias_rejections": list(
                self.abi_entry_source_alias_rejections
            ),
            "path_unbound": list(self.abi_entry_path_unbound_records),
            "warnings": list(self.abi_entry_custody_warnings),
        }

        # v22 condition/storage custody products.  The original SGL sidecars
        # and PALCompute contracts remain untouched; these are their exact
        # PHIfolder execution-planning bindings.
        self.func.phi_condition_custody_version = self.CONDITION_CUSTODY_VERSION
        self.func.phi_condition_custody_bindings = list(
            self.condition_custody_bindings
        )
        self.func.phi_condition_custody_bindings_by_ref = dict(
            self.condition_custody_bindings_by_ref
        )
        self.func.phi_condition_custody_bindings_by_addr = dict(
            self.condition_custody_bindings_by_addr
        )
        self.func.phi_condition_storage_observation_sids = set(
            self.condition_storage_observation_sids
        )
        self.func.phi_condition_storage_family_ids = set(
            self.condition_storage_family_ids
        )
        self.func.phi_condition_custody_owner_op_keys = set(
            self.condition_custody_owner_op_keys
        )
        self.func.phi_condition_custody_indirect_op_keys = set(
            self.condition_custody_indirect_op_keys
        )
        self.func.phi_condition_custody_events = list(
            self.condition_custody_events
        )
        self.func.phi_condition_custody_warnings = list(
            self.condition_custody_warnings
        )
        self.func.phi_condition_custody_debug = {
            "summary": (
                dict(self.condition_custody_events[-1])
                if self.condition_custody_events
                else {}
            ),
            "bindings": list(self.condition_custody_bindings),
            "warnings": list(self.condition_custody_warnings),
            "storage_observation_sids": sorted(
                self.condition_storage_observation_sids, key=str
            ),
            "storage_family_ids": sorted(
                self.condition_storage_family_ids, key=str
            ),
            "effect_owner_compute_op_keys": sorted(
                self.condition_custody_owner_op_keys, key=str
            ),
            "indirect_compute_op_keys": sorted(
                self.condition_custody_indirect_op_keys, key=str
            ),
        }
        self.func.phi_compute_debug = {
            "summary": (
                dict(self.compute_consumer_events[-1])
                if self.compute_consumer_events
                else {}
            ),
            "events": list(self.compute_consumer_events),
            "warnings": list(self.compute_consumer_warnings),
            "outputless_contracts": list(self.compute_outputless_contracts_by_op.values()),
            "state_alias_bindings": list(self.compute_alias_bindings_by_sid.values()),
            "phi_transition_contracts": list(self.compute_phi_transition_contracts),
            "preserved_compute_boundary_sids": sorted(
                self.compute_boundary_preservation_sids, key=str
            ),
            "preserved_outputless_boundary_op_keys": sorted(
                self.compute_boundary_preservation_op_keys, key=str
            ),
            "preserved_runtime_helper_sids": sorted(
                self.compute_helper_preservation_sids, key=str
            ),
            "preserved_outputless_helper_op_keys": sorted(
                self.compute_helper_preservation_op_keys, key=str
            ),
            "preserved_deferred_contract_sids": sorted(
                self.compute_deferred_preservation_sids, key=str
            ),
            "preserved_outputless_deferred_op_keys": sorted(
                self.compute_deferred_preservation_op_keys, key=str
            ),
        }

        self.func.phi_folder_debug = {
            "identity_phi_nodes": self.identity_phi_nodes,
            "transition_phi_nodes": self.transition_phi_nodes,
            "skipped_phi_nodes": self.skipped_phi_nodes,
            "no_inline_nodes": self.no_inline_nodes,
            "phi_dropins": self.phi_dropins,
            "phi_dropins_by_pred": self.phi_dropins_by_pred,
            "phi_dropins_by_join": self.phi_dropins_by_join,
            "inline_only_sids": sorted(self.inline_only_sids),
            "suppress_assign_sids": sorted(self.suppress_assign_sids),
            "materialize_sids": sorted(self.materialize_sids),
            "local_target_sids": sorted(self.local_target_sids),
            "preferred_expr_by_sid": self.preferred_expr_by_sid,
            "ssa_policy_by_sid": self.ssa_policy_by_sid,
            "presentation_class_by_sid": self.presentation_class_by_sid,
            "phi_source_foldable_sids": sorted(self.phi_source_foldable_sids),
            "used_temp_phi_target_sids": sorted(self.used_temp_phi_target_sids),
            "used_temp_phi_output_sids": sorted(self.used_temp_phi_output_sids),
            "value_selector_phi_nodes": self.value_selector_phi_nodes,
            "phi_join_discovery_events": self.phi_join_discovery_events,
            "pure_bridge_sids": sorted(self.pure_bridge_sids),
            "copy_bridge_sids": sorted(self.copy_bridge_sids),
            "compare_bridge_sids": sorted(self.compare_bridge_sids),
            "use_counts": self.use_counts,
            "phi_source_counts": self.phi_source_counts,
            "synthesized_phi_sids": sorted(self.synthesized_phi_sids),
            "synthesized_phi_nodes": self.synthesized_phi_nodes,
            "temp_phi_source_alias_sids": sorted(self.temp_phi_source_alias_sids),
            "temp_phi_source_aliases": dict(self.temp_phi_source_aliases),
            "phi_source_alias_sids": sorted(self.phi_source_alias_sids),
            "phi_source_aliases": dict(self.phi_source_aliases),
            "protected_copy_temp_sids": sorted(self.protected_copy_temp_sids),
            "protected_copy_temp_info": dict(self.protected_copy_temp_info),
            "real_local_copy_sids": sorted(self.real_local_copy_sids),
            "real_local_copy_info": dict(self.real_local_copy_info),
            "must_emit_state_write_sids": sorted(self.must_emit_state_write_sids),
            "state_write_info": dict(self.state_write_info),
            "state_transition_alias_sids": sorted(self.state_transition_alias_sids),
            "state_transition_aliases": dict(self.state_transition_aliases),
            "dropin_suppressed_by_source_alias": sorted(self.dropin_suppressed_by_source_alias, key=str),
            "post_update_alias_sids": sorted(self.post_update_alias_sids, key=str),
            "post_update_aliases": dict(self.post_update_aliases),
            "post_update_consumer_sids": sorted(self.post_update_consumer_sids, key=str),
            "post_update_consumer_aliases": dict(self.post_update_consumer_aliases),
            "prefer_var_expr_sids": sorted(self.prefer_var_expr_sids, key=str),
            "condition_dependency_sids": sorted(self.condition_dependency_sids, key=str),
            "required_call_result_sids": sorted(self.required_call_result_sids, key=str),
            "protected_condition_value_sids": sorted(self.protected_condition_value_sids, key=str),
            "required_phi_dropin_ids": sorted(list(self.required_phi_dropin_ids), key=str),
            "required_phi_dropin_records": list(self.required_phi_dropin_records),
            "non_suppressible_dropin_ids": sorted(list(self.non_suppressible_dropin_ids), key=str),
            "non_suppressible_dropin_records": list(self.non_suppressible_dropin_records),
            "executable_dropin_source_sids": sorted(self.executable_dropin_source_sids, key=str),
            "state_alias_debug_events": list(self.state_alias_debug_events),
            "condition_temp_defs": list(self.condition_temp_defs),
            "condition_temp_def_sids": sorted(self.condition_temp_def_sids, key=str),
            "post_update_condition_aliases": list(self.post_update_condition_aliases),
            "post_update_condition_alias_sids": sorted(self.post_update_condition_alias_sids, key=str),
            "metadata_closure_events": list(self.metadata_closure_events),
            "post_update_alias_detection_events": list(self.post_update_alias_detection_events),
            "post_update_alias_reject_events": list(self.post_update_alias_reject_events),
            "phi_dropin_post_update_promotion_events": list(self.phi_dropin_post_update_promotion_events),
            "sgl_adjacent_post_update_alias_events": list(self.sgl_adjacent_post_update_alias_events),
            "sgl_same_block_post_update_alias_events": list(self.sgl_same_block_post_update_alias_events),
            "sgl_rawcond_local_update_alias_events": list(self.sgl_rawcond_local_update_alias_events),
            "block_local_temp_post_update_alias_events": list(self.block_local_temp_post_update_alias_events),
            "transition_source_condition_alias_events": list(self.transition_source_condition_alias_events),
            "stack_update_temp_condition_alias_events": list(self.stack_update_temp_condition_alias_events),
            "path_local_phi_dropin_ids": sorted(list(self.path_local_phi_dropin_ids), key=str),
            "path_local_phi_dropin_records": list(self.path_local_phi_dropin_records),
            "duplicate_phi_cleanup_alias_sids": sorted(self.duplicate_phi_cleanup_alias_sids, key=str),
            "duplicate_phi_cleanup_alias_info": dict(self.duplicate_phi_cleanup_alias_info),
            "selector_passthrough_dropin_sids": sorted(self.selector_passthrough_dropin_sids, key=str),
            "selector_passthrough_dropin_ids": sorted(list(self.selector_passthrough_dropin_ids), key=str),
            "selector_passthrough_dropin_records": list(self.selector_passthrough_dropin_records),
            "selector_passthrough_events": list(self.selector_passthrough_events),
            "phi_compute_consumer_version": self.COMPUTE_CONSUMER_VERSION,
            "phi_compute_consumer_active": bool(self.compute_consumer_active),
            "phi_compute_consumer_events": list(self.compute_consumer_events),
            "phi_compute_consumer_warnings": list(self.compute_consumer_warnings),
            "phi_condition_custody_version": self.CONDITION_CUSTODY_VERSION,
            "phi_condition_custody_events": list(self.condition_custody_events),
            "phi_condition_custody_warnings": list(self.condition_custody_warnings),
            "phi_condition_custody_bindings": list(self.condition_custody_bindings),
            "phi_condition_storage_observation_sids": sorted(
                self.condition_storage_observation_sids, key=str
            ),
            "phi_condition_storage_family_ids": sorted(
                self.condition_storage_family_ids, key=str
            ),
            "phi_condition_custody_owner_op_keys": sorted(
                self.condition_custody_owner_op_keys, key=str
            ),
            "phi_condition_custody_indirect_op_keys": sorted(
                self.condition_custody_indirect_op_keys, key=str
            ),
            "phi_compute_boundary_preservation_sids": sorted(
                self.compute_boundary_preservation_sids, key=str
            ),
            "phi_compute_boundary_preservation_op_keys": sorted(
                self.compute_boundary_preservation_op_keys, key=str
            ),
            "phi_compute_helper_preservation_sids": sorted(
                self.compute_helper_preservation_sids, key=str
            ),
            "phi_compute_helper_preservation_op_keys": sorted(
                self.compute_helper_preservation_op_keys, key=str
            ),
            "phi_compute_deferred_preservation_sids": sorted(
                self.compute_deferred_preservation_sids, key=str
            ),
            "phi_compute_deferred_preservation_op_keys": sorted(
                self.compute_deferred_preservation_op_keys, key=str
            ),
            "phi_abi_entry_custody_version": self.ABI_ENTRY_CUSTODY_VERSION,
            "phi_abi_entry_custody_inventory": dict(
                self.abi_entry_custody_inventory
            ),
            "phi_abi_entry_roots_by_sid": dict(
                self.abi_entry_roots_by_sid
            ),
            "phi_abi_entry_lineage_by_sid": dict(
                self.abi_entry_lineage_by_sid
            ),
            "phi_abi_entry_execution_owners_by_sid": dict(
                self.abi_entry_execution_owners_by_sid
            ),
            "phi_abi_entry_storage_owners_by_family": dict(
                self.abi_entry_storage_owners_by_family
            ),
            "phi_abi_entry_convergence_contracts": list(
                self.abi_entry_convergence_contracts
            ),
            "phi_abi_entry_must_print_dropin_ids": sorted(
                list(self.abi_entry_must_print_dropin_ids), key=str
            ),
            "phi_abi_entry_must_print_dropin_records": list(
                self.abi_entry_must_print_dropin_records
            ),
            "phi_abi_entry_source_alias_rejections": list(
                self.abi_entry_source_alias_rejections
            ),
            "phi_abi_entry_path_unbound_records": list(
                self.abi_entry_path_unbound_records
            ),
            "phi_abi_entry_custody_events": list(
                self.abi_entry_custody_events
            ),
            "phi_abi_entry_custody_warnings": list(
                self.abi_entry_custody_warnings
            ),
            "groups": self.groups,
            "var_map": self.var_map,
        }


    def _promote_phi_dropin_post_update_aliases(self):
        """
        Promote executable PHI dropins whose source node is a real update of
        the target stack local.

        Canonical Sample Y case:
            phi_dropin:
                source_sid='v_367'
                target_name='local_14'
                target=local_14
                source_node=INT_ADD [local_14, 1] -> v_367

        This does not depend on var_map[v_367].  The proof is the PHI dropin
        plus source_node input dataflow.
        """

        if not hasattr(self, "phi_dropin_post_update_promotion_events"):
            self.phi_dropin_post_update_promotion_events = []

        for rec in list(getattr(self, "phi_dropins", []) or []):
            if not isinstance(rec, dict):
                continue

            source_sid = rec.get("source_sid")
            target = rec.get("target")
            target_name = rec.get("target_name") or self.name_for_var(target)
            source_node = rec.get("source_node")

            ok, reason = self._phi_dropin_source_is_target_update(rec)

            ev = {
                "kind": "phi_dropin_post_update_promotion",
                "source_sid": source_sid,
                "target_sid": rec.get("target_sid"),
                "target_name": target_name,
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "source_opcode": getattr(source_node, "opcode", None),
                "result": bool(ok),
                "reason": reason,
            }

            if not ok:
                self.phi_dropin_post_update_promotion_events.append(ev)
                continue

            source_expr = self._expr_for_phi_dropin_update_source(source_node, target_name)
            if not source_expr:
                try:
                    source_expr = self._expr_for_node_or_op(
                        source_node,
                        None,
                        self.block_of_semantic(source_node),
                    )
                except Exception:
                    source_expr = None

            if not source_expr:
                source_expr = rec.get("source_name") or str(source_sid)

            info = {
                "target_sid": rec.get("target_sid"),
                "target_name": target_name,
                "source_name": rec.get("source_name") or str(source_sid),
                "source_expr": source_expr,
                "source_opcode": getattr(source_node, "opcode", None),
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "reason": "phi_dropin_source_is_stack_local_update",
                "policy": "render_source_sid_as_post_update_target_variable",
            }

            if source_sid is not None:
                self.post_update_alias_sids.add(source_sid)
                self.prefer_var_expr_sids.add(source_sid)
                self.post_update_aliases[source_sid] = info

                self.state_transition_alias_sids.add(source_sid)
                self.state_transition_aliases[source_sid] = dict(info)

                self.must_emit_state_write_sids.add(source_sid)
                self.state_write_info[source_sid] = {
                    "kind": "phi_dropin_post_update_state_write",
                    "target_sid": rec.get("target_sid"),
                    "target_name": target_name,
                    "pred_addr": rec.get("pred_addr"),
                    "block_addr": rec.get("pred_addr"),
                    "reason": "phi_dropin_source_is_stack_local_update",
                    "source_opcode": getattr(source_node, "opcode", None),
                    "source_expr": source_expr,
                }

            ev["source_expr"] = source_expr
            ev["promoted"] = True
            self.phi_dropin_post_update_promotion_events.append(ev)

    def _phi_dropin_source_is_target_update(self, rec):
        source_node = rec.get("source_node")
        target = rec.get("target")
        target_name = rec.get("target_name") or self.name_for_var(target)

        if source_node is None:
            return False, "missing_source_node"
        if target is None:
            return False, "missing_target"
        if not self.is_stack_local(target):
            return False, "target_not_stack_local"
        if not target_name:
            return False, "missing_target_name"

        try:
            node = self._resolve_transparent_source_node_v20b(source_node)
        except Exception:
            node = source_node

        opcode = getattr(node, "opcode", None)

        if opcode in self.CALL_OPS or opcode in ("LOAD", "STORE", "INDIRECT", "MULTIEQUAL"):
            return False, "impure_or_phi_source:%s" % opcode

        if opcode not in self.PURE_INLINE_OPS:
            return False, "source_not_pure_inline:%s" % opcode

        if not self._node_inputs_reference_target_local(node, target, target_name):
            return False, "source_inputs_do_not_reference_target"

        if not self._node_has_update_component_excluding_target(node, target, target_name):
            return False, "source_has_no_update_component"

        return True, "pure_phi_source_updates_target_local"

    def _node_inputs_reference_target_local(self, node, target, target_name):
        for inp in list(getattr(node, "inputs", []) or []):
            try:
                if self.same_storage(inp, target):
                    return True
            except Exception:
                pass

            try:
                if self.name_for_var(self.to_var(inp)) == target_name:
                    return True
            except Exception:
                pass

        return False

    def _node_has_update_component_excluding_target(self, node, target, target_name):
        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC"):
            return False

        for inp in inputs:
            try:
                if self.same_storage(inp, target):
                    continue
            except Exception:
                pass

            try:
                if self.name_for_var(self.to_var(inp)) == target_name:
                    continue
            except Exception:
                pass

            if getattr(inp, "is_constant", False):
                val = None
                for attr in ("const_value", "value", "offset"):
                    val = getattr(inp, attr, None)
                    if val is not None:
                        break

                try:
                    if int(val) != 0:
                        return True
                except Exception:
                    return True
            else:
                return True

        return False

    def _expr_for_phi_dropin_update_source(self, node, target_name):
        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if not inputs:
            return None

        if len(inputs) == 1:
            opmap = {
                "INT_NEGATE": "~",
                "INT_2COMP": "-",
                "BOOL_NEGATE": "not ",
            }

            sym = opmap.get(opcode)
            if not sym:
                return None

            if self.is_stack_local(inputs[0]):
                a = target_name
            else:
                a = self._value_expr_for_metadata(inputs[0], seen=set())

            return "(%s%s)" % (sym, a)

        if len(inputs) != 2:
            return None

        symbols = {
            "INT_ADD": "+",
            "INT_SUB": "-",
            "INT_MULT": "*",
            "INT_DIV": "//",
            "INT_SDIV": "//",
            "INT_REM": "%",
            "INT_SREM": "%",
            "INT_AND": "&",
            "INT_OR": "|",
            "INT_XOR": "^",
            "INT_LEFT": "<<",
            "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>",
        }

        sym = symbols.get(opcode)
        if not sym:
            return None

        a, b = inputs[0], inputs[1]

        if self.is_stack_local(a):
            left = target_name
        else:
            left = self._value_expr_for_metadata(a, seen=set())

        if self.is_stack_local(b):
            right = target_name
        else:
            right = self._value_expr_for_metadata(b, seen=set())

        return "(%s %s %s)" % (left, sym, right)




    # ---------------------------------------------------------
    # PHI node synthesis from PAL blocks
    # ---------------------------------------------------------

    def _synthesize_missing_phi_nodes_from_blocks(self):
        """
        Ensure every MULTIEQUAL op present in PAL block.ops is represented in
        self.phi_nodes.

        Some semantic graph builders expose stack-local PHIs in func.phi_nodes
        but leave temp PHIs only as raw block ops.  The emitter deliberately
        skips MULTIEQUAL instructions, so missing phi_nodes means missing
        executable assignments such as:

            v_5848 = v_2697 / v_2690

        This pass appends the raw MULTIEQUAL op object to phi_nodes when its
        output sid is not already represented.
        """

        existing = set()

        for phi in list(self.phi_nodes or []):
            sid = self.sid_of(getattr(phi, "output", None))
            if sid is not None:
                existing.add(sid)

        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                if getattr(op, "opcode", None) != "MULTIEQUAL":
                    continue

                out = getattr(op, "output", None)
                sid = self.sid_of(out)

                if sid is None or sid in existing:
                    continue

                # Attach block metadata if the raw op does not carry it.
                try:
                    if getattr(op, "block", None) is None:
                        op.block = block
                except Exception:
                    pass

                try:
                    if getattr(op, "block_region", None) is None:
                        op.block_region = block
                except Exception:
                    pass

                self.phi_nodes.append(op)
                self.synthesized_phi_nodes.append(op)
                self.synthesized_phi_sids.add(sid)
                existing.add(sid)

    # ---------------------------------------------------------
    # Compatibility union-find
    # ---------------------------------------------------------

    def _init_sets(self):
        self.parent = {}
        for sid in self.nodes:
            self.parent[sid] = sid

        # Raw synthesized PHI ops may have output SIDs that are not yet keys in
        # formula_nodes.  Include them for compatibility naming metadata.
        for phi in self.phi_nodes:
            sid = self.sid_of(getattr(phi, "output", None))
            if sid is not None and sid not in self.parent:
                self.parent[sid] = sid

    def find(self, x):
        if x not in self.parent:
            return x
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, a, b):
        if a is None or b is None:
            return False
        if a not in self.parent or b not in self.parent:
            return False
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return False
        self.parent[rb] = ra
        return True

    # ---------------------------------------------------------
    # Basic helpers
    # ---------------------------------------------------------

    def to_node(self, x):
        if x is None:
            return None
        if hasattr(x, "var") and hasattr(x, "opcode"):
            return x
        if isinstance(x, str):
            return self.nodes.get(x)
        sid = getattr(x, "ssa_id", None)
        if sid is not None:
            return self.nodes.get(sid)
        return None

    def to_var(self, x):
        if x is None:
            return None
        if hasattr(x, "var"):
            return x.var
        return x

    def sid_of(self, x):
        if x is None:
            return None
        if isinstance(x, str):
            return x
        if hasattr(x, "var"):
            return getattr(x.var, "ssa_id", None)
        return getattr(x, "ssa_id", None)

    def opcode_of(self, x):
        node = self.to_node(x)
        if node is None:
            return None
        return getattr(node, "opcode", None)

    def is_const(self, x):
        v = self.to_var(x)
        return bool(v is not None and getattr(v, "is_constant", False))

    def is_stack_local(self, x):
        v = self.to_var(x)
        if v is None:
            return False
        return bool(getattr(v, "is_stack", False) or getattr(v, "space", None) == "stack")

    def is_call_node(self, x):
        return self.opcode_of(x) in self.CALL_OPS

    def is_condition(self, x):
        node = self.to_node(x)
        var = self.to_var(x)

        if node is not None and getattr(node, "is_condition", False):
            return True
        if var is not None and getattr(var, "is_condition", False):
            return True

        sid = self.sid_of(x)
        for cv in self.condition_vars:
            if getattr(cv, "ssa_id", None) == sid:
                return True

        return False

    def is_return_value(self, x):
        node = self.to_node(x)
        var = self.to_var(x)

        if node is not None and getattr(node, "is_return_value", False):
            return True
        if var is not None and getattr(var, "is_return_value", False):
            return True

        sid = self.sid_of(x)
        for rv in self.return_vars:
            if getattr(rv, "ssa_id", None) == sid:
                return True

        return False

    def same_storage(self, a, b):
        """
        True only when two variables refer to the same concrete storage cell.

        Critical fix:
            Temp SSA variables such as v_5848, v_2697, and v_2690 often have
            no real storage address. The old implementation compared tuples
            containing only size metadata, so unrelated temps with the same
            size could be classified as "same storage". That made:

                MULTIEQUAL [v_2697, v_2690] -> v_5848

            look like an identity PHI and prevented PHI drop-ins.

        Policy:
            - same object or same SSA id: same
            - stack/register/global storage with concrete space+offset/address:
              compare concrete storage identity
            - pure temps without concrete storage: never same merely because
              their sizes match
        """

        av = self.to_var(a)
        bv = self.to_var(b)

        if av is None or bv is None:
            return False

        if av is bv:
            return True

        asid = getattr(av, "ssa_id", None)
        bsid = getattr(bv, "ssa_id", None)

        if asid is not None and asid == bsid:
            return True

        ak = self._storage_key(av)
        bk = self._storage_key(bv)

        if ak is None or bk is None:
            return False

        return ak == bk

    def _storage_key(self, v):
        """
        Return concrete storage identity for stack/register/global variables.

        Size alone is not storage identity. At least a space plus offset, or an
        address, is required.
        """

        if v is None:
            return None

        space = getattr(v, "space", None)
        offset = getattr(v, "offset", None)
        address = getattr(v, "address", None)
        size = getattr(v, "size", None)

        if address is not None:
            return ("addr", address, size)

        if space is not None and offset is not None:
            return ("space", space, offset, size)

        return None

    def block_of_semantic(self, x):
        """
        Resolve the PAL block where semantic object x is defined.

        v3 note:
            Some temp PHI sources/targets do not carry block metadata. For
            programmatic truth we must still map them to predecessor/join
            blocks. Therefore, after direct metadata checks, scan the PAL
            function's blocks for an op whose output has the requested SSA id.
        """

        node = self.to_node(x)

        if node is not None:
            block = getattr(node, "block", None)
            if block is not None:
                return block
            block = getattr(node, "block_region", None)
            if block is not None:
                return block
            var = self.to_var(node)
            block = getattr(var, "block_region", None)
            if block is not None:
                return block

        var = self.to_var(x)
        if var is not None:
            block = getattr(var, "block_region", None)
            if block is not None:
                return block

        # Last-resort scan by SSA output.
        sid = self.sid_of(x)
        if sid is not None:
            found = self.find_def_block_for_sid(sid)
            if found is not None:
                return found

        return None

    def find_def_block_for_sid(self, sid):
        """
        Find the PAL block containing the op that defines sid.
        """

        if sid is None:
            return None

        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                out = getattr(op, "output", None)
                if out is not None and getattr(out, "ssa_id", None) == sid:
                    return block

        return None

    def find_phi_block_for_sid(self, sid):
        """
        Find the join block containing MULTIEQUAL output sid.
        """

        if sid is None:
            return None

        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                if getattr(op, "opcode", None) != "MULTIEQUAL":
                    continue
                out = getattr(op, "output", None)
                if out is not None and getattr(out, "ssa_id", None) == sid:
                    return block

        return None

    def block_addr(self, block):
        if block is None:
            return None
        return getattr(block, "addr", None)

    def cfg_node_for_block(self, block):
        if self.cfg is None or block is None:
            return None

        addr = getattr(block, "addr", None)
        if addr is None:
            return None

        nodes = getattr(self.cfg, "nodes", {})
        if addr in nodes:
            return nodes[addr]

        get_node = getattr(self.cfg, "get_node", None)
        if callable(get_node):
            try:
                return get_node(addr)
            except Exception:
                return None

        return None

    def cfg_node_for_phi(self, phi):
        """
        Resolve the CFG join node for a PHI.

        v3 hardening:
            Temp PHIs such as v_5848 may not have reliable phi.block or
            output-node block metadata. We therefore scan PAL blocks for the
            MULTIEQUAL op whose output SSA id matches the PHI output.
        """

        block = getattr(phi, "block", None)
        reason = "phi.block"

        if block is None:
            block = getattr(phi, "block_region", None)
            reason = "phi.block_region"

        out = getattr(phi, "output", None)
        out_sid = self.sid_of(out)

        if block is None:
            out_node = self.to_node(out)
            if out_node is not None:
                block = getattr(out_node, "block", None)
                reason = "out_node.block"
                if block is None:
                    block = getattr(out_node, "block_region", None)
                    reason = "out_node.block_region"

        if block is None and out_sid is not None:
            block = self.find_phi_block_for_sid(out_sid)
            reason = "scan_multiequal_output"

        if block is None and out_sid is not None:
            block = self.find_def_block_for_sid(out_sid)
            reason = "scan_any_output"

        node = self.cfg_node_for_block(block)

        self.phi_join_discovery_events.append({
            "phi_sid": out_sid,
            "block_addr": getattr(block, "addr", None) if block is not None else None,
            "cfg_addr": getattr(node, "addr", None) if node is not None else None,
            "reason": reason if block is not None else "unresolved",
        })

        return node

    def pred_nodes_for_join(self, join_node):
        if join_node is None:
            return []

        preds = []
        for e in getattr(join_node, "in_edges", []):
            src = getattr(e, "src", None)
            if src is not None:
                preds.append(src)

        if preds:
            return preds

        try:
            return list(join_node.predecessors())
        except Exception:
            return []

    # ---------------------------------------------------------
    # Use-count / materialization
    # ---------------------------------------------------------

    def _compute_use_counts(self):
        self.use_counts = {}
        self.consumer_nodes_by_sid = {}
        self.condition_use_sids = set()
        self.return_use_sids = set()

        for node in self.nodes.values():
            for inp in getattr(node, "inputs", []) or []:
                sid = self.sid_of(inp)
                if sid is not None:
                    self.use_counts[sid] = self.use_counts.get(sid, 0) + 1
                    self.consumer_nodes_by_sid.setdefault(sid, []).append(node)

        for cv in self.condition_vars:
            sid = self.sid_of(cv)
            if sid is not None:
                self.use_counts[sid] = self.use_counts.get(sid, 0) + 1
                self.condition_use_sids.add(sid)

        for rv in self.return_vars:
            sid = self.sid_of(rv)
            if sid is not None:
                self.use_counts[sid] = self.use_counts.get(sid, 0) + 1
                self.return_use_sids.add(sid)

    def _mark_materialization_policy(self):
        for node in self.nodes.values():
            sid = self.sid_of(node)
            if sid is None:
                continue

            if getattr(node, "opcode", None) in self.CALL_OPS:
                if sid in self.phi_source_foldable_sids:
                    self.inline_only_sids.add(sid)
                    self.suppress_assign_sids.add(sid)
                    continue

                self.materialize_sids.add(sid)
                try:
                    node.no_inline = True
                    node.materialize = True
                    node.semantic_role = getattr(node, "semantic_role", None) or "call_result"
                    node.var.no_inline = True
                    node.var.materialize = True
                except Exception:
                    pass
                self.no_inline_nodes.append(node)

    def _protect_condition_dependency_materialization(self):
        """
        v19 bookkeeping: protect the dataflow ancestry of branch conditions.

        This is not presentation cleanup.  It prevents execution values such as
        feedback()/mutate() call results from being suppressed merely because a
        later condition can be syntactically expanded.

        Example:
            v_1736 = feedback(local_20, local_10)
            v_1043 = ((v_1736 ^ beta) % 3) == 0

        v_1736 is an executed call result.  It must be materialized before the
        condition, not inlined/recomputed and not omitted.
        """

        deps = self._compute_condition_dependency_sids()
        self.condition_dependency_sids = set(deps)

        for sid in sorted(deps, key=str):
            node = self.nodes.get(sid)
            opcode = getattr(node, "opcode", None) if node is not None else None

            if opcode in self.CALL_OPS:
                self.required_call_result_sids.add(sid)
                self.protected_condition_value_sids.add(sid)
                self.materialize_sids.add(sid)
                self.suppress_assign_sids.discard(sid)
                self.inline_only_sids.discard(sid)
                self.phi_source_foldable_sids.discard(sid)

                try:
                    node.no_inline = True
                    node.materialize = True
                    node.semantic_role = getattr(node, "semantic_role", None) or "condition_call_result"
                    node.var.no_inline = True
                    node.var.materialize = True
                except Exception:
                    pass

                self._set_ssa_policy(
                    sid,
                    "required_condition_call_result",
                    emit=True,
                    expr_mode="var",
                    reason="call result is data dependency of branch condition",
                    target_name=self.var_map.get(sid),
                )

            elif sid in self.materialize_sids:
                self.protected_condition_value_sids.add(sid)

    def _compute_condition_dependency_sids(self):
        roots = set()

        for cv in list(getattr(self, "condition_vars", []) or []):
            sid = self.sid_of(cv)
            if sid is not None:
                roots.add(sid)

        for sid, node in self.nodes.items():
            if node is not None and getattr(node, "is_condition", False):
                roots.add(sid)

        deps = set()
        stack = list(roots)

        while stack:
            sid = stack.pop()
            if sid is None or sid in deps:
                continue

            deps.add(sid)
            node = self.nodes.get(sid)
            if node is None:
                continue

            for inp in list(getattr(node, "inputs", []) or []):
                isid = self.sid_of(inp)
                if isid is not None and isid not in deps:
                    stack.append(isid)

        return deps

    def _precompute_used_temp_phi_outputs(self):
        """
        Compute value-selector temp PHI outputs before identity classification.

        This fixes the v_5848 class of bug:
            MULTIEQUAL [v_2697, v_2690] -> v_5848
            later: INT_SRIGHT [v_5848, ...]

        Such a PHI is not an identity/blank SSA artifact. It is a branch value
        selector and must be materialized or source-aliased.
        """

        self.used_temp_phi_output_sids = set()

        # Count uses as PHI sources so we can distinguish real downstream uses
        # from PHI bookkeeping.
        phi_source_uses = {}

        for phi in self.phi_nodes:
            for inp in list(getattr(phi, "inputs", []) or []):
                sid = self.sid_of(inp)
                if sid is not None:
                    phi_source_uses[sid] = phi_source_uses.get(sid, 0) + 1

        for phi in self.phi_nodes:
            out = getattr(phi, "output", None)
            inputs = list(getattr(phi, "inputs", []) or [])
            out_sid = self.sid_of(out)

            if out is None or out_sid is None or not inputs:
                continue

            if self.is_stack_local(out):
                continue

            ov = self.to_var(out)
            if ov is not None:
                if getattr(ov, "is_parameter", False):
                    continue
                if getattr(ov, "is_global", False):
                    continue
                if getattr(ov, "is_function", False):
                    continue
                if getattr(ov, "is_constant", False):
                    continue

            total_uses = self.use_counts.get(out_sid, 0)
            bookkeeping_uses = phi_source_uses.get(out_sid, 0)
            real_uses = max(0, total_uses - bookkeeping_uses)

            distinct_source_sids = set()

            for inp in inputs:
                sid = self.sid_of(inp)
                if sid is not None and sid != out_sid:
                    distinct_source_sids.add(sid)

            # A temp PHI with distinct incoming SSA values and real downstream
            # uses is a value selector, not an identity PHI.
            if real_uses > 0 and distinct_source_sids:
                self.used_temp_phi_output_sids.add(out_sid)

        # Keep legacy name in sync early.
        self.used_temp_phi_target_sids |= set(self.used_temp_phi_output_sids)

    def _is_value_selector_phi(self, phi):
        out = getattr(phi, "output", None)
        sid = self.sid_of(out)
        return bool(sid is not None and sid in self.used_temp_phi_output_sids)


    # ---------------------------------------------------------
    # PHI classification / drop-ins
    # ---------------------------------------------------------

    def _classify_phi_nodes(self):
        for phi in self.phi_nodes:
            out = getattr(phi, "output", None)
            inputs = list(getattr(phi, "inputs", []) or [])

            if out is None or not inputs:
                self.skipped_phi_nodes.append((phi, "missing output or inputs"))
                continue

            if self._is_value_selector_phi(phi):
                self.value_selector_phi_nodes.append(phi)
                self.transition_phi_nodes.append(phi)
                continue

            if self._is_identity_phi(out, inputs):
                self.identity_phi_nodes.append(phi)
            else:
                self.transition_phi_nodes.append(phi)

    def _is_identity_phi(self, out, inputs):
        usable = [i for i in inputs if i is not None]
        if not usable:
            return False

        out_sid = self.sid_of(out)

        if out_sid in self.used_temp_phi_output_sids:
            return False

        # Identity PHIs require every incoming value to be the same concrete
        # storage as the output. Anonymous temps are not concrete storage.
        for inp in usable:
            if self.is_const(inp):
                return False
            if not self.same_storage(out, inp):
                return False

        return True

    def _build_phi_dropins(self):
        self.phi_dropins = []
        self.phi_dropins_by_pred = {}
        self.phi_dropins_by_join = {}
        self.phi_source_counts = {}
        self.used_temp_phi_target_sids = set()

        for phi in self.phi_nodes:
            out = getattr(phi, "output", None)
            inputs = list(getattr(phi, "inputs", []) or [])

            if out is None or not inputs:
                continue

            join_node = self.cfg_node_for_phi(phi)
            join_addr = getattr(join_node, "addr", None) if join_node is not None else None

            preds = self.pred_nodes_for_join(join_node)
            if not preds:
                self.skipped_phi_nodes.append((phi, "no predecessor nodes"))
                continue

            assignments = self._match_phi_inputs_to_predecessors(phi, preds)

            target_sid = self.sid_of(out)

            is_value_selector = bool(target_sid in self.used_temp_phi_output_sids)

            # Any PHI target that has downstream uses must survive as a real
            # assignment target, including temp selector PHIs like v_5848.
            if target_sid is not None:
                self.local_target_sids.add(target_sid)
                if is_value_selector or (self.use_counts.get(target_sid, 0) > 0 and not self.is_stack_local(out)):
                    self.used_temp_phi_target_sids.add(target_sid)
                    self.materialize_sids.add(target_sid)
                    self.suppress_assign_sids.discard(target_sid)
                    self.inline_only_sids.discard(target_sid)

            for pred_node, incoming in assignments:
                if pred_node is None or incoming is None:
                    continue

                # True identity storage transitions do not need drop-ins.
                # Value selector temp PHIs must keep assignments even when
                # storage metadata is ambiguous or blank.
                if (not is_value_selector) and self.same_storage(out, incoming):
                    continue

                pred_addr = getattr(pred_node, "addr", None)

                source_node = self.to_node(incoming)
                source_var = self.to_var(incoming)
                source_sid = self.sid_of(incoming)

                target_name = self.name_for_var(out)

                if source_sid is not None:
                    self.phi_source_counts[source_sid] = self.phi_source_counts.get(source_sid, 0) + 1

                record = {
                    "kind": "phi_assignment",
                    "phi": phi,
                    "join_node": join_node,
                    "join_addr": join_addr,
                    "pred_node": pred_node,
                    "pred_addr": pred_addr,
                    "target": out,
                    "target_sid": target_sid,
                    "target_name": target_name,
                    "source": incoming,
                    "source_node": source_node,
                    "source_var": source_var,
                    "source_sid": source_sid,
                    "source_name": self.name_for_var(source_var),
                    "target_is_used_temp_phi": bool(target_sid in self.used_temp_phi_target_sids),
                    "target_is_value_selector_phi": bool(is_value_selector),
                    "reason": "value_selector_phi" if is_value_selector else "phi_transition",
                }

                self.phi_dropins.append(record)
                self.phi_dropins_by_pred.setdefault(pred_addr, []).append(record)
                self.phi_dropins_by_join.setdefault(join_addr, []).append(record)

        self._classify_phi_source_foldability()

    def _protect_selector_passthrough_dropins_v20k(self):
        """
        Give transparent incoming arms of used value-selector PHIs explicit
        predecessor-local ownership.

        A selector arm such as::

            COPY [local_18] -> v_4146
            MULTIEQUAL [v_4146, v_4147, v_4148] -> v_4149

        carries the old value of ``local_18`` into ``v_4149``.  The COPY is a
        valid presentation bridge and may be suppressed, but the selector
        assignment is executable path state.  Therefore this arm must remain a
        required PHI drop-in instead of being declared accounted for by a
        normal source-op alias.

        The rule is topology/dataflow based: it applies only to a used temp
        selector target and only when the incoming source is a transparent
        chain rooted in concrete pre-existing storage/value.  Computed and CALL
        arms retain the existing source-alias fast path.
        """

        for rec in list(self.phi_dropins or []):
            if not rec.get("target_is_value_selector_phi"):
                continue

            source_sid = rec.get("source_sid")
            source_node = rec.get("source_node")
            target_sid = rec.get("target_sid")

            if source_sid is None or target_sid is None or source_node is None:
                continue

            opcode = getattr(source_node, "opcode", None)
            if opcode not in self.TRANSPARENT_OPS:
                continue

            leaf, chain, reason = self._selector_passthrough_leaf_v20k(source_node)
            leaf_var = self.to_var(leaf)

            concrete_leaf = bool(
                leaf_var is not None
                and (
                    self.is_stack_local(leaf_var)
                    or getattr(leaf_var, "is_parameter", False)
                    or getattr(leaf_var, "is_global", False)
                    or getattr(leaf_var, "is_constant", False)
                )
            )

            if not concrete_leaf:
                self.selector_passthrough_events.append({
                    "kind": "selector_passthrough_dropin_v20k_rejected",
                    "source_sid": source_sid,
                    "target_sid": target_sid,
                    "pred_addr": rec.get("pred_addr"),
                    "join_addr": rec.get("join_addr"),
                    "source_opcode": opcode,
                    "transparent_chain": list(chain),
                    "reason": reason or "transparent_chain_has_no_concrete_leaf",
                })
                continue

            rid = self._phi_record_id(rec)
            target_name = rec.get("target_name") or self.name_for_var(rec.get("target"))
            leaf_name = self.name_for_var(leaf_var)

            rec["selector_passthrough_dropin"] = True
            rec["dropin_required"] = True
            rec["dropin_scope"] = "predecessor_local_selector_passthrough"
            rec["required_reason"] = "used selector transparent arm requires explicit predecessor definition"
            rec.pop("source_aliased_to_target", None)
            rec.pop("accounted_for_by_state_alias", None)
            rec.pop("dropin_suppressed_reason", None)

            self.selector_passthrough_dropin_sids.add(source_sid)
            self.selector_passthrough_dropin_ids.add(rid)

            info = {
                "kind": "selector_passthrough_dropin_v20k",
                "id": rid,
                "source_sid": source_sid,
                "target_sid": target_sid,
                "target_name": target_name,
                "leaf_name": leaf_name,
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "source_opcode": opcode,
                "transparent_chain": list(chain),
                "reason": rec.get("required_reason"),
            }
            self.selector_passthrough_dropin_records.append(dict(info))
            self.selector_passthrough_events.append(dict(info))

    def _selector_passthrough_leaf_v20k(self, source_node):
        """Return ``(leaf, opcode_chain, rejection_reason)`` for a safe
        transparent selector source.

        Only the first input of unary transparent operations is followed.
        Cycles, missing inputs, PHIs, and computed leaves are rejected by the
        caller's concrete-leaf gate.
        """

        node = source_node
        seen = set()
        chain = []

        while node is not None:
            marker = id(node)
            if marker in seen:
                return None, chain, "transparent_chain_cycle"
            seen.add(marker)

            opcode = getattr(node, "opcode", None)
            if opcode not in self.TRANSPARENT_OPS:
                return getattr(node, "var", node), chain, None

            inputs = list(getattr(node, "inputs", []) or [])
            if not inputs:
                return None, chain, "transparent_node_has_no_input"

            chain.append(opcode)
            leaf = inputs[0]
            next_node = self.to_node(leaf)

            if next_node is None or getattr(next_node, "opcode", None) not in self.TRANSPARENT_OPS:
                return leaf, chain, None

            node = next_node

        return None, chain, "transparent_chain_has_no_leaf"

    def _classify_phi_source_foldability(self):
        for rec in self.phi_dropins:
            sid = rec.get("source_sid")
            node = rec.get("source_node")

            if sid is None or node is None:
                continue

            opcode = getattr(node, "opcode", None)
            use_count = self.use_counts.get(sid, 0)
            phi_count = self.phi_source_counts.get(sid, 0)

            # Pure bridge sources should never be emitted separately.
            if opcode in self.PURE_INLINE_OPS:
                self.phi_source_foldable_sids.add(sid)
                self.inline_only_sids.add(sid)
                self.suppress_assign_sids.add(sid)
                self.pure_bridge_sids.add(sid)
                continue

            # One-shot call result feeding a local target: fold into target.
            # Preserves reused calls such as inc2(i), because they have non-PHI uses.
            if opcode in self.CALL_OPS:
                if use_count <= phi_count:
                    self.phi_source_foldable_sids.add(sid)
                    self.inline_only_sids.add(sid)
                    self.suppress_assign_sids.add(sid)

    def _match_phi_inputs_to_predecessors(self, phi, preds):
        inputs = list(getattr(phi, "inputs", []) or [])

        remaining_preds = list(preds)
        remaining_inputs = list(inputs)
        pairs = []

        for inp in list(remaining_inputs):
            src_block = self.block_of_semantic(inp)
            src_addr = self.block_addr(src_block)
            if src_addr is None:
                continue

            matched_pred = None
            for pred in remaining_preds:
                if getattr(pred, "addr", None) == src_addr:
                    matched_pred = pred
                    break

            if matched_pred is not None:
                pairs.append((matched_pred, inp))
                remaining_preds.remove(matched_pred)
                remaining_inputs.remove(inp)

        count = min(len(remaining_preds), len(remaining_inputs))
        for i in range(count):
            pairs.append((remaining_preds[i], remaining_inputs[i]))

        if len(inputs) != len(preds):
            self.skipped_phi_nodes.append(
                (phi, "phi input/predecessor count mismatch: inputs=%d preds=%d" %
                 (len(inputs), len(preds)))
            )

        return pairs

    # ---------------------------------------------------------
    # Naming
    # ---------------------------------------------------------

    def _build_groups_without_phi_union(self):
        groups = {}

        for sid, node in self.nodes.items():
            var = self.to_var(node)
            key = self.naming_key(var)
            groups.setdefault(key, []).append(sid)

        self.groups = {}

        for key, members in groups.items():
            rep = members[0]
            self.groups[rep] = members

    def naming_key(self, var):
        if var is None:
            return ("unknown", id(var))

        if getattr(var, "is_constant", False):
            return ("const", getattr(var, "offset", None), getattr(var, "size", None))

        if getattr(var, "is_parameter", False):
            return ("param", getattr(var, "name", None), getattr(var, "offset", None))

        if getattr(var, "is_stack", False) or getattr(var, "space", None) == "stack":
            return ("stack", getattr(var, "offset", None), getattr(var, "size", None))

        if getattr(var, "is_global", False):
            return ("global", getattr(var, "offset", None), getattr(var, "size", None))

        if getattr(var, "is_function", False):
            return ("function", getattr(var, "offset", None), getattr(var, "name", None))

        return ("ssa", getattr(var, "ssa_id", None))

    def _build_var_map(self):
        self.var_map = {}
        temp_counter = 0

        for rep, members in self.groups.items():
            rep_node = self.nodes.get(rep)
            rep_var = self.to_var(rep_node)
            name = self.name_for_var(rep_var)

            if not name:
                name = "v_%d" % temp_counter
                temp_counter += 1

            for sid in members:
                self.var_map[sid] = name

        for phi in self.phi_nodes:
            out = getattr(phi, "output", None)
            sid = getattr(out, "ssa_id", None)
            if sid is not None:
                self.var_map[sid] = self.name_for_var(out)

        self._apply_used_temp_phi_source_aliases()

    def name_for_var(self, var):
        if var is None:
            return None

        if hasattr(var, "var"):
            var = var.var

        if getattr(var, "is_constant", False):
            if hasattr(var, "const_value"):
                return str(getattr(var, "const_value"))
            if hasattr(var, "value"):
                return str(getattr(var, "value"))
            if hasattr(var, "offset"):
                return str(getattr(var, "offset"))
            return "0"

        existing = getattr(var, "name", None)
        if existing:
            return self._sanitize_name(existing)

        if getattr(var, "is_parameter", False):
            return "param"

        if getattr(var, "is_stack", False) or getattr(var, "space", None) == "stack":
            off = getattr(var, "offset", None)
            if off is not None:
                return "local_%x" % abs(off)
            return "local"

        if getattr(var, "is_global", False):
            off = getattr(var, "offset", None)
            if off is not None:
                return "g_%x" % off
            return "global"

        if getattr(var, "is_function", False):
            sym = getattr(var, "symbol", None)
            if sym:
                return self._sanitize_name(sym)
            off = getattr(var, "offset", None)
            if off is not None:
                return "sub_%x" % off
            return "sub_unknown"

        sid = getattr(var, "ssa_id", None)
        if sid is not None:
            return self._sanitize_name(str(sid))

        return None

    def _sanitize_name(self, name):
        if name is None:
            return None

        s = str(name)
        if s.startswith("0x"):
            return s

        out = []
        for ch in s:
            if ch.isalnum() or ch == "_":
                out.append(ch)
            else:
                out.append("_")
        s = "".join(out)

        if not s:
            return None

        if s[0].isdigit():
            s = "v_" + s

        while s.startswith("v_v_"):
            s = s[2:]

        return s

    def _apply_used_temp_phi_source_aliases(self):
        """
        v18c generalized PHI source aliasing.

        Old behavior handled only used temp selector PHIs such as:
            MULTIEQUAL [v_2697, v_2690] -> v_5848

        v9 extends the same execution-truth idea to local-transition PHIs:
            CALL mutate(...) -> v_1728
            MULTIEQUAL [v_1728, local_20] -> local_20

        Instead of exposing both:
            v_1728 = mutate(...)
            local_20 = mutate(...)

        map the source SID to the PHI target name, so the normal defining op
        writes the target directly:
            local_20 = mutate(...)

        This also fixes counter transition temps such as:
            INT_ADD [local_14, 1] -> v_367
            MULTIEQUAL [local_14, v_367, v_367] -> local_14

        Safety policy:
            - source must not be real storage / parameter / global / constant
            - target must be a stack local or a used temp selector PHI target
            - source must be one-shot with respect to PHI source use, or a pure
              expression whose only extra uses are condition/tail tests
            - CALL sources are aliased only when they have no meaningful
              non-PHI use
        """

        for rec in list(self.phi_dropins or []):
            target_sid = rec.get("target_sid")
            source_sid = rec.get("source_sid")

            if target_sid is None or source_sid is None:
                continue

            if not self._can_alias_phi_source_to_target(rec):
                continue

            target_name = rec.get("target_name")

            if not target_name:
                target_name = self.name_for_var(rec.get("target"))

            if not target_name:
                continue

            self.var_map[source_sid] = target_name
            self.var_map[target_sid] = target_name

            self.phi_source_alias_sids.add(source_sid)
            alias_reason = self._phi_source_alias_reason(rec)
            self.phi_source_aliases[source_sid] = {
                "target_sid": target_sid,
                "target_name": target_name,
                "source_name": rec.get("source_name"),
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "reason": alias_reason,
            }

            # v18c: explicit state-transition alias contract for the emitter.
            # The source op should emit at its block location under target_name.
            self.state_transition_alias_sids.add(source_sid)
            self.state_transition_aliases[source_sid] = {
                "target_sid": target_sid,
                "target_name": target_name,
                "source_name": rec.get("source_name"),
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "reason": alias_reason,
                "source_opcode": getattr(rec.get("source_node"), "opcode", None),
            }
            self.must_emit_state_write_sids.add(source_sid)
            self.state_write_info[source_sid] = {
                "kind": "phi_source_alias_state_write",
                "target_sid": target_sid,
                "target_name": target_name,
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "reason": alias_reason,
            }

            if self._is_post_update_alias_record(rec):
                self._register_post_update_alias(rec, target_name, alias_reason)

            if self._uses_are_same_block_conditionish(source_sid, rec.get("source_node")):
                self.duplicate_phi_cleanup_alias_sids.add(source_sid)
                self.duplicate_phi_cleanup_alias_info[source_sid] = {
                    "target_sid": target_sid,
                    "target_name": target_name,
                    "pred_addr": rec.get("pred_addr"),
                    "join_addr": rec.get("join_addr"),
                    "reason": "conditionish_call_phi_duplicate_cleanup",
                }

            # Backward-compatible temp selector alias metadata.
            if target_sid in self.used_temp_phi_target_sids:
                self.temp_phi_source_alias_sids.add(source_sid)
                self.temp_phi_source_aliases[source_sid] = {
                    "target_sid": target_sid,
                    "target_name": target_name,
                    "source_name": rec.get("source_name"),
                    "pred_addr": rec.get("pred_addr"),
                    "join_addr": rec.get("join_addr"),
                    "reason": "used_temp_phi_source_alias",
                }

            # The normal assignment now carries the transition.  It must be
            # visible/materialized under the target name.  A metadata-aware
            # emitter may skip the redundant PHI drop-in record for this source.
            self.suppress_assign_sids.discard(source_sid)
            self.inline_only_sids.discard(source_sid)
            self.materialize_sids.add(source_sid)
            self.dropin_suppressed_by_source_alias.add(source_sid)
            rec["source_aliased_to_target"] = True
            rec["dropin_required"] = False
            rec["dropin_suppressed_reason"] = "normal_source_op_writes_phi_target"

            # Propagate suppression marker to equivalent records for the same
            # source/target/join. Shared PHI inputs can appear more than once.
            for other in self.phi_dropins:
                if other is rec:
                    continue
                if (
                    other.get("source_sid") == source_sid
                    and other.get("target_sid") == target_sid
                    and other.get("join_addr") == rec.get("join_addr")
                ):
                    other["source_aliased_to_target"] = True
                    other["dropin_required"] = False
                    other["dropin_suppressed_reason"] = "normal_source_op_writes_phi_target"

    def _is_post_update_alias_record(self, rec):
        """
        True when an accepted PHI source alias is the freshly computed next
        value of the same local state target.

        v20b widens the old direct INT_ADD/INT_SUB test:
          - resolves transparent wrappers around the source;
          - accepts any pure arithmetic expression that contains the target
            local and at least one non-zero constant/delta;
          - still rejects calls, loads/stores, PHIs, and non-local targets.

        This upgrades generic phi_source_alias records such as:
            v_367 = local_14 + 1  -> local_14
        into post_update_alias records.
        """

        ok, reason = self._post_update_alias_reason_v20b(rec)
        ev = {
            "source_sid": rec.get("source_sid"),
            "target_sid": rec.get("target_sid"),
            "target_name": rec.get("target_name") or self.name_for_var(rec.get("target")),
            "source_opcode": getattr(rec.get("source_node"), "opcode", None),
            "pred_addr": rec.get("pred_addr"),
            "join_addr": rec.get("join_addr"),
            "result": bool(ok),
            "reason": reason,
        }

        if ok:
            self.post_update_alias_detection_events.append(ev)
        else:
            self.post_update_alias_reject_events.append(ev)

        return bool(ok)

    def _post_update_alias_reason_v20b(self, rec):
        source_node = rec.get("source_node")
        target = rec.get("target")

        if source_node is None:
            return False, "missing_source_node"
        if target is None:
            return False, "missing_target"

        if not self.is_stack_local(target):
            return False, "target_not_stack_local"

        target_name = rec.get("target_name") or self.name_for_var(target)
        if not target_name:
            return False, "missing_target_name"

        node = self._resolve_transparent_source_node_v20b(source_node)
        opcode = getattr(node, "opcode", None)

        if opcode in self.CALL_OPS or opcode in ("LOAD", "STORE", "INDIRECT", "MULTIEQUAL"):
            return False, "impure_or_phi_source:%s" % opcode

        if opcode not in self.PURE_INLINE_OPS:
            return False, "source_not_pure_inline:%s" % opcode

        # The source expression must contain the target state variable and a
        # change component.  This covers x+1, x-1, (x+y)%10, x^mask, etc.
        if not self._source_expr_mentions_target_v20b(node, target, target_name):
            return False, "source_expr_does_not_mention_target"

        if not self._source_expr_has_update_component_v20b(node, target, target_name):
            return False, "source_expr_has_no_update_component"

        return True, "pure_source_expr_mentions_target_and_update_component"

    def _resolve_transparent_source_node_v20b(self, node):
        seen = set()
        cur = node

        while cur is not None:
            sid = self.sid_of(cur)
            if sid is not None:
                if sid in seen:
                    return cur
                seen.add(sid)

            opcode = getattr(cur, "opcode", None)
            if opcode not in self.TRANSPARENT_OPS:
                return cur

            inputs = list(getattr(cur, "inputs", []) or [])
            if not inputs:
                return cur

            nxt = inputs[0]
            nxt_node = self.to_node(nxt)
            if nxt_node is None:
                return cur
            cur = nxt_node

        return node

    def _source_expr_mentions_target_v20b(self, node, target, target_name, seen=None):
        if node is None:
            return False

        if seen is None:
            seen = set()

        sid = self.sid_of(node)
        if sid is not None:
            if sid in seen:
                return False
            seen.add(sid)

        for inp in list(getattr(node, "inputs", []) or []):
            if self.is_const(inp):
                continue

            if self.same_storage(target, inp):
                return True

            inp_name = self.name_for_var(self.to_var(inp))
            if inp_name and inp_name == target_name:
                return True

            inp_node = self.to_node(inp)
            if inp_node is not None and self._source_expr_mentions_target_v20b(inp_node, target, target_name, seen):
                return True

        return False

    def _source_expr_has_update_component_v20b(self, node, target, target_name, seen=None):
        if node is None:
            return False

        if seen is None:
            seen = set()

        sid = self.sid_of(node)
        if sid is not None:
            if sid in seen:
                return False
            seen.add(sid)

        opcode = getattr(node, "opcode", None)

        # Pure arithmetic/bitwise value builders represent a new value when
        # they combine the target with anything else.
        if opcode in (
            "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
            "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
        ):
            saw_target = False
            saw_other = False

            for inp in list(getattr(node, "inputs", []) or []):
                if self.is_const(inp):
                    saw_other = True
                    continue

                inp_name = self.name_for_var(self.to_var(inp))
                if self.same_storage(target, inp) or inp_name == target_name:
                    saw_target = True
                    continue

                inp_node = self.to_node(inp)
                if inp_node is not None and self._source_expr_mentions_target_v20b(inp_node, target, target_name, seen.copy()):
                    saw_target = True
                else:
                    saw_other = True

            return saw_target and saw_other

        if opcode in self.TRANSPARENT_OPS:
            inputs = list(getattr(node, "inputs", []) or [])
            if inputs:
                inp_node = self.to_node(inputs[0])
                if inp_node is not None:
                    return self._source_expr_has_update_component_v20b(inp_node, target, target_name, seen)

        # For non-arithmetic pure helpers, recurse and let child arithmetic
        # prove the update component.
        for inp in list(getattr(node, "inputs", []) or []):
            inp_node = self.to_node(inp)
            if inp_node is not None and self._source_expr_has_update_component_v20b(inp_node, target, target_name, seen):
                return True

        return False


    def _register_post_update_alias(self, rec, target_name, alias_reason):
        source_sid = rec.get("source_sid")
        target_sid = rec.get("target_sid")
        source_node = rec.get("source_node")

        if source_sid is None or target_sid is None or source_node is None:
            return

        self.post_update_alias_sids.add(source_sid)
        self.prefer_var_expr_sids.add(source_sid)

        source_expr = self._expr_for_node_or_op(source_node, getattr(source_node, "op", None), getattr(source_node, "block", None))

        self.post_update_aliases[source_sid] = {
            "target_sid": target_sid,
            "target_name": target_name,
            "source_opcode": getattr(source_node, "opcode", None),
            "source_expr": source_expr,
            "pred_addr": rec.get("pred_addr"),
            "join_addr": rec.get("join_addr"),
            "reason": alias_reason or "post_update_phi_source_alias",
            "policy": "render_source_sid_as_post_update_target_variable",
        }

        # Strengthen the existing policy entry if present later; the final
        # policy pass will also re-apply this.
        self.materialize_sids.add(source_sid)
        self.suppress_assign_sids.discard(source_sid)
        self.inline_only_sids.discard(source_sid)

        try:
            source_node.post_update_alias = True
            source_node.no_inline = True
            source_node.materialize = True
            source_node.prefer_var_expr = True
        except Exception:
            pass

    def _propagate_post_update_alias_consumers(self):
        """
        Mark condition/compare consumers of post-update aliases.

        If v_367 is aliased to local_14, then a consumer such as:
            v_436 = INT_SLESS [0x4, v_367]
        must be rendered as 4 < local_14, not 4 < (local_14 + 1), once the
        source assignment has been emitted as local_14 += 1.
        """

        for source_sid in list(self.post_update_alias_sids):
            info = self.post_update_aliases.get(source_sid, {})
            target_name = info.get("target_name") or self.var_map.get(source_sid)

            for consumer in self._consumer_nodes_for_sid(source_sid):
                csid = self.sid_of(consumer)
                if csid is None:
                    continue

                opcode = getattr(consumer, "opcode", None)
                if opcode not in self.COMPARE_OPS and not self.is_condition(consumer):
                    # Propagate only through condition-ish nodes.  Do not
                    # rewrite arbitrary arithmetic without a future dataflow
                    # proof.
                    continue

                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases[csid] = {
                    "source_sid": source_sid,
                    "target_name": target_name,
                    "consumer_opcode": opcode,
                    "reason": "condition_consumes_post_update_alias",
                }

                try:
                    consumer.post_update_consumer = True
                    consumer.prefer_var_inputs = True
                except Exception:
                    pass

    def _phi_source_alias_reason(self, rec):
        target_sid = rec.get("target_sid")
        source_node = rec.get("source_node")
        opcode = getattr(source_node, "opcode", None) if source_node is not None else None

        if target_sid in self.used_temp_phi_target_sids:
            return "used_temp_phi_source_alias"

        if opcode in self.CALL_OPS:
            return "call_source_to_local_phi_target"

        return "pure_source_to_local_phi_target"

    def _consumer_nodes_for_sid(self, sid):
        return list(getattr(self, "consumer_nodes_by_sid", {}).get(sid, []) or [])

    def _node_block_addr(self, node):
        """
        Best-effort block address extraction for FormulaNode/PALPcodeOp-like
        objects. Different layers have used block, cfg_node, block_region, or
        direct *_addr attributes over the life of PAL; v18c accepts all of
        them for alias-safety diagnostics.
        """

        if node is None:
            return None

        for attr in ("block_addr", "cfg_addr", "addr"):
            val = getattr(node, attr, None)
            if isinstance(val, int):
                return val

        for attr in ("block", "cfg_node", "block_region", "owner_block"):
            obj = getattr(node, attr, None)
            if obj is None:
                continue

            if isinstance(obj, int):
                return obj

            val = getattr(obj, "addr", None)
            if isinstance(val, int):
                return val

            val = getattr(obj, "start", None)
            if isinstance(val, int):
                return val

        # Last resort: defining p-code op may carry an owning block.
        op = getattr(node, "op", None)
        if op is not None and op is not node:
            return self._node_block_addr(op)

        return None

    def _is_conditionish_consumer_node(self, node):
        """
        True for small pure tests that can safely be rendered against an
        aliased local after the source write. This deliberately excludes CALL,
        STORE, LOAD, and arithmetic state producers.
        """

        if node is None:
            return False

        cop = getattr(node, "opcode", None)

        allowed = {
            "INT_EQUAL", "INT_NOTEQUAL",
            "INT_LESS", "INT_SLESS",
            "INT_LESSEQUAL", "INT_SLESSEQUAL",
            "INT_AND", "INT_OR", "INT_XOR",
            "INT_ZEXT", "CAST", "SUBPIECE",
        }

        return cop in allowed

    def _uses_are_same_block_conditionish(self, source_sid, source_node):
        """
        Safe alias widening for call/temp results that immediately become a
        local PHI target but are also tested in the same local branch block.

        Example:
            v_1743 = mutate(...)
            local_18 = PHI(..., v_1743)
            if v_1743 != 0xf: ...

        The emitted form may be:
            local_18 = mutate(...)
            if local_18 != 0xf: ...

        v18b required strong same-block addr evidence. v18c is still safe but
        more tolerant of missing block metadata: if every non-PHI consumer is a
        conditionish pure node, and no consumer is visibly in a different block,
        aliasing is allowed.
        """

        if source_sid is None or source_node is None:
            return False

        src_block_addr = self._node_block_addr(source_node)
        consumers = self._consumer_nodes_for_sid(source_sid)

        if not consumers:
            return True

        saw_real_consumer = False

        for cn in consumers:
            if cn is source_node:
                continue

            if not self._is_conditionish_consumer_node(cn):
                return False

            saw_real_consumer = True

            caddr = self._node_block_addr(cn)

            # If both addresses are known, require same block. If one side is
            # unknown, do not reject purely on missing metadata.
            if src_block_addr is not None and caddr is not None and caddr != src_block_addr:
                return False

        return saw_real_consumer or True

    def _phi_record_id(self, rec):
        return (
            rec.get("join_addr"),
            rec.get("pred_addr"),
            rec.get("target_sid"),
            rec.get("source_sid"),
            rec.get("reason"),
        )

    def _mark_path_local_phi_dropins(self):
        """
        Mark PHI records whose predecessor block is a shared branch tail.

        SGL v18b can project a shared tail block into more than one branch arm.
        Emitter must not globally de-duplicate PHI drop-ins for such records,
        otherwise one path receives the join update and the other loses it.
        """

        for rec in self.phi_dropins:
            pred = rec.get("pred_node")
            if pred is None:
                continue

            in_edges = list(getattr(pred, "in_edges", []) or [])
            out_edges = list(getattr(pred, "out_edges", []) or [])

            shared_pred = len(in_edges) > 1
            linear_to_join = (
                len(out_edges) == 1
                and getattr(getattr(out_edges[0], "dst", None), "addr", None) == rec.get("join_addr")
            )

            if not (shared_pred and linear_to_join):
                continue

            rec["path_local_dropin"] = True
            rec["dropin_scope"] = "path_local_shared_tail"
            rid = self._phi_record_id(rec)
            self.path_local_phi_dropin_ids.add(rid)
            self.path_local_phi_dropin_records.append({
                "id": rid,
                "join_addr": rec.get("join_addr"),
                "pred_addr": rec.get("pred_addr"),
                "target_sid": rec.get("target_sid"),
                "target_name": rec.get("target_name"),
                "source_sid": rec.get("source_sid"),
                "source_name": rec.get("source_name"),
                "reason": "shared branch-tail predecessor",
            })

    def _can_alias_phi_source_to_target(self, rec):
        target = rec.get("target")
        source = rec.get("source") or rec.get("source_var")
        source_sid = rec.get("source_sid")
        target_sid = rec.get("target_sid")
        source_node = rec.get("source_node")

        if source_sid is None or target_sid is None or source_node is None:
            return False

        # ABI-F: a physical/logical/implicit function-entry SID is an
        # immutable live-in execution root.  Renaming it globally to a PHI
        # target makes paths that have not executed that target appear defined
        # and is the structural source of the v_789 class of defect.
        if self._abi_sid_v23(source_sid) in self.abi_entry_root_sids:
            event = {
                "kind": "phi_abi_entry_root_source_alias_rejected_v23",
                "version": self.ABI_ENTRY_CUSTODY_VERSION,
                "source_sid": self._abi_sid_v23(source_sid),
                "target_sid": self._abi_sid_v23(target_sid),
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "reason": "immutable_ABI_entry_root_cannot_be_globally_renamed",
            }
            marker = (
                event.get("source_sid"), event.get("target_sid"),
                event.get("pred_addr"), event.get("join_addr"),
            )
            if marker not in {
                (
                    item.get("source_sid"), item.get("target_sid"),
                    item.get("pred_addr"), item.get("join_addr"),
                )
                for item in self.abi_entry_source_alias_rejections
            }:
                self.abi_entry_source_alias_rejections.append(event)
            return False

        # Target must be a real local transition target or a used temp selector.
        target_is_local = self.is_stack_local(target)
        target_is_temp_selector = target_sid in self.used_temp_phi_target_sids

        if not (target_is_local or target_is_temp_selector):
            return False

        # Never alias real storage-bearing sources; those are actual variables.
        if self.is_stack_local(source):
            return False

        sv = self.to_var(source)
        if sv is not None:
            if getattr(sv, "is_parameter", False):
                return False
            if getattr(sv, "is_global", False):
                return False
            if getattr(sv, "is_function", False):
                return False
            if getattr(sv, "is_constant", False):
                return False

        if source_sid in self.protected_copy_temp_sids:
            return False

        if source_sid in self.real_local_copy_sids:
            return False

        # v20k: a transparent arm of a used selector PHI is deliberately
        # carried by a required predecessor-local drop-in.  Do not convert it
        # back into a suppressible source alias.
        if source_sid in self.selector_passthrough_dropin_sids:
            return False

        # v19: a call result that is part of a branch-condition dependency
        # is an execution value, not a presentation bridge.  Do not rename it
        # into a PHI target or suppress its normal materialization.
        if source_sid in self.required_call_result_sids:
            return False

        opcode = getattr(source_node, "opcode", None)

        total_uses = self.use_counts.get(source_sid, 0)
        phi_uses = self.phi_source_counts.get(source_sid, 0)
        non_phi_uses = max(0, total_uses - phi_uses)

        if opcode in self.CALL_OPS:
            # Calls must not be duplicated.  Alias when the only real consumer
            # is the PHI transition itself, or when remaining consumers are
            # conditionish tests of the freshly written value.
            if total_uses <= phi_uses:
                return True

            if target_is_local and self._uses_are_same_block_conditionish(source_sid, source_node):
                return True

            return False

        if opcode in self.PURE_INLINE_OPS:
            # Pure expressions can be aliased even when the extra use is a
            # tail/condition compare, e.g. v_367 feeds local_14 and v_436.
            # Mapping v_367 -> local_14 lets the condition observe the updated
            # counter instead of re-expanding local_14 + 1 after the update.
            if self._is_post_update_alias_record(rec):
                return self._post_update_extra_uses_are_conditionish(source_sid)
            if non_phi_uses <= 1:
                return True
            return total_uses <= phi_uses

        return total_uses <= phi_uses

    def _post_update_extra_uses_are_conditionish(self, source_sid):
        """
        Safety check for post-update aliases with more than one non-PHI use.
        Accept only compare/condition consumers.  This keeps the v_367 class
        safe without opening arbitrary expression rewrites.
        """
        if source_sid is None:
            return False

        consumers = self._consumer_nodes_for_sid(source_sid)
        if not consumers:
            return True

        for cn in consumers:
            opcode = getattr(cn, "opcode", None)

            # A source may appear in its own bookkeeping; ignore impossible or
            # absent nodes conservatively.
            if cn is None:
                continue

            if opcode in self.COMPARE_OPS:
                continue

            if self.is_condition(cn):
                continue

            # Transparent bridges feeding a condition are acceptable; the
            # downstream condition pass will catch the compare node too.
            if opcode in self.TRANSPARENT_OPS:
                continue

            return False

        return True

    def _protect_snapshot_copy_temps(self):
        """
        Protect temp snapshots created from stack locals.

        Pattern:
            COPY [local_20] -> v_4658
            COPY [local_1c] -> local_20
            COPY [v_4658]  -> local_1c

        v_4658 is not a transparent bridge.  It is a snapshot required to keep
        swap semantics after local_20 is overwritten.  Therefore it must not be
        suppressed by transparent COPY policy.
        """

        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                if getattr(op, "opcode", None) != "COPY":
                    continue

                out = getattr(op, "output", None)
                inputs = list(getattr(op, "inputs", []) or [])
                if not inputs or out is None:
                    continue

                src = inputs[0]
                sid = self.sid_of(out)

                if sid is None:
                    continue

                # Source must be a real local; output must be a temp/non-local.
                if not self.is_stack_local(src):
                    continue

                if self.is_stack_local(out):
                    continue

                if self.use_counts.get(sid, 0) <= 0:
                    continue

                self.protected_copy_temp_sids.add(sid)
                self.materialize_sids.add(sid)
                self.suppress_assign_sids.discard(sid)
                self.inline_only_sids.discard(sid)

                self.protected_copy_temp_info[sid] = {
                    "block_addr": getattr(block, "addr", None),
                    "source_name": self.name_for_var(self.to_var(src)),
                    "target_name": self.name_for_var(self.to_var(out)) or sid,
                    "reason": "stack_local_snapshot_copy",
                }

    def _protect_real_local_copy_state_writes(self):
        """
        Protect real state-copy operations.

        This pass is deliberately block/op based because the bug class is
        executable state mutation, not formula presentation.

        Examples:
            COPY [local_1c] -> local_20
            COPY [v_4658]  -> local_1c

        These must survive as writes. They are not transparent SSA bridges.
        """

        for block in getattr(self.func, "blocks", []) or []:
            for idx, op in enumerate(getattr(block, "ops", []) or []):
                opcode = getattr(op, "opcode", None)

                if opcode != "COPY":
                    continue

                out = getattr(op, "output", None)
                inputs = list(getattr(op, "inputs", []) or [])

                if out is None or not inputs:
                    continue

                src = inputs[0]
                out_sid = self.sid_of(out)
                src_sid = self.sid_of(src)

                if out_sid is None:
                    continue

                # A write into stack/local storage is an executable state
                # write unless it is a provable self-copy.
                if not self.is_stack_local(out):
                    continue

                if self.same_storage(out, src):
                    continue

                target_name = self.name_for_var(self.to_var(out))
                source_name = self.name_for_var(self.to_var(src))

                self.real_local_copy_sids.add(out_sid)
                self.must_emit_state_write_sids.add(out_sid)
                self.materialize_sids.add(out_sid)
                self.suppress_assign_sids.discard(out_sid)
                self.inline_only_sids.discard(out_sid)

                info = {
                    "block_addr": getattr(block, "addr", None),
                    "op_index": idx,
                    "opcode": opcode,
                    "target_sid": out_sid,
                    "target_name": target_name,
                    "source_sid": src_sid,
                    "source_name": source_name,
                    "reason": "real_local_copy_state_write",
                }

                self.real_local_copy_info[out_sid] = info
                self.state_write_info[out_sid] = {
                    "kind": "real_local_copy",
                    **info,
                }

    def _mark_required_executable_phi_dropins(self):
        """
        v19 bookkeeping: mark PHI transition records that represent real
        predecessor-path state updates.

        The folder does not print them.  It only declares that these records
        are required unless another explicit state-write alias already accounts
        for the same source->target transition.
        """

        for rec in list(self.phi_dropins or []):
            rid = self._phi_record_id(rec)
            source_sid = rec.get("source_sid")
            target_sid = rec.get("target_sid")
            target = rec.get("target")
            source_node = rec.get("source_node")
            opcode = getattr(source_node, "opcode", None) if source_node is not None else None

            if source_sid is None or target_sid is None:
                continue

            target_is_state = bool(self.is_stack_local(target) or target_sid in self.used_temp_phi_target_sids)
            if not target_is_state:
                continue

            # If a normal source op is deliberately aliased to write the PHI
            # target at its own block location, the drop-in may be redundant.
            if source_sid in self.state_transition_alias_sids:
                rec["accounted_for_by_state_alias"] = True
                continue

            # Otherwise this PHI assignment is executable state on this path.
            rec["dropin_required"] = True
            rec["dropin_scope"] = rec.get("dropin_scope") or "executable_phi_transition"
            rec["required_reason"] = "target state requires predecessor transition"
            self.required_phi_dropin_ids.add(rid)
            self.non_suppressible_dropin_ids.add(rid)
            self.executable_dropin_source_sids.add(source_sid)

            self.required_phi_dropin_records.append({
                "id": rid,
                "join_addr": rec.get("join_addr"),
                "pred_addr": rec.get("pred_addr"),
                "target_sid": target_sid,
                "target_name": rec.get("target_name"),
                "source_sid": source_sid,
                "source_name": rec.get("source_name"),
                "source_opcode": opcode,
                "reason": rec.get("required_reason"),
            })

            self.non_suppressible_dropin_records.append({
                "id": rid,
                "join_addr": rec.get("join_addr"),
                "pred_addr": rec.get("pred_addr"),
                "target_sid": target_sid,
                "source_sid": source_sid,
                "reason": "executable phi transition cannot be presentation-suppressed",
            })

    def _suppress_duplicate_alias_dropins(self):
        """
        Final v18c cleanup: if a source op has been aliased to write a PHI
        target directly, every matching drop-in must be treated as redundant.
        This catches duplicate cases where multiple PHI records or shared-tail
        projections refer to the same source/target transition.
        """

        for rec in self.phi_dropins:
            source_sid = rec.get("source_sid")

            if source_sid is None:
                continue

            if source_sid not in self.state_transition_alias_sids:
                continue

            # Suppress only when the normal source op is explicitly contracted
            # to write the PHI target.  Required executable drop-ins without a
            # state alias must remain visible to the emitter.
            rec["source_aliased_to_target"] = True
            rec["dropin_required"] = False
            rec["dropin_suppressed_reason"] = "v19_source_alias_writes_phi_target"
            self.dropin_suppressed_by_source_alias.add(source_sid)

            target_sid = rec.get("target_sid")
            if target_sid is not None:
                self.dropin_suppressed_by_source_alias.add((rec.get("pred_addr"), rec.get("join_addr"), target_sid, source_sid))

    def _finalize_state_write_policy(self):
        """
        Convert accumulated execution-state decisions into SSA policy entries.

        PHIfolder v18's contract:
            - state transition aliases emit where their source op lives
            - real local copies emit where their COPY op lives
            - protected snapshots emit as temps
            - redundant PHI dropins are suppressed only when source alias
              fully accounts for the transition
        """

        for sid in sorted(self.state_transition_alias_sids):
            info = self.state_transition_aliases.get(sid, {})
            self.materialize_sids.add(sid)
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)

            cls = "state_transition_alias"
            reason = info.get("reason", "phi source writes target local/temp")
            if sid in self.post_update_alias_sids:
                cls = "post_update_state_alias"
                reason = self.post_update_aliases.get(sid, {}).get("reason", reason)
                self.prefer_var_expr_sids.add(sid)

            self._set_ssa_policy(
                sid,
                cls,
                emit=True,
                expr_mode="var",
                reason=reason,
                target_name=info.get("target_name") or self.var_map.get(sid),
            )

        for sid in sorted(self.real_local_copy_sids):
            info = self.real_local_copy_info.get(sid, {})
            self.materialize_sids.add(sid)
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)
            self._set_ssa_policy(
                sid,
                "real_local_copy",
                emit=True,
                expr_mode="var",
                reason=info.get("reason", "real local-to-local state copy"),
                target_name=info.get("target_name") or self.var_map.get(sid),
            )

        for sid in sorted(self.protected_copy_temp_sids):
            info = self.protected_copy_temp_info.get(sid, {})
            self.materialize_sids.add(sid)
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)
            self._set_ssa_policy(
                sid,
                "protected_snapshot_copy",
                emit=True,
                expr_mode="var",
                reason=info.get("reason", "snapshot copy required"),
                target_name=info.get("target_name") or self.var_map.get(sid),
            )



    # ---------------------------------------------------------
    # SGL CONDITION-CONSUMER METADATA CLOSURE
    # ---------------------------------------------------------

    def _consume_sgl_condition_consumers(self):
        """
        Consume frozen SGL condition-consumer records.

        Produces:
          - func.condition_temp_defs
          - func.post_update_condition_aliases

        This pass is metadata-only.  It does not mutate the ExecTree and does
        not perform emitter-style text replacement.
        """

        consumers = list(getattr(self, "sgl_condition_consumers", []) or [])
        if not consumers:
            consumers = list(getattr(self.func, "sgl_condition_consumers", []) or [])

        self.condition_temp_defs = []
        self.condition_temp_def_sids = set()
        self.post_update_condition_aliases = []
        self.post_update_condition_alias_sids = set()

        seen_temp = set()
        seen_alias = set()

        for consumer in consumers:
            cond_expr = str(consumer.get("cond_expr") or "")
            cond_sid = consumer.get("cond_sid")
            caddr = consumer.get("addr")

            # 1. v_N condition temps that should be materialized or exactly
            # inlined by the emitter.
            for sid in self._extract_temp_sids_from_condition_expr(cond_expr):
                rec = self._make_condition_temp_def_record(sid, consumer)
                if rec is None:
                    continue
                key = (rec.get("sid"), rec.get("consumer_addr"), rec.get("expr"), rec.get("opcode"))
                if key in seen_temp:
                    continue
                seen_temp.add(key)
                self.condition_temp_defs.append(rec)
                self.condition_temp_def_sids.add(sid)
                self.materialize_sids.add(sid)
                self.suppress_assign_sids.discard(sid)
                self.inline_only_sids.discard(sid)
                self.protected_condition_value_sids.add(sid)

            # 2. Condition root and descendants may consume post-update value
            # aliases already discovered by PHI.
            for rec in self._post_update_alias_records_for_consumer(cond_sid, cond_expr, consumer):
                key = (
                    rec.get("source_sid"),
                    rec.get("consumer_addr"),
                    rec.get("target_name"),
                    rec.get("source_expr"),
                    rec.get("condition_expr"),
                )
                if key in seen_alias:
                    continue
                seen_alias.add(key)
                self.post_update_condition_aliases.append(rec)
                ssid = rec.get("source_sid")
                csid = rec.get("consumer_sid")
                if ssid is not None:
                    self.post_update_condition_alias_sids.add(ssid)
                    self.prefer_var_expr_sids.add(ssid)
                if csid is not None:
                    self.post_update_consumer_sids.add(csid)
                    self.prefer_var_expr_sids.add(csid)

        # 3. SGL same-block state-write closure.  This catches RawCond
        # conditions whose condition-source address is the same block that
        # emitted the update expression, e.g. Sample Y:
        #     block/source addr 0x10129b:
        #       local_14 = local_14 + 1
        #       if 4 < (local_14 + 1)
        for rec in self._sgl_same_block_post_update_alias_records(consumers):
            key = (
                rec.get("source_sid"),
                rec.get("consumer_addr"),
                rec.get("target_name"),
                rec.get("source_expr"),
                rec.get("condition_expr"),
                rec.get("producer_addr"),
            )
            if key in seen_alias:
                continue
            seen_alias.add(key)
            self.post_update_condition_aliases.append(rec)
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            if ssid is not None:
                self.post_update_condition_alias_sids.add(ssid)
                self.post_update_alias_sids.add(ssid)
                self.prefer_var_expr_sids.add(ssid)
                self.post_update_aliases.setdefault(ssid, {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_opcode": rec.get("source_opcode"),
                    "source_expr": rec.get("source_expr"),
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "policy": "render_source_sid_as_post_update_target_variable",
                })
            if csid is not None:
                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases.setdefault(csid, {
                    "source_sid": ssid,
                    "target_name": rec.get("target_name"),
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": rec.get("reason"),
                })

        # RawCond local-update fallback. This is deliberately narrow:
        # detect simple local_N +/- const subexpressions in RawCond text only
        # when the same block has an already-known state-write contract for
        # that local. This catches Sample Y local_14 + 1 when node linkage is
        # missing but execution metadata still proves a local_14 write.
        for rec in self._sgl_rawcond_local_update_alias_records(consumers):
            key = (
                rec.get("source_sid"),
                rec.get("consumer_addr"),
                rec.get("target_name"),
                rec.get("source_expr"),
                rec.get("condition_expr"),
                rec.get("producer_addr"),
            )
            if key in seen_alias:
                continue
            seen_alias.add(key)
            self.post_update_condition_aliases.append(rec)
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            if ssid is not None:
                self.post_update_condition_alias_sids.add(ssid)
                self.post_update_alias_sids.add(ssid)
                self.prefer_var_expr_sids.add(ssid)
                self.post_update_aliases.setdefault(ssid, {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_opcode": rec.get("source_opcode"),
                    "source_expr": rec.get("source_expr"),
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "policy": "render_source_sid_as_post_update_target_variable",
                })
            if csid is not None:
                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases.setdefault(csid, {
                    "source_sid": ssid,
                    "target_name": rec.get("target_name"),
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": rec.get("reason"),
                })

        # 4. SGL-adjacent state-write closure.  This catches RawCond conditions
        # that have no formula consumer edge, e.g. Sample Y tail:
        #     block local_14 = local_14 + 1
        #     if 4 < (local_14 + 1)
        for rec in self._sgl_adjacent_post_update_alias_records():
            key = (
                rec.get("source_sid"),
                rec.get("consumer_addr"),
                rec.get("target_name"),
                rec.get("source_expr"),
                rec.get("condition_expr"),
                rec.get("producer_addr"),
            )
            if key in seen_alias:
                continue
            seen_alias.add(key)
            self.post_update_condition_aliases.append(rec)
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            if ssid is not None:
                self.post_update_condition_alias_sids.add(ssid)
                self.post_update_alias_sids.add(ssid)
                self.prefer_var_expr_sids.add(ssid)
                self.post_update_aliases.setdefault(ssid, {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_opcode": rec.get("source_opcode"),
                    "source_expr": rec.get("source_expr"),
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "policy": "render_source_sid_as_post_update_target_variable",
                })
            if csid is not None:
                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases.setdefault(csid, {
                    "source_sid": ssid,
                    "target_name": rec.get("target_name"),
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": rec.get("reason"),
                })

        # v20i. Stack-mutating temp consumed by same-block condition.
        # This is the direct fix for Sample Y when no local_14 PHI/writeback
        # path exists:
        #   INT_ADD local_14,1 -> v_367
        #   INT_SLESS 4,v_367 -> v_436
        for rec in self._stack_update_temp_condition_alias_records(consumers):
            key = (
                rec.get("source_sid"),
                rec.get("consumer_addr"),
                rec.get("target_name"),
                rec.get("source_expr"),
                rec.get("condition_expr"),
                rec.get("producer_addr"),
            )
            if key in seen_alias:
                continue
            seen_alias.add(key)
            self.post_update_condition_aliases.append(rec)
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            if ssid is not None:
                self.post_update_condition_alias_sids.add(ssid)
                self.post_update_alias_sids.add(ssid)
                self.prefer_var_expr_sids.add(ssid)
                self.post_update_aliases.setdefault(ssid, {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_opcode": rec.get("source_opcode"),
                    "source_expr": rec.get("source_expr"),
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "policy": "render_source_sid_as_post_update_target_variable",
                })
                self.state_transition_alias_sids.add(ssid)
                self.state_transition_aliases[ssid] = {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_name": "v_%s" % ssid,
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "source_opcode": rec.get("source_opcode"),
                }
                self.must_emit_state_write_sids.add(ssid)
                self.state_write_info[ssid] = {
                    "kind": "stack_update_temp_state_write",
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "pred_addr": rec.get("producer_addr"),
                    "block_addr": rec.get("producer_addr"),
                    "reason": rec.get("reason"),
                    "source_opcode": rec.get("source_opcode"),
                }
            if csid is not None:
                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases.setdefault(csid, {
                    "source_sid": ssid,
                    "target_name": rec.get("target_name"),
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": rec.get("reason"),
                })

        # v20g. PHI-transition source consumed by same-block condition.
        # This is the direct fix for Sample Y:
        #   INT_ADD local_14,1 -> v_367
        #   INT_SLESS 4,v_367 -> v_436
        #   PHI/drop-in metadata says source_sid 367 targets local_14.
        for rec in self._transition_source_condition_alias_records(consumers):
            key = (
                rec.get("source_sid"),
                rec.get("consumer_addr"),
                rec.get("target_name"),
                rec.get("source_expr"),
                rec.get("condition_expr"),
                rec.get("producer_addr"),
            )
            if key in seen_alias:
                continue
            seen_alias.add(key)
            self.post_update_condition_aliases.append(rec)
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            if ssid is not None:
                self.post_update_condition_alias_sids.add(ssid)
                self.post_update_alias_sids.add(ssid)
                self.prefer_var_expr_sids.add(ssid)
                self.post_update_aliases.setdefault(ssid, {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_opcode": rec.get("source_opcode"),
                    "source_expr": rec.get("source_expr"),
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "policy": "render_source_sid_as_post_update_target_variable",
                })
            if csid is not None:
                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases.setdefault(csid, {
                    "source_sid": ssid,
                    "target_name": rec.get("target_name"),
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": rec.get("reason"),
                })

        # v20f. Exact block-local temp/update/compare closure.
        # This catches the alpha_four tail where the semantic value is:
        #   INT_ADD local_14,1 -> v_367
        #   INT_SLESS 4,v_367 -> v_436
        # rather than a direct local_14 state-write op.
        for rec in self._block_local_temp_post_update_alias_records(consumers):
            key = (
                rec.get("source_sid"),
                rec.get("consumer_addr"),
                rec.get("target_name"),
                rec.get("source_expr"),
                rec.get("condition_expr"),
                rec.get("producer_addr"),
            )
            if key in seen_alias:
                continue
            seen_alias.add(key)
            self.post_update_condition_aliases.append(rec)
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            if ssid is not None:
                self.post_update_condition_alias_sids.add(ssid)
                self.post_update_alias_sids.add(ssid)
                self.prefer_var_expr_sids.add(ssid)
                self.post_update_aliases.setdefault(ssid, {
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_opcode": rec.get("source_opcode"),
                    "source_expr": rec.get("source_expr"),
                    "pred_addr": rec.get("producer_addr"),
                    "join_addr": rec.get("consumer_addr"),
                    "reason": rec.get("reason"),
                    "policy": "render_source_sid_as_post_update_target_variable",
                })
            if csid is not None:
                self.post_update_consumer_sids.add(csid)
                self.prefer_var_expr_sids.add(csid)
                self.post_update_consumer_aliases.setdefault(csid, {
                    "source_sid": ssid,
                    "target_name": rec.get("target_name"),
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": rec.get("reason"),
                })

        # Promote condition temp policies after records have been collected.
        for rec in self.condition_temp_defs:
            sid = rec.get("sid")
            if sid is None:
                continue
            self._set_ssa_policy(
                sid,
                "condition_temp_def",
                emit=True,
                expr_mode="var",
                reason="SGL condition consumes temp; PHI exported exact definition metadata",
                target_name=self.var_map.get(sid) or rec.get("name"),
            )

        # Promote post-update condition aliases to preferred expression metadata.
        for rec in self.post_update_condition_aliases:
            ssid = rec.get("source_sid")
            csid = rec.get("consumer_sid")
            target_name = rec.get("target_name")

            if ssid is not None:
                self.preferred_expr_by_sid.setdefault(ssid, {})
                self.preferred_expr_by_sid[ssid].update({
                    "mode": "var",
                    "post_update_condition_alias": True,
                    "target_name": target_name,
                    "condition_addr": rec.get("consumer_addr"),
                    "source_expr": rec.get("source_expr"),
                })

            if csid is not None:
                self.post_update_consumer_aliases.setdefault(csid, {})
                self.post_update_consumer_aliases[csid].update({
                    "source_sid": ssid,
                    "target_name": target_name,
                    "consumer_opcode": rec.get("consumer_opcode"),
                    "reason": "SGL condition consumes post-update alias",
                })

        self.metadata_closure_events.append({
            "kind": "sgl_condition_consumer_metadata_closure",
            "consumers": len(consumers),
            "condition_temp_defs": len(self.condition_temp_defs),
            "post_update_condition_aliases": len(self.post_update_condition_aliases),
        })

    def _extract_temp_sids_from_condition_expr(self, expr):
        out = set()
        if not expr:
            return out
        for raw in re.findall(r"\bv_(\d+)\b", str(expr)):
            try:
                out.add(int(raw))
            except Exception:
                pass
        return out

    def _make_condition_temp_def_record(self, sid, consumer):
        if sid is None:
            return None

        node = self.nodes.get(sid)
        op = None
        block = None

        if node is not None:
            op = getattr(node, "op", None)
            block = getattr(node, "block", None) or getattr(node, "block_region", None)
        else:
            op, block = self.find_def_op_for_sid(sid)

        if node is None and op is None:
            return None

        opcode = getattr(node, "opcode", None) if node is not None else getattr(op, "opcode", None)
        pure = bool(opcode in self.PURE_INLINE_OPS or opcode in self.TRANSPARENT_OPS)

        if opcode in self.CALL_OPS or opcode in ("LOAD", "STORE", "INDIRECT", "MULTIEQUAL"):
            pure = False

        name = self.var_map.get(sid) or ("v_%s" % sid)
        expr = self._expr_for_node_or_op(node, op, block)

        return {
            "kind": "condition_temp_def",
            "sid": sid,
            "name": name,
            "consumer_kind": consumer.get("kind"),
            "consumer_addr": consumer.get("addr"),
            "consumer_role": consumer.get("role"),
            "condition_expr": consumer.get("cond_expr"),
            "expr": expr,
            "opcode": opcode,
            "pure": pure,
            "source_addr": getattr(block, "addr", None) if block is not None else self._node_block_addr(node),
            "emit_policy": "materialize_before_condition",
            "inline_allowed": bool(pure),
            "owner": "PHIfolder",
        }

    def find_def_op_for_sid(self, sid):
        if sid is None:
            return None, None
        for block in getattr(self.func, "blocks", []) or []:
            for op in getattr(block, "ops", []) or []:
                out = getattr(op, "output", None)
                if self.sid_of(out) == sid:
                    return op, block
        return None, None

    def _post_update_alias_records_for_consumer(self, cond_sid, cond_expr, consumer):
        records = []

        # A. Existing PHI-discovered post-update aliases, e.g. local_14 + 1.
        for source_sid, info in list(self.post_update_aliases.items()):
            node = self.nodes.get(source_sid)
            source_expr = self._expr_for_node_or_op(node, getattr(node, "op", None), getattr(node, "block", None)) if node is not None else None
            if not source_expr:
                continue
            if not self._condition_expr_contains_exact_formula(cond_expr, source_expr):
                continue
            records.append(self._make_post_update_condition_alias_record(
                source_sid,
                cond_sid,
                source_expr,
                info.get("target_name") or self.var_map.get(source_sid),
                consumer,
                "existing_phi_post_update_alias",
                getattr(node, "opcode", None) if node is not None else None,
            ))

        # B. Direct local state-update nodes that are not PHI source aliases,
        # e.g. local_28 = (local_28 + local_2c) % 10.
        for sid, node in list(self.nodes.items()):
            if sid in self.post_update_aliases:
                continue
            if not self._node_is_direct_post_update_value(node):
                continue
            source_expr = self._expr_for_node_or_op(node, getattr(node, "op", None), getattr(node, "block", None))
            if not source_expr:
                continue
            if not self._condition_expr_contains_exact_formula(cond_expr, source_expr):
                continue
            target_name = self.name_for_var(self.to_var(getattr(node, "var", None))) or self.var_map.get(sid)
            records.append(self._make_post_update_condition_alias_record(
                sid,
                cond_sid,
                source_expr,
                target_name,
                consumer,
                "direct_state_update_condition_alias",
                getattr(node, "opcode", None),
            ))

        return [r for r in records if r is not None]

    def _make_post_update_condition_alias_record(self, source_sid, consumer_sid, source_expr, target_name, consumer, reason, opcode):
        if source_sid is None or not target_name or not source_expr:
            return None

        return {
            "kind": "post_update_condition_alias",
            "source_sid": source_sid,
            "consumer_sid": consumer_sid,
            "target_name": target_name,
            "source_expr": source_expr,
            "condition_expr": consumer.get("cond_expr"),
            "consumer_kind": consumer.get("kind"),
            "consumer_addr": consumer.get("addr"),
            "consumer_role": consumer.get("role"),
            "consumer_opcode": getattr(self.nodes.get(consumer_sid), "opcode", None) if consumer_sid is not None else None,
            "source_opcode": opcode,
            "reason": reason,
            "emit_policy": "render_source_sid_as_target_after_state_write",
            "owner": "PHIfolder",
        }

    def _node_is_direct_post_update_value(self, node):
        if node is None:
            return False

        opcode = getattr(node, "opcode", None)
        if opcode not in self.PURE_INLINE_OPS:
            return False
        if opcode in self.COMPARE_OPS or opcode in ("BOOL_NEGATE",):
            return False

        out = getattr(node, "var", None)
        target_name = self.name_for_var(self.to_var(out))
        if not target_name:
            return False

        expr = self._expr_for_node_or_op(node, getattr(node, "op", None), getattr(node, "block", None))
        if not expr:
            return False

        if not self._expr_mentions_name(expr, target_name):
            return False

        return True

    def _condition_expr_contains_exact_formula(self, cond_expr, source_expr):
        if not cond_expr or not source_expr:
            return False

        variants = self._expr_variants(source_expr)
        c = self._normalize_expr_text(cond_expr)

        for v in variants:
            if not v:
                continue
            vv = self._normalize_expr_text(v)
            if vv and vv in c:
                return True
        return False

    def _expr_variants(self, expr):
        s = str(expr).strip()
        out = {s}
        if s.startswith("(") and s.endswith(")"):
            out.add(s[1:-1].strip())
        out.add("(%s)" % s)
        out.add("((%s))" % s)
        return out

    def _normalize_expr_text(self, s):
        return re.sub(r"\s+", "", str(s or ""))

    def _expr_mentions_name(self, expr, name):
        if not expr or not name:
            return False
        return re.search(r"\b%s\b" % re.escape(str(name)), str(expr)) is not None

    def _expr_for_node_or_op(self, node, op=None, block=None):
        if node is not None:
            return self._expr_for_node(node, seen=set())
        if op is not None:
            return self._expr_for_op(op, block=block, seen=set())
        return None

    def _expr_for_node(self, node, seen=None):
        if node is None:
            return None
        if seen is None:
            seen = set()
        sid = self.sid_of(node)
        if sid is not None:
            if sid in seen:
                return self.name_for_var(self.to_var(getattr(node, "var", None))) or self.var_map.get(sid) or ("v_%s" % sid)
            seen.add(sid)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])
        return self._expr_from_opcode_inputs(opcode, inputs, getattr(node, "var", None), seen)

    def _expr_for_op(self, op, block=None, seen=None):
        if op is None:
            return None
        if seen is None:
            seen = set()
        opcode = getattr(op, "opcode", None)
        inputs = list(getattr(op, "inputs", []) or [])
        return self._expr_from_opcode_inputs(opcode, inputs, getattr(op, "output", None), seen)

    def _expr_from_opcode_inputs(self, opcode, inputs, out_var=None, seen=None):
        if seen is None:
            seen = set()

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC") and inputs:
            return self._value_expr_for_metadata(inputs[0], seen)

        binops = {
            "INT_ADD": "+",
            "INT_SUB": "-",
            "INT_MULT": "*",
            "INT_DIV": "//",
            "INT_SDIV": "//",
            "INT_REM": "%",
            "INT_SREM": "%",
            "INT_AND": "&",
            "INT_OR": "|",
            "INT_XOR": "^",
            "INT_LEFT": "<<",
            "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>",
            "INT_EQUAL": "==",
            "INT_NOTEQUAL": "!=",
            "INT_LESS": "<",
            "INT_SLESS": "<",
            "INT_LESSEQUAL": "<=",
            "INT_SLESSEQUAL": "<=",
        }

        if opcode in binops and len(inputs) == 2:
            return "(%s %s %s)" % (
                self._value_expr_for_metadata(inputs[0], seen.copy()),
                binops[opcode],
                self._value_expr_for_metadata(inputs[1], seen.copy()),
            )

        if opcode == "BOOL_NEGATE" and inputs:
            return "not (%s)" % self._value_expr_for_metadata(inputs[0], seen.copy())

        if opcode == "SUBPIECE" and inputs:
            args = ", ".join(self._value_expr_for_metadata(i, seen.copy()) for i in inputs)
            return "subpiece(%s)" % args

        if opcode == "PIECE" and inputs:
            args = ", ".join(self._value_expr_for_metadata(i, seen.copy()) for i in inputs)
            return "piece(%s)" % args

        if opcode in self.CALL_OPS:
            sid = self.sid_of(out_var)
            return self.var_map.get(sid) or self.name_for_var(self.to_var(out_var)) or ("v_%s" % sid if sid is not None else None)

        sid = self.sid_of(out_var)
        return self.var_map.get(sid) or self.name_for_var(self.to_var(out_var)) or ("v_%s" % sid if sid is not None else None)

    def _value_expr_for_metadata(self, x, seen=None):
        if seen is None:
            seen = set()

        v = self.to_var(x)
        if v is not None and getattr(v, "is_constant", False):
            return self._const_expr_for_metadata(v)

        sid = self.sid_of(x)
        if sid is not None and sid in self.nodes:
            node = self.nodes.get(sid)
            if node is not None and getattr(node, "opcode", None) not in self.CALL_OPS:
                return self._expr_for_node(node, seen)

        return self.var_map.get(sid) or self.name_for_var(v) or ("v_%s" % sid if sid is not None else str(x))

    def _const_expr_for_metadata(self, v):
        for attr in ("const_value", "value", "offset"):
            val = getattr(v, attr, None)
            if val is not None:
                if isinstance(val, int) and abs(val) >= 10:
                    return hex(val)
                return str(val)
        return "0"








    # ---------------------------------------------------------
    # STACK-UPDATE TEMP CONDITION ALIAS CLOSURE
    # ---------------------------------------------------------

    def _stack_update_temp_condition_alias_records(self, consumers):
        """
        Detect stack-local in-place update represented as temp output.

        Pattern:
            INT_ADD [local_14, 0x1] -> v_367
            INT_SLESS [0x4, v_367] -> v_436
            CBRANCH cond=v_436

        The source SID v_367 is the post-update value of local_14.  This is
        SID/dataflow-backed; it does not depend on PHI/drop-in metadata.
        """

        records = []
        seen = set()

        for consumer in list(consumers or []):
            caddr = consumer.get("addr")
            cond_sid = consumer.get("cond_sid")
            cond_expr = str(consumer.get("cond_expr") or "")
            if caddr is None:
                continue

            block = self._pal_block_for_addr(caddr) if hasattr(self, "_pal_block_for_addr") else None
            if block is None:
                self.stack_update_temp_condition_alias_events.append({
                    "kind": "stack_update_temp_condition_alias_miss",
                    "consumer_addr": caddr,
                    "condition_expr": cond_expr,
                    "reason": "no_pal_block_for_consumer_addr",
                })
                continue

            cmp_consumers = self._block_condition_consumers_by_input_sid(block, cond_sid)
            candidates = self._stack_update_temp_candidates_for_block(block)

            for source_sid, state in sorted(candidates.items(), key=lambda kv: str(kv[0])):
                if source_sid not in cmp_consumers:
                    self.stack_update_temp_condition_alias_events.append({
                        "kind": "stack_update_temp_condition_alias_reject",
                        "consumer_addr": caddr,
                        "producer_addr": state.get("producer_addr"),
                        "source_sid": source_sid,
                        "target_name": state.get("target_name"),
                        "source_expr": state.get("source_expr"),
                        "condition_expr": cond_expr,
                        "reason": "temp_not_consumed_by_condition_compare",
                    })
                    continue

                cmp_info = cmp_consumers.get(source_sid) or {}
                rec = self._make_post_update_condition_alias_record(
                    source_sid,
                    cmp_info.get("consumer_sid") or cond_sid,
                    state.get("source_expr"),
                    state.get("target_name"),
                    consumer,
                    "stack_update_temp_consumed_by_condition_alias",
                    state.get("source_opcode"),
                )
                if rec is None:
                    continue

                rec["producer_addr"] = state.get("producer_addr")
                rec["target_sid"] = state.get("target_sid")
                rec["producer_opcode"] = state.get("source_opcode")
                rec["condition_consumer_sid"] = cmp_info.get("consumer_sid")
                rec["condition_consumer_opcode"] = cmp_info.get("consumer_opcode")
                rec["stack_update_temp"] = True

                key = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("consumer_addr"),
                    rec.get("condition_consumer_sid"),
                )
                if key in seen:
                    continue
                seen.add(key)

                self.stack_update_temp_condition_alias_events.append({
                    "kind": "stack_update_temp_condition_alias",
                    "producer_addr": rec.get("producer_addr"),
                    "consumer_addr": rec.get("consumer_addr"),
                    "source_sid": rec.get("source_sid"),
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_expr": rec.get("source_expr"),
                    "condition_expr": rec.get("condition_expr"),
                    "condition_consumer_sid": rec.get("condition_consumer_sid"),
                    "condition_consumer_opcode": rec.get("condition_consumer_opcode"),
                })
                records.append(rec)

        return records

    def _stack_update_temp_candidates_for_block(self, block):
        """
        Return only real stack-update temp candidates.

        v20h over-fired on read-only bit tests:
            INT_AND [local_14, 0x1] -> v_247
            INT_NOTEQUAL [v_247, 0x0] -> v_279

        That is not a state mutation.  It is only a condition builder.

        v20i therefore restricts this fallback to canonical in-place update
        shapes that Ghidra/HF commonly lowers from stack writes such as:
            ADD dword ptr [RBP-0xc], 1
        into:
            INT_ADD [local_14, 0x1] -> v_367

        Wider arithmetic/bitwise cases should be accepted through explicit
        PHI/drop-in/state-transition metadata, not this heuristic fallback.
        """

        out = {}
        if block is None:
            return out

        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)

            if not self._is_guarded_stack_update_opcode(opcode):
                continue

            output = getattr(op, "output", None)
            source_sid = self.sid_of(output)
            if source_sid is None:
                continue

            # Output must be temp/non-stack.  If the output is stack-local, the
            # ordinary local-state emission paths own it.
            if self.is_stack_local(output):
                continue

            inputs = list(getattr(op, "inputs", []) or [])
            if not inputs:
                continue

            target_var = None
            target_name = None
            for inp in inputs:
                if self.is_stack_local(inp):
                    target_var = self.to_var(inp)
                    target_name = self.name_for_var(target_var)
                    break

            if not target_name:
                continue

            # Reject read-only condition masks such as local_14 & 1.  The
            # fallback is for mutation-like updates, not arbitrary expressions
            # that merely mention a stack local.
            if not self._stack_update_op_has_delta_component(op, target_var, target_name):
                self.stack_update_temp_condition_alias_events.append({
                    "kind": "stack_update_temp_candidate_reject",
                    "producer_addr": getattr(block, "addr", None),
                    "source_sid": source_sid,
                    "target_name": target_name,
                    "source_opcode": opcode,
                    "reason": "no_delta_component_or_read_only_test",
                })
                continue

            source_expr = self._expr_for_op(op, block=block, seen=set())
            if not source_expr or not self._expr_mentions_name(source_expr, target_name):
                source_expr = self._expr_for_stack_update_op(op, target_name)
                if not source_expr:
                    continue

            target_sid = self.sid_of(target_var)

            out[source_sid] = {
                "source_sid": source_sid,
                "target_sid": target_sid,
                "target_name": target_name,
                "source_expr": source_expr,
                "source_opcode": opcode,
                "producer_addr": getattr(block, "addr", None),
            }

        return out

    def _is_guarded_stack_update_opcode(self, opcode):
        """
        Conservative fallback whitelist.

        ADD/SUB catch counter++/counter-- and in-place stack increments.
        Single-input arithmetic forms are accepted for genuine unary stack
        updates if they appear in PAL.  Bitwise masks are deliberately not
        accepted here; they are commonly read-only condition builders.
        """
        return opcode in (
            "INT_ADD",
            "INT_SUB",
            "INT_NEGATE",
            "INT_2COMP",
        )

    def _stack_update_op_has_delta_component(self, op, target_var, target_name):
        opcode = getattr(op, "opcode", None)
        inputs = list(getattr(op, "inputs", []) or [])

        if opcode in ("INT_ADD", "INT_SUB"):
            if len(inputs) != 2:
                return False

            has_target = False
            has_delta = False

            for inp in inputs:
                if self.is_stack_local(inp):
                    iv = self.to_var(inp)
                    if self.name_for_var(iv) == target_name:
                        has_target = True
                    continue

                # A non-zero constant is the canonical increment/decrement
                # component.  Non-stack variable deltas are also accepted for
                # x = x + y style state transitions.
                if getattr(inp, "is_constant", False):
                    val = None
                    for attr in ("const_value", "value", "offset"):
                        val = getattr(inp, attr, None)
                        if val is not None:
                            break
                    try:
                        if int(val) != 0:
                            has_delta = True
                    except Exception:
                        has_delta = True
                else:
                    has_delta = True

            return bool(has_target and has_delta)

        # Unary arithmetic update over the target itself.
        if opcode in ("INT_NEGATE", "INT_2COMP"):
            return bool(inputs and self.is_stack_local(inputs[0]) and self.name_for_var(self.to_var(inputs[0])) == target_name)

        return False



    def _expr_for_stack_update_op(self, op, target_name):
        opcode = getattr(op, "opcode", None)
        inputs = list(getattr(op, "inputs", []) or [])
        if len(inputs) != 2 or not target_name:
            return None

        symbols = {
            "INT_ADD": "+",
            "INT_SUB": "-",
            "INT_AND": "&",
            "INT_OR": "|",
            "INT_XOR": "^",
            "INT_LEFT": "<<",
            "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>",
        }
        sym = symbols.get(opcode)
        if not sym:
            return None

        a, b = inputs[0], inputs[1]
        if self.is_stack_local(a):
            left = target_name
            right = self._value_expr_for_metadata(b, seen=set())
        elif self.is_stack_local(b):
            left = self._value_expr_for_metadata(a, seen=set())
            right = target_name
        else:
            return None

        return "(%s %s %s)" % (left, sym, right)



    # ---------------------------------------------------------
    # TRANSITION-SOURCE CONDITION ALIAS CLOSURE
    # ---------------------------------------------------------

    def _transition_source_condition_alias_records(self, consumers):
        """
        Use PHI/drop-in transition metadata as the source of truth for
        source_sid -> local target.

        This catches Sample Y even when var_map[source_sid] is still v_367:
            phi/drop-in: source_sid 367 -> target_name local_14
            block ops  : INT_SLESS [0x4, v_367] -> v_436
            RawCond    : 4 < (local_14 + 1)
        """

        records = []
        seen = set()
        transition_sources = self._transition_source_records_by_sid()

        for consumer in list(consumers or []):
            caddr = consumer.get("addr")
            cond_sid = consumer.get("cond_sid")
            cond_expr = str(consumer.get("cond_expr") or "")
            if caddr is None:
                continue

            block = self._pal_block_for_addr(caddr) if hasattr(self, "_pal_block_for_addr") else None
            if block is None:
                self.transition_source_condition_alias_events.append({
                    "kind": "transition_source_condition_alias_miss",
                    "consumer_addr": caddr,
                    "condition_expr": cond_expr,
                    "reason": "no_pal_block_for_consumer_addr",
                })
                continue

            cmp_consumers = self._block_condition_consumers_by_input_sid(block, cond_sid)

            for source_sid, trans in sorted(transition_sources.items(), key=lambda kv: str(kv[0])):
                if source_sid not in cmp_consumers:
                    continue

                producer_addr = trans.get("pred_addr") or self._source_sid_block_addr(source_sid)
                # Prefer exact same-block evidence, but accept unknown producer
                # addr because phi/dropin predecessor metadata may be absent.
                if producer_addr is not None and producer_addr != caddr:
                    self.transition_source_condition_alias_events.append({
                        "kind": "transition_source_condition_alias_reject",
                        "consumer_addr": caddr,
                        "producer_addr": producer_addr,
                        "source_sid": source_sid,
                        "target_name": trans.get("target_name"),
                        "condition_expr": cond_expr,
                        "reason": "producer_addr_differs_from_condition_addr",
                    })
                    continue

                node = self.nodes.get(source_sid)
                source_expr = self._expr_for_node_or_op(node, getattr(node, "op", None), getattr(node, "block", None)) if node is not None else None
                if not source_expr:
                    op, block2 = self.find_def_op_for_sid(source_sid)
                    source_expr = self._expr_for_op(op, block=block2, seen=set()) if op is not None else None

                if not source_expr:
                    source_expr = trans.get("source_expr")

                if not source_expr:
                    self.transition_source_condition_alias_events.append({
                        "kind": "transition_source_condition_alias_reject",
                        "consumer_addr": caddr,
                        "source_sid": source_sid,
                        "target_name": trans.get("target_name"),
                        "condition_expr": cond_expr,
                        "reason": "missing_source_expr",
                    })
                    continue

                target_name = trans.get("target_name")
                if not target_name:
                    continue

                # This pass is source-SID backed. The RawCond text can differ
                # by hex/decimal constants, so exact source_expr-in-cond match
                # is diagnostic, not required, when compare consumes source_sid.
                cmp_info = cmp_consumers.get(source_sid) or {}
                rec = self._make_post_update_condition_alias_record(
                    source_sid,
                    cmp_info.get("consumer_sid") or cond_sid,
                    source_expr,
                    target_name,
                    consumer,
                    "transition_source_consumed_by_condition_alias",
                    getattr(node, "opcode", None) if node is not None else trans.get("source_opcode"),
                )
                if rec is None:
                    continue

                rec["producer_addr"] = producer_addr if producer_addr is not None else caddr
                rec["target_sid"] = trans.get("target_sid")
                rec["transition_record"] = trans.get("kind")
                rec["condition_consumer_sid"] = cmp_info.get("consumer_sid")
                rec["condition_consumer_opcode"] = cmp_info.get("consumer_opcode")
                rec["source_sid_backed"] = True

                key = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("consumer_addr"),
                    rec.get("condition_consumer_sid"),
                )
                if key in seen:
                    continue
                seen.add(key)

                self.transition_source_condition_alias_events.append({
                    "kind": "transition_source_condition_alias",
                    "producer_addr": rec.get("producer_addr"),
                    "consumer_addr": rec.get("consumer_addr"),
                    "source_sid": rec.get("source_sid"),
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_expr": rec.get("source_expr"),
                    "condition_expr": rec.get("condition_expr"),
                    "condition_consumer_sid": rec.get("condition_consumer_sid"),
                    "condition_consumer_opcode": rec.get("condition_consumer_opcode"),
                    "transition_record": rec.get("transition_record"),
                })
                records.append(rec)

        return records

    def _transition_source_records_by_sid(self):
        """
        Collect source_sid -> target local facts from PHI/drop-in/state
        transition metadata.

        v20g1 hotfix: metadata containers are not stable across PAL versions.
        Accept both dict-shaped and list-shaped forms for:
          - state_transition_aliases
          - phi_source_aliases
          - phi_dropins
        """

        out = {}

        for sid, info in self._iter_sid_info_records(getattr(self, "state_transition_aliases", {}) or {}):
            target_name = info.get("target_name")
            if not target_name:
                continue
            out[sid] = {
                "kind": "state_transition_alias",
                "source_sid": sid,
                "target_sid": info.get("target_sid"),
                "target_name": target_name,
                "pred_addr": info.get("pred_addr"),
                "join_addr": info.get("join_addr"),
                "source_opcode": info.get("source_opcode") or getattr(self.nodes.get(sid), "opcode", None),
            }

        for sid, info in self._iter_sid_info_records(getattr(self, "phi_source_aliases", {}) or {}):
            target_name = info.get("target_name")
            if not target_name:
                continue
            out.setdefault(sid, {
                "kind": "phi_source_alias",
                "source_sid": sid,
                "target_sid": info.get("target_sid"),
                "target_name": target_name,
                "pred_addr": info.get("pred_addr"),
                "join_addr": info.get("join_addr"),
                "source_opcode": info.get("source_opcode") or getattr(self.nodes.get(sid), "opcode", None),
            })

        for rec in list(getattr(self, "phi_dropins", []) or []):
            if not isinstance(rec, dict):
                continue
            sid = rec.get("source_sid")
            target_name = rec.get("target_name")
            if sid is None or not target_name:
                continue
            if not str(target_name).startswith("local_"):
                continue
            out.setdefault(sid, {
                "kind": "phi_dropin",
                "source_sid": sid,
                "target_sid": rec.get("target_sid"),
                "target_name": target_name,
                "pred_addr": rec.get("pred_addr"),
                "join_addr": rec.get("join_addr"),
                "source_opcode": getattr(rec.get("source_node"), "opcode", None) or getattr(self.nodes.get(sid), "opcode", None),
            })

        return out

    def _iter_sid_info_records(self, obj):
        """
        Normalize transition metadata into (sid, dict) pairs.

        Supported shapes:
          {sid: {...}}
          [{source_sid: sid, ...}, ...]
          [(sid, {...}), ...]
        """

        if isinstance(obj, dict):
            for sid, info in obj.items():
                if isinstance(info, dict):
                    yield sid, info
                else:
                    yield sid, {"value": info}
            return

        if isinstance(obj, (list, tuple, set)):
            for item in obj:
                if isinstance(item, dict):
                    sid = item.get("source_sid")
                    if sid is None:
                        sid = item.get("sid")
                    if sid is None:
                        sid = item.get("id")
                    if sid is not None:
                        yield sid, item
                    continue

                if isinstance(item, (list, tuple)) and len(item) == 2:
                    sid, info = item
                    if isinstance(info, dict):
                        yield sid, info
                    else:
                        yield sid, {"value": info}


    def _source_sid_block_addr(self, sid):
        node = self.nodes.get(sid)
        addr = self._node_block_addr(node)
        if addr is not None:
            return addr
        block = self.find_def_block_for_sid(sid)
        return getattr(block, "addr", None) if block is not None else None



    # ---------------------------------------------------------
    # BLOCK-LOCAL TEMP POST-UPDATE ALIAS CLOSURE
    # ---------------------------------------------------------

    def _block_local_temp_post_update_alias_records(self, consumers):
        """
        Exact closure for:
            update temp -> compare condition -> CBRANCH

        Sample Y:
            INT_ADD [local_14, 0x1] -> v_367
            INT_SLESS [0x4, v_367] -> v_436
            CBRANCH cond=v_436

        If var_map says v_367 renders as local_14, then v_367 is the
        post-update value of local_14 in this condition.
        """

        records = []
        seen = set()

        for consumer in list(consumers or []):
            caddr = consumer.get("addr")
            cond_sid = consumer.get("cond_sid")
            cond_expr = str(consumer.get("cond_expr") or "")
            if caddr is None:
                continue

            block = self._pal_block_for_addr(caddr) if hasattr(self, "_pal_block_for_addr") else None
            if block is None:
                self.block_local_temp_post_update_alias_events.append({
                    "kind": "block_local_temp_post_update_alias_miss",
                    "consumer_addr": caddr,
                    "condition_expr": cond_expr,
                    "reason": "no_pal_block_for_consumer_addr",
                })
                continue

            producers = self._block_update_temp_candidates(block)
            consumers_of_temp = self._block_condition_consumers_by_input_sid(block, cond_sid)

            for source_sid, state in producers.items():
                if source_sid not in consumers_of_temp:
                    self.block_local_temp_post_update_alias_events.append({
                        "kind": "block_local_temp_post_update_alias_reject",
                        "consumer_addr": caddr,
                        "producer_addr": state.get("producer_addr"),
                        "source_sid": source_sid,
                        "target_name": state.get("target_name"),
                        "source_expr": state.get("source_expr"),
                        "condition_expr": cond_expr,
                        "reason": "temp_not_consumed_by_condition_compare",
                    })
                    continue

                cmp_info = consumers_of_temp.get(source_sid) or {}
                rec = self._make_post_update_condition_alias_record(
                    source_sid,
                    cmp_info.get("consumer_sid") or cond_sid,
                    state.get("source_expr"),
                    state.get("target_name"),
                    consumer,
                    "block_local_temp_update_feeds_condition_alias",
                    state.get("source_opcode"),
                )
                if rec is None:
                    continue

                rec["producer_addr"] = state.get("producer_addr")
                rec["target_sid"] = state.get("target_sid")
                rec["producer_opcode"] = state.get("source_opcode")
                rec["condition_consumer_sid"] = cmp_info.get("consumer_sid")
                rec["condition_consumer_opcode"] = cmp_info.get("consumer_opcode")

                key = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("consumer_addr"),
                    rec.get("producer_addr"),
                )
                if key in seen:
                    continue
                seen.add(key)

                self.block_local_temp_post_update_alias_events.append({
                    "kind": "block_local_temp_post_update_alias",
                    "producer_addr": rec.get("producer_addr"),
                    "consumer_addr": rec.get("consumer_addr"),
                    "source_sid": rec.get("source_sid"),
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_expr": rec.get("source_expr"),
                    "condition_expr": rec.get("condition_expr"),
                    "condition_consumer_sid": rec.get("condition_consumer_sid"),
                    "condition_consumer_opcode": rec.get("condition_consumer_opcode"),
                })
                records.append(rec)

        return records

    def _block_update_temp_candidates(self, block):
        out = {}
        if block is None:
            return out

        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)
            if opcode not in (
                "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
                "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
                "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
            ):
                continue

            output = getattr(op, "output", None)
            sid = self.sid_of(output)
            if sid is None:
                continue

            target_name = self.var_map.get(sid)
            if not target_name or not str(target_name).startswith("local_"):
                continue

            expr = self._expr_for_op(op, block=block, seen=set())
            if not expr:
                continue

            if not self._expr_mentions_name(expr, target_name):
                continue

            out[sid] = {
                "source_sid": sid,
                "target_sid": sid,
                "target_name": target_name,
                "source_expr": expr,
                "source_opcode": opcode,
                "producer_addr": getattr(block, "addr", None),
            }

        return out

    def _block_condition_consumers_by_input_sid(self, block, cond_sid=None):
        out = {}
        if block is None:
            return out

        # Prefer actual compare/condition op that defines cond_sid; also accept
        # any compare op in this block that consumes the candidate temp.
        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)
            if opcode not in self.COMPARE_OPS and opcode != "BOOL_NEGATE":
                continue

            osid = self.sid_of(getattr(op, "output", None))
            if cond_sid is not None and osid != cond_sid:
                # Still collect; SGL cond_sid can be absent/mismatched for
                # RawCond.  The temp-consumption proof is stronger here.
                pass

            for inp in list(getattr(op, "inputs", []) or []):
                isid = self.sid_of(inp)
                if isid is None:
                    continue
                out[isid] = {
                    "consumer_sid": osid,
                    "consumer_opcode": opcode,
                }

        return out



    # ---------------------------------------------------------
    # SGL RAWCOND LOCAL-UPDATE FALLBACK
    # ---------------------------------------------------------

    def _sgl_rawcond_local_update_alias_records(self, consumers):
        """
        Fallback for lost formula linkage.

        A RawCond like:
            (4 < (local_14 + 1))
        contains the post-update expression text, but PHI may fail to recover
        the exact source node. Accept a metadata alias only if there is an
        already-known same-address state-write contract for local_14.
        """

        records = []
        seen = set()

        for consumer in list(consumers or []):
            cond_expr = str(consumer.get("cond_expr") or "")
            caddr = consumer.get("addr")
            if not cond_expr or caddr is None:
                continue

            for cand in self._extract_local_delta_exprs_from_rawcond(cond_expr):
                target_name = cand.get("target_name")
                source_expr = cand.get("source_expr")
                if not target_name or not source_expr:
                    continue

                state = self._same_addr_state_write_contract_for_local(caddr, target_name)
                if state is None:
                    self.sgl_rawcond_local_update_alias_events.append({
                        "kind": "sgl_rawcond_local_update_alias_reject",
                        "consumer_addr": caddr,
                        "target_name": target_name,
                        "source_expr": source_expr,
                        "condition_expr": cond_expr,
                        "reason": "no_same_addr_state_write_contract_for_local",
                    })
                    continue

                rec = self._make_post_update_condition_alias_record(
                    state.get("source_sid"),
                    consumer.get("cond_sid"),
                    source_expr,
                    target_name,
                    consumer,
                    "sgl_rawcond_local_delta_state_write_alias",
                    state.get("source_opcode"),
                )
                if rec is None:
                    continue

                rec["producer_addr"] = state.get("producer_addr")
                rec["target_sid"] = state.get("target_sid")
                rec["producer_opcode"] = state.get("source_opcode")
                rec["rawcond_fallback"] = True

                key = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("source_expr"),
                    rec.get("consumer_addr"),
                    rec.get("producer_addr"),
                )
                if key in seen:
                    continue
                seen.add(key)

                self.sgl_rawcond_local_update_alias_events.append({
                    "kind": "sgl_rawcond_local_update_alias",
                    "producer_addr": rec.get("producer_addr"),
                    "consumer_addr": rec.get("consumer_addr"),
                    "source_sid": rec.get("source_sid"),
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_expr": rec.get("source_expr"),
                    "condition_expr": rec.get("condition_expr"),
                })
                records.append(rec)

        return records

    def _extract_local_delta_exprs_from_rawcond(self, cond_expr):
        """
        Extract narrow local +/- constant candidates from RawCond text.
        """

        out = []
        s = str(cond_expr or "")

        pat = re.compile(
            r"\(\s*(local_[0-9a-fA-F]+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
        )

        for m in pat.finditer(s):
            local = m.group(1)
            op = m.group(2)
            const = m.group(3)
            expr = "(%s %s %s)" % (local, op, const)
            out.append({
                "target_name": local,
                "source_expr": expr,
                "operator": op,
                "constant": const,
            })

        return out

    def _same_addr_state_write_contract_for_local(self, addr, target_name):
        """
        Find a state-write contract for target_name at addr.
        """

        if addr is None or not target_name:
            return None

        for sid, info in self._iter_sid_info_records(getattr(self, "state_write_info", {}) or {}):
            if info.get("target_name") != target_name:
                continue
            iaddr = info.get("block_addr", info.get("pred_addr", info.get("producer_addr")))
            if iaddr != addr:
                continue
            node = self.nodes.get(sid)
            return {
                "source_sid": sid,
                "target_sid": info.get("target_sid", sid),
                "target_name": target_name,
                "producer_addr": addr,
                "source_opcode": info.get("source_opcode") or getattr(node, "opcode", None),
            }

        for sid, info in self._iter_sid_info_records(getattr(self, "state_transition_aliases", {}) or {}):
            if info.get("target_name") != target_name:
                continue
            iaddr = info.get("pred_addr", info.get("block_addr", info.get("producer_addr")))
            if iaddr != addr:
                continue
            node = self.nodes.get(sid)
            return {
                "source_sid": sid,
                "target_sid": info.get("target_sid", sid),
                "target_name": target_name,
                "producer_addr": addr,
                "source_opcode": info.get("source_opcode") or getattr(node, "opcode", None),
            }

        for sid in list(getattr(self, "must_emit_state_write_sids", set()) or set()):
            if self.var_map.get(sid) != target_name:
                continue
            node = self.nodes.get(sid)
            naddr = self._node_block_addr(node)
            if naddr is not None and naddr != addr:
                continue
            return {
                "source_sid": sid,
                "target_sid": sid,
                "target_name": target_name,
                "producer_addr": addr,
                "source_opcode": getattr(node, "opcode", None) if node is not None else None,
            }

        block = self._pal_block_for_addr(addr) if hasattr(self, "_pal_block_for_addr") else None
        if block is not None:
            for op in list(getattr(block, "ops", []) or []):
                out = getattr(op, "output", None)
                sid = self.sid_of(out)
                if sid is None:
                    continue
                if (self.var_map.get(sid) or self.name_for_var(self.to_var(out))) != target_name:
                    continue
                opcode = getattr(op, "opcode", None)
                if opcode not in self.PURE_INLINE_OPS:
                    continue
                return {
                    "source_sid": sid,
                    "target_sid": sid,
                    "target_name": target_name,
                    "producer_addr": addr,
                    "source_opcode": opcode,
                }

        return None



    # ---------------------------------------------------------
    # SGL SAME-BLOCK POST-UPDATE ALIAS CLOSURE
    # ---------------------------------------------------------

    def _sgl_same_block_post_update_alias_records(self, consumers):
        """
        Derive post-update condition aliases when SGL RawCond and update op
        share the same PAL block address.

        Sample Y / alpha_four tail:
            SGL source event: src=0x10129b expr=(4 < (local_14 + 1))
            emitted block  : local_14 = (local_14 + 1)

        This pass scans the PAL block at consumer["addr"], renders pure
        state-update expressions in that block, and if the condition text
        contains the same expression, emits a post_update_condition_alias.
        """

        records = []
        seen = set()

        for consumer in list(consumers or []):
            cond_expr = str(consumer.get("cond_expr") or "")
            caddr = consumer.get("addr")

            if not cond_expr or caddr is None:
                continue

            block = self._pal_block_for_addr(caddr)
            if block is None:
                self.sgl_same_block_post_update_alias_events.append({
                    "kind": "sgl_same_block_post_update_alias_miss",
                    "consumer_addr": caddr,
                    "condition_expr": cond_expr,
                    "reason": "no_pal_block_for_consumer_addr",
                })
                continue

            for state in self._state_update_records_for_block(block):
                source_expr = state.get("source_expr")
                target_name = state.get("target_name")

                if not source_expr or not target_name:
                    continue

                if not self._condition_expr_contains_exact_formula(cond_expr, source_expr):
                    self.sgl_same_block_post_update_alias_events.append({
                        "kind": "sgl_same_block_post_update_alias_reject",
                        "consumer_addr": caddr,
                        "producer_addr": state.get("producer_addr"),
                        "source_sid": state.get("source_sid"),
                        "target_name": target_name,
                        "source_expr": source_expr,
                        "condition_expr": cond_expr,
                        "reason": "source_expr_not_in_condition",
                    })
                    continue

                rec = self._make_post_update_condition_alias_record(
                    state.get("source_sid"),
                    consumer.get("cond_sid"),
                    source_expr,
                    target_name,
                    consumer,
                    "sgl_same_block_state_write_condition_alias",
                    state.get("source_opcode"),
                )
                if rec is None:
                    continue

                rec["producer_addr"] = state.get("producer_addr")
                rec["target_sid"] = state.get("target_sid")
                rec["producer_opcode"] = state.get("source_opcode")

                key = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("source_expr"),
                    rec.get("consumer_addr"),
                    rec.get("producer_addr"),
                )
                if key in seen:
                    continue
                seen.add(key)

                self.sgl_same_block_post_update_alias_events.append({
                    "kind": "sgl_same_block_post_update_alias",
                    "producer_addr": rec.get("producer_addr"),
                    "consumer_addr": rec.get("consumer_addr"),
                    "source_sid": rec.get("source_sid"),
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "source_expr": rec.get("source_expr"),
                    "condition_expr": rec.get("condition_expr"),
                })
                records.append(rec)

        return records

    def _pal_block_for_addr(self, addr):
        if addr is None:
            return None

        for block in getattr(self.func, "blocks", []) or []:
            if getattr(block, "addr", None) == addr:
                return block

        # Some layers expose cfg nodes instead of PAL blocks.  Accept the CFG
        # node's attached block if available.
        cfg = getattr(self.func, "cfg", None) or getattr(self, "cfg", None)
        nodes = getattr(cfg, "nodes", {}) if cfg is not None else {}
        node = nodes.get(addr) if isinstance(nodes, dict) else None
        if node is not None:
            block = getattr(node, "block", None)
            if block is not None:
                return block

        get_node = getattr(cfg, "get_node", None) if cfg is not None else None
        if callable(get_node):
            try:
                node = get_node(addr)
                block = getattr(node, "block", None) if node is not None else None
                if block is not None:
                    return block
            except Exception:
                pass

        return None



    # ---------------------------------------------------------
    # SGL-ADJACENT POST-UPDATE ALIAS CLOSURE
    # ---------------------------------------------------------

    def _sgl_adjacent_post_update_alias_records(self):
        """
        Derive post-update condition aliases from frozen SGL ordering.

        This is for RawCond/text conditions that are not ordinary FormulaNode
        consumers.  It walks the ExecTree and looks for:
            block with emitted state update expression
            immediately following if/loop condition containing that expression

        It emits metadata only.
        """

        root = getattr(self.func, "exec_root", None) or getattr(self.func, "exec_tree", None)
        if root is None:
            return []

        records = []
        seen = set()

        for producer_node, consumer_node in self._iter_sgl_adjacent_block_condition_pairs(root):
            producer_block = self._exec_block_to_pal_block(producer_node)
            if producer_block is None:
                continue

            consumer = self._consumer_record_from_exec_node(consumer_node)
            if consumer is None:
                continue

            cond_expr = str(consumer.get("cond_expr") or "")
            if not cond_expr:
                continue

            for state in self._state_update_records_for_block(producer_block):
                source_expr = state.get("source_expr")
                target_name = state.get("target_name")
                if not source_expr or not target_name:
                    continue

                if not self._condition_expr_contains_exact_formula(cond_expr, source_expr):
                    continue

                rec = self._make_post_update_condition_alias_record(
                    state.get("source_sid"),
                    consumer.get("cond_sid"),
                    source_expr,
                    target_name,
                    consumer,
                    "sgl_adjacent_state_write_condition_alias",
                    state.get("source_opcode"),
                )
                if rec is None:
                    continue

                rec["producer_addr"] = state.get("producer_addr")
                rec["target_sid"] = state.get("target_sid")
                rec["producer_opcode"] = state.get("source_opcode")

                key = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("source_expr"),
                    rec.get("consumer_addr"),
                    rec.get("producer_addr"),
                )
                if key in seen:
                    continue
                seen.add(key)

                self.sgl_adjacent_post_update_alias_events.append({
                    "kind": "sgl_adjacent_post_update_alias",
                    "producer_addr": rec.get("producer_addr"),
                    "consumer_addr": rec.get("consumer_addr"),
                    "source_sid": rec.get("source_sid"),
                    "target_name": rec.get("target_name"),
                    "source_expr": rec.get("source_expr"),
                    "condition_expr": rec.get("condition_expr"),
                })
                records.append(rec)

        return records

    def _iter_sgl_adjacent_block_condition_pairs(self, node):
        """
        Yield (previous_block_node, condition_node) pairs in the same SGL
        sequence/loop body container.  Recurses through nested structures.
        """

        if node is None:
            return

        children = list(getattr(node, "children", []) or [])
        last_block = None

        for child in children:
            kind = getattr(child, "kind", None)

            if kind == "block":
                last_block = child

            elif kind in ("if", "loop"):
                if last_block is not None and getattr(child, "cond_var", None) is not None:
                    yield (last_block, child)
                for pair in self._iter_sgl_adjacent_block_condition_pairs(child):
                    yield pair
                last_block = None

            else:
                for pair in self._iter_sgl_adjacent_block_condition_pairs(child):
                    yield pair
                # A nested sequence may end with a block, but without a stable
                # last-child contract exposed here we do not propagate it out.
                last_block = None

        for attr in ("body", "then_branch", "else_branch"):
            child = getattr(node, attr, None)
            if child is not None:
                for pair in self._iter_sgl_adjacent_block_condition_pairs(child):
                    yield pair

    def _exec_block_to_pal_block(self, exec_block):
        cfg_node = getattr(exec_block, "cfg_node", None)
        if cfg_node is None:
            return None
        return getattr(cfg_node, "block", None)

    def _consumer_record_from_exec_node(self, node):
        if node is None:
            return None

        kind = getattr(node, "kind", None)
        cond = getattr(node, "cond_var", None)
        cond_sid = self.sid_of(cond)

        cfg_node = getattr(node, "cfg_node", None)
        if cfg_node is None:
            cfg_node = getattr(node, "header", None)

        addr = getattr(cfg_node, "addr", None) if cfg_node is not None else None
        cond_expr = self._cond_expr_for_exec_node(cond)

        return {
            "kind": kind,
            "addr": addr,
            "role": getattr(node, "condition_role", None),
            "cond_sid": cond_sid,
            "cond_expr": cond_expr,
        }

    def _cond_expr_for_exec_node(self, cond):
        if cond is None:
            return ""

        # SGL RawCond/string-like constants.
        cv = getattr(cond, "const_value", None)
        if isinstance(cv, str):
            return cv

        if isinstance(cond, str):
            return cond

        # FormulaNode condition.
        if hasattr(cond, "var") and hasattr(cond, "opcode"):
            expr = self._expr_for_node(cond, seen=set())
            return expr or ""

        sid = self.sid_of(cond)
        if sid is not None:
            node = self.nodes.get(sid)
            if node is not None:
                expr = self._expr_for_node(node, seen=set())
                return expr or ""

        # Last resort: readable var name.  Do not use this for alias match
        # unless it happens to match exactly.
        return self.name_for_var(self.to_var(cond)) or str(cond)

    def _state_update_records_for_block(self, block):
        records = []

        if block is None:
            return records

        for op in list(getattr(block, "ops", []) or []):
            rec = self._state_update_record_for_op(block, op)
            if rec is not None:
                records.append(rec)

        return records

    def _state_update_record_for_op(self, block, op):
        if op is None:
            return None

        opcode = getattr(op, "opcode", None)
        if opcode not in self.PURE_INLINE_OPS:
            return None
        if opcode in self.COMPARE_OPS or opcode in ("BOOL_NEGATE",):
            return None

        out = getattr(op, "output", None)
        out_sid = self.sid_of(out)
        if out_sid is None:
            return None

        # The target name may be a real local output or a source alias mapped
        # by PHIfolder earlier, e.g. v_367 -> local_14.
        target_name = self.var_map.get(out_sid) or self.name_for_var(self.to_var(out))
        if not target_name:
            return None

        source_expr = self._expr_for_op(op, block=block, seen=set())
        if not source_expr:
            return None

        # Require that the source expression mentions the same target.  This
        # rejects plain assignments and unrelated pure temps.
        if not self._expr_mentions_name(source_expr, target_name):
            return None

        return {
            "kind": "sgl_adjacent_state_update",
            "producer_addr": getattr(block, "addr", None),
            "source_sid": out_sid,
            "target_sid": out_sid,
            "target_name": target_name,
            "source_expr": source_expr,
            "source_opcode": opcode,
        }


    # ---------------------------------------------------------
    # Presentation metadata
    # ---------------------------------------------------------

    def _set_ssa_policy(self, sid, cls, emit=False, expr_mode="inline", reason=None, target_name=None):
        if sid is None:
            return

        self.presentation_class_by_sid[sid] = cls
        self.ssa_policy_by_sid[sid] = {
            "class": cls,
            "emit": bool(emit),
            "expr_mode": expr_mode,
            "reason": reason,
            "target_name": target_name,
        }

    def _is_protected_materialized_sid(self, sid):
        if sid is None:
            return False

        if sid in self.local_target_sids:
            return True

        if sid in self.used_temp_phi_target_sids:
            return True

        if sid in self.used_temp_phi_output_sids:
            return True

        if sid in self.temp_phi_source_alias_sids:
            return True

        if sid in self.phi_source_alias_sids:
            return True

        if sid in self.protected_copy_temp_sids:
            return True

        if sid in self.must_emit_state_write_sids:
            return True

        if sid in self.real_local_copy_sids:
            return True

        if sid in self.required_call_result_sids:
            return True

        if sid in self.protected_condition_value_sids:
            return True

        if sid in self.executable_dropin_source_sids:
            return True

        if sid in self.condition_temp_def_sids:
            return True

        return False

    def _classify_transparent_bridge(self, sid, node):
        opcode = getattr(node, "opcode", None)
        if opcode not in self.TRANSPARENT_OPS:
            return False

        if sid in self.protected_condition_value_sids:
            self.materialize_sids.add(sid)
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)
            self._set_ssa_policy(
                sid,
                "protected_condition_value",
                emit=True,
                expr_mode="var",
                reason="condition dependency value is protected from bridge suppression",
                target_name=self.var_map.get(sid),
            )
            return True

        if sid in self.real_local_copy_sids:
            info = self.real_local_copy_info.get(sid, {})
            self.materialize_sids.add(sid)
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)
            self._set_ssa_policy(
                sid,
                "real_local_copy",
                emit=True,
                expr_mode="var",
                reason=info.get("reason", "real local copy state write"),
                target_name=info.get("target_name") or self.var_map.get(sid),
            )
            return True

        if sid in self.protected_copy_temp_sids:
            self.materialize_sids.add(sid)
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)
            self._set_ssa_policy(
                sid,
                "protected_snapshot_copy",
                emit=True,
                expr_mode="var",
                reason="snapshot copy required for local swap/state preservation",
                target_name=self.var_map.get(sid),
            )
            return True

        inputs = list(getattr(node, "inputs", []) or [])
        if not inputs:
            return False

        # COPY/CAST/ZEXT/SEXT/TRUNC are presentation bridges unless the SID is
        # protected as a PHI target or materialized semantic value. This removes
        # artifacts like:
        #     v_6644 = v_2704
        #     v_4880 = local_2c
        #     v_4949 = local_28
        self.inline_only_sids.add(sid)
        self.suppress_assign_sids.add(sid)
        self.copy_bridge_sids.add(sid)
        self._set_ssa_policy(
            sid,
            "transparent_bridge",
            emit=False,
            expr_mode="inline",
            reason="transparent op %s" % opcode,
        )
        return True

    def _classify_pure_bridge(self, sid, node):
        opcode = getattr(node, "opcode", None)
        if opcode not in self.PURE_INLINE_OPS:
            return False

        if sid in self.protected_condition_value_sids and sid in self.materialize_sids:
            self.suppress_assign_sids.discard(sid)
            self.inline_only_sids.discard(sid)
            self._set_ssa_policy(
                sid,
                "protected_condition_value",
                emit=True,
                expr_mode="var",
                reason="condition dependency value remains materialized",
                target_name=self.var_map.get(sid),
            )
            return True

        if opcode in self.TRANSPARENT_OPS:
            return False

        uses = self.use_counts.get(sid, 0)

        # Conditions are never standalone assignments in PAL presentation.
        if self.is_condition(node):
            self.suppress_assign_sids.add(sid)
            self.inline_only_sids.add(sid)
            self.compare_bridge_sids.add(sid)
            self._set_ssa_policy(
                sid,
                "compare_bridge",
                emit=False,
                expr_mode="inline",
                reason="condition compare bridge",
            )
            return True

        # SUBPIECE is helper-like, but if it is a one-use bridge inside a
        # larger condition, suppress the standalone assignment. In POW mode we
        # can later choose to materialize helper primitives instead.
        if opcode == "SUBPIECE" and uses <= 1:
            self.suppress_assign_sids.add(sid)
            self.inline_only_sids.add(sid)
            self.pure_bridge_sids.add(sid)
            self._set_ssa_policy(
                sid,
                "helper_inline_bridge",
                emit=False,
                expr_mode="inline",
                reason="one-use SUBPIECE helper bridge",
            )
            return True

        # One-use pure arithmetic/bitwise bridge: inline and suppress.
        if uses <= 1:
            self.inline_only_sids.add(sid)
            self.suppress_assign_sids.add(sid)
            self.pure_bridge_sids.add(sid)
            self._set_ssa_policy(
                sid,
                "pure_inline_bridge",
                emit=False,
                expr_mode="inline",
                reason="one-use pure op %s" % opcode,
            )
            return True

        # Repeated pure expressions can remain materialized for execution
        # fidelity / avoiding recomputation. Do not suppress by default.
        self._set_ssa_policy(
            sid,
            "repeated_pure_expr",
            emit=True,
            expr_mode="var",
            reason="repeated pure op %s uses=%s" % (opcode, uses),
        )
        return True


    def _build_presentation_metadata(self):
        """
        Build layer-owned presentation policy for formula SIDs.

        This is the cleanup pass that prevents emitter lock-in:
          - SSA ghosts are marked suppress/inline here.
          - semantic values stay materialized here.
          - PHI selector sources keep their aliased target names here.
        """

        for sid, node in self.nodes.items():
            opcode = getattr(node, "opcode", None)

            # Calls are materialized by _mark_materialization_policy unless
            # they are explicitly PHI-foldable/selector-aliased. Do not mark
            # them as ghosts here.
            if opcode in self.CALL_OPS:
                if sid in self.required_call_result_sids:
                    self.suppress_assign_sids.discard(sid)
                    self.inline_only_sids.discard(sid)
                    self.materialize_sids.add(sid)
                    self._set_ssa_policy(
                        sid,
                        "required_condition_call_result",
                        emit=True,
                        expr_mode="var",
                        reason="call result feeds condition dependency",
                        target_name=self.var_map.get(sid),
                    )
                elif sid in self.temp_phi_source_alias_sids or sid in self.phi_source_alias_sids:
                    self.suppress_assign_sids.discard(sid)
                    self.inline_only_sids.discard(sid)
                    self.materialize_sids.add(sid)
                    self._set_ssa_policy(
                        sid,
                        "phi_source_call_alias",
                        emit=True,
                        expr_mode="var",
                        reason="call source renamed to PHI target",
                        target_name=self.var_map.get(sid),
                    )
                else:
                    self._set_ssa_policy(
                        sid,
                        "materialized_call",
                        emit=True,
                        expr_mode="var",
                        reason="call result",
                    )
                continue

            # State writes are executable statements, not bridge artifacts.
            if sid in self.must_emit_state_write_sids:
                self.suppress_assign_sids.discard(sid)
                self.inline_only_sids.discard(sid)
                self.materialize_sids.add(sid)

                existing = self.ssa_policy_by_sid.get(sid, {})
                cls = existing.get("class") or "must_emit_state_write"
                reason = existing.get("reason") or self.state_write_info.get(sid, {}).get("reason") or "state write"

                self._set_ssa_policy(
                    sid,
                    cls,
                    emit=True,
                    expr_mode="var",
                    reason=reason,
                    target_name=self.var_map.get(sid) or self.state_write_info.get(sid, {}).get("target_name"),
                )
                continue

            # PHI targets, including used temp PHI outputs such as v_5848,
            # are real semantic values and must not be suppressed.
            if self._is_protected_materialized_sid(sid):
                self.suppress_assign_sids.discard(sid)
                self.inline_only_sids.discard(sid)
                self.materialize_sids.add(sid)
                self._set_ssa_policy(
                    sid,
                    "protected_phi_or_local_target",
                    emit=True,
                    expr_mode="var",
                    reason="PHI/local target",
                    target_name=self.var_map.get(sid),
                )
                continue

            if self._classify_transparent_bridge(sid, node):
                continue

            if self._classify_pure_bridge(sid, node):
                continue

            # Default: leave visible only if it was explicitly materialized
            # elsewhere. Otherwise avoid inventing suppression not backed by
            # policy.
            if sid in self.materialize_sids:
                self._set_ssa_policy(
                    sid,
                    "materialized_value",
                    emit=True,
                    expr_mode="var",
                    reason="pre-marked materialized sid",
                )
            else:
                self._set_ssa_policy(
                    sid,
                    "unclassified_visible",
                    emit=True,
                    expr_mode="var",
                    reason="no suppression rule matched",
                )

        for rec in self.phi_dropins:
            sid = rec.get("source_sid")
            node = rec.get("source_node")
            if sid is not None and node is not None:
                mode = "formula"
                if sid in self.materialize_sids:
                    mode = "var"
                if sid in self.phi_source_foldable_sids:
                    mode = "formula"
                if (
                    sid in self.temp_phi_source_alias_sids
                    or sid in self.phi_source_alias_sids
                    or sid in self.state_transition_alias_sids
                    or sid in self.prefer_var_expr_sids
                    or sid in self.post_update_alias_sids
                ):
                    mode = "var"

                self.preferred_expr_by_sid[sid] = {
                    "mode": mode,
                    "target_sid": rec.get("target_sid"),
                    "target_name": rec.get("target_name"),
                    "post_update_alias": sid in self.post_update_alias_sids,
                }

        # v19: consumer compare nodes of post-update aliases must also prefer
        # variable-form rendering, so higher layers do not reconstruct stale
        # pre-update expressions such as local_14 + 1 after local_14 += 1.
        for sid in self.post_update_consumer_sids:
            info = self.post_update_consumer_aliases.get(sid, {})
            self.preferred_expr_by_sid.setdefault(sid, {})
            self.preferred_expr_by_sid[sid].update({
                "mode": "formula_with_var_inputs",
                "post_update_consumer": True,
                "source_sid": info.get("source_sid"),
                "target_name": info.get("target_name"),
            })

    # ---------------------------------------------------------
    # Compatibility no-ops
    # ---------------------------------------------------------

    def _fold_phi_nodes(self):
        return

    def _propagate_transparent_copies(self):
        return

    def _rewrite_graph_inputs(self):
        return

    def _simplify_graph(self):
        return

    # ---------------------------------------------------------
    # Debug
    # ---------------------------------------------------------

    def debug_summary(self):
        print("\n[PHI FOLDER / EXECUTION-AWARE DROP-IN v21 SUMMARY]")
        print("-" * 60)
        print("Formula Nodes          :", len(self.nodes))
        print("PHI Nodes              :", len(self.phi_nodes))
        print("Identity PHIs          :", len(self.identity_phi_nodes))
        print("Transition PHIs        :", len(self.transition_phi_nodes))
        print("Drop-ins               :", len(self.phi_dropins))
        print("Pred Drop-in Keys      :", len(self.phi_dropins_by_pred))
        print("Var Map Entries        :", len(self.var_map))
        print("Materialize SIDs       :", len(self.materialize_sids))
        print("Inline-only SIDs       :", len(self.inline_only_sids))
        print("Suppress Assign SIDs   :", len(self.suppress_assign_sids))
        print("SSA Policy Entries     :", len(self.ssa_policy_by_sid))
        print("Local Target SIDs      :", len(self.local_target_sids))
        print("Foldable PHI Sources   :", len(self.phi_source_foldable_sids))
        print("Used Temp PHI Targets  :", len(self.used_temp_phi_target_sids))
        print("Used Temp PHI Outputs  :", len(self.used_temp_phi_output_sids))
        print("Value Selector PHIs    :", len(self.value_selector_phi_nodes))
        print("Temp PHI Source Aliases :", len(self.temp_phi_source_alias_sids))
        print("PHI Source Aliases      :", len(self.phi_source_alias_sids))
        print("Post-update Aliases     :", len(self.post_update_alias_sids))
        print("Post-update Consumers   :", len(self.post_update_consumer_sids))
        print("Post-update Detect Events:", len(self.post_update_alias_detection_events))
        print("Post-update Reject Events:", len(self.post_update_alias_reject_events))
        print("SGL Adjacent Aliases   :", len(self.sgl_adjacent_post_update_alias_events))
        print("SGL Same-Block Aliases :", len(self.sgl_same_block_post_update_alias_events))
        print("SGL RawCond Local Aliases:", len(self.sgl_rawcond_local_update_alias_events))
        print("Block Local Temp Aliases:", len(self.block_local_temp_post_update_alias_events))
        print("Transition Source Aliases:", len(self.transition_source_condition_alias_events))
        print("Stack Update Temp Aliases:", len(self.stack_update_temp_condition_alias_events))
        print("Protected Snapshot COPYs:", len(self.protected_copy_temp_sids))
        print("Join Discovery Events  :", len(self.phi_join_discovery_events))
        print("Skipped PHIs           :", len(self.skipped_phi_nodes))
        print("Compute Consumer Active:", bool(self.compute_consumer_active))
        print("Compute Plan Bindings  :", len(self.compute_bindings_by_sid))
        print("Compute Alias Bindings :", len(self.compute_alias_bindings_by_sid))
        print("Compute PHI Transitions:", len(self.compute_phi_transition_contracts))
        print("Compute Warnings       :", len(self.compute_consumer_warnings))
        print("Condition Sidecars     :", len(self.sgl_condition_provenance_sidecars))
        print("Condition Custody Bindings:", len(self.condition_custody_bindings))
        print("Condition Storage Observations:", len(self.condition_storage_observation_sids))
        print("Condition Storage Families:", len(self.condition_storage_family_ids))
        print("Condition Custody Warnings:", len(self.condition_custody_warnings))
        print("ABI Entry Roots         :", len(self.abi_entry_roots_by_sid))
        print("ABI Convergence Contracts:", len(self.abi_entry_convergence_contracts))
        print("ABI Must-Print Drop-ins :", len(self.abi_entry_must_print_dropin_ids))
        print("ABI Path Unbound Names  :", len(self.abi_entry_path_unbound_records))
        print("ABI Custody Warnings    :", len(self.abi_entry_custody_warnings))

    def debug_dump_compute_consumers(self, verbose=False):
        """Compact default report; verbose mode prints transition ownership."""

        try:
            from pprint import pprint
        except Exception:
            pprint = print

        print("\n===== PAL PHI COMPUTE CONSUMER =====")
        summary = self.compute_consumer_events[-1] if self.compute_consumer_events else {
            "kind": "phi_compute_consumer_not_run_v21",
            "version": self.COMPUTE_CONSUMER_VERSION,
        }
        pprint(summary)

        print("\n[WARNINGS]")
        pprint(list(self.compute_consumer_warnings))

        if verbose:
            print("\n[STATE ALIAS COMPUTE BINDINGS]")
            pprint(list(self.compute_alias_bindings_by_sid.values()))
            print("\n[PHI COMPUTE TRANSITIONS]")
            pprint(list(self.compute_phi_transition_contracts))

        print("===== END PAL PHI COMPUTE CONSUMER =====")

    def debug_dump_condition_custody(self, verbose=False):
        """Print SGL-condition to PALCompute-storage custody bindings."""

        try:
            from pprint import pprint
        except Exception:
            pprint = print

        def hx(value):
            return hex(value) if isinstance(value, int) else value

        print("\n===== PAL PHI CONDITION STORAGE CUSTODY =====")
        summary = self.condition_custody_events[-1] if self.condition_custody_events else {
            "kind": "phi_condition_storage_custody_not_run_v22",
            "version": self.CONDITION_CUSTODY_VERSION,
        }
        pprint(summary, sort_dicts=False)

        print("\n[CONDITION BINDINGS]")
        for rec in self.condition_custody_bindings:
            print("-" * 72)
            print(
                "ref=%s consumer=%s@%s role=%s status=%s root=%s" % (
                    rec.get("provenance_ref"),
                    rec.get("consumer_kind"),
                    hx(rec.get("consumer_addr")),
                    rec.get("consumer_role"),
                    rec.get("status"),
                    rec.get("root_condition_sid"),
                )
            )
            print("expr=%s" % rec.get("condition_expr"))
            print("storage_observation_sids=%s" % rec.get("storage_observation_sids", []))
            print("storage_family_ids=%s" % rec.get("storage_family_ids", []))
            print("indirect_transitions=%s" % rec.get("indirect_transition_count"))
            print("effect_owner_compute_op_keys=%s" % rec.get("effect_owner_compute_op_keys", []))

            if verbose:
                print("storage_observations=")
                pprint(rec.get("storage_observations", []), sort_dicts=False)
                print("formula_traversal=")
                pprint(rec.get("formula_traversal", []), sort_dicts=False)

            if rec.get("warnings"):
                print("binding_warnings=")
                pprint(rec.get("warnings"), sort_dicts=False)

        print("\n[WARNINGS]")
        pprint(list(self.condition_custody_warnings), sort_dicts=False)
        print("===== END PAL PHI CONDITION STORAGE CUSTODY =====")

    def debug_dump_abi_entry_custody(self, verbose=False):
        """Print ABI-F entry ownership and predecessor convergence proof."""

        try:
            from pprint import pprint
        except Exception:
            pprint = print

        def hx(value):
            return hex(value) if isinstance(value, int) else value

        print("\n===== PAL PHI ABI-F ENTRY / CONVERGENCE CUSTODY =====")
        pprint(dict(self.abi_entry_custody_inventory), sort_dicts=False)

        print("\n[CONVERGENCE PROOFS]")
        for rec in self.abi_entry_convergence_contracts:
            print("-" * 72)
            print(
                "target=%s/%s join=%s root=%s/%s role=%s owned=%s/%s" % (
                    rec.get("target_sid"),
                    rec.get("target_name"),
                    hx(rec.get("join_addr")),
                    rec.get("root_sid"),
                    rec.get("root_execution_name"),
                    rec.get("root_role"),
                    rec.get("owned_predecessor_count"),
                    rec.get("predecessor_count"),
                )
            )
            for path in rec.get("paths", []) or []:
                print(
                    "  pred=%s source=%s/%s owner=%s inferred=%s owned=%s" % (
                        hx(path.get("pred_addr")),
                        path.get("source_sid"),
                        path.get("source_name"),
                        path.get("execution_owner_class"),
                        path.get("source_inferred_from_unique_root"),
                        path.get("owned"),
                    )
                )
            if verbose:
                pprint(rec, sort_dicts=False)

        print("\n[MUST-PRINT OVERRIDES]")
        pprint(list(self.abi_entry_must_print_dropin_records), sort_dicts=False)
        if verbose:
            print("\n[ENTRY-ROOT SOURCE-ALIAS REJECTIONS]")
            pprint(
                list(self.abi_entry_source_alias_rejections),
                sort_dicts=False,
            )
            print("\n[ENTRY ROOTS]")
            pprint(list(self.abi_entry_roots_by_sid.values()), sort_dicts=False)
            print("\n[EXECUTION OWNERS]")
            pprint(
                list(self.abi_entry_execution_owners_by_sid.values()),
                sort_dicts=False,
            )
            print("\n[STORAGE OWNERS]")
            pprint(
                list(self.abi_entry_storage_owners_by_family.values()),
                sort_dicts=False,
            )

        print("\n[WARNINGS]")
        pprint(list(self.abi_entry_custody_warnings), sort_dicts=False)
        print("===== END PAL PHI ABI-F ENTRY / CONVERGENCE CUSTODY =====")

    def debug_dump_dropins(self):
        print("\n[PHI DROP-INS]")
        print("-" * 60)

        for d in self.phi_dropins:
            pa = d.get("pred_addr")
            ja = d.get("join_addr")
            pa_txt = hex(pa) if isinstance(pa, int) else str(pa)
            ja_txt = hex(ja) if isinstance(ja, int) else str(ja)

            print(
                "pred=%s -> join=%s :: %s = %s" %
                (
                    pa_txt,
                    ja_txt,
                    d.get("target_name"),
                    d.get("source_name") or d.get("source_sid"),
                )
            )

        print("-" * 60)

    def debug_dump_presentation(self):
        print("\n[PHI PRESENTATION METADATA]")
        print("-" * 60)
        print("materialize_sids        :", sorted(self.materialize_sids))
        print("inline_only_sids        :", sorted(self.inline_only_sids))
        print("suppress_assign_sids    :", sorted(self.suppress_assign_sids))
        print("local_target_sids       :", sorted(self.local_target_sids))
        print("phi_source_foldable_sids:", sorted(self.phi_source_foldable_sids))
        print("used_temp_phi_target_sids:", sorted(self.used_temp_phi_target_sids))
        print("post_update_alias_sids  :", sorted(self.post_update_alias_sids))
        print("post_update_consumer_sids:", sorted(self.post_update_consumer_sids))
        print("prefer_var_expr_sids    :", sorted(self.prefer_var_expr_sids))
        print("-" * 60)

    def debug_dump_join_discovery(self):
        print("\n[PHI JOIN DISCOVERY]")
        print("-" * 60)

        for ev in self.phi_join_discovery_events:
            phi_sid = ev.get("phi_sid")
            ba = ev.get("block_addr")
            ca = ev.get("cfg_addr")
            ba_txt = hex(ba) if isinstance(ba, int) else str(ba)
            ca_txt = hex(ca) if isinstance(ca, int) else str(ca)
            print(
                "phi=%s block=%s cfg=%s reason=%s" %
                (phi_sid, ba_txt, ca_txt, ev.get("reason"))
            )

        print("-" * 60)

    def debug_dump_skipped(self):
        print("\n[SKIPPED PHIS]")
        print("-" * 60)

        for phi, reason in self.skipped_phi_nodes:
            out = getattr(getattr(phi, "output", None), "ssa_id", "?")
            print("PHI %s :: %s" % (out, reason))

        print("-" * 60)


    def debug_dump_synthesized_phis(self):
        print("\n[SYNTHESIZED PHIS FROM BLOCK OPS]")
        print("-" * 60)
        for phi in self.synthesized_phi_nodes:
            out = getattr(phi, "output", None)
            sid = self.sid_of(out)
            block = getattr(phi, "block", None) or getattr(phi, "block_region", None)
            addr = getattr(block, "addr", None) if block is not None else None
            inputs = [self.name_for_var(self.to_var(i)) or self.sid_of(i) for i in getattr(phi, "inputs", []) or []]
            print("PHI %s at %s <- %s" % (sid, hex(addr) if isinstance(addr, int) else addr, inputs))
        print("-" * 60)


    def debug_dump_temp_phi_aliases(self):
        print("\n[TEMP PHI SOURCE ALIASES]")
        print("-" * 60)

        if not self.temp_phi_source_aliases:
            print("(none)")

        for sid, info in sorted(self.temp_phi_source_aliases.items()):
            pa = info.get("pred_addr")
            ja = info.get("join_addr")
            pa_txt = hex(pa) if isinstance(pa, int) else str(pa)
            ja_txt = hex(ja) if isinstance(ja, int) else str(ja)
            print(
                "%s -> %s  pred=%s join=%s  source=%s" %
                (
                    sid,
                    info.get("target_name"),
                    pa_txt,
                    ja_txt,
                    info.get("source_name"),
                )
            )

        print("-" * 60)


    def debug_dump_ssa_policy(self, limit=None):
        print("\n[SSA PRESENTATION POLICY]")
        print("-" * 60)
        items = sorted(self.ssa_policy_by_sid.items())

        if limit is not None:
            items = items[:limit]

        for sid, policy in items:
            print(
                "%s :: class=%s emit=%s expr=%s reason=%s target=%s" %
                (
                    sid,
                    policy.get("class"),
                    policy.get("emit"),
                    policy.get("expr_mode"),
                    policy.get("reason"),
                    policy.get("target_name"),
                )
            )

        print("-" * 60)


def debug_condition_custody(pal, verbose=False):
    """Print the PHIfolder condition/storage custody sidecar inventory."""

    from pprint import pprint

    if pal is None:
        debug = {}
        bindings = []
        warnings = []
    else:
        debug = getattr(pal, "phi_condition_custody_debug", {}) or {}
        bindings = list(
            debug.get("bindings", [])
            or getattr(pal, "phi_condition_custody_bindings", [])
            or []
        )
        warnings = list(
            debug.get("warnings", [])
            or getattr(pal, "phi_condition_custody_warnings", [])
            or []
        )

    summary = dict(debug.get("summary", {}) or {})

    print("\n===== PAL PHI CONDITION STORAGE CUSTODY =====")
    pprint(summary, sort_dicts=False)
    print("\n[CONDITION BINDINGS]")
    if verbose:
        pprint(bindings, sort_dicts=False)
    else:
        compact = []
        for rec in bindings:
            compact.append({
                "provenance_ref": rec.get("provenance_ref"),
                "consumer_addr": (
                    hex(rec.get("consumer_addr"))
                    if isinstance(rec.get("consumer_addr"), int)
                    else rec.get("consumer_addr")
                ),
                "condition_expr": rec.get("condition_expr"),
                "root_condition_sid": rec.get("root_condition_sid"),
                "status": rec.get("status"),
                "storage_observation_sids": rec.get(
                    "storage_observation_sids", []
                ),
                "storage_family_ids": rec.get("storage_family_ids", []),
                "indirect_transition_count": rec.get(
                    "indirect_transition_count"
                ),
                "effect_owner_compute_op_keys": rec.get(
                    "effect_owner_compute_op_keys", []
                ),
                "warnings": len(rec.get("warnings", []) or []),
            })
        pprint(compact, sort_dicts=False)

    print("\n[WARNINGS]")
    pprint(warnings, sort_dicts=False)
    print("===== END PAL PHI CONDITION STORAGE CUSTODY =====\n")

    return {
        "summary": summary,
        "bindings": bindings,
        "warnings": warnings,
    }


def debug_abi_entry_custody(pal, verbose=False):
    """Standalone ABI-F debugger for ``debug_abi_entry_custody(self.PAL)``."""

    from pprint import pprint

    if pal is None:
        debug = {}
    else:
        debug = dict(
            getattr(pal, "phi_abi_entry_custody_debug", {}) or {}
        )

    summary = dict(
        debug.get("summary", {})
        or getattr(pal, "phi_abi_entry_custody_inventory", {})
        if pal is not None else {}
    )
    convergence = list(
        debug.get("convergence_contracts", [])
        or (
            getattr(pal, "phi_abi_entry_convergence_contracts", [])
            if pal is not None else []
        )
        or []
    )
    overrides = list(
        debug.get("must_print_dropins", [])
        or (
            getattr(pal, "phi_abi_entry_must_print_dropin_records", [])
            if pal is not None else []
        )
        or []
    )
    alias_rejections = list(
        debug.get("source_alias_rejections", []) or []
    )
    warnings = list(
        debug.get("warnings", [])
        or (
            getattr(pal, "phi_abi_entry_custody_warnings", [])
            if pal is not None else []
        )
        or []
    )

    def hx(value):
        return hex(value) if isinstance(value, int) else value

    print("\n===== PAL PHI ABI-F ENTRY / CONVERGENCE CUSTODY =====")
    pprint(summary, sort_dicts=False)
    print("\n[CONVERGENCE PROOFS]")
    compact = []
    for rec in convergence:
        item = {
            "root_sid": rec.get("root_sid"),
            "root_name": rec.get("root_execution_name"),
            "root_role": rec.get("root_role"),
            "target_sid": rec.get("target_sid"),
            "target_name": rec.get("target_name"),
            "join_addr": hx(rec.get("join_addr")),
            "owned_predecessors": "%s/%s" % (
                rec.get("owned_predecessor_count"),
                rec.get("predecessor_count"),
            ),
            "all_predecessors_owned": rec.get("all_predecessors_owned"),
            "paths": [
                {
                    "pred_addr": hx(path.get("pred_addr")),
                    "source_sid": path.get("source_sid"),
                    "source_name": path.get("source_name"),
                    "owner": path.get("execution_owner_class"),
                    "inferred": path.get("source_inferred_from_unique_root"),
                    "owned": path.get("owned"),
                }
                for path in list(rec.get("paths", []) or [])
            ],
        }
        compact.append(item)
    pprint(convergence if verbose else compact, sort_dicts=False)

    print("\n[MUST-PRINT OVERRIDES]")
    pprint(overrides, sort_dicts=False)
    if verbose:
        print("\n[ENTRY-ROOT SOURCE-ALIAS REJECTIONS]")
        pprint(alias_rejections, sort_dicts=False)
        print("\n[ENTRY ROOTS]")
        pprint(debug.get("entry_roots", []), sort_dicts=False)
        print("\n[EXECUTION OWNERS]")
        pprint(debug.get("execution_owners", []), sort_dicts=False)
        print("\n[STORAGE OWNERS]")
        pprint(debug.get("storage_owners", []), sort_dicts=False)

    print("\n[WARNINGS]")
    pprint(warnings, sort_dicts=False)
    print("===== END PAL PHI ABI-F ENTRY / CONVERGENCE CUSTODY =====\n")

    return {
        "summary": summary,
        "convergence_contracts": convergence,
        "must_print_dropins": overrides,
        "source_alias_rejections": alias_rejections,
        "warnings": warnings,
    }
