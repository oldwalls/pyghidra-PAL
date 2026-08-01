# ============================================================
# PAL SEMANTIC GRAPH BUILDER
# v38 clothed-emperor EdgeTruth tri-state custody + v37 bohdi-emperor PHI predecessor/edge linkage
# ============================================================
#
# Purpose:
#   Builds a semantic SSA formula graph from lifted PAL P-code.
#
# v18 design goals:
#   - remain legacy-compatible with PALPHIfolder: func.var_nodes = (dict, phi_nodes)
#   - consume resolver v18x metadata: storage_key, width_bits, semantic roles
#   - preserve CFG/raw-edge metadata on condition FormulaNodes
#   - expose def/use maps for PHIfolder, SGL, emitter, and future PALRAW/PALplug
#   - keep terminators out of ordinary op graph but index their condition/return vars
#
# Produces:
#   func.var_nodes                  = (var_nodes, phi_nodes)
#   func.formula_nodes              = var_nodes
#   func.phi_nodes                  = phi_nodes
#   func.condition_vars             = condition_vars
#   func.return_vars                = return_vars
#   func.call_nodes                 = call_nodes
#   func.defs_by_sid                = defs_by_sid
#   func.uses_by_sid                = uses_by_sid
#   func.block_formula_nodes        = block_addr -> [FormulaNode]
#   func.block_condition_nodes      = block_addr -> FormulaNode
#   func.semantic_debug             = dict
#   func.sgl_structuring_handoff   = dict of SGL-facing custody metadata
# ============================================================


import re

PAL_SEMANTIC_GRAPH_VERSION = (
    "PALSemanticGraphBuilder_v38_clothed_emperor_edgetruth_tristate_custody"
)

# ============================================================
# SMALL HELPERS
# ============================================================

def _safe_hex(x):
    try:
        if x is None:
            return None
        return hex(int(x))
    except Exception:
        return str(x)


def _sid(x):
    if x is None:
        return None
    if hasattr(x, "var"):
        return getattr(x.var, "ssa_id", None)
    return getattr(x, "ssa_id", None)


def _canonical_ssa_name_v29(sid):
    """
    Return one stable textual SSA identity.

    PALlibrary/PALSymbolResolver publish canonical SIDs as ``v_N`` strings in
    current bundles, while older paths may still provide the bare integer N.
    SemanticGraphBuilder must never add a second ``v_`` prefix to an already
    canonical identity because EdgeTruth/SGL freeze this text for both Python
    projections.
    """
    if sid is None:
        return None

    text = str(sid)

    # Repair only the machine-generated numeric SSA namespace.  Do not rewrite
    # arbitrary user/operator names which happen to contain ``v_v_``.
    while re.fullmatch(r"v_v_\d+", text):
        text = text[2:]

    if re.fullmatch(r"v_\d+", text):
        return text
    if text.isdigit():
        return "v_%s" % text

    # Preserve existing non-numeric identity behavior.
    if text.startswith(("v_", "c_")):
        return text
    return "v_%s" % text


def _unwrap_var(x):
    if x is None:
        return None
    if hasattr(x, "var"):
        return x.var
    return x


def _block_addr(block):
    try:
        return getattr(block, "addr", None)
    except Exception:
        return None


def _block_addr_hex(block):
    return _safe_hex(_block_addr(block))


def _storage_key(v):
    if v is None:
        return None

    key = getattr(v, "storage_key", None)
    if key is not None:
        return key

    return (
        getattr(v, "space", None),
        getattr(v, "offset", None),
        getattr(v, "size", None),
        getattr(v, "address", None),
    )


def _is_constant(v):
    v = _unwrap_var(v)
    return bool(getattr(v, "is_constant", False))


def _const_value(v):
    v = _unwrap_var(v)
    if v is None:
        return None
    if hasattr(v, "const_value"):
        return getattr(v, "const_value", None)
    return getattr(v, "offset", None)


# ============================================================
# FORMULA NODE
# ============================================================

class FormulaNode:
    """
    Semantic node representing a single SSA definition.

    Each FormulaNode corresponds to one defining PALPcodeOp output.
    """

    def __init__(self, var, op=None, block=None):

        self.var = var
        self.op = op
        self.opcode = getattr(op, "opcode", None) if op else None

        # Inputs are resolved during link_inputs().
        # They may contain FormulaNode objects, PALVariable constants,
        # unresolved PALVariable objects, or None.
        self.inputs = []

        # Direct unresolved/original inputs retained for diagnostics.
        self.raw_inputs = list(getattr(op, "inputs", []) or []) if op else []

        # Semantic flags.
        self.is_phi = False
        self.is_condition = False
        self.is_return_value = False
        self.is_induction = False
        self.is_call = False
        self.is_copy = self.opcode == "COPY"
        self.is_compare = self.opcode in (
            "INT_EQUAL", "INT_NOTEQUAL",
            "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
            "BOOL_AND", "BOOL_OR", "BOOL_XOR", "BOOL_NEGATE",
            "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
        )
        self.is_arithmetic = self.opcode in (
            "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
            "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
        )
        self.is_width_cast = self.opcode in ("CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "PIECE")

        # Role annotation for downstream heuristics/debugging.
        self.semantic_role = None

        # Region metadata.
        self.block = block
        self.block_region = block
        self.block_addr = _block_addr(block)
        self.block_addr_hex = _block_addr_hex(block)

        # v18x resolver metadata mirrored for convenience.
        self.ssa_id = getattr(var, "ssa_id", None)
        self.name = getattr(var, "name", None)
        self.storage_key = _storage_key(var)
        self.width_bits = getattr(var, "width_bits", None) or (
            (getattr(var, "size", None) or 0) * 8 if var is not None else None
        )
        self.width_bytes = getattr(var, "width_bytes", None) or getattr(var, "size", None)

        # Use/call/branch metadata filled later.
        self.users = []
        self.use_sids = []
        self.condition_block = None
        self.condition_edge_info = None
        self.call_target = None
        self.call_target_name = None
        self.return_block = None

        # Attach direct backrefs for later debugging / folding.
        if var is not None:
            try:
                var.formula_node = self
                var.def_node = self
                var.block_region = block
                var.storage_key = self.storage_key
                if self.width_bits is not None:
                    var.width_bits = self.width_bits
                if self.width_bytes is not None:
                    var.width_bytes = self.width_bytes
            except Exception:
                pass

        if self.opcode == "MULTIEQUAL":
            self.is_phi = True
            self.semantic_role = "phi_merge"

    def __repr__(self):
        sid = getattr(self.var, "ssa_id", "?")
        return "<FormulaNode %s = %s>" % (sid, self.opcode)


# ============================================================
# PHI NODE
# ============================================================

class PhiNode:
    """
    Explicit PHI representation for SSA merges.

    This is separate from FormulaNode so the PHI folder can process
    merge intent directly without rediscovering MULTIEQUAL nodes.
    """

    def __init__(self, output, formula_node=None, block=None):

        self.output = output
        self.var = output
        self.formula_node = formula_node
        self.block = block
        self.block_region = block
        self.block_addr = _block_addr(block)
        self.block_addr_hex = _block_addr_hex(block)

        # Inputs may contain FormulaNode or PALVariable objects.
        self.inputs = []
        self.raw_inputs = []

        # v18 metadata for PHIfolder.
        self.output_sid = getattr(output, "ssa_id", None)
        self.output_name = getattr(output, "name", None)
        self.output_storage_key = _storage_key(output)
        self.output_width_bits = getattr(output, "width_bits", None) or (
            (getattr(output, "size", None) or 0) * 8 if output is not None else None
        )
        self.input_sids = []
        self.input_storage_keys = []
        self.is_identity_phi = False
        self.is_storage_phi = False
        self.has_call_source = False
        self.has_constant_source = False

    def __repr__(self):
        out = getattr(self.output, "ssa_id", "?")
        return "<PHI %s <- %s>" % (out, self.inputs)


# ============================================================
# SEMANTIC GRAPH BUILDER
# ============================================================

class PALSemanticGraphBuilder:

    def __init__(self, pal_function):

        self.func = pal_function
        self.semantic_graph_version = PAL_SEMANTIC_GRAPH_VERSION

        # Main products.
        self.var_nodes = {}
        self.phi_nodes = []

        # Terminator-derived products.
        self.condition_vars = []
        self.condition_nodes = []
        self.return_vars = []

        # Useful indexes.
        self.defs_by_sid = {}
        self.uses_by_sid = {}
        self.uses_by_storage_key = {}
        self.block_formula_nodes = {}
        self.block_condition_nodes = {}

        # Diagnostics.
        self.unresolved_inputs = []
        self.call_nodes = []
        self.compare_nodes = []
        self.copy_nodes = []
        self.width_cast_nodes = []
        self.induction_nodes = []
        self.semantic_events = []

        # v20 / ALPHA_SIX metadata closure:
        # Consume frozen SGL condition-consumer records and annotate the
        # semantic graph for PHIfolder/emitter.  This is metadata only; no
        # control-flow or expression rewriting occurs here.
        self.sgl_condition_consumers = list(getattr(pal_function, "sgl_condition_consumers", []) or [])
        self.sgl_condition_consumer_index = {}
        self.sgl_condition_dependency_sids = {}
        self.sgl_condition_temp_refs = []

        # v24 / ALPHA_SEVEN SGL structuring handoff:
        # These are metadata-only "data sandwiches" for PALSGLdecomp.
        # The semantic graph does not decide break/continue/while ownership;
        # it exports raw/HF edge custody, latch/update facts, and block
        # ownership hints so SGL can make those decisions with less guessing.
        self.block_branch_custody = {}
        self.edge_condition_truth = {}

        # v25 / EdgeTruth: authoritative per-edge branch-polarity metadata.
        # This is built in SemanticGraphBuilder, before SGL structure recovery,
        # so downstream code can ask "what predicate takes src -> dst?"
        # instead of guessing from a block-level condition string.
        self.edge_truth = {}
        self.edge_truth_by_src = {}
        self.edge_truth_by_dst = {}
        self.edge_truth_predicates = {}
        self.edge_truth_profiles = {}
        self.edge_truth_debug = []
        self.edge_truth_inventory_v38 = {}
        self.edge_truth_version = (
            "PALSemanticGraphBuilder_v38_EdgeTruth_"
            "clothed_emperor_tristate_custody"
        )

        # v31 / multiway semantic handoff. FunctionCFG freezes physical topology,
        # Ghidra case labels, default evidence, and the computed BRANCHIND
        # destination. SemanticGraph resolves the source selector expression,
        # case-arm custody, join ownership, and PHI predecessor bindings without
        # using successor order or PHI input order as semantic authority.
        self.multiway_dispatch_version = (
            "PALSemanticGraphBuilder_v31_multiway_default_selector_cone_custody"
        )
        self.semantic_multiway_dispatch_facts = []
        self.semantic_multiway_dispatch_by_block = {}
        self.semantic_multiway_dispatch_inventory = {}
        self.semantic_multiway_dispatch_events = []

        self.induction_updates_by_block = {}
        self.latch_update_facts = {}
        self.block_ownership_facts = {}
        self.suspicious_successor_custody = []
        self.sgl_structuring_handoff = {}

        # v37 / bohdi emperor: generic PHI predecessor linkage.
        #
        # FunctionCFG owns the immutable structural edge token
        # ``(pred_addr, join_addr)``.  SemanticGraph binds PHI source identities
        # to those exact incoming edges using definition blocks, CFG reachability,
        # and a set/capacity matching proof.  MULTIEQUAL input ordinal and CFG
        # predecessor order are retained only as diagnostics and are never
        # semantic authority.
        self.phi_predecessor_linkage_version_v37 = (
            "PALSemanticGraphBuilder_v37_bohdi_emperor_phi_predecessor_edge_linkage"
        )
        self.phi_predecessor_bindings_v37 = []
        self.phi_predecessor_bindings_by_target_v37 = {}
        self.phi_predecessor_bindings_by_edge_v37 = {}
        self.phi_transition_descriptions_v37 = []
        self.phi_transition_by_edge_v37 = {}
        self.phi_predecessor_linkage_events_v37 = []
        self.phi_predecessor_linkage_warnings_v37 = []
        self.phi_predecessor_linkage_failures_v37 = []
        self.phi_predecessor_linkage_inventory_v37 = {}
        self._phi_cfg_edge_identity_by_pair_v37 = {}

        # v34: exact consumer-operand identity custody.
        #
        # Linked FormulaNode inputs remain expression/SSA authority. Original
        # FormulaNode.raw_inputs remain storage evidence. PALCompute and the
        # resolver's storage-family sidecars are consulted as additional
        # evidence, never as permission for a global rename. Only an exact
        # (consumer SID, operand index) contract may alter formula rendering.
        self.operand_projection_version = (
            "PALSemanticGraphBuilder_v36_ghost_emperor_split_value_site_custody"
        )
        self.operand_projection_contracts = {}
        self.storage_projection_names = {}
        self.sid_projection_names = {}
        self.operand_projection_collisions = []
        self.operand_projection_events = []
        self.operand_projection_inventory = {}

        # v34 evidence and fail-closed metadata receipts.
        self.operand_identity_evidence_v34 = []
        self.operand_identity_ambiguities_v34 = []
        self.operand_identity_failures_v34 = []
        self.operand_identity_inventory_v34 = {}
        self.resolver_name_storage_collisions_v34 = []
        self._operand_identity_by_consumer_v34 = {}
        self._operand_identity_failure_keys_v34 = set()

        # Refreshed again at projection-build time so pipeline construction
        # order cannot leave stale references.
        self.compute_storage_bindings_by_sid_v34 = dict(
            getattr(pal_function, "compute_storage_bindings_by_sid", {}) or {}
        )
        self.resolver_storage_family_by_sid_v34 = dict(
            getattr(pal_function, "indirect_storage_family_by_sid", {}) or {}
        )
        self.resolver_storage_families_by_key_v34 = dict(
            getattr(pal_function, "indirect_storage_families_by_key", {}) or {}
        )

        # v35: temporal snapshot custody. A COPY of a PHI/state epoch is not
        # transparent when the copied epoch and a later dependent epoch are
        # consumed simultaneously. This is SID/epoch custody, not storage
        # renaming: one exact COPY output receives an independent materialized
        # identity and no storage family is renamed globally.
        self.snapshot_copy_version_v35 = (
            "PALSemanticGraphBuilder_v36_ghost_emperor_split_value_site_custody"
        )
        self.snapshot_copy_contracts_v35 = {}
        self.snapshot_copy_projection_names_by_sid_v35 = {}
        self.snapshot_copy_events_v35 = []
        self.snapshot_copy_failures_v35 = []
        self.snapshot_copy_inventory_v35 = {}

        # v36 / ghost emperor: the semantic value must survive, but the native
        # COPY site is not automatically the final structured execution owner.
        # SGL owns placement and may prove an equivalent loop-exit rebind.
        self.snapshot_copy_value_site_split_version_v36 = (
            "v36_ghost_emperor_split_value_site_custody"
        )

    # ---------------------------------------------------------
    # PUBLIC ENTRY
    # ---------------------------------------------------------

    def run(self):

        self.build_nodes()
        self.link_inputs()
        self.build_use_indexes()
        self.build_phi_nodes()
        self.build_phi_predecessor_linkage_v37()

        self.mark_condition_nodes()
        self.mark_return_values()
        self.mark_call_nodes()
        self.mark_classification_nodes()

        self.detect_induction_variables()
        self.annotate_storage_flows()
        self.build_temporal_snapshot_copy_contracts_v35()
        self.build_joint_consumer_stack_operand_projections_v34()

        self.build_sgl_structuring_metadata()

        self.consume_sgl_condition_consumers()

        self.expose()

        return self.func.var_nodes

    # ---------------------------------------------------------
    # EXPOSURE / COMPATIBILITY
    # ---------------------------------------------------------

    def expose(self):
        """
        Expose semantic products on PALFunctionObject.

        Current downstream compatibility:
            PALPHIfolder accepts func.var_nodes as either:
              - dict
              - tuple(dict, phi_nodes)

        Therefore we keep tuple form for now.
        """

        self.func.semantic_graph_version = self.semantic_graph_version

        # Legacy-compatible with current PALPHIfolder and PALemitter.
        self.func.var_nodes = (self.var_nodes, self.phi_nodes)

        # Canonical aliases.
        self.func.formula_nodes = self.var_nodes
        self.func.phi_nodes = self.phi_nodes

        # v37 bohdi-emperor PHI predecessor/edge custody.  Tuple-keyed maps are
        # the exact in-memory lookup authority; list records remain
        # serialization-safe for Icecube/debug publication.
        self.func.phi_predecessor_linkage_version_v37 = (
            self.phi_predecessor_linkage_version_v37
        )
        self.func.phi_predecessor_bindings_v37 = list(
            self.phi_predecessor_bindings_v37
        )
        self.func.phi_predecessor_bindings_by_target_v37 = {
            key: list(value)
            for key, value in self.phi_predecessor_bindings_by_target_v37.items()
        }
        self.func.phi_predecessor_bindings_by_edge_v37 = {
            key: list(value)
            for key, value in self.phi_predecessor_bindings_by_edge_v37.items()
        }
        self.func.phi_transition_descriptions_v37 = list(
            self.phi_transition_descriptions_v37
        )
        self.func.phi_transition_by_edge_v37 = {
            key: list(value)
            for key, value in self.phi_transition_by_edge_v37.items()
        }
        self.func.phi_predecessor_linkage_events_v37 = list(
            self.phi_predecessor_linkage_events_v37
        )
        self.func.phi_predecessor_linkage_warnings_v37 = list(
            self.phi_predecessor_linkage_warnings_v37
        )
        self.func.phi_predecessor_linkage_failures_v37 = list(
            self.phi_predecessor_linkage_failures_v37
        )
        self.func.phi_predecessor_linkage_inventory_v37 = dict(
            self.phi_predecessor_linkage_inventory_v37
        )

        self.func.condition_vars = self.condition_vars
        self.func.condition_nodes = self.condition_nodes
        self.func.return_vars = self.return_vars
        self.func.unresolved_semantic_inputs = self.unresolved_inputs
        self.func.call_nodes = self.call_nodes

        # v18 indexes for PHI/SGL/emitter/PALRAW.
        self.func.defs_by_sid = self.defs_by_sid
        self.func.uses_by_sid = self.uses_by_sid
        self.func.uses_by_storage_key = self.uses_by_storage_key
        self.func.block_formula_nodes = self.block_formula_nodes
        self.func.block_condition_nodes = self.block_condition_nodes
        self.func.compare_nodes = self.compare_nodes
        self.func.copy_nodes = self.copy_nodes
        self.func.width_cast_nodes = self.width_cast_nodes
        self.func.induction_nodes = self.induction_nodes

        # v34 consumer-scoped operand-identity sidecars.  Tuple keys are kept
        # in-memory for exact runtime lookup; persisted debug views use the
        # detached records below.
        self.func.operand_projection_version = self.operand_projection_version
        self.func.operand_projection_contracts = dict(
            self.operand_projection_contracts
        )
        self.func.storage_projection_names = dict(
            self.storage_projection_names
        )
        self.func.sid_projection_names = dict(self.sid_projection_names)
        self.func.operand_projection_collisions = list(
            self.operand_projection_collisions
        )
        self.func.operand_projection_events = list(
            self.operand_projection_events
        )
        self.func.operand_projection_inventory = dict(
            self.operand_projection_inventory
        )
        self.func.operand_identity_evidence_v34 = list(
            self.operand_identity_evidence_v34
        )
        self.func.operand_identity_ambiguities_v34 = list(
            self.operand_identity_ambiguities_v34
        )
        self.func.operand_identity_failures_v34 = list(
            self.operand_identity_failures_v34
        )
        self.func.operand_identity_inventory_v34 = dict(
            self.operand_identity_inventory_v34
        )
        self.func.resolver_name_storage_collisions_v34 = list(
            self.resolver_name_storage_collisions_v34
        )
        self.func.snapshot_copy_value_site_split_version_v36 = (
            self.snapshot_copy_value_site_split_version_v36
        )
        self.func.snapshot_copy_version_v35 = self.snapshot_copy_version_v35
        self.func.snapshot_copy_contracts_v35 = dict(
            self.snapshot_copy_contracts_v35
        )
        self.func.snapshot_copy_projection_names_by_sid_v35 = dict(
            self.snapshot_copy_projection_names_by_sid_v35
        )
        self.func.snapshot_copy_events_v35 = list(
            self.snapshot_copy_events_v35
        )
        self.func.snapshot_copy_failures_v35 = list(
            self.snapshot_copy_failures_v35
        )
        self.func.snapshot_copy_inventory_v35 = dict(
            self.snapshot_copy_inventory_v35
        )

        # v24 SGL-facing metadata.  These payloads are intentionally keyed by
        # integer block addresses and/or (src_addr, dst_addr) tuples so SGL can
        # consume them without object identity coupling.
        self.func.block_branch_custody = dict(self.block_branch_custody)
        self.func.edge_condition_truth = dict(self.edge_condition_truth)
        self.func.edge_truth = dict(self.edge_truth)
        self.func.edge_truth_version = self.edge_truth_version
        self.func.edge_truth_by_src = {
            k: list(v) for k, v in self.edge_truth_by_src.items()
        }
        self.func.edge_truth_by_dst = {
            k: list(v) for k, v in self.edge_truth_by_dst.items()
        }
        self.func.edge_truth_predicates = dict(self.edge_truth_predicates)
        self.func.edge_truth_profiles = dict(self.edge_truth_profiles)
        self.func.edge_truth_debug = list(self.edge_truth_debug)
        self.func.edge_truth_inventory_v38 = dict(
            self.edge_truth_inventory_v38
        )

        # v31 semantic multiway-dispatch handoff. Keep FunctionCFG's raw
        # `multiway_dispatch_facts` untouched and publish semantic enrichment
        # under distinct names. SGL consumes the same records through
        # `sgl_structuring_handoff["multiway_dispatch_facts"]`.
        self.func.semantic_multiway_dispatch_version = self.multiway_dispatch_version
        self.func.semantic_multiway_dispatch_facts = list(
            self.semantic_multiway_dispatch_facts
        )
        self.func.semantic_multiway_dispatch_by_block = dict(
            self.semantic_multiway_dispatch_by_block
        )
        self.func.semantic_multiway_dispatch_inventory = dict(
            self.semantic_multiway_dispatch_inventory
        )
        self.func.semantic_multiway_dispatch_events = list(
            self.semantic_multiway_dispatch_events
        )
        self.func.multiway_dispatch_semantics = list(
            self.semantic_multiway_dispatch_facts
        )

        self.func.induction_updates_by_block = {
            k: list(v) for k, v in self.induction_updates_by_block.items()
        }
        self.func.latch_update_facts = dict(self.latch_update_facts)
        self.func.block_ownership_facts = dict(self.block_ownership_facts)
        self.func.suspicious_successor_custody = list(self.suspicious_successor_custody)
        self.func.sgl_structuring_handoff = dict(self.sgl_structuring_handoff)

        self.func.sgl_condition_consumer_index = dict(self.sgl_condition_consumer_index)
        self.func.sgl_condition_dependency_sids = {
            k: set(v) for k, v in self.sgl_condition_dependency_sids.items()
        }
        self.func.sgl_condition_temp_refs = list(self.sgl_condition_temp_refs)

        self.func.semantic_debug = {
            "formula_node_count": len(self.var_nodes),
            "phi_node_count": len(self.phi_nodes),
            "phi_predecessor_linkage_version_v37": (
                self.phi_predecessor_linkage_version_v37
            ),
            "phi_predecessor_bindings_v37": len(
                self.phi_predecessor_bindings_v37
            ),
            "phi_transition_descriptions_v37": len(
                self.phi_transition_descriptions_v37
            ),
            "phi_predecessor_linkage_failures_v37": len(
                self.phi_predecessor_linkage_failures_v37
            ),
            "phi_predecessor_linkage_inventory_v37": dict(
                self.phi_predecessor_linkage_inventory_v37
            ),
            "condition_count": len(self.condition_vars),
            "return_count": len(self.return_vars),
            "call_count": len(self.call_nodes),
            "unresolved_input_count": len(self.unresolved_inputs),
            "induction_count": len(self.induction_nodes),
            "operand_projection_version": self.operand_projection_version,
            "operand_projection_contracts": len(self.operand_projection_contracts),
            "storage_projection_names": len(self.storage_projection_names),
            "sid_projection_names": len(self.sid_projection_names),
            "operand_projection_collisions": len(self.operand_projection_collisions),
            "operand_projection_inventory": dict(self.operand_projection_inventory),
            "operand_identity_evidence_v34": len(self.operand_identity_evidence_v34),
            "operand_identity_ambiguities_v34": len(self.operand_identity_ambiguities_v34),
            "operand_identity_failures_v34": len(self.operand_identity_failures_v34),
            "operand_identity_inventory_v34": dict(self.operand_identity_inventory_v34),
            "resolver_name_storage_collisions_v34": len(self.resolver_name_storage_collisions_v34),
            "snapshot_copy_version_v35": self.snapshot_copy_version_v35,
            "snapshot_copy_contracts_v35": len(self.snapshot_copy_contracts_v35),
            "snapshot_copy_events_v35": len(self.snapshot_copy_events_v35),
            "snapshot_copy_failures_v35": len(self.snapshot_copy_failures_v35),
            "snapshot_copy_inventory_v35": dict(self.snapshot_copy_inventory_v35),
            "sgl_condition_consumer_count": len(self.sgl_condition_consumers),
            "sgl_condition_temp_refs": list(self.sgl_condition_temp_refs),
            "block_branch_custody_count": len(self.block_branch_custody),
            "edge_condition_truth_count": len(self.edge_condition_truth),
            "edge_truth_version": self.edge_truth_version,
            "edge_truth_count": len(self.edge_truth),
            "edge_truth_by_src_count": len(self.edge_truth_by_src),
            "edge_truth_by_dst_count": len(self.edge_truth_by_dst),
            "edge_truth_predicate_count": len(self.edge_truth_predicates),
            "edge_truth_profile_count": len(self.edge_truth_profiles),
            "edge_truth_debug_count": len(self.edge_truth_debug),
            "edge_truth_inventory_v38": dict(self.edge_truth_inventory_v38),
            "semantic_multiway_dispatch_version": self.multiway_dispatch_version,
            "semantic_multiway_dispatch_count": len(
                self.semantic_multiway_dispatch_facts
            ),
            "semantic_multiway_dispatch_resolved": int(
                self.semantic_multiway_dispatch_inventory.get("resolved", 0) or 0
            ),
            "semantic_multiway_dispatch_unresolved": int(
                self.semantic_multiway_dispatch_inventory.get("unresolved", 0) or 0
            ),
            "semantic_multiway_dispatch_event_count": len(
                self.semantic_multiway_dispatch_events
            ),
            "induction_update_block_count": len(self.induction_updates_by_block),
            "latch_update_loop_count": len(self.latch_update_facts),
            "block_ownership_fact_count": len(self.block_ownership_facts),
            "suspicious_successor_custody_count": len(self.suspicious_successor_custody),
            "events": list(self.semantic_events),
        }

    # ---------------------------------------------------------
    # NODE CREATION
    # ---------------------------------------------------------

    def build_nodes(self):
        """
        Build one FormulaNode for every SSA-producing ordinary P-code op.

        Control ops are normally in block.terminator, not block.ops.
        """

        for block in getattr(self.func, "blocks", []) or []:

            block_addr = _block_addr(block)
            self.block_formula_nodes.setdefault(block_addr, [])

            for op in getattr(block, "ops", []) or []:

                out = getattr(op, "output", None)

                if out is None:
                    continue

                sid = getattr(out, "ssa_id", None)

                if sid is None:
                    continue

                node = FormulaNode(out, op, block)

                # Preserve only the latest def for a given SSA id in var_nodes,
                # but record collisions because they indicate lifter trouble.
                if sid in self.var_nodes and self.var_nodes[sid] is not node:
                    self.semantic_events.append({
                        "kind": "duplicate_def_sid",
                        "sid": sid,
                        "old_block": self.var_nodes[sid].block_addr_hex,
                        "new_block": node.block_addr_hex,
                    })

                self.var_nodes[sid] = node
                self.defs_by_sid[sid] = node
                self.block_formula_nodes.setdefault(block_addr, []).append(node)

    # ---------------------------------------------------------
    # INPUT LINKING
    # ---------------------------------------------------------

    def link_inputs(self):
        """
        Resolve operation inputs into FormulaNodes when possible.

        Constants remain PALVariable objects because they carry literal values.
        Unresolved variables remain PALVariable objects.
        """

        for node in self.var_nodes.values():

            op = node.op
            resolved = []

            for inp in getattr(op, "inputs", []) or []:
                resolved.append(self.resolve_input(inp))

            node.inputs = resolved

    def resolve_input(self, inp):
        """
        Convert PALVariable input to FormulaNode if it has a defining node.

        Leaves constants and unresolved variables untouched.
        """

        if inp is None:
            return None

        # If already a FormulaNode-like object, keep it.
        if hasattr(inp, "var") and hasattr(inp, "opcode"):
            return inp

        # Constants should remain variables/literals.
        if getattr(inp, "is_constant", False):
            return inp

        sid = getattr(inp, "ssa_id", None)

        if sid is not None and sid in self.var_nodes:
            return self.var_nodes[sid]

        if sid is not None:
            self.unresolved_inputs.append(inp)

        return inp

    # ---------------------------------------------------------
    # USE INDEXES
    # ---------------------------------------------------------

    def build_use_indexes(self):

        self.uses_by_sid = {}
        self.uses_by_storage_key = {}

        for node in self.var_nodes.values():

            for inp in node.inputs:

                inp_var = _unwrap_var(inp)
                sid = getattr(inp_var, "ssa_id", None)

                if sid is not None:
                    self.uses_by_sid.setdefault(sid, []).append(node)
                    node.use_sids.append(sid)

                    def_node = self.var_nodes.get(sid)
                    if def_node is not None:
                        def_node.users.append(node)

                key = _storage_key(inp_var)
                if key is not None and any(x is not None for x in key):
                    self.uses_by_storage_key.setdefault(key, []).append(node)

    # ---------------------------------------------------------
    # PHI CONSTRUCTION
    # ---------------------------------------------------------

    def build_phi_nodes(self):
        """
        Build explicit PhiNode wrappers for MULTIEQUAL FormulaNodes.
        """

        self.phi_nodes = []

        for node in self.var_nodes.values():

            if node.opcode != "MULTIEQUAL":
                continue

            node.is_phi = True
            node.semantic_role = "phi_merge"

            phi = PhiNode(
                output=node.var,
                formula_node=node,
                block=node.block
            )

            phi.raw_inputs = list(getattr(node.op, "inputs", []) or [])

            for inp in node.inputs:
                phi.inputs.append(inp)

                inv = _unwrap_var(inp)
                phi.input_sids.append(getattr(inv, "ssa_id", None))
                phi.input_storage_keys.append(_storage_key(inv))

                if getattr(inv, "is_constant", False):
                    phi.has_constant_source = True

                inp_node = inp if hasattr(inp, "opcode") else self.get_node(inp)
                if inp_node is not None and getattr(inp_node, "opcode", None) in ("CALL", "CALLIND"):
                    phi.has_call_source = True

            out_key = phi.output_storage_key
            phi.is_storage_phi = out_key is not None and any(k is not None for k in out_key)

            # Identity PHI means all non-None sources already represent same
            # logical storage as output. PHIfolder may collapse these.
            non_null_keys = [
                k for k in phi.input_storage_keys
                if k is not None and any(x is not None for x in k)
            ]
            if phi.is_storage_phi and non_null_keys:
                phi.is_identity_phi = all(k == out_key for k in non_null_keys)

            # Backrefs.
            try:
                node.phi_node = phi
                phi.output.phi_node = phi
                phi.output.is_phi_target = True
            except Exception:
                pass

            self.phi_nodes.append(phi)


    # ---------------------------------------------------------
    # v37 BOHDI-EMPEROR PHI PREDECESSOR / EDGE LINKAGE
    # ---------------------------------------------------------

    @staticmethod
    def _phi_edge_addr_token_v37(value):
        if isinstance(value, int):
            return "0x%x" % value
        return str(value)

    def _phi_edge_key_v37(self, src_addr, dst_addr):
        return "cfg-edge-v1:%s->%s" % (
            self._phi_edge_addr_token_v37(src_addr),
            self._phi_edge_addr_token_v37(dst_addr),
        )

    def _phi_sid_text_v37(self, value):
        value = _unwrap_var(value)
        sid = getattr(value, "ssa_id", None) if value is not None else None
        return str(sid) if sid is not None else None

    def _phi_source_group_key_v37(self, value):
        var = _unwrap_var(value)
        sid = self._phi_sid_text_v37(var)
        if sid is not None:
            return ("sid", sid)
        if var is None:
            return ("none", "None")
        if getattr(var, "is_constant", False):
            return (
                "constant",
                repr(_const_value(var)),
                int(getattr(var, "size", 0) or 0),
            )
        return (
            "unresolved",
            str(getattr(var, "space", None)),
            repr(getattr(var, "offset", None)),
            int(getattr(var, "size", 0) or 0),
            str(getattr(var, "name", None)),
        )

    def _build_phi_cfg_edge_identity_index_v37(self):
        """Consume FunctionCFG v23 frozen edge facts without rewriting them."""
        index = {}
        cfg = getattr(self.func, "cfg", None)

        fact_sources = [
            getattr(self.func, "cfg_edge_identity_facts", None),
            getattr(cfg, "edge_identity_facts", None) if cfg is not None else None,
        ]
        for facts in fact_sources:
            for original in list(facts or []):
                rec = dict(original or {})
                edge_id = list(rec.get("edge_id", []) or [])
                if len(edge_id) != 2:
                    continue
                pair = (edge_id[0], edge_id[1])
                existing = index.get(pair)
                if existing is not None and existing != rec:
                    self.phi_predecessor_linkage_warnings_v37.append({
                        "kind": "phi_cfg_edge_identity_duplicate_fact_v37",
                        "edge_id": list(pair),
                        "reason": "multiple FunctionCFG edge fact records differ",
                    })
                    continue
                index[pair] = rec

        # Compatibility lookup through live edge objects.  A record without the
        # v23 frozen marker is exposed as non-authoritative and is never allowed
        # to masquerade as FunctionCFG truth.
        if cfg is not None:
            for node in self._cfg_nodes_v24():
                src = self._cfg_addr_v24(node)
                for edge in self._edge_list_v24(node):
                    dst = self._cfg_addr_v24(getattr(edge, "dst", None))
                    if src is None or dst is None:
                        continue
                    pair = (src, dst)
                    if pair in index:
                        continue
                    edge_id = getattr(edge, "edge_id", None)
                    frozen = bool(getattr(edge, "edge_identity_frozen", False))
                    if (
                        isinstance(edge_id, (tuple, list))
                        and len(edge_id) == 2
                        and tuple(edge_id) == pair
                    ):
                        frozen = frozen or (
                            getattr(edge, "edge_id_schema", None)
                            == "cfg_edge_identity_v1"
                        )
                    index[pair] = {
                        "kind": "cfg_edge_identity_live_compat_v37",
                        "version": getattr(cfg, "cfg_version", None),
                        "id_schema": (
                            getattr(edge, "edge_id_schema", None)
                            or "cfg_edge_identity_v1"
                        ),
                        "edge_id": [src, dst],
                        "edge_key": (
                            getattr(edge, "edge_key", None)
                            or self._phi_edge_key_v37(src, dst)
                        ),
                        "src_addr": src,
                        "dst_addr": dst,
                        "role": getattr(edge, "role", None),
                        "raw_type": getattr(
                            edge, "raw_type", getattr(edge, "type", None)
                        ),
                        "branch_role": getattr(
                            edge, "direct_join_branch_role", None
                        ),
                        "direct_to_join": bool(
                            getattr(edge, "direct_to_join", False)
                        ),
                        "direct_join_owner_kind": getattr(
                            edge, "direct_join_owner_kind", None
                        ),
                        "direct_join_empty_arm_candidate": bool(
                            getattr(
                                edge,
                                "direct_join_empty_arm_candidate",
                                False,
                            )
                        ),
                        "direct_join_status": getattr(
                            edge, "direct_join_status", None
                        ),
                        "edge_identity_frozen": frozen,
                        "authority": (
                            "FunctionCFG_live_edge_v23"
                            if frozen else
                            "legacy_live_CFG_edge_compatibility_only"
                        ),
                    }

        self._phi_cfg_edge_identity_by_pair_v37 = index
        return index

    def _cfg_edge_identity_record_v37(self, edge, src_addr, dst_addr):
        pair = (src_addr, dst_addr)
        rec = self._phi_cfg_edge_identity_by_pair_v37.get(pair)
        if isinstance(rec, dict):
            out = dict(rec)
        else:
            out = {
                "kind": "cfg_edge_identity_missing_v37",
                "id_schema": "cfg_edge_identity_v1",
                "edge_id": [src_addr, dst_addr],
                "edge_key": self._phi_edge_key_v37(src_addr, dst_addr),
                "src_addr": src_addr,
                "dst_addr": dst_addr,
                "edge_identity_frozen": False,
                "direct_to_join": bool(
                    getattr(edge, "direct_to_join", False)
                ) if edge is not None else False,
                "direct_join_owner_kind": getattr(
                    edge, "direct_join_owner_kind", None
                ) if edge is not None else None,
                "direct_join_empty_arm_candidate": bool(
                    getattr(
                        edge,
                        "direct_join_empty_arm_candidate",
                        False,
                    )
                ) if edge is not None else False,
                "authority": "semantic_graph_missing_FunctionCFG_v23_fact",
            }
        if "edge_identity_frozen" not in out:
            out["edge_identity_frozen"] = bool(
                out.get("id_schema") == "cfg_edge_identity_v1"
                and str(out.get("kind") or "").startswith(
                    "cfg_edge_identity_fact"
                )
            )
        return out

    def _phi_source_definition_v37(self, value):
        node = (
            value
            if hasattr(value, "opcode") and hasattr(value, "var")
            else self.get_node(value)
        )
        var = _unwrap_var(value)
        if node is not None:
            return node, getattr(node, "block_addr", None)
        block = getattr(var, "block_region", None) if var is not None else None
        return None, _block_addr(block) if block is not None else None

    def _phi_reaches_predecessor_v37(
        self, start_node, predecessor_node, join_node, limit=4096
    ):
        """Test definition-to-predecessor reachability without crossing join."""
        if start_node is None or predecessor_node is None:
            return False
        if start_node is predecessor_node:
            return True
        seen = set()
        work = [start_node]
        steps = 0
        while work and steps < limit:
            node = work.pop()
            steps += 1
            if node is None or node in seen or node is join_node:
                continue
            seen.add(node)
            for succ in self._successor_nodes_v24(node):
                if succ is predecessor_node:
                    return True
                if succ is not join_node and succ not in seen:
                    work.append(succ)
        return False

    def _phi_candidate_predecessors_v37(
        self, source_value, predecessor_nodes, join_node
    ):
        source_node, def_block = self._phi_source_definition_v37(source_value)
        predecessor_by_addr = {
            self._cfg_addr_v24(node): node
            for node in predecessor_nodes
            if self._cfg_addr_v24(node) is not None
        }
        exact = set()
        reachable = set()
        evidence = []

        if def_block is not None:
            start = self._multiway_cfg_node_v30(def_block)
            if def_block in predecessor_by_addr:
                exact.add(def_block)
                reachable.add(def_block)
                evidence.append({
                    "kind": "exact_defining_block_predecessor",
                    "defining_block": def_block,
                    "predecessor": def_block,
                })
            for pred_addr, pred_node in predecessor_by_addr.items():
                if self._phi_reaches_predecessor_v37(
                    start, pred_node, join_node
                ):
                    reachable.add(pred_addr)
            evidence.append({
                "kind": "definition_CFG_reachability",
                "defining_block": def_block,
                "reachable_predecessors": sorted(reachable),
            })
        else:
            # Entry values, constants, and unresolved live-ins can legitimately
            # feed any incoming edge.  They remain broad candidates until the
            # global capacity/matching proof removes ambiguity.
            reachable = set(predecessor_by_addr)
            evidence.append({
                "kind": "source_without_local_definition",
                "candidate_predecessors": sorted(reachable),
                "authority": "set_matching_only_not_input_order",
            })

        return {
            "source_node": source_node,
            "defining_block": def_block,
            "exact_predecessors": exact,
            "candidate_predecessors": reachable,
            "evidence": evidence,
        }

    def _phi_feasible_assignment_v37(
        self, predecessor_addrs, groups, forced=None
    ):
        """Capacity-constrained bipartite matching over edge and source groups."""
        forced = dict(forced or {})
        capacity = {
            key: int(rec.get("occurrence_count", 0) or 0)
            for key, rec in groups.items()
        }
        assigned = {}
        for pred, group_key in forced.items():
            rec = groups.get(group_key)
            if rec is None:
                return None
            if pred not in set(rec.get("candidate_predecessors", set()) or set()):
                return None
            capacity[group_key] -= 1
            if capacity[group_key] < 0:
                return None
            assigned[pred] = group_key

        remaining_edges = [
            pred for pred in predecessor_addrs if pred not in assigned
        ]
        slots = []
        for group_key, count in capacity.items():
            for ordinal in range(max(int(count), 0)):
                slots.append((group_key, ordinal))

        if len(slots) != len(remaining_edges):
            return None

        slot_owner = {}
        edge_owner = {}

        def visit(edge_addr, seen_slots):
            candidate_groups = [
                key for key, rec in groups.items()
                if edge_addr in set(
                    rec.get("candidate_predecessors", set()) or set()
                )
                and capacity.get(key, 0) > 0
            ]
            candidate_groups.sort(key=lambda key: repr(key))
            for slot in slots:
                group_key = slot[0]
                if group_key not in candidate_groups or slot in seen_slots:
                    continue
                seen_slots.add(slot)
                prior_edge = slot_owner.get(slot)
                if prior_edge is None or visit(prior_edge, seen_slots):
                    slot_owner[slot] = edge_addr
                    edge_owner[edge_addr] = group_key
                    return True
            return False

        edge_order = sorted(
            remaining_edges,
            key=lambda pred: (
                sum(
                    1 for rec in groups.values()
                    if pred in set(
                        rec.get("candidate_predecessors", set()) or set()
                    )
                ),
                pred,
            ),
        )
        for edge_addr in edge_order:
            if not visit(edge_addr, set()):
                return None

        out = dict(assigned)
        out.update(edge_owner)
        return out

    def _phi_transition_reason_v37(self, group, predecessor):
        exact = set(group.get("exact_predecessors", set()) or set())
        candidates = set(group.get("candidate_predecessors", set()) or set())
        if predecessor in exact:
            return "exact_defining_block_predecessor"
        if len(candidates) == 1:
            return "unique_CFG_reaching_predecessor"
        return "unique_capacity_constrained_edge_matching"

    def _link_one_phi_predecessors_v37(self, phi):
        join_addr = getattr(phi, "block_addr", None)
        join_node = self._multiway_cfg_node_v30(join_addr)
        target_sid = str(getattr(phi, "output_sid", None))
        predecessor_nodes = (
            self._predecessor_nodes_v24(join_node)
            if join_node is not None else []
        )
        predecessor_nodes = [
            node for node in predecessor_nodes
            if self._cfg_addr_v24(node) is not None
        ]
        predecessor_addrs = sorted({
            self._cfg_addr_v24(node) for node in predecessor_nodes
        })

        groups = {}
        for index, source in enumerate(list(getattr(phi, "inputs", []) or [])):
            key = self._phi_source_group_key_v37(source)
            group = groups.setdefault(key, {
                "group_key": key,
                "source_value": source,
                "source_sid": self._phi_sid_text_v37(source),
                "source_name": getattr(_unwrap_var(source), "name", None),
                "input_indices": [],
                "occurrence_count": 0,
                "candidate_predecessors": set(),
                "exact_predecessors": set(),
                "defining_block": None,
                "evidence": [],
            })
            group["input_indices"].append(index)
            group["occurrence_count"] += 1

        for group in groups.values():
            proof = self._phi_candidate_predecessors_v37(
                group.get("source_value"), predecessor_nodes, join_node
            )
            group["candidate_predecessors"] = set(
                proof.get("candidate_predecessors", set()) or set()
            )
            group["exact_predecessors"] = set(
                proof.get("exact_predecessors", set()) or set()
            )
            group["defining_block"] = proof.get("defining_block")
            group["evidence"] = list(proof.get("evidence", []) or [])

        total_occurrences = sum(
            int(group.get("occurrence_count", 0) or 0)
            for group in groups.values()
        )
        count_match = total_occurrences == len(predecessor_addrs)
        base_assignment = (
            self._phi_feasible_assignment_v37(
                predecessor_addrs, groups
            )
            if count_match else None
        )

        fixed_by_edge = {}
        possible_by_edge = {}
        if base_assignment is not None:
            for pred in predecessor_addrs:
                possible = []
                for group_key, group in groups.items():
                    if pred not in set(
                        group.get("candidate_predecessors", set()) or set()
                    ):
                        continue
                    if self._phi_feasible_assignment_v37(
                        predecessor_addrs,
                        groups,
                        forced={pred: group_key},
                    ) is not None:
                        possible.append(group_key)
                possible_by_edge[pred] = possible
                if len(possible) == 1:
                    fixed_by_edge[pred] = possible[0]

        bindings = []
        unresolved_edges = []
        for pred in predecessor_addrs:
            group_key = fixed_by_edge.get(pred)
            if group_key is None:
                unresolved_edges.append({
                    "edge_id": [pred, join_addr],
                    "pred_addr": pred,
                    "join_addr": join_addr,
                    "possible_source_sids": [
                        groups[key].get("source_sid")
                        for key in possible_by_edge.get(pred, [])
                    ],
                    "reason": (
                        "no_feasible_complete_phi_matching"
                        if base_assignment is None else
                        "multiple_source_groups_remain_feasible"
                    ),
                })
                continue

            group = groups[group_key]
            edge = self._edge_between_nodes_v24(
                self._multiway_cfg_node_v30(pred), join_node
            )
            edge_rec = self._cfg_edge_identity_record_v37(
                edge, pred, join_addr
            )
            source_sid = group.get("source_sid")
            reason = self._phi_transition_reason_v37(group, pred)
            transition_id = [
                join_addr,
                pred,
                target_sid,
                source_sid,
                reason,
            ]
            rec = {
                "kind": "semantic_phi_predecessor_binding_v37",
                "version": self.phi_predecessor_linkage_version_v37,
                "id_schema": "semantic_phi_predecessor_transition_v1",
                "transition_id": transition_id,
                "edge_id_schema": edge_rec.get(
                    "id_schema", "cfg_edge_identity_v1"
                ),
                "edge_id": list(edge_rec.get("edge_id", [pred, join_addr])),
                "edge_key": (
                    edge_rec.get("edge_key")
                    or self._phi_edge_key_v37(pred, join_addr)
                ),
                "edge_identity_frozen": bool(
                    edge_rec.get("edge_identity_frozen", False)
                ),
                "pred_addr": pred,
                "join_addr": join_addr,
                "target_sid": target_sid,
                "source_sid": source_sid,
                "reason": reason,
                "authority": (
                    "FunctionCFG_edge_identity_plus_definition_CFG_"
                    "reachability_plus_capacity_matching"
                ),
                "defining_block": group.get("defining_block"),
                "source_occurrence_count": group.get("occurrence_count"),
                "source_input_indices_diagnostic_only": list(
                    group.get("input_indices", []) or []
                ),
                "candidate_predecessors": sorted(
                    group.get("candidate_predecessors", set()) or set()
                ),
                "binding_evidence": list(group.get("evidence", []) or []),
                "input_order_used": False,
                "successor_order_used": False,
                "target_presentation_name": getattr(phi, "output_name", None),
                "source_presentation_name": group.get("source_name"),
                "direct_to_join": bool(edge_rec.get("direct_to_join", False)),
                "direct_join_owner_kind": edge_rec.get(
                    "direct_join_owner_kind"
                ),
                "direct_join_empty_arm_candidate": bool(
                    edge_rec.get(
                        "direct_join_empty_arm_candidate", False
                    )
                ),
                "status": "resolved",
            }
            bindings.append(rec)

        if not predecessor_addrs:
            status = "unresolved_no_join_predecessors"
        elif len(bindings) == len(predecessor_addrs) and not unresolved_edges:
            status = "resolved"
        elif bindings:
            status = "partially_resolved"
        else:
            status = "unresolved"

        group_debug = []
        for group in groups.values():
            group_debug.append({
                "source_sid": group.get("source_sid"),
                "source_name": group.get("source_name"),
                "occurrence_count": group.get("occurrence_count"),
                "input_indices_diagnostic_only": list(
                    group.get("input_indices", []) or []
                ),
                "defining_block": group.get("defining_block"),
                "exact_predecessors": sorted(
                    group.get("exact_predecessors", set()) or set()
                ),
                "candidate_predecessors": sorted(
                    group.get("candidate_predecessors", set()) or set()
                ),
                "evidence": list(group.get("evidence", []) or []),
            })

        contract = {
            "kind": "semantic_phi_predecessor_linkage_v37",
            "version": self.phi_predecessor_linkage_version_v37,
            "join_addr": join_addr,
            "target_sid": target_sid,
            "target_name": getattr(phi, "output_name", None),
            "status": status,
            "predecessor_addrs": predecessor_addrs,
            "predecessor_count": len(predecessor_addrs),
            "source_occurrences": total_occurrences,
            "source_predecessor_count_match": count_match,
            "complete_matching_exists": base_assignment is not None,
            "bindings": bindings,
            "unresolved_edges": unresolved_edges,
            "source_groups": group_debug,
            "resolved_bindings": len(bindings),
            "unresolved_bindings": len(unresolved_edges),
            "input_order_used_for_predecessor_mapping": False,
            "successor_order_used_for_predecessor_mapping": False,
            "authority": (
                "FunctionCFG_v23_edge_identity_plus_set_based_"
                "definition_reachability_matching"
            ),
        }

        try:
            phi.predecessor_linkage_contract_v37 = contract
            phi.predecessor_linkage_status_v37 = status
            phi.predecessor_bindings_v37 = list(bindings)
            phi.predecessor_unresolved_edges_v37 = list(unresolved_edges)
            if getattr(phi, "formula_node", None) is not None:
                phi.formula_node.phi_predecessor_linkage_v37 = contract
            if getattr(phi, "output", None) is not None:
                phi.output.phi_predecessor_linkage_v37 = contract
        except Exception:
            pass

        return contract

    def build_phi_predecessor_linkage_v37(self):
        """Bind every provable PHI source to an exact incoming CFG edge.

        No binding is inferred from MULTIEQUAL input ordinal, CFG predecessor
        order, branch successor order, target presentation names, or storage
        naming.  Ambiguous sources remain explicit unresolved records.
        """
        self.phi_predecessor_bindings_v37 = []
        self.phi_predecessor_bindings_by_target_v37 = {}
        self.phi_predecessor_bindings_by_edge_v37 = {}
        self.phi_transition_descriptions_v37 = []
        self.phi_transition_by_edge_v37 = {}
        self.phi_predecessor_linkage_events_v37 = []
        self.phi_predecessor_linkage_warnings_v37 = []
        self.phi_predecessor_linkage_failures_v37 = []
        self.phi_predecessor_linkage_inventory_v37 = {}
        self._build_phi_cfg_edge_identity_index_v37()

        contracts = []
        for phi in list(self.phi_nodes or []):
            contract = self._link_one_phi_predecessors_v37(phi)
            contracts.append(contract)
            for rec in list(contract.get("bindings", []) or []):
                binding = dict(rec)
                self.phi_predecessor_bindings_v37.append(binding)
                target = str(binding.get("target_sid"))
                edge_pair = (
                    binding.get("pred_addr"),
                    binding.get("join_addr"),
                )
                self.phi_predecessor_bindings_by_target_v37.setdefault(
                    target, []
                ).append(binding)
                self.phi_predecessor_bindings_by_edge_v37.setdefault(
                    edge_pair, []
                ).append(binding)

                transition = {
                    "kind": "semantic_phi_transition_description_v37",
                    "version": self.phi_predecessor_linkage_version_v37,
                    "id_schema": binding.get("id_schema"),
                    "transition_id": list(
                        binding.get("transition_id", []) or []
                    ),
                    "edge_id_schema": binding.get("edge_id_schema"),
                    "edge_id": list(binding.get("edge_id", []) or []),
                    "edge_key": binding.get("edge_key"),
                    "pred_addr": binding.get("pred_addr"),
                    "join_addr": binding.get("join_addr"),
                    "target_sid": binding.get("target_sid"),
                    "source_sid": binding.get("source_sid"),
                    "reason": binding.get("reason"),
                    "authority": binding.get("authority"),
                    "edge_identity_frozen": binding.get(
                        "edge_identity_frozen"
                    ),
                    "direct_to_join": binding.get("direct_to_join"),
                    "direct_join_owner_kind": binding.get(
                        "direct_join_owner_kind"
                    ),
                    "direct_join_empty_arm_candidate": binding.get(
                        "direct_join_empty_arm_candidate"
                    ),
                    "input_order_used": False,
                    "successor_order_used": False,
                }
                self.phi_transition_descriptions_v37.append(transition)
                self.phi_transition_by_edge_v37.setdefault(
                    edge_pair, []
                ).append(transition)

            if contract.get("status") != "resolved":
                warning = {
                    "kind": "phi_predecessor_linkage_unresolved_v37",
                    "join_addr": contract.get("join_addr"),
                    "target_sid": contract.get("target_sid"),
                    "status": contract.get("status"),
                    "unresolved_edges": list(
                        contract.get("unresolved_edges", []) or []
                    ),
                    "source_predecessor_count_match": contract.get(
                        "source_predecessor_count_match"
                    ),
                    "complete_matching_exists": contract.get(
                        "complete_matching_exists"
                    ),
                    "input_order_fallback_used": False,
                }
                self.phi_predecessor_linkage_warnings_v37.append(warning)

            self.phi_predecessor_linkage_events_v37.append({
                "kind": "phi_predecessor_linkage_compiled_v37",
                "join_addr": contract.get("join_addr"),
                "target_sid": contract.get("target_sid"),
                "status": contract.get("status"),
                "predecessors": contract.get("predecessor_count"),
                "resolved_bindings": contract.get("resolved_bindings"),
                "unresolved_bindings": contract.get("unresolved_bindings"),
                "input_order_used": False,
                "successor_order_used": False,
            })

        audit = self._audit_phi_predecessor_linkage_v37()
        resolved_contracts = sum(
            1 for rec in contracts if rec.get("status") == "resolved"
        )
        partial_contracts = sum(
            1 for rec in contracts
            if rec.get("status") == "partially_resolved"
        )
        unresolved_contracts = len(contracts) - resolved_contracts - partial_contracts
        frozen_edges = sum(
            1 for rec in self.phi_predecessor_bindings_v37
            if rec.get("edge_identity_frozen")
        )
        self.phi_predecessor_linkage_inventory_v37 = {
            "kind": "phi_predecessor_linkage_inventory_v37",
            "version": self.phi_predecessor_linkage_version_v37,
            "edge_id_schema": "cfg_edge_identity_v1",
            "transition_id_schema": "semantic_phi_predecessor_transition_v1",
            "phis": len(contracts),
            "resolved_phis": resolved_contracts,
            "partially_resolved_phis": partial_contracts,
            "unresolved_phis": unresolved_contracts,
            "resolved_bindings": len(self.phi_predecessor_bindings_v37),
            "transition_descriptions": len(
                self.phi_transition_descriptions_v37
            ),
            "edge_buckets": len(self.phi_transition_by_edge_v37),
            "bindings_with_frozen_CFG_edge_identity": frozen_edges,
            "bindings_without_frozen_CFG_edge_identity": (
                len(self.phi_predecessor_bindings_v37) - frozen_edges
            ),
            "warnings": len(self.phi_predecessor_linkage_warnings_v37),
            "failures": len(self.phi_predecessor_linkage_failures_v37),
            "input_order_used_for_predecessor_mapping": False,
            "successor_order_used_for_predecessor_mapping": False,
            "presentation_names_used_as_identity": False,
            "audit": audit,
            "rule": (
                "bind_PHI_sources_to_FunctionCFG_edge_identity_by_definition_"
                "block_reachability_and_capacity_matching_only"
            ),
        }
        self.semantic_events.extend(
            list(self.phi_predecessor_linkage_events_v37)
        )
        self.semantic_events.extend(
            list(self.phi_predecessor_linkage_warnings_v37)
        )
        self.semantic_events.append(
            dict(self.phi_predecessor_linkage_inventory_v37)
        )
        return list(self.phi_predecessor_bindings_v37)

    def _audit_phi_predecessor_linkage_v37(self):
        phi_targets = {
            str(getattr(phi, "output_sid", None)): {
                self._phi_sid_text_v37(inp)
                for inp in list(getattr(phi, "inputs", []) or [])
            }
            for phi in list(self.phi_nodes or [])
        }
        failures = []
        seen = {}
        for rec in list(self.phi_predecessor_bindings_v37 or []):
            pred = rec.get("pred_addr")
            join = rec.get("join_addr")
            target = str(rec.get("target_sid"))
            source = rec.get("source_sid")
            edge_id = list(rec.get("edge_id", []) or [])

            if edge_id != [pred, join]:
                failures.append({
                    "kind": "phi_predecessor_edge_identity_mismatch_v37",
                    "target_sid": target,
                    "source_sid": source,
                    "edge_id": edge_id,
                    "expected_edge_id": [pred, join],
                })
            if target not in phi_targets:
                failures.append({
                    "kind": "phi_predecessor_target_not_PHI_output_v37",
                    "target_sid": target,
                })
            elif source not in phi_targets[target]:
                failures.append({
                    "kind": "phi_predecessor_source_not_PHI_input_v37",
                    "target_sid": target,
                    "source_sid": source,
                })
            if rec.get("input_order_used") or rec.get(
                "successor_order_used"
            ):
                failures.append({
                    "kind": "phi_predecessor_order_authority_violation_v37",
                    "target_sid": target,
                    "source_sid": source,
                    "edge_id": edge_id,
                })

            owner_key = (pred, join, target)
            prior = seen.get(owner_key)
            if prior is not None and prior != source:
                failures.append({
                    "kind": "phi_predecessor_conflicting_edge_owner_v37",
                    "edge_id": [pred, join],
                    "target_sid": target,
                    "first_source_sid": prior,
                    "second_source_sid": source,
                })
            else:
                seen[owner_key] = source

            if not rec.get("edge_identity_frozen"):
                self.phi_predecessor_linkage_warnings_v37.append({
                    "kind": "phi_predecessor_unfrozen_CFG_edge_identity_v37",
                    "edge_id": [pred, join],
                    "target_sid": target,
                    "source_sid": source,
                    "reason": (
                        "FunctionCFG_v23_frozen_edge_fact_not_visible; "
                        "binding remains compatibility metadata"
                    ),
                })

        self.phi_predecessor_linkage_failures_v37 = failures
        audit = {
            "kind": (
                "phi_predecessor_linkage_verified_v37"
                if not failures else
                "phi_predecessor_linkage_failed_v37"
            ),
            "bindings_checked": len(self.phi_predecessor_bindings_v37),
            "unique_edge_target_owners": len(seen),
            "failures": list(failures),
            "input_order_used": False,
            "successor_order_used": False,
        }
        self.phi_predecessor_linkage_events_v37.append(audit)
        if failures:
            first = failures[0]
            raise RuntimeError(
                "PALSemanticGraphBuilder v37 PHI predecessor linkage failed: %s"
                % first.get("kind")
            )
        return audit

    # ---------------------------------------------------------
    # TERMINATOR-AWARE CONDITION MARKING
    # ---------------------------------------------------------

    def mark_condition_nodes(self):
        """
        Mark variables used as CBRANCH conditions.

        Important:
            The lifter stores CBRANCH in block.terminator, not block.ops.
        """

        self.condition_vars = []
        self.condition_nodes = []
        self.block_condition_nodes = {}

        for block in getattr(self.func, "blocks", []) or []:

            term = getattr(block, "terminator", None)

            if term is None:
                continue

            if getattr(term, "opcode", None) != "CBRANCH":
                continue

            cond_var = getattr(term, "condition", None)

            # Fallback for older terminator format.
            if cond_var is None:
                inputs = getattr(term, "inputs", []) or []
                if len(inputs) >= 2:
                    cond_var = inputs[1]

            if cond_var is None:
                continue

            self.condition_vars.append(cond_var)

            sid = getattr(cond_var, "ssa_id", None)
            node = self.var_nodes.get(sid) if sid is not None else None

            if node is not None:
                node.is_condition = True
                node.semantic_role = "branch_condition"
                node.condition_block = block
                node.condition_edge_info = self._edge_info_for_block(block)

                self.condition_nodes.append(node)
                self.block_condition_nodes[_block_addr(block)] = node

                try:
                    cond_var.is_condition = True
                    cond_var.semantic_role = "branch_condition"
                    cond_var.block_region = block
                    cond_var.condition_block = block
                except Exception:
                    pass

    def _edge_info_for_block(self, block):
        """
        Capture CFG/raw-edge branch custody for a condition node, when present.
        """

        info = []

        cfg_node = None
        try:
            cfg = getattr(self.func, "cfg", None)
            if cfg is not None:
                nodes = getattr(cfg, "nodes", None)
                if isinstance(nodes, dict):
                    cfg_node = nodes.get(_block_addr(block))
        except Exception:
            cfg_node = None

        if cfg_node is None:
            cfg_node = getattr(block, "cfg_node", None)

        for e in list(getattr(cfg_node, "out_edges", []) or []):
            dst = getattr(e, "dst", None)
            info.append({
                "dst": _safe_hex(getattr(dst, "addr", None)),
                "raw_type": getattr(e, "raw_type", None),
                "role": getattr(e, "role", None),
                "explicit_target": bool(getattr(e, "explicit_target", False) or getattr(e, "is_explicit_target", False)),
                "fallthrough": bool(getattr(e, "fallthrough", False) or getattr(e, "is_fallthrough", False)),
                "backedge": bool(getattr(e, "is_backedge", False) or getattr(e, "backedge", False)),
                "loop_exit": bool(getattr(e, "is_loop_exit", False) or getattr(e, "loop_exit", False)),
            })

        return info

    # ---------------------------------------------------------
    # TERMINATOR-AWARE RETURN MARKING
    # ---------------------------------------------------------

    def mark_return_values(self):
        """
        Record variables returned by RETURN terminators.
        """

        self.return_vars = []

        for block in getattr(self.func, "blocks", []) or []:

            term = getattr(block, "terminator", None)

            if term is None:
                continue

            if getattr(term, "opcode", None) != "RETURN":
                continue

            inputs = getattr(term, "inputs", []) or []

            if not inputs:
                continue

            # Ghidra RETURN often carries address/space in inputs[0],
            # return value in the last input. Using last input is robust.
            ret_var = inputs[-1]

            if ret_var is None:
                continue

            self.return_vars.append(ret_var)

            sid = getattr(ret_var, "ssa_id", None)
            node = self.var_nodes.get(sid) if sid is not None else None

            if node is not None:
                node.is_return_value = True
                node.return_block = block

                if node.semantic_role is None:
                    node.semantic_role = "return_value"

                try:
                    ret_var.is_return_value = True
                    ret_var.semantic_role = "return_value"
                    ret_var.block_region = block
                except Exception:
                    pass

    # ---------------------------------------------------------
    # CALL / CLASSIFICATION MARKING
    # ---------------------------------------------------------

    def mark_call_nodes(self):
        """
        Mark FormulaNodes produced by CALL/CALLIND operations.
        """

        self.call_nodes = []

        for node in self.var_nodes.values():

            if node.opcode not in ("CALL", "CALLIND"):
                continue

            node.is_call = True
            node.semantic_role = "call_result"
            self.call_nodes.append(node)

            try:
                node.var.semantic_role = "call_result"
                node.var.is_call_result = True
            except Exception:
                pass

            # The first input is usually the call target.
            if node.inputs:
                target = node.inputs[0]
                target_var = _unwrap_var(target)

                node.call_target = target_var
                node.call_target_name = getattr(target_var, "name", None) or getattr(target_var, "symbol", None)

                try:
                    target_var.is_function = True
                    target_var.semantic_role = "call_target"
                except Exception:
                    pass

    def mark_classification_nodes(self):

        self.compare_nodes = []
        self.copy_nodes = []
        self.width_cast_nodes = []

        for node in self.var_nodes.values():

            if node.is_compare:
                self.compare_nodes.append(node)
                if node.semantic_role is None:
                    node.semantic_role = "comparison"

            if node.is_copy:
                self.copy_nodes.append(node)
                if node.semantic_role is None:
                    node.semantic_role = "copy"

            if node.is_width_cast:
                self.width_cast_nodes.append(node)
                if node.semantic_role is None:
                    node.semantic_role = "width_cast"

    # ---------------------------------------------------------
    # STORAGE FLOW ANNOTATIONS
    # ---------------------------------------------------------

    def annotate_storage_flows(self):
        """
        Lightweight annotations for PHIfolder/emitter.

        This does not rewrite graph structure.
        """

        for node in self.var_nodes.values():

            out = node.var
            out_key = _storage_key(out)
            input_keys = [_storage_key(_unwrap_var(i)) for i in node.inputs]

            node.output_storage_key = out_key
            node.input_storage_keys = input_keys

            # True if the op writes back into one of its input storages.
            node.is_state_update = (
                out_key is not None
                and any(k == out_key for k in input_keys if k is not None)
                and any(x is not None for x in out_key)
            )

            if node.is_state_update and node.semantic_role is None:
                node.semantic_role = "state_update"

            try:
                out.output_storage_key = out_key
                out.input_storage_keys = input_keys
                out.is_state_update = bool(node.is_state_update)
            except Exception:
                pass

    # ---------------------------------------------------------
    # v34 RAW/LINKED/COMPUTE OPERAND-IDENTITY CUSTODY
    # ---------------------------------------------------------

    @staticmethod
    def _projection_sid_text_v32(value):
        """Compatibility helper retained for v32+ downstream consumers."""
        if value is None:
            return None
        if hasattr(value, "var"):
            value = getattr(value, "var", value)
        sid = getattr(value, "ssa_id", value)
        if sid is None:
            return None
        return str(sid)

    def _sid_variants_v34(self, sid):
        out = []
        if sid is None:
            return out
        for value in (sid, str(sid)):
            if value not in out:
                out.append(value)
        text = str(sid)
        if text.startswith("v_") and text[2:].isdigit():
            for value in (text[2:], int(text[2:])):
                if value not in out:
                    out.append(value)
        elif text.isdigit():
            for value in ("v_%s" % text, int(text)):
                if value not in out:
                    out.append(value)
        return out

    def _lookup_sid_mapping_v34(self, mapping, sid):
        if not isinstance(mapping, dict):
            return None
        for key in self._sid_variants_v34(sid):
            try:
                if key in mapping:
                    return mapping.get(key)
            except Exception:
                pass
        return None

    def _refresh_operand_identity_sidecars_v34(self):
        self.compute_storage_bindings_by_sid_v34 = dict(
            getattr(self.func, "compute_storage_bindings_by_sid", {}) or {}
        )
        self.resolver_storage_family_by_sid_v34 = dict(
            getattr(self.func, "indirect_storage_family_by_sid", {}) or {}
        )
        self.resolver_storage_families_by_key_v34 = dict(
            getattr(self.func, "indirect_storage_families_by_key", {}) or {}
        )

    def _normalize_concrete_stack_key_v34(self, value):
        if value is None:
            return None

        if isinstance(value, (tuple, list)) and len(value) >= 2:
            space = value[0]
            off = value[1]
            size = value[2] if len(value) >= 3 else 0
            if str(space or "").lower() != "stack":
                return None
            try:
                return ("stack", int(off), int(size or 0))
            except Exception:
                return None

        if not isinstance(value, dict):
            return None

        space = (
            value.get("storage_space")
            or value.get("space")
            or value.get("address_space")
            or value.get("memory_space")
        )
        off = value.get("storage_offset")
        if off is None:
            off = value.get("offset")
        if off is None:
            off = value.get("stack_offset")
        size = value.get("storage_size")
        if size is None:
            size = value.get("size")
        if size is None:
            width_bits = value.get("width_bits")
            if isinstance(width_bits, int) and width_bits > 0:
                size = (width_bits + 7) // 8

        if str(space or "").lower() == "stack" and off is not None:
            try:
                return ("stack", int(off), int(size or 0))
            except Exception:
                pass

        # PALCompute/resolver records are versioned and may nest physical
        # storage under one of several evidence fields. This walk is bounded
        # and key-driven; arbitrary mappings are not interpreted as storage.
        for key in (
            "storage_key", "output_storage_key", "input_storage_key",
            "stack_key", "physical_storage_key", "storage",
            "output_storage", "input_storage", "physical_storage",
            "storage_binding", "binding", "high_storage",
        ):
            nested = value.get(key)
            candidate = self._normalize_concrete_stack_key_v34(nested)
            if candidate is not None:
                return candidate
        return None

    def _concrete_stack_key_v32(self, value):
        value = _unwrap_var(value)
        if value is None:
            return None

        key = self._normalize_concrete_stack_key_v34(
            getattr(value, "storage_key", None)
        )
        if key is not None:
            return key

        space = (
            getattr(value, "storage_space", None)
            or getattr(value, "space", None)
        )
        if str(space or "").lower() != "stack":
            return None

        off = getattr(value, "storage_offset", None)
        if off is None:
            off = getattr(value, "offset", None)
        if off is None:
            off = getattr(value, "stack_offset", None)
        if off is None:
            return None

        size = getattr(value, "storage_size", None)
        if size is None:
            size = getattr(value, "size", None)

        try:
            return ("stack", int(off), int(size or 0))
        except Exception:
            return None

    def _stack_projection_name_v32(self, key):
        key = self._normalize_concrete_stack_key_v34(key)
        if key is None:
            return None
        try:
            return "local_%x" % abs(int(key[1]))
        except Exception:
            return None

    def _projection_source_v32(self, value, seen=None):
        """Return (operand_sid, concrete_stack_key, evidence_var).

        Follow only value-preserving transports. A PHI is accepted only when
        every resolvable arm proves one exact concrete stack key. This remains
        graph/storage evidence and never changes object identity.
        """

        if value is None:
            return None, None, None
        if seen is None:
            seen = set()

        operand_var = _unwrap_var(value)
        operand_sid = getattr(operand_var, "ssa_id", None)
        direct = self._concrete_stack_key_v32(operand_var)
        if direct is not None:
            return operand_sid, direct, operand_var

        node = (
            value
            if hasattr(value, "opcode") and hasattr(value, "var")
            else self.get_node(operand_var)
        )
        if node is None:
            return operand_sid, None, operand_var

        node_sid = getattr(getattr(node, "var", None), "ssa_id", None)
        marker = str(node_sid) if node_sid is not None else "node:%s" % id(node)
        if marker in seen:
            return operand_sid, None, operand_var
        seen.add(marker)

        # The original PAL operand is stronger storage evidence than the
        # linked FormulaNode output. Preserve index alignment for unary
        # transparent transports.
        raw_inputs = list(getattr(node, "raw_inputs", []) or [])
        if not raw_inputs:
            raw_inputs = list(getattr(getattr(node, "op", None), "inputs", []) or [])

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])
        if opcode == "COPY" and self._snapshot_contract_for_node_v35(node):
            # A protected snapshot is a temporal identity boundary. Following
            # through it would launder the captured epoch back into live state.
            return operand_sid, None, operand_var
        if opcode in (
            "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC", "SUBPIECE"
        ) and inputs:
            raw = raw_inputs[0] if raw_inputs else None
            raw_key = self._concrete_stack_key_v32(raw)
            if raw_key is not None:
                return operand_sid, raw_key, _unwrap_var(raw)
            _, key, evidence = self._projection_source_v32(inputs[0], seen)
            return operand_sid, key, evidence

        if opcode == "MULTIEQUAL" and inputs:
            proofs = []
            unresolved = 0
            for index, inp in enumerate(inputs):
                raw = raw_inputs[index] if index < len(raw_inputs) else None
                raw_key = self._concrete_stack_key_v32(raw)
                if raw_key is not None:
                    proofs.append((raw_key, _unwrap_var(raw)))
                    continue
                _, key, evidence = self._projection_source_v32(inp, set(seen))
                if key is None:
                    unresolved += 1
                    continue
                proofs.append((key, evidence))
            keys = {item[0] for item in proofs}
            if proofs and unresolved == 0 and len(keys) == 1:
                key = next(iter(keys))
                evidence = next(
                    (item[1] for item in proofs if item[1] is not None),
                    operand_var,
                )
                return operand_sid, key, evidence

        return operand_sid, None, operand_var

    def _legacy_var_expr_v33(self, value):
        """Projection-blind legacy variable authority.

        At SemanticGraph time func.var_map is normally absent because
        PHIfolder runs later. It remains first for compatibility with drivers
        that pre-seed a map, followed by PALVariable.name and SSA identity.
        """

        value = _unwrap_var(value)
        if value is None:
            return "None"
        if getattr(value, "is_constant", False):
            return self._const_expr_v24(value)

        sid = getattr(value, "ssa_id", None)
        var_map = getattr(self.func, "var_map", {}) or {}
        for key in self._sid_variants_v34(sid):
            try:
                if key in var_map:
                    return str(var_map[key])
            except Exception:
                pass

        name = getattr(value, "name", None)
        if name:
            return str(name)
        if sid is not None:
            return _canonical_ssa_name_v29(sid)
        return str(value)

    def _legacy_formula_expr_v33(self, node, seen=None):
        """Projection-blind facsimile of _formula_expr_v24 for detection."""

        if node is None:
            return None
        if seen is None:
            seen = set()

        sid = getattr(getattr(node, "var", None), "ssa_id", None)
        marker = str(sid) if sid is not None else "node:%s" % id(node)
        if marker in seen:
            return self._legacy_var_expr_v33(getattr(node, "var", None))
        seen.add(marker)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode == "COPY":
            projection = self._snapshot_projection_name_v35(node)
            if projection is not None:
                return projection
        if opcode in (
            "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC", "SUBPIECE"
        ) and inputs:
            child = self.get_node(inputs[0])
            if child is not None:
                return self._legacy_formula_expr_v33(child, seen)
            return self._legacy_var_expr_v33(inputs[0])

        binops = {
            "INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*",
            "INT_DIV": "//", "INT_SDIV": "//", "INT_REM": "%",
            "INT_SREM": "%", "INT_AND": "&", "INT_OR": "|",
            "INT_XOR": "^", "INT_LEFT": "<<", "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>", "INT_EQUAL": "==", "INT_NOTEQUAL": "!=",
            "INT_LESS": "<", "INT_SLESS": "<", "INT_LESSEQUAL": "<=",
            "INT_SLESSEQUAL": "<=", "BOOL_AND": "and", "BOOL_OR": "or",
            "BOOL_XOR": "^",
        }
        if opcode in binops and len(inputs) == 2:
            left = self._legacy_value_expr_v33(inputs[0], seen.copy())
            right = self._legacy_value_expr_v33(inputs[1], seen.copy())
            return "(%s %s %s)" % (left, binops[opcode], right)

        if opcode == "BOOL_NEGATE" and inputs:
            return "not (%s)" % self._legacy_value_expr_v33(
                inputs[0], seen.copy()
            )

        return self._legacy_var_expr_v33(getattr(node, "var", None))

    def _legacy_value_expr_v33(self, value, seen=None):
        if value is None:
            return "None"
        if hasattr(value, "var") and hasattr(value, "opcode"):
            return self._legacy_formula_expr_v33(value, seen or set())
        if getattr(value, "is_constant", False):
            return self._const_expr_v24(value)
        child = self.get_node(value)
        if child is not None:
            if getattr(child, "opcode", None) in ("CALL", "CALLIND"):
                return self._legacy_var_expr_v33(getattr(child, "var", value))
            return self._legacy_formula_expr_v33(child, seen or set())
        return self._legacy_var_expr_v33(value)

    def _baseline_projection_name_v33(self, operand, evidence_var=None):
        rendered = self._legacy_value_expr_v33(operand, set())
        if rendered not in (None, ""):
            return str(rendered)
        return self._legacy_var_expr_v33(evidence_var)

    def _baseline_projection_name_v32(self, operand, evidence_var=None):
        return self._baseline_projection_name_v33(operand, evidence_var)

    def _projection_contract_for_operand_v32(self, consumer, operand_index):
        sid = self._projection_sid_text_v32(getattr(consumer, "var", None))
        if sid is None:
            return None
        for variant in self._sid_variants_v34(sid):
            rec = self.operand_projection_contracts.get(
                (str(variant), int(operand_index))
            )
            if isinstance(rec, dict):
                return rec
        return None

    def _storage_projection_for_var_v32(self, value):
        return None

    def _sid_projection_for_var_v32(self, value):
        return None

    def _register_storage_projection_v32(self, key, name, evidence):
        return False

    def _transparent_stack_sinks_v32(self, root_sid, max_depth=6):
        """Compatibility-only inventory. v34 never publishes global names."""
        out = []
        if root_sid is None:
            return out
        work = [(root_sid, 0)]
        seen = set()
        transparent = {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC"}

        while work:
            sid, depth = work.pop(0)
            marker = str(sid)
            if marker in seen or depth > max_depth:
                continue
            seen.add(marker)

            users = list(self.uses_by_sid.get(sid, []) or [])
            if not users:
                users = list(self.uses_by_sid.get(str(sid), []) or [])

            for user in users:
                if getattr(user, "opcode", None) not in transparent:
                    continue
                inputs = list(getattr(user, "inputs", []) or [])
                if not any(
                    self._projection_sid_text_v32(inp) == str(sid)
                    for inp in inputs
                ):
                    continue
                out_var = getattr(user, "var", None)
                out_sid = getattr(out_var, "ssa_id", None)
                key = self._concrete_stack_key_v32(out_var)
                if key is not None:
                    out.append((out_sid, key, out_var, user))
                elif out_sid is not None:
                    work.append((out_sid, depth + 1))
        return out

    # ---------------------------------------------------------
    # v35 ERASE-EMPEROR TEMPORAL SNAPSHOT COPY CUSTODY
    # ---------------------------------------------------------

    def _snapshot_sid_text_v35(self, value):
        value = _unwrap_var(value)
        sid = getattr(value, "ssa_id", None) if value is not None else None
        return str(sid) if sid is not None else None

    def _snapshot_contract_for_sid_v35(self, sid):
        if sid is None:
            return None
        for variant in self._sid_variants_v34(sid):
            for key in (variant, str(variant)):
                try:
                    rec = self.snapshot_copy_contracts_v35.get(key)
                except Exception:
                    rec = None
                if isinstance(rec, dict):
                    return rec
        return None

    def _snapshot_contract_for_node_v35(self, node):
        if node is None:
            return None
        return self._snapshot_contract_for_sid_v35(
            getattr(getattr(node, "var", None), "ssa_id", None)
        )

    def _snapshot_projection_name_v35(self, node_or_value):
        node = (
            node_or_value
            if hasattr(node_or_value, "opcode") and hasattr(node_or_value, "var")
            else self.get_node(_unwrap_var(node_or_value))
        )
        rec = self._snapshot_contract_for_node_v35(node)
        if isinstance(rec, dict) and rec.get("projection_name"):
            return str(rec.get("projection_name"))
        return None

    def _formula_node_for_value_v35(self, value):
        if value is None:
            return None
        if hasattr(value, "opcode") and hasattr(value, "var"):
            return value
        return self.get_node(_unwrap_var(value))

    def _node_depends_on_sid_v35(self, node, target_sid, seen=None, depth=0, max_depth=24):
        if node is None or target_sid is None or depth > max_depth:
            return False
        if seen is None:
            seen = set()
        node_sid = self._snapshot_sid_text_v35(getattr(node, "var", None))
        marker = node_sid if node_sid is not None else "node:%s" % id(node)
        if marker in seen:
            return False
        seen.add(marker)
        if node_sid == str(target_sid):
            return True
        for inp in list(getattr(node, "inputs", []) or []):
            inp_sid = self._snapshot_sid_text_v35(inp)
            if inp_sid == str(target_sid):
                return True
            child = self._formula_node_for_value_v35(inp)
            if child is not None and self._node_depends_on_sid_v35(
                child, target_sid, set(seen), depth + 1, max_depth
            ):
                return True
        return False

    def _transparent_equivalent_to_sid_v35(self, node, target_sid, seen=None, depth=0, max_depth=12):
        """True only for a pure one-input transport chain back to target_sid."""
        if node is None or target_sid is None or depth > max_depth:
            return False
        if seen is None:
            seen = set()
        sid = self._snapshot_sid_text_v35(getattr(node, "var", None))
        marker = sid if sid is not None else "node:%s" % id(node)
        if marker in seen:
            return False
        seen.add(marker)
        if sid == str(target_sid):
            return True
        if getattr(node, "opcode", None) not in {
            "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC", "SUBPIECE"
        }:
            return False
        inputs = list(getattr(node, "inputs", []) or [])
        if len(inputs) != 1:
            return False
        inp_sid = self._snapshot_sid_text_v35(inputs[0])
        if inp_sid == str(target_sid):
            return True
        child = self._formula_node_for_value_v35(inputs[0])
        return self._transparent_equivalent_to_sid_v35(
            child, target_sid, seen, depth + 1, max_depth
        )

    def _snapshot_source_is_state_epoch_v35(self, source_node, source_var):
        if source_node is not None:
            if getattr(source_node, "opcode", None) == "MULTIEQUAL":
                return True, "source_is_phi_epoch"
            if bool(getattr(source_node, "is_phi", False)):
                return True, "source_is_phi_epoch"
            if bool(getattr(source_node, "is_state_update", False)):
                return True, "source_is_state_update"
            if getattr(source_node, "semantic_role", None) in {
                "phi_merge", "state_update", "loop_induction"
            }:
                return True, "source_semantic_role_%s" % getattr(
                    source_node, "semantic_role", None
                )
        if source_var is not None:
            if bool(getattr(source_var, "is_phi_target", False)):
                return True, "source_var_is_phi_target"
            if bool(getattr(source_var, "is_state_update", False)):
                return True, "source_var_is_state_update"
            if bool(getattr(source_var, "is_induction_variable", False)):
                return True, "source_var_is_induction_epoch"
        return False, "source_not_proven_state_epoch"

    def _snapshot_joint_consumer_records_v35(self, copy_node, source_sid, snapshot_sid):
        records = []
        sensitive = {
            "INT_SUB", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_LESS", "INT_SLESS",
            "INT_LESSEQUAL", "INT_SLESSEQUAL", "PTRADD", "PTRSUB",
        }
        for user in list(getattr(copy_node, "users", []) or []):
            opcode = getattr(user, "opcode", None)
            inputs = list(getattr(user, "inputs", []) or [])
            if opcode not in sensitive or len(inputs) < 2:
                continue
            snapshot_indexes = [
                index for index, inp in enumerate(inputs)
                if self._snapshot_sid_text_v35(inp) == str(snapshot_sid)
            ]
            if not snapshot_indexes:
                continue
            for snapshot_index in snapshot_indexes:
                for other_index, other in enumerate(inputs):
                    if other_index == snapshot_index:
                        continue
                    other_sid = self._snapshot_sid_text_v35(other)
                    if other_sid in (None, str(snapshot_sid), str(source_sid)):
                        continue
                    other_node = self._formula_node_for_value_v35(other)
                    if other_node is None:
                        continue
                    depends = self._node_depends_on_sid_v35(other_node, source_sid)
                    transparent_same = self._transparent_equivalent_to_sid_v35(
                        other_node, source_sid
                    )
                    if not depends or transparent_same:
                        continue
                    records.append({
                        "consumer_sid": self._snapshot_sid_text_v35(
                            getattr(user, "var", None)
                        ),
                        "consumer_opcode": opcode,
                        "consumer_block_addr": getattr(user, "block_addr", None),
                        "snapshot_operand_index": int(snapshot_index),
                        "later_epoch_operand_index": int(other_index),
                        "later_epoch_sid": other_sid,
                        "later_epoch_opcode": getattr(other_node, "opcode", None),
                        "later_epoch_depends_on_source": True,
                        "later_epoch_is_transparent_source_alias": False,
                        "proof": (
                            "snapshot_and_later_source_dependent_epoch_are_"
                            "simultaneously_consumed_by_order_sensitive_operation"
                        ),
                    })
        return records

    def _snapshot_downstream_uses_v35(self, copy_node):
        out = []
        for user in list(getattr(copy_node, "users", []) or []):
            out.append({
                "sid": self._snapshot_sid_text_v35(getattr(user, "var", None)),
                "opcode": getattr(user, "opcode", None),
                "block_addr": getattr(user, "block_addr", None),
                "is_condition": bool(getattr(user, "is_condition", False)),
                "user_count": len(list(getattr(user, "users", []) or [])),
            })
        return out

    def build_temporal_snapshot_copy_contracts_v35(self):
        """Protect COPY outputs that capture a state epoch before later mutation.

        Positive proof requires:
          * a distinct COPY output SID;
          * a PHI/state source epoch; and
          * one order-sensitive consumer that simultaneously consumes the COPY
            and a distinct, non-transparent value depending on the source epoch.

        This pass never renames a storage family. It freezes only the exact COPY
        output SID as an independent materialized snapshot identity.
        """
        self.snapshot_copy_contracts_v35 = {}
        self.snapshot_copy_projection_names_by_sid_v35 = {}
        self.snapshot_copy_events_v35 = []
        self.snapshot_copy_failures_v35 = []
        examined = 0
        state_candidates = 0
        protected = 0

        for node in list(self.var_nodes.values()):
            if getattr(node, "opcode", None) != "COPY":
                continue
            examined += 1
            inputs = list(getattr(node, "inputs", []) or [])
            if len(inputs) != 1:
                continue
            out_var = getattr(node, "var", None)
            source_var = _unwrap_var(inputs[0])
            snapshot_sid = getattr(out_var, "ssa_id", None)
            source_sid = getattr(source_var, "ssa_id", None)
            if snapshot_sid is None or source_sid is None:
                continue
            if str(snapshot_sid) == str(source_sid):
                continue

            source_node = self._formula_node_for_value_v35(inputs[0])
            state_source, source_reason = self._snapshot_source_is_state_epoch_v35(
                source_node, source_var
            )
            if not state_source:
                continue
            state_candidates += 1

            joint = self._snapshot_joint_consumer_records_v35(
                node, source_sid, snapshot_sid
            )
            if not joint:
                continue

            projection_name = _canonical_ssa_name_v29(snapshot_sid)
            contract = {
                "kind": "temporal_snapshot_copy_contract_v35",
                "version": self.snapshot_copy_version_v35,
                "snapshot_sid": str(snapshot_sid),
                "snapshot_name_before": getattr(out_var, "name", None),
                "projection_name": projection_name,
                "source_sid": str(source_sid),
                "source_name": getattr(source_var, "name", None),
                "source_opcode": getattr(source_node, "opcode", None),
                "source_block_addr": getattr(source_node, "block_addr", None),
                "capture_block_addr": getattr(node, "block_addr", None),
                "source_state_reason": source_reason,
                "joint_consumers": joint,
                "downstream_uses": self._snapshot_downstream_uses_v35(node),
                # Compatibility: downstream layers still need one concrete
                # value definition. v36 narrows the scope: this does not force
                # emission at the original COPY occurrence.
                "materialization_required": True,
                "snapshot_value_required": True,
                "native_producer_site_required": False,
                "materialization_scope": (
                    "value_lifetime_not_native_producer_site"
                ),
                "execution_placement_authority": "PALSGLdecomp",
                "structural_relocation_candidate": True,
                "native_capture_op_id": (
                    str(getattr(node, "op_id", None))
                    if getattr(node, "op_id", None) is not None
                    else None
                ),
                "native_capture_output_sid": str(snapshot_sid),
                "native_capture_source_sid": str(source_sid),
                "transparent_copy_allowed": False,
                "formula_inline_allowed": False,
                "projection_scope": "exact_snapshot_output_sid",
                "storage_family_renamed": False,
                "semantic_identity": "state_epoch_snapshot",
                "reason": (
                    "COPY_captures_state_epoch_consumed_with_later_dependent_"
                    "epoch_by_order_sensitive_operation"
                ),
            }
            for key in (snapshot_sid, str(snapshot_sid), projection_name):
                self.snapshot_copy_contracts_v35[key] = contract
                self.snapshot_copy_projection_names_by_sid_v35[str(key)] = (
                    projection_name
                )

            try:
                node.is_temporal_snapshot_v35 = True
                node.snapshot_materialization_required = True
                node.snapshot_value_required_v36 = True
                node.snapshot_native_producer_site_required_v36 = False
                node.snapshot_execution_placement_authority_v36 = (
                    "PALSGLdecomp"
                )
                node.snapshot_copy_contract_v35 = contract
                out_var.is_temporal_snapshot_v35 = True
                out_var.snapshot_materialization_required = True
                out_var.snapshot_value_required_v36 = True
                out_var.snapshot_native_producer_site_required_v36 = False
                out_var.snapshot_execution_placement_authority_v36 = (
                    "PALSGLdecomp"
                )
                out_var.snapshot_copy_contract_v35 = contract
                out_var.snapshot_projection_name_v35 = projection_name
            except Exception:
                pass

            event = {
                "kind": "temporal_snapshot_copy_protected_v35",
                "snapshot_sid": str(snapshot_sid),
                "source_sid": str(source_sid),
                "projection_name": projection_name,
                "capture_block_addr": getattr(node, "block_addr", None),
                "joint_consumer_count": len(joint),
                "joint_consumers": list(joint),
                "reason": contract["reason"],
            }
            self.snapshot_copy_events_v35.append(event)
            self.semantic_events.append(dict(event))
            protected += 1

        self.snapshot_copy_inventory_v35 = {
            "kind": "temporal_snapshot_copy_inventory_v35",
            "version": self.snapshot_copy_version_v35,
            "copy_nodes_examined": examined,
            "state_source_candidates": state_candidates,
            "protected_snapshots": protected,
            "contracts": len({id(v) for v in self.snapshot_copy_contracts_v35.values()}),
            "failures": len(self.snapshot_copy_failures_v35),
            "global_storage_renames": 0,
            "global_sid_family_renames": 0,
            "rule": (
                "distinct_COPY_epoch_plus_PHI_state_source_plus_joint_"
                "order_sensitive_use_with_later_dependent_epoch"
            ),
        }
        self.semantic_events.append(dict(self.snapshot_copy_inventory_v35))
        self._audit_temporal_snapshot_copy_contracts_v35()
        return dict(self.snapshot_copy_contracts_v35)

    def _audit_temporal_snapshot_copy_contracts_v35(self):
        unique = {}
        for rec in self.snapshot_copy_contracts_v35.values():
            if not isinstance(rec, dict):
                continue
            unique[rec.get("snapshot_sid")] = rec

        failures = []
        for sid, rec in unique.items():
            node = None
            for variant in self._sid_variants_v34(sid):
                if variant in self.var_nodes:
                    node = self.var_nodes.get(variant)
                    break
            if node is None:
                failures.append({
                    "kind": "temporal_snapshot_copy_custody_failure_v35",
                    "snapshot_sid": sid,
                    "reason": "snapshot_formula_node_missing",
                })
                continue
            rendered = self._formula_expr_v24(node, set())
            projection = str(rec.get("projection_name"))
            if str(rendered) != projection:
                failures.append({
                    "kind": "temporal_snapshot_copy_custody_failure_v35",
                    "snapshot_sid": sid,
                    "reason": "snapshot_copy_still_rendered_transparently",
                    "rendered": rendered,
                    "expected": projection,
                })
                continue
            for joint in list(rec.get("joint_consumers", []) or []):
                consumer = None
                for variant in self._sid_variants_v34(joint.get("consumer_sid")):
                    if variant in self.var_nodes:
                        consumer = self.var_nodes.get(variant)
                        break
                if consumer is None:
                    failures.append({
                        "kind": "temporal_snapshot_copy_custody_failure_v35",
                        "snapshot_sid": sid,
                        "reason": "joint_consumer_missing",
                        "consumer_sid": joint.get("consumer_sid"),
                    })
                    continue
                expr = self._formula_expr_v24(consumer, set())
                if projection not in str(expr):
                    failures.append({
                        "kind": "temporal_snapshot_copy_custody_failure_v35",
                        "snapshot_sid": sid,
                        "reason": "joint_consumer_does_not_reference_snapshot_identity",
                        "consumer_sid": joint.get("consumer_sid"),
                        "rendered": expr,
                        "expected_token": projection,
                    })

        self.snapshot_copy_failures_v35 = failures
        audit = {
            "kind": (
                "temporal_snapshot_copy_custody_verified_v35"
                if not failures else
                "temporal_snapshot_copy_custody_failed_v35"
            ),
            "snapshots_checked": len(unique),
            "failures": list(failures),
        }
        self.snapshot_copy_events_v35.append(audit)
        self.semantic_events.append(dict(audit))
        if failures:
            first = failures[0]
            raise RuntimeError(
                "PALSemanticGraphBuilder v35 temporal snapshot custody failed "
                "for %s: %s"
                % (first.get("snapshot_sid"), first.get("reason"))
            )
        return audit

    def _raw_operand_for_node_v34(self, node, operand_index):
        raw_inputs = list(getattr(node, "raw_inputs", []) or [])
        if not raw_inputs:
            raw_inputs = list(
                getattr(getattr(node, "op", None), "inputs", []) or []
            )
        try:
            return raw_inputs[int(operand_index)]
        except Exception:
            return None

    def _compute_storage_binding_v34(self, sid):
        return self._lookup_sid_mapping_v34(
            self.compute_storage_bindings_by_sid_v34, sid
        )

    def _resolver_storage_family_v34(self, sid):
        family_key = self._lookup_sid_mapping_v34(
            self.resolver_storage_family_by_sid_v34, sid
        )
        if family_key is None:
            return None, None
        family = None
        for key in (family_key, str(family_key)):
            try:
                if key in self.resolver_storage_families_by_key_v34:
                    family = self.resolver_storage_families_by_key_v34.get(key)
                    break
            except Exception:
                pass
        return family_key, family if isinstance(family, dict) else None

    def _resolver_name_storage_collision_audit_v34(self):
        groups = {}
        vars_in = getattr(self.func, "vars", {}) or {}
        values = vars_in.values() if isinstance(vars_in, dict) else vars_in
        for var in list(values or []):
            key = self._concrete_stack_key_v32(var)
            name = getattr(var, "name", None)
            sid = getattr(var, "ssa_id", None)
            if key is None or not name:
                continue
            groups.setdefault(str(name), []).append({
                "sid": str(sid) if sid is not None else None,
                "storage_key": key,
                "size": getattr(var, "size", None),
            })

        collisions = []
        for name, items in groups.items():
            keys = {tuple(item["storage_key"]) for item in items}
            if len(keys) < 2:
                continue
            collisions.append({
                "kind": "resolver_existing_name_distinct_stack_storage_collision_v34",
                "name": name,
                "distinct_storage_keys": sorted(keys, key=lambda x: (x[1], x[2])),
                "members": items,
                "resolver_mutation_requested": False,
                "authority": "SemanticGraph_audit_of_resolver_preserved_names",
            })
        self.resolver_name_storage_collisions_v34 = collisions
        return collisions

    def _operand_reaches_condition_v34(self, node, max_depth=12):
        if node is None:
            return False
        work = [(node, 0)]
        seen = set()
        while work:
            current, depth = work.pop(0)
            if current is None or id(current) in seen or depth > max_depth:
                continue
            seen.add(id(current))
            if bool(getattr(current, "is_condition", False)):
                return True
            for user in list(getattr(current, "users", []) or []):
                work.append((user, depth + 1))
        return False

    def _operand_identity_evidence_for_v34(self, node, operand_index, operand):
        raw_operand = self._raw_operand_for_node_v34(node, operand_index)
        linked_var = _unwrap_var(operand)
        raw_var = _unwrap_var(raw_operand)
        linked_sid = getattr(linked_var, "ssa_id", None)
        raw_sid = getattr(raw_var, "ssa_id", None)

        evidence = []

        def add(source, key=None, family_id=None, payload=None):
            key = self._normalize_concrete_stack_key_v34(key)
            evidence.append({
                "source": source,
                "stack_key": key,
                "family_id": str(family_id) if family_id is not None else None,
                "payload": payload,
            })

        add("linked_direct", self._concrete_stack_key_v32(linked_var))
        add("raw_direct", self._concrete_stack_key_v32(raw_var))

        _, linked_transport_key, linked_transport_var = self._projection_source_v32(
            operand
        )
        add(
            "linked_transparent_transport",
            linked_transport_key,
            payload={
                "evidence_sid": getattr(linked_transport_var, "ssa_id", None),
                "evidence_name": getattr(linked_transport_var, "name", None),
            },
        )

        if raw_operand is not None:
            _, raw_transport_key, raw_transport_var = self._projection_source_v32(
                raw_operand
            )
            add(
                "raw_transparent_transport",
                raw_transport_key,
                payload={
                    "evidence_sid": getattr(raw_transport_var, "ssa_id", None),
                    "evidence_name": getattr(raw_transport_var, "name", None),
                },
            )

        linked_binding = self._compute_storage_binding_v34(linked_sid)
        raw_binding = self._compute_storage_binding_v34(raw_sid)
        add(
            "PALCompute_linked_storage_binding",
            self._normalize_concrete_stack_key_v34(linked_binding),
            (linked_binding or {}).get("family_id") if isinstance(linked_binding, dict) else None,
            linked_binding,
        )
        add(
            "PALCompute_raw_storage_binding",
            self._normalize_concrete_stack_key_v34(raw_binding),
            (raw_binding or {}).get("family_id") if isinstance(raw_binding, dict) else None,
            raw_binding,
        )

        linked_family_id, linked_family = self._resolver_storage_family_v34(linked_sid)
        raw_family_id, raw_family = self._resolver_storage_family_v34(raw_sid)
        add(
            "resolver_linked_storage_family",
            self._normalize_concrete_stack_key_v34(linked_family),
            linked_family_id,
            linked_family,
        )
        add(
            "resolver_raw_storage_family",
            self._normalize_concrete_stack_key_v34(raw_family),
            raw_family_id,
            raw_family,
        )

        keys = []
        key_sources = {}
        family_ids = set()
        for item in evidence:
            key = item.get("stack_key")
            if key is not None:
                key = tuple(key)
                if key not in keys:
                    keys.append(key)
                key_sources.setdefault(key, []).append(item.get("source"))
            if item.get("family_id"):
                family_ids.add(item.get("family_id"))

        # Exact-consumer raw storage is stronger than a linked FormulaNode's
        # PHI/high-variable image. PALCompute and resolver evidence are
        # fallbacks. Conflicting lower-authority keys remain visible in the
        # receipt but do not veto an exact raw operand key.
        authority_order = [
            "raw_direct",
            "PALCompute_raw_storage_binding",
            "raw_transparent_transport",
            "linked_direct",
            "PALCompute_linked_storage_binding",
            "linked_transparent_transport",
            "resolver_raw_storage_family",
            "resolver_linked_storage_family",
        ]
        chosen_item = None
        for source in authority_order:
            chosen_item = next(
                (
                    item for item in evidence
                    if item.get("source") == source
                    and item.get("stack_key") is not None
                ),
                None,
            )
            if chosen_item is not None:
                break
        chosen_key = (
            tuple(chosen_item.get("stack_key"))
            if chosen_item is not None else None
        )
        shadowed_conflicts = [
            tuple(key) for key in keys
            if chosen_key is not None and tuple(key) != tuple(chosen_key)
        ]
        conflict = bool(shadowed_conflicts)
        hard_conflict = bool(keys and chosen_key is None)
        baseline = self._baseline_projection_name_v33(operand, raw_var)

        record = {
            "kind": "joint_consumer_operand_identity_evidence_v34",
            "version": self.operand_projection_version,
            "consumer_sid": self._projection_sid_text_v32(
                getattr(node, "var", None)
            ),
            "consumer_opcode": getattr(node, "opcode", None),
            "consumer_block_addr": getattr(node, "block_addr", None),
            "consumer_reaches_condition": self._operand_reaches_condition_v34(node),
            "operand_index": int(operand_index),
            "linked_sid": str(linked_sid) if linked_sid is not None else None,
            "linked_name": getattr(linked_var, "name", None),
            "raw_sid": str(raw_sid) if raw_sid is not None else None,
            "raw_name": getattr(raw_var, "name", None),
            "baseline_name": str(baseline) if baseline is not None else None,
            "chosen_stack_key": chosen_key,
            "concrete_stack_keys": list(keys),
            "stack_key_sources": {
                str(key): list(sources) for key, sources in key_sources.items()
            },
            "storage_family_ids": sorted(family_ids),
            "evidence_conflict": conflict,
            "hard_evidence_conflict": hard_conflict,
            "chosen_storage_authority": (
                chosen_item.get("source") if chosen_item is not None else None
            ),
            "shadowed_conflicting_stack_keys": shadowed_conflicts,
            "evidence": evidence,
            "authority_order": authority_order,
        }
        self.operand_identity_evidence_v34.append(record)
        return record

    def _projection_debug_item_v33(
        self,
        node,
        operand_index,
        operand,
        operand_sid,
        stack_key,
        evidence_var,
        legacy_render,
    ):
        # Compatibility shim retained for older tests.
        return {
            "consumer_sid": self._projection_sid_text_v32(
                getattr(node, "var", None)
            ),
            "consumer_opcode": getattr(node, "opcode", None),
            "consumer_block_addr": getattr(node, "block_addr", None),
            "operand_index": int(operand_index),
            "source_sid": str(operand_sid),
            "storage_key": stack_key,
            "legacy_render": str(legacy_render),
            "evidence_name": getattr(evidence_var, "name", None),
        }

    def _record_operand_identity_failure_v34(self, node, reason, details=None):
        sid = self._projection_sid_text_v32(getattr(node, "var", None))
        key = (sid, str(reason))
        if key in self._operand_identity_failure_keys_v34:
            return
        self._operand_identity_failure_keys_v34.add(key)
        rec = {
            "kind": "noncommutative_operand_identity_custody_failure_v34",
            "version": self.operand_projection_version,
            "consumer_sid": sid,
            "consumer_opcode": getattr(node, "opcode", None),
            "consumer_block_addr": getattr(node, "block_addr", None),
            "reason": reason,
            "details": details,
        }
        self.operand_identity_failures_v34.append(rec)
        self.operand_projection_events.append(dict(rec))

    def build_joint_consumer_stack_operand_projections_v34(self):
        """Compile exact projections from synchronized SSA and storage views.

        FormulaNode.inputs owns expression identity. FormulaNode.raw_inputs
        owns the original PAL storage image. PALCompute and resolver sidecars
        are supplementary. A projection is compiled only when both operands at
        one binary consumer render identically and two distinct concrete stack
        keys are positively proved. No SID-wide or storage-wide rename exists.
        """

        self._refresh_operand_identity_sidecars_v34()
        self._resolver_name_storage_collision_audit_v34()

        self.operand_projection_contracts = {}
        self.storage_projection_names = {}
        self.sid_projection_names = {}
        self.operand_projection_collisions = []
        self.operand_projection_events = []
        self.operand_identity_evidence_v34 = []
        self.operand_identity_ambiguities_v34 = []
        self.operand_identity_failures_v34 = []
        self.operand_identity_inventory_v34 = {}
        self._operand_identity_by_consumer_v34 = {}
        self._operand_identity_failure_keys_v34 = set()

        supported_binary = {
            "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
            "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL",
            "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
            "INT_SLESSEQUAL", "BOOL_AND", "BOOL_OR", "BOOL_XOR",
        }
        noncommutative = {
            "INT_SUB", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_LESS",
            "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
        }

        examined = 0
        collision_candidates = 0
        resolved = 0
        unresolved = 0
        same_storage = 0
        conflicts = 0

        for node in self.var_nodes.values():
            opcode = getattr(node, "opcode", None)
            inputs = list(getattr(node, "inputs", []) or [])
            if opcode not in supported_binary or len(inputs) != 2:
                continue
            examined += 1

            items = []
            for index, operand in enumerate(inputs):
                var = _unwrap_var(operand)
                if var is None or getattr(var, "is_constant", False):
                    continue
                items.append(
                    self._operand_identity_evidence_for_v34(
                        node, index, operand
                    )
                )

            consumer_sid = self._projection_sid_text_v32(
                getattr(node, "var", None)
            )
            if len(items) != 2:
                self._operand_identity_by_consumer_v34[consumer_sid] = {
                    "status": "not_two_dynamic_operands",
                    "opcode": opcode,
                    "items": items,
                }
                continue

            same_render = items[0].get("baseline_name") == items[1].get("baseline_name")
            if not same_render:
                self._operand_identity_by_consumer_v34[consumer_sid] = {
                    "status": "distinct_legacy_rendering",
                    "opcode": opcode,
                    "items": items,
                }
                continue

            collision_candidates += 1
            keys = [item.get("chosen_stack_key") for item in items]
            concrete = [tuple(key) for key in keys if key is not None]
            distinct_keys = set(concrete)
            any_conflict = any(item.get("hard_evidence_conflict") for item in items)
            soft_conflicts = [
                item for item in items if item.get("evidence_conflict")
            ]
            if soft_conflicts:
                self.operand_projection_events.append({
                    "kind": "joint_consumer_lower_authority_storage_conflict_shadowed_v34",
                    "consumer_sid": consumer_sid,
                    "opcode": opcode,
                    "participants": soft_conflicts,
                    "rule": "exact_raw_operand_storage_outranks_linked_PHI_image",
                })
            linked_sids = {item.get("linked_sid") for item in items if item.get("linked_sid") is not None}
            raw_sids = {item.get("raw_sid") for item in items if item.get("raw_sid") is not None}
            family_sets = [set(item.get("storage_family_ids") or []) for item in items]

            if any_conflict:
                conflicts += 1
                status = "conflicting_storage_evidence"
                ambiguity = {
                    "kind": "joint_consumer_operand_identity_ambiguous_v34",
                    "consumer_sid": consumer_sid,
                    "consumer_opcode": opcode,
                    "consumer_block_addr": getattr(node, "block_addr", None),
                    "collision_name": items[0].get("baseline_name"),
                    "status": status,
                    "participants": items,
                }
                self.operand_identity_ambiguities_v34.append(ambiguity)
                self._operand_identity_by_consumer_v34[consumer_sid] = {
                    "status": status, "opcode": opcode, "items": items,
                }
                if opcode in noncommutative and self._operand_reaches_condition_v34(node):
                    self._record_operand_identity_failure_v34(
                        node, status, ambiguity
                    )
                continue

            if len(distinct_keys) == 2 and len(concrete) == 2:
                projections = [self._stack_projection_name_v32(key) for key in concrete]
                if None in projections or len(set(projections)) != 2:
                    status = "distinct_stack_projection_name_not_unique"
                    self._record_operand_identity_failure_v34(
                        node, status, {"items": items, "projections": projections}
                    )
                    self._operand_identity_by_consumer_v34[consumer_sid] = {
                        "status": status, "opcode": opcode, "items": items,
                    }
                    continue

                collision = {
                    "kind": "joint_consumer_distinct_stack_name_collision_v34",
                    "version": self.operand_projection_version,
                    "consumer_sid": consumer_sid,
                    "consumer_opcode": opcode,
                    "consumer_block_addr": getattr(node, "block_addr", None),
                    "collision_name": items[0].get("baseline_name"),
                    "distinct_stack_offsets": sorted(key[1] for key in distinct_keys),
                    "participants": [],
                    "reason": (
                        "linked_formula_operands_share_text_but_raw_or_upstream_"
                        "storage_evidence_proves_distinct_stack_cells"
                    ),
                }

                for item, key, projection in zip(items, concrete, projections):
                    rec = {
                        "kind": "joint_consumer_operand_projection_contract_v34",
                        "version": self.operand_projection_version,
                        "consumer_sid": consumer_sid,
                        "consumer_opcode": opcode,
                        "consumer_block_addr": getattr(node, "block_addr", None),
                        "operand_index": item.get("operand_index"),
                        "source_sid": item.get("linked_sid"),
                        "linked_source_sid": item.get("linked_sid"),
                        "raw_source_sid": item.get("raw_sid"),
                        "storage_key": key,
                        "baseline_name": item.get("baseline_name"),
                        "projection_name": projection,
                        "projection_role": "exact_consumer_stack_operand",
                        "projection_scope": "consumer_sid_plus_operand_index_only",
                        "storage_authority": "raw_linked_compute_resolver_evidence_v34",
                        "evidence": item,
                        "reason": collision["reason"],
                    }
                    self.operand_projection_contracts[
                        (str(consumer_sid), int(item.get("operand_index")))
                    ] = rec
                    collision["participants"].append(dict(rec))

                self.operand_projection_collisions.append(collision)
                event = {
                    "kind": "joint_consumer_stack_projection_compiled_v34",
                    "consumer_sid": consumer_sid,
                    "opcode": opcode,
                    "block_addr": getattr(node, "block_addr", None),
                    "collision_name": items[0].get("baseline_name"),
                    "operand_contracts": 2,
                    "raw_operand_storage_consumed": any(
                        any(ev.get("source") == "raw_direct" and ev.get("stack_key") is not None
                            for ev in item.get("evidence", []))
                        for item in items
                    ),
                    "compute_storage_binding_consumed": any(
                        any(str(ev.get("source") or "").startswith("PALCompute") and ev.get("stack_key") is not None
                            for ev in item.get("evidence", []))
                        for item in items
                    ),
                    "global_storage_projections": 0,
                    "global_sid_projections": 0,
                }
                self.operand_projection_events.append(event)
                self._operand_identity_by_consumer_v34[consumer_sid] = {
                    "status": "resolved_exact_consumer_projection",
                    "opcode": opcode,
                    "items": items,
                    "contracts": collision["participants"],
                }
                resolved += 1
                continue

            if len(distinct_keys) == 1 and len(concrete) == 2:
                same_storage += 1
                self._operand_identity_by_consumer_v34[consumer_sid] = {
                    "status": "same_concrete_stack_storage",
                    "opcode": opcode,
                    "items": items,
                }
                self.operand_projection_events.append({
                    "kind": "joint_consumer_same_storage_collision_not_projected_v34",
                    "consumer_sid": consumer_sid,
                    "opcode": opcode,
                    "storage_key": next(iter(distinct_keys)),
                    "baseline_name": items[0].get("baseline_name"),
                    "reason": "same_storage_epochs_are_not_distinct_stack_cells",
                })
                continue

            # No complete concrete pair. Different family evidence or distinct
            # SIDs make the collision auditable, but not safely nameable.
            distinct_family = bool(
                family_sets[0] and family_sets[1]
                and family_sets[0].isdisjoint(family_sets[1])
            )
            status = (
                "distinct_storage_families_without_concrete_stack_keys"
                if distinct_family else
                "incomplete_concrete_storage_evidence"
            )
            ambiguity = {
                "kind": "joint_consumer_operand_identity_ambiguous_v34",
                "version": self.operand_projection_version,
                "consumer_sid": consumer_sid,
                "consumer_opcode": opcode,
                "consumer_block_addr": getattr(node, "block_addr", None),
                "collision_name": items[0].get("baseline_name"),
                "status": status,
                "linked_sids": sorted(linked_sids),
                "raw_sids": sorted(raw_sids),
                "participants": items,
                "canonical_predicate_must_not_claim_high_confidence": True,
            }
            self.operand_identity_ambiguities_v34.append(ambiguity)
            self._operand_identity_by_consumer_v34[consumer_sid] = {
                "status": status,
                "opcode": opcode,
                "items": items,
            }
            unresolved += 1

            # Fail closed only for a condition-reaching noncommutative
            # consumer where upstream evidence positively distinguishes
            # families or at least one concrete stack cell is visible. Fully
            # untyped same-name temporaries remain warnings to protect matrix
            # compatibility until PALRAW supplies stronger evidence.
            any_concrete = any(item.get("concrete_stack_keys") for item in items)
            if (
                opcode in noncommutative
                and self._operand_reaches_condition_v34(node)
                and (distinct_family or any_concrete)
            ):
                self._record_operand_identity_failure_v34(
                    node, status, ambiguity
                )

        self.operand_projection_inventory = {
            "kind": "joint_consumer_stack_projection_inventory_v34",
            "version": self.operand_projection_version,
            "active": bool(self.operand_projection_collisions),
            "consumers_examined": examined,
            "same_render_collision_candidates": collision_candidates,
            "collision_consumers": len(self.operand_projection_collisions),
            "operand_contracts": len(self.operand_projection_contracts),
            "storage_projection_keys": 0,
            "sid_projection_names": 0,
            "resolved": resolved,
            "same_storage_negative": same_storage,
            "unresolved": unresolved,
            "evidence_conflicts": conflicts,
            "global_projection_side_effects": False,
            "renderer_authority_aligned": True,
            "raw_inputs_consumed_as_storage_authority": True,
            "PALCompute_storage_bindings_consumed": bool(
                self.compute_storage_bindings_by_sid_v34
            ),
            "resolver_storage_families_consumed": bool(
                self.resolver_storage_family_by_sid_v34
            ),
            "rule": (
                "same_exact_consumer_render_plus_distinct_concrete_stack_"
                "storage_from_linked_raw_compute_or_resolver_evidence"
            ),
        }
        self.operand_identity_inventory_v34 = {
            "kind": "operand_identity_inventory_v34",
            "version": self.operand_projection_version,
            "evidence_records": len(self.operand_identity_evidence_v34),
            "ambiguities": len(self.operand_identity_ambiguities_v34),
            "failures": len(self.operand_identity_failures_v34),
            "resolver_name_storage_collisions": len(
                self.resolver_name_storage_collisions_v34
            ),
            "positive_distinct_stack_collisions_resolved": resolved,
            "unresolved_condition_noncommutative_failures": sum(
                1 for item in self.operand_identity_failures_v34
                if item.get("consumer_opcode") in noncommutative
            ),
            "canonical_metadata_policy": (
                "resolved_projection_or_low_confidence_unresolved_status;_"
                "never_high_confidence_after_identity_ambiguity"
            ),
        }
        self.semantic_events.append(dict(self.operand_projection_inventory))
        self.semantic_events.append(dict(self.operand_identity_inventory_v34))

        # Positive distinct-storage evidence must never survive as identical
        # final operands. This is the fail-closed gate before EdgeTruth.
        for collision in self.operand_projection_collisions:
            consumer_sid = collision.get("consumer_sid")
            node = self.var_nodes.get(consumer_sid)
            if node is None:
                for key in self._sid_variants_v34(consumer_sid):
                    if key in self.var_nodes:
                        node = self.var_nodes.get(key)
                        break
            if node is None:
                continue
            inputs = list(getattr(node, "inputs", []) or [])
            if len(inputs) != 2:
                continue
            left = self._value_expr_v24(
                inputs[0], set(), consumer=node, operand_index=0
            )
            right = self._value_expr_v24(
                inputs[1], set(), consumer=node, operand_index=1
            )
            if str(left) == str(right):
                self._record_operand_identity_failure_v34(
                    node,
                    "compiled_exact_projection_did_not_separate_rendered_operands",
                    {"left": left, "right": right, "collision": collision},
                )

        if self.operand_identity_failures_v34:
            # Publish the forensic receipt before failing. Pipeline wrappers
            # may catch the exception, but the function object must still show
            # the exact consumer, operands and evidence that blocked EdgeTruth.
            self.func.operand_projection_contracts = dict(
                self.operand_projection_contracts
            )
            self.func.operand_identity_evidence_v34 = list(
                self.operand_identity_evidence_v34
            )
            self.func.operand_identity_ambiguities_v34 = list(
                self.operand_identity_ambiguities_v34
            )
            self.func.operand_identity_failures_v34 = list(
                self.operand_identity_failures_v34
            )
            self.func.operand_identity_inventory_v34 = dict(
                self.operand_identity_inventory_v34
            )
            # Do not allow a known distinct-storage noncommutative collision to
            # become canonical EdgeTruth. The error is generic and carries no
            # specimen address or constant.
            first = self.operand_identity_failures_v34[0]
            raise RuntimeError(
                "PALSemanticGraphBuilder v34 operand-identity custody failed "
                "for consumer %s opcode %s: %s"
                % (
                    first.get("consumer_sid"),
                    first.get("consumer_opcode"),
                    first.get("reason"),
                )
            )

    def build_joint_consumer_stack_operand_projections_v33(self):
        """Compatibility wrapper for older drivers/tests."""
        return self.build_joint_consumer_stack_operand_projections_v34()

    def build_joint_consumer_stack_operand_projections_v32(self):
        """Compatibility wrapper for older drivers/tests."""
        return self.build_joint_consumer_stack_operand_projections_v34()

    def _formula_identity_status_v34(self, node, seen=None):
        if node is None:
            return "not_applicable"
        if seen is None:
            seen = set()
        sid = self._projection_sid_text_v32(getattr(node, "var", None))
        marker = sid if sid is not None else "node:%s" % id(node)
        if marker in seen:
            return "cycle"
        seen.add(marker)

        statuses = []
        rec = self._operand_identity_by_consumer_v34.get(sid)
        if isinstance(rec, dict):
            statuses.append(str(rec.get("status") or ""))
        for inp in list(getattr(node, "inputs", []) or []):
            child = inp if hasattr(inp, "opcode") and hasattr(inp, "var") else self.get_node(inp)
            if child is not None:
                statuses.append(self._formula_identity_status_v34(child, set(seen)))

        if any(
            status in (
                "conflicting_storage_evidence",
                "distinct_storage_families_without_concrete_stack_keys",
                "incomplete_concrete_storage_evidence",
                "distinct_stack_projection_name_not_unique",
                "unresolved_operand_identity_collision_v34",
            )
            for status in statuses
        ):
            return "unresolved_operand_identity_collision_v34"
        if any(
            status in (
                "resolved_exact_consumer_projection",
                "resolved_exact_consumer_projection_v34",
            )
            for status in statuses
        ):
            return "resolved_exact_consumer_projection_v34"
        return "direct_or_noncolliding_v34"

    def _formula_metadata_expr_v34(self, node):
        expr = self._formula_expr_v24(node) if node is not None else None
        status = self._formula_identity_status_v34(node)
        authoritative = status != "unresolved_operand_identity_collision_v34"
        return expr, status, authoritative

    # ---------------------------------------------------------
    # INDUCTION DETECTION
    # ---------------------------------------------------------

    def detect_induction_variables(self):
        """
        Conservative induction detection.

        Marks arithmetic updates that look like:
            x_next = x_prev + const
            x_next = x_prev - const

        Also catches cases where x_prev and x_next are different SSA names
        but share the same storage identity or flow from a PHI.
        """

        self.induction_nodes = []

        for node in self.var_nodes.values():

            if node.opcode not in ("INT_ADD", "INT_SUB"):
                continue

            if len(node.inputs) != 2:
                continue

            a = node.inputs[0]
            b = node.inputs[1]

            av = _unwrap_var(a)
            bv = _unwrap_var(b)
            out = node.var

            # x = x + const / x = x - const
            if self.same_storage(out, av) and self.is_constant_var(bv):
                self.mark_induction(node, base=av, step=bv)
                continue

            # x = const + x
            if node.opcode == "INT_ADD" and self.same_storage(out, bv) and self.is_constant_var(av):
                self.mark_induction(node, base=bv, step=av)
                continue

            # SSA update where base comes from PHI or prior storage version.
            if self.looks_like_loop_update(node):
                step = bv if self.is_constant_var(bv) else av
                base = av if self.is_constant_var(bv) else bv
                self.mark_induction(node, base=base, step=step)
                continue

    def looks_like_loop_update(self, node):
        """
        Heuristic induction recognizer for SSA-style updates.

        This does not attempt to prove loop structure. It only identifies
        arithmetic update nodes that are likely induction candidates.
        """

        if len(node.inputs) != 2:
            return False

        a = node.inputs[0]
        b = node.inputs[1]

        av = _unwrap_var(a)
        bv = _unwrap_var(b)

        # One side must be a constant step.
        if self.is_constant_var(av):
            base = b
        elif self.is_constant_var(bv):
            base = a
        else:
            return False

        base_node = base if hasattr(base, "opcode") else self.get_node(base)

        # Base comes from PHI: classic loop-carried SSA shape.
        if base_node is not None and getattr(base_node, "is_phi", False):
            return True

        # Base is formula node whose variable shares logical storage.
        base_var = _unwrap_var(base)

        if self.same_storage(node.var, base_var):
            return True

        return False

    def mark_induction(self, node, base=None, step=None):

        node.is_induction = True
        node.semantic_role = "loop_induction"
        node.induction_base = base
        node.induction_step = step
        node.induction_step_value = _const_value(step)

        if node not in self.induction_nodes:
            self.induction_nodes.append(node)

        try:
            node.var.is_induction_variable = True
            node.var.semantic_role = "loop_induction"
            node.var.induction_base = base
            node.var.induction_step = step
            node.var.induction_step_value = node.induction_step_value
        except Exception:
            pass


    # ---------------------------------------------------------
    # SGL CONDITION CONSUMER INGESTION
    # ---------------------------------------------------------

    def consume_sgl_condition_consumers(self):
        """
        Index frozen SGL condition consumers against the semantic graph.

        This pass does not change formulas.  It annotates condition roots and
        captures dependency/temp references for PHIfolder metadata closure.
        """

        consumers = list(getattr(self.func, "sgl_condition_consumers", []) or [])
        self.sgl_condition_consumers = consumers
        self.sgl_condition_consumer_index = {}
        self.sgl_condition_dependency_sids = {}
        self.sgl_condition_temp_refs = []

        seen_temp = set()

        for idx, rec in enumerate(consumers):
            cond_sid = rec.get("cond_sid")
            addr = rec.get("addr")
            expr = str(rec.get("cond_expr") or "")

            key = (addr, rec.get("kind"), rec.get("role"), cond_sid, expr)
            self.sgl_condition_consumer_index.setdefault(addr, []).append({
                "index": idx,
                "kind": rec.get("kind"),
                "role": rec.get("role"),
                "cond_sid": cond_sid,
                "cond_expr": expr,
            })

            deps = set()
            if cond_sid is not None:
                deps = self._collect_dependency_sids(cond_sid)
                self.sgl_condition_dependency_sids[cond_sid] = deps

                node = self.var_nodes.get(cond_sid)
                if node is not None:
                    try:
                        node.sgl_condition_consumer = True
                        node.sgl_condition_consumer_record = rec
                        node.sgl_condition_dependency_sids = set(deps)
                    except Exception:
                        pass

            for sid in self._extract_temp_sids_from_expr(expr):
                tkey = (sid, addr, expr)
                if tkey in seen_temp:
                    continue
                seen_temp.add(tkey)
                node = self.var_nodes.get(sid)
                self.sgl_condition_temp_refs.append({
                    "sid": sid,
                    "name": _canonical_ssa_name_v29(sid),
                    "consumer_addr": addr,
                    "consumer_kind": rec.get("kind"),
                    "consumer_role": rec.get("role"),
                    "condition_expr": expr,
                    "has_formula_node": node is not None,
                    "opcode": getattr(node, "opcode", None) if node is not None else None,
                    "block_addr": getattr(node, "block_addr", None) if node is not None else None,
                })

        self.semantic_events.append({
            "kind": "sgl_condition_consumers_ingested",
            "count": len(consumers),
            "temp_refs": len(self.sgl_condition_temp_refs),
        })

    def _extract_temp_sids_from_expr(self, expr):
        out = set()
        if not expr:
            return out
        for raw in re.findall(r"\bv_(\d+)\b", str(expr)):
            try:
                out.add(int(raw))
            except Exception:
                pass
        return out

    def _collect_dependency_sids(self, root_sid):
        deps = set()
        stack = [root_sid]

        while stack:
            sid = stack.pop()
            if sid is None or sid in deps:
                continue

            deps.add(sid)
            node = self.var_nodes.get(sid)
            if node is None:
                continue

            for inp in list(getattr(node, "inputs", []) or []):
                isid = _sid(inp)
                if isid is not None and isid not in deps:
                    stack.append(isid)

        return deps



    # ---------------------------------------------------------
    # v24 SGL STRUCTURING METADATA HANDOFF
    # ---------------------------------------------------------

    def build_sgl_structuring_metadata(self):
        """
        Build metadata-only custody payloads for PALSGLdecomp.

        This pass deliberately avoids creating structured control flow.  It
        exports facts SGL can consume before applying its branch/latch
        heuristics:
            - per-block branch custody and raw/HF successor divergence hints;
            - per-edge condition polarity/trust records;
            - induction/latch update indexes keyed by block and loop header;
            - block ownership/join/gateway hints.
        """

        self.block_branch_custody = {}
        self.edge_condition_truth = {}
        self.edge_truth = {}
        self.edge_truth_by_src = {}
        self.edge_truth_by_dst = {}
        self.edge_truth_predicates = {}
        self.edge_truth_profiles = {}
        self.edge_truth_debug = []
        self.edge_truth_inventory_v38 = {}
        self.edge_truth_version = (
            "PALSemanticGraphBuilder_v38_EdgeTruth_"
            "clothed_emperor_tristate_custody"
        )
        self.semantic_multiway_dispatch_facts = []
        self.semantic_multiway_dispatch_by_block = {}
        self.semantic_multiway_dispatch_inventory = {}
        self.semantic_multiway_dispatch_events = []
        self.induction_updates_by_block = {}
        self.latch_update_facts = {}
        self.block_ownership_facts = {}
        self.suspicious_successor_custody = []
        self.sgl_structuring_handoff = {}

        self.build_block_branch_custody()
        self.build_edge_condition_truth()
        self.build_edge_truth()
        self.build_induction_update_indexes()
        self.build_block_ownership_facts()
        self.build_multiway_dispatch_semantics_v31()
        self.detect_suspicious_successor_custody()

        self.sgl_structuring_handoff = {
            "version": (
                "PALSemanticGraphBuilder_v38_clothed_emperor_"
                "edgetruth_tristate_handoff"
            ),
            "block_branch_custody": self.block_branch_custody,
            "edge_condition_truth": self.edge_condition_truth,
            "edge_truth_version": self.edge_truth_version,
            "edge_truth": self.edge_truth,
            "edge_truth_by_src": self.edge_truth_by_src,
            "edge_truth_by_dst": self.edge_truth_by_dst,
            "edge_truth_predicates": self.edge_truth_predicates,
            "edge_truth_profiles": self.edge_truth_profiles,
            "edge_truth_debug": self.edge_truth_debug,
            "edge_truth_inventory_v38": self.edge_truth_inventory_v38,
            "multiway_dispatch_version": self.multiway_dispatch_version,
            "multiway_dispatch_facts": self.semantic_multiway_dispatch_facts,
            "multiway_dispatch_by_block": self.semantic_multiway_dispatch_by_block,
            "multiway_dispatch_inventory": self.semantic_multiway_dispatch_inventory,
            "multiway_dispatch_events": self.semantic_multiway_dispatch_events,
            "induction_updates_by_block": self.induction_updates_by_block,
            "latch_update_facts": self.latch_update_facts,
            "block_ownership_facts": self.block_ownership_facts,
            "suspicious_successor_custody": self.suspicious_successor_custody,
            "snapshot_copy_version_v35": self.snapshot_copy_version_v35,
            "snapshot_copy_contracts_v35": dict(self.snapshot_copy_contracts_v35),
            "snapshot_copy_projection_names_by_sid_v35": dict(
                self.snapshot_copy_projection_names_by_sid_v35
            ),
            "snapshot_copy_inventory_v35": dict(self.snapshot_copy_inventory_v35),
            "phi_predecessor_linkage_version_v37": (
                self.phi_predecessor_linkage_version_v37
            ),
            "phi_predecessor_bindings_v37": list(
                self.phi_predecessor_bindings_v37
            ),
            "phi_predecessor_bindings_by_edge_v37": {
                key: list(value)
                for key, value in self.phi_predecessor_bindings_by_edge_v37.items()
            },
            "phi_transition_descriptions_v37": list(
                self.phi_transition_descriptions_v37
            ),
            "phi_transition_by_edge_v37": {
                key: list(value)
                for key, value in self.phi_transition_by_edge_v37.items()
            },
            "phi_predecessor_linkage_inventory_v37": dict(
                self.phi_predecessor_linkage_inventory_v37
            ),
        }

        self.semantic_events.append({
            "kind": "sgl_structuring_metadata_built_v24",
            "contract_patch": "clothed_emperor_v38",
            "tri_state_edge_truth": True,
            "block_branch_custody": len(self.block_branch_custody),
            "edge_condition_truth": len(self.edge_condition_truth),
            "edge_truth_version": self.edge_truth_version,
            "edge_truth": len(self.edge_truth),
            "edge_truth_by_src": len(self.edge_truth_by_src),
            "edge_truth_by_dst": len(self.edge_truth_by_dst),
            "edge_truth_predicates": len(self.edge_truth_predicates),
            "edge_truth_profiles": len(self.edge_truth_profiles),
            "edge_truth_debug": len(self.edge_truth_debug),
            "edge_truth_inventory_v38": dict(self.edge_truth_inventory_v38),
            "phi_predecessor_bindings_v37": len(
                self.phi_predecessor_bindings_v37
            ),
            "phi_transition_descriptions_v37": len(
                self.phi_transition_descriptions_v37
            ),
            "phi_predecessor_linkage_failures_v37": len(
                self.phi_predecessor_linkage_failures_v37
            ),
            "semantic_multiway_dispatches": len(
                self.semantic_multiway_dispatch_facts
            ),
            "semantic_multiway_dispatch_resolved": int(
                self.semantic_multiway_dispatch_inventory.get("resolved", 0) or 0
            ),
            "semantic_multiway_dispatch_unresolved": int(
                self.semantic_multiway_dispatch_inventory.get("unresolved", 0) or 0
            ),
            "induction_update_blocks": len(self.induction_updates_by_block),
            "latch_update_loops": len(self.latch_update_facts),
            "ownership_blocks": len(self.block_ownership_facts),
            "suspicious_custody": len(self.suspicious_successor_custody),
        })

    def build_block_branch_custody(self):
        """
        Export a block-address keyed view of each conditional block's outgoing
        edge custody.  SGL should be able to answer: which successor is raw
        true/false, which one is fallthrough/explicit target, and whether PALRAW
        or FunctionCFG marked the successor set as suspicious.
        """

        for cfg_node in self._cfg_nodes_v24():
            block = getattr(cfg_node, "block", None)
            term = getattr(block, "terminator", None) if block is not None else None
            addr = self._cfg_addr_v24(cfg_node)

            if addr is None:
                continue

            cond = self._terminator_condition_v24(term)
            cond_sid = getattr(cond, "ssa_id", None) if cond is not None else None
            cond_node = self.var_nodes.get(cond_sid) if cond_sid is not None else None

            edge_records = []
            for e in self._edge_list_v24(cfg_node):
                dst = getattr(e, "dst", None)
                edge_records.append(self._edge_record_v24(e, cfg_node, dst, cond_node))

            roles = [r.get("role") for r in edge_records if r.get("role")]
            statuses = [str(r.get("status") or r.get("palraw_status") or "").lower() for r in edge_records]
            successors_differ = any(
                ("successors_differ" in s or "mismatch" in s) for s in statuses
            )
            order_fallback = any("order_fallback" in str(r or "") for r in roles)

            hf_extra = [
                r.get("dst") for r in edge_records
                if "order_fallback" in str(r.get("role") or "")
            ]

            self.block_branch_custody[addr] = {
                "block_addr": addr,
                "block_hex": _safe_hex(addr),
                "has_condition": cond is not None,
                "condition_sid": cond_sid,
                "condition_name": getattr(cond, "name", None) if cond is not None else None,
                "condition_opcode": getattr(cond_node, "opcode", None) if cond_node is not None else None,
                "condition_expr": self._formula_metadata_expr_v34(cond_node)[0] if cond_node is not None else None,
                "condition_identity_status": self._formula_metadata_expr_v34(cond_node)[1] if cond_node is not None else "not_applicable",
                "condition_expr_authoritative": self._formula_metadata_expr_v34(cond_node)[2] if cond_node is not None else False,
                "terminal_opcode": getattr(term, "opcode", None) if term is not None else None,
                "terminal_target": self._terminator_target_addr_v24(term),
                "terminal_mnemonic": self._terminal_mnemonic_v24(cfg_node),
                "edges": edge_records,
                "roles": roles,
                "successors_differ": bool(successors_differ or order_fallback),
                "successors_match": False if successors_differ else (None if not edge_records else not order_fallback),
                "hf_extra_successors": hf_extra,
                "raw_missing_successors": [],
                "custody_hint": self._custody_hint_from_edges_v24(edge_records),
            }

    def build_edge_condition_truth(self):
        """
        Build per-edge condition expressions.  Each record says what expression
        is true when execution takes src -> dst, using edge polarity metadata
        when present and narrow mnemonic/opcode inference when absent.
        """

        for cfg_node in self._cfg_nodes_v24():
            block = getattr(cfg_node, "block", None)
            term = getattr(block, "terminator", None) if block is not None else None
            if getattr(term, "opcode", None) != "CBRANCH":
                continue

            src = self._cfg_addr_v24(cfg_node)
            if src is None:
                continue

            cond = self._terminator_condition_v24(term)
            cond_sid = getattr(cond, "ssa_id", None) if cond is not None else None
            cond_node = self.var_nodes.get(cond_sid) if cond_sid is not None else None
            hf_expr, identity_status, identity_authoritative = self._formula_metadata_expr_v34(cond_node) if cond_node is not None else (None, "not_applicable", False)
            opcode = getattr(cond_node, "opcode", None) if cond_node is not None else None
            mnemonic = self._terminal_mnemonic_v24(cfg_node)

            for e in self._edge_list_v24(cfg_node):
                dst_node = getattr(e, "dst", None)
                dst = self._cfg_addr_v24(dst_node)
                if dst is None:
                    continue

                explicit_invert = self._edge_condition_invert_attr_v24(e)
                upstream_unresolved = (
                    self._edge_truth_upstream_unresolved_v38(e)
                )
                if upstream_unresolved:
                    inferred_invert = None
                    inferred_reason = upstream_unresolved
                else:
                    inferred_invert, inferred_reason = self._infer_edge_invert_v24(
                        e, mnemonic, opcode, hf_expr
                    )

                if isinstance(explicit_invert, bool):
                    invert = explicit_invert
                    reason = self._edge_condition_reason_v24(e) or "edge_condition_invert_attr"
                    trust = "edge_metadata"
                elif isinstance(inferred_invert, bool):
                    invert = inferred_invert
                    reason = inferred_reason or self._edge_condition_reason_v24(e)
                    trust = "mnemonic_opcode_inferred"
                else:
                    invert = None
                    reason = (
                        inferred_reason
                        or self._edge_condition_reason_v24(e)
                        or "unresolved_edge_polarity_v38"
                    )
                    trust = "unresolved_edge_polarity_v38"

                polarity_resolved = isinstance(invert, bool)
                predicate_authoritative = bool(
                    identity_authoritative
                    and polarity_resolved
                    and hf_expr is not None
                )
                edge_expr = (
                    self._edge_truth_apply_invert_v25(hf_expr, invert)
                    if predicate_authoritative else None
                )

                status = self._edge_status_v24(e)
                if status and ("differ" in str(status).lower() or "mismatch" in str(status).lower()):
                    trust = "raw_hf_divergence_requires_sgl_care"

                if not identity_authoritative:
                    predicate_status = identity_status
                    trust = "unresolved_operand_identity_collision_v34"
                elif not polarity_resolved:
                    predicate_status = "unresolved_edge_polarity_v38"
                elif hf_expr is None:
                    predicate_status = "missing_hf_expression_v38"
                else:
                    predicate_status = "resolved_authoritative_v38"

                edge_identity = self._cfg_edge_identity_record_v37(
                    e, src, dst
                )
                self.edge_condition_truth[(src, dst)] = {
                    "edge_id_schema": edge_identity.get(
                        "id_schema", "cfg_edge_identity_v1"
                    ),
                    "edge_id": list(
                        edge_identity.get("edge_id", [src, dst])
                    ),
                    "edge_key": (
                        edge_identity.get("edge_key")
                        or self._phi_edge_key_v37(src, dst)
                    ),
                    "edge_identity_frozen": bool(
                        edge_identity.get("edge_identity_frozen", False)
                    ),
                    "direct_to_join": bool(
                        edge_identity.get("direct_to_join", False)
                    ),
                    "direct_join_owner_kind": edge_identity.get(
                        "direct_join_owner_kind"
                    ),
                    "direct_join_empty_arm_candidate": bool(
                        edge_identity.get(
                            "direct_join_empty_arm_candidate", False
                        )
                    ),
                    "src": src,
                    "src_hex": _safe_hex(src),
                    "dst": dst,
                    "dst_hex": _safe_hex(dst),
                    "condition_sid": cond_sid,
                    "condition_opcode": opcode,
                    "hf_expr": hf_expr,
                    "edge_expr": edge_expr,
                    "predicate_status": predicate_status,
                    "operand_identity_status": identity_status,
                    "predicate_authoritative": predicate_authoritative,
                    "predicate_holds_means_take_edge": predicate_authoritative,
                    "polarity_resolved": polarity_resolved,
                    "upstream_edge_truth_unresolved": bool(
                        upstream_unresolved
                    ),
                    "invert_for_edge": invert,
                    "invert_source": reason,
                    "trust": trust,
                    "mnemonic": mnemonic,
                    "role": getattr(e, "role", None),
                    "raw_type": getattr(e, "raw_type", getattr(e, "type", None)),
                    "explicit_target": bool(getattr(e, "explicit_target", False) or getattr(e, "is_explicit_target", False)),
                    "fallthrough": bool(getattr(e, "fallthrough", False) or getattr(e, "is_fallthrough", False)),
                    "backedge": bool(getattr(e, "backedge", False) or getattr(e, "is_backedge", False)),
                    "loop_exit": bool(getattr(e, "loop_exit", False) or getattr(e, "is_loop_exit", False)),
                    "status": status,
                }


    def build_edge_truth(self):
        """
        v25 EdgeTruth compiler.

        EdgeTruth is the canonical branch-polarity contract exported by the
        semantic graph.  It is deliberately edge-keyed:

            (src_block_addr, dst_block_addr) -> predicate for taking src -> dst

        This pass does not structure control flow and does not rewrite Python.
        It only reconciles ASM mnemonic evidence, raw/CFG target/fallthrough
        custody, edge metadata, and HighFunction comparison expressions into an
        auditable per-edge record.  SGL can later consume this table instead of
        asking for a block-level condition.
        """

        self.edge_truth = {}
        self.edge_truth_by_src = {}
        self.edge_truth_by_dst = {}
        self.edge_truth_predicates = {}
        self.edge_truth_profiles = {}
        self.edge_truth_debug = []
        self.edge_truth_inventory_v38 = {}
        self.edge_truth_version = (
            "PALSemanticGraphBuilder_v38_EdgeTruth_"
            "clothed_emperor_tristate_custody"
        )

        for cfg_node in self._cfg_nodes_v24():
            block = getattr(cfg_node, "block", None)
            term = getattr(block, "terminator", None) if block is not None else None
            if getattr(term, "opcode", None) != "CBRANCH":
                continue

            src = self._cfg_addr_v24(cfg_node)
            if src is None:
                continue

            cond = self._terminator_condition_v24(term)
            cond_sid = getattr(cond, "ssa_id", None) if cond is not None else None
            cond_node = self.var_nodes.get(cond_sid) if cond_sid is not None else None
            hf_expr, identity_status, identity_authoritative = self._formula_metadata_expr_v34(cond_node) if cond_node is not None else (None, "not_applicable", False)
            opcode = getattr(cond_node, "opcode", None) if cond_node is not None else None
            mnemonic = self._terminal_mnemonic_v24(cfg_node)
            terminal_target = self._terminator_target_addr_v24(term)

            edges = [e for e in self._edge_list_v24(cfg_node) if self._cfg_addr_v24(getattr(e, "dst", None)) is not None]

            # v28: terminal_mnemonic is often absent even though the same
            # evidence survives on edge metadata or inside v24 reason strings
            # such as "mnemonic=JLE hf_cond_opcode=INT_SLESS".  Build a
            # branch-level effective mnemonic before comparing ASM-vs-HF
            # polarity, and keep the raw terminal value for audit.
            effective_mnemonic = self._edge_truth_effective_mnemonic_for_edges_v28(
                edges,
                mnemonic=mnemonic,
            )

            branch_profile = self._branch_truth_profile_v25(
                cfg_node=cfg_node,
                term=term,
                edges=edges,
                mnemonic=effective_mnemonic,
                opcode=opcode,
                hf_expr=hf_expr,
                terminal_target=terminal_target,
            )
            branch_profile["condition_sid"] = cond_sid
            branch_profile["condition_opcode"] = opcode
            branch_profile["hf_expr"] = hf_expr
            branch_profile["mnemonic"] = effective_mnemonic
            branch_profile["terminal_mnemonic_raw"] = mnemonic
            branch_profile["effective_mnemonic"] = effective_mnemonic
            self.edge_truth_profiles[src] = dict(branch_profile)

            for e in edges:
                dst_node = getattr(e, "dst", None)
                dst = self._cfg_addr_v24(dst_node)
                if dst is None:
                    continue

                legacy = dict(self.edge_condition_truth.get((src, dst), {}) or {})
                selected = self._select_edge_truth_v25(
                    e=e,
                    src=src,
                    dst=dst,
                    branch_profile=branch_profile,
                    legacy=legacy,
                    hf_expr=hf_expr,
                    opcode=opcode,
                    mnemonic=branch_profile.get("effective_mnemonic") or mnemonic,
                )

                invert = self._edge_truth_tristate_bool_v38(
                    selected.get("invert_for_edge")
                )
                polarity_resolved = isinstance(invert, bool)
                predicate_authoritative = bool(
                    identity_authoritative
                    and polarity_resolved
                    and hf_expr is not None
                )
                predicate = (
                    self._edge_truth_apply_invert_v25(hf_expr, invert)
                    if predicate_authoritative else None
                )
                inverse = (
                    self._edge_truth_apply_invert_v25(hf_expr, not invert)
                    if predicate_authoritative else None
                )

                if not identity_authoritative:
                    predicate_status = identity_status
                    selection_source = "operand_identity_gate_v34"
                    selection_reason = identity_status
                    confidence = "unresolved"
                elif not polarity_resolved:
                    predicate_status = "unresolved_edge_polarity_v38"
                    selection_source = (
                        selected.get("source")
                        or "unresolved_edge_polarity_v38"
                    )
                    selection_reason = (
                        selected.get("reason")
                        or "no_authoritative_edge_polarity_v38"
                    )
                    confidence = "unresolved"
                elif hf_expr is None:
                    predicate_status = "missing_hf_expression_v38"
                    selection_source = "hf_expression_gate_v38"
                    selection_reason = "missing_hf_expression_v38"
                    confidence = "unresolved"
                else:
                    predicate_status = "resolved_authoritative_v38"
                    selection_source = selected.get("source")
                    selection_reason = selected.get("reason")
                    confidence = selected.get("confidence")

                role = getattr(e, "role", None)
                raw_type = getattr(e, "raw_type", getattr(e, "type", None))
                status = self._edge_status_v24(e)
                explicit = self._edge_is_explicit_target_v25(e, dst, terminal_target)
                fallthrough = self._edge_is_fallthrough_v25(e, dst, terminal_target, edges)

                edge_identity = self._cfg_edge_identity_record_v37(
                    e, src, dst
                )
                rec = {
                    "version": self.edge_truth_version,
                    "edge_id_schema": edge_identity.get(
                        "id_schema", "cfg_edge_identity_v1"
                    ),
                    "edge_id": list(
                        edge_identity.get("edge_id", [src, dst])
                    ),
                    "edge_key": (
                        edge_identity.get("edge_key")
                        or self._phi_edge_key_v37(src, dst)
                    ),
                    "edge_identity_frozen": bool(
                        edge_identity.get("edge_identity_frozen", False)
                    ),
                    "direct_to_join": bool(
                        edge_identity.get("direct_to_join", False)
                    ),
                    "direct_join_owner_kind": edge_identity.get(
                        "direct_join_owner_kind"
                    ),
                    "direct_join_empty_arm_candidate": bool(
                        edge_identity.get(
                            "direct_join_empty_arm_candidate", False
                        )
                    ),
                    "src": src,
                    "src_hex": _safe_hex(src),
                    "dst": dst,
                    "dst_hex": _safe_hex(dst),

                    # Canonical contract.
                    "predicate": predicate,
                    "edge_expr": predicate,
                    "inverse_predicate": inverse,
                    "predicate_holds_means_take_edge": predicate_authoritative,
                    "predicate_status": predicate_status,
                    "operand_identity_status": identity_status,
                    "predicate_authoritative": predicate_authoritative,
                    "polarity_resolved": polarity_resolved,
                    "upstream_edge_truth_unresolved": bool(
                        self._edge_truth_upstream_unresolved_v38(e)
                    ),
                    "invert_for_edge": invert,
                    "selection_source": selection_source,
                    "selection_reason": selection_reason,
                    "confidence": confidence,

                    # HF / semantic expression evidence.
                    "condition_sid": cond_sid,
                    "condition_name": getattr(cond, "name", None) if cond is not None else None,
                    "condition_opcode": opcode,
                    "hf_expr": hf_expr,
                    "hf_relation": branch_profile.get("hf_relation"),
                    "hf_relation_family": branch_profile.get("hf_relation_family"),

                    # ASM/raw/CFG edge evidence.
                    "mnemonic": branch_profile.get("effective_mnemonic") or mnemonic,
                    "terminal_mnemonic_raw": branch_profile.get("terminal_mnemonic_raw"),
                    "effective_mnemonic": branch_profile.get("effective_mnemonic") or mnemonic,
                    "mnemonic_relation": branch_profile.get("mnemonic_relation"),
                    "mnemonic_relation_family": branch_profile.get("mnemonic_relation_family"),
                    "mnemonic_vs_hf": branch_profile.get("mnemonic_vs_hf"),
                    "terminal_target": terminal_target,
                    "terminal_target_hex": _safe_hex(terminal_target),
                    "taken_edge_dst": branch_profile.get("taken_edge_dst"),
                    "taken_edge_dst_hex": _safe_hex(branch_profile.get("taken_edge_dst")),
                    "fallthrough_edge_dst": branch_profile.get("fallthrough_edge_dst"),
                    "fallthrough_edge_dst_hex": _safe_hex(branch_profile.get("fallthrough_edge_dst")),
                    "is_taken_edge": bool(selected.get("is_taken_edge")),
                    "is_fallthrough_edge": bool(selected.get("is_fallthrough_edge")),
                    "edge_role": role,
                    "role": role,
                    "raw_type": raw_type,
                    "explicit_target": bool(explicit),
                    "fallthrough": bool(fallthrough),
                    "backedge": bool(getattr(e, "backedge", False) or getattr(e, "is_backedge", False)),
                    "loop_exit": bool(getattr(e, "loop_exit", False) or getattr(e, "is_loop_exit", False)),
                    "status": status,
                    "peer_dsts": [d for d in branch_profile.get("successors", []) if d != dst],
                    "edge_count": branch_profile.get("edge_count"),
                    "successors": list(branch_profile.get("successors", []) or []),

                    # Legacy compatibility and audit.
                    "legacy_edge_condition_truth": legacy,
                    "legacy_edge_expr": legacy.get("edge_expr"),
                    "legacy_invert_for_edge": legacy.get("invert_for_edge"),
                    "legacy_trust": legacy.get("trust"),
                    "explicit_invert_attr": self._edge_condition_invert_attr_v24(e),
                    "condition_polarity": getattr(e, "condition_polarity", None),
                    "edge_condition_reason": self._edge_condition_reason_v24(e),
                    "truth_votes": list(selected.get("votes", []) or []),
                    "divergence": dict(selected.get("divergence", {}) or {}),
                }

                if not polarity_resolved:
                    rec["divergence"].setdefault(
                        "unresolved_edge_polarity_v38",
                        {
                            "source": selection_source,
                            "reason": selection_reason,
                            "rule": (
                                "topology_does_not_authorize_predicate_"
                                "orientation"
                            ),
                        },
                    )

                self.edge_truth[(src, dst)] = rec
                self.edge_truth_by_src.setdefault(src, []).append(rec)
                self.edge_truth_by_dst.setdefault(dst, []).append(rec)
                self.edge_truth_predicates[(src, dst)] = predicate

                if self._edge_truth_record_needs_debug_v25(rec):
                    self.edge_truth_debug.append(self._edge_truth_debug_record_v25(rec))

        records = list(self.edge_truth.values())
        self.edge_truth_inventory_v38 = {
            "version": self.edge_truth_version,
            "total": len(records),
            "predicate_authoritative": sum(
                1 for rec in records
                if rec.get("predicate_authoritative") is True
            ),
            "predicate_unresolved": sum(
                1 for rec in records
                if rec.get("predicate_authoritative") is not True
            ),
            "polarity_unresolved": sum(
                1 for rec in records
                if not isinstance(rec.get("invert_for_edge"), bool)
            ),
            "operand_identity_unresolved": sum(
                1 for rec in records
                if rec.get("operand_identity_status")
                == "unresolved_operand_identity_collision_v34"
            ),
            "direct_join_polarity_unresolved": sum(
                1 for rec in records
                if rec.get("direct_to_join")
                and not isinstance(rec.get("invert_for_edge"), bool)
            ),
        }

        self.semantic_events.append({
            "kind": "edge_truth_built_v38_clothed_emperor",
            "edge_truth_version": self.edge_truth_version,
            "edge_truth": len(self.edge_truth),
            "edge_truth_by_src": len(self.edge_truth_by_src),
            "edge_truth_by_dst": len(self.edge_truth_by_dst),
            "edge_truth_predicates": len(self.edge_truth_predicates),
            "edge_truth_profiles": len(self.edge_truth_profiles),
            "debug_records": len(self.edge_truth_debug),
            "inventory": dict(self.edge_truth_inventory_v38),
            "tri_state_contract": True,
        })

    def _branch_truth_profile_v25(self, cfg_node, term, edges, mnemonic, opcode, hf_expr, terminal_target):
        """
        Build branch-level truth facts used by every outgoing edge.
        """

        dsts = [self._cfg_addr_v24(getattr(e, "dst", None)) for e in edges]
        dsts = [d for d in dsts if d is not None]

        taken_edge_dst = None
        if terminal_target is not None and terminal_target in dsts:
            taken_edge_dst = terminal_target

        if taken_edge_dst is None:
            for e in edges:
                dst = self._cfg_addr_v24(getattr(e, "dst", None))
                if dst is None:
                    continue
                if self._edge_is_explicit_target_v25(e, dst, terminal_target):
                    taken_edge_dst = dst
                    break

        fallthrough_edge_dst = None
        for e in edges:
            dst = self._cfg_addr_v24(getattr(e, "dst", None))
            if dst is None:
                continue
            if self._edge_is_fallthrough_v25(e, dst, terminal_target, edges):
                fallthrough_edge_dst = dst
                break

        if fallthrough_edge_dst is None and len(dsts) == 2 and taken_edge_dst in dsts:
            fallthrough_edge_dst = [d for d in dsts if d != taken_edge_dst][0]

        mnemonic_relation, mnemonic_family = self._mnemonic_relation_v25(mnemonic)
        hf_relation, hf_family = self._opcode_relation_v25(opcode, hf_expr)
        relation_cmp = self._compare_relations_v25(mnemonic_relation, hf_relation)

        taken_invert = None
        taken_invert_reason = None
        taken_invert_confidence = None

        if relation_cmp == "same":
            taken_invert = False
            taken_invert_reason = "asm_mnemonic_matches_hf_opcode"
            taken_invert_confidence = "high"
        elif relation_cmp == "complement":
            taken_invert = True
            taken_invert_reason = "asm_mnemonic_complements_hf_opcode"
            taken_invert_confidence = "high"
        elif relation_cmp == "same_family_unknown_polarity":
            taken_invert = None
            taken_invert_reason = (
                "asm_hf_same_family_unknown_polarity_unresolved_v38"
            )
            taken_invert_confidence = "unresolved"
        else:
            taken_invert = None
            taken_invert_reason = "asm_hf_relation_unknown"
            taken_invert_confidence = "low"

        return {
            "src": self._cfg_addr_v24(cfg_node),
            "terminal_target": terminal_target,
            "taken_edge_dst": taken_edge_dst,
            "fallthrough_edge_dst": fallthrough_edge_dst,
            "mnemonic": mnemonic,
            "mnemonic_relation": mnemonic_relation,
            "mnemonic_relation_family": mnemonic_family,
            "hf_relation": hf_relation,
            "hf_relation_family": hf_family,
            "mnemonic_vs_hf": relation_cmp,
            "taken_invert": taken_invert,
            "taken_invert_reason": taken_invert_reason,
            "taken_invert_confidence": taken_invert_confidence,
            "edge_count": len(edges),
            "successors": dsts,
        }

    def _select_edge_truth_v25(self, e, src, dst, branch_profile, legacy, hf_expr, opcode, mnemonic):
        """
        Select the predicate polarity for a single src -> dst edge.

        The selected predicate always means: if predicate is true, execution
        takes this exact edge.
        """

        votes = []
        divergence = {}

        explicit_invert = self._edge_condition_invert_attr_v24(e)
        upstream_unresolved = self._edge_truth_upstream_unresolved_v38(e)
        explicit = self._edge_is_explicit_target_v25(e, dst, branch_profile.get("terminal_target"))
        fallthrough = self._edge_is_fallthrough_v25(e, dst, branch_profile.get("terminal_target"), None)
        taken_edge_dst = branch_profile.get("taken_edge_dst")
        fallthrough_edge_dst = branch_profile.get("fallthrough_edge_dst")
        is_taken_edge = bool(dst == taken_edge_dst or explicit)
        is_fallthrough_edge = bool(dst == fallthrough_edge_dst or fallthrough)

        # v27: edge-level invert attributes are strong evidence, but in
        # optimized code they may be generated from the same too-broad
        # mnemonic/opcode complement rule we are trying to retire.  Before
        # accepting them as authoritative, allow a narrow normalized-bound
        # correction such as:
        #
        #     ASM: JLE taken edge   (x <= C-1)
        #     HF : INT_SLESS        (x < C)
        #
        # In that case the HF expression is already the taken-edge predicate
        # and must not be wrapped in not(...).
        norm_override = self._edge_truth_normalized_relational_override_v28(
            e=e,
            src=src,
            dst=dst,
            branch_profile=branch_profile,
            hf_expr=hf_expr,
            opcode=opcode,
            mnemonic=mnemonic,
            explicit_invert=explicit_invert,
            is_taken_edge=is_taken_edge,
            is_fallthrough_edge=is_fallthrough_edge,
            legacy=legacy,
        )
        if norm_override is not None:
            invert = self._edge_truth_tristate_bool_v38(
                norm_override.get("invert_for_edge")
            )
            if not isinstance(invert, bool):
                norm_override = None
        if norm_override is not None:
            votes.append({
                "source": "normalized_relational_override_v28",
                "invert": invert,
                "confidence": norm_override.get("confidence", "high"),
                "reason": norm_override.get("reason"),
            })
            if explicit_invert is not None and explicit_invert != invert:
                divergence["explicit_edge_invert_overridden_v28"] = {
                    "explicit_invert": explicit_invert,
                    "normalized_invert": invert,
                    "reason": norm_override.get("reason"),
                }
            return {
                "invert_for_edge": invert,
                "source": "normalized_relational_override_v28",
                "reason": norm_override.get("reason"),
                "confidence": norm_override.get("confidence", "high"),
                "votes": votes,
                "divergence": divergence,
                "is_taken_edge": is_taken_edge,
                "is_fallthrough_edge": is_fallthrough_edge,
            }

        if explicit_invert is not None:
            invert = explicit_invert
            votes.append({"source": "edge_condition_invert_attr", "invert": invert, "confidence": "authoritative"})
            return {
                "invert_for_edge": invert,
                "source": "edge_metadata",
                "reason": self._edge_condition_reason_v24(e) or "edge_condition_invert_attr",
                "confidence": "authoritative",
                "votes": votes,
                "divergence": divergence,
                "is_taken_edge": is_taken_edge,
                "is_fallthrough_edge": is_fallthrough_edge,
            }

        # FunctionCFG/EdgeTruth may deliberately publish a tri-state result.
        # Its explicit unresolved verdict is a veto on SemanticGraph's older
        # mnemonic/opcode and CFG-shape compatibility heuristics.
        if upstream_unresolved:
            divergence["upstream_edge_truth_unresolved_v38"] = {
                "reason": upstream_unresolved,
                "condition_invert_for_edge": explicit_invert,
            }
            votes.append({
                "source": "upstream_edge_truth_unresolved_v38",
                "invert": None,
                "confidence": "unresolved",
                "reason": upstream_unresolved,
            })
            return {
                "invert_for_edge": None,
                "source": "upstream_edge_truth_unresolved_v38",
                "reason": upstream_unresolved,
                "confidence": "unresolved",
                "votes": votes,
                "divergence": divergence,
                "is_taken_edge": is_taken_edge,
                "is_fallthrough_edge": is_fallthrough_edge,
            }

        taken_invert = branch_profile.get("taken_invert")
        taken_reason = branch_profile.get("taken_invert_reason")
        taken_conf = branch_profile.get("taken_invert_confidence") or "low"

        if taken_invert is not None:
            if is_taken_edge:
                invert = taken_invert
                reason = "taken_edge:%s" % taken_reason
                votes.append({"source": "asm_hf_relation_taken_edge", "invert": invert, "confidence": taken_conf})
                return {
                    "invert_for_edge": invert,
                    "source": "asm_raw_hf_edge_relation",
                    "reason": reason,
                    "confidence": taken_conf,
                    "votes": votes,
                    "divergence": divergence,
                    "is_taken_edge": is_taken_edge,
                    "is_fallthrough_edge": is_fallthrough_edge,
                }
            if is_fallthrough_edge:
                invert = not taken_invert
                reason = "fallthrough_complement_of_taken_edge:%s" % taken_reason
                votes.append({"source": "asm_hf_relation_fallthrough_edge", "invert": invert, "confidence": taken_conf})
                return {
                    "invert_for_edge": invert,
                    "source": "asm_raw_hf_edge_relation",
                    "reason": reason,
                    "confidence": taken_conf,
                    "votes": votes,
                    "divergence": divergence,
                    "is_taken_edge": is_taken_edge,
                    "is_fallthrough_edge": is_fallthrough_edge,
                }

        # Legacy v24 truth is retained as a compatibility fallback.  This keeps
        # existing known-good metadata available while v25 exposes richer audit
        # fields for SGL integration.
        if legacy and legacy.get("edge_expr") is not None:
            invert = self._edge_truth_tristate_bool_v38(
                legacy.get("invert_for_edge")
            )
            if isinstance(invert, bool):
                votes.append({"source": "legacy_edge_condition_truth_v24", "invert": invert, "confidence": legacy.get("trust")})
                if str(legacy.get("trust") or "").startswith("raw_hf_divergence"):
                    divergence["legacy_raw_hf_divergence"] = True
                return {
                    "invert_for_edge": invert,
                    "source": "legacy_edge_condition_truth_v24",
                    "reason": legacy.get("invert_source") or legacy.get("trust") or "legacy_edge_truth",
                    "confidence": "medium",
                    "votes": votes,
                    "divergence": divergence,
                    "is_taken_edge": is_taken_edge,
                    "is_fallthrough_edge": is_fallthrough_edge,
                }
            divergence["legacy_edge_truth_missing_boolean_polarity_v38"] = True

        # v38 clothed-emperor: CFG shape proves target/fallthrough topology,
        # never the truth orientation of a HighFunction predicate.  Preserve
        # unresolved polarity as None so downstream structure recovery cannot
        # silently turn uncertainty into a direct predicate.
        if is_taken_edge:
            reason = "taken_edge_topology_only_no_predicate_relation_v38"
        elif is_fallthrough_edge:
            reason = "fallthrough_topology_only_no_predicate_relation_v38"
        else:
            reason = "unclassified_edge_no_predicate_relation_v38"
            divergence["unclassified_successor_edge"] = True

        status = self._edge_status_v24(e)
        if status and ("differ" in str(status).lower() or "mismatch" in str(status).lower()):
            divergence["edge_status_divergence"] = str(status)

        divergence["unresolved_edge_polarity_v38"] = {
            "is_taken_edge": is_taken_edge,
            "is_fallthrough_edge": is_fallthrough_edge,
            "mnemonic_vs_hf": branch_profile.get("mnemonic_vs_hf"),
        }
        votes.append({
            "source": "unresolved_edge_polarity_v38",
            "invert": None,
            "confidence": "unresolved",
            "reason": reason,
        })
        return {
            "invert_for_edge": None,
            "source": "unresolved_edge_polarity_v38",
            "reason": reason,
            "confidence": "unresolved",
            "votes": votes,
            "divergence": divergence,
            "is_taken_edge": is_taken_edge,
            "is_fallthrough_edge": is_fallthrough_edge,
        }

    def _edge_truth_normalized_relational_override_v28(self, e, src, dst, branch_profile, hf_expr, opcode, mnemonic,
                                                        explicit_invert=None, is_taken_edge=False, is_fallthrough_edge=False,
                                                        legacy=None):
        """
        Correct the most common optimized-bound polarity trap before SGL sees it.

        Ghidra/HighFunction often normalizes inclusive machine bounds into an
        exclusive comparison by changing the constant, e.g.:

            machine branch:  JLE  body    ; x <= 2
            HF expression:   x < 3

        A naive mnemonic/opcode comparison sees JLE vs INT_SLESS and may mark
        the taken edge as inverted.  That is wrong when the HF expression is of
        the form value < constant (or value <= constant for the matching <=
        opcode): the HF expression already describes the inclusive taken edge.

        This is deliberately narrow.  It only fires for explicit/taken edges
        with a normal variable/expression on the left and a literal constant on
        the right.  The fallthrough edge gets the complement.
        """
        if hf_expr is None:
            return None

        # v28: use an effective mnemonic, not only the terminal field.
        # In optimized Ghidra/PAL paths the direct mnemonic can be None while
        # the real Jcc survives in edge metadata or legacy reason strings.
        m = self._edge_truth_effective_mnemonic_v28(
            e=e,
            branch_profile=branch_profile,
            mnemonic=mnemonic,
            legacy=legacy,
        )
        m = str(m or "").upper()
        op = str(opcode or "")
        shape = self._edge_truth_binary_compare_shape_v27(hf_expr)
        if not shape:
            return None

        rel = shape.get("op")
        left_is_const = bool(shape.get("left_is_const"))
        right_is_const = bool(shape.get("right_is_const"))

        # Direct normalized inclusive <= branch represented as x < C.
        # Signed:   JLE/JNG + INT_SLESS
        # Unsigned: JBE/JNA + INT_LESS
        direct_less_bound = (
            rel == "<"
            and right_is_const
            and not left_is_const
            and (
                (m in ("JLE", "JNG") and op == "INT_SLESS")
                or (m in ("JBE", "JNA") and op == "INT_LESS")
            )
        )

        # Direct normalized >= branch represented as C < x.  This is rarer, but
        # covers the symmetric form for compilers/Ghidra renderers that place
        # the adjusted literal on the left side.
        direct_greater_equal_bound = (
            rel == "<"
            and left_is_const
            and not right_is_const
            and (
                (m in ("JGE", "JNL") and op == "INT_SLESS")
                or (m in ("JAE", "JNB", "JNC") and op == "INT_LESS")
            )
        )

        if not (direct_less_bound or direct_greater_equal_bound):
            return None

        if not (is_taken_edge or is_fallthrough_edge):
            return None

        # For the taken edge, the HF predicate is direct.  For the fallthrough,
        # it is the complement.
        invert = False if is_taken_edge else True
        reason = "normalized_bound_direct_taken_v28:%s:%s:%s" % (m, op, rel)

        return {
            "invert_for_edge": invert,
            "reason": reason,
            "confidence": "high",
            "shape": shape,
            "overrode_explicit_invert": (
                explicit_invert is not None and explicit_invert != invert
            ),
        }

    def _edge_truth_effective_mnemonic_for_edges_v28(self, edges, mnemonic=None):
        """
        Derive a branch-level mnemonic from all surviving metadata.

        Some PAL/Ghidra paths do not expose terminal_mnemonic directly, while
        FunctionCFG/v24 edge metadata still carries strings like
        "mnemonic=JLE hf_cond_opcode=INT_SLESS".  EdgeTruth must consume that
        evidence before deciding polarity.
        """
        direct = self._edge_truth_extract_mnemonic_v28(mnemonic)
        if direct:
            return direct

        for e in list(edges or []):
            m = self._edge_truth_effective_mnemonic_v28(e=e, mnemonic=None)
            if m:
                return m
        return None

    def _edge_truth_effective_mnemonic_v28(self, e=None, branch_profile=None, mnemonic=None, legacy=None):
        """
        Return the best available Jcc mnemonic for polarity analysis.

        Order:
          1. explicit terminal/effective mnemonic passed by caller;
          2. branch profile effective/raw mnemonic;
          3. edge attributes;
          4. reason/status/role strings containing either "mnemonic=JLE" or
             a standalone Jcc token.
        """
        candidates = []
        candidates.append(mnemonic)

        if isinstance(branch_profile, dict):
            candidates.extend([
                branch_profile.get("effective_mnemonic"),
                branch_profile.get("mnemonic"),
                branch_profile.get("terminal_mnemonic_raw"),
                branch_profile.get("taken_invert_reason"),
                branch_profile.get("mnemonic_vs_hf"),
            ])

        if isinstance(legacy, dict):
            # v24 edge_condition_truth often carries the only surviving Jcc
            # evidence in fields such as invert_source/reason:
            # "mnemonic=JLE hf_cond_opcode=INT_SLESS".
            for key in (
                "mnemonic", "terminal_mnemonic", "raw_mnemonic", "branch_mnemonic",
                "invert_source", "reason", "selection_reason", "condition_reason",
                "trust", "status", "role", "raw_type",
            ):
                candidates.append(legacy.get(key))

        if e is not None:
            for attr in (
                "mnemonic", "branch_mnemonic", "terminal_mnemonic", "raw_mnemonic",
                "condition_mnemonic", "asm_mnemonic",
            ):
                try:
                    candidates.append(getattr(e, attr, None))
                except Exception:
                    pass
            candidates.extend([
                self._edge_condition_reason_v24(e),
                self._edge_status_v24(e),
                getattr(e, "condition_polarity", None),
                getattr(e, "role", None),
                getattr(e, "raw_type", getattr(e, "type", None)),
            ])

        for c in candidates:
            m = self._edge_truth_extract_mnemonic_v28(c)
            if m:
                return m
        return None

    def _edge_truth_extract_mnemonic_v28(self, value):
        """
        Extract Jcc from strings such as:
            JLE
            mnemonic=JLE hf_cond_opcode=INT_SLESS
            raw_mnemonic:JNZ
        """
        if value is None:
            return None
        s = str(value).upper()
        if not s or s in ("NONE", "NULL"):
            return None

        m = re.search(r"\bMNEMONIC\s*[=:]\s*(J[A-Z]+)\b", s)
        if m:
            return m.group(1)

        m = re.search(r"\b(?:RAW_|ASM_|BRANCH_|TERMINAL_|CONDITION_)?MNEMONIC\s*[=:]\s*(J[A-Z]+)\b", s)
        if m:
            return m.group(1)

        m = re.search(r"\bJ[A-Z]+\b", s)
        if m:
            return m.group(0)
        return None

    def _edge_truth_binary_compare_shape_v27(self, expr):
        """
        Very small parser for the metadata renderer's parenthesized binary
        comparisons.  It intentionally avoids full expression parsing; we only
        need to recognize whether a comparison is value < constant or
        constant < value for normalized-bound polarity.
        """
        s = str(expr or "").strip()
        if not s:
            return None

        # Peel redundant balanced outer parentheses.
        old = None
        while s != old and len(s) >= 2 and s[0] == "(" and s[-1] == ")":
            old = s
            inner = s[1:-1].strip()
            if self._edge_truth_balanced_parens_v27(inner):
                s = inner
            else:
                break

        # Locate a top-level relational operator.
        ops = ["<=", ">=", "==", "!=", "<", ">"]
        depth = 0
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == "(":
                depth += 1
                i += 1
                continue
            if ch == ")":
                depth -= 1
                i += 1
                continue
            if depth == 0:
                for op in ops:
                    if s.startswith(op, i):
                        left = s[:i].strip()
                        right = s[i + len(op):].strip()
                        if left and right:
                            return {
                                "left": left,
                                "op": op,
                                "right": right,
                                "left_is_const": self._edge_truth_expr_is_int_const_v27(left),
                                "right_is_const": self._edge_truth_expr_is_int_const_v27(right),
                            }
                i += 1
                continue
            i += 1
        return None

    def _edge_truth_balanced_parens_v27(self, s):
        depth = 0
        for ch in str(s or ""):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return False
        return depth == 0

    def _edge_truth_expr_is_int_const_v27(self, s):
        s = str(s or "").strip()
        if not s:
            return False
        if s.startswith("+"):
            s = s[1:]
        if s.startswith("-"):
            return self._edge_truth_expr_is_int_const_v27(s[1:])
        try:
            int(s, 0)
            return True
        except Exception:
            return False

    def _edge_is_explicit_target_v25(self, e, dst=None, terminal_target=None):
        if e is None:
            return False
        role = str(getattr(e, "role", None) or "").lower()
        raw_type = str(getattr(e, "raw_type", getattr(e, "type", None)) or "").lower()
        if bool(getattr(e, "explicit_target", False) or getattr(e, "is_explicit_target", False)):
            return True
        if "explicit" in role or "raw_true" in role or raw_type in ("true", "taken", "branch"):
            return True
        if terminal_target is not None and dst is not None and dst == terminal_target:
            return True
        return False

    def _edge_is_fallthrough_v25(self, e, dst=None, terminal_target=None, edges=None):
        if e is None:
            return False
        role = str(getattr(e, "role", None) or "").lower()
        raw_type = str(getattr(e, "raw_type", getattr(e, "type", None)) or "").lower()
        if bool(getattr(e, "fallthrough", False) or getattr(e, "is_fallthrough", False)):
            return True
        if "fallthrough" in role or raw_type in ("false", "fallthrough"):
            return True
        if terminal_target is not None and dst is not None and dst != terminal_target:
            # Only infer complement by address when this is a normal binary branch.
            if edges is None or len(list(edges or [])) == 2:
                return True
        return False

    def _mnemonic_relation_v25(self, mnemonic):
        m = str(mnemonic or "").upper()
        aliases = {
            "JZ": ("EQ", "eq"), "JE": ("EQ", "eq"),
            "JNZ": ("NE", "eq"), "JNE": ("NE", "eq"),
            "JL": ("SLT", "signed_order"), "JNGE": ("SLT", "signed_order"),
            "JGE": ("SGE", "signed_order"), "JNL": ("SGE", "signed_order"),
            "JLE": ("SLE", "signed_order"), "JNG": ("SLE", "signed_order"),
            "JG": ("SGT", "signed_order"), "JNLE": ("SGT", "signed_order"),
            "JB": ("ULT", "unsigned_order"), "JNAE": ("ULT", "unsigned_order"), "JC": ("ULT", "unsigned_order"),
            "JAE": ("UGE", "unsigned_order"), "JNB": ("UGE", "unsigned_order"), "JNC": ("UGE", "unsigned_order"),
            "JBE": ("ULE", "unsigned_order"), "JNA": ("ULE", "unsigned_order"),
            "JA": ("UGT", "unsigned_order"), "JNBE": ("UGT", "unsigned_order"),
            "JS": ("SIGN", "sign"),
            "JNS": ("NSIGN", "sign"),
        }
        return aliases.get(m, (None, None))

    def _opcode_relation_v25(self, opcode, expr=None):
        op = str(opcode or "")
        mapping = {
            "INT_EQUAL": ("EQ", "eq"),
            "FLOAT_EQUAL": ("EQ", "eq"),
            "INT_NOTEQUAL": ("NE", "eq"),
            "FLOAT_NOTEQUAL": ("NE", "eq"),
            "INT_SLESS": ("SLT", "signed_order"),
            "FLOAT_LESS": ("SLT", "signed_order"),
            "INT_LESS": ("ULT", "unsigned_order"),
            "INT_SLESSEQUAL": ("SLE", "signed_order"),
            "FLOAT_LESSEQUAL": ("SLE", "signed_order"),
            "INT_LESSEQUAL": ("ULE", "unsigned_order"),
        }
        if op in mapping:
            return mapping[op]

        # Conservative textual fallback for older FormulaNode renderers.
        s = str(expr or "")
        if "!=" in s:
            return ("NE", "eq")
        if "==" in s:
            return ("EQ", "eq")
        if "<=" in s:
            return ("LE", "unknown_order")
        if ">=" in s:
            return ("GE", "unknown_order")
        if "<" in s:
            return ("LT", "unknown_order")
        if ">" in s:
            return ("GT", "unknown_order")
        return (None, None)

    def _compare_relations_v25(self, mnemonic_relation, hf_relation):
        if mnemonic_relation is None or hf_relation is None:
            return "unknown"
        if mnemonic_relation == hf_relation:
            return "same"
        comp = {
            "EQ": "NE", "NE": "EQ",
            "SLT": "SGE", "SGE": "SLT",
            "SLE": "SGT", "SGT": "SLE",
            "ULT": "UGE", "UGE": "ULT",
            "ULE": "UGT", "UGT": "ULE",
            "SIGN": "NSIGN", "NSIGN": "SIGN",
        }
        if comp.get(hf_relation) == mnemonic_relation:
            return "complement"
        # Generic textual relation fallback.
        generic_comp = {"LT": "GE", "GE": "LT", "LE": "GT", "GT": "LE"}
        if generic_comp.get(hf_relation) == mnemonic_relation:
            return "complement"
        return "different"

    def _edge_truth_apply_invert_v25(self, expr, invert):
        if expr is None or not isinstance(invert, bool):
            return None
        if not invert:
            return expr
        return "not (%s)" % expr

    def _edge_truth_tristate_bool_v38(self, value):
        """
        Normalize only explicit boolean spellings without inventing polarity.

        ``None`` is a first-class EdgeTruth state.  In particular, never use
        ``bool(value)`` here: ``bool(None)`` would turn unresolved polarity into
        a proven direct predicate, while ``bool("False")`` would invert the
        textual meaning.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ("true", "1"):
                return True
            if normalized in ("false", "0"):
                return False
        return None

    def _edge_truth_upstream_unresolved_v38(self, e):
        """
        Return FunctionCFG's explicit unresolved EdgeTruth reason, if present.

        Do not treat every occurrence of the word ``unresolved`` as branch
        polarity evidence; restrict the veto to the branch/edge-custody
        classifications published by the current PALlibrary lineage.
        """
        if e is None:
            return None
        candidates = []
        for attr in (
            "condition_polarity_reason",
            "condition_polarity",
            "edge_truth_status",
            "edge_truth_reason",
            "status",
            "palraw_status",
            "raw_status",
            "successor_status",
        ):
            try:
                candidates.append(getattr(e, attr, None))
            except Exception:
                continue

        markers = (
            "binary_branch_truth_unresolved",
            "unresolved_cfg_edge_custody",
            "edge_truth_unresolved",
            "unresolved_edge_truth",
            "branch_polarity_unresolved",
        )
        for value in candidates:
            text = str(value or "").strip()
            lowered = text.lower()
            if any(marker in lowered for marker in markers):
                return text
        return None

    def _edge_truth_record_needs_debug_v25(self, rec):
        if rec is None:
            return False
        if rec.get("predicate_authoritative") is not True:
            return True
        if not isinstance(rec.get("invert_for_edge"), bool):
            return True
        if rec.get("confidence") == "unresolved":
            return True
        if rec.get("confidence") in ("low", "medium"):
            return True
        div = rec.get("divergence") or {}
        if div:
            return True
        status = str(rec.get("status") or "").lower()
        if "differ" in status or "mismatch" in status:
            return True
        if rec.get("legacy_edge_expr") is not None and rec.get("legacy_edge_expr") != rec.get("edge_expr"):
            return True
        return False

    def _edge_truth_debug_record_v25(self, rec):
        return {
            "kind": "edge_truth_debug_v26",
            "src": rec.get("src"),
            "src_hex": rec.get("src_hex"),
            "dst": rec.get("dst"),
            "dst_hex": rec.get("dst_hex"),
            "predicate": rec.get("predicate"),
            "invert_for_edge": rec.get("invert_for_edge"),
            "selection_source": rec.get("selection_source"),
            "selection_reason": rec.get("selection_reason"),
            "confidence": rec.get("confidence"),
            "mnemonic": rec.get("mnemonic"),
            "mnemonic_relation": rec.get("mnemonic_relation"),
            "condition_opcode": rec.get("condition_opcode"),
            "hf_relation": rec.get("hf_relation"),
            "mnemonic_vs_hf": rec.get("mnemonic_vs_hf"),
            "is_taken_edge": rec.get("is_taken_edge"),
            "is_fallthrough_edge": rec.get("is_fallthrough_edge"),
            "legacy_edge_expr": rec.get("legacy_edge_expr"),
            "legacy_invert_for_edge": rec.get("legacy_invert_for_edge"),
            "divergence": rec.get("divergence"),
            "status": rec.get("status"),
            "role": rec.get("role"),
            "raw_type": rec.get("raw_type"),
        }

    # ---------------------------------------------------------
    # v31 MULTIWAY DEFAULT / SELECTOR-CONE SEMANTIC HANDOFF
    # ---------------------------------------------------------

    def build_multiway_dispatch_semantics_v31(self):
        """Build the v31 fail-closed multiway handoff for SGL.

        v31 retains all v30 authorities and adds two narrowly proved classes:

          * a unique unlabeled physical arm may be separated as default when
            explicit labels account for every other target; and
          * a BRANCHIND input may itself be the semantic selector when no
            LOAD-backed address cone exists and Ghidra case-label evidence
            proves a true multiway switch.

        Neither successor order nor PHI input order is semantic authority.
        """
        raw_facts = self._multiway_cfg_facts_v30()
        out = []
        events = []

        for raw in raw_facts:
            rec = self._semantic_multiway_record_v30(raw)
            out.append(rec)
            events.extend(list(rec.get("events", []) or []))

        out.sort(key=lambda rec: (
            rec.get("dispatcher") is None,
            rec.get("dispatcher") if isinstance(rec.get("dispatcher"), int) else 0,
        ))

        self.semantic_multiway_dispatch_facts = out
        self.semantic_multiway_dispatch_by_block = {
            rec.get("dispatcher"): rec
            for rec in out
            if rec.get("dispatcher") is not None
        }
        self.semantic_multiway_dispatch_events = events
        self.semantic_multiway_dispatch_inventory = {
            "kind": "semantic_multiway_dispatch_inventory_v31",
            "version": self.multiway_dispatch_version,
            "dispatchers": len(out),
            "resolved": sum(
                1 for rec in out if rec.get("structuring_status") == "resolved"
            ),
            "partially_resolved": sum(
                1 for rec in out
                if rec.get("structuring_status") == "partially_resolved"
            ),
            "unresolved": sum(
                1 for rec in out if rec.get("structuring_status") == "unresolved"
            ),
            "selector_resolved": sum(
                1 for rec in out
                if (rec.get("selector") or {}).get("status", "").startswith("resolved")
            ),
            "default_partition_resolved": sum(
                1 for rec in out
                if (rec.get("case_default_partition") or {}).get("status")
                in ("resolved", "not_applicable_all_targets_labeled")
            ),
            "phi_predecessor_resolved": sum(
                1 for rec in out
                if (rec.get("phi_custody") or {}).get("status") == "resolved"
            ),
            "successor_order_used_for_case_values": False,
            "phi_input_order_used_for_predecessor_mapping": False,
            "rule": (
                "FunctionCFG_jump_table_truth_plus_unique_default_partition_"
                "plus_selector_dependency_cone_plus_definition_owned_PHI_predecessors"
            ),
        }

        self.semantic_events.append({
            "kind": "semantic_multiway_dispatch_handoff_built_v31",
            "version": self.multiway_dispatch_version,
            "dispatchers": len(out),
            "resolved": self.semantic_multiway_dispatch_inventory.get("resolved"),
            "partially_resolved": self.semantic_multiway_dispatch_inventory.get(
                "partially_resolved"
            ),
            "unresolved": self.semantic_multiway_dispatch_inventory.get("unresolved"),
            "successor_order_used_for_case_values": False,
            "phi_input_order_used_for_predecessor_mapping": False,
        })

    def build_multiway_dispatch_semantics_v30(self):
        """Compatibility entrypoint retained for older pipeline drivers."""
        return self.build_multiway_dispatch_semantics_v31()


    def _multiway_cfg_facts_v30(self):
        cfg = getattr(self.func, "cfg", None)
        for owner, attr in (
            (cfg, "multiway_dispatches"),
            (self.func, "multiway_dispatch_facts"),
            (self.func, "cfg_multiway_dispatches"),
        ):
            if owner is None:
                continue
            facts = getattr(owner, attr, None)
            if facts:
                return [dict(rec) for rec in list(facts or [])]
        return []

    def _multiway_target_addr_v31(self, value):
        """Normalize one target/address-like value without using list order."""
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except Exception:
                return None
        if isinstance(value, dict):
            for key in (
                "target", "target_addr", "destination", "dst", "address", "addr",
            ):
                if key in value:
                    addr = self._multiway_target_addr_v31(value.get(key))
                    if addr is not None:
                        return addr
            return None
        for attr in ("target", "target_addr", "destination", "dst", "address", "addr", "offset"):
            try:
                addr = self._multiway_target_addr_v31(getattr(value, attr, None))
            except Exception:
                addr = None
            if addr is not None:
                return addr
        return None

    def _multiway_unique_values_v31(self, values):
        out = []
        seen = set()
        for value in list(values or []):
            key = repr(value)
            if key in seen:
                continue
            seen.add(key)
            out.append(value)
        return out

    def _multiway_case_record_has_labels_v31(self, case):
        return bool(list((case or {}).get("values", []) or []))

    def _multiway_merge_case_records_v31(self, cases):
        """Merge records by target while retaining all label provenance."""
        by_target = {}
        order = []
        for original in list(cases or []):
            case = dict(original or {})
            target = self._multiway_target_addr_v31(case.get("target"))
            case["target"] = target
            if target not in by_target:
                by_target[target] = case
                order.append(target)
                case["values"] = list(case.get("values", []) or [])
                case["case_addresses"] = list(case.get("case_addresses", []) or [])
                case["source_indices"] = list(case.get("source_indices", []) or [])
                continue
            merged = by_target[target]
            merged["values"] = self._multiway_unique_values_v31(
                list(merged.get("values", []) or []) + list(case.get("values", []) or [])
            )
            merged["case_addresses"] = self._multiway_unique_values_v31(
                list(merged.get("case_addresses", []) or [])
                + list(case.get("case_addresses", []) or [])
            )
            merged["source_indices"] = self._multiway_unique_values_v31(
                list(merged.get("source_indices", []) or [])
                + list(case.get("source_indices", []) or [])
            )
        return [by_target[target] for target in order if target is not None]

    def _multiway_normalize_case_default_partition_v31(self, raw):
        """Separate explicit case labels from a uniquely proved default arm.

        The proof is set-based.  Successor order is never consulted.  A default
        is accepted only from explicit FunctionCFG evidence, one unlabeled case
        record, or one physical successor left after all labelled targets are
        accounted for.  Ambiguous residual targets remain unresolved.
        """
        original = dict(raw or {})
        normalized = dict(original)
        original_cases = self._multiway_merge_case_records_v31(
            [dict(item) for item in list(original.get("cases", []) or [])]
        )

        physical = []
        for value in list(original.get("successors", []) or []):
            addr = self._multiway_target_addr_v31(value)
            if addr is not None and addr not in physical:
                physical.append(addr)
        for case in original_cases:
            target = self._multiway_target_addr_v31(case.get("target"))
            if target is not None and target not in physical:
                physical.append(target)
        explicit_default = self._multiway_target_addr_v31(
            original.get("default_target")
        )
        if explicit_default is not None and explicit_default not in physical:
            physical.append(explicit_default)

        labelled_cases = [
            case for case in original_cases
            if self._multiway_case_record_has_labels_v31(case)
        ]
        unlabeled_cases = [
            case for case in original_cases
            if not self._multiway_case_record_has_labels_v31(case)
        ]
        labelled_targets = set(
            self._multiway_target_addr_v31(case.get("target"))
            for case in labelled_cases
        )
        labelled_targets.discard(None)
        residual_targets = sorted(set(physical) - labelled_targets)

        candidate_evidence = {}
        if explicit_default is not None:
            candidate_evidence.setdefault(explicit_default, []).append(
                "FunctionCFG_explicit_default_target"
            )

        unlabeled_targets = set()
        for case in unlabeled_cases:
            target = self._multiway_target_addr_v31(case.get("target"))
            if target is None:
                continue
            unlabeled_targets.add(target)
            candidate_evidence.setdefault(target, []).append(
                "unique_unlabeled_case_record"
            )

        raw_values = list(original.get("raw_label_values", []) or [])
        explicit_values = []
        for case in labelled_cases:
            explicit_values.extend(list(case.get("values", []) or []))
        explicit_values = self._multiway_unique_values_v31(explicit_values)
        labels_complete = bool(explicit_values) and not list(
            original.get("unmapped_case_records", []) or []
        )
        if raw_values:
            labels_complete = labels_complete and (
                len(self._multiway_unique_values_v31(raw_values))
                == len(explicit_values)
            )

        if labels_complete and len(residual_targets) == 1:
            candidate_evidence.setdefault(residual_targets[0], []).append(
                "unique_physical_successor_not_owned_by_explicit_labels"
            )

        candidates = sorted(candidate_evidence)
        resolved_default = None
        status = "unresolved_default_partition"
        reason = None

        if not physical:
            status = "unresolved_no_physical_targets"
            reason = "physical successor inventory is empty"
        elif len(candidates) == 1:
            candidate = candidates[0]
            # An inferred default may not collide with an explicitly labelled
            # target.  An explicit FunctionCFG default is allowed to share a
            # target with a case because compilers can coalesce arm bodies.
            inferred_only = "FunctionCFG_explicit_default_target" not in candidate_evidence[candidate]
            if inferred_only and candidate in labelled_targets:
                reason = "inferred default target is also explicitly labelled"
            elif len(unlabeled_targets) > 1 and explicit_default is None:
                reason = "multiple unlabeled targets survive"
            else:
                resolved_default = candidate
                status = "resolved"
                reason = "+".join(candidate_evidence[candidate])
        elif len(candidates) > 1:
            status = "unresolved_ambiguous_default_targets"
            reason = "multiple independently plausible default targets"
        elif set(physical) == labelled_targets and not unlabeled_cases:
            status = "not_applicable_all_targets_labeled"
            reason = "every physical target has explicit case labels"
        else:
            reason = "no unique unlabeled physical target is proven"

        cases_out = []
        for case in labelled_cases:
            cases_out.append(dict(case))
        # Preserve an explicitly labelled case that shares the explicit default
        # body; only unlabeled records are removed from case inventory.

        original_issues = [str(x) for x in list(original.get("issues", []) or [])]
        superseded = []
        active = []
        for issue in original_issues:
            repairable = (
                issue.startswith("case_label_count_mismatch:")
                or issue.startswith("default_")
            )
            if status == "resolved" and repairable:
                superseded.append(issue)
            else:
                active.append(issue)

        normalized["cases"] = cases_out
        normalized["default_target"] = resolved_default
        if status == "resolved":
            normalized["default_status"] = (
                "resolved_by_semantic_unique_unlabeled_target_v31"
            )
        elif status == "not_applicable_all_targets_labeled":
            normalized["default_status"] = (
                "not_exposed_or_all_successors_labeled"
            )
        normalized["issues"] = active
        normalized["case_default_partition_v31"] = {
            "kind": "multiway_case_default_partition_v31",
            "status": status,
            "reason": reason,
            "physical_targets": sorted(set(physical)),
            "explicit_case_targets": sorted(labelled_targets),
            "explicit_case_values": list(explicit_values),
            "unlabeled_case_targets": sorted(unlabeled_targets),
            "residual_targets": residual_targets,
            "default_target": resolved_default,
            "candidate_evidence": {
                target: list(evidence)
                for target, evidence in candidate_evidence.items()
            },
            "original_case_records": len(original_cases),
            "explicit_case_records": len(cases_out),
            "raw_label_count": len(self._multiway_unique_values_v31(raw_values)),
            "superseded_issues": superseded,
            "active_issues": active,
            "successor_order_used": False,
        }

        if (
            str(original.get("status") or "unresolved") != "resolved"
            and status in ("resolved", "not_applicable_all_targets_labeled")
            and not active
            and str(original.get("join_status") or "") == "resolved"
            and cases_out
            and not list(original.get("unmapped_case_records", []) or [])
        ):
            normalized["status"] = "resolved"
            normalized["status_authority_v31"] = (
                "semantic_default_partition_closed_only_FunctionCFG_issue"
            )

        return normalized, dict(normalized["case_default_partition_v31"])

    def _multiway_trace_sids_v31(self, value, parent_key=None):
        out = set()
        if value is None:
            return out
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key).lower()
                if "sid" in key_text:
                    out |= self._multiway_trace_sids_v31(item, parent_key=key_text)
                elif isinstance(item, (dict, list, tuple, set)):
                    out |= self._multiway_trace_sids_v31(item, parent_key=key_text)
            return out
        if isinstance(value, (list, tuple, set)):
            for item in value:
                out |= self._multiway_trace_sids_v31(item, parent_key=parent_key)
            return out
        if isinstance(value, int):
            if parent_key and "sid" in str(parent_key):
                out.add(value)
            return out
        text = str(value)
        for match in re.findall(r"\bv_\d+\b", text):
            out.add(match)
        if parent_key and "sid" in str(parent_key):
            if text.isdigit():
                out.add(int(text))
            elif text:
                out.add(text)
        return out

    def _multiway_dispatch_terminator_values_v31(self, raw):
        dispatcher = self._multiway_cfg_node_v30(raw.get("dispatcher"))
        block = getattr(dispatcher, "block", None) if dispatcher is not None else None
        term = getattr(block, "terminator", None) if block is not None else None
        if str(getattr(term, "opcode", "") or "").upper() != "BRANCHIND":
            return []
        out = []
        for value in list(getattr(term, "inputs", []) or []):
            var = _unwrap_var(value)
            if var is None or getattr(var, "is_constant", False):
                continue
            out.append(value)
        return out

    def _multiway_selector_root_candidates_v31(self, raw):
        computed = dict(raw.get("computed_target") or {})
        candidates = []

        def add(value, source):
            if value is None:
                return
            node = value if hasattr(value, "opcode") else self.get_node(value)
            candidate = node if node is not None else value
            var = _unwrap_var(candidate)
            if var is None or getattr(var, "is_constant", False):
                return
            sid = _sid(candidate)
            key = ("sid", str(sid)) if sid is not None else ("obj", id(candidate))
            if any(rec.get("key") == key for rec in candidates):
                for rec in candidates:
                    if rec.get("key") == key and source not in rec["sources"]:
                        rec["sources"].append(source)
                return
            candidates.append({
                "key": key,
                "value": candidate,
                "sid": sid,
                "expr": self._multiway_expr_v30(candidate),
                "sources": [source],
            })

        computed_sid = computed.get("computed_target_sid")
        add(self._multiway_node_for_sid_v30(computed_sid), "computed_target_formula")
        add(self._multiway_var_for_sid_v30(computed_sid), "computed_target_var")

        # The concrete BRANCHIND input is a root, not merely another use in the
        # definition trace.  Prefer it before considering internal dependency
        # nodes, otherwise a direct formula such as (selector & 3) and its leaf
        # selector can be misreported as two competing roots.
        for value in self._multiway_dispatch_terminator_values_v31(raw):
            add(value, "BRANCHIND_terminator_input")

        # FunctionCFG's serialization-safe definition trace is fallback only
        # when neither the computed SID nor the concrete terminator yielded a
        # live PAL value.  Trace order is never used as authority.
        if not candidates:
            for sid in self._multiway_trace_sids_v31(
                computed.get("definition_trace", [])
            ):
                add(self._multiway_node_for_sid_v30(sid), "definition_trace_formula")
                add(self._multiway_var_for_sid_v30(sid), "definition_trace_var")

        return candidates

    def _multiway_direct_selector_candidate_v31(self, candidate, raw):
        value = (candidate or {}).get("value")
        if value is None:
            return None
        node = value if hasattr(value, "opcode") else self.get_node(value)
        var = _unwrap_var(value)
        if var is None or getattr(var, "is_constant", False):
            return None

        case_values = []
        for case in list(raw.get("cases", []) or []):
            case_values.extend(list((case or {}).get("values", []) or []))
        successor_targets = set()
        for successor in list(raw.get("successors", []) or []):
            target = self._multiway_target_addr_v31(successor)
            if target is not None:
                successor_targets.add(target)
        if not case_values or len(successor_targets) < 2:
            return None

        disallowed = {
            "LOAD", "STORE", "CALL", "CALLIND", "CALLOTHER", "INDIRECT",
            "PTRADD", "PTRSUB",
        }
        opcode = str(getattr(node, "opcode", "") or "") if node is not None else ""
        if opcode in disallowed:
            return None

        load_tables = list(raw.get("load_tables", []) or [])
        table_addresses = set(
            item.get("address") for item in load_tables
            if isinstance(item, dict) and isinstance(item.get("address"), int)
        )
        if node is not None and table_addresses:
            if self._multiway_constants_v30(node) & table_addresses:
                return None

        selector_value = value
        normalization = []
        if node is not None:
            selector_value, normalization = self._multiway_strip_index_affine_v30(node)
        selector_expr = self._multiway_expr_v30(selector_value)
        selector_sid = _sid(selector_value)
        dependencies = sorted(
            self._multiway_dynamic_leaf_sids_v30(selector_value),
            key=lambda item: str(item),
        )
        if not selector_expr:
            return None
        if selector_sid is None and not dependencies:
            return None

        return {
            "selector_value": selector_value,
            "selector_sid": selector_sid,
            "selector_expr": selector_expr,
            "selector_dependencies": dependencies,
            "dispatch_index_sid": _sid(value),
            "dispatch_index_expr": self._multiway_expr_v30(value),
            "normalization": normalization,
            "opcode": opcode or None,
            "sources": list((candidate or {}).get("sources", []) or []),
            "signature": (str(selector_sid), selector_expr),
        }

    def _multiway_selector_contract_v31(self, raw):
        computed = dict(raw.get("computed_target") or {})
        computed_sid = computed.get("computed_target_sid")
        candidates = self._multiway_selector_root_candidates_v31(raw)
        computed_value = (
            self._multiway_node_for_sid_v30(computed_sid)
            or self._multiway_var_for_sid_v30(computed_sid)
        )
        if computed_value is None:
            for candidate in candidates:
                if "BRANCHIND_terminator_input" in candidate.get("sources", []):
                    computed_value = candidate.get("value")
                    break
        computed_expr = self._multiway_expr_v30(computed_value)

        base = {
            "kind": "multiway_selector_contract_v31",
            "computed_target_sid": computed_sid,
            "computed_target_expr": computed_expr,
            "computed_target_definition_trace": list(
                computed.get("definition_trace", []) or []
            ),
            "selector_sid": None,
            "selector_expr": None,
            "selector_dependencies": [],
            "dispatch_index_sid": None,
            "dispatch_index_expr": None,
            "normalization": [],
            "load_sid": None,
            "load_address_expr": None,
            "status": "unresolved_selector_dependency_missing",
            "confidence": "low",
            "reason": None,
            "case_label_relation": "unresolved",
            "successor_order_used": False,
            "candidate_inventory": [
                {
                    "sid": rec.get("sid"),
                    "expr": rec.get("expr"),
                    "sources": list(rec.get("sources", []) or []),
                    "opcode": getattr(rec.get("value"), "opcode", None),
                }
                for rec in candidates
            ],
            "events": [],
        }

        all_loads = []
        for candidate in candidates:
            value = candidate.get("value")
            root = value if hasattr(value, "opcode") else self.get_node(value)
            for load in self._multiway_find_load_nodes_v30(
                root, list(raw.get("load_tables", []) or [])
            ):
                key = _sid(load)
                if not any(_sid(existing) == key and key is not None for existing in all_loads):
                    if key is None and any(existing is load for existing in all_loads):
                        continue
                    all_loads.append(load)

        base["events"].append({
            "kind": "multiway_selector_dependency_cone_classified_v31",
            "dispatcher": raw.get("dispatcher"),
            "computed_target_sid": computed_sid,
            "candidate_count": len(candidates),
            "load_candidate_count": len(all_loads),
            "successor_order_used": False,
        })

        if len(all_loads) == 1:
            load_node = all_loads[0]
            address_value = self._multiway_load_address_value_v30(load_node)
            analysis = self._multiway_analyze_table_address_v30(
                address_value,
                list(raw.get("load_tables", []) or []),
            )
            base.update(analysis)
            base["kind"] = "multiway_selector_contract_v31"
            base["computed_target_sid"] = computed_sid
            base["computed_target_expr"] = computed_expr
            base["computed_target_definition_trace"] = list(
                computed.get("definition_trace", []) or []
            )
            base["load_sid"] = getattr(load_node, "ssa_id", None)
            base["load_address_expr"] = self._multiway_expr_v30(address_value)
            base["successor_order_used"] = False
            if str(base.get("status") or "").startswith("resolved"):
                base["events"].extend([
                    {
                        "kind": "multiway_selector_index_recovered_v31",
                        "dispatcher": raw.get("dispatcher"),
                        "selector_sid": base.get("selector_sid"),
                        "selector_expr": base.get("selector_expr"),
                        "authority": "LOAD_backed_table_address_dependency_cone",
                    },
                    {
                        "kind": "multiway_selector_computed_target_separated_v31",
                        "dispatcher": raw.get("dispatcher"),
                        "computed_target_expr": computed_expr,
                        "selector_expr": base.get("selector_expr"),
                    },
                ])
            return base

        if len(all_loads) > 1:
            base["status"] = "unresolved_selector_candidate_ambiguous"
            base["reason"] = "multiple LOAD-backed selector candidates survive"
            base["load_candidates"] = [_sid(node) for node in all_loads]
            base["events"].append({
                "kind": "multiway_selector_candidate_ambiguous_v31",
                "dispatcher": raw.get("dispatcher"),
                "candidate_sids": list(base["load_candidates"]),
                "reason": base["reason"],
            })
            return base

        direct = []
        seen_signatures = set()
        for candidate in candidates:
            rec = self._multiway_direct_selector_candidate_v31(candidate, raw)
            if rec is None:
                continue
            signature = rec.get("signature")
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            direct.append(rec)

        if len(direct) == 1:
            selected = direct[0]
            base.update({
                "selector_sid": selected.get("selector_sid"),
                "selector_expr": selected.get("selector_expr"),
                "selector_dependencies": list(selected.get("selector_dependencies", []) or []),
                "dispatch_index_sid": selected.get("dispatch_index_sid"),
                "dispatch_index_expr": selected.get("dispatch_index_expr"),
                "normalization": list(selected.get("normalization", []) or []),
                "status": (
                    "resolved_direct_branchind_selector_leaf"
                    if not selected.get("opcode")
                    else "resolved_direct_selector_formula"
                ),
                "confidence": "high",
                "reason": (
                    "unique nonconstant BRANCHIND dependency is directly governed "
                    "by FunctionCFG/Ghidra case labels"
                ),
                "case_label_relation": (
                    "Ghidra_JumpTable_labels_apply_to_direct_selector_dependency"
                ),
                "direct_selector_sources": list(selected.get("sources", []) or []),
            })
            base["events"].extend([
                {
                    "kind": "multiway_selector_index_recovered_v31",
                    "dispatcher": raw.get("dispatcher"),
                    "selector_sid": base.get("selector_sid"),
                    "selector_expr": base.get("selector_expr"),
                    "authority": "direct_BRANCHIND_selector_dependency_cone",
                },
                {
                    "kind": "multiway_selector_computed_target_separated_v31",
                    "dispatcher": raw.get("dispatcher"),
                    "computed_target_expr": computed_expr,
                    "selector_expr": base.get("selector_expr"),
                    "direct_selector": True,
                },
            ])
            return base

        if len(direct) > 1:
            base["status"] = "unresolved_selector_candidate_ambiguous"
            base["reason"] = "multiple direct semantic selector candidates survive"
            base["direct_candidates"] = [
                {
                    "sid": rec.get("selector_sid"),
                    "expr": rec.get("selector_expr"),
                    "sources": rec.get("sources"),
                }
                for rec in direct
            ]
            base["events"].append({
                "kind": "multiway_selector_candidate_ambiguous_v31",
                "dispatcher": raw.get("dispatcher"),
                "candidates": list(base["direct_candidates"]),
                "reason": base["reason"],
            })
            return base

        base["reason"] = (
            "no unique LOAD-backed or direct nonconstant BRANCHIND selector "
            "dependency is proven"
        )
        base["events"].append({
            "kind": "multiway_selector_dependency_missing_v31",
            "dispatcher": raw.get("dispatcher"),
            "computed_target_sid": computed_sid,
            "reason": base["reason"],
        })
        return base

    def _semantic_multiway_record_v30(self, raw):
        """Compatibility-named v31 semantic record builder."""
        raw_original = dict(raw or {})
        raw, partition = self._multiway_normalize_case_default_partition_v31(
            raw_original
        )
        dispatcher = raw.get("dispatcher")
        join = raw.get("join")
        raw_cases = [dict(item) for item in list(raw.get("cases", []) or [])]
        default_target = raw.get("default_target")
        events = []
        issues = list(raw.get("issues", []) or [])

        if partition.get("status") == "resolved":
            events.extend([
                {
                    "kind": "multiway_default_arm_proven_v31",
                    "dispatcher": dispatcher,
                    "default_target": default_target,
                    "authority": partition.get("reason"),
                },
                {
                    "kind": "multiway_explicit_label_count_verified_v31",
                    "dispatcher": dispatcher,
                    "explicit_case_records": partition.get("explicit_case_records"),
                    "raw_label_count": partition.get("raw_label_count"),
                },
                {
                    "kind": "multiway_label_default_partition_resolved_v31",
                    "dispatcher": dispatcher,
                    "physical_targets": list(partition.get("physical_targets", []) or []),
                    "explicit_case_targets": list(partition.get("explicit_case_targets", []) or []),
                    "default_target": default_target,
                    "successor_order_used": False,
                },
            ])
        elif partition.get("status") != "not_applicable_all_targets_labeled":
            events.append({
                "kind": "multiway_default_arm_unproven_v31",
                "dispatcher": dispatcher,
                "status": partition.get("status"),
                "reason": partition.get("reason"),
                "candidates": dict(partition.get("candidate_evidence", {}) or {}),
            })

        selector = self._multiway_selector_contract_v31(raw)
        events.extend(list(selector.get("events", []) or []))
        if not str(selector.get("status") or "").startswith("resolved"):
            issues.append("semantic_selector_%s" % selector.get("status"))

        arm_roots = set(
            item.get("target") for item in raw_cases if item.get("target") is not None
        )
        if default_target is not None:
            arm_roots.add(default_target)

        arms = []
        for case in raw_cases:
            target = case.get("target")
            region = self._multiway_arm_region_v30(
                dispatcher, target, join, arm_roots
            )
            arm = {
                "role": "dispatch_case",
                "target": target,
                "target_hex": _safe_hex(target),
                "values": list(case.get("values", []) or []),
                "case_addresses": list(case.get("case_addresses", []) or []),
                "source_indices": list(case.get("source_indices", []) or []),
                "authority": case.get("authority") or raw.get("authority"),
                "region": region,
                "join_predecessors": list(region.get("join_predecessors", []) or []),
                "phi_inputs": [],
            }
            arms.append(arm)
            events.append({
                "kind": "multiway_dispatch_case_semantic_owned_v31",
                "dispatcher": dispatcher,
                "target": target,
                "values": list(arm["values"]),
                "region_status": region.get("status"),
            })

        default_arm = None
        if default_target is not None:
            region = self._multiway_arm_region_v30(
                dispatcher, default_target, join, arm_roots
            )
            default_arm = {
                "role": "dispatch_default",
                "target": default_target,
                "target_hex": _safe_hex(default_target),
                "values": [],
                "authority": raw.get("authority"),
                "default_status": raw.get("default_status"),
                "region": region,
                "join_predecessors": list(region.get("join_predecessors", []) or []),
                "phi_inputs": [],
            }
            arms.append(default_arm)
            events.append({
                "kind": "multiway_dispatch_default_semantic_owned_v31",
                "dispatcher": dispatcher,
                "target": default_target,
                "region_status": region.get("status"),
            })

        shared = self._multiway_shared_arm_blocks_v30(arms)
        for arm in arms:
            region = arm.get("region") or {}
            blocks = set(region.get("blocks", []) or [])
            region["shared_blocks"] = sorted(blocks & shared)
            region["path_local_blocks"] = sorted(blocks - shared)

        phi_custody = self._multiway_phi_custody_v30(join, arms)
        if phi_custody.get("status") == "unresolved":
            issues.append("phi_predecessor_custody_unresolved")
        elif phi_custody.get("status") == "partially_resolved":
            issues.append("phi_predecessor_custody_partially_resolved")

        case_value_coverage = self._multiway_case_value_coverage_v30(raw_cases)
        arm_statuses = [
            (arm.get("region") or {}).get("status") for arm in arms
        ]
        arms_resolved = bool(arms) and all(
            status in (
                "resolved_to_join",
                "resolved_terminal",
                "resolved_fallthrough_to_arm",
            )
            for status in arm_statuses
        )

        raw_status = str(raw.get("status") or "unresolved")
        selector_resolved = str(selector.get("status") or "").startswith("resolved")
        join_resolved = (
            join is not None
            and str(raw.get("join_status") or "") == "resolved"
        )
        cases_resolved = bool(raw_cases) and not raw.get("unmapped_case_records")
        default_ok = raw.get("default_status") in (
            "resolved_by_unique_unlabeled_successor",
            "resolved_by_semantic_unique_unlabeled_target_v31",
            "not_exposed_or_all_successors_labeled",
        )

        if (
            raw_status == "resolved"
            and selector_resolved
            and cases_resolved
            and default_ok
            and join_resolved
            and arms_resolved
            and phi_custody.get("status") in ("resolved", "not_applicable")
        ):
            structuring_status = "resolved"
        elif selector_resolved and cases_resolved and default_ok and arms:
            structuring_status = "partially_resolved"
        else:
            structuring_status = "unresolved"

        if not default_ok:
            issues.append("default_%s" % raw.get("default_status"))
        if not arms_resolved:
            issues.append("arm_region_custody_unresolved")

        rec = {
            "kind": "semantic_multiway_dispatch_v31",
            "version": self.multiway_dispatch_version,
            "dispatcher": dispatcher,
            "dispatcher_hex": _safe_hex(dispatcher),
            "terminator": raw.get("terminator"),
            "cfg_status": raw_status,
            "structuring_status": structuring_status,
            "selector": selector,
            "selector_sid": selector.get("selector_sid"),
            "selector_expr": selector.get("selector_expr"),
            "computed_target_sid": selector.get("computed_target_sid"),
            "computed_target_expr": selector.get("computed_target_expr"),
            "cases": [arm for arm in arms if arm.get("role") == "dispatch_case"],
            "default": default_arm,
            "arms": arms,
            "case_default_partition": partition,
            "case_value_coverage": case_value_coverage,
            "join": join,
            "join_hex": _safe_hex(join),
            "join_status": raw.get("join_status"),
            "join_evidence": dict(raw.get("join_evidence") or {}),
            "phi_custody": phi_custody,
            "shared_arm_blocks": sorted(shared),
            "successors": list(raw.get("successors", []) or []),
            "load_tables": list(raw.get("load_tables", []) or []),
            "raw_case_addresses": list(raw.get("raw_case_addresses", []) or []),
            "raw_label_values": list(raw.get("raw_label_values", []) or []),
            "unmapped_case_records": list(
                raw.get("unmapped_case_records", []) or []
            ),
            "authority": (
                "FunctionCFG_jump_table_truth+SemanticGraph_v31_default_"
                "partition_selector_cone_and_PHI_custody"
            ),
            "successor_order_used_for_case_values": False,
            "phi_input_order_used_for_predecessor_mapping": False,
            "issues": self._multiway_unique_strings_v30(issues),
            "events": events,
            "raw_cfg_record": raw_original,
            "normalized_cfg_record_v31": raw,
        }

        events.append({
            "kind": "multiway_dispatch_semantic_handoff_v31",
            "dispatcher": dispatcher,
            "structuring_status": structuring_status,
            "selector_status": selector.get("status"),
            "partition_status": partition.get("status"),
            "case_targets": len(raw_cases),
            "default_target": default_target,
            "join": join,
            "phi_status": phi_custody.get("status"),
            "issues": list(rec["issues"]),
        })
        return rec


    def _multiway_selector_contract_v30(self, raw):
        """Compatibility wrapper for the v31 selector-cone contract."""
        return self._multiway_selector_contract_v31(raw)


    def _multiway_find_load_nodes_v30(self, root, load_tables):
        if root is None:
            return []
        table_addresses = set(
            item.get("address") for item in list(load_tables or [])
            if isinstance(item.get("address"), int)
        )
        loads = []
        seen = set()
        work = [root]
        while work:
            node = work.pop()
            if node is None:
                continue
            sid = getattr(node, "ssa_id", None)
            key = sid if sid is not None else id(node)
            if key in seen:
                continue
            seen.add(key)
            if getattr(node, "opcode", None) == "LOAD":
                loads.append(node)
                continue
            for inp in list(getattr(node, "inputs", []) or []):
                child = inp if hasattr(inp, "opcode") else self.get_node(inp)
                if child is not None:
                    work.append(child)

        if len(loads) <= 1 or not table_addresses:
            return loads

        scored = []
        for node in loads:
            addr = self._multiway_load_address_value_v30(node)
            constants = self._multiway_constants_v30(addr)
            score = len(constants & table_addresses)
            scored.append((score, node))
        best = max(score for score, _ in scored)
        if best <= 0:
            return loads
        return [node for score, node in scored if score == best]

    def _multiway_load_address_value_v30(self, load_node):
        inputs = list(getattr(load_node, "inputs", []) or [])
        if not inputs:
            return None
        # Ghidra LOAD input0 is the address-space ID; the final input is the
        # actual address. This also works with older two-input PAL LOAD nodes.
        return inputs[-1]

    def _multiway_analyze_table_address_v30(self, address_value, load_tables):
        table_addresses = set(
            item.get("address") for item in list(load_tables or [])
            if isinstance(item.get("address"), int)
        )
        record = {
            "kind": "multiway_selector_contract_v30",
            "selector_sid": None,
            "selector_expr": None,
            "selector_dependencies": [],
            "dispatch_index_sid": None,
            "dispatch_index_expr": None,
            "normalization": [],
            "status": "unresolved_table_address_shape",
            "confidence": "low",
            "reason": None,
            "case_label_relation": "unresolved",
        }

        dynamic = self._multiway_table_dynamic_component_v30(
            address_value, table_addresses
        )
        if dynamic is None:
            record["reason"] = "table address has no unique dynamic index component"
            return record

        component = dynamic.get("component")
        normalization = list(dynamic.get("normalization", []) or [])
        index_value, affine_steps = self._multiway_strip_index_affine_v30(component)
        normalization.extend(affine_steps)

        selector_value = index_value
        selector_sid = _sid(selector_value)
        selector_expr = self._multiway_expr_v30(selector_value)
        index_sid = _sid(component)
        index_expr = self._multiway_expr_v30(component)
        dependencies = sorted(
            self._multiway_dynamic_leaf_sids_v30(selector_value),
            key=lambda value: str(value),
        )

        if selector_value is None or not selector_expr:
            record["reason"] = "dynamic table index could not be rendered"
            return record
        if not dependencies and selector_sid is None:
            record["reason"] = "dynamic table index has no semantic dependency"
            return record

        record.update({
            "selector_sid": selector_sid,
            "selector_expr": selector_expr,
            "selector_dependencies": dependencies,
            "dispatch_index_sid": index_sid,
            "dispatch_index_expr": index_expr,
            "normalization": normalization,
            "status": "resolved_source_selector_provenance",
            "confidence": "high" if dynamic.get("authority") == "ptradd_index" else "medium",
            "reason": dynamic.get("reason"),
            "case_label_relation": (
                "Ghidra_JumpTable_labels_apply_to_recovered_source_selector"
            ),
            "table_base_evidence": list(dynamic.get("table_base_evidence", []) or []),
        })
        return record

    def _multiway_table_dynamic_component_v30(self, value, table_addresses, depth=0):
        if value is None or depth > 16:
            return None
        node = value if hasattr(value, "opcode") else self.get_node(value)
        if node is None:
            if getattr(value, "is_constant", False):
                return None
            return {
                "component": value,
                "authority": "dynamic_leaf",
                "reason": "table_address_dynamic_leaf",
                "normalization": [],
                "table_base_evidence": [],
            }

        opcode = str(getattr(node, "opcode", "") or "")
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE") and inputs:
            rec = self._multiway_table_dynamic_component_v30(
                inputs[0], table_addresses, depth + 1
            )
            if rec is not None:
                rec.setdefault("normalization", []).append({
                    "opcode": opcode,
                    "role": "transparent_index_transport",
                    "output_sid": getattr(node, "ssa_id", None),
                })
            return rec

        if opcode == "PTRADD" and len(inputs) >= 2:
            index = inputs[1]
            scale = inputs[2] if len(inputs) > 2 else None
            return {
                "component": index,
                "authority": "ptradd_index",
                "reason": "PTRADD index operand is the dynamic table index",
                "normalization": [{
                    "opcode": "PTRADD",
                    "role": "table_index_scale",
                    "scale": self._multiway_const_v30(scale),
                    "base_expr": self._multiway_expr_v30(inputs[0]),
                }],
                "table_base_evidence": sorted(
                    self._multiway_constants_v30(inputs[0]) & table_addresses
                ),
            }

        if opcode in ("INT_ADD", "PTRSUB") and len(inputs) >= 2:
            left, right = inputs[0], inputs[1]
            left_dynamic = bool(self._multiway_dynamic_leaf_sids_v30(left))
            right_dynamic = bool(self._multiway_dynamic_leaf_sids_v30(right))
            left_constants = self._multiway_constants_v30(left)
            right_constants = self._multiway_constants_v30(right)

            if left_dynamic and not right_dynamic:
                component, static = left, right
            elif right_dynamic and not left_dynamic:
                component, static = right, left
            elif left_dynamic and right_dynamic:
                left_base = bool(left_constants & table_addresses)
                right_base = bool(right_constants & table_addresses)
                if left_base and not right_base:
                    component, static = right, left
                elif right_base and not left_base:
                    component, static = left, right
                else:
                    return None
            else:
                return None

            inner = self._multiway_table_dynamic_component_v30(
                component, table_addresses, depth + 1
            )
            if inner is None:
                inner = {
                    "component": component,
                    "authority": "unique_dynamic_addend",
                    "reason": "unique dynamic addend in table address",
                    "normalization": [],
                    "table_base_evidence": [],
                }
            inner.setdefault("normalization", []).append({
                "opcode": opcode,
                "role": "table_base_composition",
                "static_expr": self._multiway_expr_v30(static),
            })
            inner.setdefault("table_base_evidence", []).extend(sorted(
                self._multiway_constants_v30(static) & table_addresses
            ))
            return inner

        if opcode in ("INT_MULT", "INT_LEFT") and len(inputs) >= 2:
            left, right = inputs[0], inputs[1]
            if self._multiway_is_constant_value_v30(left):
                component, scale = right, left
            elif self._multiway_is_constant_value_v30(right):
                component, scale = left, right
            else:
                return None
            return {
                "component": component,
                "authority": "scaled_dynamic_index",
                "reason": "%s isolates one dynamic table index" % opcode,
                "normalization": [{
                    "opcode": opcode,
                    "role": "table_index_scale",
                    "scale": self._multiway_const_v30(scale),
                }],
                "table_base_evidence": [],
            }

        # Non-address arithmetic (AND/REM/etc.) is preserved as the selector
        # expression. It may represent source code such as switch(x & 3).
        if self._multiway_dynamic_leaf_sids_v30(node):
            return {
                "component": node,
                "authority": "dynamic_index_expression",
                "reason": "dynamic table-index expression preserved without rewriting",
                "normalization": [],
                "table_base_evidence": [],
            }
        return None

    def _multiway_strip_index_affine_v30(self, value):
        steps = []
        current = value
        seen = set()
        while current is not None:
            node = current if hasattr(current, "opcode") else self.get_node(current)
            if node is None:
                break
            sid = getattr(node, "ssa_id", None)
            if sid in seen:
                break
            if sid is not None:
                seen.add(sid)
            opcode = str(getattr(node, "opcode", "") or "")
            inputs = list(getattr(node, "inputs", []) or [])

            if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE") and inputs:
                steps.append({
                    "opcode": opcode,
                    "role": "transparent_selector_transport",
                    "output_sid": sid,
                })
                current = inputs[0]
                continue

            if opcode in ("INT_MULT", "INT_LEFT") and len(inputs) >= 2:
                if self._multiway_is_constant_value_v30(inputs[0]):
                    current, scale = inputs[1], inputs[0]
                elif self._multiway_is_constant_value_v30(inputs[1]):
                    current, scale = inputs[0], inputs[1]
                else:
                    break
                steps.append({
                    "opcode": opcode,
                    "role": "dispatch_index_scale_removed",
                    "scale": self._multiway_const_v30(scale),
                })
                continue

            if opcode in ("INT_ADD", "INT_SUB") and len(inputs) >= 2:
                left, right = inputs[0], inputs[1]
                if opcode == "INT_ADD" and self._multiway_is_constant_value_v30(left):
                    current, bias = right, self._multiway_const_v30(left)
                    direction = "constant_plus_selector"
                elif self._multiway_is_constant_value_v30(right):
                    current, bias = left, self._multiway_const_v30(right)
                    direction = "selector_plus_constant" if opcode == "INT_ADD" else "selector_minus_constant"
                else:
                    break
                steps.append({
                    "opcode": opcode,
                    "role": "dispatch_index_affine_normalization_removed",
                    "bias": bias,
                    "direction": direction,
                })
                continue
            break
        return current, steps

    def _multiway_arm_region_v30(self, dispatcher_addr, start_addr, join_addr, arm_roots):
        start = self._multiway_cfg_node_v30(start_addr)
        join = self._multiway_cfg_node_v30(join_addr)
        if start is None:
            return {
                "status": "unresolved_missing_arm_entry",
                "blocks": [],
                "join_predecessors": [],
                "frontier": [],
                "reason": "case/default target has no CFG node",
            }

        seen = set()
        work = [start]
        frontier = []
        join_predecessors = set()
        hit_join = False
        terminal = False
        fallthrough_arms = set()
        escaped = set()

        while work and len(seen) < 4096:
            node = work.pop()
            addr = self._cfg_addr_v24(node)
            if node is join or (join_addr is not None and addr == join_addr):
                hit_join = True
                continue
            if node in seen:
                continue
            seen.add(node)

            term = getattr(getattr(node, "block", None), "terminator", None)
            if getattr(term, "opcode", None) == "RETURN":
                terminal = True
                frontier.append({"kind": "return", "block": addr})
                continue

            successors = self._successor_nodes_v24(node)
            if not successors:
                frontier.append({"kind": "dead_end", "block": addr})
                escaped.add(addr)
                continue

            for succ in successors:
                saddr = self._cfg_addr_v24(succ)
                if join_addr is not None and saddr == join_addr:
                    hit_join = True
                    join_predecessors.add(addr)
                    frontier.append({
                        "kind": "join",
                        "src": addr,
                        "dst": join_addr,
                    })
                    continue
                if saddr in arm_roots and saddr != start_addr:
                    fallthrough_arms.add(saddr)
                    frontier.append({
                        "kind": "fallthrough_to_arm",
                        "src": addr,
                        "dst": saddr,
                    })
                    continue
                if saddr == dispatcher_addr:
                    frontier.append({
                        "kind": "dispatch_cycle",
                        "src": addr,
                        "dst": saddr,
                    })
                    escaped.add(saddr)
                    continue
                work.append(succ)

        block_addrs = sorted(
            self._cfg_addr_v24(node) for node in seen
            if self._cfg_addr_v24(node) is not None
        )
        unresolved_frontier = [
            rec for rec in frontier
            if rec.get("kind") in ("dead_end", "dispatch_cycle")
        ]
        if unresolved_frontier:
            status = "unresolved_region_escape"
        elif hit_join and not terminal and not fallthrough_arms:
            status = "resolved_to_join"
        elif terminal and not hit_join and not fallthrough_arms:
            status = "resolved_terminal"
        elif fallthrough_arms and not hit_join and not terminal:
            status = "resolved_fallthrough_to_arm"
        elif hit_join or terminal or fallthrough_arms:
            status = "partially_resolved_mixed_frontier"
        else:
            status = "unresolved_no_terminal_frontier"

        return {
            "status": status,
            "blocks": block_addrs,
            "entry": start_addr,
            "entry_hex": _safe_hex(start_addr),
            "join": join_addr,
            "join_predecessors": sorted(join_predecessors),
            "falls_through_to_arms": sorted(fallthrough_arms),
            "terminal": terminal,
            "reaches_join": hit_join,
            "frontier": frontier,
            "shared_blocks": [],
            "path_local_blocks": list(block_addrs),
            "successor_order_used": False,
        }

    def _multiway_shared_arm_blocks_v30(self, arms):
        counts = {}
        for arm in list(arms or []):
            blocks = set((arm.get("region") or {}).get("blocks", []) or [])
            for addr in blocks:
                counts[addr] = counts.get(addr, 0) + 1
        return set(addr for addr, count in counts.items() if count > 1)

    def _multiway_phi_custody_v30(self, join_addr, arms):
        if join_addr is None:
            return {
                "status": "unresolved",
                "join": None,
                "phis": [],
                "reason": "multiway join is unresolved",
                "phi_input_order_used_for_predecessor_mapping": False,
            }

        join_node = self._multiway_cfg_node_v30(join_addr)
        if join_node is None:
            return {
                "status": "unresolved",
                "join": join_addr,
                "phis": [],
                "reason": "join address has no CFG node",
                "phi_input_order_used_for_predecessor_mapping": False,
            }

        predecessors = self._predecessor_nodes_v24(join_node)
        predecessor_addrs = set(
            self._cfg_addr_v24(node) for node in predecessors
            if self._cfg_addr_v24(node) is not None
        )
        phis = [
            phi for phi in list(self.phi_nodes or [])
            if getattr(phi, "block_addr", None) == join_addr
        ]

        if not phis:
            return {
                "status": "not_applicable",
                "join": join_addr,
                "predecessors": sorted(predecessor_addrs),
                "phis": [],
                "reason": "join contains no MULTIEQUAL",
                "phi_input_order_used_for_predecessor_mapping": False,
            }

        records = []
        unresolved = 0
        total = 0
        generic_authority_used = False
        for phi in phis:
            # v37 bohdi-emperor generic predecessor linkage is the primary
            # authority when it fully resolved this PHI.  The older local
            # reachability path remains only as compatibility for pipelines
            # that did not run build_phi_predecessor_linkage_v37().
            generic_contract = getattr(
                phi, "predecessor_linkage_contract_v37", None
            )
            generic_bindings = list(
                (generic_contract or {}).get("bindings", []) or []
            )
            if (
                isinstance(generic_contract, dict)
                and generic_contract.get("status") == "resolved"
                and len(generic_bindings) == len(predecessor_addrs)
            ):
                generic_authority_used = True
                bindings = []
                for item in generic_bindings:
                    total += 1
                    bindings.append({
                        "input_index": None,
                        "input_indices_diagnostic_only": list(
                            item.get(
                                "source_input_indices_diagnostic_only", []
                            ) or []
                        ),
                        "input_sid": item.get("source_sid"),
                        "input_name": item.get(
                            "source_presentation_name"
                        ),
                        "input_constant": str(
                            item.get("source_sid") or ""
                        ).startswith("c_"),
                        "input_constant_value": None,
                        "defining_block": item.get("defining_block"),
                        "predecessor": item.get("pred_addr"),
                        "edge_id": list(item.get("edge_id", []) or []),
                        "edge_key": item.get("edge_key"),
                        "status": (
                            "resolved_bohdi_emperor_phi_predecessor_v37"
                        ),
                        "authority": item.get("authority"),
                        "input_order_used": False,
                    })
                records.append({
                    "output_sid": getattr(phi, "output_sid", None),
                    "output_name": getattr(phi, "output_name", None),
                    "block": join_addr,
                    "bindings": bindings,
                    "resolved_bindings": len(bindings),
                    "unresolved_bindings": 0,
                    "authority": (
                        "PALSemanticGraphBuilder_v37_generic_PHI_"
                        "predecessor_edge_linkage"
                    ),
                })
                continue

            bindings = []
            for index, inp in enumerate(list(getattr(phi, "inputs", []) or [])):
                total += 1
                inp_var = _unwrap_var(inp)
                input_sid = getattr(inp_var, "ssa_id", None)
                def_node = inp if hasattr(inp, "opcode") else self.get_node(inp_var)
                def_block = getattr(def_node, "block_addr", None) if def_node is not None else None
                predecessor = None
                status = "unresolved"
                authority = None

                if def_block in predecessor_addrs:
                    predecessor = def_block
                    status = "resolved_exact_defining_block_predecessor"
                    authority = "FormulaNode.defining_block_equals_join_predecessor"
                elif def_block is not None:
                    candidates = []
                    def_cfg = self._multiway_cfg_node_v30(def_block)
                    for pred in predecessors:
                        if self._multiway_reaches_before_join_v30(
                            def_cfg, pred, join_node
                        ):
                            candidates.append(self._cfg_addr_v24(pred))
                    candidates = sorted(set(candidates))
                    if len(candidates) == 1:
                        predecessor = candidates[0]
                        status = "resolved_unique_reaching_predecessor"
                        authority = "unique_CFG_reachability_to_join_predecessor"
                    else:
                        status = "unresolved_predecessor_reachability"
                else:
                    status = (
                        "unresolved_constant_or_entry_source"
                        if getattr(inp_var, "is_constant", False)
                        else "unresolved_missing_definition"
                    )

                if not status.startswith("resolved"):
                    unresolved += 1
                bindings.append({
                    "input_index": index,
                    "input_sid": input_sid,
                    "input_name": getattr(inp_var, "name", None),
                    "input_constant": bool(getattr(inp_var, "is_constant", False)),
                    "input_constant_value": _const_value(inp_var),
                    "defining_block": def_block,
                    "predecessor": predecessor,
                    "status": status,
                    "authority": authority,
                    "input_order_used": False,
                })

            records.append({
                "output_sid": getattr(phi, "output_sid", None),
                "output_name": getattr(phi, "output_name", None),
                "block": join_addr,
                "bindings": bindings,
                "resolved_bindings": sum(
                    1 for item in bindings if item.get("status", "").startswith("resolved")
                ),
                "unresolved_bindings": sum(
                    1 for item in bindings if not item.get("status", "").startswith("resolved")
                ),
                "authority": "legacy_local_multiway_PHI_linkage_fallback",
            })

        # Attach predecessor-owned PHI sources to each arm. An arm can own more
        # than one join predecessor when it branches internally before joining.
        for arm in list(arms or []):
            owned = set(arm.get("join_predecessors", []) or [])
            phi_inputs = []
            for phi_rec in records:
                for binding in phi_rec.get("bindings", []) or []:
                    if binding.get("predecessor") in owned:
                        phi_inputs.append({
                            "output_sid": phi_rec.get("output_sid"),
                            "input_sid": binding.get("input_sid"),
                            "predecessor": binding.get("predecessor"),
                            "binding_status": binding.get("status"),
                            "authority": binding.get("authority"),
                        })
            arm["phi_inputs"] = phi_inputs

        if total == 0:
            status = "not_applicable"
        elif unresolved == 0:
            status = "resolved"
        elif unresolved < total:
            status = "partially_resolved"
        else:
            status = "unresolved"

        return {
            "status": status,
            "join": join_addr,
            "predecessors": sorted(predecessor_addrs),
            "phis": records,
            "total_bindings": total,
            "resolved_bindings": total - unresolved,
            "unresolved_bindings": unresolved,
            "phi_input_order_used_for_predecessor_mapping": False,
            "authority": (
                "PALSemanticGraphBuilder_v37_generic_PHI_predecessor_edge_linkage"
                if generic_authority_used else
                "FormulaNode_definition_block_or_unique_CFG_reachability"
            ),
        }

    def _multiway_reaches_before_join_v30(self, start, target, join, limit=4096):
        if start is None or target is None:
            return False
        if start is target:
            return True
        seen = set()
        work = [start]
        steps = 0
        while work and steps < limit:
            node = work.pop()
            steps += 1
            if node in seen or node is join:
                continue
            seen.add(node)
            for succ in self._successor_nodes_v24(node):
                if succ is target:
                    return True
                if succ is not join and succ not in seen:
                    work.append(succ)
        return False

    def _multiway_case_value_coverage_v30(self, cases):
        values = []
        duplicates = []
        seen = set()
        for case in list(cases or []):
            for value in list(case.get("values", []) or []):
                if value in seen:
                    duplicates.append(value)
                else:
                    seen.add(value)
                    values.append(value)
        return {
            "values": sorted(values),
            "duplicates": sorted(set(duplicates)),
            "case_targets": len(list(cases or [])),
            "value_count": len(values),
            "authority": "FunctionCFG_v22_Ghidra_JumpTable_labels",
            "successor_order_used": False,
        }

    def _multiway_cfg_node_v30(self, addr):
        cfg = getattr(self.func, "cfg", None)
        nodes = getattr(cfg, "nodes", None) if cfg is not None else None
        if isinstance(nodes, dict):
            return nodes.get(addr)
        return None

    def _multiway_node_for_sid_v30(self, sid):
        if sid is None:
            return None
        variants = [sid, str(sid)]
        text = str(sid)
        if text.startswith("v_") and text[2:].isdigit():
            variants.append(int(text[2:]))
        elif text.isdigit():
            variants.append("v_%s" % text)
        for key in variants:
            if key in self.var_nodes:
                return self.var_nodes[key]
        return None

    def _multiway_var_for_sid_v30(self, sid):
        node = self._multiway_node_for_sid_v30(sid)
        if node is not None:
            return getattr(node, "var", None)
        vars_in = getattr(self.func, "vars", {}) or {}
        if isinstance(vars_in, dict):
            for key in (sid, str(sid), _canonical_ssa_name_v29(sid)):
                if key in vars_in:
                    return vars_in[key]
        return None

    def _multiway_dynamic_leaf_sids_v30(self, value, seen=None):
        if seen is None:
            seen = set()
        if value is None:
            return set()
        node = value if hasattr(value, "opcode") else self.get_node(value)
        if node is None:
            var = _unwrap_var(value)
            if var is None or getattr(var, "is_constant", False):
                return set()
            sid = getattr(var, "ssa_id", None)
            return set([sid]) if sid is not None else set()
        sid = getattr(node, "ssa_id", None)
        key = sid if sid is not None else id(node)
        if key in seen:
            return set()
        seen.add(key)
        if getattr(node, "opcode", None) == "LOAD":
            addr = self._multiway_load_address_value_v30(node)
            return self._multiway_dynamic_leaf_sids_v30(addr, seen)
        out = set()
        for inp in list(getattr(node, "inputs", []) or []):
            if self._multiway_is_constant_value_v30(inp):
                continue
            out |= self._multiway_dynamic_leaf_sids_v30(inp, seen)
        if not out and sid is not None:
            out.add(sid)
        return out

    def _multiway_constants_v30(self, value, seen=None):
        if seen is None:
            seen = set()
        if value is None:
            return set()
        var = _unwrap_var(value)
        if getattr(var, "is_constant", False):
            val = self._multiway_const_v30(var)
            return set([val]) if isinstance(val, int) else set()
        node = value if hasattr(value, "opcode") else self.get_node(value)
        if node is None:
            return set()
        sid = getattr(node, "ssa_id", None)
        key = sid if sid is not None else id(node)
        if key in seen:
            return set()
        seen.add(key)
        out = set()
        for inp in list(getattr(node, "inputs", []) or []):
            out |= self._multiway_constants_v30(inp, seen)
        return out

    def _multiway_is_constant_value_v30(self, value):
        return bool(getattr(_unwrap_var(value), "is_constant", False))

    def _multiway_const_v30(self, value):
        var = _unwrap_var(value)
        if var is None or not getattr(var, "is_constant", False):
            return None
        for attr in ("const_value", "value", "offset", "address"):
            val = getattr(var, attr, None)
            if isinstance(val, int):
                return val
        return None

    def _multiway_expr_v30(self, value, seen=None):
        if value is None:
            return None
        if seen is None:
            seen = set()
        node = value if hasattr(value, "opcode") else self.get_node(value)
        if node is None:
            return self._var_expr_v24(value)
        sid = getattr(node, "ssa_id", None)
        key = sid if sid is not None else id(node)
        if key in seen:
            return self._var_expr_v24(getattr(node, "var", None))
        seen.add(key)
        opcode = str(getattr(node, "opcode", "") or "")
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT") and inputs:
            return self._multiway_expr_v30(inputs[0], seen)
        if opcode == "SUBPIECE" and inputs:
            return self._multiway_expr_v30(inputs[0], seen)
        if opcode == "LOAD":
            addr = self._multiway_load_address_value_v30(node)
            return "LOAD[%s]" % self._multiway_expr_v30(addr, seen)
        if opcode == "PTRADD" and len(inputs) >= 2:
            base = self._multiway_expr_v30(inputs[0], seen.copy())
            index = self._multiway_expr_v30(inputs[1], seen.copy())
            scale = self._multiway_expr_v30(inputs[2], seen.copy()) if len(inputs) > 2 else "1"
            return "(%s + (%s * %s))" % (base, index, scale)

        binops = {
            "INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*",
            "INT_DIV": "//", "INT_SDIV": "//", "INT_REM": "%",
            "INT_SREM": "%", "INT_AND": "&", "INT_OR": "|",
            "INT_XOR": "^", "INT_LEFT": "<<", "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>", "INT_EQUAL": "==", "INT_NOTEQUAL": "!=",
            "INT_LESS": "<", "INT_SLESS": "<", "INT_LESSEQUAL": "<=",
            "INT_SLESSEQUAL": "<=", "PTRSUB": "-",
        }
        if opcode in binops and len(inputs) >= 2:
            left = self._multiway_expr_v30(inputs[0], seen.copy())
            right = self._multiway_expr_v30(inputs[1], seen.copy())
            return "(%s %s %s)" % (left, binops[opcode], right)
        return self._var_expr_v24(getattr(node, "var", None))

    def _multiway_unique_strings_v30(self, values):
        out = []
        seen = set()
        for value in list(values or []):
            if value is None:
                continue
            text = str(value)
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out

    def build_induction_update_indexes(self):
        """
        Export induction updates by block and latch/update facts by loop header.
        This does not assert source-level `for`; it only gives SGL a stable list
        of state updates that look like loop-carried iterator/latch work.
        """

        by_block = {}
        for node in list(self.induction_nodes):
            baddr = getattr(node, "block_addr", None)
            if baddr is None:
                continue
            rec = self._induction_record_v24(node)
            by_block.setdefault(baddr, []).append(rec)

        self.induction_updates_by_block = by_block

        cfg = getattr(self.func, "cfg", None)
        headers = list(getattr(cfg, "loop_headers", []) or []) if cfg is not None else []
        latches = getattr(cfg, "loop_latches", {}) if cfg is not None else {}
        loop_nodes = getattr(cfg, "loop_nodes", {}) if cfg is not None else {}
        loop_exits = getattr(cfg, "loop_exits", {}) if cfg is not None else {}

        facts = {}
        for header in headers:
            haddr = self._cfg_addr_v24(header)
            if haddr is None:
                continue

            latch_nodes = list(latches.get(header, []) or []) if isinstance(latches, dict) else []
            update_blocks = []
            updates = []

            for latch in latch_nodes:
                laddr = self._cfg_addr_v24(latch)
                if laddr is None:
                    continue
                if laddr in by_block:
                    update_blocks.append(laddr)
                    updates.extend(by_block.get(laddr, []))

            nodes = set(loop_nodes.get(header, set()) or set()) if isinstance(loop_nodes, dict) else set()
            exits = set(loop_exits.get(header, set()) or set()) if isinstance(loop_exits, dict) else set()

            normal_gateways = []
            continuation_gateways = []
            for ex in exits:
                eaddr = self._cfg_addr_v24(ex)
                if eaddr is None:
                    continue
                preds = self._predecessor_nodes_v24(ex)
                pred_inside = [p for p in preds if p in nodes]
                if self._node_is_condition_block_v24(ex) or len(preds) > 1:
                    continuation_gateways.append(eaddr)
                if pred_inside:
                    normal_gateways.append(eaddr)

            facts[haddr] = {
                "loop_header": haddr,
                "loop_header_hex": _safe_hex(haddr),
                "latch_blocks": [self._cfg_addr_v24(n) for n in latch_nodes if self._cfg_addr_v24(n) is not None],
                "update_blocks": sorted(set(update_blocks)),
                "updates": updates,
                "exit_blocks": [self._cfg_addr_v24(n) for n in exits if self._cfg_addr_v24(n) is not None],
                "normal_completion_gateways": sorted(set(normal_gateways)),
                "continuation_gateways": sorted(set(continuation_gateways)),
                "must_execute_latch_after_normal_body": bool(update_blocks),
                "source": "FunctionCFG.loop_latches+SemanticGraph.induction_nodes",
            }

        self.latch_update_facts = facts

    def build_block_ownership_facts(self):
        """
        Export conservative block ownership/gateway facts.  These help SGL avoid
        inlining shared continuation blocks as branch-local action blocks.
        """

        cfg = getattr(self.func, "cfg", None)
        loop_nodes = getattr(cfg, "loop_nodes", {}) if cfg is not None else {}
        loop_headers = list(getattr(cfg, "loop_headers", []) or []) if cfg is not None else []

        for node in self._cfg_nodes_v24():
            addr = self._cfg_addr_v24(node)
            if addr is None:
                continue

            preds = self._predecessor_nodes_v24(node)
            succs = self._successor_nodes_v24(node)
            in_loops = []
            not_owned_by = []

            for header in loop_headers:
                haddr = self._cfg_addr_v24(header)
                members = set(loop_nodes.get(header, set()) or set()) if isinstance(loop_nodes, dict) else set()
                if node in members:
                    in_loops.append(haddr)
                else:
                    if any(p in members for p in preds):
                        not_owned_by.append(haddr)

            incoming_roles = []
            incoming_order_fallback = False
            incoming_loop_exit = False
            incoming_latch = False
            for p in preds:
                e = self._edge_between_nodes_v24(p, node)
                role = getattr(e, "role", None) if e is not None else None
                raw_type = getattr(e, "raw_type", getattr(e, "type", None)) if e is not None else None
                incoming_roles.append(role or raw_type)
                if "order_fallback" in str(role or ""):
                    incoming_order_fallback = True
                if e is not None and bool(getattr(e, "loop_exit", False) or getattr(e, "is_loop_exit", False)):
                    incoming_loop_exit = True
                if e is not None and bool(getattr(e, "backedge", False) or getattr(e, "is_backedge", False) or getattr(e, "is_latch_edge", False)):
                    incoming_latch = True

            condition_block = self._node_is_condition_block_v24(node)
            executable_ops = self._node_has_executable_ops_v24(node)
            is_join = len(preds) > 1
            role_hint = self._block_role_hint_v24(
                node, is_join, condition_block, executable_ops,
                incoming_order_fallback, incoming_loop_exit, incoming_latch,
                not_owned_by,
            )

            self.block_ownership_facts[addr] = {
                "addr": addr,
                "addr_hex": _safe_hex(addr),
                "predecessor_count": len(preds),
                "successor_count": len(succs),
                "predecessors": [self._cfg_addr_v24(p) for p in preds if self._cfg_addr_v24(p) is not None],
                "successors": [self._cfg_addr_v24(s) for s in succs if self._cfg_addr_v24(s) is not None],
                "is_join": bool(is_join),
                "is_shared_successor": bool(is_join),
                "condition_block": bool(condition_block),
                "executable_ops": bool(executable_ops),
                "incoming_roles": incoming_roles,
                "incoming_order_fallback": bool(incoming_order_fallback),
                "incoming_loop_exit": bool(incoming_loop_exit),
                "incoming_latch": bool(incoming_latch),
                "owning_loop_candidates": [x for x in in_loops if x is not None],
                "not_owned_by_loops": [x for x in not_owned_by if x is not None],
                "role_hint": role_hint,
            }

    def detect_suspicious_successor_custody(self):
        """
        Summarize the exact blocks/edges where SGL should avoid broad
        inference.  PALRAW/HF divergence and order-fallback successors are the
        main signals for alpha_four O3's 0x101235 class.
        """

        out = []

        for addr, rec in self.block_branch_custody.items():
            if rec.get("successors_differ"):
                out.append({
                    "kind": "block_successor_custody_suspicious",
                    "block": addr,
                    "block_hex": _safe_hex(addr),
                    "reason": "successors_differ_or_order_fallback",
                    "terminal_mnemonic": rec.get("terminal_mnemonic"),
                    "condition_expr": rec.get("condition_expr"),
                    "edges": rec.get("edges", []),
                    "recommendation": "SGL should prefer edge_condition_truth and avoid inlining fallback successors as branch-local action blocks.",
                })

        for key, rec in self.edge_condition_truth.items():
            role = str(rec.get("role") or "")
            status = str(rec.get("status") or "")
            if "order_fallback" in role or "differ" in status.lower() or "mismatch" in status.lower():
                out.append({
                    "kind": "edge_condition_truth_suspicious",
                    "src": rec.get("src"),
                    "dst": rec.get("dst"),
                    "src_hex": rec.get("src_hex"),
                    "dst_hex": rec.get("dst_hex"),
                    "reason": "fallback_or_raw_hf_divergence",
                    "edge_expr": rec.get("edge_expr"),
                    "hf_expr": rec.get("hf_expr"),
                    "invert_for_edge": rec.get("invert_for_edge"),
                    "trust": rec.get("trust"),
                    "recommendation": "Treat destination ownership conservatively in SGL conditional-latch lowering.",
                })

        for key, rec in self.edge_truth.items():
            if (
                rec.get("predicate_authoritative") is not True
                or not isinstance(rec.get("invert_for_edge"), bool)
            ):
                out.append({
                    "kind": "edge_truth_unresolved_polarity_v38",
                    "src": rec.get("src"),
                    "dst": rec.get("dst"),
                    "src_hex": rec.get("src_hex"),
                    "dst_hex": rec.get("dst_hex"),
                    "direct_to_join": bool(rec.get("direct_to_join")),
                    "reason": rec.get("selection_reason"),
                    "predicate": rec.get("predicate"),
                    "invert_for_edge": rec.get("invert_for_edge"),
                    "confidence": rec.get("confidence"),
                    "recommendation": (
                        "SGL must not synthesize an executable branch predicate "
                        "until polarity is authoritative."
                    ),
                })

        self.suspicious_successor_custody = out

    # ---------------------------------------------------------
    # v24 metadata helpers
    # ---------------------------------------------------------

    def _cfg_nodes_v24(self):
        cfg = getattr(self.func, "cfg", None)
        if cfg is not None:
            nodes = getattr(cfg, "nodes", None)
            if isinstance(nodes, dict):
                for n in nodes.values():
                    if getattr(n, "addr", None) == "EXIT":
                        continue
                    yield n
                return

        # Fallback: synthesize block-like records by returning block objects.
        for block in getattr(self.func, "blocks", []) or []:
            yield block

    def _cfg_addr_v24(self, node):
        if node is None:
            return None
        addr = getattr(node, "addr", None)
        if addr is None and hasattr(node, "block"):
            addr = getattr(getattr(node, "block", None), "addr", None)
        try:
            if addr == "EXIT":
                return None
            return int(addr)
        except Exception:
            return addr

    def _edge_list_v24(self, cfg_node):
        try:
            return list(getattr(cfg_node, "out_edges", []) or [])
        except Exception:
            return []

    def _successor_nodes_v24(self, cfg_node):
        try:
            succ = getattr(cfg_node, "successors", None)
            if callable(succ):
                return [s for s in list(succ() or []) if s is not None]
            if succ is not None:
                return [s for s in list(succ or []) if s is not None]
        except Exception:
            pass
        return [getattr(e, "dst", None) for e in self._edge_list_v24(cfg_node) if getattr(e, "dst", None) is not None]

    def _predecessor_nodes_v24(self, cfg_node):
        try:
            pred = getattr(cfg_node, "predecessors", None)
            if callable(pred):
                return [p for p in list(pred() or []) if p is not None]
            if pred is not None:
                return [p for p in list(pred or []) if p is not None]
        except Exception:
            pass
        try:
            return [getattr(e, "src", None) for e in list(getattr(cfg_node, "in_edges", []) or []) if getattr(e, "src", None) is not None]
        except Exception:
            return []

    def _edge_between_nodes_v24(self, src, dst):
        cfg = getattr(self.func, "cfg", None)
        if cfg is not None and hasattr(cfg, "edge_between"):
            try:
                e = cfg.edge_between(src, dst)
                if e is not None:
                    return e
            except Exception:
                pass
        for e in self._edge_list_v24(src):
            if getattr(e, "dst", None) is dst:
                return e
        return None

    def _terminator_condition_v24(self, term):
        if term is None or getattr(term, "opcode", None) != "CBRANCH":
            return None
        cond = getattr(term, "condition", None)
        if cond is not None:
            return cond
        inputs = getattr(term, "inputs", []) or []
        if len(inputs) >= 2:
            return inputs[1]
        return None

    def _terminator_target_addr_v24(self, term):
        if term is None:
            return None
        for attr in ("target", "true_target"):
            target = getattr(term, attr, None)
            if target is not None:
                for a in ("addr", "address", "offset", "value"):
                    val = getattr(target, a, None)
                    if isinstance(val, int):
                        return val
        inputs = list(getattr(term, "inputs", []) or [])
        if inputs:
            target = inputs[0]
            for a in ("addr", "address", "offset", "value"):
                val = getattr(target, a, None)
                if isinstance(val, int):
                    return val
        return None

    def _terminal_mnemonic_v24(self, cfg_node):
        # Prefer explicit edge/CFG annotations when PALRAW or FunctionCFG has them.
        for e in self._edge_list_v24(cfg_node):
            for attr in ("mnemonic", "branch_mnemonic", "terminal_mnemonic", "raw_mnemonic"):
                val = getattr(e, attr, None)
                if val:
                    s = str(val).upper()
                    m = re.search(r"\bJ[A-Z]+\b", s)
                    return m.group(0) if m else s

        block = getattr(cfg_node, "block", None)
        term = getattr(block, "terminator", None) if block is not None else None
        for attr in ("mnemonic", "branch_mnemonic", "terminal_mnemonic", "raw_mnemonic"):
            val = getattr(term, attr, None) if term is not None else None
            if val:
                s = str(val).upper()
                m = re.search(r"\bJ[A-Z]+\b", s)
                return m.group(0) if m else s

        return None

    def _edge_record_v24(self, e, src_node, dst_node, cond_node=None):
        src_addr = self._cfg_addr_v24(src_node)
        dst_addr = self._cfg_addr_v24(dst_node)
        status = self._edge_status_v24(e)
        edge_identity = self._cfg_edge_identity_record_v37(
            e, src_addr, dst_addr
        )
        return {
            "edge_id_schema": edge_identity.get(
                "id_schema", "cfg_edge_identity_v1"
            ),
            "edge_id": list(
                edge_identity.get("edge_id", [src_addr, dst_addr])
            ),
            "edge_key": (
                edge_identity.get("edge_key")
                or self._phi_edge_key_v37(src_addr, dst_addr)
            ),
            "edge_identity_frozen": bool(
                edge_identity.get("edge_identity_frozen", False)
            ),
            "direct_to_join": bool(
                edge_identity.get("direct_to_join", False)
            ),
            "direct_join_owner_kind": edge_identity.get(
                "direct_join_owner_kind"
            ),
            "direct_join_empty_arm_candidate": bool(
                edge_identity.get(
                    "direct_join_empty_arm_candidate", False
                )
            ),
            "src": src_addr,
            "src_hex": _safe_hex(src_addr),
            "dst": dst_addr,
            "dst_hex": _safe_hex(dst_addr),
            "role": getattr(e, "role", None),
            "raw_type": getattr(e, "raw_type", getattr(e, "type", None)),
            "type": getattr(e, "type", None),
            "explicit_target": bool(getattr(e, "explicit_target", False) or getattr(e, "is_explicit_target", False)),
            "fallthrough": bool(getattr(e, "fallthrough", False) or getattr(e, "is_fallthrough", False)),
            "backedge": bool(getattr(e, "backedge", False) or getattr(e, "is_backedge", False)),
            "latch_edge": bool(getattr(e, "is_latch_edge", False) or getattr(e, "latch_edge", False)),
            "loop_exit": bool(getattr(e, "loop_exit", False) or getattr(e, "is_loop_exit", False)),
            "function_exit": bool(getattr(e, "function_exit", False) or getattr(e, "is_function_exit_edge", False)),
            "condition_invert_for_edge": self._edge_condition_invert_attr_v24(e),
            "condition_polarity": getattr(e, "condition_polarity", None),
            "condition_reason": self._edge_condition_reason_v24(e),
            "status": status,
            "palraw_status": status,
            "mnemonic": self._terminal_mnemonic_v24(src_node),
            "condition_opcode": getattr(cond_node, "opcode", None) if cond_node is not None else None,
        }

    def _edge_status_v24(self, e):
        if e is None:
            return None
        for attr in ("status", "palraw_status", "raw_status", "successor_status"):
            val = getattr(e, attr, None)
            if val:
                return str(val)
        return None

    def _edge_condition_invert_attr_v24(self, e):
        if e is None:
            return None
        for attr in ("condition_invert_for_edge", "invert_condition_for_edge", "condition_inverted_for_edge"):
            if hasattr(e, attr):
                try:
                    value = self._edge_truth_tristate_bool_v38(
                        getattr(e, attr)
                    )
                    if isinstance(value, bool):
                        return value
                except Exception:
                    continue
        return None

    def _edge_condition_reason_v24(self, e):
        if e is None:
            return None
        return (
            getattr(e, "condition_polarity_reason", None)
            or getattr(e, "condition_polarity", None)
            or getattr(e, "role", None)
            or getattr(e, "raw_type", None)
        )

    def _infer_edge_invert_v24(self, e, mnemonic, opcode, expr):
        """
        Narrow RAW/HF complement inference.  This is metadata, not a structure
        decision.  SGL can choose whether to consume it.
        """

        if e is None:
            return None, None

        raw_type = getattr(e, "raw_type", getattr(e, "type", None))
        role = getattr(e, "role", None)
        explicit = bool(
            getattr(e, "explicit_target", False)
            or getattr(e, "is_explicit_target", False)
            or role == "raw_true_explicit_target"
            or raw_type == "true"
        )

        pol = getattr(e, "condition_polarity", None)
        if pol == "fallthrough" and explicit:
            return True, "condition_polarity_fallthrough_explicit_target"

        m = str(mnemonic or "").upper()
        op = str(opcode or "")
        s = str(expr or "")

        # Target/taken edge only.  Fallthrough edge is the complement.
        if not explicit:
            return None, None

        if m in ("JZ", "JE"):
            if op == "INT_NOTEQUAL" or "!=" in s:
                return True, "raw_JZ_complements_HF_notequal"
        if m in ("JNZ", "JNE"):
            if op == "INT_EQUAL" or "==" in s:
                return True, "raw_JNZ_complements_HF_equal"
        if m in ("JG", "JA", "JNLE", "JNBE"):
            if op in ("INT_SLESS", "INT_LESS", "INT_SLESSEQUAL", "INT_LESSEQUAL") or "<" in s:
                return True, "raw_greater_branch_complements_HF_less"
        if m in ("JLE", "JBE", "JNG", "JNA"):
            # Usually Ghidra has already normalized <= as const<var or x<C+1.
            # Export a conservative non-invert hint; SGL has protected latch
            # logic for cases where a backedge needs inversion.
            if op in ("INT_SLESS", "INT_LESS", "INT_SLESSEQUAL", "INT_LESSEQUAL") or "<" in s:
                return False, "raw_less_equal_branch_left_direct_for_HF_less"

        return None, None

    def _custody_hint_from_edges_v24(self, edge_records):
        roles = " ".join(str(r.get("role") or "") for r in edge_records).lower()
        if "order_fallback" in roles:
            return "contains_order_fallback_successor"
        if any(r.get("backedge") or r.get("latch_edge") for r in edge_records):
            return "contains_latch_or_backedge"
        if any(r.get("loop_exit") for r in edge_records):
            return "contains_loop_exit"
        return "ordinary_branch_custody" if edge_records else "no_edges"

    def _induction_record_v24(self, node):
        base = getattr(node, "induction_base", None)
        step = getattr(node, "induction_step", None)
        return {
            "sid": getattr(node, "ssa_id", None),
            "name": getattr(node, "name", None),
            "block": getattr(node, "block_addr", None),
            "block_hex": _safe_hex(getattr(node, "block_addr", None)),
            "opcode": getattr(node, "opcode", None),
            "base_sid": _sid(base),
            "base_name": getattr(_unwrap_var(base), "name", None),
            "step_sid": _sid(step),
            "step_value": getattr(node, "induction_step_value", None),
            "storage_key": getattr(node, "storage_key", None),
            "output_storage_key": getattr(node, "output_storage_key", None),
            "semantic_role": getattr(node, "semantic_role", None),
        }

    def _node_is_condition_block_v24(self, cfg_node):
        block = getattr(cfg_node, "block", None)
        term = getattr(block, "terminator", None) if block is not None else None
        return getattr(term, "opcode", None) == "CBRANCH"

    def _node_has_executable_ops_v24(self, cfg_node):
        block = getattr(cfg_node, "block", None)
        if block is None and hasattr(cfg_node, "ops"):
            block = cfg_node
        if block is None:
            return False

        term = getattr(block, "terminator", None)
        term_cond = self._terminator_condition_v24(term)
        cond_sid = getattr(term_cond, "ssa_id", None) if term_cond is not None else None

        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)
            if opcode == "MULTIEQUAL":
                continue
            out = getattr(op, "output", None)
            out_sid = getattr(out, "ssa_id", None)
            if cond_sid is not None and out_sid == cond_sid:
                continue
            if opcode in (
                "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                "INT_LESSEQUAL", "INT_SLESSEQUAL", "BOOL_NEGATE",
                "BOOL_AND", "BOOL_OR", "BOOL_XOR",
            ) and getattr(term, "opcode", None) == "CBRANCH":
                continue
            return True
        return False

    def _block_role_hint_v24(self, node, is_join, condition_block, executable_ops,
                             incoming_order_fallback, incoming_loop_exit,
                             incoming_latch, not_owned_by):
        if incoming_order_fallback:
            return "order_fallback_continuation_gateway"
        if condition_block and is_join and incoming_loop_exit:
            return "shared_loop_exit_condition_gateway"
        if condition_block and is_join:
            return "shared_condition_join_gateway"
        if not_owned_by and condition_block:
            return "enclosing_loop_condition_gateway"
        if incoming_latch:
            return "latch_or_backedge_target"
        if is_join and executable_ops:
            return "shared_executable_join"
        if is_join:
            return "shared_join"
        if condition_block:
            return "condition_block"
        return "ordinary_block"

    def _formula_expr_v24(self, node, seen=None):
        """
        Small expression renderer for metadata only.  It intentionally mirrors
        SGL's simple expression format but does not affect emitted code.
        """

        if node is None:
            return None
        if seen is None:
            seen = set()

        sid = getattr(getattr(node, "var", None), "ssa_id", None)
        if sid is not None:
            if sid in seen:
                return self._var_expr_v24(getattr(node, "var", None))
            seen.add(sid)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode == "COPY":
            projection = self._snapshot_projection_name_v35(node)
            if projection is not None:
                return projection
        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC", "SUBPIECE") and inputs:
            child = self.get_node(inputs[0])
            if child is not None:
                return self._formula_expr_v24(child, seen)
            return self._var_expr_v24(inputs[0])

        binops = {
            "INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*",
            "INT_DIV": "//", "INT_SDIV": "//", "INT_REM": "%", "INT_SREM": "%",
            "INT_AND": "&", "INT_OR": "|", "INT_XOR": "^",
            "INT_LEFT": "<<", "INT_RIGHT": ">>", "INT_SRIGHT": ">>",
            "INT_EQUAL": "==", "INT_NOTEQUAL": "!=",
            "INT_LESS": "<", "INT_SLESS": "<",
            "INT_LESSEQUAL": "<=", "INT_SLESSEQUAL": "<=",
            "BOOL_AND": "and", "BOOL_OR": "or", "BOOL_XOR": "^",
        }

        if opcode in binops and len(inputs) == 2:
            a = self._value_expr_v24(inputs[0], seen.copy(), consumer=node, operand_index=0)
            b = self._value_expr_v24(inputs[1], seen.copy(), consumer=node, operand_index=1)
            consumer_sid = self._projection_sid_text_v32(getattr(node, "var", None))
            identity = self._operand_identity_by_consumer_v34.get(consumer_sid) or {}
            if (
                opcode in {
                    "INT_SUB", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
                    "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_LESS",
                    "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
                }
                and str(a) == str(b)
                and identity.get("status") == "resolved_exact_consumer_projection"
            ):
                self._record_operand_identity_failure_v34(
                    node,
                    "resolved_distinct_storage_operands_recollapsed_during_formula_render",
                    {"left": a, "right": b, "identity": identity},
                )
                raise RuntimeError(
                    "PALSemanticGraphBuilder v34 exact operand projection "
                    "re-collapsed during metadata rendering for %s"
                    % consumer_sid
                )
            return "(%s %s %s)" % (a, binops[opcode], b)

        if opcode == "BOOL_NEGATE" and inputs:
            return "not (%s)" % self._value_expr_v24(inputs[0], seen.copy(), consumer=node, operand_index=0)

        if opcode in ("CALL", "CALLIND"):
            return self._var_expr_v24(getattr(node, "var", None))

        return self._var_expr_v24(getattr(node, "var", None))

    def _value_expr_v24(self, v, seen=None, consumer=None, operand_index=None):
        if v is None:
            return "None"
        if consumer is not None and operand_index is not None:
            rec = self._projection_contract_for_operand_v32(consumer, operand_index)
            if isinstance(rec, dict) and rec.get("projection_name"):
                return str(rec.get("projection_name"))
        if hasattr(v, "var") and hasattr(v, "opcode"):
            return self._formula_expr_v24(v, seen or set())
        if getattr(v, "is_constant", False):
            return self._const_expr_v24(v)
        child = self.get_node(v)
        if child is not None:
            if getattr(child, "opcode", None) in ("CALL", "CALLIND"):
                return self._var_expr_v24(getattr(child, "var", v))
            return self._formula_expr_v24(child, seen or set())
        return self._var_expr_v24(v)

    def _var_expr_v24(self, v):
        """Generic variable renderer with no global v33 projection override.

        Exact joint-consumer repair occurs only in _value_expr_v24 when both
        consumer and operand_index identify a compiled contract. All unrelated
        expressions retain the stable legacy authority order.
        """
        return self._legacy_var_expr_v33(v)

    def _const_expr_v24(self, v):
        v = _unwrap_var(v)
        for attr in ("const_value", "value", "offset", "address"):
            val = getattr(v, attr, None)
            if val is None:
                continue
            if isinstance(val, int) and abs(val) >= 10:
                return hex(val)
            return str(val)
        return "0"


    # ---------------------------------------------------------
    # EDGE TRUTH PUBLIC HELPERS
    # ---------------------------------------------------------

    def edge_truth_for(self, src_addr, dst_addr):
        """
        Return the canonical EdgeTruth record for a concrete CFG edge.

        Downstream layers may call this when they have integer addresses rather
        than cfg-node objects.  The record's predicate always means: when this
        predicate is true, execution takes src_addr -> dst_addr.
        """
        try:
            key = (int(src_addr), int(dst_addr))
        except Exception:
            key = (src_addr, dst_addr)
        return self.edge_truth.get(key)

    def edge_predicate_for(self, src_addr, dst_addr):
        """
        Return only the canonical predicate string for src_addr -> dst_addr.
        """
        rec = self.edge_truth_for(src_addr, dst_addr)
        if rec is None:
            return None
        return rec.get("predicate") or rec.get("edge_expr")

    # ---------------------------------------------------------
    # HELPERS
    # ---------------------------------------------------------

    def get_node(self, var):
        """
        Resolve PALVariable -> FormulaNode if present.
        """

        if var is None:
            return None

        if hasattr(var, "var") and hasattr(var, "opcode"):
            return var

        sid = getattr(var, "ssa_id", None)

        if sid is None:
            return None

        return self.var_nodes.get(sid)

    def unwrap_var(self, x):
        return _unwrap_var(x)

    def is_constant_var(self, v):
        return _is_constant(v)

    def same_storage(self, a, b):
        """
        Conservative logical-storage equivalence.

        This intentionally does not compare only SSA id, because different SSA
        versions of the same local/register often need to be recognized as
        related.
        """

        a = _unwrap_var(a)
        b = _unwrap_var(b)

        if a is None or b is None:
            return False

        # Exact object identity.
        if a is b:
            return True

        # Same SSA id.
        aid = getattr(a, "ssa_id", None)
        bid = getattr(b, "ssa_id", None)
        if aid is not None and aid == bid:
            return True

        # Same storage identity, if available.
        ak = _storage_key(a)
        bk = _storage_key(b)

        if ak == bk and ak is not None and any(x is not None for x in ak):
            return True

        # Same name + same storage class can help after resolver cleanup,
        # but avoid applying this to compiler temps.
        an = getattr(a, "name", None)
        bn = getattr(b, "name", None)
        avtype = getattr(a, "var_type", None)
        bvtype = getattr(b, "var_type", None)

        if an and an == bn and avtype == bvtype and avtype in ("stack", "global", "param"):
            return True

        return False

    # ---------------------------------------------------------
    # DEBUG
    # ---------------------------------------------------------

    def debug_summary(self):

        print("\n[SEMANTIC GRAPH SUMMARY]")
        print("-" * 60)

        print("Formula Nodes :", len(self.var_nodes))
        print("PHI Nodes     :", len(self.phi_nodes))
        print("Condition Vars:", len(self.condition_vars))
        print("Return Vars   :", len(self.return_vars))
        print("Call Nodes    :", len(self.call_nodes))
        print("Inductions    :", len(self.induction_nodes))
        print("SGL Branch Custody:", len(getattr(self, "block_branch_custody", {}) or {}))
        print("SGL Edge Condition Truth:", len(getattr(self, "edge_condition_truth", {}) or {}))
        print("EdgeTruth v26:", len(getattr(self, "edge_truth", {}) or {}))
        print("EdgeTruth Debug:", len(getattr(self, "edge_truth_debug", []) or []))
        print("Multiway Semantic v31:", len(
            getattr(self, "semantic_multiway_dispatch_facts", []) or []
        ))
        print("SGL Latch Facts:", len(getattr(self, "latch_update_facts", {}) or {}))
        print("SGL Suspicious Custody:", len(getattr(self, "suspicious_successor_custody", []) or []))

        if self.unresolved_inputs:
            print("Unresolved Inputs:", len(self.unresolved_inputs))

        if self.semantic_events:
            print("Events:", len(self.semantic_events))

        print("-" * 60)

    def debug_dump(self, limit=None):

        print("\n[SEMANTIC GRAPH DUMP]")
        print("-" * 60)

        count = 0

        for sid, node in self.var_nodes.items():

            if limit is not None and count >= limit:
                print("... truncated ...")
                break

            count += 1

            flags = []

            if node.is_phi:
                flags.append("PHI")
            if node.is_condition:
                flags.append("COND")
            if node.is_return_value:
                flags.append("RET")
            if node.is_induction:
                flags.append("IND")
            if node.is_call:
                flags.append("CALL")
            if node.is_compare:
                flags.append("CMP")

            flag_txt = ",".join(flags) if flags else "-"

            ins = []

            for i in node.inputs:

                if hasattr(i, "var"):
                    ins.append(getattr(i.var, "ssa_id", str(i)))
                else:
                    ins.append(getattr(i, "ssa_id", str(i)))

            print(
                "%-12s = %-12s %-30s block=%s flags=%s role=%s width=%s storage=%s" %
                (
                    sid,
                    node.opcode,
                    str(ins),
                    node.block_addr_hex,
                    flag_txt,
                    node.semantic_role,
                    node.width_bits,
                    node.storage_key,
                )
            )

        print("-" * 60)
