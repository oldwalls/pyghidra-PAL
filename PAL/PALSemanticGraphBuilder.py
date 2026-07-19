# ============================================================
# PAL SEMANTIC GRAPH BUILDER
# v29 canonical SSA identity bridge + authoritative EdgeTruth metadata
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
        self.edge_truth_version = "PALSemanticGraphBuilder_v28_EdgeTruth"

        self.induction_updates_by_block = {}
        self.latch_update_facts = {}
        self.block_ownership_facts = {}
        self.suspicious_successor_custody = []
        self.sgl_structuring_handoff = {}

    # ---------------------------------------------------------
    # PUBLIC ENTRY
    # ---------------------------------------------------------

    def run(self):

        self.build_nodes()
        self.link_inputs()
        self.build_use_indexes()
        self.build_phi_nodes()

        self.mark_condition_nodes()
        self.mark_return_values()
        self.mark_call_nodes()
        self.mark_classification_nodes()

        self.detect_induction_variables()
        self.annotate_storage_flows()

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

        # Legacy-compatible with current PALPHIfolder and PALemitter.
        self.func.var_nodes = (self.var_nodes, self.phi_nodes)

        # Canonical aliases.
        self.func.formula_nodes = self.var_nodes
        self.func.phi_nodes = self.phi_nodes
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
            "condition_count": len(self.condition_vars),
            "return_count": len(self.return_vars),
            "call_count": len(self.call_nodes),
            "unresolved_input_count": len(self.unresolved_inputs),
            "induction_count": len(self.induction_nodes),
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
        self.edge_truth_version = "PALSemanticGraphBuilder_v28_EdgeTruth"
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
        self.detect_suspicious_successor_custody()

        self.sgl_structuring_handoff = {
            "version": "PALSemanticGraphBuilder_v26_edgetruth_authoritative",
            "block_branch_custody": self.block_branch_custody,
            "edge_condition_truth": self.edge_condition_truth,
            "edge_truth_version": self.edge_truth_version,
            "edge_truth": self.edge_truth,
            "edge_truth_by_src": self.edge_truth_by_src,
            "edge_truth_by_dst": self.edge_truth_by_dst,
            "edge_truth_predicates": self.edge_truth_predicates,
            "edge_truth_profiles": self.edge_truth_profiles,
            "edge_truth_debug": self.edge_truth_debug,
            "induction_updates_by_block": self.induction_updates_by_block,
            "latch_update_facts": self.latch_update_facts,
            "block_ownership_facts": self.block_ownership_facts,
            "suspicious_successor_custody": self.suspicious_successor_custody,
        }

        self.semantic_events.append({
            "kind": "sgl_structuring_metadata_built_v24",
            "block_branch_custody": len(self.block_branch_custody),
            "edge_condition_truth": len(self.edge_condition_truth),
            "edge_truth_version": self.edge_truth_version,
            "edge_truth": len(self.edge_truth),
            "edge_truth_by_src": len(self.edge_truth_by_src),
            "edge_truth_by_dst": len(self.edge_truth_by_dst),
            "edge_truth_predicates": len(self.edge_truth_predicates),
            "edge_truth_profiles": len(self.edge_truth_profiles),
            "edge_truth_debug": len(self.edge_truth_debug),
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
                "condition_expr": self._formula_expr_v24(cond_node) if cond_node is not None else None,
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
            hf_expr = self._formula_expr_v24(cond_node) if cond_node is not None else None
            opcode = getattr(cond_node, "opcode", None) if cond_node is not None else None
            mnemonic = self._terminal_mnemonic_v24(cfg_node)

            for e in self._edge_list_v24(cfg_node):
                dst_node = getattr(e, "dst", None)
                dst = self._cfg_addr_v24(dst_node)
                if dst is None:
                    continue

                explicit_invert = self._edge_condition_invert_attr_v24(e)
                inferred_invert, inferred_reason = self._infer_edge_invert_v24(
                    e, mnemonic, opcode, hf_expr
                )

                if explicit_invert is not None:
                    invert = bool(explicit_invert)
                    reason = self._edge_condition_reason_v24(e) or "edge_condition_invert_attr"
                    trust = "edge_metadata"
                else:
                    invert = bool(inferred_invert)
                    reason = inferred_reason or self._edge_condition_reason_v24(e) or "edge_direct"
                    trust = "mnemonic_opcode_inferred" if inferred_reason else "edge_direct"

                edge_expr = None
                if hf_expr:
                    edge_expr = "not (%s)" % hf_expr if invert else hf_expr

                status = self._edge_status_v24(e)
                if status and ("differ" in str(status).lower() or "mismatch" in str(status).lower()):
                    trust = "raw_hf_divergence_requires_sgl_care"

                self.edge_condition_truth[(src, dst)] = {
                    "src": src,
                    "src_hex": _safe_hex(src),
                    "dst": dst,
                    "dst_hex": _safe_hex(dst),
                    "condition_sid": cond_sid,
                    "condition_opcode": opcode,
                    "hf_expr": hf_expr,
                    "edge_expr": edge_expr,
                    "invert_for_edge": bool(invert),
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
        self.edge_truth_version = "PALSemanticGraphBuilder_v28_EdgeTruth"

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
            hf_expr = self._formula_expr_v24(cond_node) if cond_node is not None else None
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

                invert = bool(selected.get("invert_for_edge"))
                predicate = self._edge_truth_apply_invert_v25(hf_expr, invert)
                inverse = self._edge_truth_apply_invert_v25(hf_expr, not invert) if hf_expr else None

                role = getattr(e, "role", None)
                raw_type = getattr(e, "raw_type", getattr(e, "type", None))
                status = self._edge_status_v24(e)
                explicit = self._edge_is_explicit_target_v25(e, dst, terminal_target)
                fallthrough = self._edge_is_fallthrough_v25(e, dst, terminal_target, edges)

                rec = {
                    "version": "PALSemanticGraphBuilder_v28_EdgeTruth",
                    "src": src,
                    "src_hex": _safe_hex(src),
                    "dst": dst,
                    "dst_hex": _safe_hex(dst),

                    # Canonical contract.
                    "predicate": predicate,
                    "edge_expr": predicate,
                    "inverse_predicate": inverse,
                    "predicate_holds_means_take_edge": True,
                    "invert_for_edge": invert,
                    "selection_source": selected.get("source"),
                    "selection_reason": selected.get("reason"),
                    "confidence": selected.get("confidence"),

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

                self.edge_truth[(src, dst)] = rec
                self.edge_truth_by_src.setdefault(src, []).append(rec)
                self.edge_truth_by_dst.setdefault(dst, []).append(rec)
                self.edge_truth_predicates[(src, dst)] = predicate

                if self._edge_truth_record_needs_debug_v25(rec):
                    self.edge_truth_debug.append(self._edge_truth_debug_record_v25(rec))

        self.semantic_events.append({
            "kind": "edge_truth_built_v28",
            "edge_truth_version": self.edge_truth_version,
            "edge_truth": len(self.edge_truth),
            "edge_truth_by_src": len(self.edge_truth_by_src),
            "edge_truth_by_dst": len(self.edge_truth_by_dst),
            "edge_truth_predicates": len(self.edge_truth_predicates),
            "edge_truth_profiles": len(self.edge_truth_profiles),
            "debug_records": len(self.edge_truth_debug),
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
            taken_invert = False
            taken_invert_reason = "asm_hf_same_family_unknown_polarity_default_direct"
            taken_invert_confidence = "medium"
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
            invert = bool(norm_override.get("invert_for_edge"))
            votes.append({
                "source": "normalized_relational_override_v28",
                "invert": invert,
                "confidence": norm_override.get("confidence", "high"),
                "reason": norm_override.get("reason"),
            })
            if explicit_invert is not None and bool(explicit_invert) != invert:
                divergence["explicit_edge_invert_overridden_v28"] = {
                    "explicit_invert": bool(explicit_invert),
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
            invert = bool(explicit_invert)
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

        taken_invert = branch_profile.get("taken_invert")
        taken_reason = branch_profile.get("taken_invert_reason")
        taken_conf = branch_profile.get("taken_invert_confidence") or "low"

        if taken_invert is not None:
            if is_taken_edge:
                invert = bool(taken_invert)
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
                invert = not bool(taken_invert)
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
            invert = bool(legacy.get("invert_for_edge"))
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

        # Last-resort CFG shape fallback.  Do not pretend it is high trust.
        if is_taken_edge:
            invert = False
            reason = "taken_edge_default_direct_no_relation"
        elif is_fallthrough_edge:
            invert = True
            reason = "fallthrough_default_inverse_no_relation"
        else:
            invert = False
            reason = "unknown_edge_default_direct"
            divergence["unclassified_successor_edge"] = True

        status = self._edge_status_v24(e)
        if status and ("differ" in str(status).lower() or "mismatch" in str(status).lower()):
            divergence["edge_status_divergence"] = str(status)

        votes.append({"source": "cfg_shape_fallback", "invert": invert, "confidence": "low"})
        return {
            "invert_for_edge": invert,
            "source": "cfg_shape_fallback",
            "reason": reason,
            "confidence": "low",
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
                explicit_invert is not None and bool(explicit_invert) != bool(invert)
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
        if expr is None:
            return None
        if not invert:
            return expr
        return "not (%s)" % expr

    def _edge_truth_record_needs_debug_v25(self, rec):
        if rec is None:
            return False
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
        dst_addr = self._cfg_addr_v24(dst_node)
        status = self._edge_status_v24(e)
        return {
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
                    return bool(getattr(e, attr))
                except Exception:
                    return None
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
            return False, None

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
            return False, None

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

        return False, None

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
            a = self._value_expr_v24(inputs[0], seen.copy())
            b = self._value_expr_v24(inputs[1], seen.copy())
            return "(%s %s %s)" % (a, binops[opcode], b)

        if opcode == "BOOL_NEGATE" and inputs:
            return "not (%s)" % self._value_expr_v24(inputs[0], seen.copy())

        if opcode in ("CALL", "CALLIND"):
            return self._var_expr_v24(getattr(node, "var", None))

        return self._var_expr_v24(getattr(node, "var", None))

    def _value_expr_v24(self, v, seen=None):
        if v is None:
            return "None"
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
        v = _unwrap_var(v)
        if v is None:
            return "None"
        if getattr(v, "is_constant", False):
            return self._const_expr_v24(v)
        sid = getattr(v, "ssa_id", None)
        var_map = getattr(self.func, "var_map", {}) or {}
        if sid is not None and sid in var_map:
            return str(var_map[sid])
        name = getattr(v, "name", None)
        if name:
            return str(name)
        if sid is not None:
            return _canonical_ssa_name_v29(sid)
        return str(v)

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
