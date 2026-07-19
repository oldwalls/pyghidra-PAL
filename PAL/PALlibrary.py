# ======================================
# PAL ITERATION 23b - UNIFIED IR + HARDENED FUNCTION/CALL ABI EVIDENCE
# Lifter + CFG + Symbol Resolution
#
# v23b remains deliberately additive. INDIRECT remains present in the PAL IR for
# compatibility with the alpha-twelve consumers, but its special iop input is
# now resolved to the authoritative HighFunction CALL/STORE owner instead of
# surviving only as an ordinary hexadecimal constant.
#
# ABI-A/ABI-B add serialization-safe function-entry and call-site contracts.
# They distinguish logical prototype parameters from HighFunction physical
# input carriers and implicit machine live-ins.  Existing parameter names and
# consumer behavior remain unchanged until PALSymbolResolver ABI-C consumes
# these facts.
#
# v23b makes prototype arity explicitly authoritative, unresolved, or
# conflicting.  It also separates recovered datatype class from physical ABI
# carrier bank so undefined8 values resident in XMM registers cannot silently
# become integer arguments.  This remains a metadata-only iteration.
# ======================================


# ======================================
# VARIABLE (SSA)
# ======================================

class PALVariable:

    def __init__(self, ssa_id, space, offset, size,
                 is_constant=False, address=None):

        self.ssa_id = ssa_id

        # storage identity
        self.space = space
        self.offset = offset
        self.size = size
        self.address = address

        # Numeric evidence captured by the lifter.  These fields are additive:
        # alpha-nine consumers may ignore them and continue using .size.
        self.width_bytes = int(size) if isinstance(size, int) and size > 0 else None
        self.width_bits = self.width_bytes * 8 if self.width_bytes else None
        self.declared_type = None
        self.declared_type_name = None
        self.declared_domain = None
        self.declared_signedness = None
        self.type_provenance = []
        self.numeric_evidence = {
            "storage_space": space,
            "storage_offset": offset,
            "storage_address": address,
            "width_bytes": self.width_bytes,
            "width_bits": self.width_bits,
            "is_constant": bool(is_constant),
            "sources": ["varnode"],
        }
        self.numeric_contract = None

        # Parameter/signature evidence.  Naming and parameter ordering remain
        # unchanged in this metadata-only iteration.
        self.parameter_ordinal = None
        self.original_name = None

        # VALUE vs LOCATION separation
        self.value = offset if is_constant else None

        # flags
        self.is_constant = is_constant
        self.is_parameter = False
        self.is_stack = False
        self.is_global = False
        self.is_temp = False
        self.is_function = False

        # semantic metadata
        self.var_type = None
        self.semantic_role = None
        self.name = None

        # SSA
        self.def_op = None

        # v22 INDIRECT/storage evidence. These are raw Ghidra observations;
        # resolver/compute layers decide how the storage is represented.
        self.is_addr_tied = None
        self.is_persistent = None
        self.is_input_varnode = None
        self.is_unaffected = None
        self.high_variable_identity = None
        self.indirect_custody_contract = None

    def __repr__(self):
        return f"{self.name or self.ssa_id}"


# ======================================
# P-CODE OPERATION
# ======================================

class PALPcodeOp:

    def __init__(self, op_id, opcode, inputs, output=None):

        self.op_id = op_id
        self.opcode = opcode
        self.inputs = inputs
        self.output = output

        # Raw fixed-width operation evidence.  PALCompute will classify these
        # facts later; PALPcodeOp deliberately performs no C/Python inference.
        self.input_widths = [getattr(v, "width_bits", None) for v in list(inputs or [])]
        self.output_width = getattr(output, "width_bits", None) if output is not None else None
        self.numeric_evidence = {
            "opcode": opcode,
            "input_widths": list(self.input_widths),
            "output_width": self.output_width,
            "source": "high_pcode",
        }
        self.compute_contract = None
        self.call_site_abi_contract = None

        # v22 SSA-marker evidence. INDIRECT is not an executable arithmetic
        # operation; this contract binds it to the operation producing the
        # possible indirect effect.
        self.is_ssa_marker = opcode in {"MULTIEQUAL", "INDIRECT"}
        self.indirect_custody_contract = None
        self.input_roles = ["runtime_operand" for _ in list(inputs or [])]
        self.non_runtime_input_indices = []

        if output:
            output.def_op = self

    def __repr__(self):
        return f"{self.opcode}"


# ======================================
# CONTROL TERMINATOR
# ======================================

class PALTerminator:
    """
    Represents control flow instruction at block end.

    v21b branch-custody model:
        Raw machine control flow supplies physical taken/fallthrough topology.
        HF supplies a normalized predicate, but optimized boolean carriers can
        make raw Jcc/HF-opcode composition invalid.  PAL therefore classifies
        direct flags, source zero-tests, materialized boolean carriers, and
        unresolved cases before assigning edge truth.
    """

    def __init__(self, opcode, inputs, condition=None):

        self.opcode = opcode          # BRANCH / CBRANCH / RETURN
        self.inputs = inputs

        # HighFunction/PAL condition variable.
        self.condition = condition

        # Control operations also retain their raw widths.  This is evidence
        # only; branch ownership/polarity remains entirely under CFG/SGL.
        self.input_widths = [getattr(v, "width_bits", None) for v in list(inputs or [])]
        self.condition_width = getattr(condition, "width_bits", None) if condition is not None else None
        self.numeric_evidence = {
            "opcode": opcode,
            "input_widths": list(self.input_widths),
            "condition_width": self.condition_width,
            "source": "high_pcode",
        }

        # semantic edges (filled later)
        self.true_target = None
        self.false_target = None
        self.target = None

        # HighFunction p-code image for this terminator.
        self.hf_pcode_repr = None
        self.hf_seqnum = None
        self.hf_target_addr = None
        self.hf_normalized_target_addr = None

        # Raw machine / instruction p-code terminal image.
        self.raw_terminal_addr = None
        self.raw_terminal_asm = None
        self.raw_terminal_mnemonic = None
        self.raw_terminal_pcode = []
        self.raw_successors = []
        self.raw_normalized_successors = []
        self.raw_branch_target_addr = None
        self.raw_fallthrough_addr = None
        self.raw_normalized_branch_target_addr = None
        self.raw_normalized_fallthrough_addr = None

        # Branch condition-to-edge binding.
        #   "target"      => self.condition is true for explicit target edge.
        #   "fallthrough" => self.condition is true for fallthrough edge;
        #                    target edge must use not(condition).
        #   "unknown"     => do not infer polarity.
        self.condition_polarity = "unknown"
        self.condition_invert_for_target = None
        self.condition_invert_for_fallthrough = None
        self.condition_polarity_reason = None
        self.condition_truth_authority = None
        self.condition_polarity_hint = None
        self.condition_evidence_class = None

        # Full audit record for POW/diagnostic lookups.
        self.raw_hf_audit = None

# ======================================
# BASIC BLOCK
# ======================================

class PALBlock:

    def __init__(self, block_id, addr):

        self.block_id = block_id
        self.addr = addr

        self.ops = []
        self.terminator = None

        self.successors = []
        self.predecessors = []

        # v18+ POW/PALRAW image slots.
        self.hf_block_index = block_id
        self.hf_block_repr = None
        self.hf_start_addr = addr
        self.hf_stop_addr = None
        self.hf_pcode_image = []
        self.raw_instruction_image = []
        self.raw_terminal_image = None
        self.raw_successors = []
        self.raw_normalized_successors = []
        self.branch_polarity_audit = None

    def __repr__(self):
        return f"<Block {hex(self.addr)}>"

# ============================================================================
# CFG NODE / EDGE
# ============================================================================

class CFGEdge:
    """
    CFG edge with stable topology plus semantic metadata.

    .type remains the older public edge type: true/false/uncond/backedge.
    .raw_type preserves the original type before loop classification.

    v18+ PALRAW metadata tells SGL whether the HF condition must be negated
    for this edge.  This avoids body-swapping heuristics.
    """

    def __init__(self, src, dst, etype, **meta):
        self.src = src
        self.dst = dst
        self.type = etype
        self.raw_type = etype
        self.original_type = etype
        self.meta = dict(meta or {})

        self.is_backedge = False
        self.is_loop_exit = False
        self.is_latch_edge = False
        self.is_function_exit_edge = False

        self.loop_header = None
        self.loop_latch = None

        self.explicit_branch_target = bool(meta.get("explicit_branch_target", False))
        self.is_fallthrough = bool(meta.get("fallthrough", False))
        self.role = meta.get("role", etype)

        # PALRAW condition binding metadata.
        self.condition_polarity = meta.get("condition_polarity", "unknown")

        # v19: polarity is tri-state.  False means "proven direct", not
        # "no proof of inversion".  In particular, an order fallback must not
        # manufacture an authoritative False which EdgeTruth can later mistake
        # for measured branch truth.
        condition_invert = meta.get("condition_invert_for_edge", None)
        if condition_invert is not None:
            self.condition_invert_for_edge = bool(condition_invert)
        self.condition_polarity_reason = meta.get("condition_polarity_reason")
        self.condition_truth_authority = meta.get("condition_truth_authority")
        self.raw_terminal_addr = meta.get("raw_terminal_addr")
        self.raw_terminal_mnemonic = meta.get("raw_terminal_mnemonic")
        self.raw_branch_target_addr = meta.get("raw_branch_target_addr")
        self.raw_fallthrough_addr = meta.get("raw_fallthrough_addr")

    def set_meta(self, **meta):
        self.meta.update(meta or {})

        if "role" in meta:
            self.role = meta["role"]
        if "explicit_branch_target" in meta:
            self.explicit_branch_target = bool(meta["explicit_branch_target"])
        if "fallthrough" in meta:
            self.is_fallthrough = bool(meta["fallthrough"])
        if "condition_polarity" in meta:
            self.condition_polarity = meta["condition_polarity"]
        if "condition_invert_for_edge" in meta:
            condition_invert = meta["condition_invert_for_edge"]
            if condition_invert is None:
                if hasattr(self, "condition_invert_for_edge"):
                    delattr(self, "condition_invert_for_edge")
            else:
                self.condition_invert_for_edge = bool(condition_invert)
        if "condition_polarity_reason" in meta:
            self.condition_polarity_reason = meta["condition_polarity_reason"]
        if "condition_truth_authority" in meta:
            self.condition_truth_authority = meta["condition_truth_authority"]
        if "raw_terminal_addr" in meta:
            self.raw_terminal_addr = meta["raw_terminal_addr"]
        if "raw_terminal_mnemonic" in meta:
            self.raw_terminal_mnemonic = meta["raw_terminal_mnemonic"]
        if "raw_branch_target_addr" in meta:
            self.raw_branch_target_addr = meta["raw_branch_target_addr"]
        if "raw_fallthrough_addr" in meta:
            self.raw_fallthrough_addr = meta["raw_fallthrough_addr"]

        return self

    def __repr__(self):
        s = getattr(self.src, "addr", "?")
        d = getattr(self.dst, "addr", "?")
        s_txt = hex(s) if isinstance(s, int) else str(s)
        d_txt = hex(d) if isinstance(d, int) else str(d)
        return "<CFGEdge %s -> %s type=%s raw=%s role=%s pol=%s invert=%s>" % (
            s_txt, d_txt, self.type, self.raw_type, self.role,
            self.condition_polarity,
            getattr(self, "condition_invert_for_edge", None),
        )


class CFGNode:
    def __init__(self, block):
        self.block = block
        self.addr = getattr(block, "addr", None)

        self.out_edges = []
        self.in_edges = []

        self.dominators = set()
        self.postdominators = set()

        self.ipdom = None

    def predecessors(self):
        return [e.src for e in self.in_edges]

    def successors(self):
        return [e.dst for e in self.out_edges]

    def add_edge(self, dst, etype, **meta):
        e = CFGEdge(self, dst, etype, **meta)
        self.out_edges.append(e)
        dst.in_edges.append(e)
        return e



# ======================================
# FUNCTION OBJECT
# ======================================

class PALFunctionObject:

    def __init__(self, name, entry_addr, addr_range):

        self.func_name = name
        self.function_address = int(entry_addr)
        self.range = (int(addr_range[0]), int(addr_range[1]))

        self.blocks = []
        self.vars = {}
        self.parameters = []

        self.cfg = None

        # v21 numeric-execution evidence.  These containers do not participate
        # in alpha-nine structure recovery; later PALCompute passes consume them.
        self.target_numeric_model = {}
        self.function_signature = {
            "name": name,
            "parameters": [],
            "return": None,
            "calling_convention": None,
        }
        self.numeric_contracts_by_sid = {}
        self.compute_plans_by_sid = {}
        self.numeric_evidence_events = []
        self.compute_events = []
        self.compute_warnings = []

        # v22 HighFunction INDIRECT custody inventory. All structures are
        # serialization-safe and contain no live Java/PyGhidra objects.
        self.indirect_custody_contracts = []
        self.indirect_custody_by_op = {}
        self.indirect_custody_by_output = {}
        self.indirect_effect_owner_groups = {}
        self.indirect_custody_inventory = {}
        self.indirect_custody_warnings = []

        # v23b ABI-A/ABI-B foundational truth. These are evidence contracts,
        # not yet executable calling-convention plans.
        self.function_abi_contract = {}
        self.call_site_abi_contracts = []
        self.call_site_abi_by_op = {}
        self.abi_inventory = {}
        self.abi_warnings = []
        self.abi_observations = []

        # v18+ POW/PALRAW images.  These are stable lookup tables for
        # later raw/HF/source comparison and simulation metadata.
        self.high_function = None
        self.decompiled_c_image = None
        self.hf_pcode_image = {}
        self.raw_machine_image = {}
        self.raw_pcode_image = {}
        self.raw_vs_hf_branch_image = {}
        self.branch_polarity_by_addr = {}
        self.pow_image = {}

    def __repr__(self):
        return f"<PALFunction {self.func_name}>"


# ======================================
# LIFTER
# ======================================

class PALLifter:

    CONTROL_OPS = {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN"}

    def __init__(self, ghidra_func, program, decomp, monitor):

        self.func = ghidra_func
        self.program = program
        self.decomp = decomp
        self.monitor = monitor

        self.pal = None
        self._abi_high_parameters = []

    # ------------------------------------------------------------------
    # v21 raw numeric/type evidence helpers
    # ------------------------------------------------------------------

    def _safe_call(self, obj, method, default=None):
        if obj is None:
            return default
        try:
            fn = getattr(obj, method, None)
            if fn is None:
                return default
            return fn()
        except Exception:
            return default

    def _safe_call_args(self, obj, method, *args, **kwargs):
        default = kwargs.pop("default", None)
        if obj is None:
            return default
        try:
            fn = getattr(obj, method, None)
            if fn is None:
                return default
            return fn(*args)
        except Exception:
            return default

    def _safe_bool(self, value, default=None):
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        try:
            return bool(value)
        except Exception:
            return default

    def _safe_list(self, value):
        if value is None:
            return []
        try:
            return list(value)
        except Exception:
            out = []
            has_next = getattr(value, "hasNext", None)
            next_item = getattr(value, "next", None)
            if callable(has_next) and callable(next_item):
                try:
                    while has_next():
                        out.append(next_item())
                except Exception:
                    pass
            return out

    def _safe_int(self, value, default=None):
        if value is None:
            return default
        try:
            return int(value)
        except Exception:
            return default

    def _java_class_name(self, obj):
        if obj is None:
            return None
        try:
            cls = obj.getClass()
            name = cls.getSimpleName()
            if name:
                return str(name)
        except Exception:
            pass
        try:
            return type(obj).__name__
        except Exception:
            return None

    def _datatype_image(self, datatype, include_child=True):
        """Return a serialization-safe image of a Ghidra DataType.

        The image records evidence only.  Name/class hints are deliberately not
        converted into an authoritative C contract here; PALCompute will apply
        deterministic precedence rules later.
        """
        if datatype is None:
            return None

        name = self._safe_call(datatype, "getName")
        display_name = self._safe_call(datatype, "getDisplayName")
        length = self._safe_int(self._safe_call(datatype, "getLength"))
        class_name = self._java_class_name(datatype)

        image = {
            "name": str(name) if name is not None else None,
            "display_name": str(display_name) if display_name is not None else None,
            "class_name": class_name,
            "length_bytes": length if isinstance(length, int) and length >= 0 else None,
            "width_bits": length * 8 if isinstance(length, int) and length > 0 else None,
            "signed": None,
            "kind_hint": None,
        }

        signed = self._safe_call(datatype, "isSigned")
        if isinstance(signed, bool):
            image["signed"] = signed

        cls_lower = str(class_name or "").lower()
        if "pointer" in cls_lower:
            image["kind_hint"] = "pointer"
        elif "array" in cls_lower:
            image["kind_hint"] = "array"
        elif "boolean" in cls_lower or "bool" in cls_lower:
            image["kind_hint"] = "boolean"
        elif "float" in cls_lower or "double" in cls_lower:
            image["kind_hint"] = "float"
        elif "integer" in cls_lower or "char" in cls_lower or "enum" in cls_lower:
            image["kind_hint"] = "integer"
        elif "structure" in cls_lower or "union" in cls_lower:
            image["kind_hint"] = "aggregate"

        if include_child and image["kind_hint"] in ("pointer", "array"):
            child = self._safe_call(datatype, "getDataType")
            if child is not None and child is not datatype:
                image["element_type"] = self._datatype_image(child, include_child=False)

        base = self._safe_call(datatype, "getBaseDataType")
        if include_child and base is not None and base is not datatype:
            image["base_type"] = self._datatype_image(base, include_child=False)

        return image

    # ------------------------------------------------------------------
    # v23b ABI storage evidence
    # ------------------------------------------------------------------

    def _register_image(self, address, size=None):
        if address is None:
            return None
        register = None
        language = self._safe_call(self.program, "getLanguage")
        for owner in (self.program, language):
            if owner is None:
                continue
            if isinstance(size, int) and size > 0:
                register = self._safe_call_args(
                    owner, "getRegister", address, size, default=None
                )
            if register is None:
                register = self._safe_call_args(
                    owner, "getRegister", address, default=None
                )
            if register is not None:
                break
        if register is None:
            return None

        base = self._safe_call(register, "getBaseRegister")
        return {
            "name": str(self._safe_call(register, "getName") or "") or None,
            "base_name": (
                str(self._safe_call(base, "getName") or "") or None
                if base is not None else None
            ),
            "size_bytes": self._safe_int(
                self._safe_call(register, "getMinimumByteSize")
            ),
            "repr": self._safe_str(register),
        }

    def _varnode_storage_image(self, vn):
        if vn is None:
            return None
        address = self._safe_call(vn, "getAddress")
        size = self._safe_int(self._safe_call(vn, "getSize"))
        space = None
        offset = self._safe_int(self._safe_call(vn, "getOffset"))
        if address is not None:
            try:
                space = str(address.getAddressSpace().getName())
            except Exception:
                space = None
            try:
                offset = int(address.getOffset())
            except Exception:
                pass

        flags = {}
        for key, method in (
            ("constant", "isConstant"),
            ("register", "isRegister"),
            ("address", "isAddress"),
            ("unique", "isUnique"),
            ("input", "isInput"),
            ("unaffected", "isUnaffected"),
        ):
            value = self._safe_call(vn, method)
            if isinstance(value, bool):
                flags[key] = value

        register = self._register_image(address, size)
        kind = "unknown"
        lower_space = str(space or "").lower()
        if register is not None or flags.get("register") or lower_space == "register":
            kind = "register"
        elif "stack" in lower_space:
            kind = "stack"
        elif lower_space in ("ram", "mem", "memory") or flags.get("address"):
            kind = "memory"
        elif flags.get("constant"):
            kind = "constant"
        elif flags.get("unique"):
            kind = "unique"

        key = "%s:%s:%s" % (space, offset, size)
        return {
            "kind": kind,
            "space": space,
            "offset": offset,
            "size_bytes": size,
            "width_bits": size * 8 if isinstance(size, int) and size > 0 else None,
            "storage_key": key,
            "register": register,
            "flags": flags,
            "repr": self._safe_str(vn),
        }

    def _variable_storage_image(self, storage):
        if storage is None:
            return None
        varnodes = self._safe_list(self._safe_call(storage, "getVarnodes"))
        pieces = [
            image for image in (
                self._varnode_storage_image(vn) for vn in varnodes
            ) if image is not None
        ]
        flags = {}
        for key, method in (
            ("register", "isRegisterStorage"),
            ("stack", "isStackStorage"),
            ("memory", "isMemoryStorage"),
            ("unassigned", "isUnassignedStorage"),
            ("void", "isVoidStorage"),
            ("auto", "isAutoStorage"),
        ):
            value = self._safe_call(storage, method)
            if isinstance(value, bool):
                flags[key] = value
        return {
            "repr": self._safe_str(storage),
            "size_bytes": self._safe_int(self._safe_call(storage, "size")),
            "flags": flags,
            "pieces": pieces,
            "storage_keys": [p.get("storage_key") for p in pieces],
        }

    def _high_variable_image(self, high_var):
        if high_var is None:
            return None
        name = self._safe_call(high_var, "getName")
        datatype = self._safe_call(high_var, "getDataType")
        slot = self._safe_int(self._safe_call(high_var, "getSlot"))
        representative = self._safe_call(high_var, "getRepresentative")

        representative_image = None
        if representative is not None:
            rep_addr = self._safe_call(representative, "getAddress")
            rep_space = None
            rep_offset = self._safe_int(self._safe_call(representative, "getOffset"))
            if rep_addr is not None:
                try:
                    rep_space = str(rep_addr.getAddressSpace().getName())
                except Exception:
                    rep_space = None
            representative_image = {
                "unique_id": self._safe_int(self._safe_call(representative, "getUniqueId")),
                "space": rep_space,
                "offset": rep_offset,
                "size": self._safe_int(self._safe_call(representative, "getSize")),
                "repr": self._safe_str(representative),
            }

        # The representative varnode is the strongest serialization-safe key
        # exposed by the Java HighVariable interface. Name alone is not an
        # identity: different scopes can legitimately reuse it.
        identity_key = None
        if representative_image is not None:
            uid = representative_image.get("unique_id")
            if uid is not None:
                identity_key = "high_rep:%s" % uid
            else:
                identity_key = "high_storage:%s:%s:%s" % (
                    representative_image.get("space"),
                    representative_image.get("offset"),
                    representative_image.get("size"),
                )

        return {
            "name": str(name) if name is not None else None,
            "class_name": self._java_class_name(high_var),
            "slot": slot,
            "datatype": self._datatype_image(datatype),
            "identity_key": identity_key,
            "representative": representative_image,
        }

    def _varnode_numeric_evidence(self, vn):
        if vn is None:
            return {}

        size = self._safe_int(self._safe_call(vn, "getSize"))
        evidence = {
            "width_bytes": size,
            "width_bits": size * 8 if isinstance(size, int) and size > 0 else None,
            "varnode_repr": self._safe_str(vn),
            "varnode_class": self._java_class_name(vn),
            "varnode_unique_id": self._safe_int(self._safe_call(vn, "getUniqueId")),
            "merge_group": self._safe_int(self._safe_call(vn, "getMergeGroup")),
            "abi_storage": self._varnode_storage_image(vn),
        }

        for key, method in (
            ("is_addr_tied", "isAddrTied"),
            ("is_persistent", "isPersistent"),
            ("is_input", "isInput"),
            ("is_unaffected", "isUnaffected"),
            ("is_constant", "isConstant"),
            ("is_address", "isAddress"),
            ("is_register", "isRegister"),
            ("is_unique", "isUnique"),
        ):
            value = self._safe_call(vn, method)
            if isinstance(value, bool):
                evidence[key] = value

        pc_addr = self._safe_call(vn, "getPCAddress")
        if pc_addr is not None:
            try:
                evidence["pc_address"] = int(pc_addr.getOffset())
            except Exception:
                evidence["pc_address"] = self._safe_str(pc_addr)

        high_var = self._safe_call(vn, "getHigh")
        high_image = self._high_variable_image(high_var)
        if high_image is not None:
            evidence["high_variable"] = high_image

        try:
            addr = vn.getAddress()
            if addr is not None:
                evidence["storage_space"] = str(addr.getAddressSpace().getName())
                evidence["storage_offset"] = int(addr.getOffset())
        except Exception:
            pass

        return evidence

    def _apply_varnode_numeric_evidence(self, var, vn):
        if var is None or vn is None:
            return

        evidence = self._varnode_numeric_evidence(vn)
        current = getattr(var, "numeric_evidence", None)
        if not isinstance(current, dict):
            current = {}
            var.numeric_evidence = current
        current.update({k: v for k, v in evidence.items() if v is not None})

        width_bytes = evidence.get("width_bytes")
        if isinstance(width_bytes, int) and width_bytes > 0:
            var.width_bytes = width_bytes
            var.width_bits = width_bytes * 8

        high_image = evidence.get("high_variable") or {}
        var.is_addr_tied = evidence.get("is_addr_tied")
        var.is_persistent = evidence.get("is_persistent")
        var.is_input_varnode = evidence.get("is_input")
        var.is_unaffected = evidence.get("is_unaffected")
        var.high_variable_identity = high_image.get("identity_key")

        datatype = high_image.get("datatype") or {}
        if datatype:
            var.declared_type = dict(datatype)
            var.declared_type_name = datatype.get("display_name") or datatype.get("name")
            var.declared_domain = datatype.get("kind_hint")
            if isinstance(datatype.get("signed"), bool):
                var.declared_signedness = "signed" if datatype["signed"] else "unsigned"
            if "high_variable_datatype" not in var.type_provenance:
                var.type_provenance.append("high_variable_datatype")

    # ------------------------------------------------------------------
    # v22 HighFunction INDIRECT custody evidence
    # ------------------------------------------------------------------

    def _seqnum_image(self, op):
        seq = self._safe_call(op, "getSeqnum")
        if seq is None:
            return {
                "repr": None,
                "time": None,
                "order": None,
                "target": None,
            }

        target = self._safe_call(seq, "getTarget")
        target_offset = None
        if target is not None:
            try:
                target_offset = int(target.getOffset())
            except Exception:
                target_offset = None

        return {
            "repr": self._safe_str(seq),
            "time": self._safe_int(self._safe_call(seq, "getTime")),
            "order": self._safe_int(self._safe_call(seq, "getOrder")),
            "target": target_offset,
        }

    def _op_block_addr(self, op):
        parent = self._safe_call(op, "getParent")
        start = self._safe_call(parent, "getStart")
        if start is None:
            return None
        try:
            return int(start.getOffset())
        except Exception:
            return None

    def _custody_var_image(self, raw_vn, pal_var):
        evidence = self._varnode_numeric_evidence(raw_vn)
        high_image = evidence.get("high_variable") or {}
        return {
            "sid": getattr(pal_var, "ssa_id", None),
            "name": getattr(pal_var, "name", None),
            "space": getattr(pal_var, "space", None),
            "offset": getattr(pal_var, "offset", None),
            "size": getattr(pal_var, "size", None),
            "width_bits": getattr(pal_var, "width_bits", None),
            "is_constant": bool(getattr(pal_var, "is_constant", False)),
            "constant_value": (
                getattr(pal_var, "value", None)
                if bool(getattr(pal_var, "is_constant", False))
                else None
            ),
            "is_addr_tied": evidence.get("is_addr_tied"),
            "is_persistent": evidence.get("is_persistent"),
            "is_input": evidence.get("is_input"),
            "is_unaffected": evidence.get("is_unaffected"),
            "pc_address": evidence.get("pc_address"),
            "merge_group": evidence.get("merge_group"),
            "high_variable": high_image or None,
            "high_identity_key": high_image.get("identity_key"),
            "varnode_repr": evidence.get("varnode_repr"),
        }

    def _indirect_custody_contract(self, high, raw_op, block_addr,
                                   raw_inputs, raw_output, inputs, output,
                                   get_var):
        """Build a serialization-safe INDIRECT-to-effect-owner contract.

        HighFunction encodes INDIRECT input1 as an operation reference whose
        numeric offset is SequenceNumber.getTime(), not as a runtime integer.
        PcodeSyntaxTree.getOpRef() is therefore authoritative; no adjacency or
        opcode-shape heuristic is used here.
        """
        warnings = []
        raw_inputs = list(raw_inputs or [])
        inputs = list(inputs or [])

        if len(raw_inputs) < 2:
            warnings.append("indirect_missing_iop_input")

        prior_raw = raw_inputs[0] if raw_inputs else None
        iop_raw = raw_inputs[1] if len(raw_inputs) > 1 else None
        prior_var = inputs[0] if inputs else None

        owner_ref_id = self._safe_int(self._safe_call(iop_raw, "getOffset"))
        owner_op = None
        if owner_ref_id is not None:
            try:
                owner_op = high.getOpRef(owner_ref_id)
            except Exception as exc:
                warnings.append("owner_lookup_failed:%s" % self._safe_str(exc))
        else:
            warnings.append("indirect_iop_reference_not_numeric")

        if owner_op is None:
            warnings.append("indirect_effect_owner_unresolved")

        owner_opcode = self._safe_call(owner_op, "getMnemonic")
        owner_opcode = str(owner_opcode) if owner_opcode is not None else None
        owner_seq = self._seqnum_image(owner_op)

        try:
            owner_raw_inputs = list(owner_op.getInputs()) if owner_op is not None else []
        except Exception:
            owner_raw_inputs = []
        owner_inputs = [get_var(vn) for vn in owner_raw_inputs]

        owner_raw_output = self._safe_call(owner_op, "getOutput")
        owner_output = get_var(owner_raw_output) if owner_raw_output is not None else None
        owner_input_sids = [getattr(v, "ssa_id", None) for v in owner_inputs]

        if owner_opcode in {"CALL", "CALLIND"}:
            owner_category = "call_boundary"
        elif owner_opcode == "STORE":
            owner_category = "memory_store"
        else:
            owner_category = "other_effect" if owner_opcode else "unresolved"

        owner_details = {
            "call_target_sid": None,
            "call_argument_sids": [],
            "memory_space_sid": None,
            "memory_address_sid": None,
            "memory_value_sid": None,
        }
        if owner_opcode in {"CALL", "CALLIND"}:
            owner_details["call_target_sid"] = (
                owner_input_sids[0] if owner_input_sids else None
            )
            owner_details["call_argument_sids"] = list(owner_input_sids[1:])
        elif owner_opcode == "STORE":
            owner_details["memory_space_sid"] = (
                owner_input_sids[0] if len(owner_input_sids) > 0 else None
            )
            owner_details["memory_address_sid"] = (
                owner_input_sids[1] if len(owner_input_sids) > 1 else None
            )
            owner_details["memory_value_sid"] = (
                owner_input_sids[2] if len(owner_input_sids) > 2 else None
            )

        prior_image = self._custody_var_image(prior_raw, prior_var)
        output_image = self._custody_var_image(raw_output, output)
        prior_high_key = prior_image.get("high_identity_key")
        output_high_key = output_image.get("high_identity_key")
        same_high_variable = None
        if prior_high_key is not None and output_high_key is not None:
            same_high_variable = prior_high_key == output_high_key

        prior_is_constant = bool(self._safe_call(prior_raw, "isConstant", False))
        prior_constant_value = self._safe_int(self._safe_call(prior_raw, "getOffset"))
        indirect_creation = bool(prior_is_constant and prior_constant_value == 0)

        indirect_seq = self._seqnum_image(raw_op)
        contract = {
            "kind": "lifter_indirect_custody_v22",
            "version": "v22_highfunction_iop_owner_contracts",
            "indirect_op_id": indirect_seq.get("repr"),
            "indirect_seqnum": indirect_seq,
            "block_addr": block_addr,
            "prior_sid": getattr(prior_var, "ssa_id", None),
            "output_sid": getattr(output, "ssa_id", None),
            "prior_storage": prior_image,
            "output_storage": output_image,
            "same_high_variable": same_high_variable,
            "address_escape_or_memory_custody": bool(
                prior_image.get("is_addr_tied") or output_image.get("is_addr_tied")
            ),
            "owner_ref_id": owner_ref_id,
            "owner_ref_hex": (
                "0x%x" % owner_ref_id if isinstance(owner_ref_id, int) else None
            ),
            "owner_resolved": owner_op is not None,
            "owner_op_id": owner_seq.get("repr"),
            "owner_seqnum": owner_seq,
            "owner_opcode": owner_opcode,
            "owner_category": owner_category,
            "owner_block_addr": self._op_block_addr(owner_op),
            "owner_repr": self._safe_str(owner_op),
            "owner_input_sids": owner_input_sids,
            "owner_output_sid": getattr(owner_output, "ssa_id", None),
            "owner_details": owner_details,
            "indirect_creation": indirect_creation,
            "preserves_prior_value_possibly": not indirect_creation,
            "runtime_operation": False,
            "emits_runtime_helper": False,
            "authority": "ghidra_highfunction_getOpRef",
            "warnings": list(warnings),
        }
        return contract

    def _register_indirect_custody_contract(self, pal_op, output, contract):
        pal_op.indirect_custody_contract = contract
        pal_op.numeric_evidence["indirect_custody"] = contract
        if output is not None:
            output.indirect_custody_contract = contract

        self.pal.indirect_custody_contracts.append(contract)
        indirect_key = contract.get("indirect_op_id") or "indirect:%d" % (
            len(self.pal.indirect_custody_contracts) - 1
        )
        self.pal.indirect_custody_by_op[indirect_key] = contract

        output_sid = contract.get("output_sid")
        if output_sid is not None:
            self.pal.indirect_custody_by_output[output_sid] = contract

        owner_key = str(contract.get("owner_ref_id"))
        group = self.pal.indirect_effect_owner_groups.setdefault(owner_key, {
            "owner_ref_id": contract.get("owner_ref_id"),
            "owner_ref_hex": contract.get("owner_ref_hex"),
            "owner_resolved": contract.get("owner_resolved"),
            "owner_op_id": contract.get("owner_op_id"),
            "owner_opcode": contract.get("owner_opcode"),
            "owner_category": contract.get("owner_category"),
            "owner_block_addr": contract.get("owner_block_addr"),
            "owner_repr": contract.get("owner_repr"),
            "indirect_op_ids": [],
            "output_sids": [],
            "contracts": 0,
        })
        group["contracts"] += 1
        group["indirect_op_ids"].append(indirect_key)
        group["output_sids"].append(output_sid)

        for warning in contract.get("warnings", []) or []:
            self.pal.indirect_custody_warnings.append({
                "kind": "lifter_indirect_custody_warning_v22",
                "indirect_op_id": indirect_key,
                "owner_ref_id": contract.get("owner_ref_id"),
                "warning": warning,
            })

    def _finalize_indirect_custody_inventory(self):
        contracts = list(self.pal.indirect_custody_contracts or [])
        categories = {}
        for contract in contracts:
            category = contract.get("owner_category") or "unknown"
            categories[category] = categories.get(category, 0) + 1

        inventory = {
            "kind": "lifter_indirect_custody_inventory_v22",
            "version": "v22_highfunction_iop_owner_contracts",
            "function": self.pal.func_name,
            "indirect_contracts": len(contracts),
            "indirect_preserving": sum(
                1 for c in contracts if c.get("preserves_prior_value_possibly")
            ),
            "indirect_creation": sum(
                1 for c in contracts if c.get("indirect_creation")
            ),
            "resolved_owner_refs": sum(
                1 for c in contracts if c.get("owner_resolved")
            ),
            "unresolved_owner_refs": sum(
                1 for c in contracts if not c.get("owner_resolved")
            ),
            "owner_groups": len(self.pal.indirect_effect_owner_groups),
            "owner_categories": categories,
            "address_tied_contracts": sum(
                1 for c in contracts if c.get("address_escape_or_memory_custody")
            ),
            "same_high_variable_contracts": sum(
                1 for c in contracts if c.get("same_high_variable") is True
            ),
            "warnings": len(self.pal.indirect_custody_warnings),
            "rule": "resolve_INDIRECT_input1_via_HighFunction_getOpRef",
        }
        self.pal.indirect_custody_inventory = inventory
        self.pal.numeric_evidence_events.append(inventory)
        self.pal.numeric_evidence_events.extend(self.pal.indirect_custody_warnings)

    def _parameter_ordinal(self, symbol, high_var=None):
        for obj, method in (
            (high_var, "getSlot"),
            (symbol, "getCategoryIndex"),
            (symbol, "getSlot"),
        ):
            value = self._safe_int(self._safe_call(obj, method))
            if isinstance(value, int) and value >= 0:
                return value
        return None

    def _parameter_symbol_evidence(self, symbol, high_var=None):
        datatype = self._safe_call(symbol, "getDataType")
        if datatype is None and high_var is not None:
            datatype = self._safe_call(high_var, "getDataType")
        representative = self._safe_call(high_var, "getRepresentative")
        return {
            "name": str(self._safe_call(symbol, "getName") or ""),
            "ordinal": self._parameter_ordinal(symbol, high_var),
            "datatype": self._datatype_image(datatype),
            "symbol_class": self._java_class_name(symbol),
            "storage": self._varnode_storage_image(representative),
            "high_variable": self._high_variable_image(high_var),
        }

    def _target_numeric_model(self):
        model = {
            "byte_bits": 8,
            "endianness": None,
            "pointer_width_bits": None,
            "language_id": None,
            "processor": None,
            "compiler_spec_id": None,
            "executable_format": None,
            "data_organization": {},
        }

        executable_format = self._safe_call(self.program, "getExecutableFormat")
        if executable_format is not None:
            model["executable_format"] = str(executable_format)

        language = self._safe_call(self.program, "getLanguage")
        if language is not None:
            big = self._safe_call(language, "isBigEndian")
            if isinstance(big, bool):
                model["endianness"] = "big" if big else "little"
            language_id = self._safe_call(language, "getLanguageID")
            processor = self._safe_call(language, "getProcessor")
            model["language_id"] = str(language_id) if language_id is not None else None
            model["processor"] = str(processor) if processor is not None else None

        compiler_spec = self._safe_call(self.program, "getCompilerSpec")
        compiler_id = self._safe_call(compiler_spec, "getCompilerSpecID")
        if compiler_id is not None:
            model["compiler_spec_id"] = str(compiler_id)

        default_pointer_size = self._safe_int(self._safe_call(self.program, "getDefaultPointerSize"))
        if isinstance(default_pointer_size, int) and default_pointer_size > 0:
            model["pointer_width_bits"] = default_pointer_size * 8

        data_type_manager = self._safe_call(self.program, "getDataTypeManager")
        data_org = self._safe_call(data_type_manager, "getDataOrganization")
        if data_org is not None:
            sizes = {}
            for key, method in (
                ("pointer_bytes", "getPointerSize"),
                ("char_bytes", "getCharSize"),
                ("short_bytes", "getShortSize"),
                ("int_bytes", "getIntegerSize"),
                ("long_bytes", "getLongSize"),
                ("long_long_bytes", "getLongLongSize"),
            ):
                value = self._safe_int(self._safe_call(data_org, method))
                if isinstance(value, int) and value > 0:
                    sizes[key] = value
            model["data_organization"] = sizes
            if model["pointer_width_bits"] is None and sizes.get("pointer_bytes"):
                model["pointer_width_bits"] = sizes["pointer_bytes"] * 8

        return model

    def _function_prototype_image(self, func, high=None):
        prototype = None
        if high is not None:
            prototype = self._safe_call(high, "getFunctionPrototype")

        parameters = []
        count = self._safe_int(self._safe_call(prototype, "getNumParams"))
        if isinstance(count, int) and count >= 0:
            for ordinal in range(count):
                param = self._safe_call_args(
                    prototype, "getParam", ordinal, default=None
                )
                datatype = self._safe_call(param, "getType")
                if datatype is None:
                    datatype = self._safe_call(param, "getDataType")
                parameters.append({
                    "ordinal": ordinal,
                    "name": str(self._safe_call(param, "getName") or "") or None,
                    "datatype": self._datatype_image(datatype),
                    "repr": self._safe_str(param),
                })

        variadic_values = []
        for owner, method in (
            (func, "hasVarArgs"),
            (func, "isVarArgs"),
            (prototype, "isDotdotdot"),
            (prototype, "hasVarArgs"),
        ):
            value = self._safe_call(owner, method)
            if isinstance(value, bool):
                variadic_values.append({"source": method, "value": value})

        return {
            "repr": self._safe_str(prototype) if prototype is not None else None,
            "model_name": (
                str(self._safe_call(prototype, "getModelName") or "") or None
            ),
            "parameter_count": count,
            "parameters": parameters,
            "variadic_evidence": variadic_values,
            "variadic": any(item["value"] for item in variadic_values),
        }

    @staticmethod
    def _prototype_text_arity_hint(prototype_text):
        """Extract only arity facts that are safe to claim from C text.

        Empty C parentheses are intentionally *not* zero-argument evidence.
        In C, ``f()`` can mean an unspecified parameter list, whereas
        ``f(void)`` is explicit zero arity.
        """

        if prototype_text is None:
            return "absent"
        compact = "".join(str(prototype_text).lower().split())
        if compact.endswith("(void)"):
            return "explicit_void"
        if compact.endswith("()"):
            return "empty_unspecified"
        if "..." in compact:
            return "variadic_text"
        if "(" in compact and compact.endswith(")"):
            return "nonempty_text"
        return "unparsed"

    @staticmethod
    def _signature_source_class(signature_source):
        text = str(signature_source or "").upper()
        for source in ("USER_DEFINED", "IMPORTED", "ANALYSIS", "DEFAULT"):
            if source in text:
                return source.lower()
        return "unknown"

    def _prototype_authority(self, signature):
        parameters = list(signature.get("parameters", []) or [])
        observed_count = len(parameters)
        reported_count = signature.get("reported_parameter_count")
        source_class = self._signature_source_class(
            signature.get("signature_source")
        )
        text_hint = self._prototype_text_arity_hint(
            signature.get("prototype_text")
        )
        declared_variadic = bool(signature.get("variadic"))
        conflicts = []

        if (
            isinstance(reported_count, int)
            and reported_count >= 0
            and reported_count != observed_count
        ):
            conflicts.append({
                "kind": "function_parameter_count_disagreement",
                "reported": reported_count,
                "enumerated": observed_count,
            })
        if text_hint == "explicit_void" and observed_count:
            conflicts.append({
                "kind": "explicit_void_with_enumerated_parameters",
                "enumerated": observed_count,
            })

        if conflicts:
            status = "conflicting_evidence"
            fixed_count = None
            reason = "prototype sources disagree on fixed arity"
        elif observed_count > 0:
            status = "authoritative_n"
            fixed_count = observed_count
            reason = "Function parameter objects enumerate fixed parameters"
        elif text_hint == "explicit_void":
            status = "authoritative_zero"
            fixed_count = 0
            reason = "prototype text explicitly declares (void)"
        elif declared_variadic:
            status = "authoritative_zero"
            fixed_count = 0
            reason = "variadic declaration has no enumerated fixed parameters"
        elif source_class in ("user_defined", "imported"):
            status = "authoritative_zero"
            fixed_count = 0
            reason = "%s signature explicitly enumerates zero parameters" % (
                source_class
            )
        else:
            status = "unresolved"
            fixed_count = None
            reason = (
                "empty parameter enumeration lacks explicit void or strong "
                "signature-source authority"
            )

        return {
            "kind": "function_prototype_authority_v23b",
            "version": "v23b_authoritative_prototypes_and_carriers",
            "status": status,
            "fixed_parameter_count": fixed_count,
            "observed_parameter_count": observed_count,
            "reported_parameter_count": reported_count,
            "high_prototype_parameter_count": (
                (signature.get("prototype") or {}).get("parameter_count")
            ),
            "signature_source": signature.get("signature_source"),
            "signature_source_class": source_class,
            "prototype_text": signature.get("prototype_text"),
            "prototype_text_arity_hint": text_hint,
            "declared_variadic": declared_variadic,
            "conflicts": conflicts,
            "reason": reason,
            "authority": (
                "Ghidra_Function_signature_source_plus_explicit_C_arity"
            ),
        }

    def _function_signature_image(self, func=None, high=None):
        func = func or self.func
        calling_convention = self._safe_call(func, "getCallingConventionName")
        prototype = self._function_prototype_image(func, high=high)
        return_parameter = self._safe_call(func, "getReturn")
        entry = self._safe_call(func, "getEntryPoint")
        entry_offset = None
        if entry is not None:
            try:
                entry_offset = int(entry.getOffset())
            except Exception:
                pass

        prototype_text = self._safe_call_args(
            func, "getPrototypeString", True, True, default=None
        )
        if prototype_text is None:
            prototype_text = self._safe_call(func, "getPrototypeString")

        signature = {
            "name": str(self._safe_call(func, "getName") or ""),
            "entry": entry_offset,
            "calling_convention": str(calling_convention) if calling_convention is not None else None,
            "return": self._datatype_image(self._safe_call(func, "getReturnType")),
            "return_storage": self._variable_storage_image(
                self._safe_call(return_parameter, "getVariableStorage")
            ),
            "parameters": [],
            "parameter_count": 0,
            "reported_parameter_count": self._safe_int(
                self._safe_call(func, "getParameterCount")
            ),
            "variadic": bool(prototype.get("variadic")),
            "variadic_evidence": list(
                prototype.get("variadic_evidence", []) or []
            ),
            "no_return": bool(self._safe_call(func, "hasNoReturn", False)),
            "external": bool(self._safe_call(func, "isExternal", False)),
            "thunk": bool(self._safe_call(func, "isThunk", False)),
            "prototype": prototype,
            "prototype_text": (
                str(prototype_text) if prototype_text is not None else None
            ),
            "signature_source": self._safe_str(
                self._safe_call(func, "getSignatureSource")
            ),
        }

        parameters = self._safe_list(self._safe_call(func, "getParameters"))

        for fallback_ordinal, parameter in enumerate(parameters):
            ordinal = self._safe_int(self._safe_call(parameter, "getOrdinal"), fallback_ordinal)
            name = self._safe_call(parameter, "getName")
            datatype = self._safe_call(parameter, "getDataType")
            storage = self._safe_call(parameter, "getVariableStorage")
            signature["parameters"].append({
                "ordinal": ordinal,
                "name": str(name) if name is not None else None,
                "datatype": self._datatype_image(datatype),
                "storage": self._safe_str(storage),
                "storage_image": self._variable_storage_image(storage),
                "auto_parameter": self._safe_bool(
                    self._safe_call(parameter, "isAutoParameter"), False
                ),
            })

        signature["parameters"].sort(key=lambda item: (
            item.get("ordinal") is None,
            item.get("ordinal") if isinstance(item.get("ordinal"), int) else 0,
            str(item.get("name") or ""),
        ))
        signature["parameter_count"] = len(signature["parameters"])
        signature["prototype_text_arity_hint"] = (
            self._prototype_text_arity_hint(signature.get("prototype_text"))
        )
        signature["prototype_authority"] = self._prototype_authority(signature)

        return signature

    def _select_abi_backend(self, signature=None):
        signature = signature or {}
        target = dict(getattr(self.pal, "target_numeric_model", {}) or {})
        language = str(target.get("language_id") or "").lower()
        processor = str(target.get("processor") or "").lower()
        compiler = str(target.get("compiler_spec_id") or "").lower()
        executable = str(target.get("executable_format") or "").lower()
        convention = str(signature.get("calling_convention") or "").lower()
        pointer_width = target.get("pointer_width_bits")

        is_x86 = "x86" in language or "x86" in processor
        is_64 = pointer_width == 64 or ":64:" in language
        windows_evidence = any(
            token in text
            for text in (compiler, executable, convention)
            for token in ("windows", "win64", "microsoft")
        )
        elf_evidence = "elf" in executable or "gcc" in compiler

        if is_x86 and is_64 and elf_evidence and not windows_evidence:
            return {
                "name": "sysv_amd64",
                "status": "evidence_selected",
                "reason": (
                    "x86_64 target plus ELF/GCC compiler evidence"
                ),
            }
        if is_x86 and is_64 and windows_evidence:
            return {
                "name": "win64",
                "status": "recognized_unimplemented",
                "reason": "x86_64 target plus Windows ABI evidence",
            }
        return {
            "name": "unknown",
            "status": "unresolved",
            "reason": "target/compiler evidence does not select an ABI backend",
        }

    def _abi_datatype_class(self, datatype, width_bits=None):
        datatype = dict(datatype or {})
        kind = str(datatype.get("kind_hint") or "").lower()
        if kind == "float":
            return "sse"
        if kind in ("integer", "pointer", "boolean", "enum"):
            return "integer"
        if kind in ("aggregate", "array"):
            return "aggregate"
        if isinstance(width_bits, int) and 0 < width_bits <= 64:
            return "unknown_scalar"
        return "unknown"

    @staticmethod
    def _register_prefix_index(register_name, prefixes):
        text = str(register_name or "").upper().lstrip("%")
        for prefix in prefixes:
            if not text.startswith(prefix):
                continue
            digits = []
            for char in text[len(prefix):]:
                if not char.isdigit():
                    break
                digits.append(char)
            if digits:
                return int("".join(digits))
        return None

    def _abi_carrier_image(self, storage):
        storage = dict(storage or {})
        register = dict(storage.get("register") or {})
        register_name = str(register.get("name") or "").upper().lstrip("%")
        base_name = str(register.get("base_name") or "").upper().lstrip("%")
        names = [name for name in (register_name, base_name) if name]

        vector_index = None
        for name in names:
            vector_index = self._register_prefix_index(
                name, ("XMM", "YMM", "ZMM")
            )
            if vector_index is not None:
                break

        gp_aliases = (
            ("RDI", "EDI", "DI", "DIL"),
            ("RSI", "ESI", "SI", "SIL"),
            ("RDX", "EDX", "DX", "DL"),
            ("RCX", "ECX", "CX", "CL"),
            ("R8", "R8D", "R8W", "R8B"),
            ("R9", "R9D", "R9W", "R9B"),
        )
        gp_index = None
        for index, aliases in enumerate(gp_aliases):
            if any(name in aliases for name in names):
                gp_index = index
                break

        if vector_index is not None:
            bank = "sse"
            carrier_class = "sse"
            carrier_index = vector_index
            role = "vector_argument_register"
        elif gp_index is not None:
            bank = "gp"
            carrier_class = "integer"
            carrier_index = gp_index
            role = "integer_argument_register"
        elif register_name == "AL":
            bank = "special_abi"
            carrier_class = "special"
            carrier_index = None
            role = "variadic_xmm_register_count"
        elif storage.get("kind") == "stack":
            bank = "stack"
            carrier_class = "memory"
            carrier_index = None
            role = "stack_argument_or_local_storage"
        elif storage.get("kind") == "register":
            bank = "machine_register"
            carrier_class = "machine_state"
            carrier_index = None
            role = "non_argument_register"
        else:
            bank = "unknown"
            carrier_class = "unknown"
            carrier_index = None
            role = "unclassified_storage"

        return {
            "bank": bank,
            "class": carrier_class,
            "index": carrier_index,
            "role": role,
            "register_name": register_name or None,
            "base_register_name": base_name or None,
            "storage_key": storage.get("storage_key"),
            "authority": "physical_register_storage",
        }

    def _high_parameter_record(self, var, evidence, legacy_index):
        storage = dict(evidence.get("storage") or {})
        datatype = dict(evidence.get("datatype") or {})
        datatype_class = self._abi_datatype_class(
            datatype, getattr(var, "width_bits", None)
        )
        carrier = self._abi_carrier_image(storage)
        return {
            "sid": getattr(var, "ssa_id", None),
            "legacy_emitted_name": getattr(var, "name", None),
            "high_name": evidence.get("name"),
            "high_ordinal": evidence.get("ordinal"),
            "legacy_lexical_index": legacy_index,
            "datatype": datatype or None,
            "storage": storage or None,
            "storage_key": storage.get("storage_key"),
            "register": dict(storage.get("register") or {}) or None,
            "width_bits": getattr(var, "width_bits", None),
            "datatype_class": datatype_class,
            "argument_class": datatype_class,
            "carrier": carrier,
            "carrier_bank": carrier.get("bank"),
            "carrier_class": carrier.get("class"),
            "carrier_index": carrier.get("index"),
            "high_variable": evidence.get("high_variable"),
        }

    @staticmethod
    def _logical_storage_keys(parameter):
        image = dict(parameter.get("storage_image") or {})
        return set(
            key for key in list(image.get("storage_keys", []) or []) if key
        )

    def _logical_parameter_bindings(self, logical, physical):
        bindings = []
        for parameter in list(logical or []):
            keys = self._logical_storage_keys(parameter)
            matches = []
            for carrier in list(physical or []):
                key = carrier.get("storage_key")
                if key and key in keys:
                    matches.append(carrier.get("sid"))
            bindings.append({
                "logical_ordinal": parameter.get("ordinal"),
                "logical_name": parameter.get("name"),
                "storage_keys": sorted(keys),
                "physical_sids": matches,
                "binding_status": (
                    "exact_storage_match" if len(matches) == 1
                    else "ambiguous_storage_match" if len(matches) > 1
                    else "unresolved_storage_match"
                ),
            })
        return bindings

    def _implicit_input_role(self, var):
        evidence = dict(getattr(var, "numeric_evidence", {}) or {})
        storage = dict(evidence.get("abi_storage") or {})
        register = dict(storage.get("register") or {})
        name_values = [
            str(value or "").lower().lstrip("%") for value in (
                getattr(var, "name", None),
                getattr(var, "original_name", None),
                (evidence.get("high_variable") or {}).get("name"),
                register.get("name"),
                register.get("base_name"),
            )
        ]
        names = " ".join(name_values)
        compact = names.replace("_", "").replace("%", "")
        if any(token in compact for token in ("fsoffset", "tpidr", "threadpointer")):
            return "thread_local_storage_base"
        register_name = str(register.get("name") or "").lower().lstrip("%")
        if register_name == "al" or any(
            value in ("al", "in_al") for value in name_values
        ):
            return "variadic_xmm_register_count"
        register_family = " ".join((
            register_name,
            str(register.get("base_name") or "").lower().lstrip("%"),
        ))
        if any(
            token in register_family for token in ("xmm", "ymm", "zmm")
        ):
            return "vector_argument_register_live_in"
        if any(token in names for token in ("rsp", " esp", " sp")):
            return "stack_pointer"
        if any(token in names for token in ("rbp", " ebp", " fp")):
            return "frame_pointer"
        if "flag" in names or register_name in ("eflags", "rflags"):
            return "condition_flags"
        return "machine_live_in"

    def _implicit_input_records(
        self, excluded_sids, high_parameter_sids=None, high_ordinals=None
    ):
        high_parameter_sids = set(high_parameter_sids or [])
        high_ordinals = dict(high_ordinals or {})
        records = []
        for var in list((getattr(self.pal, "vars", {}) or {}).values()):
            sid = getattr(var, "ssa_id", None)
            if sid in excluded_sids or bool(getattr(var, "is_constant", False)):
                continue
            evidence = dict(getattr(var, "numeric_evidence", {}) or {})
            is_input = evidence.get("is_input") is True
            unaffected = evidence.get("is_unaffected") is True
            if getattr(var, "def_op", None) is not None:
                continue
            if not (is_input or unaffected):
                continue
            storage = dict(evidence.get("abi_storage") or {})
            high = dict(evidence.get("high_variable") or {})
            high_name = str(high.get("name") or "")
            # Persistent RAM/global inputs belong to memory custody, not the
            # function calling convention.  ABI implicit inputs are register
            # live-ins (or Ghidra's explicit in_* machine-state symbols).
            if (
                storage.get("kind") != "register"
                and not high_name.lower().startswith("in_")
            ):
                continue
            role = self._implicit_input_role(var)
            is_high_parameter_carrier = sid in high_parameter_sids
            # An unmatched HighFunction parameter can be either an implicit
            # carrier or simply a prototype/storage binding we could not prove.
            # Only promote it to implicit custody when the machine role itself
            # is recognizable.  Unknown unmatched carriers remain visible in
            # unbound_high_function_input_parameters instead.
            if (
                is_high_parameter_carrier
                and role == "machine_live_in"
                and not high_name.lower().startswith("in_")
            ):
                continue
            records.append({
                "sid": sid,
                "name": getattr(var, "name", None),
                "high_name": high_name or None,
                "role": role,
                "storage": storage or None,
                "register": dict(storage.get("register") or {}) or None,
                "width_bits": getattr(var, "width_bits", None),
                "is_input": is_input,
                "is_unaffected": unaffected,
                "high_function_parameter_carrier": is_high_parameter_carrier,
                "high_ordinal": high_ordinals.get(sid),
                "authority": "HighFunction_input_or_unaffected_varnode",
            })
        records.sort(key=lambda item: (
            str(item.get("role") or ""), str(item.get("sid") or "")
        ))
        return records

    def _finalize_function_abi_contract(self, high):
        signature = self._function_signature_image(self.func, high=high)
        self.pal.function_signature = signature
        prototype_authority = dict(
            signature.get("prototype_authority") or {}
        )
        physical = sorted(
            list(self._abi_high_parameters or []),
            key=lambda item: (
                item.get("high_ordinal") is None,
                item.get("high_ordinal") if isinstance(
                    item.get("high_ordinal"), int
                ) else 0,
                str(item.get("high_name") or ""),
                str(item.get("sid") or ""),
            ),
        )
        logical = list(signature.get("parameters", []) or [])
        bindings = self._logical_parameter_bindings(logical, physical)
        physical_sids = set(
            item.get("sid") for item in physical if item.get("sid")
        )
        bound_physical_sids = set(
            sid
            for binding in bindings
            for sid in list(binding.get("physical_sids", []) or [])
            if sid
        )
        high_ordinals = {
            item.get("sid"): item.get("high_ordinal")
            for item in physical if item.get("sid")
        }
        implicit = self._implicit_input_records(
            bound_physical_sids,
            high_parameter_sids=physical_sids,
            high_ordinals=high_ordinals,
        )
        backend = self._select_abi_backend(signature)

        variadic_count_inputs = [
            item for item in implicit
            if item.get("role") == "variadic_xmm_register_count"
        ]
        vector_input_carriers = [
            item for item in implicit
            if item.get("role") == "vector_argument_register_live_in"
        ]
        unbound_physical = [
            item for item in physical
            if item.get("sid") not in bound_physical_sids
        ]
        declared_variadic = bool(signature.get("variadic"))
        machine_variadic_evidence = bool(variadic_count_inputs)

        bank_order = (
            "gp", "sse", "stack", "special_abi",
            "machine_register", "unknown",
        )
        physical_carrier_banks = {}
        for bank in bank_order:
            members = [
                item for item in physical
                if item.get("carrier_bank") == bank
            ]
            members.sort(key=lambda item: (
                item.get("carrier_index") is None,
                item.get("carrier_index")
                if isinstance(item.get("carrier_index"), int) else 0,
                str((item.get("carrier") or {}).get("register_name") or ""),
                str(item.get("sid") or ""),
            ))
            if members:
                physical_carrier_banks[bank] = [{
                    "sid": item.get("sid"),
                    "register": (
                        (item.get("carrier") or {}).get("register_name")
                    ),
                    "index": item.get("carrier_index"),
                    "high_ordinal": item.get("high_ordinal"),
                    "legacy_emitted_name": item.get("legacy_emitted_name"),
                    "datatype_class": item.get("datatype_class"),
                    "carrier_class": item.get("carrier_class"),
                } for item in members]

        canonical_plan = {
            "kind": "abi_physical_carrier_order_plan_v23b",
            "status": (
                "metadata_only" if backend.get("name") == "sysv_amd64"
                else "backend_not_implemented"
            ),
            "gp_sids": [
                item.get("sid")
                for item in physical_carrier_banks.get("gp", [])
            ],
            "sse_sids": [
                item.get("sid")
                for item in physical_carrier_banks.get("sse", [])
            ],
            "stack_sids": [
                item.get("sid")
                for item in physical_carrier_banks.get("stack", [])
            ],
            "intra_bank_order_authority": "physical_register_index",
            "inter_bank_source_order": "unresolved",
            "execution_mutation_authorized": False,
        }

        variadic_protocol = {
            "kind": "abi_variadic_entry_protocol_v23b",
            "declared_variadic": declared_variadic,
            "machine_variadic_evidence": machine_variadic_evidence,
            "effective_variadic": (
                declared_variadic or machine_variadic_evidence
            ),
            "status": (
                "declared_and_machine_evidenced"
                if declared_variadic and machine_variadic_evidence
                else "machine_evidenced"
                if machine_variadic_evidence
                else "declared_only"
                if declared_variadic
                else "not_evidenced"
            ),
            "xmm_count_input_sids": [
                item.get("sid") for item in variadic_count_inputs
            ],
            "vector_register_input_sids": [
                item.get("sid") for item in vector_input_carriers
            ],
            "fixed_parameter_count_inference": None,
            "fixed_parameter_count_inference_status": (
                "deferred_to_entry_protocol_analysis"
            ),
            "authority": (
                "declared_signature_plus_recognized_machine_live_ins"
            ),
        }
        contract = {
            "kind": "lifter_function_abi_contract_v23b",
            "version": "v23b_authoritative_prototypes_and_carriers",
            "function": self.pal.func_name,
            "entry": self.pal.function_address,
            "calling_convention": signature.get("calling_convention"),
            "abi_backend": backend,
            "variadic": declared_variadic,
            "declared_variadic": declared_variadic,
            "machine_variadic_evidence": machine_variadic_evidence,
            "effective_variadic": (
                declared_variadic or machine_variadic_evidence
            ),
            "variadic_evidence": list(
                signature.get("variadic_evidence", []) or []
            ) + ([{
                "source": "recognized_AL_live_in",
                "value": True,
                "sids": [
                    item.get("sid") for item in variadic_count_inputs
                ],
            }] if machine_variadic_evidence else []),
            "variadic_protocol": variadic_protocol,
            "no_return": bool(signature.get("no_return")),
            "logical_parameters": logical,
            "logical_parameter_count": prototype_authority.get(
                "fixed_parameter_count"
            ),
            "observed_listing_parameter_count": len(logical),
            "prototype_authority": prototype_authority,
            "prototype_text": signature.get("prototype_text"),
            "signature_source": signature.get("signature_source"),
            "high_function_input_parameters": physical,
            "high_function_input_parameter_count": len(physical),
            "physical_carrier_banks": physical_carrier_banks,
            "physical_carrier_order_plan": canonical_plan,
            "logical_to_physical_bindings": bindings,
            "unbound_high_function_input_parameters": unbound_physical,
            "unbound_high_function_input_parameter_count": len(
                unbound_physical
            ),
            "implicit_inputs": implicit,
            "implicit_input_count": len(implicit),
            "variadic_xmm_count_inputs": variadic_count_inputs,
            "vector_argument_register_inputs": vector_input_carriers,
            "return": signature.get("return"),
            "return_storage": signature.get("return_storage"),
            "prototype": signature.get("prototype"),
            "legacy_parameter_order_policy": "lexicographic_high_symbol_name",
            "future_parameter_order_policy": "logical_prototype_ordinal",
            "authority": (
                "Ghidra_Function_prototype_plus_HighFunction_input_storage"
            ),
        }
        self.pal.function_abi_contract = contract

        if contract["variadic"] and not variadic_count_inputs:
            self.pal.abi_observations.append({
                "kind": "lifter_abi_variadic_xmm_count_unresolved_v23b",
                "function": self.pal.func_name,
                "status": "unresolved_observation",
                "reason": (
                    "variadic function has no recognized AL/XMM-count live-in"
                ),
            })
        if prototype_authority.get("status") in (
            "unresolved", "conflicting_evidence"
        ):
            self.pal.abi_observations.append({
                "kind": "lifter_abi_function_prototype_observation_v23b",
                "function": self.pal.func_name,
                "status": prototype_authority.get("status"),
                "prototype_authority": prototype_authority,
            })
        unresolved = [
            item for item in bindings
            if item.get("binding_status") == "unresolved_storage_match"
        ]
        if unresolved:
            self.pal.abi_observations.append({
                "kind": "lifter_abi_logical_physical_binding_incomplete_v23b",
                "function": self.pal.func_name,
                "status": "unresolved_observation",
                "unresolved_logical_ordinals": [
                    item.get("logical_ordinal") for item in unresolved
                ],
                "reason": "prototype storage did not match a HighFunction input",
            })
        return contract

    def _direct_call_target(self, raw_target):
        if raw_target is None:
            return None, None
        address = self._safe_call(raw_target, "getAddress")
        target_offset = None
        if address is not None:
            try:
                target_offset = int(address.getOffset())
            except Exception:
                pass
        if target_offset is None:
            target_offset = self._safe_int(self._safe_call(raw_target, "getOffset"))

        function = None
        manager = self._safe_call(self.program, "getFunctionManager")
        candidate_addresses = []
        if address is not None:
            candidate_addresses.append(address)
        if target_offset is not None:
            factory = self._safe_call(self.program, "getAddressFactory")
            default_space = self._safe_call(factory, "getDefaultAddressSpace")
            normalized = self._safe_call_args(
                default_space, "getAddress", target_offset, default=None
            )
            if normalized is not None and normalized not in candidate_addresses:
                candidate_addresses.append(normalized)
        if manager is not None:
            for candidate in candidate_addresses:
                function = self._safe_call_args(
                    manager, "getFunctionAt", candidate, default=None
                )
                if function is None:
                    function = self._safe_call_args(
                        manager, "getFunctionContaining", candidate, default=None
                    )
                if function is not None:
                    break
        return function, target_offset

    def _call_argument_image(self, index, raw_vn, pal_var, target_parameter=None):
        variable_evidence = dict(
            getattr(pal_var, "numeric_evidence", {}) or {}
        )
        high = dict(variable_evidence.get("high_variable") or {})
        datatype = dict(high.get("datatype") or {})
        authority = "argument_high_variable_datatype"
        if target_parameter:
            target_datatype = dict(target_parameter.get("datatype") or {})
            if target_datatype:
                datatype = target_datatype
                authority = "target_logical_parameter_datatype"
        width_bits = getattr(pal_var, "width_bits", None)
        datatype_class = self._abi_datatype_class(datatype, width_bits)
        storage = self._varnode_storage_image(raw_vn)
        observed_carrier = self._abi_carrier_image(storage)
        effective_class = datatype_class
        effective_class_authority = authority
        if (
            datatype_class in ("unknown", "unknown_scalar")
            and observed_carrier.get("bank") in ("gp", "sse")
        ):
            effective_class = observed_carrier.get("class")
            effective_class_authority = "physical_argument_register_storage"
        return {
            "index": index,
            "sid": getattr(pal_var, "ssa_id", None),
            "name": getattr(pal_var, "name", None),
            "width_bits": width_bits,
            "datatype": datatype or None,
            "datatype_class": datatype_class,
            "argument_class": effective_class,
            "class_authority": effective_class_authority,
            "storage": storage,
            "observed_carrier": observed_carrier,
            "constant": bool(getattr(pal_var, "is_constant", False)),
            "constant_value": (
                getattr(pal_var, "value", None)
                if bool(getattr(pal_var, "is_constant", False)) else None
            ),
        }

    def _sysv_amd64_scalar_allocation(self, arguments, variadic):
        gp_registers = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
        fp_registers = [
            "XMM0", "XMM1", "XMM2", "XMM3",
            "XMM4", "XMM5", "XMM6", "XMM7",
        ]
        gp_index = 0
        fp_index = 0
        stack_slot = 0
        allocations = []
        deferred = 0
        for argument in list(arguments or []):
            item = dict(argument)
            cls = item.get("argument_class")
            if cls == "sse" and fp_index < len(fp_registers):
                item["carrier_kind"] = "xmm_register"
                item["carrier"] = fp_registers[fp_index]
                fp_index += 1
            elif cls in ("integer", "unknown_scalar") and gp_index < len(gp_registers):
                item["carrier_kind"] = "gp_register"
                item["carrier"] = gp_registers[gp_index]
                gp_index += 1
            elif cls in ("integer", "unknown_scalar", "sse"):
                item["carrier_kind"] = "stack_overflow_argument"
                item["carrier"] = "stack+%d" % (stack_slot * 8)
                item["stack_slot"] = stack_slot
                stack_slot += 1
            else:
                item["carrier_kind"] = "deferred_complex_classification"
                item["carrier"] = None
                deferred += 1
            allocations.append(item)
        return {
            "kind": "sysv_amd64_scalar_argument_allocation_v23b",
            "allocations": allocations,
            "gp_registers_used": gp_index,
            "xmm_registers_used": fp_index,
            "stack_slots_used": stack_slot,
            "variadic_al_value": fp_index if variadic else None,
            "deferred_complex_arguments": deferred,
            "authority": "datatype_class_plus_SysV_AMD64_scalar_register_order",
            "limitations": [
                "aggregate_eightbyte_classification_deferred",
                "variadic_default_promotions_recorded_later_by_PALCompute",
            ],
        }

    def _call_site_abi_contract(
        self, raw_op, pal_op, raw_inputs, inputs, block_addr
    ):
        opcode = getattr(pal_op, "opcode", None)
        direct = opcode == "CALL"
        target_function = None
        target_offset = None
        if direct and raw_inputs:
            target_function, target_offset = self._direct_call_target(raw_inputs[0])

        target_signature = (
            self._function_signature_image(target_function)
            if target_function is not None else None
        )
        target_prototype_authority = (
            dict((target_signature or {}).get("prototype_authority") or {})
            if target_signature is not None else {
                "kind": "function_prototype_authority_v23b",
                "version": "v23b_authoritative_prototypes_and_carriers",
                "status": "unresolved",
                "fixed_parameter_count": None,
                "reason": "call target function is unresolved",
                "authority": "no_target_Function_object",
            }
        )
        logical_parameters = list(
            (target_signature or {}).get("parameters", []) or []
        )
        fixed_count = target_prototype_authority.get(
            "fixed_parameter_count"
        )
        prototype_status = target_prototype_authority.get("status")
        variadic = (
            bool(target_signature.get("variadic"))
            if target_signature is not None else None
        )

        raw_arguments = list(raw_inputs[1:] if raw_inputs else [])
        pal_arguments = list(inputs[1:] if inputs else [])
        arguments = []
        for index, pal_var in enumerate(pal_arguments):
            target_parameter = (
                logical_parameters[index]
                if index < len(logical_parameters) else None
            )
            raw_vn = raw_arguments[index] if index < len(raw_arguments) else None
            argument = self._call_argument_image(
                index, raw_vn, pal_var, target_parameter=target_parameter
            )
            if prototype_status in ("authoritative_zero", "authoritative_n"):
                if isinstance(fixed_count, int) and index < fixed_count:
                    argument["parameter_region"] = "fixed"
                elif variadic:
                    argument["parameter_region"] = "variadic"
                else:
                    argument["parameter_region"] = "excess_for_fixed_prototype"
            else:
                argument["parameter_region"] = "prototype_unresolved"
            arguments.append(argument)

        actual_count = len(arguments)
        if target_function is None:
            arity_status = "target_unresolved"
        elif prototype_status == "conflicting_evidence":
            arity_status = "target_prototype_conflicting"
        elif prototype_status not in ("authoritative_zero", "authoritative_n"):
            arity_status = "target_prototype_unresolved"
        elif variadic:
            arity_status = (
                "valid_variadic_arity" if actual_count >= fixed_count
                else "missing_fixed_arguments"
            )
        else:
            arity_status = (
                "valid_fixed_arity" if actual_count == fixed_count
                else "fixed_arity_mismatch"
            )

        backend = self._select_abi_backend(target_signature or {})
        allocation = None
        if backend.get("name") == "sysv_amd64":
            allocation = self._sysv_amd64_scalar_allocation(
                arguments, bool(variadic)
            )

        target_name = (
            str(self._safe_call(target_function, "getName") or "") or None
            if target_function is not None else None
        )
        target_entry = (target_signature or {}).get("entry")
        if target_entry is None:
            target_entry = target_offset

        contract = {
            "kind": "lifter_call_site_abi_contract_v23b",
            "version": "v23b_authoritative_prototypes_and_carriers",
            "caller": self.pal.func_name,
            "caller_entry": self.pal.function_address,
            "op_id": getattr(pal_op, "op_id", None),
            "block_addr": block_addr,
            "opcode": opcode,
            "direct": direct,
            "target_resolved": target_function is not None,
            "target_name": target_name,
            "target_entry": target_entry,
            "target_external": (
                bool((target_signature or {}).get("external"))
                if target_signature is not None else None
            ),
            "target_no_return": (
                bool((target_signature or {}).get("no_return"))
                if target_signature is not None else None
            ),
            "target_calling_convention": (
                (target_signature or {}).get("calling_convention")
            ),
            "target_prototype_authority": target_prototype_authority,
            "target_variadic": variadic,
            "target_fixed_parameter_count": fixed_count,
            "logical_argument_count": actual_count,
            "observed_argument_count": actual_count,
            "variadic_argument_count": (
                max(actual_count - fixed_count, 0)
                if (
                    prototype_status in (
                        "authoritative_zero", "authoritative_n"
                    )
                    and isinstance(fixed_count, int)
                    and variadic
                ) else 0
                if (
                    prototype_status in (
                        "authoritative_zero", "authoritative_n"
                    )
                    and isinstance(fixed_count, int)
                ) else None
            ),
            "arity_status": arity_status,
            "arity_authority": (
                "authoritative_target_prototype"
                if prototype_status in (
                    "authoritative_zero", "authoritative_n"
                ) else "observation_only"
            ),
            "arguments": arguments,
            "abi_backend": backend,
            "carrier_allocation": allocation,
            "target_signature": target_signature,
            "target_operand": (
                self._varnode_storage_image(raw_inputs[0])
                if raw_inputs else None
            ),
            "authority": (
                "HighFunction_CALL_inputs_plus_target_Function_prototype"
            ),
        }
        return contract

    def _register_call_site_abi_contract(self, pal_op, contract):
        pal_op.call_site_abi_contract = contract
        pal_op.numeric_evidence["call_site_abi"] = contract
        if isinstance(getattr(pal_op, "hf_image", None), dict):
            pal_op.hf_image["call_site_abi"] = contract
        self.pal.call_site_abi_contracts.append(contract)
        op_id = contract.get("op_id")
        if op_id is not None:
            self.pal.call_site_abi_by_op[str(op_id)] = contract

    def _finalize_abi_inventory(self):
        function = dict(getattr(self.pal, "function_abi_contract", {}) or {})
        calls = list(getattr(self.pal, "call_site_abi_contracts", []) or [])
        arities = {}
        backends = {}
        prototype_authorities = {}
        for contract in calls:
            status = str(contract.get("arity_status") or "unknown")
            arities[status] = arities.get(status, 0) + 1
            backend = str((contract.get("abi_backend") or {}).get("name") or "unknown")
            backends[backend] = backends.get(backend, 0) + 1
            prototype_status = str(
                (contract.get("target_prototype_authority") or {}).get(
                    "status"
                ) or "unresolved"
            )
            prototype_authorities[prototype_status] = (
                prototype_authorities.get(prototype_status, 0) + 1
            )
            if status in ("missing_fixed_arguments", "fixed_arity_mismatch"):
                self.pal.abi_warnings.append({
                    "kind": "lifter_call_site_arity_warning_v23b",
                    "op_id": contract.get("op_id"),
                    "target": contract.get("target_name"),
                    "status": status,
                    "actual": contract.get("logical_argument_count"),
                    "fixed": contract.get("target_fixed_parameter_count"),
                    "variadic": contract.get("target_variadic"),
                    "authority": "authoritative_target_prototype",
                })
            elif status in (
                "target_unresolved",
                "target_prototype_unresolved",
                "target_prototype_conflicting",
            ):
                self.pal.abi_observations.append({
                    "kind": "lifter_call_site_prototype_observation_v23b",
                    "op_id": contract.get("op_id"),
                    "target": contract.get("target_name"),
                    "status": status,
                    "observed_argument_count": contract.get(
                        "observed_argument_count"
                    ),
                    "prototype_authority": contract.get(
                        "target_prototype_authority"
                    ),
                })

        inventory = {
            "kind": "lifter_abi_inventory_v23b",
            "version": "v23b_authoritative_prototypes_and_carriers",
            "function": self.pal.func_name,
            "abi_backend": dict(function.get("abi_backend") or {}),
            "function_prototype_authority": dict(
                function.get("prototype_authority") or {}
            ),
            "variadic": bool(function.get("variadic")),
            "declared_variadic": bool(function.get("declared_variadic")),
            "machine_variadic_evidence": bool(
                function.get("machine_variadic_evidence")
            ),
            "effective_variadic": bool(function.get("effective_variadic")),
            "logical_parameters": function.get("logical_parameter_count", 0),
            "high_function_input_parameters": function.get(
                "high_function_input_parameter_count", 0
            ),
            "unbound_high_function_input_parameters": function.get(
                "unbound_high_function_input_parameter_count", 0
            ),
            "implicit_inputs": function.get("implicit_input_count", 0),
            "variadic_xmm_count_inputs": len(
                function.get("variadic_xmm_count_inputs", []) or []
            ),
            "vector_argument_register_inputs": len(
                function.get("vector_argument_register_inputs", []) or []
            ),
            "physical_carrier_banks": {
                bank: len(list(members or []))
                for bank, members in dict(
                    function.get("physical_carrier_banks") or {}
                ).items()
            },
            "call_sites": len(calls),
            "direct_calls": sum(1 for item in calls if item.get("direct")),
            "indirect_calls": sum(1 for item in calls if not item.get("direct")),
            "resolved_targets": sum(
                1 for item in calls if item.get("target_resolved")
            ),
            "variadic_targets": sum(
                1 for item in calls if item.get("target_variadic") is True
            ),
            "arity_statuses": arities,
            "target_prototype_authorities": prototype_authorities,
            "call_backends": backends,
            "warnings": len(self.pal.abi_warnings),
            "unresolved_observations": len(self.pal.abi_observations),
            "rule": (
                "prototype_authority_gates_arity_and_storage_gates_carriers"
            ),
        }
        self.pal.abi_inventory = inventory
        self.pal.numeric_evidence_events.append(inventory)
        self.pal.numeric_evidence_events.extend(self.pal.abi_observations)
        self.pal.numeric_evidence_events.extend(self.pal.abi_warnings)
        return inventory

    # -------------------------------------

    # def lift(self):
    def lift(self):

        self.decomp.openProgram(self.program)

        start = self.func.getEntryPoint().getOffset()
        end = self.func.getBody().getMaxAddress().getOffset()

        self.pal = PALFunctionObject(
            self.func.getName(),
            start,
            (start, end)
        )

        # Raw target/signature facts only.  No execution contract is inferred
        # in the lifter and no alpha-nine consumer depends on these fields.
        self.pal.target_numeric_model = self._target_numeric_model()
        self.pal.function_signature = self._function_signature_image()
        self.pal.numeric_evidence_events.append({
            "kind": "lifter_numeric_target_evidence_v21",
            "function": self.pal.func_name,
            "target": dict(self.pal.target_numeric_model),
        })

        decomp_res = self.decomp.decompileFunction(
            self.func, 30, self.monitor
        )
        high = decomp_res.getHighFunction()

        # Preserve HighFunction/decompiled-C images for later POW/PALRAW use.
        self.pal.high_function = high
        self.pal.decompiled_c_image = self._safe_decompiled_c(decomp_res)

        # SSA variable creation
        def get_var(vn):

            if vn is None:
                return None

            # constant
            if vn.isConstant():

                vid = f"c_{vn.getOffset()}_{vn.getSize()}"

                if vid not in self.pal.vars:
                    self.pal.vars[vid] = PALVariable(
                        vid, "const",
                        vn.getOffset(),
                        vn.getSize(),
                        True
                    )

                v = self.pal.vars[vid]
                self._apply_varnode_numeric_evidence(v, vn)
                return v

            vid = f"v_{vn.getUniqueId()}"

            if vid not in self.pal.vars:

                addr = None
                space = "unknown"

                try:
                    a = vn.getAddress()
                    if a:
                        space = a.getAddressSpace().getName()
                        addr = int(a.getOffset())
                except:
                    pass

                self.pal.vars[vid] = PALVariable(
                    vid,
                    space,
                    vn.getOffset(),
                    vn.getSize(),
                    False,
                    addr
                )

            v = self.pal.vars[vid]
            self._apply_varnode_numeric_evidence(v, vn)
            return v

        # PARAMETERS (stable ordering)
        params = []
        for sym in high.getLocalSymbolMap().getSymbols():
            if sym.isParameter():
                high_var = sym.getHighVariable()
                vn = high_var.getRepresentative()
                evidence = self._parameter_symbol_evidence(sym, high_var)
                params.append((sym.getName(), vn, evidence))

        params.sort(key=lambda x: x[0])  # deterministic

        for idx, (name, vn, evidence) in enumerate(params):
            v = get_var(vn)
            v.is_parameter = True
            v.name = f"param_{idx}"
            v.original_name = str(name) if name is not None else None
            v.parameter_ordinal = evidence.get("ordinal")
            v.numeric_evidence["parameter_symbol"] = dict(evidence)

            datatype = evidence.get("datatype") or {}
            if datatype:
                v.declared_type = dict(datatype)
                v.declared_type_name = datatype.get("display_name") or datatype.get("name")
                v.declared_domain = datatype.get("kind_hint")
                if isinstance(datatype.get("signed"), bool):
                    v.declared_signedness = "signed" if datatype["signed"] else "unsigned"
                if "parameter_symbol_datatype" not in v.type_provenance:
                    v.type_provenance.append("parameter_symbol_datatype")

            self.pal.parameters.append(v)
            self._abi_high_parameters.append(
                self._high_parameter_record(v, evidence, idx)
            )
            self.pal.numeric_evidence_events.append({
                "kind": "lifter_parameter_evidence_v21",
                "sid": v.ssa_id,
                "emitted_name": v.name,
                "original_name": v.original_name,
                "ordinal": v.parameter_ordinal,
                "width_bits": v.width_bits,
                "datatype": dict(datatype) if datatype else None,
            })

        # BLOCKS
        addr_map = {}

        for hb in high.getBasicBlocks():

            b = PALBlock(hb.getIndex(), hb.getStart().getOffset())
            b.hf_block_repr = self._safe_str(hb)
            try:
                b.hf_stop_addr = int(hb.getStop().getOffset())
            except Exception:
                b.hf_stop_addr = None

            addr_map[b.addr] = b
            self.pal.blocks.append(b)

            it = hb.getIterator()

            while it.hasNext():

                op = it.next()
                opc = op.getMnemonic()

                # Keep the raw Java varnodes long enough to distinguish
                # INDIRECT's special iop input from an ordinary constant.
                # The legacy PALVariable inputs are still built unchanged.
                raw_inputs = list(op.getInputs())
                raw_output = op.getOutput()
                inputs = [get_var(i) for i in raw_inputs]
                output = get_var(raw_output)

                hf_op_image = self._hf_op_image(op, opc, inputs, output)
                b.hf_pcode_image.append(hf_op_image)

                if opc in self.CONTROL_OPS:

                    cond = None
                    if opc == "CBRANCH" and len(inputs) >= 2:
                        cond = inputs[1]

                    term = PALTerminator(opc, inputs, cond)
                    term.hf_pcode_repr = hf_op_image.get("repr")
                    term.hf_seqnum = hf_op_image.get("seqnum")
                    term.hf_target_addr = self._term_target_addr_from_inputs(inputs)
                    term.numeric_evidence["block_addr"] = b.addr
                    term.numeric_evidence["seqnum"] = term.hf_seqnum
                    b.terminator = term

                else:
                    pal_op = PALPcodeOp(
                        op.getSeqnum().toString(),
                        opc,
                        inputs,
                        output
                    )
                    pal_op.hf_pcode_repr = hf_op_image.get("repr")
                    pal_op.hf_image = hf_op_image
                    pal_op.numeric_evidence["block_addr"] = b.addr
                    pal_op.numeric_evidence["seqnum"] = pal_op.op_id
                    pal_op.numeric_evidence["input_sids"] = [
                        getattr(v, "ssa_id", None) for v in list(inputs or [])
                    ]
                    pal_op.numeric_evidence["output_sid"] = getattr(output, "ssa_id", None)

                    if opc in {"CALL", "CALLIND"}:
                        call_contract = self._call_site_abi_contract(
                            raw_op=op,
                            pal_op=pal_op,
                            raw_inputs=raw_inputs,
                            inputs=inputs,
                            block_addr=b.addr,
                        )
                        self._register_call_site_abi_contract(
                            pal_op, call_contract
                        )

                    if opc == "INDIRECT":
                        if len(pal_op.input_roles) > 0:
                            pal_op.input_roles[0] = "prior_value"
                        if len(pal_op.input_roles) > 1:
                            pal_op.input_roles[1] = "iop_effect_owner_reference"
                            pal_op.non_runtime_input_indices = [1]
                        custody = self._indirect_custody_contract(
                            high=high,
                            raw_op=op,
                            block_addr=b.addr,
                            raw_inputs=raw_inputs,
                            raw_output=raw_output,
                            inputs=inputs,
                            output=output,
                            get_var=get_var,
                        )
                        pal_op.numeric_evidence["input_roles"] = list(
                            pal_op.input_roles
                        )
                        pal_op.numeric_evidence["non_runtime_input_indices"] = list(
                            pal_op.non_runtime_input_indices
                        )
                        pal_op.hf_image["indirect_custody"] = custody
                        self._register_indirect_custody_contract(
                            pal_op, output, custody
                        )

                    b.ops.append(pal_op)

        self._finalize_function_abi_contract(high)
        self._finalize_indirect_custody_inventory()
        self._finalize_abi_inventory()

        self.pal.numeric_evidence_events.append({
            "kind": "lifter_numeric_inventory_v21",
            "function": self.pal.func_name,
            "variables": len(self.pal.vars),
            "parameters": len(self.pal.parameters),
            "operations": sum(len(getattr(b, "ops", []) or []) for b in self.pal.blocks),
        })

        # LINKING + EDGE SEMANTICS
        for hb in high.getBasicBlocks():

            src = addr_map.get(hb.getStart().getOffset())

            for i in range(hb.getOutSize()):

                dest = hb.getOut(i)
                dst = addr_map.get(dest.getStart().getOffset())

                if not dst:
                    continue

                src.successors.append(dst)
                dst.predecessors.append(src)

        # v18+ PALRAW/POW image capture.  This does not change topology.
        self._attach_hf_pcode_image()
        self._attach_raw_machine_image(addr_map)
        self._attach_pow_image()

        return self.pal


    # ------------------------------------------------------------------
    # v18+ PALRAW / POW image helpers
    # ------------------------------------------------------------------

    def _safe_str(self, x):
        try:
            return str(x)
        except Exception:
            return None

    def _safe_decompiled_c(self, decomp_res):
        try:
            return str(decomp_res.getDecompiledFunction().getC())
        except Exception:
            try:
                return str(decomp_res.getCCodeMarkup())
            except Exception:
                return None

    def _term_target_addr_from_inputs(self, inputs):
        if not inputs:
            return None
        target = inputs[0]
        for attr in ("address", "offset", "value"):
            val = getattr(target, attr, None)
            if isinstance(val, int):
                return int(val)
        return None

    def _hf_op_image(self, op, opc, inputs, output):
        def vimg(v):
            if v is None:
                return None
            return {
                "sid": getattr(v, "ssa_id", None),
                "name": getattr(v, "name", None),
                "space": getattr(v, "space", None),
                "offset": getattr(v, "offset", None),
                "size": getattr(v, "size", None),
                "width_bytes": getattr(v, "width_bytes", None),
                "width_bits": getattr(v, "width_bits", None),
                "declared_type_name": getattr(v, "declared_type_name", None),
                "declared_signedness": getattr(v, "declared_signedness", None),
                "address": getattr(v, "address", None),
                "is_constant": bool(getattr(v, "is_constant", False)),
            }

        try:
            seq = op.getSeqnum().toString()
        except Exception:
            seq = None

        return {
            "seqnum": seq,
            "opcode": opc,
            "repr": self._safe_str(op),
            "inputs": [vimg(v) for v in list(inputs or [])],
            "output": vimg(output),
        }

    def _addr(self, x):
        if x is None:
            return None
        if isinstance(x, int):
            return int(x)
        # v21c: raw-flow images are also carried as printable hexadecimal
        # strings.  Accept that representation explicitly instead of asking a
        # Python string for Ghidra's getOffset(), which silently erased every
        # raw branch target from flow_ints.
        if isinstance(x, str):
            try:
                s = x.strip()
                return int(s, 16) if s.lower().startswith("0x") else int(s)
            except Exception:
                return None
        try:
            return int(x.getOffset())
        except Exception:
            return None

    def _fmt_addr(self, x):
        i = self._addr(x)
        if i is None:
            return None if x is None else str(x)
        return "0x%x" % i

    def _get_listing(self):
        try:
            return self.program.getListing()
        except Exception:
            return None

    def _get_instruction_at(self, addr_int):
        listing = self._get_listing()
        if listing is None or addr_int is None:
            return None
        try:
            af = self.program.getAddressFactory()
            space = af.getDefaultAddressSpace()
            return listing.getInstructionAt(space.getAddress(int(addr_int)))
        except Exception:
            return None

    def _raw_varnode_image(self, vn):
        if vn is None:
            return None
        d = {"repr": self._safe_str(vn)}
        try:
            a = vn.getAddress()
            d["space"] = str(a.getAddressSpace().getName())
            d["offset"] = int(a.getOffset())
            d["addr"] = self._fmt_addr(a)
        except Exception:
            d["space"] = None
            d["offset"] = None
            d["addr"] = None
        try:
            d["size"] = int(vn.getSize())
        except Exception:
            d["size"] = None
        for k, m in (("is_constant", "isConstant"), ("is_address", "isAddress"), ("is_register", "isRegister"), ("is_unique", "isUnique")):
            try:
                d[k] = bool(getattr(vn, m)())
            except Exception:
                d[k] = None
        return d

    def _raw_pcode_image(self, instr):
        out = []
        try:
            pcode_ops = instr.getPcode()
        except Exception:
            return out
        for op in pcode_ops:
            try:
                n = op.getNumInputs()
                inputs = [self._raw_varnode_image(op.getInput(i)) for i in range(n)]
            except Exception:
                inputs = []
            try:
                output = self._raw_varnode_image(op.getOutput())
            except Exception:
                output = None
            out.append({
                "repr": self._safe_str(op),
                "opcode": self._safe_str(getattr(op, "getOpcode", lambda: None)()),
                "output": output,
                "inputs": inputs,
            })
        return out

    def _instruction_image(self, instr):
        if instr is None:
            return None
        try:
            addr = instr.getAddress()
        except Exception:
            addr = None
        try:
            ft = instr.getFallThrough()
        except Exception:
            ft = None
        try:
            raw_flows = list(instr.getFlows())
        except Exception:
            raw_flows = []
        flows = [self._fmt_addr(f) for f in raw_flows]
        try:
            mnemonic = str(instr.getMnemonicString())
        except Exception:
            mnemonic = None
        return {
            "addr": self._fmt_addr(addr),
            "addr_int": self._addr(addr),
            "assembly": self._safe_str(instr),
            "mnemonic": mnemonic,
            "fallthrough": self._fmt_addr(ft),
            "fallthrough_int": self._addr(ft),
            "flows": flows,
            # Preserve integer identity from the original Ghidra Address
            # objects.  `flows` remains the printable/debug projection.
            "flow_ints": [self._addr(f) for f in raw_flows if f is not None],
            "raw_pcode": self._raw_pcode_image(instr),
        }

    def _mnemonic_upper(self, irec):
        m = (irec or {}).get("mnemonic")
        if not m:
            asm = (irec or {}).get("assembly") or ""
            m = asm.split()[0] if asm.split() else ""
        return str(m).upper()

    def _is_call_instruction(self, irec):
        return self._mnemonic_upper(irec).startswith("CALL")

    def _is_uncond_jump_instruction(self, irec):
        return self._mnemonic_upper(irec) in ("JMP", "BR", "BRA")

    def _is_cond_jump_instruction(self, irec):
        m = self._mnemonic_upper(irec)
        return m.startswith("J") and not self._is_uncond_jump_instruction(irec)

    def _is_terminal_control_instruction(self, irec):
        if not irec:
            return False
        if self._is_call_instruction(irec):
            return irec.get("fallthrough") is None
        if self._is_uncond_jump_instruction(irec):
            return True
        if self._is_cond_jump_instruction(irec):
            return True
        if irec.get("fallthrough") is None:
            return True
        return False

    def _scan_raw_block(self, start_addr, next_block_addr=None, max_insns=96):
        rec = {
            "block_start": self._fmt_addr(start_addr),
            "block_start_int": int(start_addr) if start_addr is not None else None,
            "next_block_start": self._fmt_addr(next_block_addr),
            "instructions": [],
            "terminal": None,
            "terminal_successors": [],
        }
        cur = int(start_addr)
        seen = set()
        for _ in range(max_insns):
            if cur in seen:
                break
            seen.add(cur)
            instr = self._get_instruction_at(cur)
            if instr is None:
                break
            irec = self._instruction_image(instr)
            rec["instructions"].append(irec)
            if self._is_terminal_control_instruction(irec):
                rec["terminal"] = irec
                rec["terminal_successors"] = self._raw_successors(irec)
                break
            ft = irec.get("fallthrough_int")
            if ft is None:
                rec["terminal"] = irec
                rec["terminal_successors"] = self._raw_successors(irec)
                break
            if next_block_addr is not None and ft >= int(next_block_addr) and ft != int(start_addr):
                rec["terminal"] = irec
                rec["terminal_successors"] = self._raw_successors(irec)
                break
            cur = ft
        if rec["terminal"] is None and rec["instructions"]:
            rec["terminal"] = rec["instructions"][-1]
            rec["terminal_successors"] = self._raw_successors(rec["terminal"])
        return rec

    def _raw_successors(self, irec):
        out = []
        for f in irec.get("flows", []) or []:
            if f is not None:
                out.append(f)
        ft = irec.get("fallthrough")
        if ft is not None:
            out.append(ft)
        dedup = []
        seen = set()
        for x in out:
            if x in seen:
                continue
            seen.add(x)
            dedup.append(x)
        return dedup

    def _normalize_raw_successor(self, succ_addr, block_starts, current_start=None, depth=0):
        if succ_addr is None or depth > 8:
            return succ_addr
        if isinstance(succ_addr, str) and succ_addr.startswith("0x"):
            si = int(succ_addr, 16)
        else:
            try:
                si = int(succ_addr)
            except Exception:
                return succ_addr
        if si in block_starts:
            return self._fmt_addr(si)
        instr = self._get_instruction_at(si)
        if instr is None:
            return self._fmt_addr(si)
        irec = self._instruction_image(instr)
        if self._is_uncond_jump_instruction(irec) and irec.get("flows"):
            return self._normalize_raw_successor(irec["flows"][0], block_starts, current_start, depth + 1)
        if self._is_cond_jump_instruction(irec):
            return self._fmt_addr(si)
        ft = irec.get("fallthrough_int")
        if ft is None:
            return self._fmt_addr(si)
        if ft in block_starts:
            return self._fmt_addr(ft)
        if current_start is not None and ft == current_start:
            return self._fmt_addr(si)
        return self._normalize_raw_successor(ft, block_starts, current_start, depth + 1)

    def _attach_hf_pcode_image(self):
        self.pal.hf_pcode_image = {}
        for b in self.pal.blocks:
            self.pal.hf_pcode_image[b.addr] = {
                "block_addr": self._fmt_addr(b.addr),
                "block_id": getattr(b, "block_id", None),
                "hf_block_repr": getattr(b, "hf_block_repr", None),
                "ops": list(getattr(b, "hf_pcode_image", []) or []),
            }

    def _attach_raw_machine_image(self, addr_map):
        starts = sorted(int(a) for a in addr_map.keys())
        block_starts = set(starts)
        next_by_start = {}
        for i, s in enumerate(starts):
            next_by_start[s] = starts[i + 1] if i + 1 < len(starts) else None

        self.pal.raw_machine_image = {}
        self.pal.raw_pcode_image = {}
        self.pal.raw_vs_hf_branch_image = {}
        self.pal.branch_polarity_by_addr = {}

        for s in starts:
            b = addr_map[s]
            raw_block = self._scan_raw_block(s, next_by_start.get(s))
            b.raw_instruction_image = raw_block.get("instructions", [])
            b.raw_terminal_image = raw_block.get("terminal")
            b.raw_successors = raw_block.get("terminal_successors", [])
            b.raw_normalized_successors = [
                self._normalize_raw_successor(x, block_starts, current_start=s)
                for x in b.raw_successors
            ]

            self.pal.raw_machine_image[s] = raw_block
            self.pal.raw_pcode_image[s] = {
                "block_addr": self._fmt_addr(s),
                "terminal_raw_pcode": (raw_block.get("terminal") or {}).get("raw_pcode", []),
                "instructions": [
                    {"addr": i.get("addr"), "assembly": i.get("assembly"), "raw_pcode": i.get("raw_pcode", [])}
                    for i in raw_block.get("instructions", [])
                ],
            }

            # v21: normalize the HighFunction label and the two raw machine
            # destinations independently.  HighFunction may point at a
            # semantic block while the raw jump points into a folded gateway;
            # comparing only their literal addresses loses branch custody.
            term = getattr(b, "terminator", None)
            if term is not None and getattr(term, "opcode", None) == "CBRANCH":
                raw = getattr(b, "raw_terminal_image", None) or {}
                flows = raw.get("flow_ints") or []
                raw_target = flows[0] if flows else None
                raw_fallthrough = raw.get("fallthrough_int")
                term.hf_normalized_target_addr = self._normalize_raw_successor(
                    getattr(term, "hf_target_addr", None), block_starts, current_start=s
                )
                term.raw_normalized_branch_target_addr = self._normalize_raw_successor(
                    raw_target, block_starts, current_start=s
                )
                term.raw_normalized_fallthrough_addr = self._normalize_raw_successor(
                    raw_fallthrough, block_starts, current_start=s
                )

            self._annotate_block_branch_polarity(b, block_starts)

    def _cond_def_opcode(self, term):
        cond = getattr(term, "condition", None)
        op = getattr(cond, "def_op", None)
        return getattr(op, "opcode", None), op

    def _const_from_var(self, v):
        if v is None:
            return None
        if getattr(v, "is_constant", False):
            return getattr(v, "value", None) if getattr(v, "value", None) is not None else getattr(v, "offset", None)
        return None

    def _signed_const_from_var(self, v):
        """Return a p-code constant interpreted at its declared bit width."""
        value = self._const_from_var(v)
        if not isinstance(value, int):
            return None

        size = getattr(v, "size", None)
        if not isinstance(size, int) or size <= 0:
            return value

        bits = size * 8
        mask = (1 << bits) - 1
        value &= mask
        sign = 1 << (bits - 1)
        return value - (1 << bits) if value & sign else value

    def _signed_zero_bound_shape(self, defop):
        """
        Classify the two common HighFunction encodings of a sign test.

            x < 0    -> "negative"
            -1 < x   -> "nonnegative"

        The distinction is essential for JS/JNS.  Opcode alone is not enough:
        both expressions are INT_SLESS but have opposite truth polarity.
        """
        inputs = list(getattr(defop, "inputs", []) or [])
        if len(inputs) < 2:
            return None

        left, right = inputs[0], inputs[1]
        left_const = self._signed_const_from_var(left)
        right_const = self._signed_const_from_var(right)
        left_is_const = bool(getattr(left, "is_constant", False))
        right_is_const = bool(getattr(right, "is_constant", False))

        if not left_is_const and right_is_const and right_const == 0:
            return "negative"
        if left_is_const and left_const == -1 and not right_is_const:
            return "nonnegative"
        return None

    def _addr_int(self, value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 16) if value.lower().startswith("0x") else int(value)
            except Exception:
                return None
        try:
            return int(value)
        except Exception:
            return None

    def _raw_mnemonic_hf_opcode_hint(self, block):
        """Return the legacy raw-mnemonic/HF-opcode relation as evidence.

        A raw Jcc can test a materialized boolean whose provenance HighFunction
        later rewrites as a source-level predicate.  Therefore Jcc + HF opcode
        is not, by itself, an execution-truth contract.  The caller grants this
        relation authority only after excluding that carrier class.
        """
        term = getattr(block, "terminator", None)
        raw = getattr(block, "raw_terminal_image", None) or {}
        if term is None or getattr(term, "opcode", None) != "CBRANCH":
            return "unknown", None, None, "not_cbranch"

        m = self._mnemonic_upper(raw)
        opc, defop = self._cond_def_opcode(term)
        reason = "mnemonic=%s hf_cond_opcode=%s" % (m, opc)

        # Direct zero/nonzero branch families.
        if m in ("JZ", "JE"):
            if opc == "INT_EQUAL":
                return "target", False, True, reason
            if opc == "INT_NOTEQUAL":
                return "fallthrough", True, False, reason
        if m in ("JNZ", "JNE"):
            if opc == "INT_NOTEQUAL":
                return "target", False, True, reason
            if opc == "INT_EQUAL":
                return "fallthrough", True, False, reason

        # Unsigned carry families.  HighFunction INT_LESS is the unsigned
        # predicate x < y.  JB/JC takes that predicate directly; JAE/JNC takes
        # its complement.  This is the PALexec 0x101172 short-circuit gate.
        if opc == "INT_LESS":
            if m in ("JB", "JC", "JNAE"):
                return "target", False, True, reason
            if m in ("JAE", "JNB", "JNC"):
                return "fallthrough", True, False, reason

        # Direct signed less-than / greater-or-equal pair.
        if opc == "INT_SLESS":
            if m in ("JL", "JNGE"):
                return "target", False, True, reason
            if m in ("JGE", "JNL"):
                return "fallthrough", True, False, reason

        # Signed/unsigned greater-than branches often get represented by HF as
        # the opposite <= / < threshold test.  Mark fallthrough when the HF cond
        # is a less-than family.
        if m in ("JG", "JA"):
            if opc in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
                return "fallthrough", True, False, reason

        # <= branches paired with HF 'constant < var' are also fallthrough-side.
        if m in ("JLE", "JBE"):
            if opc in ("INT_LESS", "INT_SLESS"):
                return "fallthrough", True, False, reason
            if opc in ("INT_LESSEQUAL", "INT_SLESSEQUAL"):
                return "target", False, True, reason

        # Sign branches require expression shape.  Ghidra legitimately emits
        # either x < 0 or -1 < x for the same machine sign family.  A blanket
        # JNS rule therefore fixes one program by reversing another.
        if m in ("JNS", "JS") and opc == "INT_SLESS":
            shape = self._signed_zero_bound_shape(defop)
            shape_reason = "%s hf_sign_shape=%s" % (reason, shape)
            if shape == "negative":
                if m == "JS":
                    return "target", False, True, shape_reason
                return "fallthrough", True, False, shape_reason
            if shape == "nonnegative":
                if m == "JNS":
                    return "target", False, True, shape_reason
                return "fallthrough", True, False, shape_reason

        # Unknown is genuinely unknown.  Do not manufacture direct polarity.
        return "unknown", None, None, reason

    def _raw_zero_test_shape_v21b(self, block):
        """Describe a TEST x,x / CMP x,0 immediately feeding the raw Jcc."""
        instructions = list(getattr(block, "raw_instruction_image", []) or [])
        if len(instructions) < 2:
            return None
        pre = instructions[-2] or {}
        mnemonic = self._mnemonic_upper(pre)
        asm = str(pre.get("assembly") or "").strip()
        operands_text = asm[len(asm.split()[0]):].strip() if asm.split() else ""
        operands = [x.strip().upper() for x in operands_text.split(",") if x.strip()]

        if mnemonic == "TEST" and len(operands) == 2 and operands[0] == operands[1]:
            return {
                "kind": "test_same_operand",
                "assembly": asm,
                "operand": operands[0],
                "raw_instruction_count": len(instructions),
                "isolated_predecessor_carrier": len(instructions) == 2,
            }

        if mnemonic == "CMP" and len(operands) == 2:
            zero_spellings = {"0", "0X0", "0H", "+0", "-0"}
            if operands[0] in zero_spellings or operands[1] in zero_spellings:
                return {
                    "kind": "compare_against_zero",
                    "assembly": asm,
                    "operands": operands,
                    "raw_instruction_count": len(instructions),
                    "isolated_predecessor_carrier": len(instructions) == 2,
                }

        return None

    def _hf_condition_is_explicit_zero_test_v21b(self, defop):
        if defop is None or str(getattr(defop, "opcode", "")).upper() not in (
            "INT_EQUAL", "INT_NOTEQUAL"
        ):
            return False
        inputs = list(getattr(defop, "inputs", []) or [])
        if len(inputs) < 2:
            return False
        for value in inputs[:2]:
            if self._const_from_var(value) == 0:
                return True
        return False

    def _infer_condition_polarity(self, block):
        """Classify direct-flag branches vs materialized-boolean carriers.

        Most raw Jcc instructions consume flags from a source comparison; for
        those, raw mnemonic versus HF relation determines polarity.  A distinct
        compiler shape first materializes a comparison result, then executes
        TEST carrier,carrier / JZ.  In that class the raw JZ tests the carrier,
        not the HF operands, and the HF target label owns semantic truth.

        v21d carrier-family gate:
            An isolated ``CMP/TEST value,0`` is not sufficient evidence of a
            materialized Boolean.  Ordered and sign branches (JG/JL/JNS/etc.)
            directly consume numeric flags and frequently pair with an HF
            complementary predicate such as ``value < 1`` or ``value < 0``.
            Only the zero/nonzero Jcc family is eligible for the isolated
            carrier interpretation.  This preserves optimized TEST/JZ carrier
            blocks while keeping source-value comparisons under raw-Jcc/HF
            relation custody.
        """
        term = getattr(block, "terminator", None)
        if term is None or getattr(term, "opcode", None) != "CBRANCH":
            return "unknown", None, None, "not_cbranch"

        hint_pol, hint_target, hint_fall, hint_reason = self._raw_mnemonic_hf_opcode_hint(block)
        term.condition_polarity_hint = {
            "polarity": hint_pol,
            "invert_for_target": hint_target,
            "invert_for_fallthrough": hint_fall,
            "reason": hint_reason,
            "authoritative": False,
        }

        opc, defop = self._cond_def_opcode(term)
        raw_zero_test = self._raw_zero_test_shape_v21b(block)
        hf_zero_test = self._hf_condition_is_explicit_zero_test_v21b(defop)
        comparison_op = str(opc or "").upper() in (
            "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
            "INT_LESSEQUAL", "INT_SLESSEQUAL"
        )
        raw = getattr(block, "raw_terminal_image", None) or {}
        raw_mnemonic = self._mnemonic_upper(raw)
        carrier_branch_family = raw_mnemonic in ("JZ", "JE", "JNZ", "JNE")
        ordered_or_sign_zero_test = bool(raw_zero_test and not carrier_branch_family)

        possible_carrier = bool(
            raw_zero_test
            and comparison_op
            and not hf_zero_test
            and carrier_branch_family
        )
        materialized_carrier = bool(
            possible_carrier and raw_zero_test.get("isolated_predecessor_carrier") is True
        )
        ambiguous_carrier = bool(possible_carrier and not materialized_carrier)

        term.condition_evidence_class = {
            "kind": (
                "materialized_boolean_carrier" if materialized_carrier else
                "ambiguous_zero_test_carrier" if ambiguous_carrier else
                "direct_ordered_or_sign_zero_test" if ordered_or_sign_zero_test else
                "direct_flags_or_source_zero_test"
            ),
            "raw_zero_test": dict(raw_zero_test) if raw_zero_test else None,
            "raw_branch_mnemonic": raw_mnemonic,
            "carrier_branch_family_eligible": bool(carrier_branch_family),
            "hf_condition_opcode": opc,
            "hf_explicit_zero_test": bool(hf_zero_test),
        }

        hf_target = self._addr_int(
            getattr(term, "hf_normalized_target_addr", None)
            if getattr(term, "hf_normalized_target_addr", None) is not None
            else getattr(term, "hf_target_addr", None)
        )
        raw_target = self._addr_int(
            getattr(term, "raw_normalized_branch_target_addr", None)
            if getattr(term, "raw_normalized_branch_target_addr", None) is not None
            else getattr(term, "raw_branch_target_addr", None)
        )
        raw_fallthrough = self._addr_int(
            getattr(term, "raw_normalized_fallthrough_addr", None)
            if getattr(term, "raw_normalized_fallthrough_addr", None) is not None
            else getattr(term, "raw_fallthrough_addr", None)
        )

        base = (
            "branch_truth_evidence_v21d "
            "hf_target=%s raw_target=%s raw_fallthrough=%s legacy_hint=(%s)"
            % (
                self._fmt_addr(hf_target),
                self._fmt_addr(raw_target),
                self._fmt_addr(raw_fallthrough),
                hint_reason,
            )
        )

        if materialized_carrier:
            if hf_target is not None and raw_target is not None and hf_target == raw_target:
                term.condition_truth_authority = "hf_materialized_boolean_carrier_target"
                return "target", False, True, base + " class=materialized_boolean binding=raw_taken"
            if hf_target is not None and raw_fallthrough is not None and hf_target == raw_fallthrough:
                term.condition_truth_authority = "hf_materialized_boolean_carrier_target"
                return "fallthrough", True, False, base + " class=materialized_boolean binding=raw_fallthrough"
            term.condition_truth_authority = "unresolved_materialized_boolean_custody"
            return "unknown", None, None, base + " class=materialized_boolean binding=unresolved"

        if ambiguous_carrier:
            term.condition_truth_authority = "unresolved_ambiguous_zero_test_carrier"
            return "unknown", None, None, base + " class=ambiguous_zero_test_carrier"

        # Direct flags/source-value zero tests: the old relation is now used
        # only after the instruction shape has ruled out a boolean carrier.
        if hint_target is not None and hint_fall is not None:
            term.condition_truth_authority = "raw_jcc_hf_relation_direct_flags"
            return hint_pol, bool(hint_target), bool(hint_fall), base + " class=direct_flags"

        term.condition_truth_authority = "unresolved_direct_flag_relation"
        return "unknown", None, None, base + " class=direct_flags binding=unresolved"

    def _annotate_block_branch_polarity(self, block, block_starts):
        term = getattr(block, "terminator", None)
        if term is None:
            return
        raw = getattr(block, "raw_terminal_image", None) or {}
        term.raw_terminal_addr = raw.get("addr_int")
        term.raw_terminal_asm = raw.get("assembly")
        term.raw_terminal_mnemonic = raw.get("mnemonic")
        term.raw_terminal_pcode = raw.get("raw_pcode", []) or []
        term.raw_successors = list(getattr(block, "raw_successors", []) or [])
        term.raw_normalized_successors = list(getattr(block, "raw_normalized_successors", []) or [])
        flows = raw.get("flow_ints") or []
        term.raw_branch_target_addr = flows[0] if flows else None
        term.raw_fallthrough_addr = raw.get("fallthrough_int")

        polarity, inv_target, inv_fall, reason = self._infer_condition_polarity(block)
        term.condition_polarity = polarity
        term.condition_invert_for_target = None if inv_target is None else bool(inv_target)
        term.condition_invert_for_fallthrough = None if inv_fall is None else bool(inv_fall)
        term.condition_polarity_reason = reason
        term.raw_hf_audit = {
            "block_addr": self._fmt_addr(block.addr),
            "hf_condition_sid": getattr(getattr(term, "condition", None), "ssa_id", None),
            "hf_condition_repr": str(getattr(term, "condition", None)),
            "hf_target_addr": self._fmt_addr(getattr(term, "hf_target_addr", None)),
            "raw_terminal_addr": raw.get("addr"),
            "raw_terminal_asm": raw.get("assembly"),
            "raw_terminal_mnemonic": raw.get("mnemonic"),
            "raw_successors": term.raw_successors,
            "raw_normalized_successors": term.raw_normalized_successors,
            "condition_polarity": polarity,
            "condition_invert_for_target": None if inv_target is None else bool(inv_target),
            "condition_invert_for_fallthrough": None if inv_fall is None else bool(inv_fall),
            "condition_polarity_reason": reason,
            "condition_truth_authority": getattr(term, "condition_truth_authority", None),
            "condition_polarity_hint": dict(getattr(term, "condition_polarity_hint", {}) or {}),
            "condition_evidence_class": dict(getattr(term, "condition_evidence_class", {}) or {}),
            "hf_normalized_target_addr": self._fmt_addr(
                self._addr_int(getattr(term, "hf_normalized_target_addr", None))
            ),
            "raw_normalized_branch_target_addr": self._fmt_addr(
                self._addr_int(getattr(term, "raw_normalized_branch_target_addr", None))
            ),
            "raw_normalized_fallthrough_addr": self._fmt_addr(
                self._addr_int(getattr(term, "raw_normalized_fallthrough_addr", None))
            ),
            "hf_pcode": list(getattr(block, "hf_pcode_image", []) or []),
            "raw_pcode": raw.get("raw_pcode", []) or [],
        }
        block.branch_polarity_audit = term.raw_hf_audit
        self.pal.raw_vs_hf_branch_image[block.addr] = term.raw_hf_audit
        self.pal.branch_polarity_by_addr[block.addr] = {
            "condition_polarity": polarity,
            "condition_invert_for_target": None if inv_target is None else bool(inv_target),
            "condition_invert_for_fallthrough": None if inv_fall is None else bool(inv_fall),
            "reason": reason,
            "condition_truth_authority": getattr(term, "condition_truth_authority", None),
            "condition_polarity_hint": dict(getattr(term, "condition_polarity_hint", {}) or {}),
            "condition_evidence_class": dict(getattr(term, "condition_evidence_class", {}) or {}),
        }

    def _attach_pow_image(self):
        self.pal.pow_image = {
            "function_name": getattr(self.pal, "func_name", None),
            "function_address": self._fmt_addr(getattr(self.pal, "function_address", None)),
            "range": [self._fmt_addr(x) for x in getattr(self.pal, "range", [])],
            "decompiled_c": getattr(self.pal, "decompiled_c_image", None),
            "hf_pcode_image": getattr(self.pal, "hf_pcode_image", {}),
            "raw_machine_image": getattr(self.pal, "raw_machine_image", {}),
            "raw_pcode_image": getattr(self.pal, "raw_pcode_image", {}),
            "raw_vs_hf_branch_image": getattr(self.pal, "raw_vs_hf_branch_image", {}),
            "branch_polarity_by_addr": getattr(self.pal, "branch_polarity_by_addr", {}),
            "target_numeric_model": getattr(self.pal, "target_numeric_model", {}),
            "function_signature": getattr(self.pal, "function_signature", {}),
            "numeric_evidence_events": getattr(self.pal, "numeric_evidence_events", []),
            "indirect_custody_inventory": getattr(
                self.pal, "indirect_custody_inventory", {}
            ),
            "indirect_custody_contracts": getattr(
                self.pal, "indirect_custody_contracts", []
            ),
            "indirect_effect_owner_groups": getattr(
                self.pal, "indirect_effect_owner_groups", {}
            ),
            "indirect_custody_warnings": getattr(
                self.pal, "indirect_custody_warnings", []
            ),
            "function_abi_contract": getattr(
                self.pal, "function_abi_contract", {}
            ),
            "call_site_abi_contracts": getattr(
                self.pal, "call_site_abi_contracts", []
            ),
            "abi_inventory": getattr(self.pal, "abi_inventory", {}),
            "abi_observations": getattr(self.pal, "abi_observations", []),
            "abi_warnings": getattr(self.pal, "abi_warnings", []),
        }


# ======================================
# CFG BUILDER (SEMANTIC EDGES)
# ======================================
# ============================================================================
# FUNCTION CFG (CORRECTED + ORDERED + STABLE)
# ============================================================================

# ============================================================================
# FUNCTION CFG
# Stable CFG builder with sane repair order
# ============================================================================
#
# Design goals:
#   1. Preserve all raw Ghidra successors, even for blocks with no terminator.
#   2. Repair missing fall-through/orphan forward edges before computing loops.
#   3. Never invent a loop backedge merely because a header dominates a block.
#   4. Use dominators to classify natural loops after the graph is connected.
#   5. Compute postdominators/IPDOM only after edge repair is complete.
#
# Important:
#   This class assumes CFGNode, CFGEdge, and PALTerminator already exist.
# ============================================================================


class FunctionCFG:

    def __init__(self, pal_func):

        self.pal_func = pal_func
        self.cfg_version = "FunctionCFG_v21d_zero_test_carrier_family_gate"
        try:
            self.pal_func.cfg_version = self.cfg_version
        except Exception:
            pass

        self.nodes = {}
        self.entry = None
        self.exit = None
        self.exit_nodes = set()

        # Diagnostics
        self.repaired_edges = []
        self.branch_resolution_events = []
        self.backedges = []
        self.loop_headers = set()
        self.loop_latches = {}

        # ------------------------------------------------------------
        # 1. CREATE NODES
        # ------------------------------------------------------------
        for b in getattr(pal_func, "blocks", []):
            self.nodes[b.addr] = CFGNode(b)

        # ------------------------------------------------------------
        # 2. BUILD RAW EDGES FROM GHIDRA
        # ------------------------------------------------------------
        self._build_raw_edges(pal_func)

        # ------------------------------------------------------------
        # 3. ENTRY DETECTION
        # ------------------------------------------------------------
        self._detect_entry(pal_func)

        # ------------------------------------------------------------
        # 4. EXIT DETECTION
        # ------------------------------------------------------------
        self._detect_exits()

        # ------------------------------------------------------------
        # 5. REPAIR FORWARD ORPHANS BEFORE DOMINATOR LOOP LOGIC
        # ------------------------------------------------------------
        self._repair_orphan_fallthroughs()

        # ------------------------------------------------------------
        # 6. DOMINATORS
        # ------------------------------------------------------------
        self._compute_dominators()

        # ------------------------------------------------------------
        # 7. NATURAL LOOP CLASSIFICATION
        #    Important: classify existing edges; do not invent broad ones.
        # ------------------------------------------------------------
        self._classify_backedges()

        # ------------------------------------------------------------
        # 8. STRICT LATCH REPAIR, ONLY IF STILL ORPHANED
        # ------------------------------------------------------------
        self._repair_strict_phi_latches()

        # If strict latch repair changed the graph, recompute dominators.
        if getattr(self, "_changed_after_dominators", False):
            self._compute_dominators()
            self._classify_backedges()

        # ------------------------------------------------------------
        # 9. POSTDOM + IPDOM
        # ------------------------------------------------------------
        self._compute_postdominators()
        self._compute_ipdom()

        self.debug_print()

    # =========================================================================
    # RAW EDGE BUILDING
    # =========================================================================

    def _build_raw_edges(self, pal_func):
        """
        Build edges from PALBlock.successors.

        Critical correction:
            Do not skip blocks merely because block.terminator is None.
            Some useful fall-through blocks may have no explicit terminator
            but still need successors.
        """

        for b in getattr(pal_func, "blocks", []):

            node = self.nodes.get(b.addr)

            if node is None:
                continue

            term = getattr(b, "terminator", None)
            succs = list(getattr(b, "successors", []) or [])

            if not succs:
                continue

            # RETURN should not have ordinary successors.
            if term is not None and getattr(term, "opcode", None) == "RETURN":
                continue

            # Conditional branch.
            if term is not None and getattr(term, "opcode", None) == "CBRANCH":

                self._add_cbranch_edges(node, term, succs)
                continue

            # Unconditional branch, fall-through, or no terminator.
            for s in succs:
                dst = self.nodes.get(getattr(s, "addr", None))
                if dst is not None:
                    self._add_edge(node, dst, "uncond")

    def _add_cbranch_edges(self, node, term, succs):
        """
        Add typed CBRANCH edges.

        v18+ PALRAW rule:
            Edge topology follows explicit branch target/fallthrough.
            Condition polarity is separate metadata.  SGL must use
            edge.condition_invert_for_edge rather than swapping branch bodies.
        """

        succ_nodes = []

        for s in succs:
            dst = self.nodes.get(getattr(s, "addr", None))
            if dst is not None:
                succ_nodes.append(dst)

        if not succ_nodes:
            return

        base_meta = {
            "condition_polarity": getattr(term, "condition_polarity", "unknown"),
            "condition_polarity_reason": getattr(term, "condition_polarity_reason", None),
            "condition_truth_authority": getattr(term, "condition_truth_authority", None),
            "hf_target_addr": getattr(term, "hf_target_addr", None),
            "hf_normalized_target_addr": getattr(term, "hf_normalized_target_addr", None),
            "raw_terminal_addr": getattr(term, "raw_terminal_addr", None),
            "raw_terminal_mnemonic": getattr(term, "raw_terminal_mnemonic", None),
            "raw_branch_target_addr": getattr(term, "raw_branch_target_addr", None),
            "raw_fallthrough_addr": getattr(term, "raw_fallthrough_addr", None),
            "raw_normalized_branch_target_addr": getattr(term, "raw_normalized_branch_target_addr", None),
            "raw_normalized_fallthrough_addr": getattr(term, "raw_normalized_fallthrough_addr", None),
        }

        if len(succ_nodes) == 1:
            self._add_edge(
                node,
                succ_nodes[0],
                "uncond",
                role="single_successor_from_cbranch",
                explicit_branch_target=False,
                **base_meta,
            )
            return

        branch_addr = self._branch_target_addr(term)

        true_node = None
        false_node = None

        if branch_addr is not None:
            for dst in succ_nodes:
                if getattr(dst, "addr", None) == branch_addr:
                    true_node = dst
                    break

        if true_node is not None:
            for dst in succ_nodes:
                if dst is not true_node:
                    false_node = dst
                    break

            binding = self._bind_classified_condition_to_binary_edges_v21b(
                node, term, true_node, false_node, topology_resolved=True
            )
            true_meta = dict(base_meta)
            true_meta.update({
                "condition_invert_for_edge": binding["first_invert"],
                "condition_polarity": getattr(term, "condition_polarity", "unknown"),
                "condition_polarity_reason": binding["reason"],
                "condition_truth_authority": binding["authority"],
            })
            false_meta = dict(base_meta)
            false_meta.update({
                "condition_invert_for_edge": binding["second_invert"],
                "condition_polarity": getattr(term, "condition_polarity", "unknown"),
                "condition_polarity_reason": binding["reason"],
                "condition_truth_authority": binding["authority"],
            })

            e_true = self._add_edge(
                node,
                true_node,
                "true",
                role="raw_true_explicit_target",
                explicit_branch_target=True,
                branch_target_addr=branch_addr,
                **true_meta,
            )
            e_false = self._add_edge(
                node,
                false_node,
                "false",
                role="raw_false_fallthrough",
                explicit_branch_target=False,
                branch_target_addr=branch_addr,
                fallthrough=True,
                **false_meta,
            )

            self._record_condition_binding_v21b(node, true_node, false_node, binding)

            try:
                term.true_target = true_node.block
                term.false_target = false_node.block
                term.target = true_node.block
            except Exception:
                pass

            for dst in succ_nodes:
                if dst is not true_node and dst is not false_node:
                    self._add_edge(
                        node,
                        dst,
                        "uncond",
                        role="extra_cbranch_successor",
                        explicit_branch_target=False,
                        **base_meta,
                    )

            return

        # v19: the raw taken address may land inside a HighFunction block or
        # in a short raw gateway which Ghidra folds into a later HF successor.
        # Exact target matching then fails even though the raw fallthrough
        # still matches one HF successor exactly.  For a binary CBRANCH that
        # exact fallthrough match proves the peer is the taken-side successor;
        # successor order is unnecessary.
        raw_fallthrough_addr = getattr(term, "raw_fallthrough_addr", None)
        if len(succ_nodes) == 2 and raw_fallthrough_addr is not None:
            exact_fallthrough_nodes = [
                dst for dst in succ_nodes
                if getattr(dst, "addr", None) == raw_fallthrough_addr
            ]

            if len(exact_fallthrough_nodes) == 1:
                false_node = exact_fallthrough_nodes[0]
                true_node = succ_nodes[0] if succ_nodes[1] is false_node else succ_nodes[1]

                binding = self._bind_classified_condition_to_binary_edges_v21b(
                    node, term, true_node, false_node, topology_resolved=True
                )
                target_invert = binding["first_invert"]
                fallthrough_invert = binding["second_invert"]
                true_meta = dict(base_meta)
                true_meta.update({
                    "condition_invert_for_edge": target_invert,
                    "condition_polarity": getattr(term, "condition_polarity", "unknown"),
                    "condition_polarity_reason": binding["reason"],
                    "condition_truth_authority": binding["authority"],
                })
                false_meta = dict(base_meta)
                false_meta.update({
                    "condition_invert_for_edge": fallthrough_invert,
                    "condition_polarity": getattr(term, "condition_polarity", "unknown"),
                    "condition_polarity_reason": binding["reason"],
                    "condition_truth_authority": binding["authority"],
                })

                self._add_edge(
                    node,
                    true_node,
                    "true",
                    role="raw_taken_by_exact_fallthrough_complement_v19",
                    explicit_branch_target=False,
                    branch_target_addr=branch_addr,
                    **true_meta,
                )
                self._add_edge(
                    node,
                    false_node,
                    "false",
                    role="raw_false_exact_fallthrough_v19",
                    explicit_branch_target=False,
                    branch_target_addr=branch_addr,
                    fallthrough=True,
                    **false_meta,
                )

                self._record_condition_binding_v21b(node, true_node, false_node, binding)

                self.branch_resolution_events.append({
                    "kind": "binary_branch_resolved_by_exact_fallthrough_complement_v19",
                    "src": getattr(node, "addr", None),
                    "raw_branch_target": branch_addr,
                    "raw_fallthrough": raw_fallthrough_addr,
                    "taken_dst": getattr(true_node, "addr", None),
                    "fallthrough_dst": getattr(false_node, "addr", None),
                    "condition_polarity": getattr(term, "condition_polarity", "unknown"),
                    "taken_invert": target_invert,
                    "fallthrough_invert": fallthrough_invert,
                    "reason": binding["reason"],
                    "condition_truth_authority": binding["authority"],
                })

                try:
                    term.true_target = true_node.block
                    term.false_target = false_node.block
                    term.target = true_node.block
                except Exception:
                    pass

                return

        # Fallback: preserve successor order but mark it as order-based.
        true_node = succ_nodes[0]
        false_node = succ_nodes[1]

        binding = self._bind_classified_condition_to_binary_edges_v21b(
            node, term, true_node, false_node, topology_resolved=False
        )
        true_meta = dict(base_meta)
        true_meta.update({
            "condition_invert_for_edge": binding["first_invert"],
            "condition_polarity_reason": binding["reason"],
            "condition_truth_authority": binding["authority"],
        })
        false_meta = dict(base_meta)
        false_meta.update({
            "condition_invert_for_edge": binding["second_invert"],
            "condition_polarity_reason": binding["reason"],
            "condition_truth_authority": binding["authority"],
        })

        self._add_edge(
            node,
            true_node,
            "true",
            role="raw_true_order_fallback",
            explicit_branch_target=False,
            branch_target_addr=branch_addr,
            **true_meta,
        )
        self._add_edge(
            node,
            false_node,
            "false",
            role="raw_false_order_fallback",
            explicit_branch_target=False,
            branch_target_addr=branch_addr,
            fallthrough=True,
            **false_meta,
        )

        self._record_condition_binding_v21b(node, true_node, false_node, binding)

        try:
            term.true_target = true_node.block
            term.false_target = false_node.block
        except Exception:
            pass

        self.branch_resolution_events.append({
            "kind": "binary_branch_unresolved_order_fallback_v19",
            "src": getattr(node, "addr", None),
            "raw_branch_target": branch_addr,
            "raw_fallthrough": getattr(term, "raw_fallthrough_addr", None),
            "first_dst": getattr(true_node, "addr", None),
            "second_dst": getattr(false_node, "addr", None),
            "condition_polarity": getattr(term, "condition_polarity", "unknown"),
            "first_invert": binding["first_invert"],
            "second_invert": binding["second_invert"],
            "condition_truth_authority": binding["authority"],
            "reason": "raw target and fallthrough did not uniquely map to HF successors",
        })

        for dst in succ_nodes[2:]:
            self._add_edge(
                node,
                dst,
                "uncond",
                role="extra_cbranch_successor_order_fallback",
                explicit_branch_target=False,
                **base_meta,
            )

    def _addr_int_v21(self, value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 16) if value.lower().startswith("0x") else int(value)
            except Exception:
                return None
        try:
            return int(value)
        except Exception:
            return None

    def _bind_classified_condition_to_binary_edges_v21b(self, src, term, first_node, second_node,
                                                         topology_resolved=False):
        """Transfer evidence-classified term polarity to concrete CFG edges.

        For resolved raw topology, first/second are taken/fallthrough and the
        lifter's classified tri-state contract transfers directly.  For an
        order fallback, those positions have no measured custody, so even a
        term-level taken/fallthrough contract must remain unresolved.
        """
        hf_raw = self._addr_int_v21(getattr(term, "hf_target_addr", None))
        hf_norm = self._addr_int_v21(getattr(term, "hf_normalized_target_addr", None))
        first_invert = getattr(term, "condition_invert_for_target", None)
        second_invert = getattr(term, "condition_invert_for_fallthrough", None)
        authority = getattr(term, "condition_truth_authority", None) or "unresolved_branch_truth"
        reason = getattr(term, "condition_polarity_reason", None) or "missing_term_branch_truth_v21b"

        if topology_resolved and first_invert is not None and second_invert is not None:
            direct = first_node if not bool(first_invert) else second_node
            return {
                "first_invert": bool(first_invert),
                "second_invert": bool(second_invert),
                "authority": authority,
                "reason": reason,
                "hf_target": hf_raw,
                "hf_normalized_target": hf_norm,
                "direct_dst": getattr(direct, "addr", None),
                "resolved": True,
            }

        # Order fallback or unresolved lifter evidence: no authoritative edge
        # assignment.  In particular, do not use a normalized gateway address
        # as a substitute for measured taken/fallthrough custody.
        return {
            "first_invert": None,
            "second_invert": None,
            "authority": "unresolved_cfg_edge_custody",
            "reason": reason + " cfg_binding=unresolved",
            "hf_target": hf_raw,
            "hf_normalized_target": hf_norm,
            "direct_dst": None,
            "resolved": False,
        }

    def _record_condition_binding_v21b(self, src, first_node, second_node, binding):
        self.branch_resolution_events.append({
            "kind": (
                "binary_branch_truth_bound_by_evidence_class_v21d"
                if binding.get("resolved") else
                "binary_branch_truth_unresolved_v21d"
            ),
            "src": getattr(src, "addr", None),
            "first_dst": getattr(first_node, "addr", None),
            "second_dst": getattr(second_node, "addr", None),
            "hf_target": binding.get("hf_target"),
            "hf_normalized_target": binding.get("hf_normalized_target"),
            "direct_dst": binding.get("direct_dst"),
            "first_invert": binding.get("first_invert"),
            "second_invert": binding.get("second_invert"),
            "condition_truth_authority": binding.get("authority"),
            "reason": binding.get("reason"),
        })

    def _branch_target_addr(self, term):
        """
        Extract the raw CBRANCH target address when available, otherwise use
        term.inputs[0].

        PALVariable may expose the address as:
            .address
            .offset
            .value
        """

        # v19: the instruction-derived target is the topology authority.  The
        # HF operand can survive as a label which does not coincide with a
        # HighFunction block start, but it must never displace a measured raw
        # branch target.
        raw_target = getattr(term, "raw_branch_target_addr", None)
        if isinstance(raw_target, int):
            return raw_target

        inputs = list(getattr(term, "inputs", []) or [])

        if not inputs:
            return None

        target = inputs[0]

        if target is None:
            return None

        for attr in ("address", "offset", "value"):
            val = getattr(target, attr, None)

            if isinstance(val, int):
                return val

        return None

    # =========================================================================
    # ENTRY / EXIT
    # =========================================================================

    def _detect_entry(self, pal_func):

        # Prefer the function entry address when available.
        entry_addr = getattr(pal_func, "function_address", None)

        if entry_addr in self.nodes:
            self.entry = self.nodes[entry_addr]
            return

        # Fallback: first node with no incoming edges.
        for n in self._real_nodes():
            if not getattr(n, "in_edges", []):
                self.entry = n
                return

        # Last fallback: lowest-address block.
        ordered = self._real_nodes_sorted()

        self.entry = ordered[0] if ordered else None

    def _detect_exits(self):

        self.exit_nodes = set()

        for n in self._real_nodes():

            term = getattr(n.block, "terminator", None)

            if term is not None and getattr(term, "opcode", None) == "RETURN":
                self.exit_nodes.add(n)

        if len(self.exit_nodes) == 1:
            self.exit = next(iter(self.exit_nodes))
            return

        # Multiple exits or no explicit exit: create virtual exit.
        virtual_block = type("VirtualExit", (), {"addr": "EXIT"})()
        self.exit = CFGNode(virtual_block)
        self.nodes["EXIT"] = self.exit

        for n in self.exit_nodes:
            self._add_edge(n, self.exit, "uncond")

    # =========================================================================
    # ORPHAN / FALLTHROUGH REPAIR
    # =========================================================================

    def _repair_orphan_fallthroughs(self):
        """
        Repair no-outgoing non-return nodes by connecting them to the next
        forward block in address order.

        This is intentionally done BEFORE dominator/backedge classification.

        For the current main() case this repairs:
            0x101296 -> 0x1012a8
            0x1012a8 -> 0x1012ac
            0x1012cb -> 0x1012d8

        without inventing:
            0x1012cb -> 0x1012ac
        """

        ordered = self._real_nodes_sorted()

        for idx, n in enumerate(ordered):

            if getattr(n, "out_edges", []):
                continue

            term = getattr(n.block, "terminator", None)

            if term is not None and getattr(term, "opcode", None) == "RETURN":
                continue

            candidate = self._next_forward_node(n, ordered)

            if candidate is None:
                continue

            self._add_edge(n, candidate, "uncond")
            self.repaired_edges.append((n, candidate, "fallthrough"))

    def _next_forward_node(self, node, ordered):

        addr = getattr(node, "addr", None)

        if not isinstance(addr, int):
            return None

        best = None
        best_addr = None

        for cand in ordered:

            if cand is node:
                continue

            caddr = getattr(cand, "addr", None)

            if not isinstance(caddr, int):
                continue

            if caddr <= addr:
                continue

            if best is None or caddr < best_addr:
                best = cand
                best_addr = caddr

        return best

    # =========================================================================
    # STRICT PHI-LATCH REPAIR
    # =========================================================================

    def _repair_strict_phi_latches(self):
        """
        Optional strict repair for still-orphaned loop latches.

        Unlike the old _fix_backedges(), this does NOT connect any dominated
        orphan to any dominating conditional header.

        It only repairs an orphan n -> header when:
            - n still has no outgoing edges
            - header is conditional
            - header dominates n
            - n defines a variable consumed by a MULTIEQUAL in header

        In many functions, _repair_orphan_fallthroughs() already handles the
        common case and this method does nothing.
        """

        self._changed_after_dominators = False

        for n in self._real_nodes():

            if getattr(n, "out_edges", []):
                continue

            term = getattr(n.block, "terminator", None)

            if term is not None and getattr(term, "opcode", None) == "RETURN":
                continue

            defined = self._defined_sids(n)

            if not defined:
                continue

            for h in self._real_nodes():

                if h is n:
                    continue

                hterm = getattr(h.block, "terminator", None)

                if hterm is None or getattr(hterm, "opcode", None) != "CBRANCH":
                    continue

                if h not in getattr(n, "dominators", set()):
                    continue

                phi_inputs = self._phi_input_sids(h)

                if defined & phi_inputs:
                    self._add_edge(n, h, "uncond")
                    self.repaired_edges.append((n, h, "strict_phi_latch"))
                    self._changed_after_dominators = True
                    break

    def _defined_sids(self, node):

        out = set()

        for op in getattr(node.block, "ops", []):

            v = getattr(op, "output", None)
            sid = getattr(v, "ssa_id", None)

            if sid is not None:
                out.add(sid)

        return out

    def _phi_input_sids(self, node):

        out = set()

        for op in getattr(node.block, "ops", []):

            if getattr(op, "opcode", None) != "MULTIEQUAL":
                continue

            for inp in getattr(op, "inputs", []):

                sid = getattr(inp, "ssa_id", None)

                if sid is not None:
                    out.add(sid)

        return out

    # =========================================================================
    # DOMINATORS
    # =========================================================================

    def _compute_dominators(self):

        nodes = list(self.nodes.values())

        entry = self.entry

        if entry is None:
            return

        for n in nodes:
            n.dominators = {n} if n == entry else set(nodes)

        changed = True

        while changed:

            changed = False

            for n in nodes:

                if n == entry:
                    continue

                preds = n.predecessors()

                if not preds:
                    # Unreachable island. Keep it self-dominated only.
                    new_dom = {n}
                else:
                    new_dom = set(nodes)

                    for p in preds:
                        new_dom &= getattr(p, "dominators", set(nodes))

                    new_dom.add(n)

                if new_dom != getattr(n, "dominators", set()):
                    n.dominators = new_dom
                    changed = True

    # =========================================================================
    # LOOP CLASSIFICATION
    # =========================================================================

    def _classify_backedges(self):
        """
        Classify existing natural-loop backedges.

        Edge n -> h is a backedge when h dominates n.

        Important:
            This method does not invent edges. It only marks what exists.
        """

        self.backedges = []
        self.loop_headers = set()
        self.loop_latches = {}

        for n in self._real_nodes():

            for e in getattr(n, "out_edges", []):

                dst = getattr(e, "dst", None)

                if dst is None:
                    continue

                if dst in getattr(n, "dominators", set()):

                    if not hasattr(e, "raw_type") or e.raw_type is None:
                        e.raw_type = getattr(e, "type", None)
                    e.type = "backedge"
                    e.is_backedge = True
                    e.role = "latch_to_header"
                    e.meta["latch_to_header"] = True
                    e.meta["loop_header_addr"] = getattr(dst, "addr", None)

                    self.backedges.append(e)
                    self.loop_headers.add(dst)
                    self.loop_latches.setdefault(dst, []).append(n)

    # =========================================================================
    # POSTDOMINATORS
    # =========================================================================

    def _compute_postdominators(self):

        nodes = list(self.nodes.values())

        exit_node = self.exit

        if exit_node is None:
            return

        for n in nodes:
            n.postdominators = set(nodes)

        exit_node.postdominators = {exit_node}

        changed = True

        while changed:

            changed = False

            for n in nodes:

                if n == exit_node:
                    continue

                succs = n.successors()

                if not succs:
                    # Dead-end non-return. Treat as self-only postdominated.
                    new_pdom = {n}
                else:
                    new_pdom = set(nodes)

                    for s in succs:
                        new_pdom &= getattr(s, "postdominators", set(nodes))

                    new_pdom.add(n)

                if new_pdom != getattr(n, "postdominators", set()):
                    n.postdominators = new_pdom
                    changed = True

    # =========================================================================
    # IPDOM
    # =========================================================================

    def _compute_ipdom(self):

        for n in self.nodes.values():

            if n == self.exit:
                n.ipdom = None
                continue

            candidates = getattr(n, "postdominators", set()) - {n}

            if not candidates:
                n.ipdom = None
                continue

            ipdom = None

            for c in candidates:

                # c is immediate if it is not postdominated by any
                # other candidate closer to n.
                is_immediate = True

                for other in candidates:

                    if other is c:
                        continue

                    if c in getattr(other, "postdominators", set()):
                        is_immediate = False
                        break

                if is_immediate:
                    ipdom = c
                    break

            n.ipdom = ipdom

    # =========================================================================
    # EDGE HELPERS
    # =========================================================================

    def _add_edge(self, src, dst, etype, **meta):

        if src is None or dst is None:
            return None

        # Avoid duplicate edges; merge metadata if one exists.
        for e in getattr(src, "out_edges", []):
            if e.dst is dst:
                if e.type == "uncond" and etype in ("true", "false", "backedge"):
                    e.type = etype
                if not hasattr(e, "raw_type") or e.raw_type is None:
                    e.raw_type = etype
                if hasattr(e, "set_meta"):
                    e.set_meta(**meta)
                else:
                    e.meta = getattr(e, "meta", {}) or {}
                    e.meta.update(meta or {})
                return e

        e = CFGEdge(src, dst, etype, **meta)

        src.out_edges.append(e)
        dst.in_edges.append(e)

        return e

    def get_node(self, block_or_addr):

        if hasattr(block_or_addr, "addr"):
            return self.nodes.get(block_or_addr.addr)

        return self.nodes.get(block_or_addr)

    def _real_nodes(self):

        for n in self.nodes.values():

            if getattr(n, "addr", None) == "EXIT":
                continue

            yield n

    def _real_nodes_sorted(self):

        real = list(self._real_nodes())

        def key(n):
            addr = getattr(n, "addr", None)
            if isinstance(addr, int):
                return addr
            return 10 ** 30

        return sorted(real, key=key)

    # =========================================================================
    # DEBUG
    # =========================================================================

    def debug_print(self):

        print("\n===== CFG DEBUG =====\n")

        print("[EDGES]")
        for n in self._real_nodes_sorted():
            for e in getattr(n, "out_edges", []):
                s = getattr(e.src, "addr", "?")
                d = getattr(e.dst, "addr", "?")

                s_txt = hex(s) if isinstance(s, int) else str(s)
                d_txt = hex(d) if isinstance(d, int) else str(d)

                raw = getattr(e, "raw_type", getattr(e, "type", None))
                role = getattr(e, "role", getattr(e, "type", None))
                pol = getattr(e, "condition_polarity", "unknown")
                inv = getattr(e, "condition_invert_for_edge", None)
                print("%s -> %s  %s raw=%s role=%s pol=%s inv=%s" % (
                    s_txt, d_txt, e.type, raw, role, pol, inv
                ))

        if self.branch_resolution_events:
            print("\n[BRANCH RESOLUTION EVENTS]")
            for event in self.branch_resolution_events:
                print(event)

        print("\n[IPDOM]")
        for n in self._real_nodes_sorted():
            ip = getattr(n, "ipdom", None)

            if ip is None:
                ip_txt = "None"
            else:
                ip_addr = getattr(ip, "addr", None)
                ip_txt = hex(ip_addr) if isinstance(ip_addr, int) else str(ip_addr)

            n_addr = getattr(n, "addr", "?")
            n_txt = hex(n_addr) if isinstance(n_addr, int) else str(n_addr)

            print("%s -> ipdom: %s" % (n_txt, ip_txt))

        if self.repaired_edges:
            print("\n[REPAIRED EDGES]")
            for src, dst, reason in self.repaired_edges:
                s = getattr(src, "addr", "?")
                d = getattr(dst, "addr", "?")
                s_txt = hex(s) if isinstance(s, int) else str(s)
                d_txt = hex(d) if isinstance(d, int) else str(d)
                print("%s -> %s  %s" % (s_txt, d_txt, reason))

        if self.backedges:
            print("\n[BACKEDGES]")
            for e in self.backedges:
                s = getattr(e.src, "addr", "?")
                d = getattr(e.dst, "addr", "?")
                s_txt = hex(s) if isinstance(s, int) else str(s)
                d_txt = hex(d) if isinstance(d, int) else str(d)
                print("%s -> %s" % (s_txt, d_txt))

        print("\n=====================\n")

# ======================================
# SYMBOL RESOLVER (FIXED)
# ======================================
import PALSymbolResolver


# ======================================
# DEBUG DUMP
# ======================================

def debug_dump(pal):

    print("\n===== PAL DEBUG DUMP =====\n")

    print("Variables:")
    for v in pal.vars.values():
        print(f"{v.ssa_id} | {v.name} | {v.var_type} | const={v.value}")

    print("\nBlocks:")
    for b in pal.blocks:

        print(f"\nBLOCK {hex(b.addr)}")

        for op in b.ops:
            print(f"  {op.opcode} {op.inputs} -> {op.output}")

        if b.terminator:
            print(f"  TERM {b.terminator.opcode} cond={b.terminator.condition}")

    print("\nCFG Edges:")
    for n in pal.cfg.nodes.values():
        for e in n.out_edges:
            
            if isinstance(e.src.addr, str) or isinstance(e.dst.addr, str):
                print(e.src.addr, e.dst.addr, e.type)
            else:
                print(hex(e.src.addr), hex(e.dst.addr), e.type)

    print("\n===== END DEBUG =====\n")


def debug_dump_numeric_evidence(pal, include_operations=True):
    """Print the v21 lifter evidence without running PALCompute inference."""

    print("\n===== PAL NUMERIC EVIDENCE v21 =====\n")
    print("[TARGET]")
    print(getattr(pal, "target_numeric_model", {}) or {})

    print("\n[FUNCTION SIGNATURE]")
    print(getattr(pal, "function_signature", {}) or {})

    print("\n[PARAMETERS]")
    for var in list(getattr(pal, "parameters", []) or []):
        print({
            "sid": getattr(var, "ssa_id", None),
            "name": getattr(var, "name", None),
            "original_name": getattr(var, "original_name", None),
            "ordinal": getattr(var, "parameter_ordinal", None),
            "width_bits": getattr(var, "width_bits", None),
            "declared_type": getattr(var, "declared_type_name", None),
            "declared_signedness": getattr(var, "declared_signedness", None),
            "provenance": list(getattr(var, "type_provenance", []) or []),
        })

    print("\n[VARIABLES]")
    vars_in = getattr(pal, "vars", {}) or {}
    variables = vars_in.values() if isinstance(vars_in, dict) else list(vars_in)
    for var in variables:
        print({
            "sid": getattr(var, "ssa_id", None),
            "name": getattr(var, "name", None),
            "space": getattr(var, "space", None),
            "width_bits": getattr(var, "width_bits", None),
            "declared_type": getattr(var, "declared_type_name", None),
            "declared_domain": getattr(var, "declared_domain", None),
            "declared_signedness": getattr(var, "declared_signedness", None),
        })

    if include_operations:
        print("\n[OPERATIONS]")
        for block in list(getattr(pal, "blocks", []) or []):
            for op in list(getattr(block, "ops", []) or []):
                print(dict(getattr(op, "numeric_evidence", {}) or {}))
            term = getattr(block, "terminator", None)
            if term is not None:
                print(dict(getattr(term, "numeric_evidence", {}) or {}))

    print("\n[EVIDENCE EVENTS]")
    for event in list(getattr(pal, "numeric_evidence_events", []) or []):
        print(event)

    print("\n===== END PAL NUMERIC EVIDENCE =====\n")


def debug_dump_indirect_custody(pal, include_contracts=False):
    """Print the compact v22 INDIRECT owner/storage inventory.

    Full contracts are optional because production functions can contain many
    custody markers. Owner groups and warnings are always shown.
    """

    print("\n===== PAL INDIRECT CUSTODY v22 =====\n")
    print("[INVENTORY]")
    print(dict(getattr(pal, "indirect_custody_inventory", {}) or {}))

    print("\n[EFFECT OWNER GROUPS]")
    groups = dict(getattr(pal, "indirect_effect_owner_groups", {}) or {})

    def owner_sort(item):
        group = item[1] or {}
        ref_id = group.get("owner_ref_id")
        return (ref_id is None, ref_id if isinstance(ref_id, int) else 0, item[0])

    for _, group in sorted(groups.items(), key=owner_sort):
        print({
            "owner_ref_hex": group.get("owner_ref_hex"),
            "owner_resolved": group.get("owner_resolved"),
            "owner_opcode": group.get("owner_opcode"),
            "owner_category": group.get("owner_category"),
            "owner_op_id": group.get("owner_op_id"),
            "owner_block_addr": group.get("owner_block_addr"),
            "contracts": group.get("contracts"),
            "output_sids": list(group.get("output_sids", []) or []),
        })

    print("\n[WARNINGS]")
    warnings = list(getattr(pal, "indirect_custody_warnings", []) or [])
    print(warnings)

    if include_contracts:
        print("\n[CONTRACTS]")
        for contract in list(getattr(pal, "indirect_custody_contracts", []) or []):
            print(contract)

    print("\n===== END PAL INDIRECT CUSTODY =====\n")


def debug_dump_abi_contracts(pal, include_calls=True, include_details=False):
    """Pretty-print ABI-A function-entry and ABI-B call-site evidence."""

    from pprint import pprint

    print("\n===== PAL FUNCTION/CALL ABI CUSTODY v23b =====\n")
    print("[INVENTORY]")
    pprint(dict(getattr(pal, "abi_inventory", {}) or {}), sort_dicts=False)

    function = dict(getattr(pal, "function_abi_contract", {}) or {})
    print("\n[FUNCTION ENTRY]")
    if include_details:
        pprint(function, sort_dicts=False)
    else:
        pprint({
            "function": function.get("function"),
            "entry": function.get("entry"),
            "calling_convention": function.get("calling_convention"),
            "abi_backend": function.get("abi_backend"),
            "prototype_authority": function.get("prototype_authority"),
            "variadic": function.get("variadic"),
            "declared_variadic": function.get("declared_variadic"),
            "machine_variadic_evidence": function.get(
                "machine_variadic_evidence"
            ),
            "effective_variadic": function.get("effective_variadic"),
            "no_return": function.get("no_return"),
            "logical_parameter_count": function.get("logical_parameter_count"),
            "observed_listing_parameter_count": function.get(
                "observed_listing_parameter_count"
            ),
            "high_function_input_parameter_count": function.get(
                "high_function_input_parameter_count"
            ),
            "implicit_input_count": function.get("implicit_input_count"),
            "unbound_high_function_input_parameter_count": function.get(
                "unbound_high_function_input_parameter_count"
            ),
            "legacy_parameter_order_policy": function.get(
                "legacy_parameter_order_policy"
            ),
            "future_parameter_order_policy": function.get(
                "future_parameter_order_policy"
            ),
        }, sort_dicts=False)

        print("\n[LOGICAL PARAMETERS]")
        for parameter in list(function.get("logical_parameters", []) or []):
            pprint({
                "ordinal": parameter.get("ordinal"),
                "name": parameter.get("name"),
                "datatype": parameter.get("datatype"),
                "storage": parameter.get("storage_image"),
            }, sort_dicts=False)

        print("\n[HIGHFUNCTION INPUT CARRIERS]")
        for carrier in list(
            function.get("high_function_input_parameters", []) or []
        ):
            pprint({
                "sid": carrier.get("sid"),
                "legacy_emitted_name": carrier.get("legacy_emitted_name"),
                "high_name": carrier.get("high_name"),
                "high_ordinal": carrier.get("high_ordinal"),
                "legacy_lexical_index": carrier.get("legacy_lexical_index"),
                "register": carrier.get("register"),
                "storage_key": carrier.get("storage_key"),
                "datatype_class": carrier.get("datatype_class"),
                "argument_class": carrier.get("argument_class"),
                "carrier_bank": carrier.get("carrier_bank"),
                "carrier_class": carrier.get("carrier_class"),
                "carrier_index": carrier.get("carrier_index"),
            }, sort_dicts=False)

        print("\n[PHYSICAL CARRIER BANKS]")
        pprint(
            dict(function.get("physical_carrier_banks", {}) or {}),
            sort_dicts=False,
        )

        print("\n[VARIADIC ENTRY PROTOCOL]")
        pprint(
            dict(function.get("variadic_protocol", {}) or {}),
            sort_dicts=False,
        )

        print("\n[IMPLICIT INPUTS]")
        pprint(
            list(function.get("implicit_inputs", []) or []),
            sort_dicts=False,
        )

        print("\n[LOGICAL/PHYSICAL BINDINGS]")
        pprint(
            list(function.get("logical_to_physical_bindings", []) or []),
            sort_dicts=False,
        )

    if include_calls:
        print("\n[CALL SITES]")
        for contract in list(
            getattr(pal, "call_site_abi_contracts", []) or []
        ):
            if include_details:
                pprint(contract, sort_dicts=False)
                print("-" * 72)
                continue
            allocation = dict(contract.get("carrier_allocation") or {})
            pprint({
                "op_id": contract.get("op_id"),
                "block_addr": contract.get("block_addr"),
                "opcode": contract.get("opcode"),
                "target": contract.get("target_name"),
                "target_entry": contract.get("target_entry"),
                "target_resolved": contract.get("target_resolved"),
                "target_prototype_authority": contract.get(
                    "target_prototype_authority"
                ),
                "target_variadic": contract.get("target_variadic"),
                "target_fixed_parameter_count": contract.get(
                    "target_fixed_parameter_count"
                ),
                "logical_argument_count": contract.get(
                    "logical_argument_count"
                ),
                "variadic_argument_count": contract.get(
                    "variadic_argument_count"
                ),
                "arity_status": contract.get("arity_status"),
                "arity_authority": contract.get("arity_authority"),
                "abi_backend": contract.get("abi_backend"),
                "gp_registers_used": allocation.get("gp_registers_used"),
                "xmm_registers_used": allocation.get("xmm_registers_used"),
                "stack_slots_used": allocation.get("stack_slots_used"),
                "variadic_al_value": allocation.get("variadic_al_value"),
            }, sort_dicts=False)

    print("\n[UNRESOLVED OBSERVATIONS]")
    pprint(list(getattr(pal, "abi_observations", []) or []), sort_dicts=False)

    print("\n[PROVEN WARNINGS]")
    pprint(list(getattr(pal, "abi_warnings", []) or []), sort_dicts=False)
    print("\n===== END PAL FUNCTION/CALL ABI CUSTODY v23b =====\n")
