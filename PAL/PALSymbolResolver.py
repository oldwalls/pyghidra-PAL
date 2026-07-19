# ======================================
# PALSymbolResolver.py
# v24 ABI-C logical/callable/physical/implicit namespace separation
#
# Purpose:
#   - keep naming/role metadata compatible with PAL CFG/SGL/PHI/emitter
#   - avoid stale None var_type/name values for unique/register temps
#   - prevent CALL targets from remaining misnamed as globals
#   - attach storage/address metadata for future PALplug peek/poke execution
#   - bind Ghidra/PAL incoming parameters into the variable logic machine
#   - expose SSA parameter-copy aliases without forcing prologue assignments
#   - normalize raw lifter datatype images into stable width/domain/view records
#   - preserve same-width COPY/CAST reinterpretations as numeric flow evidence
#   - normalize Ghidra INDIRECT custody into stable storage-family contracts
#   - stop address-taken C storage from becoming a free parameter SSA alias
#   - separate logical parameters from ABI carriers and implicit machine inputs
#   - preserve the legacy physical parameter list as evidence, not signature truth
# ======================================

import hashlib
import keyword
import re


class PALSymbolResolver:

    # Stable cognitive vocabulary. SSA numeric identity selects words directly;
    # Python's randomized hash() is never used. Two-word combinations cover
    # 4096 identities before a deterministic numeric tier is required.
    HUMAN_ALIAS_WORDS = (
        "amber", "anchor", "apple", "arch", "beach", "birch", "bird", "brook",
        "cabin", "canyon", "cedar", "cliff", "cloud", "coral", "crane", "creek",
        "dawn", "delta", "dune", "ember", "fern", "field", "finch", "forest",
        "garden", "glade", "harbor", "hazel", "hill", "island", "ivy", "jade",
        "lake", "lantern", "leaf", "lily", "maple", "meadow", "moon", "moss",
        "oak", "oasis", "ocean", "olive", "orchid", "otter", "pearl", "pine",
        "pond", "quartz", "rain", "reed", "ridge", "river", "rose", "sail",
        "shore", "sky", "stone", "sun", "tide", "trail", "willow", "wind",
    )

    def __init__(self, pal_function, program=None):

        self.func = pal_function
        self.program = program

        vars_in = getattr(pal_function, "vars", [])

        # Normalize container to dictionary.
        if isinstance(vars_in, dict):
            self.vars = vars_in
        else:
            self.vars = {
                getattr(v, "ssa_id", None): v
                for v in vars_in
                if getattr(v, "ssa_id", None)
            }

        self.parameters = list(getattr(pal_function, "parameters", []) or [])

        self._function_cache = {}
        self._symbol_cache = {}

        # v19 parameter-intake metadata.  These are populated during resolve()
        # and deliberately kept separate from CFG/SGL/PHI logic.
        self._parameter_records = []
        self._parameter_by_sid = {}
        self._parameter_by_storage_exact = {}
        self._parameter_by_storage_loose = {}
        self._parameter_binding_events = []
        self._parameter_alias_events = []
        self._parameter_conflicts = []

        # ABI-C resolver namespace state.  PALlibrary v23b owns raw ABI
        # recovery; this layer decides which recovered identities are logical
        # Python arguments, which are physical carriers, and which are implicit
        # machine state.  `self.parameters` remains untouched as the legacy
        # compatibility/audit surface.
        self._abi_lifter_contract = dict(
            getattr(pal_function, "function_abi_contract", {}) or {}
        )
        self._abi_active = bool(self._abi_lifter_contract)
        self._abi_non_callable_physical_sids = set()
        self._abi_logical_parameter_contracts = []
        self._abi_callable_parameter_order = []
        self._abi_callable_parameter_objects = []
        self._abi_physical_carrier_bindings = {}
        self._abi_implicit_inputs = {}
        self._abi_variadic_contract = {}
        self._abi_alias_contracts_by_sid = {}
        self._abi_namespace_warnings = []
        self._abi_namespace_inventory = {}
        self._abi_namespace_collisions = []
        self._abi_unowned_physical_sids = []
        self._abi_unresolved_owner_sids = []
        self._abi_legacy_signature_snapshot = []

        # v21 resolver-owned numeric metadata.  This remains separate from
        # naming, CFG, SGL and PHI state: PALCompute may consume it later, while
        # alpha-nine structural users can ignore it completely.
        self._numeric_normalization_events = []
        self._numeric_type_flow_events = []
        self._numeric_conflicts = []
        self._numeric_contracts_by_sid = {}
        self._numeric_type_flows_by_output_sid = {}
        self._human_alias_contracts_by_sid = {}

        # v22c resolver-owned INDIRECT metadata.  PALlibrary supplies the
        # HighFunction/getOpRef evidence; this layer gives every successive SSA
        # image of the same HighVariable a stable storage-family identity.  No
        # PALVariable object or formula edge is merged or rewritten here.
        self._indirect_storage_families_by_key = {}
        self._indirect_storage_family_by_sid = {}
        self._indirect_custody_transitions = []
        self._indirect_custody_by_output_sid = {}
        self._indirect_effect_owner_chains_by_family = {}
        self._indirect_parameter_initializers = []
        self._indirect_escape_barrier_sids = set()
        self._indirect_machine_state_sids = set()
        self._indirect_resolver_warnings = []
        self._indirect_resolver_inventory = {}

    # -------------------------------------------------
    # ITERATION / BASIC HELPERS
    # -------------------------------------------------

    def _iter_vars(self):
        return self.vars.values()

    def _iter_blocks(self):
        return list(getattr(self.func, "blocks", []) or [])

    def _sid(self, var):
        return getattr(var, "ssa_id", None)

    def _offset(self, var):
        return getattr(var, "offset", None)

    def _space(self, var):
        return getattr(var, "space", None)

    def _size(self, var):
        return getattr(var, "size", None) or 0

    def _set_default_bool_flags(self, var):
        for attr in (
            "is_constant", "is_parameter", "is_stack", "is_global",
            "is_temp", "is_function", "is_register", "is_unique",
            "is_address", "is_unknown_storage",
        ):
            if not hasattr(var, attr):
                setattr(var, attr, False)

    def _set_storage_metadata(self, var):
        space = self._space(var)
        off = self._offset(var)
        size = self._size(var)

        var.storage_space = space
        var.storage_offset = off
        var.storage_size = size
        var.width_bytes = size
        var.width_bits = size * 8 if size else None
        var.storage_key = (space, off, size)

        if space == "stack":
            var.stack_offset = off
            var.ram_addr = None
            var.memory_kind = "stack"
        elif space == "ram":
            var.ram_addr = off
            var.memory_addr = off
            var.memory_kind = "ram"
        elif space == "const":
            var.memory_kind = "literal"
        elif space == "register":
            var.register_offset = off
            var.memory_kind = "register"
        elif space == "unique":
            var.unique_offset = off
            var.memory_kind = "unique"
        else:
            var.memory_kind = "unknown"

    def _const_signed_value(self, value, size):
        if value is None or not size:
            return value

        bits = int(size) * 8
        mask = (1 << bits) - 1
        value = int(value) & mask
        sign = 1 << (bits - 1)

        if value & sign:
            return value - (1 << bits)

        return value

    def _address_for_offset(self, off):
        if not self.program or off is None:
            return None

        try:
            af = self.program.getAddressFactory()
            default_space = af.getDefaultAddressSpace()
            return default_space.getAddress(int(off))
        except Exception:
            return None

    def _function_at(self, off):
        if off is None:
            return None

        if off in self._function_cache:
            return self._function_cache[off]

        func = None

        try:
            addr = self._address_for_offset(off)
            if addr is not None:
                fm = self.program.getFunctionManager()
                func = fm.getFunctionAt(addr)
        except Exception:
            func = None

        self._function_cache[off] = func
        return func

    def _symbol_name_at(self, off):
        if off is None:
            return None

        if off in self._symbol_cache:
            return self._symbol_cache[off]

        name = None

        try:
            addr = self._address_for_offset(off)
            if addr is not None:
                sym = self.program.getSymbolTable().getPrimarySymbol(addr)
                if sym is not None:
                    name = sym.getName()
        except Exception:
            name = None

        self._symbol_cache[off] = name
        return name

    def _name_for_function(self, off):
        func = self._function_at(off)
        if func is not None:
            try:
                return getattr(func, "name", None) or func.getName()
            except Exception:
                pass

        sym = self._symbol_name_at(off)
        if sym:
            return sym

        if off is not None:
            return "sub_%x" % int(off)

        return "sub_unknown"

    def _name_for_global(self, off):
        sym = self._symbol_name_at(off)
        if sym:
            return sym

        if off is not None:
            return "g_%x" % int(off)

        return "g_unknown"

    def _is_auto_global_name(self, name):
        return isinstance(name, str) and (name.startswith("g_") or name == "g_unknown")

    # -------------------------------------------------
    # PUBLIC ENTRY
    # -------------------------------------------------

    def resolve(self):

        self._normalize_vars()
        self._normalize_numeric_metadata()
        self._prepare_abi_namespace_intake()
        self._tag_parameters()
        self._bind_parameter_backing_vars()
        self._resolve_abi_namespaces()
        self._tag_constants()
        self._tag_memory_vars()
        self._tag_call_targets()
        self._normalize_indirect_storage_families()
        self._discover_parameter_copy_aliases()
        self._finalize_indirect_storage_families()
        self._discover_numeric_type_flows()
        self._tag_unclassified_temps()
        self._detect_induction_variables()
        self._generate_human_alias_contracts()
        self._publish_metadata()

        return self.vars

    # -------------------------------------------------
    # NORMALIZATION
    # -------------------------------------------------

    def _normalize_vars(self):

        for var in self._iter_vars():
            self._set_default_bool_flags(var)
            self._set_storage_metadata(var)

            if not hasattr(var, "symbol_kind"):
                var.symbol_kind = None

            if not hasattr(var, "semantic_role"):
                var.semantic_role = None

    # -------------------------------------------------
    # NUMERIC TYPE / VIEW NORMALIZATION
    # -------------------------------------------------

    def _clean_type_name(self, value):
        if value is None:
            return None

        try:
            text = str(value).strip().lower()
        except Exception:
            return None

        if not text:
            return None

        return " ".join(text.replace("\t", " ").split())

    def _declared_type_image(self, var):
        image = getattr(var, "declared_type", None)
        if isinstance(image, dict):
            return dict(image)
        return {}

    def _normalized_domain_for_var(self, var, image, type_name):
        hint = self._clean_type_name(image.get("kind_hint"))
        existing = self._clean_type_name(getattr(var, "declared_domain", None))
        class_name = self._clean_type_name(image.get("class_name")) or ""
        name = type_name or ""

        # Explicit pointer/array syntax wins before integer aliases such as
        # byte/char are considered.
        if (
            hint == "pointer"
            or "pointer" in class_name
            or "*" in name
        ):
            return "pointer"

        if hint == "array" or "array" in class_name or name.endswith("[]"):
            return "array"

        if hint == "boolean" or "bool" in class_name or name in ("bool", "boolean"):
            return "boolean"

        if (
            hint == "float"
            or "float" in class_name
            or name in ("float", "double", "long double", "float4", "float8", "float10")
        ):
            return "float"

        if hint == "aggregate" or any(token in class_name for token in ("struct", "union", "enum")):
            return "aggregate"

        # Ghidra's undefined/DefaultDataType images are storage evidence only;
        # they do not prove an integer interpretation or signedness.
        if (
            name.startswith("undefined")
            or name in ("unknown", "void")
            or "defaultdatatype" in class_name
        ):
            return "unknown"

        if hint == "integer" or "integerdatatype" in class_name:
            return "integer"

        integer_names = {
            "byte", "char", "signed char", "unsigned char", "uchar",
            "short", "short int", "signed short", "signed short int",
            "unsigned short", "unsigned short int", "ushort",
            "int", "signed", "signed int", "unsigned", "unsigned int", "uint",
            "long", "long int", "signed long", "signed long int",
            "unsigned long", "unsigned long int", "ulong",
            "long long", "long long int", "signed long long",
            "unsigned long long", "unsigned long long int", "ulonglong",
            "int8_t", "uint8_t", "int16_t", "uint16_t",
            "int32_t", "uint32_t", "int64_t", "uint64_t",
            "size_t", "ssize_t", "intptr_t", "uintptr_t",
        }
        if name in integer_names:
            return "integer"

        if existing in ("integer", "pointer", "array", "boolean", "float", "aggregate"):
            return existing

        return "unknown"

    def _normalized_signedness_for_var(self, var, image, type_name, domain):
        if domain != "integer":
            return None

        existing = self._clean_type_name(getattr(var, "declared_signedness", None))
        if existing in ("signed", "unsigned"):
            return existing

        image_signed = image.get("signed")
        if isinstance(image_signed, bool):
            return "signed" if image_signed else "unsigned"

        name = type_name or ""
        unsigned_names = {
            "byte", "unsigned char", "uchar", "unsigned short",
            "unsigned short int", "ushort", "unsigned", "unsigned int",
            "uint", "unsigned long", "unsigned long int", "ulong",
            "unsigned long long", "unsigned long long int", "ulonglong",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t",
            "size_t", "uintptr_t",
        }
        signed_names = {
            "signed char", "short", "short int", "signed short",
            "signed short int", "int", "signed", "signed int", "long",
            "long int", "signed long", "signed long int", "long long",
            "long long int", "signed long long", "int8_t", "int16_t",
            "int32_t", "int64_t", "ssize_t", "intptr_t",
        }

        if name in unsigned_names:
            return "unsigned"
        if name in signed_names:
            return "signed"

        # Plain C char is target/compiler dependent.  Keep it unknown unless
        # Ghidra supplied explicit signedness above.
        return None

    def _canonical_numeric_type(self, domain, signedness, width_bits):
        width = int(width_bits) if isinstance(width_bits, int) and width_bits > 0 else None

        if domain == "integer":
            if signedness == "signed" and width:
                return "s%d" % width
            if signedness == "unsigned" and width:
                return "u%d" % width
            return "int%d" % width if width else "integer"

        if domain == "pointer":
            return "ptr%d" % width if width else "pointer"
        if domain == "boolean":
            return "bool%d" % width if width else "boolean"
        if domain == "float":
            return "f%d" % width if width else "float"
        if domain == "array":
            return "array"
        if domain == "aggregate":
            return "aggregate"

        return "bits%d" % width if width else "unknown"

    def _numeric_view_for_var(self, var):
        if var is None:
            return {
                "sid": None,
                "width_bits": None,
                "domain": "unknown",
                "signedness": None,
                "canonical_type": "unknown",
                "declared_type": None,
            }

        contract = getattr(var, "numeric_contract", None)
        if isinstance(contract, dict):
            return {
                "sid": self._sid(var),
                "width_bits": contract.get("storage_width_bits"),
                "domain": contract.get("domain"),
                "signedness": contract.get("default_signedness"),
                "canonical_type": contract.get("canonical_type"),
                "declared_type": contract.get("declared_type_name"),
            }

        width = getattr(var, "width_bits", None)
        if width is None:
            size = self._size(var)
            width = size * 8 if size else None

        return {
            "sid": self._sid(var),
            "width_bits": width,
            "domain": "unknown",
            "signedness": None,
            "canonical_type": self._canonical_numeric_type("unknown", None, width),
            "declared_type": getattr(var, "declared_type_name", None),
        }

    def _normalize_numeric_metadata(self):
        """Normalize lifter facts without choosing execution semantics.

        A PAL variable is a fixed-width storage identity.  Its normalized
        signedness is only a default declared view; CAST/COPY and consuming
        opcodes may establish different use-site views later.
        """

        self._numeric_normalization_events = []
        self._numeric_type_flow_events = []
        self._numeric_conflicts = []
        self._numeric_contracts_by_sid = {}
        self._numeric_type_flows_by_output_sid = {}

        domain_counts = {}
        signedness_counts = {}

        for var in self._iter_vars():
            image = self._declared_type_image(var)
            # Resolver runs are idempotent: per-variable flow indexes describe
            # the current graph once, not the history of repeated pipeline runs.
            var.numeric_outgoing_type_flows = []
            var.numeric_incoming_type_flows = []
            type_name = self._clean_type_name(
                getattr(var, "declared_type_name", None)
                or image.get("display_name")
                or image.get("name")
            )

            width = getattr(var, "width_bits", None)
            if not isinstance(width, int) or width <= 0:
                size = self._size(var)
                width = size * 8 if size else None

            type_width = image.get("width_bits")
            if (
                isinstance(width, int)
                and isinstance(type_width, int)
                and width > 0
                and type_width > 0
                and width != type_width
            ):
                self._numeric_conflicts.append({
                    "kind": "resolver_storage_declared_width_mismatch_v21",
                    "sid": self._sid(var),
                    "storage_width_bits": width,
                    "declared_width_bits": type_width,
                    "declared_type": type_name,
                })

            domain = self._normalized_domain_for_var(var, image, type_name)
            signedness = self._normalized_signedness_for_var(var, image, type_name, domain)
            canonical = self._canonical_numeric_type(domain, signedness, width)

            contract = {
                "kind": "resolver_variable_numeric_contract_v21",
                "sid": self._sid(var),
                "storage_space": self._space(var),
                "storage_width_bits": width,
                "declared_type_name": type_name,
                "declared_type_width_bits": type_width,
                "domain": domain,
                "default_signedness": signedness,
                "canonical_type": canonical,
                "use_site_override_required": True,
                "authoritative_execution_contract": False,
                "provenance": list(getattr(var, "type_provenance", []) or []),
            }

            if not getattr(var, "declared_domain", None) and domain != "unknown":
                var.declared_domain = domain
            if not getattr(var, "declared_signedness", None) and signedness is not None:
                var.declared_signedness = signedness

            provenance = getattr(var, "type_provenance", None)
            if not isinstance(provenance, list):
                provenance = []
                var.type_provenance = provenance
            if "resolver_numeric_normalization_v21" not in provenance:
                provenance.append("resolver_numeric_normalization_v21")
            contract["provenance"] = list(provenance)

            # Retain raw lifter evidence and expose the normalized image beside
            # it.  Missing legacy fields are enriched, never overwritten.
            numeric_evidence = getattr(var, "numeric_evidence", None)
            if not isinstance(numeric_evidence, dict):
                numeric_evidence = {}
                var.numeric_evidence = numeric_evidence
            numeric_evidence["resolver_normalization_v21"] = dict(contract)

            var.normalized_domain = domain
            var.normalized_signedness = signedness
            var.normalized_type_name = canonical
            var.numeric_contract = contract

            sid = self._sid(var)
            if sid is not None:
                self._numeric_contracts_by_sid[str(sid)] = contract

            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            key = signedness or "not_applicable_or_unknown"
            signedness_counts[key] = signedness_counts.get(key, 0) + 1

        self._numeric_normalization_events.append({
            "kind": "resolver_numeric_normalization_v21",
            "variables": len(list(self._iter_vars())),
            "contracts": len(self._numeric_contracts_by_sid),
            "domains": domain_counts,
            "signedness": signedness_counts,
            "conflicts": len(self._numeric_conflicts),
            "rule": "storage_identity_plus_default_declared_view",
        })

    # -------------------------------------------------
    # PARAMETERS
    # -------------------------------------------------

    def _abi_sid_text(self, value):
        if value is None:
            return None
        return str(value)

    def _abi_prototype_authority(self):
        return dict(
            (self._abi_lifter_contract or {}).get("prototype_authority") or {}
        )

    def _abi_prototype_is_authoritative(self):
        status = str(
            self._abi_prototype_authority().get("status") or ""
        ).lower()
        return status.startswith("authoritative")

    def _abi_effective_variadic(self):
        contract = self._abi_lifter_contract or {}
        protocol = dict(contract.get("variadic_protocol") or {})
        return bool(
            protocol.get("effective_variadic")
            or contract.get("effective_variadic")
            or contract.get("declared_variadic")
            or contract.get("machine_variadic_evidence")
        )

    def _prepare_abi_namespace_intake(self):
        """Classify physical inputs before legacy parameter tagging.

        PALlibrary v23b intentionally records every HighFunction input carrier,
        including register-save-area XMM live-ins.  The old resolver treated
        that physical list as a source-language signature.  ABI-C retains the
        list, but prevents proven implicit or unresolved variadic carriers from
        receiving ordinary parameter identity.
        """

        self._abi_lifter_contract = dict(
            getattr(self.func, "function_abi_contract", {}) or {}
        )
        self._abi_active = bool(self._abi_lifter_contract)
        self._abi_non_callable_physical_sids = set()

        if not self._abi_active:
            return

        contract = self._abi_lifter_contract
        physical = list(contract.get("high_function_input_parameters") or [])
        physical_sids = set(
            self._abi_sid_text(item.get("sid"))
            for item in physical
            if item.get("sid") is not None
        )
        implicit_sids = set(
            self._abi_sid_text(item.get("sid"))
            for item in list(contract.get("implicit_inputs") or [])
            if item.get("sid") is not None
        )
        bound_sids = set(
            self._abi_sid_text(sid)
            for binding in list(
                contract.get("logical_to_physical_bindings") or []
            )
            for sid in list(binding.get("physical_sids") or [])
            if sid is not None
        )

        # Explicit implicit state is never a Python argument.  When prototype
        # authority exists, unbound HighFunction carriers are also physical
        # evidence only.  For a machine-evidenced variadic prologue with
        # unresolved fixed arity, *all* carriers remain in deferred ABI custody
        # until a later entry-protocol analysis proves the logical signature.
        excluded = set(implicit_sids)
        if self._abi_prototype_is_authoritative():
            excluded.update(physical_sids - bound_sids)
        elif self._abi_effective_variadic():
            excluded.update(physical_sids)

        self._abi_non_callable_physical_sids = excluded

    def _tag_abi_non_callable_carrier(self, var, record, reason):
        """Tag a legacy parameter-list member as physical evidence only."""

        self._set_default_bool_flags(var)
        self._set_storage_metadata(var)

        var.is_parameter = False
        var.is_callable_parameter = False
        var.is_abi_physical_carrier = True
        var.is_temp = False
        var.var_type = "abi_carrier"
        var.semantic_role = "abi_physical_carrier"
        var.symbol_kind = "ABI_CARRIER"
        var.abi_namespace = "physical_abi_carrier"
        var.abi_exclusion_reason = reason
        var.legacy_parameter_index = record.get("index")
        var.legacy_parameter_name = record.get("name")
        var.legacy_parameter_storage_key = record.get("storage_key")

        if self._space(var) == "register":
            var.is_register = True
            var.storage_role = "abi_register_carrier"
        elif self._space(var) == "stack":
            var.is_stack = True
            var.storage_role = "abi_stack_carrier"

        # Crucially, var.name is not changed here.  Old ASCII/debug projections
        # can still display the legacy name while ABI-C consumers use the
        # callable/implicit sidecars below.

    def _abi_safe_identifier(self, value, fallback="abi_value"):
        text = str(value or "").strip()
        text = re.sub(r"[^0-9A-Za-z_]", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        if not text:
            text = str(fallback)
        if text[0].isdigit():
            text = "_%s" % text
        if keyword.iskeyword(text):
            text = "%s_" % text
        return text

    def _abi_allocate_identifier(self, preferred, used, sid=None, namespace=None):
        base = self._abi_safe_identifier(preferred)
        candidate = base
        if candidate in used:
            sid_suffix = self._abi_safe_identifier(sid or "value")
            candidate = "%s_%s" % (base, sid_suffix)
            counter = 2
            while candidate in used:
                candidate = "%s_%s_%d" % (base, sid_suffix, counter)
                counter += 1
            self._abi_namespace_collisions.append({
                "kind": "resolver_abi_name_collision_resolved_v24",
                "namespace": namespace,
                "requested_name": base,
                "allocated_name": candidate,
                "sid": self._abi_sid_text(sid),
            })
        used.add(candidate)
        return candidate

    def _abi_implicit_custody_class(self, role):
        role = str(role or "machine_live_in")
        if role in ("stack_pointer", "frame_pointer"):
            return "frame_state"
        if role == "thread_local_storage_base":
            return "tls_state"
        if role == "variadic_xmm_register_count":
            return "variadic_protocol_state"
        if role == "vector_argument_register_live_in":
            return "variadic_register_state"
        if role == "condition_flags":
            return "condition_state"
        return "machine_state"

    def _abi_implicit_alias_base(self, item, physical_by_sid):
        role = str(item.get("role") or "machine_live_in")
        sid = self._abi_sid_text(item.get("sid"))
        physical = dict(physical_by_sid.get(sid) or {})
        register = dict(item.get("register") or {})
        register_name = str(
            register.get("name")
            or (physical.get("carrier") or {}).get("register_name")
            or physical.get("register")
            or ""
        ).lower()

        if role == "variadic_xmm_register_count":
            return "abi_xmm_count"
        if role == "stack_pointer":
            return "abi_stack_pointer"
        if role == "frame_pointer":
            return "abi_frame_pointer"
        if role == "thread_local_storage_base":
            return "abi_tls_base"
        if role == "condition_flags":
            return "abi_condition_flags"
        if role == "vector_argument_register_live_in":
            index = physical.get("carrier_index")
            if index is None:
                match = re.search(r"(?:xmm|ymm|zmm)(\d+)", register_name)
                index = int(match.group(1)) if match else None
            if index is not None:
                return "abi_xmm%d" % int(index)
        if register_name:
            return "abi_%s" % self._abi_safe_identifier(register_name)
        return "abi_machine_%s" % self._abi_safe_identifier(sid or "input")

    def _parameter_name_for_index(self, idx, var=None):
        """Return the user-visible incoming parameter name.

        Prefer a Ghidra/PAL-provided name.  If none exists, use one-based
        names because these are function arguments, not zero-indexed array
        slots in the analyst view.
        """

        if var is not None:
            for attr in ("name", "symbol", "high_name", "display_name"):
                name = getattr(var, attr, None)
                if name:
                    return str(name)

        return "param_%d" % (idx + 1)

    def _storage_key_exact(self, var):
        return (self._space(var), self._offset(var), self._size(var))

    def _storage_key_loose(self, var):
        return (self._space(var), self._offset(var))

    def _register_parameter_record(self, idx, var):
        name = self._parameter_name_for_index(idx, var)

        # Normalize nameless parameter objects before any signature/emitter stage
        # sees them.  Existing Ghidra names are preserved.
        if not getattr(var, "name", None):
            var.name = name

        record = {
            "index": idx,
            "name": name,
            "sid": self._sid(var),
            "space": self._space(var),
            "offset": self._offset(var),
            "size": self._size(var),
            "storage_key": self._storage_key_exact(var),
            "storage_key_loose": self._storage_key_loose(var),
            "object": var,
        }

        self._parameter_records.append(record)

        sid = record["sid"]
        if sid is not None:
            self._parameter_by_sid[str(sid)] = record

        skey = record["storage_key"]
        if skey[0] is not None and skey[1] is not None:
            self._parameter_by_storage_exact.setdefault(skey, []).append(record)

        lkey = record["storage_key_loose"]
        if lkey[0] is not None and lkey[1] is not None:
            self._parameter_by_storage_loose.setdefault(lkey, []).append(record)

        return record

    def _tag_parameter_var(self, var, record, binding_kind):
        """Bind a PAL variable object to an incoming function parameter.

        This is the missing bridge for non-main functions: the signature name
        must be the same symbolic identity that formula/body expressions use.
        We do not emit prologue copies here; we only attach identity metadata and
        rename the direct backing var to the parameter name.
        """

        self._set_default_bool_flags(var)
        self._set_storage_metadata(var)

        var.is_parameter = True
        var.is_temp = False
        var.is_global = False
        var.is_function = False
        var.var_type = "param"
        var.semantic_role = "function_parameter"
        var.symbol_kind = "PARAMETER"

        if self._space(var) == "stack":
            var.is_stack = True
            var.storage_role = "stack_parameter"
        elif self._space(var) == "register":
            var.is_register = True
            var.storage_role = "register_parameter"
        elif self._space(var) == "unique":
            var.is_unique = True
            var.storage_role = "unique_parameter"

        var.parameter_index = record["index"]
        var.parameter_name = record["name"]
        var.parameter_storage_key = record["storage_key"]
        var.parameter_binding_kind = binding_kind

        # Direct parameter backing variables should render as the argument name.
        # If Ghidra later emits an SSA COPY from this value, that copy remains a
        # separate v_####/local_#### alias and is recorded below.
        var.name = record["name"]

        event = {
            "sid": self._sid(var),
            "name": getattr(var, "name", None),
            "parameter": record["name"],
            "parameter_index": record["index"],
            "binding_kind": binding_kind,
            "storage_key": self._storage_key_exact(var),
        }
        self._parameter_binding_events.append(event)

    def _match_parameter_record_for_var(self, var):
        sid = self._sid(var)
        if sid is not None:
            rec = self._parameter_by_sid.get(str(sid))
            if rec is not None:
                return rec, "sid"

        # Object identity catches the case where pal_function.parameters contains
        # the exact same object as func.vars.
        for rec in self._parameter_records:
            if var is rec.get("object"):
                return rec, "object"

        # v20 conservative rule:
        # Register/unique storage is not a stable variable identity after entry.
        # Compilers freely reuse argument registers for loop indexes, address
        # calculations, and scratch values.  v19 matched by register storage and
        # could rename a later scratch temp as param_N.  Only stack parameter
        # slots are stable enough for storage-based body binding.
        space = self._space(var)
        if space not in ("stack",):
            skey_rejected = self._storage_key_exact(var)
            exact_rejected = self._parameter_by_storage_exact.get(skey_rejected) or []
            if exact_rejected:
                self._parameter_conflicts.append({
                    "kind": "non_stack_storage_match_rejected_v20",
                    "sid": sid,
                    "space": space,
                    "storage_key": skey_rejected,
                    "candidates": [r["name"] for r in exact_rejected],
                    "reason": "register/unique parameter storage is entry-only and may be reused",
                })
            return None, None

        skey = self._storage_key_exact(var)
        exact = self._parameter_by_storage_exact.get(skey) or []
        if len(exact) == 1:
            return exact[0], "stack_storage_exact"
        if len(exact) > 1:
            self._parameter_conflicts.append({
                "kind": "stack_storage_exact_ambiguous",
                "sid": sid,
                "storage_key": skey,
                "candidates": [r["name"] for r in exact],
            })
            return None, None

        # Loose match allows size=0/unknown mismatches, common in bridge objects,
        # but only for stack parameter slots.
        lkey = self._storage_key_loose(var)
        loose = self._parameter_by_storage_loose.get(lkey) or []
        if len(loose) == 1:
            return loose[0], "stack_storage_loose"
        if len(loose) > 1:
            self._parameter_conflicts.append({
                "kind": "stack_storage_loose_ambiguous",
                "sid": sid,
                "storage_key_loose": lkey,
                "candidates": [r["name"] for r in loose],
            })

        return None, None

    def _tag_parameters(self):

        self._parameter_records = []
        self._parameter_by_sid = {}
        self._parameter_by_storage_exact = {}
        self._parameter_by_storage_loose = {}
        self._parameter_binding_events = []
        self._parameter_alias_events = []
        self._parameter_conflicts = []

        for idx, var in enumerate(self.parameters):

            self._set_default_bool_flags(var)
            self._set_storage_metadata(var)

            record = self._register_parameter_record(idx, var)
            sid = self._abi_sid_text(record.get("sid"))
            if sid in self._abi_non_callable_physical_sids:
                self._tag_abi_non_callable_carrier(
                    var, record, "ABI_C_non_callable_physical_input"
                )
            else:
                self._tag_parameter_var(var, record, "declared_parameter")

        self._abi_legacy_signature_snapshot = [
            {
                "index": record.get("index"),
                "name": record.get("name"),
                "sid": self._abi_sid_text(record.get("sid")),
            }
            for record in self._parameter_records
        ]

    def _bind_parameter_backing_vars(self):
        """Bind body vars that represent incoming parameters.

        The old resolver only tagged pal_function.parameters.  If the formula
        graph used a distinct variable object with the same Ghidra storage, the
        function signature existed but the body still referenced anonymous
        locals/register temps.  This pass closes that bridge.
        """

        if not self._parameter_records:
            return

        for var in self._iter_vars():

            if getattr(var, "is_constant", False):
                continue

            if self._space(var) in ("const", "ram"):
                continue

            rec, kind = self._match_parameter_record_for_var(var)
            if rec is None:
                continue

            sid = self._abi_sid_text(self._sid(var))
            if sid in self._abi_non_callable_physical_sids:
                self._tag_abi_non_callable_carrier(
                    var, rec, "ABI_C_non_callable_backing_input"
                )
                continue

            # Avoid duplicate event spam for the exact parameter object already
            # tagged above, but still ensure metadata is normalized.
            already = (
                getattr(var, "is_parameter", False)
                and getattr(var, "parameter_name", None) == rec["name"]
            )
            self._tag_parameter_var(var, rec, kind)
            if already and self._parameter_binding_events:
                self._parameter_binding_events[-1]["already_tagged"] = True

    def _resolve_abi_namespaces(self):
        """Publish logical, physical-carrier, and implicit-input identities.

        This pass is deliberately sidecar-first.  It does not replace
        `PALFunction.parameters`, because older emitters still inspect that
        physical list.  ABI-C consumers must use `callable_parameter_order` (or
        `callable_parameters`) and may inspect `legacy_physical_parameters` for
        audit/debug only.
        """

        self._abi_logical_parameter_contracts = []
        self._abi_callable_parameter_order = []
        self._abi_callable_parameter_objects = []
        self._abi_physical_carrier_bindings = {}
        self._abi_implicit_inputs = {}
        self._abi_variadic_contract = {}
        self._abi_alias_contracts_by_sid = {}
        self._abi_namespace_warnings = []
        self._abi_namespace_inventory = {}
        self._abi_namespace_collisions = []
        self._abi_unowned_physical_sids = []
        self._abi_unresolved_owner_sids = []

        contract = dict(
            getattr(self.func, "function_abi_contract", {})
            or self._abi_lifter_contract
            or {}
        )
        self._abi_lifter_contract = contract
        self._abi_active = bool(contract)

        physical = list(contract.get("high_function_input_parameters") or [])
        physical_by_sid = {
            self._abi_sid_text(item.get("sid")): dict(item)
            for item in physical
            if item.get("sid") is not None
        }
        legacy_by_sid = {
            self._abi_sid_text(record.get("sid")): record
            for record in self._parameter_records
            if record.get("sid") is not None
        }

        bindings = list(contract.get("logical_to_physical_bindings") or [])
        bindings_by_ordinal = {}
        bindings_by_name = {}
        for binding in bindings:
            ordinal = binding.get("logical_ordinal")
            if ordinal is not None:
                bindings_by_ordinal[ordinal] = dict(binding)
            name = binding.get("logical_name")
            if name:
                bindings_by_name[str(name)] = dict(binding)

        raw_logical = list(contract.get("logical_parameters") or [])
        raw_logical.sort(key=lambda item: (
            item.get("ordinal") is None,
            item.get("ordinal") if isinstance(item.get("ordinal"), int) else 0,
            str(item.get("name") or ""),
        ))

        for fallback_ordinal, item in enumerate(raw_logical):
            ordinal = item.get("ordinal")
            if ordinal is None:
                ordinal = fallback_ordinal
            logical_name = item.get("name") or "param_%d" % fallback_ordinal
            binding = dict(
                bindings_by_ordinal.get(ordinal)
                or bindings_by_name.get(str(logical_name))
                or {}
            )
            physical_sids = [
                self._abi_sid_text(sid)
                for sid in list(binding.get("physical_sids") or [])
                if sid is not None
            ]
            source_sid = physical_sids[0] if len(physical_sids) == 1 else None
            legacy = legacy_by_sid.get(source_sid) if source_sid else None
            preferred_name = (
                legacy.get("name") if legacy is not None else logical_name
            )
            self._abi_logical_parameter_contracts.append({
                "kind": "resolver_logical_parameter_contract_abi_c",
                "version": "v24_logical_physical_implicit_namespaces",
                "logical_ordinal": ordinal,
                "logical_name": str(logical_name),
                "preferred_callable_name": str(preferred_name),
                "callable_name": None,
                "physical_sids": physical_sids,
                "source_sid": source_sid,
                "binding_status": binding.get("binding_status") or (
                    "exact_storage_match" if len(physical_sids) == 1
                    else "multi_carrier_binding" if len(physical_sids) > 1
                    else "unresolved_storage_match"
                ),
                "storage_keys": list(binding.get("storage_keys") or []),
                "datatype": item.get("datatype"),
                "datatype_class": item.get("datatype_class"),
                "source_contract": dict(item),
                "identity_namespace": "logical_parameter",
                "authority": "authoritative_function_prototype_ordinal",
            })

        authoritative = self._abi_prototype_is_authoritative()
        effective_variadic = self._abi_effective_variadic()
        used_names = set()
        callable_records = []
        callable_status = None

        if authoritative:
            callable_status = "authoritative_logical_parameter_order"
            if not self._abi_logical_parameter_contracts:
                callable_status = "authoritative_zero_parameter_signature"
            for logical in self._abi_logical_parameter_contracts:
                callable_name = self._abi_allocate_identifier(
                    logical.get("preferred_callable_name"),
                    used_names,
                    logical.get("source_sid") or logical.get("logical_ordinal"),
                    "logical_parameter",
                )
                logical["callable_name"] = callable_name
                callable_records.append({
                    "kind": "resolver_callable_parameter_abi_c",
                    "version": "v24_logical_physical_implicit_namespaces",
                    "ordinal": len(callable_records),
                    "name": callable_name,
                    "identity_namespace": "logical_parameter",
                    "logical_ordinal": logical.get("logical_ordinal"),
                    "logical_name": logical.get("logical_name"),
                    "source_sid": logical.get("source_sid"),
                    "physical_sids": list(logical.get("physical_sids") or []),
                    "binding_status": logical.get("binding_status"),
                    "selection_source": "authoritative_logical_prototype",
                    "required_python_argument": True,
                    "physical_order_is_signature_authority": False,
                })
        elif effective_variadic:
            # A register-save prologue proves variadic machinery, not the fixed
            # source arity.  Fabricating six GP arguments would merely replace
            # one physical permutation bug with another.  Keep signature
            # generation explicitly deferred until a call/prototype layer can
            # prove the fixed logical parameters.
            callable_status = "deferred_unresolved_variadic_fixed_arity"
        else:
            callable_status = (
                "legacy_non_variadic_fallback"
                if self._abi_active else "legacy_no_abi_contract_fallback"
            )
            for record in self._parameter_records:
                sid = self._abi_sid_text(record.get("sid"))
                callable_name = self._abi_allocate_identifier(
                    record.get("name"), used_names, sid, "logical_parameter"
                )
                callable_records.append({
                    "kind": "resolver_callable_parameter_abi_c",
                    "version": "v24_logical_physical_implicit_namespaces",
                    "ordinal": len(callable_records),
                    "name": callable_name,
                    "identity_namespace": "logical_parameter",
                    "logical_ordinal": None,
                    "logical_name": None,
                    "source_sid": sid,
                    "physical_sids": [sid] if sid is not None else [],
                    "binding_status": "legacy_identity_binding",
                    "selection_source": callable_status,
                    "required_python_argument": True,
                    "physical_order_is_signature_authority": False,
                })

        self._abi_callable_parameter_order = callable_records

        # Reset/add the callable sidecar without disturbing legacy
        # `is_parameter` consumers.  Only the selected identity receives the
        # new authoritative flag.
        for var in self._iter_vars():
            var.is_callable_parameter = False
        for record in callable_records:
            sid = record.get("source_sid")
            var = self._var_for_sid(sid)
            if var is None:
                continue
            var.is_callable_parameter = True
            var.callable_parameter_index = record.get("ordinal")
            var.callable_parameter_name = record.get("name")
            var.abi_namespace = "logical_parameter"
            var.abi_owner_id = "logical:%s" % record.get("ordinal")
            self._abi_callable_parameter_objects.append(var)

        # Implicit aliases share the callable namespace's collision set, so an
        # unusual source parameter named `abi_tls_base` can never shadow TLS
        # custody in detached UI/debug projections.
        implicit_used_names = set(used_names)
        for item in list(contract.get("implicit_inputs") or []):
            sid = self._abi_sid_text(item.get("sid"))
            if sid is None:
                continue
            role = str(item.get("role") or "machine_live_in")
            alias = self._abi_allocate_identifier(
                self._abi_implicit_alias_base(item, physical_by_sid),
                implicit_used_names,
                sid,
                "implicit_machine_input",
            )
            custody_class = self._abi_implicit_custody_class(role)
            implicit = dict(item)
            implicit.update({
                "kind": "resolver_implicit_input_contract_abi_c",
                "version": "v24_logical_physical_implicit_namespaces",
                "sid": sid,
                "identity_namespace": "implicit_machine_input",
                "canonical_alias": alias,
                "custody_class": custody_class,
                "callable_argument": False,
                "owner_id": "implicit:%s" % sid,
                "authority": "PALlibrary_v23b_implicit_input_role",
            })
            self._abi_implicit_inputs[sid] = implicit
            alias_contract = {
                "kind": "resolver_abi_alias_contract_abi_c",
                "version": "v24_logical_physical_implicit_namespaces",
                "sid": sid,
                "canonical_alias": alias,
                "identity_namespace": "implicit_machine_input",
                "role": role,
                "custody_class": custody_class,
                "mutates_pal_name": False,
            }
            self._abi_alias_contracts_by_sid[sid] = alias_contract

            var = self._var_for_sid(sid)
            if var is not None:
                if getattr(var, "is_callable_parameter", False):
                    self._abi_namespace_warnings.append({
                        "kind": "resolver_abi_logical_implicit_overlap_v24",
                        "sid": sid,
                        "callable_name": getattr(
                            var, "callable_parameter_name", None
                        ),
                        "implicit_role": role,
                    })
                var.is_callable_parameter = False
                var.is_implicit_machine_input = True
                var.abi_namespace = "implicit_machine_input"
                var.abi_owner_id = implicit.get("owner_id")
                var.abi_implicit_role = role
                var.abi_custody_class = custody_class
                var.abi_canonical_alias = alias
                var.abi_alias_contract = alias_contract
                var.var_type = "abi_implicit"
                var.is_temp = False
                var.symbol_kind = "ABI_IMPLICIT_INPUT"
                var.semantic_role = custody_class
                if role in (
                    "stack_pointer", "frame_pointer",
                    "thread_local_storage_base",
                ):
                    var.var_type = "machine_state"

        callable_owner_by_sid = {}
        for record in callable_records:
            for sid in list(record.get("physical_sids") or []):
                if sid is not None:
                    callable_owner_by_sid[self._abi_sid_text(sid)] = record

        physical_alias_used = set(implicit_used_names)
        for item in physical:
            sid = self._abi_sid_text(item.get("sid"))
            if sid is None:
                continue
            bank = item.get("carrier_bank") or (
                (item.get("carrier") or {}).get("bank")
            ) or "unknown"
            index = item.get("carrier_index")
            if index is None:
                index = (item.get("carrier") or {}).get("index")
            register = (
                (item.get("carrier") or {}).get("register_name")
                or (item.get("register") or {}).get("name")
                or item.get("register")
            )

            implicit = self._abi_implicit_inputs.get(sid)
            logical_owner = callable_owner_by_sid.get(sid)
            legacy = legacy_by_sid.get(sid)
            if implicit is not None:
                owner = {
                    "namespace": "implicit_machine_input",
                    "owner_id": implicit.get("owner_id"),
                    "role": implicit.get("role"),
                    "resolved": True,
                    "authority": "explicit_implicit_input_contract",
                }
                carrier_alias = implicit.get("canonical_alias")
            elif logical_owner is not None:
                owner = {
                    "namespace": "logical_parameter",
                    "owner_id": "logical:%s" % logical_owner.get("ordinal"),
                    "role": "callable_parameter_carrier",
                    "resolved": True,
                    "authority": logical_owner.get("selection_source"),
                }
                carrier_alias = logical_owner.get("name")
            elif effective_variadic:
                role = (
                    "variadic_vector_register_state"
                    if bank == "sse" else
                    "variadic_entry_gp_carrier"
                    if bank == "gp" else
                    "variadic_entry_physical_carrier"
                )
                owner = {
                    "namespace": "variadic_protocol",
                    "owner_id": "variadic:%s:%s" % (bank, index),
                    "role": role,
                    "resolved": True,
                    "authority": "machine_variadic_entry_protocol",
                }
                carrier_alias = None
            elif legacy is not None and not authoritative:
                owner = {
                    "namespace": "logical_parameter",
                    "owner_id": "legacy_logical:%s" % legacy.get("index"),
                    "role": "legacy_callable_parameter_carrier",
                    "resolved": True,
                    "authority": "legacy_non_variadic_fallback",
                }
                carrier_alias = legacy.get("name")
            else:
                owner = {
                    "namespace": "physical_abi_carrier",
                    "owner_id": "physical:%s" % sid,
                    "role": "unresolved_physical_carrier_custody",
                    "resolved": False,
                    "authority": "physical_storage_only",
                }
                carrier_alias = None
                self._abi_unresolved_owner_sids.append(sid)

            if not carrier_alias:
                base = "abi_%s" % self._abi_safe_identifier(
                    register or "%s_%s" % (bank, index if index is not None else sid)
                ).lower()
                carrier_alias = self._abi_allocate_identifier(
                    base, physical_alias_used, sid, "physical_abi_carrier"
                )

            binding = {
                "kind": "resolver_physical_carrier_binding_abi_c",
                "version": "v24_logical_physical_implicit_namespaces",
                "sid": sid,
                "legacy_emitted_name": item.get("legacy_emitted_name"),
                "high_name": item.get("high_name"),
                "high_ordinal": item.get("high_ordinal"),
                "carrier_bank": bank,
                "carrier_class": item.get("carrier_class"),
                "carrier_index": index,
                "register": register,
                "storage_key": item.get("storage_key"),
                "canonical_alias": carrier_alias,
                "callable_argument": owner.get("namespace") == "logical_parameter",
                "owner": owner,
                "authority": "PALlibrary_v23b_physical_carrier_evidence",
            }
            self._abi_physical_carrier_bindings[sid] = binding
            if not owner:
                self._abi_unowned_physical_sids.append(sid)

            if sid not in self._abi_alias_contracts_by_sid:
                self._abi_alias_contracts_by_sid[sid] = {
                    "kind": "resolver_abi_alias_contract_abi_c",
                    "version": "v24_logical_physical_implicit_namespaces",
                    "sid": sid,
                    "canonical_alias": carrier_alias,
                    "identity_namespace": "physical_abi_carrier",
                    "role": owner.get("role"),
                    "custody_class": owner.get("namespace"),
                    "mutates_pal_name": False,
                }

            var = self._var_for_sid(sid)
            if var is not None:
                var.is_abi_physical_carrier = True
                var.abi_physical_carrier_binding = binding
                var.abi_physical_owner = owner
                if not getattr(var, "is_callable_parameter", False) and sid not in self._abi_implicit_inputs:
                    var.abi_namespace = owner.get("namespace")
                    var.abi_owner_id = owner.get("owner_id")
                    var.abi_canonical_alias = carrier_alias

        protocol = dict(contract.get("variadic_protocol") or {})
        gp_sids = [
            sid for sid, item in self._abi_physical_carrier_bindings.items()
            if item.get("carrier_bank") == "gp"
        ]
        sse_sids = [
            sid for sid, item in self._abi_physical_carrier_bindings.items()
            if item.get("carrier_bank") == "sse"
        ]
        xmm_count_sids = [
            sid for sid, item in self._abi_implicit_inputs.items()
            if item.get("role") == "variadic_xmm_register_count"
        ]
        vector_live_in_sids = [
            sid for sid, item in self._abi_implicit_inputs.items()
            if item.get("role") == "vector_argument_register_live_in"
        ]
        self._abi_variadic_contract = dict(protocol)
        self._abi_variadic_contract.update({
            "kind": "resolver_variadic_contract_abi_c",
            "version": "v24_logical_physical_implicit_namespaces",
            "declared_variadic": bool(
                protocol.get("declared_variadic")
                or contract.get("declared_variadic")
            ),
            "machine_variadic_evidence": bool(
                protocol.get("machine_variadic_evidence")
                or contract.get("machine_variadic_evidence")
            ),
            "effective_variadic": effective_variadic,
            "callable_signature_status": callable_status,
            "callable_fixed_parameter_count": (
                None if callable_status == "deferred_unresolved_variadic_fixed_arity"
                else len(callable_records)
            ),
            "python_interface_policy": (
                "defer_fixed_signature_require_explicit_abi_state"
                if callable_status == "deferred_unresolved_variadic_fixed_arity"
                else "logical_fixed_parameters_only"
            ),
            "gp_carrier_sids": gp_sids,
            "sse_carrier_sids": sse_sids,
            "xmm_count_input_sids": xmm_count_sids,
            "xmm_count_aliases": [
                self._abi_implicit_inputs[sid].get("canonical_alias")
                for sid in xmm_count_sids
            ],
            "vector_register_input_sids": vector_live_in_sids,
            "implicit_state_is_python_argument": False,
            "authority": "PALlibrary_v23b_protocol_plus_resolver_namespace_policy",
        })

        implicit_sids = set(self._abi_implicit_inputs)
        callable_physical_sids = set(
            sid
            for item in callable_records
            for sid in list(item.get("physical_sids") or [])
            if sid is not None
        )
        implicit_xmm_callable = sorted(
            (set(vector_live_in_sids) | set(xmm_count_sids))
            & callable_physical_sids,
            key=str,
        )
        legacy_names_before = [
            item.get("name") for item in self._abi_legacy_signature_snapshot
        ]
        legacy_names_after = [
            getattr(var, "name", None) for var in self.parameters
        ]
        callable_names = [item.get("name") for item in callable_records]
        final_callable_collisions = sorted({
            name for name in callable_names if callable_names.count(name) > 1
        }, key=str)
        legacy_storage_preserved = legacy_names_before == legacy_names_after
        non_variadic_callable_preserved = (
            True if effective_variadic
            else callable_names == legacy_names_before
        )

        if self._abi_unowned_physical_sids:
            self._abi_namespace_warnings.append({
                "kind": "resolver_abi_physical_inputs_without_owner_v24",
                "sids": list(self._abi_unowned_physical_sids),
            })
        if implicit_xmm_callable:
            self._abi_namespace_warnings.append({
                "kind": "resolver_abi_implicit_xmm_exposed_as_callable_v24",
                "sids": implicit_xmm_callable,
            })
        if final_callable_collisions:
            self._abi_namespace_warnings.append({
                "kind": "resolver_abi_callable_name_collision_v24",
                "names": final_callable_collisions,
            })
        if not legacy_storage_preserved:
            self._abi_namespace_warnings.append({
                "kind": "resolver_abi_legacy_parameter_surface_mutated_v24",
                "before": legacy_names_before,
                "after": legacy_names_after,
            })

        self._abi_namespace_inventory = {
            "kind": "resolver_abi_namespace_inventory_v24",
            "version": "v24_logical_physical_implicit_namespaces",
            "active": self._abi_active,
            "prototype_authority": self._abi_prototype_authority().get("status"),
            "logical_parameters": len(self._abi_logical_parameter_contracts),
            "legacy_parameter_records": len(self._parameter_records),
            "callable_parameters": len(callable_records),
            "callable_signature_status": callable_status,
            "physical_carriers": len(self._abi_physical_carrier_bindings),
            "physical_carriers_with_owner": sum(
                1 for item in self._abi_physical_carrier_bindings.values()
                if item.get("owner")
            ),
            "physical_inputs_without_owner": len(self._abi_unowned_physical_sids),
            "physical_inputs_with_unresolved_owner": len(
                self._abi_unresolved_owner_sids
            ),
            "implicit_inputs": len(self._abi_implicit_inputs),
            "frame_state_inputs": sum(
                1 for item in self._abi_implicit_inputs.values()
                if item.get("custody_class") == "frame_state"
            ),
            "tls_state_inputs": sum(
                1 for item in self._abi_implicit_inputs.values()
                if item.get("custody_class") == "tls_state"
            ),
            "variadic_protocol_inputs": sum(
                1 for item in self._abi_implicit_inputs.values()
                if item.get("custody_class") == "variadic_protocol_state"
            ),
            "implicit_xmm_required_python_arguments": len(implicit_xmm_callable),
            "final_callable_name_collisions": len(final_callable_collisions),
            "resolved_name_collisions": len(self._abi_namespace_collisions),
            "legacy_parameter_surface_preserved": legacy_storage_preserved,
            "non_variadic_callable_signature_preserved": non_variadic_callable_preserved,
            "warnings": len(self._abi_namespace_warnings),
            "acceptance_gates": {
                "implicit_xmm_not_callable": not implicit_xmm_callable,
                "every_physical_input_has_owner": not self._abi_unowned_physical_sids,
                "callable_names_unique": not final_callable_collisions,
                "legacy_parameter_surface_unchanged": legacy_storage_preserved,
                "non_variadic_callable_signature_unchanged": non_variadic_callable_preserved,
            },
            "rule": "logical_signature_separate_from_physical_and_implicit_ABI_custody",
        }

    # -------------------------------------------------
    # INDIRECT STORAGE-FAMILY NORMALIZATION (v22c)
    # -------------------------------------------------

    def _var_for_sid(self, sid):
        if sid is None:
            return None

        direct = self.vars.get(sid)
        if direct is not None:
            return direct

        direct = self.vars.get(str(sid))
        if direct is not None:
            return direct

        for var in self._iter_vars():
            if str(self._sid(var)) == str(sid):
                return var
        return None

    def _indirect_family_key(self, contract, ordinal):
        prior = dict(contract.get("prior_storage") or {})
        output = dict(contract.get("output_storage") or {})
        prior_key = prior.get("high_identity_key")
        output_key = output.get("high_identity_key")

        if prior_key is not None and output_key is not None and prior_key != output_key:
            self._indirect_resolver_warnings.append({
                "kind": "resolver_indirect_high_identity_mismatch_v22c",
                "indirect_op_id": contract.get("indirect_op_id"),
                "prior_sid": contract.get("prior_sid"),
                "output_sid": contract.get("output_sid"),
                "prior_high_identity_key": prior_key,
                "output_high_identity_key": output_key,
                "action": "keep_output_family_distinct_from_prior_family",
            })

        # The output HighVariable owns the new SSA state.  The prior key is a
        # valid fallback only when output-side evidence is unavailable.
        key = output_key or prior_key
        if key is not None:
            return str(key)

        # If an earlier transition already introduced either SID, retain that
        # family.  This is conservative graph continuity, not name matching.
        for sid in (contract.get("output_sid"), contract.get("prior_sid")):
            existing = self._indirect_storage_family_by_sid.get(str(sid))
            if existing:
                return str(existing)

        output_sid = contract.get("output_sid")
        fallback = "unresolved_indirect_output:%s" % (
            str(output_sid) if output_sid is not None else str(ordinal)
        )
        self._indirect_resolver_warnings.append({
            "kind": "resolver_indirect_high_identity_missing_v22c",
            "indirect_op_id": contract.get("indirect_op_id"),
            "prior_sid": contract.get("prior_sid"),
            "output_sid": output_sid,
            "fallback_family_key": fallback,
            "action": "isolate_unresolved_output_family",
        })
        return fallback

    def _new_indirect_family(self, key, contract):
        output_storage = dict(contract.get("output_storage") or {})
        prior_storage = dict(contract.get("prior_storage") or {})
        high = dict(
            output_storage.get("high_variable")
            or prior_storage.get("high_variable")
            or {}
        )
        return {
            "kind": "resolver_indirect_storage_family_v22c",
            "version": "v22c_indirect_storage_families",
            "family_id": "storage_family:%s" % key,
            "high_identity_key": key,
            "high_name": high.get("name"),
            "high_slot": high.get("slot"),
            "declared_datatype": dict(high.get("datatype") or {}),
            "member_sids": [],
            "entry_sids": [],
            "transition_output_sids": [],
            "transition_ids": [],
            "transitions": [],
            "parameter_initializers": [],
            "address_tied": False,
            "persistent": False,
            "storage_spaces": [],
            "classification": None,
            "ordinary_c_local_candidate": False,
            "cfg_governed": True,
            "linear_runtime_order_claimed": False,
            "authority": "PALlibrary_INDIRECT_custody_plus_high_variable_identity",
        }

    def _append_unique(self, values, value):
        if value is None:
            return
        if value not in values:
            values.append(value)

    def _normalize_indirect_storage_families(self):
        """Turn lifter INDIRECT evidence into storage-family sidecar records.

        An INDIRECT output is a new SSA state of storage, not an arithmetic
        result.  This pass groups states only by PALlibrary's HighVariable
        identity evidence and preserves every prior->output transition.  CFG
        structure remains authoritative for runtime ordering.
        """

        self._indirect_storage_families_by_key = {}
        self._indirect_storage_family_by_sid = {}
        self._indirect_custody_transitions = []
        self._indirect_custody_by_output_sid = {}
        self._indirect_effect_owner_chains_by_family = {}
        self._indirect_parameter_initializers = []
        self._indirect_escape_barrier_sids = set()
        self._indirect_machine_state_sids = set()
        self._indirect_resolver_warnings = []
        self._indirect_resolver_inventory = {}

        contracts = list(
            getattr(self.func, "indirect_custody_contracts", []) or []
        )
        if not contracts:
            self._indirect_resolver_inventory = {
                "kind": "resolver_indirect_storage_inventory_v22c",
                "version": "v22c_indirect_storage_families",
                "active": False,
                "input_contracts": 0,
                "storage_families": 0,
                "custody_transitions": 0,
                "warnings": 0,
                "rule": "no_lifter_INDIRECT_contracts_present",
            }
            return

        ops_by_id = {}
        ops_by_output_sid = {}
        for block in self._iter_blocks():
            for op in getattr(block, "ops", []) or []:
                op_id = getattr(op, "op_id", None)
                if op_id is not None:
                    ops_by_id[str(op_id)] = op
                output = getattr(op, "output", None)
                output_sid = self._sid(output)
                if output_sid is not None:
                    ops_by_output_sid.setdefault(str(output_sid), []).append(op)

        for ordinal, contract in enumerate(contracts):
            if not isinstance(contract, dict):
                self._indirect_resolver_warnings.append({
                    "kind": "resolver_indirect_contract_not_mapping_v22c",
                    "ordinal": ordinal,
                })
                continue

            key = self._indirect_family_key(contract, ordinal)
            family = self._indirect_storage_families_by_key.get(key)
            if family is None:
                family = self._new_indirect_family(key, contract)
                self._indirect_storage_families_by_key[key] = family

            prior_sid = contract.get("prior_sid")
            output_sid = contract.get("output_sid")
            prior_storage = dict(contract.get("prior_storage") or {})
            output_storage = dict(contract.get("output_storage") or {})
            creation = bool(contract.get("indirect_creation"))
            same_high = contract.get("same_high_variable")
            prior_high_key = prior_storage.get("high_identity_key")
            output_high_key = output_storage.get("high_identity_key")
            keys_disagree = bool(
                prior_high_key is not None
                and output_high_key is not None
                and prior_high_key != output_high_key
            )

            # A false same-high result is a transition into the output family,
            # not proof that the prior SSA value belongs to that family.
            if not creation and same_high is not False and not keys_disagree:
                self._append_unique(family["member_sids"], prior_sid)
            self._append_unique(family["member_sids"], output_sid)
            self._append_unique(family["transition_output_sids"], output_sid)

            # Make SID continuity available to a later contract whose Ghidra
            # HighVariable image is missing.  This is only a fallback; an
            # explicit output HighVariable identity remains authoritative.
            for member_sid in family["member_sids"]:
                self._indirect_storage_family_by_sid.setdefault(
                    str(member_sid), key
                )

            transition_id = contract.get("indirect_op_id")
            if transition_id is None:
                transition_id = "indirect_transition:%d" % ordinal
            transition_id = str(transition_id)

            transition = {
                "kind": "resolver_indirect_custody_transition_v22c",
                "version": "v22c_indirect_storage_families",
                "observation_ordinal": ordinal,
                "transition_id": transition_id,
                "family_id": family["family_id"],
                "high_identity_key": key,
                "block_addr": contract.get("block_addr"),
                "prior_sid": prior_sid,
                "output_sid": output_sid,
                "same_high_variable": same_high,
                "indirect_creation": creation,
                "preserves_prior_value_possibly": contract.get(
                    "preserves_prior_value_possibly"
                ),
                "owner_ref_id": contract.get("owner_ref_id"),
                "owner_ref_hex": contract.get("owner_ref_hex"),
                "owner_resolved": contract.get("owner_resolved"),
                "owner_op_id": contract.get("owner_op_id"),
                "owner_opcode": contract.get("owner_opcode"),
                "owner_category": contract.get("owner_category"),
                "owner_block_addr": contract.get("owner_block_addr"),
                "address_escape_or_memory_custody": contract.get(
                    "address_escape_or_memory_custody"
                ),
                "runtime_operation": False,
                "emits_runtime_helper": False,
                "runtime_order": "controlled_by_CFG_not_observation_ordinal",
                "authority": contract.get("authority"),
            }
            family["transitions"].append(transition)
            family["transition_ids"].append(transition_id)
            self._indirect_custody_transitions.append(transition)
            if output_sid is not None:
                self._indirect_custody_by_output_sid[str(output_sid)] = transition

            family["address_tied"] = bool(
                family["address_tied"]
                or contract.get("address_escape_or_memory_custody")
                or prior_storage.get("is_addr_tied")
                or output_storage.get("is_addr_tied")
            )
            family["persistent"] = bool(
                family["persistent"]
                or prior_storage.get("is_persistent")
                or output_storage.get("is_persistent")
            )
            for storage in (prior_storage, output_storage):
                self._append_unique(family["storage_spaces"], storage.get("space"))

            # Attach resolver custody directly to the PAL operation without
            # changing the legacy two-input INDIRECT shape.
            op = ops_by_id.get(transition_id)
            if op is None and output_sid is not None:
                candidates = ops_by_output_sid.get(str(output_sid), [])
                op = next(
                    (candidate for candidate in candidates
                     if getattr(candidate, "opcode", None) == "INDIRECT"),
                    None,
                )
            if op is not None:
                op.resolver_indirect_transition = transition
                op.indirect_storage_family_id = family["family_id"]
                evidence = getattr(op, "numeric_evidence", None)
                if not isinstance(evidence, dict):
                    evidence = {}
                    op.numeric_evidence = evidence
                evidence["resolver_indirect_storage_v22c"] = transition

        # Derive entry states only after every transition output is known.
        for key, family in self._indirect_storage_families_by_key.items():
            outputs = set(str(sid) for sid in family["transition_output_sids"])
            family["entry_sids"] = [
                sid for sid in family["member_sids"]
                if str(sid) not in outputs
            ]

            for sid in family["member_sids"]:
                sid_key = str(sid)
                previous = self._indirect_storage_family_by_sid.get(sid_key)
                if previous is not None and previous != key:
                    self._indirect_resolver_warnings.append({
                        "kind": "resolver_indirect_sid_family_collision_v22c",
                        "sid": sid,
                        "first_family_key": previous,
                        "second_family_key": key,
                        "action": "retain_first_family_binding",
                    })
                    continue
                self._indirect_storage_family_by_sid[sid_key] = key

            self._indirect_effect_owner_chains_by_family[family["family_id"]] = [
                {
                    "observation_ordinal": item["observation_ordinal"],
                    "transition_id": item["transition_id"],
                    "owner_ref_id": item["owner_ref_id"],
                    "owner_ref_hex": item["owner_ref_hex"],
                    "owner_op_id": item["owner_op_id"],
                    "owner_opcode": item["owner_opcode"],
                    "owner_category": item["owner_category"],
                    "prior_sid": item["prior_sid"],
                    "output_sid": item["output_sid"],
                }
                for item in family["transitions"]
            ]

            for sid in family["member_sids"]:
                var = self._var_for_sid(sid)
                if var is None:
                    continue
                var.is_indirect_storage_member = True
                var.indirect_storage_family_id = family["family_id"]
                var.indirect_storage_family_key = key
                var.indirect_address_escape_barrier = bool(family["address_tied"])
                if family["address_tied"]:
                    self._indirect_escape_barrier_sids.add(str(sid))
                    # A rerun must never preserve a stale free-alias tag on an
                    # address-taken storage state.
                    var.is_parameter_alias = False
                    var.parameter_alias_of = None

    def _record_indirect_parameter_initializer(self, block, op, src, out, pname):
        sid = self._sid(out)
        key = self._indirect_storage_family_by_sid.get(str(sid))
        family = self._indirect_storage_families_by_key.get(key)
        entry_state = bool(family and sid in family.get("entry_sids", []))
        role = "parameter_storage_initializer" if entry_state else "parameter_storage_write"

        event = {
            "kind": "resolver_indirect_parameter_initializer_v22c",
            "version": "v22c_indirect_storage_families",
            "parameter": pname,
            "source_sid": self._sid(src),
            "output_sid": sid,
            "family_id": family.get("family_id") if family else None,
            "high_identity_key": key,
            "block_addr": getattr(block, "addr", None),
            "op_id": getattr(op, "op_id", None),
            "opcode": getattr(op, "opcode", None),
            "role": role,
            "entry_state": entry_state,
            "free_parameter_alias": False,
            "parameter_value_equivalence_scope": "this_COPY_only",
            "mutation_barrier_after_address_escape": True,
            "authority": "COPY_provenance_plus_INDIRECT_storage_family",
        }
        self._indirect_parameter_initializers.append(event)
        if family is not None:
            family["parameter_initializers"].append(event)

        out.is_parameter_alias = False
        out.parameter_alias_of = None
        out.is_parameter_initializer = True
        out.parameter_initializer_of = pname
        out.parameter_initializer_source_sid = self._sid(src)
        out.semantic_role = role
        out.symbol_kind = "ADDRESS_TIED_STORAGE_STATE"
        op.resolver_indirect_parameter_initializer = event

    def _finalize_indirect_storage_families(self):
        families = list(self._indirect_storage_families_by_key.values())

        for family in families:
            storage_spaces = set(family["storage_spaces"] or [])
            if "ram" in storage_spaces:
                family["persistent"] = True

            if family["persistent"]:
                classification = (
                    "persistent_address_tied_storage"
                    if family["address_tied"]
                    else "persistent_indirect_storage"
                )
                ordinary_candidate = False
            elif family["address_tied"]:
                classification = "address_tied_c_storage"
                ordinary_candidate = not family["persistent"]
            elif storage_spaces and storage_spaces.issubset({"register", "unique"}):
                classification = "non_address_tied_machine_state"
                ordinary_candidate = False
            else:
                # Unknown/non-address-tied custody stays outside ordinary local
                # folding, but is not mislabeled as machine state without
                # register/unique storage evidence.
                classification = "non_address_tied_indirect_storage"
                ordinary_candidate = False

            family["classification"] = classification
            family["ordinary_c_local_candidate"] = ordinary_candidate
            family["address_escape_barrier"] = bool(family["address_tied"])

            for sid in family["member_sids"]:
                var = self._var_for_sid(sid)
                if var is None:
                    continue
                var.indirect_storage_classification = classification
                var.indirect_ordinary_c_local_candidate = ordinary_candidate
                if classification == "non_address_tied_machine_state":
                    var.is_indirect_machine_state = True
                    self._indirect_machine_state_sids.add(str(sid))

        owner_categories = {}
        owner_refs = set()
        for transition in self._indirect_custody_transitions:
            category = transition.get("owner_category") or "unknown"
            owner_categories[category] = owner_categories.get(category, 0) + 1
            owner_ref = transition.get("owner_ref_id")
            if owner_ref is not None:
                owner_refs.add("ref:%s" % str(owner_ref))
            else:
                owner_refs.add(
                    "unresolved:%s" % (
                        transition.get("owner_op_id")
                        or transition.get("transition_id")
                    )
                )

        self._indirect_resolver_inventory = {
            "kind": "resolver_indirect_storage_inventory_v22c",
            "version": "v22c_indirect_storage_families",
            "active": bool(self._indirect_custody_transitions),
            "input_contracts": len(
                list(getattr(self.func, "indirect_custody_contracts", []) or [])
            ),
            "storage_families": len(families),
            "address_tied_families": sum(
                1 for family in families if family["address_tied"]
            ),
            "persistent_families": sum(
                1 for family in families if family["persistent"]
            ),
            "machine_state_families": sum(
                1 for family in families
                if family["classification"] == "non_address_tied_machine_state"
            ),
            "custody_transitions": len(self._indirect_custody_transitions),
            "effect_owner_groups": len(owner_refs),
            "owner_categories": owner_categories,
            "parameter_initializers": len(self._indirect_parameter_initializers),
            "escape_barrier_sids": len(self._indirect_escape_barrier_sids),
            "machine_state_sids": len(self._indirect_machine_state_sids),
            "warnings": len(self._indirect_resolver_warnings),
            "runtime_order": "CFG_governed_not_linearized",
            "rule": "HighVariable_identity_families_plus_address_escape_alias_barrier",
        }

    def _parameter_name_for_var(self, var):
        if var is None:
            return None

        # ABI-C physical/implicit inputs may still carry a legacy `param_N`
        # display name, but that is not callable identity and must not seed
        # parameter-copy aliases.
        if getattr(var, "is_callable_parameter", None) is False and (
            getattr(var, "is_abi_physical_carrier", False)
            or getattr(var, "is_implicit_machine_input", False)
        ):
            return None

        # Address-taken storage may have been initialized from a parameter, but
        # later CALL/STORE owners can mutate it.  Never propagate that entry
        # value as a timeless parameter alias.
        sid = self._sid(var)
        if (
            sid is not None
            and str(sid) in self._indirect_escape_barrier_sids
        ):
            return None

        if getattr(var, "is_parameter", False):
            return getattr(var, "parameter_name", None) or getattr(var, "name", None)

        if getattr(var, "is_parameter_alias", False):
            return getattr(var, "parameter_alias_of", None)

        sid = self._sid(var)
        if sid is not None:
            for event in self._parameter_alias_events:
                if str(event.get("alias_sid")) == str(sid):
                    return event.get("parameter")

        return None

    def _discover_parameter_copy_aliases(self):
        """Record real SSA aliases copied from parameters.

        We intentionally do not rename COPY outputs to the parameter name.
        Those variables are Ghidra/P-code SSA aliases and should remain visible
        as v_####/local_#### when they occur.
        """

        if not self._parameter_records:
            return

        copy_like = {"COPY"}

        for block in self._iter_blocks():

            for op in getattr(block, "ops", []) or []:

                opcode = getattr(op, "opcode", None)
                if opcode not in copy_like:
                    continue

                out = getattr(op, "output", None)
                inputs = getattr(op, "inputs", []) or []
                if out is None or not inputs:
                    continue

                src = inputs[0]
                pname = self._parameter_name_for_var(src)
                if not pname:
                    continue

                out_sid = self._sid(out)
                if (
                    out_sid is not None
                    and str(out_sid) in self._indirect_escape_barrier_sids
                ):
                    self._record_indirect_parameter_initializer(
                        block, op, src, out, pname
                    )
                    continue

                # A direct backing parameter variable is not an alias of itself.
                if getattr(out, "is_parameter", False):
                    continue

                out.is_parameter_alias = True
                out.parameter_alias_of = pname
                out.parameter_alias_source_sid = self._sid(src)
                out.parameter_alias_opcode = opcode
                out.semantic_role = "parameter_ssa_alias"
                out.symbol_kind = "PARAMETER_ALIAS"

                if not getattr(out, "var_type", None):
                    out.var_type = "temp"
                    out.is_temp = True

                if not getattr(out, "name", None):
                    sid = self._sid(out)
                    out.name = sid or "tmp_param_alias"

                self._parameter_alias_events.append({
                    "alias_sid": self._sid(out),
                    "alias_name": getattr(out, "name", None),
                    "parameter": pname,
                    "source_sid": self._sid(src),
                    "opcode": opcode,
                    "block_addr": getattr(block, "addr", None),
                })

    def _discover_numeric_type_flows(self):
        """Record conversion-family bit transport and view transitions.

        COPY is not assumed to mean "same C type".  It preserves or resizes a
        bit-vector, while its source and output may carry different declared
        views.  CAST is an explicit view boundary even when its width does not
        change.  SUBPIECE/ZEXT/SEXT preserve their explicit width-conversion
        evidence.  PALCompute will decide the runtime action from these facts.
        """

        conversion_like = {"COPY", "CAST", "SUBPIECE", "INT_ZEXT", "INT_SEXT"}

        for block in self._iter_blocks():
            for op in getattr(block, "ops", []) or []:
                opcode = getattr(op, "opcode", None)
                if opcode not in conversion_like:
                    continue

                inputs = list(getattr(op, "inputs", []) or [])
                out = getattr(op, "output", None)
                if not inputs or out is None:
                    continue

                src = inputs[0]
                source_view = self._numeric_view_for_var(src)
                output_view = self._numeric_view_for_var(out)

                input_widths = list(getattr(op, "input_widths", []) or [])
                source_width = input_widths[0] if input_widths else source_view.get("width_bits")
                output_width = getattr(op, "output_width", None)
                if output_width is None:
                    output_width = output_view.get("width_bits")

                if isinstance(source_width, int) and isinstance(output_width, int):
                    if source_width == output_width:
                        width_relation = "same_width"
                    elif source_width > output_width:
                        width_relation = "narrowing"
                    else:
                        width_relation = "widening"
                else:
                    width_relation = "unknown"

                changed_axes = []
                for axis in ("domain", "signedness", "canonical_type"):
                    before = source_view.get(axis)
                    after = output_view.get(axis)
                    if before != after:
                        changed_axes.append(axis)

                view_change = bool(changed_axes)
                if opcode == "INT_ZEXT":
                    classification = "zero_extension"
                elif opcode == "INT_SEXT":
                    classification = "sign_extension"
                elif opcode == "SUBPIECE":
                    classification = (
                        "narrowing_subpiece"
                        if width_relation == "narrowing"
                        else "subpiece_%s" % width_relation
                    )
                elif width_relation == "same_width":
                    if opcode == "CAST" and view_change:
                        classification = "same_width_explicit_recast"
                    elif opcode == "CAST":
                        classification = "same_width_explicit_view_boundary"
                    elif view_change:
                        classification = "same_width_copy_recast"
                    else:
                        classification = "bit_preserving_copy"
                elif width_relation == "narrowing":
                    classification = "narrowing_%s" % opcode.lower()
                elif width_relation == "widening":
                    classification = "widening_%s" % opcode.lower()
                else:
                    classification = "unresolved_%s_flow" % opcode.lower()

                subpiece_byte_offset = None
                if opcode == "SUBPIECE" and len(inputs) > 1:
                    offset_var = inputs[1]
                    subpiece_byte_offset = getattr(offset_var, "const_unsigned", None)
                    if subpiece_byte_offset is None:
                        subpiece_byte_offset = getattr(offset_var, "const_value", None)
                    if subpiece_byte_offset is None and self._space(offset_var) == "const":
                        subpiece_byte_offset = self._offset(offset_var)

                if opcode == "INT_ZEXT":
                    conversion_semantics = "zero_extend_to_output_width"
                elif opcode == "INT_SEXT":
                    conversion_semantics = "sign_extend_to_output_width"
                elif opcode == "SUBPIECE":
                    conversion_semantics = "extract_subpiece_at_byte_offset"
                elif opcode == "CAST":
                    conversion_semantics = "explicit_declared_view_boundary"
                else:
                    conversion_semantics = "copy_bit_transport_with_possible_assignment_conversion"

                flow = {
                    "kind": "resolver_numeric_type_flow_v21",
                    "opcode": opcode,
                    "block_addr": getattr(block, "addr", None),
                    "op_id": getattr(op, "op_id", None),
                    "source_sid": self._sid(src),
                    "output_sid": self._sid(out),
                    "source_width_bits": source_width,
                    "output_width_bits": output_width,
                    "width_relation": width_relation,
                    "preserves_raw_bits": width_relation == "same_width",
                    "source_view": source_view,
                    "output_view": output_view,
                    "view_change": view_change,
                    "changed_axes": changed_axes,
                    "classification": classification,
                    "conversion_semantics": conversion_semantics,
                    "subpiece_byte_offset": subpiece_byte_offset,
                    "explicit_cast_boundary": opcode == "CAST",
                    "copy_may_encode_assignment_conversion": opcode == "COPY" and view_change,
                    "runtime_semantics_deferred_to_palcompute": True,
                }

                op.resolver_numeric_flow = flow
                numeric_evidence = getattr(op, "numeric_evidence", None)
                if not isinstance(numeric_evidence, dict):
                    numeric_evidence = {}
                    op.numeric_evidence = numeric_evidence
                numeric_evidence["resolver_type_flow_v21"] = flow

                outgoing = getattr(src, "numeric_outgoing_type_flows", None)
                if not isinstance(outgoing, list):
                    outgoing = []
                    src.numeric_outgoing_type_flows = outgoing
                outgoing.append(flow)

                incoming = getattr(out, "numeric_incoming_type_flows", None)
                if not isinstance(incoming, list):
                    incoming = []
                    out.numeric_incoming_type_flows = incoming
                incoming.append(flow)

                self._numeric_type_flow_events.append(flow)
                out_sid = self._sid(out)
                if out_sid is not None:
                    self._numeric_type_flows_by_output_sid.setdefault(str(out_sid), []).append(flow)

        class_counts = {}
        for flow in self._numeric_type_flow_events:
            classification = flow.get("classification") or "unknown"
            class_counts[classification] = class_counts.get(classification, 0) + 1

        self._numeric_normalization_events.append({
            "kind": "resolver_numeric_type_flow_inventory_v21",
            "conversion_flows": len(self._numeric_type_flow_events),
            "copy_cast_flows": sum(
                1 for flow in self._numeric_type_flow_events
                if flow.get("opcode") in ("COPY", "CAST")
            ),
            "classifications": class_counts,
            "same_width_recasts": sum(
                1 for flow in self._numeric_type_flow_events
                if flow.get("classification") in (
                    "same_width_explicit_recast",
                    "same_width_copy_recast",
                )
            ),
        })

    # -------------------------------------------------
    # CONSTANTS
    # -------------------------------------------------

    def _tag_constants(self):

        for var in self._iter_vars():

            if self._space(var) != "const":
                continue

            off = self._offset(var)
            size = self._size(var)

            var.is_constant = True
            var.is_temp = False
            var.var_type = "const"
            var.semantic_role = "literal"
            var.symbol_kind = "CONSTANT"

            if off is not None:
                var.const_value = off
                var.value = off

                if size:
                    bits = size * 8
                    var.const_mask = (1 << bits) - 1
                    var.const_unsigned = int(off) & var.const_mask
                    var.const_signed = self._const_signed_value(off, size)

            if not getattr(var, "name", None):
                try:
                    var.name = hex(int(off))
                except Exception:
                    var.name = "const_unknown"

    # -------------------------------------------------
    # MEMORY VARIABLE CLASSIFICATION
    # -------------------------------------------------

    def _tag_memory_vars(self):

        for var in self._iter_vars():

            space = self._space(var)
            off = self._offset(var)

            # ABI-C already assigned these values to physical or implicit
            # custody.  Storage classification may enrich register/stack flags
            # but must not demote them into ordinary temps/locals.
            if (
                getattr(var, "is_implicit_machine_input", False)
                or (
                    getattr(var, "is_abi_physical_carrier", False)
                    and not getattr(var, "is_callable_parameter", False)
                )
            ):
                if space == "register":
                    var.is_register = True
                elif space == "stack":
                    var.is_stack = True
                var.is_temp = False
                continue

            # ---------- STACK LOCALS ----------
            if space == "stack":

                if getattr(var, "is_parameter", False):
                    # Some decompilers represent parameters in stack space.
                    # Preserve parameter role/name while recording stack storage.
                    var.is_stack = True
                    var.storage_role = "stack_parameter"
                    continue

                var.var_type = "stack"
                var.is_stack = True
                var.is_temp = False
                var.semantic_role = "local_storage"
                var.symbol_kind = "STACK_LOCAL"

                if off is not None and not getattr(var, "name", None):
                    var.name = "local_%x" % abs(int(off))

            # ---------- RAM SPACE ----------
            elif space == "ram":

                func = self._function_at(off)

                if func is not None:

                    var.var_type = "function"
                    var.is_function = True
                    var.is_global = False
                    var.is_temp = False
                    var.symbol_kind = "FUNCTION_SYMBOL"
                    var.semantic_role = "call_target"

                    symbol = self._name_for_function(off)
                    var.symbol = symbol
                    if not getattr(var, "name", None) or self._is_auto_global_name(getattr(var, "name", None)):
                        var.name = symbol

                else:

                    var.var_type = "global"
                    var.is_global = True
                    var.is_temp = False
                    var.symbol_kind = "GLOBAL_SYMBOL"
                    var.semantic_role = "memory_global"

                    if not getattr(var, "name", None):
                        var.name = self._name_for_global(off)

            # ---------- REGISTER ----------
            elif space == "register":

                if not getattr(var, "is_parameter", False):
                    var.var_type = "temp"
                    var.is_register = True
                    var.is_temp = True
                    var.semantic_role = "compiler_register_temp"
                    var.symbol_kind = "REGISTER_TEMP"

                    if not getattr(var, "name", None):
                        sid = self._sid(var)
                        var.name = sid or "reg_%x" % int(off or 0)

            # ---------- UNIQUE ----------
            elif space == "unique":

                var.var_type = "temp"
                var.is_unique = True
                var.is_temp = True
                var.semantic_role = "compiler_unique_temp"
                var.symbol_kind = "UNIQUE_TEMP"

                if not getattr(var, "name", None):
                    sid = self._sid(var)
                    var.name = sid or "u_%x" % int(off or 0)

    # -------------------------------------------------
    # FUNCTION SYMBOLS FROM CALL OPS
    # -------------------------------------------------

    def _tag_call_targets(self):

        for block in self._iter_blocks():

            for op in getattr(block, "ops", []) or []:

                if getattr(op, "opcode", None) not in ("CALL", "CALLIND"):
                    continue

                inputs = getattr(op, "inputs", None) or []
                if not inputs:
                    continue

                target = inputs[0]

                # Direct call target.
                if self._space(target) == "ram":
                    off = self._offset(target)

                    target.is_function = True
                    target.is_global = False
                    target.is_temp = False
                    target.var_type = "function"
                    target.symbol_kind = "FUNCTION_SYMBOL"
                    target.semantic_role = "call_target"
                    target.call_target_addr = off

                    symbol = self._name_for_function(off)
                    target.symbol = symbol

                    # Important v18x fix:
                    # _tag_memory_vars may have named an unresolved RAM target
                    # g_xxx before this CALL context proves it is a function.
                    if (
                        not getattr(target, "name", None)
                        or self._is_auto_global_name(getattr(target, "name", None))
                    ):
                        target.name = symbol

                # Indirect call target.
                else:
                    try:
                        target.is_function_pointer = True
                        if not getattr(target, "semantic_role", None):
                            target.semantic_role = "indirect_call_target"
                    except Exception:
                        pass

    # -------------------------------------------------
    # FALLBACK TEMP CLASSIFICATION
    # -------------------------------------------------

    def _tag_unclassified_temps(self):

        for var in self._iter_vars():

            if getattr(var, "var_type", None):
                continue

            if getattr(var, "is_constant", False):
                continue

            var.var_type = "temp"
            var.is_temp = True
            var.symbol_kind = "TEMP"
            var.semantic_role = "compiler_temp"

            if not getattr(var, "name", None):
                sid = self._sid(var)
                var.name = sid or "tmp_unknown"

    # -------------------------------------------------
    # LOOP INDUCTION VARIABLE DETECTION
    # -------------------------------------------------

    def _detect_induction_variables(self):

        cfg = getattr(self.func, "cfg", None)
        if not cfg:
            return

        for block in self._iter_blocks():

            for op in getattr(block, "ops", []) or []:

                if getattr(op, "opcode", None) != "INT_ADD":
                    continue

                out = getattr(op, "output", None)
                inputs = getattr(op, "inputs", []) or []

                if not out or len(inputs) != 2:
                    continue

                a, b = inputs

                # SSA/self form: v = v + const.
                if a is out and getattr(b, "is_constant", False):
                    out.is_induction_variable = True
                    out.semantic_role = "loop_induction"
                    out.induction_stride = getattr(b, "const_signed", None) or getattr(b, "const_value", None)

                # SSA transition form: v2 = v1 + const.
                elif getattr(b, "is_constant", False):
                    out.is_induction_variable = True
                    out.semantic_role = "loop_induction"
                    out.induction_source = a
                    out.induction_stride = getattr(b, "const_signed", None) or getattr(b, "const_value", None)

    # -------------------------------------------------
    # DETERMINISTIC HUMAN ALIASES (IM-D)
    # -------------------------------------------------

    def _human_alias_for_sid(self, sid):
        text = str(sid or "")
        match = re.match(r"^v_(\d+)$", text)
        if match:
            identity = int(match.group(1))
        else:
            # Stable fallback for nonstandard SSA identities.
            identity = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:12], 16)

        words = self.HUMAN_ALIAS_WORDS
        width = len(words)
        low = identity % width
        high = (identity // width) % width
        tier = identity // (width * width)
        if identity < width:
            alias = words[low]
        else:
            alias = "%s_%s" % (words[high], words[low])
        if tier:
            alias = "%s_%d" % (alias, tier)
        return alias, identity

    def _generate_human_alias_contracts(self):
        previous_operator_aliases = dict(
            getattr(self.func, "operator_aliases_by_sid", {}) or {}
        )
        contracts = {}
        for var in sorted(self._iter_vars(), key=lambda value: str(self._sid(value))):
            sid = self._sid(var)
            if sid is None or not str(sid).startswith("v_"):
                continue
            generated, identity = self._human_alias_for_sid(sid)
            operator_alias = previous_operator_aliases.get(str(sid))
            pal_name = getattr(var, "name", None) or str(sid)
            active_source = "operator" if operator_alias else "generated"
            active_name = operator_alias or generated
            contract = {
                "kind": "resolver_human_alias_contract_im_d",
                "version": "im_d_v1_deterministic_aliases",
                "sid": str(sid),
                "canonical_ssa_name": str(sid),
                "pal_name": str(pal_name),
                "generated_human_alias": generated,
                "operator_alias": operator_alias,
                "active_name_source": active_source,
                "active_name": active_name,
                "numeric_identity": identity,
                "algorithm": "ssa_numeric_identity_base64_cognitive_v1",
                "operator_alias_mutates_ground_truth": False,
            }
            contracts[str(sid)] = contract
            var.canonical_ssa_name = str(sid)
            var.generated_human_alias = generated
            var.operator_alias = operator_alias
            var.human_alias_contract = contract
        self._human_alias_contracts_by_sid = contracts

    # -------------------------------------------------
    # EXPORT / DEBUG METADATA
    # -------------------------------------------------

    def _publish_metadata(self):

        parameter_records = [
            {
                "index": r["index"],
                "name": r["name"],
                "sid": r["sid"],
                "space": r["space"],
                "offset": r["offset"],
                "size": r["size"],
                "storage_key": r["storage_key"],
            }
            for r in self._parameter_records
        ]

        parameter_bindings_by_sid = {
            str(e.get("sid")): e
            for e in self._parameter_binding_events
            if e.get("sid") is not None
        }

        parameter_aliases_by_sid = {
            str(e.get("alias_sid")): e.get("parameter")
            for e in self._parameter_alias_events
            if e.get("alias_sid") is not None
        }

        numeric_flow_recasts = [
            flow for flow in self._numeric_type_flow_events
            if flow.get("classification") in (
                "same_width_explicit_recast",
                "same_width_copy_recast",
            )
        ]

        # Public metadata for later SemanticGraphBuilder/emitter/PAL EXEC use.
        self.func.parameter_records = parameter_records
        self.func.parameter_bindings = list(self._parameter_binding_events)
        self.func.parameter_bindings_by_sid = parameter_bindings_by_sid
        self.func.parameter_copy_aliases = list(self._parameter_alias_events)
        self.func.parameter_aliases_by_sid = parameter_aliases_by_sid
        self.func.parameter_conflicts = list(self._parameter_conflicts)
        self.func.parameter_resolver_version = "v24_logical_physical_implicit_namespaces"

        # ABI-C public custody surfaces.  `legacy_physical_parameters` is the
        # old HighFunction-derived order preserved byte-for-byte for auditing;
        # only `callable_parameter_order` is authorized to define a future
        # Python function signature.
        self.func.legacy_physical_parameters = list(parameter_records)
        self.func.logical_parameter_contracts = list(
            self._abi_logical_parameter_contracts
        )
        self.func.callable_parameter_order = list(
            self._abi_callable_parameter_order
        )
        self.func.callable_parameters = list(
            self._abi_callable_parameter_objects
        )
        self.func.physical_carrier_bindings = dict(
            self._abi_physical_carrier_bindings
        )
        self.func.implicit_inputs = dict(self._abi_implicit_inputs)
        self.func.variadic_contract = dict(self._abi_variadic_contract)
        self.func.abi_alias_contracts_by_sid = dict(
            self._abi_alias_contracts_by_sid
        )
        self.func.abi_namespace_inventory = dict(
            self._abi_namespace_inventory
        )
        self.func.abi_namespace_collisions = list(
            self._abi_namespace_collisions
        )
        self.func.abi_namespace_warnings = list(
            self._abi_namespace_warnings
        )
        self.func.abi_namespace_version = (
            "v24_logical_physical_implicit_namespaces"
        )

        # INDIRECT custody is a storage identity sidecar.  Consumers must use
        # family IDs as mutation barriers while retaining original SSA SIDs and
        # the lifter's legacy two-input INDIRECT operation shape.
        self.func.indirect_storage_families_by_key = dict(
            self._indirect_storage_families_by_key
        )
        self.func.indirect_storage_family_by_sid = dict(
            self._indirect_storage_family_by_sid
        )
        self.func.indirect_custody_transitions = list(
            self._indirect_custody_transitions
        )
        self.func.indirect_custody_transitions_by_output_sid = dict(
            self._indirect_custody_by_output_sid
        )
        self.func.indirect_effect_owner_chains_by_family = dict(
            self._indirect_effect_owner_chains_by_family
        )
        self.func.indirect_parameter_initializers = list(
            self._indirect_parameter_initializers
        )
        self.func.indirect_escape_barrier_sids = sorted(
            self._indirect_escape_barrier_sids, key=str
        )
        self.func.indirect_machine_state_sids = sorted(
            self._indirect_machine_state_sids, key=str
        )
        self.func.indirect_resolver_inventory = dict(
            self._indirect_resolver_inventory
        )
        self.func.indirect_resolver_warnings = list(
            self._indirect_resolver_warnings
        )
        self.func.indirect_resolver_version = "v22c_indirect_storage_families"

        # Resolver-normalized numerical evidence for PALCompute and later
        # emitters.  These maps are additive and do not alter formula trees.
        self.func.numeric_contracts_by_sid = dict(self._numeric_contracts_by_sid)
        self.func.numeric_type_flow_events = list(self._numeric_type_flow_events)
        self.func.numeric_type_flows_by_output_sid = dict(self._numeric_type_flows_by_output_sid)
        self.func.numeric_normalization_events = list(self._numeric_normalization_events)
        self.func.numeric_normalization_conflicts = list(self._numeric_conflicts)
        self.func.numeric_resolver_version = "v21_storage_and_use_site_views"

        # IM-D naming is a sidecar contract. It never changes var.name or any
        # executable formula; the detached UI chooses which name projection to
        # display from this table.
        self.func.human_alias_contracts_by_sid = dict(
            self._human_alias_contracts_by_sid
        )
        self.func.human_alias_resolver_version = "im_d_v1_deterministic_aliases"
        self.func.operator_aliases_by_sid = {
            sid: contract.get("operator_alias")
            for sid, contract in self._human_alias_contracts_by_sid.items()
            if contract.get("operator_alias")
        }

        # The existing PAL numeric dump already prints this event stream.  Keep
        # resolver summaries there while detailed flow records remain on the
        # function and individual conversion-op evidence.
        numeric_events = list(getattr(self.func, "numeric_evidence_events", []) or [])
        numeric_events = [
            event for event in numeric_events
            if not str(event.get("kind", "")).startswith("resolver_numeric_")
        ]
        numeric_events.extend(self._numeric_normalization_events)
        self.func.numeric_evidence_events = numeric_events

        resolver_events = list(
            getattr(self.func, "resolver_evidence_events", []) or []
        )
        resolver_events = [
            event for event in resolver_events
            if not str(event.get("kind", "")).startswith("resolver_indirect_")
            and not str(event.get("kind", "")).startswith("resolver_abi_")
        ]
        resolver_events.append(dict(self._indirect_resolver_inventory))
        resolver_events.extend(self._indirect_resolver_warnings)
        resolver_events.append(dict(self._abi_namespace_inventory))
        resolver_events.extend(self._abi_namespace_collisions)
        resolver_events.extend(self._abi_namespace_warnings)
        self.func.resolver_evidence_events = resolver_events

        self.func.symbol_resolver_debug = {
            "vars_total": len(list(self._iter_vars())),
            "parameters": [getattr(v, "name", None) for v in self.parameters],
            "parameter_records": parameter_records,
            "parameter_bindings": list(self._parameter_binding_events),
            "parameter_copy_aliases": list(self._parameter_alias_events),
            "parameter_conflicts": list(self._parameter_conflicts),
            "abi_namespace_version": "v24_logical_physical_implicit_namespaces",
            "abi_namespace_inventory": dict(self._abi_namespace_inventory),
            "logical_parameter_contracts": list(
                self._abi_logical_parameter_contracts
            ),
            "callable_parameter_order": list(
                self._abi_callable_parameter_order
            ),
            "physical_carrier_bindings": dict(
                self._abi_physical_carrier_bindings
            ),
            "implicit_inputs": dict(self._abi_implicit_inputs),
            "variadic_contract": dict(self._abi_variadic_contract),
            "abi_alias_contracts_by_sid": dict(
                self._abi_alias_contracts_by_sid
            ),
            "abi_namespace_collisions": list(
                self._abi_namespace_collisions
            ),
            "abi_namespace_warnings": list(
                self._abi_namespace_warnings
            ),
            "indirect_resolver_version": "v22c_indirect_storage_families",
            "indirect_resolver_inventory": dict(self._indirect_resolver_inventory),
            "indirect_storage_families": dict(
                self._indirect_storage_families_by_key
            ),
            "indirect_storage_family_by_sid": dict(
                self._indirect_storage_family_by_sid
            ),
            "indirect_custody_transitions": list(
                self._indirect_custody_transitions
            ),
            "indirect_effect_owner_chains_by_family": dict(
                self._indirect_effect_owner_chains_by_family
            ),
            "indirect_parameter_initializers": list(
                self._indirect_parameter_initializers
            ),
            "indirect_escape_barrier_sids": sorted(
                self._indirect_escape_barrier_sids, key=str
            ),
            "indirect_machine_state_sids": sorted(
                self._indirect_machine_state_sids, key=str
            ),
            "indirect_resolver_warnings": list(
                self._indirect_resolver_warnings
            ),
            "numeric_resolver_version": "v21_storage_and_use_site_views",
            "numeric_normalization_events": list(self._numeric_normalization_events),
            "numeric_contracts_by_sid": dict(self._numeric_contracts_by_sid),
            "numeric_type_flows": list(self._numeric_type_flow_events),
            "numeric_same_width_recasts": numeric_flow_recasts,
            "numeric_conflicts": list(self._numeric_conflicts),
            "human_alias_version": "im_d_v1_deterministic_aliases",
            "human_alias_contracts": dict(self._human_alias_contracts_by_sid),
            "functions": sorted([
                getattr(v, "name", None)
                for v in self._iter_vars()
                if getattr(v, "is_function", False)
            ], key=str),
            "globals": sorted([
                getattr(v, "name", None)
                for v in self._iter_vars()
                if getattr(v, "is_global", False)
            ], key=str),
            "stack_locals": sorted([
                getattr(v, "name", None)
                for v in self._iter_vars()
                if getattr(v, "is_stack", False)
            ], key=str),
            "temps": sorted([
                getattr(v, "name", None)
                for v in self._iter_vars()
                if getattr(v, "is_temp", False)
            ], key=str),
        }


def debug_dump_indirect_storage_resolver(pal, include_transitions=False):
    """Print the compact v22c resolver custody view.

    `pal` is the PALFunction after PALSymbolResolver.resolve().  The optional
    transition dump is intentionally separate because large production
    functions may contain hundreds of custody edges.
    """

    from pprint import pprint

    print("===== PAL RESOLVER INDIRECT STORAGE v22c =====")
    print("\n[INVENTORY]")
    pprint(dict(getattr(pal, "indirect_resolver_inventory", {}) or {}))

    print("\n[STORAGE FAMILIES]")
    families = dict(getattr(pal, "indirect_storage_families_by_key", {}) or {})
    for key in sorted(families, key=str):
        family = families[key]
        pprint({
            "family_id": family.get("family_id"),
            "high_identity_key": family.get("high_identity_key"),
            "high_name": family.get("high_name"),
            "classification": family.get("classification"),
            "address_tied": family.get("address_tied"),
            "persistent": family.get("persistent"),
            "member_sids": family.get("member_sids"),
            "entry_sids": family.get("entry_sids"),
            "transitions": len(family.get("transitions", []) or []),
            "parameter_initializers": len(
                family.get("parameter_initializers", []) or []
            ),
        })

    print("\n[PARAMETER INITIALIZERS / STORAGE WRITES]")
    pprint(list(getattr(pal, "indirect_parameter_initializers", []) or []))

    print("\n[WARNINGS]")
    pprint(list(getattr(pal, "indirect_resolver_warnings", []) or []))

    if include_transitions:
        print("\n[CUSTODY TRANSITIONS â€” CFG GOVERNS RUNTIME ORDER]")
        for transition in list(
            getattr(pal, "indirect_custody_transitions", []) or []
        ):
            pprint(transition)

    print("===== END PAL RESOLVER INDIRECT STORAGE =====")


def debug_dump_abi_namespaces(pal, include_bindings=False):
    """Print the compact ABI-C resolver acceptance surface.

    `include_bindings=True` adds the complete physical-carrier owner records;
    the default remains short enough for routine specimen regression output.
    """

    from pprint import pprint

    print("===== PAL SYMBOL RESOLVER ABI-C NAMESPACES =====")
    print("\n[INVENTORY]")
    pprint(dict(getattr(pal, "abi_namespace_inventory", {}) or {}), sort_dicts=False)

    print("\n[CALLABLE PARAMETER ORDER]")
    for item in list(getattr(pal, "callable_parameter_order", []) or []):
        pprint({
            "ordinal": item.get("ordinal"),
            "name": item.get("name"),
            "identity_namespace": item.get("identity_namespace"),
            "logical_ordinal": item.get("logical_ordinal"),
            "logical_name": item.get("logical_name"),
            "physical_sids": item.get("physical_sids"),
            "binding_status": item.get("binding_status"),
            "selection_source": item.get("selection_source"),
        }, sort_dicts=False)

    print("\n[IMPLICIT MACHINE INPUTS]")
    implicit = dict(getattr(pal, "implicit_inputs", {}) or {})
    for sid in sorted(implicit, key=str):
        item = implicit[sid]
        pprint({
            "sid": sid,
            "source_name": item.get("high_name") or item.get("name"),
            "canonical_alias": item.get("canonical_alias"),
            "role": item.get("role"),
            "custody_class": item.get("custody_class"),
            "register": item.get("register"),
            "callable_argument": item.get("callable_argument"),
        }, sort_dicts=False)

    print("\n[VARIADIC CONTRACT]")
    pprint(dict(getattr(pal, "variadic_contract", {}) or {}), sort_dicts=False)

    print("\n[PHYSICAL OWNER COVERAGE]")
    physical = dict(getattr(pal, "physical_carrier_bindings", {}) or {})
    owner_counts = {}
    for item in physical.values():
        owner = dict(item.get("owner") or {})
        namespace = owner.get("namespace") or "UNOWNED"
        owner_counts[namespace] = owner_counts.get(namespace, 0) + 1
    pprint({
        "physical_carriers": len(physical),
        "owner_namespaces": owner_counts,
        "unowned_sids": sorted([
            sid for sid, item in physical.items() if not item.get("owner")
        ], key=str),
    }, sort_dicts=False)

    if include_bindings:
        print("\n[PHYSICAL CARRIER BINDINGS]")
        for sid in sorted(physical, key=str):
            pprint(physical[sid], sort_dicts=False)

    print("\n[WARNINGS]")
    pprint(list(getattr(pal, "abi_namespace_warnings", []) or []), sort_dicts=False)
    print("===== END PAL SYMBOL RESOLVER ABI-C NAMESPACES =====")
