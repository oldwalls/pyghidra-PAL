# ============================================================
# PAL EMITTER
# BUILD: v46p_immutable_abi_context_continuity
# Paired executable/readable rendering + authoritative ABI custody
# ============================================================
#
# Consumes:
#   func.exec_root / func.exec_tree
#   func.formula_nodes / func.var_nodes
#   func.phi_nodes
#   func.var_map
#   func.condition_vars
#   func.return_vars
#
# PHI/drop-in metadata from PALPHIfolder_presentation_dropins_v2:
#   func.phi_dropins
#   func.phi_dropins_by_pred
#   func.phi_dropins_by_join
#
# Presentation metadata:
#   func.inline_only_sids
#   func.suppress_assign_sids
#   func.materialize_sids
#   func.local_target_sids
#   func.preferred_expr_by_sid
#   func.phi_source_foldable_sids
#
# Design:
#   - CALL/CALLIND are never inlined during normal expression rendering.
#   - Materialized CALL outputs are emitted as statements.
#   - Suppressed SSA bridge assignments are hidden only if their semantic
#     replacement is emitted through PHI drop-ins or expression rendering.
#   - PHI drop-ins close transitions:
#         v_796 = local_1c + v_2808
#         local_1c = local_1c + v_2808
#   - Local initializers are never suppressed.
#   - INDIRECT is a metadata-only storage-version transition.  It is never
#     rendered as Python syntax and never treated as COPY.
#   - Readable mode names the HighVariable storage family.  Executable mode
#     reads/writes address-tied families through PAL's existing memory helpers.
#   - ABI-D entry/call/return plans and ABI-F convergence contracts are
#     consumed verbatim.  The emitter never recovers carrier placement from
#     parameter names, expressions, or target spelling.
#   - The executable projection uses one explicit ``abi_context`` boundary.
#     ``c_abi_get``, ``c_abi_call``, and ``c_abi_return`` are PALABI transport
#     primitives; their arguments come only from the published custody
#     contracts.  Numeric helpers remain isolated in PALhelpers.
# ============================================================


import ast
import copy
import json
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path

from PALCodeDocument import PALCodeDocument

_INDENT = "    "

# Human-readable diagnostic printers are opt-in. This switch does not disable
# detached PAL metadata collection or executable/readable emission.
DEBUG_REPORTING = "OFF"



_BINARY = {
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
    "INT_CARRY": "<carry>",
    "INT_SCARRY": "<scarry>",
    "INT_SBORROW": "<sborrow>",
}


_UNARY = {
    "INT_NEGATE": "~",
    "INT_2COMP": "-",
    "BOOL_NEGATE": "not ",
}


_TRANSPARENT = {
    "COPY",
    "CAST",
    "INT_ZEXT",
    "INT_SEXT",
    "TRUNC",
}


_SKIP_OPS = {
    "MULTIEQUAL",
}


_COMPARE_OPS = {
    "INT_EQUAL",
    "INT_NOTEQUAL",
    "INT_LESS",
    "INT_SLESS",
    "INT_LESSEQUAL",
    "INT_SLESSEQUAL",
}


_COMMUTATIVE = {
    "INT_ADD",
    "INT_MULT",
    "INT_AND",
    "INT_OR",
    "INT_XOR",
    "INT_EQUAL",
    "INT_NOTEQUAL",
}


class PALemitter:

    VERSION = "v46p_immutable_abi_context_continuity"
    ABI_CUSTODY_VERSION = "v46f_canonical_ABI_SSA_predicate_bridge"

    ABI_RUNTIME_HELPERS = frozenset((
        "c_abi_context", "c_abi_get", "c_abi_call", "c_abi_return",
    ))

    RENDER_EXECUTABLE = "executable"
    RENDER_READABLE = "readable"
    RENDER_MODES = (RENDER_EXECUTABLE, RENDER_READABLE)

    # ---------------------------------------------------------
    # CONSTRUCTION
    # ---------------------------------------------------------

    def _normalize_render_mode_v44(self, mode):
        mode = str(mode or self.RENDER_EXECUTABLE).strip().lower()
        aliases = {
            "exec": self.RENDER_EXECUTABLE,
            "helper": self.RENDER_EXECUTABLE,
            "helpers": self.RENDER_EXECUTABLE,
            "human": self.RENDER_READABLE,
            "humanized": self.RENDER_READABLE,
            "presentation": self.RENDER_READABLE,
        }
        mode = aliases.get(mode, mode)
        if mode not in self.RENDER_MODES:
            raise ValueError(
                "PAL emitter render_mode must be one of %s, got %r"
                % (", ".join(self.RENDER_MODES), mode)
            )
        return mode

    def _is_readable_render_v44(self):
        return self.render_mode == self.RENDER_READABLE

    def _debug_reporting_enabled_v46g(self):
        """
        Gate emitter-side console reports without disabling audit metadata.

        Precedence:
            func.emitter_debug_reporting
            PAL_EMITTER_DEBUG_REPORTING environment variable
            module-level DEBUG_REPORTING
        """
        value = getattr(self.func, "emitter_debug_reporting", None)
        if value is None:
            value = os.environ.get("PAL_EMITTER_DEBUG_REPORTING")
        if value is None:
            value = DEBUG_REPORTING
        if isinstance(value, bool):
            return value
        return str(value).strip().upper() in {
            "1", "TRUE", "YES", "Y", "ON", "ENABLE", "ENABLED",
        }

    @staticmethod
    def _readable_c_string_normalize_mapping_v46g(payload):
        if not isinstance(payload, dict):
            return {}
        strings = payload.get("strings", payload)
        if not isinstance(strings, dict):
            return {}

        normalized = {}
        for raw_address, raw_text in strings.items():
            try:
                address = (
                    int(raw_address)
                    if isinstance(raw_address, int)
                    else int(str(raw_address).strip(), 0)
                )
            except Exception:
                continue
            if not isinstance(raw_text, str):
                continue
            normalized[address] = raw_text
        return normalized

    @staticmethod
    def _readable_c_string_normalized_program_token_v46h(value):
        if value is None:
            return None
        text = Path(str(value)).name.strip().lower()
        for suffix in (".exe", ".elf", ".bin", ".out"):
            if text.endswith(suffix):
                text = text[:-len(suffix)]
                break
        return re.sub(r"[^a-z0-9]+", "", text) or None

    def _readable_c_string_program_tokens_v46h(self):
        """
        Collect explicit program/project identity evidence when available.

        PALFunctionObject currently does not normally expose these fields, so
        an empty result is expected during Batch emission.
        """
        values = [
            getattr(self.func, "program_name", None),
            getattr(self.func, "project_name", None),
            getattr(self.func, "executable_name", None),
            os.environ.get("PAL_PROGRAM_NAME"),
            os.environ.get("PAL_ACTIVE_PROJECT"),
        ]

        program = getattr(self.func, "program", None)
        get_name = getattr(program, "getName", None)
        if callable(get_name):
            try:
                values.append(get_name())
            except Exception:
                pass

        tokens = []
        for value in values:
            token = self._readable_c_string_normalized_program_token_v46h(
                value
            )
            if token and token not in tokens:
                tokens.append(token)
        return tokens

    def _readable_c_string_call_addresses_v46h(self):
        """
        Return exact constant addresses observed as CALL/CALLIND arguments.

        These addresses select among project overlays only. They are not
        themselves classified as strings. A readable substitution still
        requires exact membership in the selected overlay.
        """
        addresses = set()
        seen_objects = set()

        def consume(op_or_node):
            if op_or_node is None:
                return

            marker = id(op_or_node)
            if marker in seen_objects:
                return
            seen_objects.add(marker)

            if getattr(op_or_node, "opcode", None) not in (
                "CALL", "CALLIND"
            ):
                return

            inputs = list(getattr(op_or_node, "inputs", []) or [])
            for value in inputs[1:]:
                raw = getattr(value, "var", value)
                if not getattr(raw, "is_constant", False):
                    continue
                address = self._const_int_value(raw)
                if isinstance(address, int):
                    addresses.add(address)

        for node in list((getattr(self, "nodes", {}) or {}).values()):
            consume(node)

        try:
            for op in self._iter_all_ops():
                consume(op)
        except Exception:
            # FormulaNodes cover ordinary PAL calls. The block walk is extra
            # coverage for outputless call operations.
            pass

        return addresses

    def _readable_c_string_overlay_candidates_v46h(self):
        """
        Discover bounded project overlays without requiring a live Program.

        Search is limited to:
          - explicit function/environment paths;
          - the emitter module root and its parents;
          - CWD and its parents;
          - direct project/* children under those roots.

        No recursive repository or home-directory scan occurs.
        """
        candidates = []
        markers = set()

        def add(path, authority, explicit=False):
            if not path:
                return

            try:
                candidate = Path(str(path)).expanduser()
            except Exception:
                return

            if candidate.name != "PAL_stdio_strings.json":
                candidate = candidate / "PAL_stdio_strings.json"

            try:
                marker = str(candidate.resolve(strict=False))
            except Exception:
                marker = str(candidate)

            if marker in markers:
                return

            markers.add(marker)
            candidates.append({
                "path": candidate,
                "authority": authority,
                "explicit": bool(explicit),
            })

        add(
            getattr(self.func, "pal_stdio_strings_path", None),
            "func.pal_stdio_strings_path",
            explicit=True,
        )
        add(
            getattr(self.func, "stdio_strings_path", None),
            "func.stdio_strings_path",
            explicit=True,
        )
        add(
            os.environ.get("PAL_STDIO_STRINGS"),
            "PAL_STDIO_STRINGS",
            explicit=True,
        )

        roots = []
        root_markers = set()

        for base in (
            Path(__file__).resolve().parent,
            Path.cwd(),
        ):
            for root in [base] + list(base.parents):
                try:
                    marker = str(root.resolve(strict=False))
                except Exception:
                    marker = str(root)

                if marker in root_markers:
                    continue

                root_markers.add(marker)
                roots.append(Path(marker))

        for root in roots:
            add(root, "direct_root_candidate")

            project_dir = root / "project"
            if project_dir.is_dir():
                for overlay in sorted(
                    project_dir.glob("*/PAL_stdio_strings.json")
                ):
                    add(
                        overlay,
                        "PAL_project_directory_discovery",
                    )

            if root.parent.name == "project":
                add(root, "active_project_directory")

        return candidates

    def _readable_c_string_overlay_record_v46h(self, candidate):
        path = candidate.get("path")

        if not isinstance(path, Path) or not path.is_file():
            return None

        try:
            with path.open("rt", encoding="utf-8") as handle:
                payload = json.load(handle)

            mapping = self._readable_c_string_normalize_mapping_v46g(
                payload
            )
        except Exception as exc:
            self.readable_c_string_overlay_warnings.append({
                "kind": (
                    "emitter_readable_c_string_overlay_load_failed_v46h"
                ),
                "path": str(path),
                "authority": candidate.get("authority"),
                "error": str(exc),
                "action": "preserve_pointer_arguments",
            })
            return None

        if not mapping:
            return None

        program_value = (
            payload.get("program")
            if isinstance(payload, dict)
            else None
        )

        return {
            "path": path,
            "authority": candidate.get("authority"),
            "explicit": bool(candidate.get("explicit")),
            "mapping": mapping,
            "program_token": (
                self._readable_c_string_normalized_program_token_v46h(
                    program_value
                )
            ),
            "directory_token": (
                self._readable_c_string_normalized_program_token_v46h(
                    path.parent.name
                )
            ),
        }

    def _select_readable_c_string_overlay_v46h(self, records):
        records = list(records or [])

        if not records:
            return None, "none"

        explicit = [
            record for record in records
            if record.get("explicit")
        ]
        if explicit:
            return explicit[0], "explicit_path"

        identity_tokens = set(
            self._readable_c_string_program_tokens_v46h()
        )
        if identity_tokens:
            matches = [
                record for record in records
                if (
                    record.get("program_token") in identity_tokens
                    or record.get("directory_token") in identity_tokens
                )
            ]
            if len(matches) == 1:
                return matches[0], "program_identity"

        if len(records) == 1:
            return records[0], "single_project_overlay"

        call_addresses = self._readable_c_string_call_addresses_v46h()
        scored = []

        for record in records:
            mapping_addresses = set(record.get("mapping", {}))
            overlap = call_addresses & mapping_addresses
            scored.append((len(overlap), record))

        best_score = max(score for score, _ in scored)
        best = [
            record for score, record in scored
            if score == best_score and score > 0
        ]

        if len(best) == 1:
            return best[0], "unique_call_address_coverage"

        self.readable_c_string_overlay_warnings.append({
            "kind": "emitter_readable_c_string_overlay_ambiguous_v46h",
            "candidate_paths": [
                str(record.get("path")) for record in records
            ],
            "call_constant_addresses": [
                hex(value) for value in sorted(call_addresses)
            ],
            "best_address_overlap": best_score,
            "action": (
                "preserve_pointer_arguments_set_PAL_STDIO_STRINGS_"
                "for_explicit_authority"
            ),
        })
        return None, "ambiguous"

    def _load_readable_c_string_overlay_v46h(self):
        """
        Load one presentation-only address -> string mapping.

        Selection is fail-closed. No selected overlay means readable output
        retains numeric pointers. Executable rendering is never affected.
        """
        self.readable_c_string_overlay_source = None
        self.readable_c_string_overlay_selection = "none"
        self.readable_c_string_overlay_warnings = []

        inline = getattr(self.func, "pal_stdio_strings", None)
        normalized = self._readable_c_string_normalize_mapping_v46g(
            inline
        )

        if normalized:
            self.readable_c_string_overlay_source = (
                "func.pal_stdio_strings"
            )
            self.readable_c_string_overlay_selection = "inline_mapping"
            return normalized

        records = []

        for candidate in (
            self._readable_c_string_overlay_candidates_v46h()
        ):
            record = self._readable_c_string_overlay_record_v46h(
                candidate
            )
            if record is not None:
                records.append(record)

        selected, reason = (
            self._select_readable_c_string_overlay_v46h(records)
        )
        self.readable_c_string_overlay_selection = reason

        if selected is None:
            return {}

        self.readable_c_string_overlay_source = str(
            selected.get("path")
        )
        return dict(selected.get("mapping") or {})

    def _readable_c_string_literal_for_value_v46g(self, value):
        if (
            not self._is_readable_render_v44()
            or not self.readable_c_string_literals
            or value is None
        ):
            return None

        raw = getattr(value, "var", value)
        if not getattr(raw, "is_constant", False):
            return None

        address = self._const_int_value(raw)
        if address is None:
            return None
        return self.readable_c_string_literals.get(int(address))

    @staticmethod
    def _standalone_integer_literal_v46i(rendered):
        """
        Parse only a complete Python integer literal.

        This deliberately rejects variables, arithmetic, casts, helper calls,
        dereferences, indexing, and composite expressions.  Redundant balanced
        parentheses around the literal are accepted because the canonical
        expression renderer may preserve them.
        """
        if rendered is None:
            return None

        text = str(rendered).strip()
        while (
            len(text) >= 2
            and text.startswith("(")
            and text.endswith(")")
        ):
            depth = 0
            encloses_all = True
            for index, character in enumerate(text):
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                    if depth == 0 and index != len(text) - 1:
                        encloses_all = False
                        break
                if depth < 0:
                    encloses_all = False
                    break
            if not encloses_all or depth != 0:
                break
            text = text[1:-1].strip()

        if not re.fullmatch(
            r"[+-]?(?:"
            r"0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|"
            r"0[bB][01](?:_?[01])*|"
            r"0[oO][0-7](?:_?[0-7])*|"
            r"(?:0|[1-9][0-9]*(?:_?[0-9])*)"
            r")",
            text,
        ):
            return None

        try:
            return int(text.replace("_", ""), 0)
        except Exception:
            return None

    def _readable_call_argument_expr_v46i(self, value):
        """
        Project one READ call argument through the string overlay.

        First use direct PAL constant identity.  If ABI planning has wrapped
        the constant in an SSA/formula carrier, render it canonically and
        accept only a complete standalone integer literal.  Exact overlay
        membership is still required.

        EXEC and all non-call expression paths remain unchanged.
        """
        literal = self._readable_c_string_literal_for_value_v46g(value)
        if literal is not None:
            return repr(literal)

        rendered = self._expr(value)
        if (
            not self._is_readable_render_v44()
            or not self.readable_c_string_literals
        ):
            return rendered

        address = self._standalone_integer_literal_v46i(rendered)
        if address is None:
            return rendered

        literal = self.readable_c_string_literals.get(int(address))
        if literal is None:
            return rendered

        return repr(literal)

    # Historical helper name retained for compatibility with isolated callers.
    def _readable_call_argument_expr_v46g(self, value):
        return self._readable_call_argument_expr_v46i(value)

    def __init__(self, func, render_mode="executable"):

        self.func = func
        self.render_mode = self._normalize_render_mode_v44(render_mode)
        # Clean visual cognition is the readable-mode default. Width/sign
        # contracts remain attached to every projection and may be restored
        # inline for diagnostics by setting this function-level UI policy.
        self.readable_show_type_views = bool(
            getattr(func, "emitter_readable_type_views", False)
        )
        existing_document = getattr(func, "code_document", None)
        function_name = getattr(func, "func_name", "func")
        if not isinstance(existing_document, PALCodeDocument):
            existing_document = PALCodeDocument(function_name=function_name)
        self.code_document = existing_document
        self.func.code_document = existing_document
        # A new live emitter pass is the sole producer of IM-C registry truth.
        # Projection passes within emit_function_pair share this registry, but
        # stale records from a previous emitter instance are not retained.
        self.code_document.reset_metadata()
        self._provenance_context_stack = []
        self._provenance_statement_ordinals = {}
        self._current_exec_path = None
        self._current_exec_occurrence_id = None
        self._current_block_occurrence_id = None
        self._imc_pending_operation_fragments = []

        self.nodes, self.phi_nodes = self._load_semantic_graph(func)
        self.var_map = getattr(func, "var_map", {}) or {}

        # v46h: FormulaNodes must exist before overlay selection so a
        # program-less PALFunctionObject can identify the unique project
        # overlay by exact constant call-argument coverage.
        self.readable_c_string_literals = (
            self._load_readable_c_string_overlay_v46h()
        )

        self.condition_vars = list(getattr(func, "condition_vars", []))
        self.return_vars = list(getattr(func, "return_vars", []))

        # PHI transition metadata.
        self.phi_dropins = list(getattr(func, "phi_dropins", []) or [])
        self.phi_dropins_by_pred = getattr(func, "phi_dropins_by_pred", {}) or {}
        self.phi_dropins_by_join = getattr(func, "phi_dropins_by_join", {}) or {}

        # Presentation metadata.
        self.inline_only_sids = set(getattr(func, "inline_only_sids", set()) or set())
        self.suppress_assign_sids = set(getattr(func, "suppress_assign_sids", set()) or set())
        self.materialize_sids = set(getattr(func, "materialize_sids", set()) or set())
        self.local_target_sids = set(getattr(func, "local_target_sids", set()) or set())
        self.preferred_expr_by_sid = getattr(func, "preferred_expr_by_sid", {}) or {}
        self.phi_source_foldable_sids = set(getattr(func, "phi_source_foldable_sids", set()) or set())

        # PHIfolder v8 presentation policy.
        self.ssa_policy_by_sid = dict(getattr(func, "ssa_policy_by_sid", {}) or {})
        self.presentation_class_by_sid = dict(getattr(func, "presentation_class_by_sid", {}) or {})

        # v43 / Inning M: contract-driven C-truth rendering.  The emitter does
        # not infer widths or signedness; it consumes PALCompute contracts as
        # bound to final execution ownership by PALPHIfolder v21.
        self.c_truth_active = bool(getattr(func, "phi_compute_consumer_active", False))
        self.c_truth_consumer_version = getattr(func, "phi_compute_consumer_version", None)
        self.c_truth_bindings_by_sid = dict(
            getattr(func, "phi_compute_bindings_by_sid", {}) or {}
        )
        self.c_truth_alias_bindings_by_sid = dict(
            getattr(func, "phi_compute_alias_bindings_by_sid", {}) or {}
        )
        self.c_truth_contracts_by_op = dict(
            getattr(func, "phi_compute_contracts_by_op", {})
            or getattr(func, "compute_contracts_by_op", {})
            or {}
        )
        self.c_truth_outputless_contracts_by_op = dict(
            getattr(func, "phi_compute_outputless_contracts_by_op", {}) or {}
        )
        self.c_truth_control_contracts_by_block = dict(
            getattr(func, "phi_compute_control_contracts_by_block", {})
            or getattr(func, "compute_control_contracts_by_block", {})
            or {}
        )
        self.c_truth_compute_plans_by_sid = dict(
            getattr(func, "compute_plans_by_sid", {}) or {}
        )
        self.c_truth_consumer_warnings = list(
            getattr(func, "phi_compute_consumer_warnings", []) or []
        )
        self.c_truth_helper_calls = []
        self.c_truth_helper_call_keys = set()
        self.c_truth_render_warnings = []
        self.c_truth_raw_rewrite_events = []
        self.c_truth_raw_probe_events = []
        self.c_truth_readable_projection_events = []
        self.c_truth_required_helpers = set()
        self._c_truth_rendering_disabled = False
        self._c_truth_raw_contract_index = None
        self._c_truth_condition_context = None

        # v45: PALCompute/PALPHIfolder INDIRECT storage-custody products.
        # These tables remain sidecars; the legacy FormulaNodes are not
        # rewritten.  Expression rendering consults the sidecars before it can
        # descend into an INDIRECT node.
        self.custody_storage_bindings_by_sid = dict(
            getattr(func, "compute_storage_bindings_by_sid", {}) or {}
        )
        self.custody_indirect_contracts_by_output_sid = dict(
            getattr(func, "compute_indirect_contracts_by_output_sid", {}) or {}
        )
        self.custody_indirect_contracts_by_op = dict(
            getattr(func, "compute_indirect_contracts_by_op", {}) or {}
        )
        self.custody_effect_owners_by_op = dict(
            getattr(func, "compute_indirect_effect_owner_bindings_by_op", {}) or {}
        )
        self.custody_storage_families_by_key = dict(
            getattr(func, "indirect_storage_families_by_key", {}) or {}
        )
        self.custody_condition_bindings = list(
            getattr(func, "phi_condition_custody_bindings", []) or []
        )
        self.custody_condition_observation_sids = set(
            getattr(func, "phi_condition_storage_observation_sids", set()) or set()
        )
        self.custody_parameter_initializers = list(
            getattr(func, "compute_indirect_parameter_initializers", []) or []
        )
        self.custody_parameter_initializers_by_output_sid = {
            str(record.get("output_sid")): record
            for record in self.custody_parameter_initializers
            if isinstance(record, dict) and record.get("output_sid") is not None
        }
        self.custody_active = bool(
            self.custody_indirect_contracts_by_output_sid
            or self.custody_indirect_contracts_by_op
            or self.custody_parameter_initializers
        )
        self.custody_family_descriptors = {}
        self.custody_family_by_sid = {}
        self.custody_family_by_name = {}
        self.custody_indirect_suppressions = []
        self.custody_owner_render_events = []
        self.custody_read_events = []
        self.custody_write_events = []
        self.custody_parameter_initializer_events = []
        self.custody_parameter_initializer_preamble_events = []
        self.custody_parameter_initializer_rejections = []
        self.custody_parameter_initializer_preamble_output_sids = set()
        self.custody_parameter_initializer_preamble_records_by_output_sid = {}
        self.custody_static_warnings = []
        self.custody_warnings = []
        self.custody_unresolved_address_families = set()
        self._custody_event_keys = set()

        # v46 / ABI-G: final consumers for the ABI-D plans after ABI-F has
        # attached entry-state execution ownership and predecessor-complete
        # convergence proof.  Prefer the PHIfolder handoff; the direct
        # PALCompute fields are compatibility-only for pipelines which have
        # not yet installed ABI-F.
        self.abi_function_entry_plan = dict(
            getattr(func, "phi_function_entry_abi_plan", {})
            or getattr(func, "function_entry_abi_plan", {})
            or {}
        )
        self.abi_call_site_plans_by_op = dict(
            getattr(func, "phi_call_site_abi_plans_by_op", {})
            or getattr(func, "call_site_abi_plans_by_op", {})
            or {}
        )
        self.abi_return_boundary_reconciliation = dict(
            getattr(func, "phi_return_boundary_reconciliation", {})
            or getattr(func, "compute_return_boundary_reconciliation", {})
            or {}
        )
        self.abi_entry_roots_by_sid = dict(
            getattr(func, "phi_abi_entry_roots_by_sid", {}) or {}
        )
        self.abi_entry_lineage_by_sid = dict(
            getattr(func, "phi_abi_entry_lineage_by_sid", {}) or {}
        )
        self.abi_entry_execution_owners_by_sid = dict(
            getattr(func, "phi_abi_entry_execution_owners_by_sid", {}) or {}
        )
        self.abi_entry_storage_owners_by_family = dict(
            getattr(func, "phi_abi_entry_storage_owners_by_family", {}) or {}
        )
        self.abi_entry_convergence_contracts = list(
            getattr(func, "phi_abi_entry_convergence_contracts", []) or []
        )
        self.abi_entry_convergence_by_target_sid = dict(
            getattr(func, "phi_abi_entry_convergence_by_target_sid", {}) or {}
        )
        self.abi_entry_convergence_by_join = dict(
            getattr(func, "phi_abi_entry_convergence_by_join", {}) or {}
        )
        self.abi_entry_convergence_by_pred = dict(
            getattr(func, "phi_abi_entry_convergence_by_pred", {}) or {}
        )
        self.abi_entry_custody_inventory = dict(
            getattr(func, "phi_abi_entry_custody_inventory", {}) or {}
        )
        self.abi_entry_custody_warnings = list(
            getattr(func, "phi_abi_entry_custody_warnings", []) or []
        )
        self.abi_entry_path_unbound_records = list(
            getattr(func, "phi_abi_entry_path_unbound_records", []) or []
        )
        self.abi_entry_must_print_dropin_ids = self._canonical_key_set(
            getattr(func, "phi_abi_entry_must_print_dropin_ids", set()) or set()
        )
        self.abi_entry_must_print_dropin_records = list(
            getattr(func, "phi_abi_entry_must_print_dropin_records", []) or []
        )
        # ABI-C keeps legacy HighFunction spellings as audit metadata while
        # ABI-D/F publish the canonical execution identities.  RawCond and
        # storage-family surfaces can still contain those legacy spellings, so
        # retain the resolver sidecars for an identity-only rewrite.  This is
        # never argument-placement inference.
        self.abi_implicit_inputs_by_sid = dict(
            getattr(func, "implicit_inputs", {}) or {}
        )
        self.abi_alias_contracts_by_sid = dict(
            getattr(func, "abi_alias_contracts_by_sid", {}) or {}
        )
        # Presence of the ABI-D entry plan is itself the authority boundary.
        # A simple fixed-arity leaf can legitimately have no ABI-F roots and
        # no call-site plans, while its return boundary still needs exact ABI
        # rendering.  Legacy functions have no entry plan and remain byte-for-
        # byte on the pre-v46 path.
        self.abi_active = bool(self.abi_function_entry_plan)
        self.abi_context_name = self._sanitize_name(
            getattr(func, "emitter_abi_context_name", None) or "abi_context"
        )
        self.abi_execution_name_by_sid = {}
        self.abi_convergence_alias_by_sid = {}
        self.abi_executable_identity_alias_by_sid = {}
        self.abi_raw_name_aliases = {}
        self.abi_raw_name_alias_candidates = {}
        self.abi_ambiguous_raw_name_aliases = {}
        self.abi_exact_machine_carrier_alias_sources = set()
        self.abi_immutable_context_alias_names = set()
        self.abi_immutable_context_root_ids = set()
        self.abi_immutable_context_events = []
        self.abi_unresolved_identity_events = []
        self.abi_entry_storage_initializers_by_op = {}
        self.abi_entry_storage_initializer_rejections = {}
        self.abi_entry_storage_initializer_rejected_output_sids = set()
        self.abi_fixed_argument_local_initializers_by_op = {}
        self.abi_fixed_argument_local_initializer_events = []
        self.abi_phi_entry_local_seed_contracts_by_key = {}
        self.abi_phi_entry_local_seed_events = []
        self.abi_fixed_argument_names = []
        self.abi_fixed_argument_sids = set()
        self.abi_entry_materialization_records = []
        self.abi_entry_context_records = []
        self.abi_return_boundaries_by_block = {}
        self.abi_call_plans_by_op_id = {}
        self.abi_call_plans_by_plan_id = {}
        self.abi_entry_materialization_events = []
        self.abi_entry_storage_initializer_events = []
        self.abi_fixed_argument_local_initializer_events = []
        self.abi_phi_entry_local_seed_events = []
        self.abi_call_render_events = []
        self.abi_convergence_render_events = []
        self.abi_identity_reuse_events = []
        self.abi_identity_reuse_rejections = []
        self.abi_immutable_context_events = []
        self.abi_unresolved_identity_events = []
        self.abi_phi_entry_local_seed_events = []
        self.abi_return_render_events = []
        self.abi_render_warnings = []
        self._abi_event_keys = set()

        # PHIfolder v18d+/v19 post-update alias contract.
        #
        # These describe SSA temps that are the post-update value of a state
        # variable already emitted as an assignment, e.g.:
        #     v_367 = local_14 + 1
        #     local_14 = local_14 + 1
        # Later conditions must render v_367 as local_14, not as
        # (local_14 + 1), otherwise the update is counted twice.
        self.post_update_alias_sids = set(getattr(func, "post_update_alias_sids", set()) or set())
        self.post_update_aliases = dict(getattr(func, "post_update_aliases", {}) or {})
        self.post_update_consumer_sids = set(getattr(func, "post_update_consumer_sids", set()) or set())
        self.post_update_consumer_aliases = dict(getattr(func, "post_update_consumer_aliases", {}) or {})
        self.prefer_var_expr_sids = set(getattr(func, "prefer_var_expr_sids", set()) or set())

        # Constructor-order safety: the SID alias-map builder below consumes
        # these tables even when PHIfolder legitimately exported empty maps.
        self.state_transition_alias_sids = set(
            getattr(func, "state_transition_alias_sids", set()) or set()
        )
        self.state_transition_aliases = dict(
            getattr(func, "state_transition_aliases", {}) or {}
        )

        # PHIfolder v19 bookkeeping metadata: execution-required values.
        self.condition_dependency_sids = set(getattr(func, "condition_dependency_sids", set()) or set())
        self.required_call_result_sids = set(getattr(func, "required_call_result_sids", set()) or set())
        self.protected_condition_value_sids = set(getattr(func, "protected_condition_value_sids", set()) or set())
        self.required_phi_dropin_ids = self._canonical_key_set(getattr(func, "required_phi_dropin_ids", set()) or set())
        self.non_suppressible_dropin_ids = self._canonical_key_set(getattr(func, "non_suppressible_dropin_ids", set()) or set())
        self.executable_dropin_source_sids = set(getattr(func, "executable_dropin_source_sids", set()) or set())
        self.protected_copy_temp_sids = set(getattr(func, "protected_copy_temp_sids", set()) or set())
        # ABI-F's overrides are already merged by current PHIfolder builds.
        # Union them defensively for frozen bundles produced by an early ABI-F
        # snapshot; this does not broaden either legacy suppression set.
        self.required_phi_dropin_ids.update(self.abi_entry_must_print_dropin_ids)
        self.non_suppressible_dropin_ids.update(
            self.abi_entry_must_print_dropin_ids
        )

        # PHIfolder v20 / ALPHA_SIX metadata-closure products.
        self.condition_temp_defs = list(getattr(func, "condition_temp_defs", []) or [])
        self.condition_temp_def_sids = set(getattr(func, "condition_temp_def_sids", set()) or set())
        self.post_update_condition_aliases = list(getattr(func, "post_update_condition_aliases", []) or [])
        self.post_update_condition_alias_sids = set(getattr(func, "post_update_condition_alias_sids", set()) or set())
        self.metadata_closure_events = list(getattr(func, "metadata_closure_events", []) or [])

        self.condition_temp_defs_by_sid = self._index_records_by_sid(self.condition_temp_defs, "sid")
        self.condition_temp_defs_by_consumer_addr = self._index_records_by_key(self.condition_temp_defs, "consumer_addr")
        self.post_update_aliases_by_consumer_addr = self._index_records_by_key(self.post_update_condition_aliases, "consumer_addr")

        # v25 guarded SID-backed PHIfolder metadata consumption.  These are stronger
        # than text rewrite records and fix the v_367/local_14 class:
        #   INT_ADD local_14,1 -> v_367
        #   INT_SLESS 4,v_367 -> v_436
        #   condition should render v_367 as local_14 when rendering v_436.
        self.post_update_source_target_by_sid = {}
        self.post_update_consumer_sources_by_sid = {}
        self._build_post_update_sid_alias_maps()

        # v34 SGL latch/update epilogue override metadata.
        # SGL may intentionally duplicate a simple latch/update block as both:
        #   - an explicit continue arm, and
        #   - a normal loop-body epilogue.
        # PHIfolder suppressors still own broad SSA noise cleanup, but these
        # block/source facts protect real iterator/state updates from being
        # hidden when the duplicated epilogue occurrence is printed.
        self.sgl_latch_update_block_addrs = set()
        self.sgl_latch_update_source_sids = set()
        self._build_sgl_latch_update_override_sets()

        # v30 snapshot COPY protection.  COPY(local_X) -> v_N is not a
        # transparent bridge when v_N later feeds a stack-local write.  That is
        # a value snapshot, e.g. the temp in a swap.
        self.snapshot_copy_temp_sids = set()
        self._build_snapshot_copy_temp_sids()

        # v26 transparent bridge aliases.  These are non-state temp bridges
        # such as:
        #     SUBPIECE [local_1c, 0] -> v_2228
        # They must render as local_1c inside SGL RawCond strings.
        self.transparent_expr_alias_by_sid = {}
        self._build_transparent_expr_alias_maps()

        # Condition render context.  Set while rendering compare/boolean nodes.
        self._current_condition_consumer_sid = None

        # v19h dynamic source->target aliases established while printing a
        # structured block occurrence.  If a temp source is immediately closed
        # into a PHI target by the same block, print the defining op directly
        # as target = expr and remember temp -> target for later conditions.
        self.dynamic_value_alias_by_sid = {}

        # Optional richer records for diagnostics/future printers.
        self.required_phi_dropin_records = list(getattr(func, "required_phi_dropin_records", []) or [])
        self.non_suppressible_dropin_records = list(getattr(func, "non_suppressible_dropin_records", []) or [])

        # PHIfolder v18c/v19 state-transition alias contract.
        # If a source SID is aliased to a PHI target, the normal source op
        # already emits the state write at its own block location.  The
        # matching PHI drop-in is bookkeeping, even if other metadata marks
        # it as executable.
        self.phi_source_alias_sids = set(getattr(func, "phi_source_alias_sids", set()) or set())
        self.phi_source_aliases = dict(getattr(func, "phi_source_aliases", {}) or {})
        self.state_transition_alias_sids = set(getattr(func, "state_transition_alias_sids", set()) or set())
        self.state_transition_aliases = dict(getattr(func, "state_transition_aliases", {}) or {})
        self.dropin_suppressed_by_source_alias = self._canonical_key_set(getattr(func, "dropin_suppressed_by_source_alias", set()) or set())

        # Structured-tree emission must allow the same CFG block to appear in
        # multiple branch arms when SGL intentionally duplicated a latch/tail
        # block.  Keep a recursion stack only; do not globally suppress blocks.
        self._block_emit_stack = []
        self._allow_duplicate_block_ops = False


        # PHIfolder v7 value-selector metadata.
        # A temp PHI selector can be handled upstream by aliasing its source
        # SIDs into the selector target name:
        #     v_2697 -> v_5848
        #     v_2690 -> v_5848
        # The normal CALL op then emits the executable assignment:
        #     v_5848 = transform_b(local_2c)
        # In that case, the matching PHI drop-in is bookkeeping only and must
        # not be emitted a second time.
        self.temp_phi_source_alias_sids = set(getattr(func, "temp_phi_source_alias_sids", set()) or set())
        self.temp_phi_source_aliases = getattr(func, "temp_phi_source_aliases", {}) or {}
        self.used_temp_phi_output_sids = set(getattr(func, "used_temp_phi_output_sids", set()) or set())
        self.value_selector_phi_nodes = list(getattr(func, "value_selector_phi_nodes", []) or [])

        self.lines = []
        self.indent = 0

        self.emitted_ops = set()
        self.emitted_blocks = set()
        self.emitted_returns = set()
        # v44f: retain global return suppression, but distinguish structured
        # occurrences which each own a terminal control transfer.  This set is
        # intentionally return-only; it does not relax assignment/SSA traffic
        # suppressors.
        self.emitted_return_occurrences = set()
        self.return_must_print_events = []
        self.return_suppression_events = []
        self.emitted_phi_dropins = set()

        self.debug_events = []

        # True only while rendering a structured loop header condition.
        # Used to invert compiler exit-test patterns such as:
        #     4 < i
        # into Python while-continuation:
        #     4 >= i
        self._rendering_loop_condition = False
        self._current_structured_loop_condition = None
        self.loop_condition_alias_guard_events = []
        self._loop_condition_alias_guard_event_keys = set()
        self._last_assignment = None

        # v41: values emitted as real assignments in a block occurrence may be
        # referenced by later payload expressions in that same linear execution
        # stream.  This is especially important for conditional header payload
        # blocks: a materialized LOAD such as v_416 = MEM[...] must be reused as
        # v_416 by the following checksum/condition expressions rather than
        # re-rendered as another MEM[...] or leaked through suppressed address
        # temps.  This is emitter-local presentation/provenance state only.
        self.materialized_runtime_value_sids = set()

        # v37 expression-rendering context.  The emitter may need to inline a
        # same-block pure SSA temp on an assignment RHS when PHIfolder/SGL has
        # suppressed the temp assignment.  Keep the context narrow so condition
        # and branch-polarty logic remain owned by SGL/EdgeTruth.
        self._current_expr_op = None
        self._current_expr_block_addr = None

        # v19c printer contract:
        # Default to state-machine-preserving structured while/if output.
        # Do not reconstruct for/range loops unless the driver explicitly
        # opts in. PAL's current priority is programmatic truth, not source
        # prettification.
        self.enable_for_loop_recovery = bool(getattr(func, "enable_for_loop_recovery", False))

        self._build_storage_custody_consumer_v45()
        self._build_abi_custody_consumer_v46()
        self.abi_static_warnings = list(self.abi_render_warnings)


    def _transparent_alias_source_name(self, x):
        """
        Constructor-safe source rendering for transparent bridge aliases.

        Used by _transparent_expr_alias_for_node() while __init__ is still
        building metadata maps. Do not call _expr() here, because _expr()
        depends on runtime fields such as dynamic_value_alias_by_sid that may
        not be initialized yet.

        Main case:
            SUBPIECE [local_1c, 0] -> v_2228
        should produce:
            v_2228 -> local_1c
        """

        if x is None:
            return None

        if hasattr(x, "var"):
            x = x.var

        if getattr(x, "is_constant", False):
            try:
                return self._const(x)
            except Exception:
                return str(getattr(x, "const_value", getattr(x, "value", 0)))

        sid = getattr(x, "ssa_id", None)

        if sid is not None:
            if sid in self.var_map:
                return self.var_map[sid]
            if str(sid) in self.var_map:
                return self.var_map[str(sid)]

        name = getattr(x, "name", None)
        if name:
            return self._sanitize_name(name)

        if sid is not None:
            return self._sanitize_name(str(sid))

        return self._sanitize_name(str(x))




    # ---------------------------------------------------------
    # SEMANTIC GRAPH LOADING
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

    def _canonical_key_set(self, values):

        out = set()

        for v in list(values or []):
            try:
                out.add(tuple(v))
            except Exception:
                out.add(v)

        return out

    def _index_records_by_sid(self, records, key):
        out = {}
        for rec in list(records or []):
            sid = rec.get(key) if isinstance(rec, dict) else None
            if sid is None:
                continue
            out.setdefault(sid, []).append(rec)
            out.setdefault(str(sid), []).append(rec)
        return out

    def _index_records_by_key(self, records, key):
        out = {}
        for rec in list(records or []):
            val = rec.get(key) if isinstance(rec, dict) else None
            if val is None:
                continue
            out.setdefault(val, []).append(rec)
            out.setdefault(str(val), []).append(rec)
        return out

    # =========================================================
    # SGL LATCH / EPILOGUE OVERRIDE METADATA
    # =========================================================

    def _addr_variants(self, addr):
        """Return robust lookup variants for an address-like value."""
        out = set()
        if addr is None:
            return out
        out.add(addr)
        out.add(str(addr))
        try:
            i = int(addr, 0) if isinstance(addr, str) else int(addr)
            out.add(i)
            out.add(str(i))
            out.add(hex(i))
        except Exception:
            pass
        return out

    def _sid_variants(self, sid):
        out = set()
        if sid is None:
            return out
        out.add(sid)
        out.add(str(sid))
        s = str(sid)
        if s.startswith("v_") and s[2:].isdigit():
            out.add(s[2:])
            try:
                out.add(int(s[2:]))
            except Exception:
                pass
        elif s.isdigit():
            out.add("v_" + s)
            try:
                out.add(int(s))
            except Exception:
                pass
        return out

    def _record_sgl_latch_update_block(self, addr):
        for a in self._addr_variants(addr):
            self.sgl_latch_update_block_addrs.add(a)

    def _record_sgl_latch_update_sid(self, sid):
        for s in self._sid_variants(sid):
            self.sgl_latch_update_source_sids.add(s)

    def _build_sgl_latch_update_override_sets(self):
        """
        Consume SGL/GraphBuilder latch metadata as a narrow suppressor override.

        This does not make emission decisions by itself. It only records which
        source SIDs and block addresses have been classified upstream as
        executable loop latch/update facts. _should_suppress_assignment() can
        then avoid hiding such state updates in duplicated normal-epilogue
        occurrences.
        """
        facts = getattr(self.func, "latch_update_facts", None)

        if isinstance(facts, dict):
            iterable = facts.values()
        elif isinstance(facts, (list, tuple, set)):
            iterable = facts
        else:
            iterable = []

        for info in list(iterable or []):
            if not isinstance(info, dict):
                continue

            for key in ("latch_blocks", "update_blocks", "blocks"):
                for addr in list(info.get(key, []) or []):
                    self._record_sgl_latch_update_block(addr)

            for rec in list(info.get("updates", []) or []):
                if not isinstance(rec, dict):
                    continue
                self._record_sgl_latch_update_block(rec.get("block"))
                self._record_sgl_latch_update_sid(
                    rec.get("source_sid")
                    if rec.get("source_sid") is not None
                    else rec.get("sid")
                )

        # Some SGL versions expose a consolidated handoff. Accept the same
        # shapes under it without requiring a specific version string.
        handoff = getattr(self.func, "sgl_structuring_handoff", None)
        if isinstance(handoff, dict):
            for key in ("latch_update_facts", "loop_latch_ownership", "loop_latch_update_facts"):
                sub = handoff.get(key)
                if isinstance(sub, dict):
                    vals = sub.values()
                elif isinstance(sub, (list, tuple, set)):
                    vals = sub
                else:
                    vals = []
                for info in list(vals or []):
                    if not isinstance(info, dict):
                        continue
                    for bkey in ("latch_blocks", "update_blocks", "blocks"):
                        for addr in list(info.get(bkey, []) or []):
                            self._record_sgl_latch_update_block(addr)
                    for rec in list(info.get("updates", []) or []):
                        if isinstance(rec, dict):
                            self._record_sgl_latch_update_block(rec.get("block"))
                            self._record_sgl_latch_update_sid(rec.get("source_sid") if rec.get("source_sid") is not None else rec.get("sid"))

    def _current_block_is_sgl_latch_update(self):
        addr = getattr(self, "_current_block_addr", None)
        if addr is None:
            return False
        return any(a in self.sgl_latch_update_block_addrs for a in self._addr_variants(addr))

    def _is_sgl_latch_update_source_sid(self, sid):
        if sid is None:
            return False
        return any(s in self.sgl_latch_update_source_sids for s in self._sid_variants(sid))

    def _is_sgl_latch_epilogue_override_op(self, op):
        """
        Narrow override for duplicated SGL loop latch/update epilogues.

        Generic rule:
          - current block was classified by SGL/GraphBuilder as a latch/update
            block;
          - op defines the latch/update source SID, or the op is an arithmetic
            state update that closes through a PHI/drop-in for this block;
          - output is presented as a real local/state variable.

        This protects iterator updates such as local_i = local_i + 1 without
        weakening global SSA suppression.
        """
        if op is None or not self._current_block_is_sgl_latch_update():
            return False

        oc = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        sid = self._sid_of(out)

        if sid is None:
            return False

        if self._is_sgl_latch_update_source_sid(sid):
            return True

        if oc not in ("INT_ADD", "INT_SUB"):
            return False

        # If the block has a PHI/drop-in closing this source into a target,
        # it is an executable state transition even when the SID is globally
        # marked as post-update/presentation alias.
        rec = self._branch_closure_record_for_source_sid(sid)
        if rec is not None and rec.get("target") is not None:
            return True

        # Last fallback: PHIfolder may expose only the post-update target map.
        target = self._post_update_target_for_source_sid(sid, None)
        return bool(target)

    def _reset_assignment_boundary(self):
        """
        Assignment duplicate suppression is linear-text local, not a control
        flow fact. Reset it at structured control-flow boundaries so an
        assignment in one branch cannot suppress the same required assignment
        in a later join/epilogue occurrence.

        v40: materialized expression reuse is also linear-text local.  If a
        pure temp was just assigned immediately before a condition, the
        condition may reuse the temp name; once we cross a structured boundary,
        that alias is no longer safe.
        """
        self._last_assignment = None
        self._last_value_expr_alias = None

    def _iter_sid_info_records(self, obj):
        """
        Normalize metadata containers from PHIfolder.  Different PAL versions
        have used dicts, lists of records, and pair lists.
        """
        if isinstance(obj, dict):
            for sid, info in obj.items():
                if isinstance(info, dict):
                    yield sid, info
                else:
                    yield sid, {"target_name": info}
            return

        if isinstance(obj, (list, tuple, set)):
            for item in obj:
                if isinstance(item, dict):
                    sid = (
                        item.get("source_sid")
                        if item.get("source_sid") is not None
                        else item.get("sid")
                    )
                    if sid is not None:
                        yield sid, item
                    continue
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    sid, info = item
                    if isinstance(info, dict):
                        yield sid, info
                    else:
                        yield sid, {"target_name": info}

    def _build_post_update_sid_alias_maps(self):
        """
        Build SID-backed alias maps from all PHIfolder post-update products.

        Output:
          post_update_source_target_by_sid[source_sid] = target_name
          post_update_consumer_sources_by_sid[consumer_sid][source_sid] = target_name
        """

        def add_source(source_sid, target_name):
            if source_sid is None or not target_name:
                return
            name = self._sanitize_name(str(target_name))
            self.post_update_source_target_by_sid[source_sid] = name
            self.post_update_source_target_by_sid[str(source_sid)] = name

        def add_consumer(consumer_sid, source_sid, target_name):
            if consumer_sid is None or source_sid is None or not target_name:
                return
            name = self._sanitize_name(str(target_name))
            for ckey in (consumer_sid, str(consumer_sid)):
                bucket = self.post_update_consumer_sources_by_sid.setdefault(ckey, {})
                bucket[source_sid] = name
                bucket[str(source_sid)] = name

        for sid, info in self._iter_sid_info_records(getattr(self.func, "post_update_aliases", {}) or self.post_update_aliases):
            add_source(sid, info.get("target_name"))

        for rec in list(self.post_update_condition_aliases or []):
            if not isinstance(rec, dict):
                continue
            ssid = rec.get("source_sid")
            csid = (
                rec.get("condition_consumer_sid")
                if rec.get("condition_consumer_sid") is not None
                else rec.get("consumer_sid")
            )
            target = rec.get("target_name")

            # Important v25 guard:
            # A condition-alias record alone does not authorize renaming the
            # source temp's assignment LHS.  It only authorizes rendering that
            # source temp as the target while rendering the stated condition
            # consumer.  Otherwise a read-only parity test record can corrupt:
            #     v_247 = local_14 & 1
            # into:
            #     local_14 = local_14 & 1
            add_consumer(csid, ssid, target)

            # Global source->target renaming is allowed only when PHIfolder
            # also exported the source as a real post-update/state-write alias.
            if (
                ssid in self.post_update_alias_sids
                or str(ssid) in self.post_update_alias_sids
                or ssid in self.state_transition_alias_sids
                or str(ssid) in self.state_transition_alias_sids
            ):
                add_source(ssid, target)

        for sid, info in self._iter_sid_info_records(getattr(self.func, "post_update_consumer_aliases", {}) or self.post_update_consumer_aliases):
            # Some PHIfolder versions key this table by consumer SID and store
            # source_sid/target_name inside the record.
            csid = sid
            ssid = info.get("source_sid")
            target = info.get("target_name")
            add_source(ssid, target)
            add_consumer(csid, ssid, target)

        for sid, info in self._iter_sid_info_records(getattr(self.func, "state_transition_aliases", {}) or self.state_transition_aliases):
            # Do not treat every state transition as a post-update condition
            # alias, but make it available to _alias_target_name_for_sid when
            # PHIfolder explicitly marked sid as post-update.
            if sid in self.post_update_alias_sids or str(sid) in self.post_update_alias_sids:
                add_source(sid, info.get("target_name"))

    def _post_update_target_for_source_sid(self, source_sid, consumer_sid=None):
        if source_sid is None:
            return None

        if consumer_sid is not None:
            bucket = (
                self.post_update_consumer_sources_by_sid.get(consumer_sid)
                or self.post_update_consumer_sources_by_sid.get(str(consumer_sid))
            )
            if bucket:
                target = bucket.get(source_sid) or bucket.get(str(source_sid))
                if target:
                    return target

        if consumer_sid is None:
            return (
                self.post_update_source_target_by_sid.get(source_sid)
                or self.post_update_source_target_by_sid.get(str(source_sid))
            )

        return None

    def _expr_with_condition_consumer(self, x, consumer_sid, seen=None):
        old = self._current_condition_consumer_sid
        self._current_condition_consumer_sid = consumer_sid
        try:
            return self._expr(x, seen)
        finally:
            self._current_condition_consumer_sid = old

    def _build_snapshot_copy_temp_sids(self):
        """
        Detect COPY(local_X) -> temp snapshots that must remain executable.

        This is intentionally expression-logic based, not address/test based.

        Transparent bridge:
            CAST(local_20) -> v
            ZEXT(v) -> w
            CALL printf(..., w)
            safe to fold.

        Snapshot:
            COPY(local_20) -> v_old
            ... local_20 is overwritten ...
            COPY(v_old) -> local_1c
            must emit v_old = local_20.

        Conservative generic rule:
            If COPY reads a stack local into a non-stack temp, and that temp is
            later consumed by an op that writes a stack local, protect it.
        """

        self.snapshot_copy_temp_sids = set()

        users = {}
        copy_sources = {}

        for op in self._iter_all_ops():
            out = getattr(op, "output", None)
            out_sid = self._sid_of(out)
            for inp in list(getattr(op, "inputs", []) or []):
                isid = self._sid_of(inp)
                if isid is not None:
                    users.setdefault(isid, []).append(op)
                    users.setdefault(str(isid), []).append(op)

            if getattr(op, "opcode", None) != "COPY":
                continue

            ins = list(getattr(op, "inputs", []) or [])
            if not ins or out_sid is None:
                continue

            src = ins[0]
            if not self._is_stack_local_var(src):
                continue

            # A COPY into the same local is an initializer/state write, not a
            # temp snapshot.
            if self._is_stack_local_var(out):
                continue

            copy_sources[out_sid] = src

        for sid, src in list(copy_sources.items()):
            for user in list(users.get(sid, []) or []) + list(users.get(str(sid), []) or []):
                if user is None:
                    continue

                uoc = getattr(user, "opcode", None)
                uout = getattr(user, "output", None)

                # Calls/returns only observe values. They do not by themselves
                # make a local snapshot necessary.
                if uoc in ("CALL", "CALLIND", "RETURN", "CBRANCH", "BRANCH", "BRANCHIND"):
                    continue

                if self._is_stack_local_var(uout):
                    self.snapshot_copy_temp_sids.add(sid)
                    self.snapshot_copy_temp_sids.add(str(sid))
                    break

    def _iter_all_ops(self):
        seen_blocks = set()

        for block in list(getattr(self.func, "blocks", []) or []):
            bid = id(block)
            if bid in seen_blocks:
                continue
            seen_blocks.add(bid)
            for op in list(getattr(block, "ops", []) or []):
                yield op
            term = getattr(block, "terminator", None)
            if term is not None:
                yield term

        # Some PAL objects expose CFG nodes rather than func.blocks.
        for cfg in list(getattr(self.func, "cfg_nodes", []) or []):
            block = getattr(cfg, "block", None)
            if block is None:
                continue
            bid = id(block)
            if bid in seen_blocks:
                continue
            seen_blocks.add(bid)
            for op in list(getattr(block, "ops", []) or []):
                yield op
            term = getattr(block, "terminator", None)
            if term is not None:
                yield term



    def _build_transparent_expr_alias_maps(self):
        """
        Build non-state expression aliases for transparent/width bridge temps.

        Main Sample X case:
            SUBPIECE [local_1c, 0] -> v_2228

        SGL RawCond may already contain textual v_2228:
            ((v_5848 >> (v_2228 & 0x1f)) & 1) == 0

        Since v_2228 has no executable assignment, RawCond must be rewritten to
        local_1c before printing.
        """

        self.transparent_expr_alias_by_sid = {}

        for sid, node in list((getattr(self, "nodes", {}) or {}).items()):
            # v33: transparent aliases are for non-state bridge temps only.
            # A transparent-looking op that writes a stack local is executable
            # state, e.g. COPY [v_4658] -> local_1c in a swap.  Do not place
            # such outputs into transparent_expr_alias_by_sid.
            out_var = getattr(node, "var", None)
            if self._is_stack_local_var(out_var):
                continue

            alias = self._transparent_expr_alias_for_node(node)
            if not alias:
                continue

            osid = self._sid_of(getattr(node, "var", None))
            if osid is None:
                osid = sid

            self.transparent_expr_alias_by_sid[osid] = alias
            self.transparent_expr_alias_by_sid[str(osid)] = alias

            s_osid = str(osid)
            if s_osid.startswith("v_") and s_osid[2:].isdigit():
                self.transparent_expr_alias_by_sid[s_osid[2:]] = alias
                try:
                    self.transparent_expr_alias_by_sid[int(s_osid[2:])] = alias
                except Exception:
                    pass
            elif s_osid.isdigit():
                self.transparent_expr_alias_by_sid["v_" + s_osid] = alias
                try:
                    self.transparent_expr_alias_by_sid[int(s_osid)] = alias
                except Exception:
                    pass

    def _transparent_expr_alias_for_node(self, node):
        if node is None:
            return None

        # v43: width-changing conversions are not presentation-transparent
        # once PALCompute assigned them a runtime helper.
        plan = self._c_truth_plan_for_node(node) if hasattr(self, "c_truth_active") else None
        if (
            getattr(self, "c_truth_active", False)
            and isinstance(plan, dict)
            and plan.get("runtime_helper")
        ):
            return None

        # v33 safety: transparent aliases must never target real stack-local
        # outputs.  CAST/ZEXT/SUBPIECE temps may fold; local writes may not.
        if self._is_stack_local_var(getattr(node, "var", None)):
            return None

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if not inputs:
            return None

        # COPY/CAST/ZEXT/SEXT/TRUNC of a named local/temp are transparent for
        # expression rendering when PHIfolder did not materialize them.
        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC"):
            sid = self._sid_of(getattr(node, "var", None))
            if opcode == "COPY" and (
                sid in getattr(self, "snapshot_copy_temp_sids", set())
                or str(sid) in getattr(self, "snapshot_copy_temp_sids", set())
            ):
                return None

            src = inputs[0]
            if getattr(src, "is_constant", False):
                return None
            return self._transparent_alias_source_name(src)

        # SUBPIECE(x, 0) is a low-piece extraction.  For current PAL integer
        # helper policy, this should render as x when x is already the local
        # scalar being tested.  Width/sign helper correctness belongs later.
        if opcode == "SUBPIECE":
            if len(inputs) < 1:
                return None

            off = inputs[1] if len(inputs) >= 2 else None
            if off is not None and getattr(off, "is_constant", False):
                try:
                    if int(getattr(off, "const_value", getattr(off, "value", getattr(off, "offset", 0)))) != 0:
                        return None
                except Exception:
                    return None

            src = inputs[0]
            if getattr(src, "is_constant", False):
                return None

            return self._transparent_alias_source_name(src)

        return None

    def _transparent_expr_alias_for_sid(self, sid):
        """
        Lookup a transparent non-state alias by SID and recursively collapse
        alias chains.

        Sample X final-call case:
            CAST     [local_28] -> v_6642
            INT_ZEXT [v_6642]   -> v_4949

        The map may first contain:
            v_4949 -> v_6642
            v_6642 -> local_28

        This helper returns:
            v_4949 -> local_28
        """

        if sid is None:
            return None

        if self._c_truth_contract_for_sid_has_helper(sid):
            return None

        table = getattr(self, "transparent_expr_alias_by_sid", {}) or {}

        def keys_for(x):
            keys = [x, str(x)]
            s = str(x)
            if s.startswith("v_") and s[2:].isdigit():
                keys.append(s[2:])
                try:
                    keys.append(int(s[2:]))
                except Exception:
                    pass
            elif s.isdigit():
                keys.append("v_" + s)
                try:
                    keys.append(int(s))
                except Exception:
                    pass
            return keys

        cur = sid
        seen = set()

        for _ in range(8):
            hit = None
            for k in keys_for(cur):
                if k in table:
                    hit = table[k]
                    break

            if not hit:
                return cur if cur != sid and isinstance(cur, str) else None

            hit_s = str(hit)
            if hit_s in seen:
                return hit_s

            seen.add(hit_s)

            # If the alias itself names another transparent temp, continue.
            found_next = False
            for k in keys_for(hit_s):
                if k in table:
                    cur = hit_s
                    found_next = True
                    break

            if found_next:
                continue

            return hit_s

        return str(cur) if cur != sid else None


    def _apply_transparent_expr_alias_rewrites(self, s):
        if not s or not getattr(self, "transparent_expr_alias_by_sid", None):
            return s

        out = str(s)
        pairs = []

        for sid, target in list(self.transparent_expr_alias_by_sid.items()):
            if sid is None or not target:
                continue

            raw = str(sid)
            names = {raw}

            if raw.isdigit():
                names.add("v_%s" % raw)
            elif raw.startswith("v_"):
                names.add(raw)

            for name in names:
                if name and name != target:
                    pairs.append((name, str(target)))

        for name, target in sorted(set(pairs), key=lambda kv: len(kv[0]), reverse=True):
            out = re.sub(r"\b%s\b" % re.escape(name), target, out)

        return out

    # =========================================================
    # v45 / INDIRECT STORAGE-CUSTODY CONSUMER
    # =========================================================

    def _custody_sid_keys_v45(self, sid):
        if sid is None:
            return []
        text = str(sid)
        keys = [sid, text]
        if text.startswith("v_") and text[2:].isdigit():
            keys.extend([text[2:], int(text[2:])])
        elif text.isdigit():
            keys.extend(["v_%s" % text, int(text)])
        result = []
        seen = set()
        for key in keys:
            marker = (type(key).__name__, str(key))
            if marker in seen:
                continue
            seen.add(marker)
            result.append(key)
        return result

    def _custody_lookup_sid_v45(self, mapping, sid):
        if not isinstance(mapping, dict):
            return None
        for key in self._custody_sid_keys_v45(sid):
            if key in mapping:
                return mapping.get(key)
        return None

    def _custody_binding_for_sid_v45(self, sid):
        return self._custody_lookup_sid_v45(
            self.custody_storage_bindings_by_sid, sid
        )

    def _custody_contract_for_sid_v45(self, sid):
        return self._custody_lookup_sid_v45(
            self.custody_indirect_contracts_by_output_sid, sid
        )

    def _custody_pointer_width_v45(self):
        model = getattr(self.func, "target_numeric_model", {}) or {}
        for key in (
            "pointer_width_bits", "address_width_bits", "pointer_bits",
            "default_pointer_width_bits",
        ):
            width = model.get(key) if isinstance(model, dict) else None
            if isinstance(width, int) and width > 0:
                return width
        return 64

    def _custody_signed_offset_v45(self, value, width=None):
        if value is None:
            return None
        try:
            raw = int(value)
        except Exception:
            return None
        width = width or self._custody_pointer_width_v45()
        if isinstance(width, int) and width > 0:
            modulus = 1 << width
            raw &= modulus - 1
            sign = 1 << (width - 1)
            if raw & sign:
                raw -= modulus
        return raw

    def _custody_offset_text_v45(self, value):
        value = self._custody_signed_offset_v45(value)
        if value is None:
            return None
        if value < 0:
            return "-0x%x" % abs(value)
        if value >= 10:
            return "0x%x" % value
        return str(value)

    def _custody_representative_from_contract_v45(self, contract, family_id):
        if not isinstance(contract, dict):
            return None
        lifter = contract.get("lifter_indirect_custody_contract") or {}
        for key in ("output_storage", "prior_storage"):
            storage = lifter.get(key) or {}
            high = storage.get("high_variable") or {}
            representative = high.get("representative")
            if not isinstance(representative, dict):
                continue
            storage_family = contract.get("storage_family_id")
            if family_id is None or str(storage_family) == str(family_id):
                return dict(representative)
        return None

    def _custody_representative_from_sid_v45(self, sid):
        node = self.nodes.get(sid) or self.nodes.get(str(sid))
        var = getattr(node, "var", None) if node is not None else None
        if var is None:
            return None
        evidence = getattr(var, "numeric_evidence", {}) or {}
        high = evidence.get("high_variable") or {}
        representative = high.get("representative")
        return dict(representative) if isinstance(representative, dict) else None

    def _custody_ptrsub_index_v45(self):
        by_offset = {}
        bases = {}
        pointer_width = self._custody_pointer_width_v45()
        for node in self.nodes.values():
            if getattr(node, "opcode", None) != "PTRSUB":
                continue
            inputs = list(getattr(node, "inputs", []) or [])
            if len(inputs) < 2:
                continue
            offset = self._const_int_value(inputs[1])
            offset = self._custody_signed_offset_v45(offset, pointer_width)
            if offset is None:
                continue
            base = inputs[0]
            by_offset.setdefault(offset, base)
            base_sid = self._sid_of(base)
            if base_sid is not None:
                bases[str(base_sid)] = base
        return by_offset, list(bases.values())

    def _build_storage_custody_consumer_v45(self):
        if not self.custody_active:
            return

        families_by_id = {}
        for family in self.custody_storage_families_by_key.values():
            if not isinstance(family, dict):
                continue
            family_id = family.get("family_id")
            if family_id is not None:
                families_by_id[str(family_id)] = family

        ptrsub_by_offset, stack_bases = self._custody_ptrsub_index_v45()
        pointer_width = self._custody_pointer_width_v45()

        # First establish family membership and canonical HighVariable names.
        for sid, binding in self.custody_storage_bindings_by_sid.items():
            if not isinstance(binding, dict):
                continue
            family_id = binding.get("family_id")
            if family_id is None:
                continue
            family_key = str(family_id)
            family = families_by_id.get(family_key, {})
            descriptor = self.custody_family_descriptors.setdefault(
                family_key,
                {
                    "kind": "emitter_storage_family_descriptor_v45",
                    "version": self.VERSION,
                    "family_id": family_id,
                    "high_name": (
                        binding.get("high_name") or family.get("high_name")
                    ),
                    "classification": (
                        binding.get("classification")
                        or family.get("classification")
                    ),
                    "address_tied": bool(
                        binding.get("address_tied")
                        or family.get("address_tied")
                    ),
                    "persistent": bool(
                        binding.get("persistent") or family.get("persistent")
                    ),
                    "member_sids": [],
                    "representative": None,
                    "width_bits": None,
                    "stack_base": None,
                    "memory_backed": False,
                    "address_resolved": False,
                },
            )
            sid_text = str(binding.get("sid") or sid)
            if sid_text not in descriptor["member_sids"]:
                descriptor["member_sids"].append(sid_text)
            self.custody_family_by_sid[sid_text] = descriptor

        # Contracts retain the serialized HighVariable representative that
        # identifies a real RAM or stack storage location.
        for sid, contract in self.custody_indirect_contracts_by_output_sid.items():
            if not isinstance(contract, dict):
                continue
            family_id = contract.get("storage_family_id")
            descriptor = self.custody_family_descriptors.get(str(family_id))
            if descriptor is None:
                continue
            if descriptor.get("representative") is None:
                representative = self._custody_representative_from_contract_v45(
                    contract, family_id
                )
                if representative is None:
                    representative = self._custody_representative_from_sid_v45(sid)
                if representative is not None:
                    descriptor["representative"] = representative
            width = contract.get("output_width_bits")
            if isinstance(width, int) and width > 0:
                descriptor["width_bits"] = width

        # Fill names/widths from resolver family records when no transition
        # happened to carry the strongest image first.
        for family_key, descriptor in self.custody_family_descriptors.items():
            family = families_by_id.get(family_key, {})
            if not descriptor.get("high_name"):
                descriptor["high_name"] = family.get("high_name")
            if not descriptor.get("width_bits"):
                datatype = family.get("declared_datatype") or {}
                size = datatype.get("length") or datatype.get("size")
                if isinstance(size, int) and size > 0:
                    descriptor["width_bits"] = size * 8
            if not descriptor.get("width_bits"):
                descriptor["width_bits"] = 64 if descriptor.get("persistent") else 32

            high_name = descriptor.get("high_name")
            if high_name:
                high_name = self._sanitize_name(str(high_name))
                descriptor["high_name"] = high_name
                self.custody_family_by_name[high_name] = descriptor

            representative = descriptor.get("representative") or {}
            space = representative.get("space")
            offset = representative.get("offset")
            size = representative.get("size")
            if isinstance(size, int) and size > 0:
                descriptor["width_bits"] = size * 8
            descriptor["storage_space"] = space
            descriptor["storage_offset"] = offset
            descriptor["memory_backed"] = bool(
                descriptor.get("address_tied") or descriptor.get("persistent")
            )

            if space == "ram" and offset is not None:
                descriptor["address_resolved"] = True
            elif space == "stack" and offset is not None:
                normalized = self._custody_signed_offset_v45(offset, pointer_width)
                descriptor["storage_offset"] = normalized
                base = ptrsub_by_offset.get(normalized)
                if base is None and len(stack_bases) == 1:
                    base = stack_bases[0]
                descriptor["stack_base"] = base
                descriptor["address_resolved"] = base is not None

            if descriptor.get("memory_backed") and not descriptor.get("address_resolved"):
                self.custody_unresolved_address_families.add(family_key)
                self.custody_static_warnings.append({
                    "kind": "emitter_storage_family_address_unresolved_v45",
                    "family_id": descriptor.get("family_id"),
                    "high_name": descriptor.get("high_name"),
                    "classification": descriptor.get("classification"),
                    "representative": representative or None,
                    "action": "render_canonical_family_name_and_defer_memory_synchronization",
                })

    def _custody_descriptor_for_sid_v45(self, sid):
        if sid is None:
            return None
        descriptor = self.custody_family_by_sid.get(str(sid))
        if descriptor is not None:
            return descriptor
        binding = self._custody_binding_for_sid_v45(sid)
        family_id = binding.get("family_id") if isinstance(binding, dict) else None
        return self.custody_family_descriptors.get(str(family_id))

    def _custody_address_expr_v45(self, descriptor):
        if not isinstance(descriptor, dict) or not descriptor.get("address_resolved"):
            return None
        space = descriptor.get("storage_space")
        offset = descriptor.get("storage_offset")
        if space == "ram":
            try:
                return hex(int(offset)) if abs(int(offset)) >= 10 else str(int(offset))
            except Exception:
                return None
        if space == "stack":
            base = descriptor.get("stack_base")
            if base is None:
                return None
            base_expr = self._var(base)
            offset_expr = self._custody_offset_text_v45(offset)
            if offset_expr is None:
                return None
            width = self._custody_pointer_width_v45()
            self.c_truth_required_helpers.add("c_ptrsub")
            return "c_ptrsub(%s, %s, %s)" % (base_expr, offset_expr, width)
        return None

    def _custody_record_event_v45(self, collection, event, key):
        marker = (self.render_mode, key)
        if marker in self._custody_event_keys:
            return
        self._custody_event_keys.add(marker)
        collection.append(event)

    def _custody_read_expr_for_sid_v45(self, sid, context="expression"):
        descriptor = self._custody_descriptor_for_sid_v45(sid)
        if not isinstance(descriptor, dict):
            return None
        name = descriptor.get("high_name")
        if not name:
            return None

        if self._is_readable_render_v44():
            projected = name
        else:
            address = self._custody_address_expr_v45(descriptor)
            if descriptor.get("memory_backed") and address is not None:
                width = int(descriptor.get("width_bits") or 32)
                self.c_truth_required_helpers.add("c_load")
                projected = "c_load(MEM, %s, %s)" % (address, width)
            else:
                projected = name

        self._custody_record_event_v45(
            self.custody_read_events,
            {
                "kind": "emitter_storage_family_read_v45",
                "version": self.VERSION,
                "projection": self.render_mode,
                "sid": str(sid),
                "family_id": descriptor.get("family_id"),
                "high_name": name,
                "context": context,
                "memory_backed": bool(descriptor.get("memory_backed")),
                "address_resolved": bool(descriptor.get("address_resolved")),
                "rendered": projected,
            },
            ("read", str(sid), context, projected),
        )
        return projected

    def _custody_wrap_assignment_expr_v45(self, lhs, expr, sid=None):
        if self._is_readable_render_v44() or not self.custody_active:
            return expr
        descriptor = self._custody_descriptor_for_sid_v45(sid)
        if not isinstance(descriptor, dict):
            descriptor = self.custody_family_by_name.get(str(lhs))
        if not isinstance(descriptor, dict) or not descriptor.get("memory_backed"):
            return expr
        address = self._custody_address_expr_v45(descriptor)
        if address is None:
            return expr
        width = int(descriptor.get("width_bits") or 32)
        self.c_truth_required_helpers.update(("c_load", "c_store"))
        wrapped = (
            "(lambda _pal_v: (c_store(MEM, %s, _pal_v, %s), "
            "c_load(MEM, %s, %s))[1])(%s)"
            % (address, width, address, width, expr)
        )
        self._custody_record_event_v45(
            self.custody_write_events,
            {
                "kind": "emitter_storage_family_write_through_v45",
                "version": self.VERSION,
                "projection": self.render_mode,
                "family_id": descriptor.get("family_id"),
                "high_name": lhs,
                "width_bits": width,
                "address": address,
                "source_expr": expr,
                "rendered": wrapped,
            },
            ("write", str(lhs), str(expr), address),
        )
        return wrapped

    def _custody_consume_indirect_op_v45(self, op):
        if getattr(op, "opcode", None) != "INDIRECT":
            return False
        out = getattr(op, "output", None)
        sid = self._sid_of(out)
        contract = self._custody_contract_for_sid_v45(sid)
        descriptor = self._custody_descriptor_for_sid_v45(sid)
        resolved = bool(
            isinstance(contract, dict)
            and contract.get("custody_resolved") is True
            and contract.get("indirect_runtime_operation") is False
            and contract.get("runtime_helper") is None
            and contract.get("effect_owner_compute_op_key") is not None
        )
        if not resolved:
            self.custody_warnings.append({
                "kind": "emitter_indirect_custody_unresolved_v45",
                "sid": sid,
                "op_key": contract.get("op_key") if isinstance(contract, dict) else None,
                "status": contract.get("status") if isinstance(contract, dict) else None,
                "action": "suppress_nonruntime_INDIRECT_but_flag_executable_projection",
            })
        high_name = descriptor.get("high_name") if isinstance(descriptor, dict) else None
        if sid is not None and high_name:
            self.dynamic_value_alias_by_sid[sid] = high_name
            self.dynamic_value_alias_by_sid[str(sid)] = high_name
        self._custody_record_event_v45(
            self.custody_indirect_suppressions,
            {
                "kind": "emitter_indirect_metadata_transition_suppressed_v45",
                "version": self.VERSION,
                "projection": self.render_mode,
                "sid": sid,
                "family_id": descriptor.get("family_id") if isinstance(descriptor, dict) else None,
                "high_name": high_name,
                "resolved": resolved,
                "indirect_op_key": contract.get("op_key") if isinstance(contract, dict) else None,
                "effect_owner_compute_op_key": (
                    contract.get("effect_owner_compute_op_key")
                    if isinstance(contract, dict) else None
                ),
                "emitted_runtime_expression": False,
            },
            ("indirect", sid, contract.get("op_key") if isinstance(contract, dict) else None),
        )
        return True

    def _custody_note_effect_owner_emitted_v45(self, op):
        if not self.custody_active or op is None:
            return
        contract = self._c_truth_plan_for_op(op)
        if not isinstance(contract, dict):
            return
        effects = list(contract.get("indirect_custody_effects_owned", []) or [])
        if not effects:
            effects = list(
                self.custody_effect_owners_by_op.get(contract.get("op_key"), [])
                or []
            )
        if not effects:
            return
        family_ids = []
        output_sids = []
        for effect in effects:
            family_id = effect.get("family_id")
            output_sid = effect.get("output_sid")
            if family_id is not None and family_id not in family_ids:
                family_ids.append(family_id)
            if output_sid is not None and output_sid not in output_sids:
                output_sids.append(output_sid)
        self._custody_record_event_v45(
            self.custody_owner_render_events,
            {
                "kind": "emitter_storage_effect_owner_rendered_v45",
                "version": self.VERSION,
                "projection": self.render_mode,
                "owner_compute_op_key": contract.get("op_key"),
                "owner_op_id": contract.get("op_id"),
                "owner_opcode": contract.get("opcode"),
                "owner_block_addr": contract.get("block_addr"),
                "custody_transitions": len(effects),
                "storage_family_ids": family_ids,
                "output_sids": output_sids,
                "runtime_policy": "owner_executes_once_later_reads_observe_family_storage",
            },
            ("owner", contract.get("op_key")),
        )

    def _custody_effects_owned_by_op_v45(self, op):
        """Return custody transitions owned by a real CALL/STORE operation."""
        if not self.custody_active or op is None:
            return []
        contract = self._c_truth_plan_for_op(op)
        if not isinstance(contract, dict):
            return []
        effects = list(contract.get("indirect_custody_effects_owned", []) or [])
        if effects:
            return effects
        return list(
            self.custody_effect_owners_by_op.get(contract.get("op_key"), [])
            or []
        )

    def _custody_parameter_initializer_for_op_v45(self, op):
        if not self.custody_active or op is None:
            return None
        contract = self._c_truth_plan_for_op(op)
        if isinstance(contract, dict):
            initializer = contract.get("parameter_storage_initializer")
            if isinstance(initializer, dict):
                return initializer
        sid = self._sid_of(getattr(op, "output", None))
        return self.custody_parameter_initializers_by_output_sid.get(str(sid))

    def _custody_note_parameter_initializer_emitted_v45(self, op, lhs):
        initializer = self._custody_parameter_initializer_for_op_v45(op)
        if not isinstance(initializer, dict):
            return
        output_sid = initializer.get("output_sid") or self._sid_of(
            getattr(op, "output", None)
        )
        self._custody_record_event_v45(
            self.custody_parameter_initializer_events,
            {
                "kind": "emitter_parameter_storage_initializer_rendered_v45b",
                "version": self.VERSION,
                "projection": self.render_mode,
                "output_sid": output_sid,
                "source_sid": initializer.get("source_sid"),
                "parameter": initializer.get("parameter"),
                "family_id": initializer.get("family_id"),
                "lhs": lhs,
                "must_print_authority": (
                    "PALCompute_parameter_storage_initializer"
                ),
            },
            ("parameter_initializer", output_sid),
        )

    def _custody_parameter_initializer_family_v46l(self, record):
        """Return the exact resolver storage family named by one sidecar."""
        if not isinstance(record, dict):
            return None

        output_sid = record.get("output_sid")
        descriptor = self._custody_descriptor_for_sid_v45(output_sid)
        if isinstance(descriptor, dict):
            return descriptor

        family_id = record.get("family_id")
        if family_id is not None:
            descriptor = self.custody_family_descriptors.get(str(family_id))
            if isinstance(descriptor, dict):
                return descriptor

        for family in self.custody_storage_families_by_key.values():
            if not isinstance(family, dict):
                continue
            if str(family.get("family_id")) == str(family_id):
                return family

        return None

    def _custody_parameter_initializer_source_v46l(self, record):
        """
        Resolve only a published callable parameter identity.

        The resolver sidecar's ``parameter`` field is the primary authority.
        Source-SID ABI ownership is a compatibility confirmation, not a new
        name inference rule.
        """
        if not isinstance(record, dict):
            return None

        allowed = {
            self._sanitize_name(str(name))
            for name in self._abi_signature_parameters_v46()
            if name
        }
        candidates = []

        published = record.get("parameter")
        if published:
            published_name = self._sanitize_name(str(published))
            return published_name if published_name in allowed else None

        source_sid = record.get("source_sid")
        abi_name = self._abi_name_for_sid_v46(source_sid)
        if abi_name:
            candidates.append(self._sanitize_name(str(abi_name)))

        for parameter in list(getattr(self.func, "parameters", []) or []):
            if str(self._sid_of(parameter)) != str(source_sid):
                continue
            candidates.append(self._sanitize_name(str(self._var(parameter))))

        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if candidate in allowed:
                return candidate

        return None

    def _custody_parameter_initializer_target_v46l(self, record):
        """Resolve the nonpersistent C-storage family destination."""
        if not isinstance(record, dict):
            return None

        output_sid = record.get("output_sid")
        family = self._custody_parameter_initializer_family_v46l(record)
        family = family if isinstance(family, dict) else {}

        classification = family.get("classification")
        persistent = bool(family.get("persistent"))
        storage_space = family.get("storage_space")
        ordinary_local = bool(family.get("ordinary_c_local_candidate"))

        local_authority = bool(
            storage_space == "stack"
            or ordinary_local
            or (
                classification == "address_tied_c_storage"
                and not persistent
            )
        )
        if not local_authority:
            return None

        candidates = [
            family.get("high_name"),
            self.var_map.get(output_sid),
            self.var_map.get(str(output_sid)),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            name = self._sanitize_name(str(candidate))
            if name:
                return name

        return None

    def _custody_reject_parameter_initializer_v46l(
        self,
        record,
        reason,
        **details
    ):
        warning = {
            "kind": (
                "emitter_parameter_storage_initializer_"
                "preamble_rejected_v46l"
            ),
            "version": self.VERSION,
            "projection": self.render_mode,
            "reason": reason,
            "output_sid": (
                record.get("output_sid")
                if isinstance(record, dict) else None
            ),
            "source_sid": (
                record.get("source_sid")
                if isinstance(record, dict) else None
            ),
            "parameter": (
                record.get("parameter")
                if isinstance(record, dict) else None
            ),
            "family_id": (
                record.get("family_id")
                if isinstance(record, dict) else None
            ),
            "action": "leave_missing_initializer_visible_in_custody_gate",
        }
        warning.update(details)
        self.custody_parameter_initializer_rejections.append(warning)
        self.custody_warnings.append(warning)
        return None

    def _emit_custody_parameter_initializer_preamble_v46l(self):
        """
        Materialize resolver-proven parameter-to-storage COPYs independently
        of the ExecTree.

        The corresponding live COPY may have been folded away before
        structured emission.  The sidecar remains the authoritative statement
        that a callable parameter initializes distinct, mutable C storage:

            local_20 = param_3
        """
        for record in list(self.custody_parameter_initializers or []):
            if not isinstance(record, dict):
                self._custody_reject_parameter_initializer_v46l(
                    record,
                    "record_not_mapping",
                )
                continue

            output_sid = record.get("output_sid")
            source_sid = record.get("source_sid")

            if (
                record.get("role") != "parameter_storage_initializer"
                or record.get("entry_state") is not True
                or str(record.get("opcode") or "").upper() != "COPY"
                or output_sid is None
                or source_sid is None
            ):
                self._custody_reject_parameter_initializer_v46l(
                    record,
                    "sidecar_contract_incomplete_or_not_entry_COPY",
                )
                continue

            output_key = str(output_sid)
            if output_key in self.custody_parameter_initializer_preamble_output_sids:
                continue

            source_name = self._custody_parameter_initializer_source_v46l(
                record
            )
            if not source_name:
                self._custody_reject_parameter_initializer_v46l(
                    record,
                    "published_parameter_not_in_callable_signature",
                )
                continue

            target_name = self._custody_parameter_initializer_target_v46l(
                record
            )
            if not target_name:
                self._custody_reject_parameter_initializer_v46l(
                    record,
                    "nonpersistent_local_storage_identity_unresolved",
                )
                continue

            if target_name == source_name:
                self._custody_reject_parameter_initializer_v46l(
                    record,
                    "source_and_target_execution_names_identical",
                    source_name=source_name,
                    target_name=target_name,
                )
                continue

            before = len(self.lines)
            self._emit_assignment(
                target_name,
                source_name,
                custody_sid=output_sid,
                provenance={
                    "role": (
                        "custody_parameter_initializer_preamble"
                    ),
                    "definition_sids": [output_sid],
                    "use_sids": [source_sid],
                    "metadata_refs": [
                        "custody:parameter_initializer:%s"
                        % output_key
                    ],
                },
            )
            if len(self.lines) == before:
                self._custody_reject_parameter_initializer_v46l(
                    record,
                    "assignment_writer_suppressed_preamble",
                    source_name=source_name,
                    target_name=target_name,
                )
                continue

            self.custody_parameter_initializer_preamble_output_sids.add(
                output_key
            )
            self.custody_parameter_initializer_preamble_records_by_output_sid[
                output_key
            ] = record

            event = {
                "kind": (
                    "emitter_parameter_storage_initializer_"
                    "preamble_rendered_v46l"
                ),
                "version": self.VERSION,
                "projection": self.render_mode,
                "output_sid": output_sid,
                "source_sid": source_sid,
                "parameter": record.get("parameter"),
                "family_id": record.get("family_id"),
                "lhs": target_name,
                "rhs": source_name,
                "rendered": self.lines[-1].strip(),
                "must_print_authority": (
                    "PALSymbolResolver_parameter_initializer_sidecar_"
                    "via_PALCompute"
                ),
                "execution_policy": (
                    "emit_before_ExecTree_even_when_COPY_was_folded"
                ),
            }
            self.custody_parameter_initializer_preamble_events.append(event)
            self._custody_record_event_v45(
                self.custody_parameter_initializer_events,
                event,
                ("parameter_initializer", output_key),
            )

    def _custody_parameter_initializer_op_materialized_v46l(self, op):
        """Suppress only the live COPY already materialized by the preamble."""
        if op is None:
            return False
        output_sid = self._sid_of(getattr(op, "output", None))
        if output_sid is None:
            return False
        output_key = str(output_sid)
        record = self.custody_parameter_initializer_preamble_records_by_output_sid.get(
            output_key
        )
        if not isinstance(record, dict):
            return False
        return (
            str(getattr(op, "opcode", "") or "").upper()
            == str(record.get("opcode") or "").upper()
        )

    def _apply_custody_raw_condition_reads_v45(self, expr):
        """
        Make RawCond text observe the same storage families as FormulaNode
        rendering.  PHIfolder limits the candidates to exact condition
        dependency SIDs; this is not a general textual variable rewrite.
        """
        if (
            self._is_readable_render_v44()
            or not self.custody_active
            or not isinstance(expr, str)
            or not expr.strip()
        ):
            return expr

        out = str(expr)
        replacements = []
        for sid in sorted(self.custody_condition_observation_sids, key=str):
            descriptor = self._custody_descriptor_for_sid_v45(sid)
            if not isinstance(descriptor, dict):
                continue
            if not descriptor.get("memory_backed"):
                continue
            address = self._custody_address_expr_v45(descriptor)
            if address is None:
                continue
            width = int(descriptor.get("width_bits") or 32)
            rendered = "c_load(MEM, %s, %s)" % (address, width)
            self.c_truth_required_helpers.add("c_load")
            names = {str(sid)}
            high_name = descriptor.get("high_name")
            if high_name:
                names.add(str(high_name))
            for name in names:
                if name and name != rendered:
                    replacements.append((name, rendered, descriptor))

        for name, rendered, descriptor in sorted(
            replacements, key=lambda item: len(item[0]), reverse=True
        ):
            updated = re.sub(r"\b%s\b" % re.escape(name), rendered, out)
            if updated == out:
                continue
            out = updated
            self._custody_record_event_v45(
                self.custody_read_events,
                {
                    "kind": "emitter_condition_storage_family_read_v45",
                    "version": self.VERSION,
                    "projection": self.render_mode,
                    "sid_or_name": name,
                    "family_id": descriptor.get("family_id"),
                    "high_name": descriptor.get("high_name"),
                    "context": "raw_condition_sidecar",
                    "rendered": rendered,
                },
                ("condition_read", name, rendered),
            )
        return out

    # =========================================================
    # v46 / ABI ENTRY, CALL, RETURN, AND CONVERGENCE CONSUMER
    # =========================================================

    @staticmethod
    def _abi_canonical_numeric_sid_text_v46f(sid):
        """
        Canonicalize only PAL's generated numeric SSA namespace.

        This deliberately does not sanitize arbitrary readable/operator names.
        It exists so an identity already published as ``v_1156`` cannot become
        ``v_v_1156`` when frozen condition text crosses EdgeTruth/SGL.
        """
        if sid is None:
            return None
        text = str(sid)
        while re.fullmatch(r"v_v_\d+", text):
            text = text[2:]
        if re.fullmatch(r"v_\d+", text):
            return text
        if text.isdigit():
            return "v_%s" % text
        return text

    def _abi_sid_identifier_spellings_v46f(self, sid):
        """
        Return identity-backed identifier spellings for one ABI SID.

        The extra ``v_v_N`` spelling is accepted solely as compatibility for
        already-frozen pre-v46f SGL predicates.  It is derived from a unique
        ABI-owned SID and is therefore safe in READ as well as EXEC; ambiguous
        legacy spellings such as ``param_N`` remain executable-only below.
        """
        canonical = self._abi_canonical_numeric_sid_text_v46f(sid)
        if canonical is None:
            return []
        names = [canonical]
        if re.fullmatch(r"v_\d+", canonical):
            names.append("v_%s" % canonical)
        result = []
        seen = set()
        for name in names:
            if not name or name in seen:
                continue
            seen.add(name)
            result.append(name)
        return result

    def _abi_sid_keys_v46(self, sid):
        if sid is None:
            return []
        text = str(sid)
        canonical = self._abi_canonical_numeric_sid_text_v46f(sid)
        keys = [sid, text, canonical]
        if canonical and canonical.startswith("v_") and canonical[2:].isdigit():
            keys.extend([canonical[2:], int(canonical[2:])])
        elif canonical and canonical.isdigit():
            keys.extend(["v_%s" % canonical, int(canonical)])
        result = []
        seen = set()
        for key in keys:
            if key is None:
                continue
            marker = (type(key).__name__, str(key))
            if marker in seen:
                continue
            seen.add(marker)
            result.append(key)
        return result

    def _abi_lookup_sid_v46(self, mapping, sid):
        if not isinstance(mapping, dict):
            return None
        for key in self._abi_sid_keys_v46(sid):
            if key in mapping:
                return mapping.get(key)
        return None

    def _abi_record_event_v46(self, collection, event, key):
        marker = (self.render_mode, key)
        if marker in self._abi_event_keys:
            return
        self._abi_event_keys.add(marker)
        collection.append(event)

    @staticmethod
    def _abi_register_text_v46(register):
        if isinstance(register, dict):
            return (
                register.get("name")
                or register.get("base_name")
                or register.get("repr")
            )
        if register is None:
            return None
        return str(register)

    def _abi_unique_name_v46(self, proposed, sid, used_names):
        base = self._sanitize_name(proposed or ("abi_value_%s" % str(sid)))
        owner = used_names.get(base)
        if owner in (None, str(sid)):
            used_names[base] = str(sid)
            return base
        ordinal = 2
        while True:
            candidate = "%s_%d" % (base, ordinal)
            if candidate not in used_names:
                used_names[candidate] = str(sid)
                self.abi_render_warnings.append({
                    "kind": "emitter_abi_name_collision_v46",
                    "sid": str(sid),
                    "requested_name": base,
                    "allocated_name": candidate,
                    "existing_owner_sid": owner,
                    "action": "deterministic_suffix_without_changing_ABI_owner",
                })
                return candidate
            ordinal += 1

    def _abi_root_for_id_v46(self, root_id):
        for record in self.abi_entry_roots_by_sid.values():
            if isinstance(record, dict) and record.get("root_id") == root_id:
                return record
        return None

    def _abi_root_for_sid_v46(self, sid):
        record = self._abi_lookup_sid_v46(self.abi_entry_roots_by_sid, sid)
        return record if isinstance(record, dict) else None

    def _abi_root_ids_for_sid_v46c(self, sid):
        """
        Return the ABI-F root identities which own ``sid``.

        ABI entry values routinely cross transparent COPY/CAST bridges before
        reaching an address-tied stack family.  A direct root lookup is
        therefore insufficient at the exact operation which performs the
        storage initialization.  PHIfolder already proved this lineage; the
        emitter consumes that proof without re-walking expressions or
        inferring carriers from names.
        """
        if sid is None:
            return []

        candidates = []

        def add(value):
            if value is None:
                return
            if isinstance(value, dict):
                add(value.get("root_id"))
                add(value.get("root_ids"))
                return
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    add(item)
                return
            text = str(value)
            if text and text not in candidates:
                candidates.append(text)

        add(self._abi_root_for_sid_v46(sid))
        add(self._abi_lookup_sid_v46(self.abi_entry_lineage_by_sid, sid))
        add(self._abi_lookup_sid_v46(
            self.abi_entry_execution_owners_by_sid, sid
        ))

        # Reject stale or foreign identifiers instead of guessing ownership.
        return [
            root_id for root_id in candidates
            if self._abi_root_for_id_v46(root_id) is not None
        ]

    def _abi_unique_root_for_sid_v46c(self, sid, required_role=None):
        roots = []
        for root_id in self._abi_root_ids_for_sid_v46c(sid):
            root = self._abi_root_for_id_v46(root_id)
            if not isinstance(root, dict):
                continue
            if (
                required_role is not None
                and str(root.get("role") or "") != str(required_role)
            ):
                continue
            if all(
                str(item.get("root_id")) != str(root.get("root_id"))
                for item in roots
            ):
                roots.append(root)
        return roots[0] if len(roots) == 1 else None

    def _abi_storage_descriptor_for_output_v46c(self, out, output_sid):
        """
        Resolve the already-published storage family for an output.

        PALCompute bindings are SID-versioned, while an entry initializer may
        precede the first INDIRECT version recorded for the family.  The
        canonical HighVariable name is the second authoritative index built by
        the v45 custody consumer, so use it as a lookup key when the initial
        output SID itself has no family record.
        """
        descriptor = self._custody_descriptor_for_sid_v45(output_sid)
        if isinstance(descriptor, dict):
            return descriptor

        names = []
        raw_name = getattr(out, "name", None)
        if raw_name:
            name = self._sanitize_name(str(raw_name))
            names.append(name)
            descriptor = self.custody_family_by_name.get(name)
            if isinstance(descriptor, dict):
                return descriptor
        rendered_name = self._var(out)
        if rendered_name:
            names.append(self._sanitize_name(str(rendered_name)))
        for name in names:
            descriptor = self.custody_family_by_name.get(name)
            if isinstance(descriptor, dict):
                return descriptor
        return None

    def _abi_register_raw_name_alias_v46(self, source, target):
        """
        Register a textual ABI alias only when it has one canonical owner.

        Ghidra's legacy HighFunction parameter labels are not identities.  In
        variadic functions the same ``param_N`` spelling can describe a GP
        carrier and an XMM live-in.  First-wins replacement would silently
        bind a frozen RawCond to whichever record happened to be indexed
        first.  Ambiguous spellings are therefore removed from the rewrite
        table and retained as audit records; SID-backed FormulaNodes continue
        to resolve normally through ``abi_execution_name_by_sid``.
        """
        if source is None or target is None:
            return
        # Preserve the literal RawCond token.  _sanitize_name intentionally
        # folds v_v_N -> v_N, which is precisely the frozen-SGL spelling this
        # bridge must recognize before cleanup.
        source = re.sub(r"[^A-Za-z0-9_]", "_", str(source))
        if source and source[0].isdigit():
            source = "v_" + source
        target = self._sanitize_name(str(target))
        if not source or source == target:
            return

        candidates = self.abi_raw_name_alias_candidates.setdefault(
            source, set()
        )
        candidates.add(target)
        ordered = sorted(str(item) for item in candidates)

        if len(ordered) == 1:
            self.abi_raw_name_aliases[source] = ordered[0]
            self.abi_ambiguous_raw_name_aliases.pop(source, None)
            return

        self.abi_raw_name_aliases.pop(source, None)
        self.abi_ambiguous_raw_name_aliases[source] = {
            "kind": "emitter_abi_ambiguous_legacy_name_v46d",
            "source_name": source,
            "candidate_targets": ordered,
            "rewrite_policy": "SID_context_required_no_global_text_rewrite",
            "hazard": "legacy_HighFunction_name_is_not_physical_identity",
        }

    def _abi_build_raw_name_aliases_v46b(self):
        """
        Bridge legacy HighFunction spellings to ABI-C canonical identities.

        RawCond strings do not carry object identity, and some frozen SGL
        bundles spell an already textual SID as ``v_v_N``.  Only SIDs already
        owned by ABI-C/D are admitted here; this is a spelling bridge, not ABI
        placement inference.  Identity-derived ``v_N``/``v_v_N`` spellings are
        safe in both projections.  Potentially ambiguous legacy names such as
        ``param_N`` remain quarantined or executable-only.
        """
        for sid, target in list(self.abi_execution_name_by_sid.items()):
            sid_text = str(sid)
            self._abi_register_raw_name_alias_v46(sid_text, target)
            if sid_text.startswith("v_"):
                self._abi_register_raw_name_alias_v46(
                    "v_%s" % sid_text, target
                )

            records = []
            for table in (
                self.abi_entry_roots_by_sid,
                self.abi_implicit_inputs_by_sid,
                self.abi_alias_contracts_by_sid,
            ):
                record = self._abi_lookup_sid_v46(table, sid)
                if isinstance(record, dict):
                    records.append(record)

            for record in records:
                for key in (
                    "source_name", "high_name", "name", "execution_name"
                ):
                    source_name = record.get(key)
                    self._abi_register_raw_name_alias_v46(
                        source_name, target
                    )

                    source_token = (
                        self._abi_raw_identifier_token_v46j(
                            source_name
                        )
                    )
                    if (
                        source_token
                        and source_token.startswith("in_")
                    ):
                        self.abi_exact_machine_carrier_alias_sources.add(
                            source_token
                        )

                register = self._abi_register_text_v46(
                    record.get("register")
                )
                if register:
                    # Ghidra's implicit live-in spelling is an exact ABI
                    # machine-carrier surface, not a mutable state alias.
                    carrier_token = self._abi_raw_identifier_token_v46j(
                        "in_%s" % register
                    )
                    self._abi_register_raw_name_alias_v46(
                        carrier_token, target
                    )
                    if carrier_token:
                        self.abi_exact_machine_carrier_alias_sources.add(
                            carrier_token
                        )

    def _abi_entry_storage_initializer_contract_v46b(self, op):
        """
        Identify a physical variadic GP carrier copied into shared stack state.

        These COPY/transparent ops are easily mistaken for same-HighVariable
        SSA traffic, but when the destination is a memory-backed stack family
        they are the executable initialization of the SysV register-save area.
        """
        if not self.abi_active or op is None:
            return None
        op_key = self._op_key(op)
        if op_key in self.abi_entry_storage_initializers_by_op:
            return self.abi_entry_storage_initializers_by_op.get(op_key)

        opcode = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        inputs = list(getattr(op, "inputs", []) or [])
        if opcode not in _TRANSPARENT or out is None or len(inputs) != 1:
            return None

        source_sid = self._sid_of(inputs[0])
        output_sid = self._sid_of(out)
        root = self._abi_unique_root_for_sid_v46c(
            source_sid, required_role="variadic_entry_gp_carrier"
        )
        if not isinstance(root, dict):
            return None

        descriptor = self._abi_storage_descriptor_for_output_v46c(
            out, output_sid
        )
        if not isinstance(descriptor, dict):
            return None

        # The initial SSA version of an address-tied local may not itself be
        # flagged ``is_stack_local`` even though PALCompute has already bound
        # its HighVariable family to a resolved stack address.  Storage-family
        # custody is the stronger authority.  Require an exact canonical-name
        # match so this narrow must-print rule cannot capture an unrelated
        # transparent GP value.
        output_name = self._sanitize_name(str(self._var(out)))
        family_name = self._sanitize_name(str(
            descriptor.get("high_name") or ""
        ))
        representative = dict(descriptor.get("representative") or {})
        storage_space = (
            descriptor.get("storage_space")
            or representative.get("space")
        )
        rejection_reasons = []
        if descriptor.get("memory_backed") is not True:
            # A non-memory family is ordinary identity transport, not a save.
            return None
        if descriptor.get("address_resolved") is not True:
            rejection_reasons.append("storage_address_unresolved")
        if str(storage_space) != "stack":
            rejection_reasons.append("storage_space_not_stack")
        if not family_name:
            rejection_reasons.append("storage_family_name_missing")
        elif output_name != family_name:
            rejection_reasons.append("output_family_name_mismatch")
        if rejection_reasons:
            self.abi_entry_storage_initializer_rejections[op_key] = {
                "kind": "emitter_abi_entry_storage_candidate_rejected_v46d",
                "version": self.ABI_CUSTODY_VERSION,
                "op_key": op_key,
                "op_id": str(getattr(op, "op_id", None)),
                "source_sid": str(source_sid),
                "source_root_sid": str(root.get("sid")),
                "root_id": root.get("root_id"),
                "output_sid": str(output_sid),
                "output_name": output_name,
                "storage_family_id": descriptor.get("family_id"),
                "storage_family_name": family_name,
                "storage_space": storage_space,
                "memory_backed": descriptor.get("memory_backed"),
                "address_resolved": descriptor.get("address_resolved"),
                "reasons": rejection_reasons,
                "action": "fail_closed_do_not_suppress_candidate",
            }
            self.abi_entry_storage_initializer_rejected_output_sids.add(
                str(output_sid)
            )
            return None

        root_sid = root.get("sid")
        source_name = self._abi_name_for_sid_v46(root_sid)
        if not source_name:
            return None

        contract = {
            "kind": "emitter_abi_entry_storage_initializer_v46d",
            "version": self.ABI_CUSTODY_VERSION,
            "op_key": op_key,
            "op_id": str(getattr(op, "op_id", None)),
            "source_sid": str(source_sid),
            "source_root_sid": str(root_sid),
            "source_name": source_name,
            "output_sid": str(output_sid),
            "output_name": family_name,
            "storage_family_id": descriptor.get("family_id"),
            "storage_space": storage_space,
            "storage_offset": descriptor.get("storage_offset"),
            "width_bits": descriptor.get("width_bits") or root.get("width_bits"),
            "root_id": root.get("root_id"),
            "root_role": root.get("role"),
            "execution_policy": "must_print_executable_shared_storage_initialization",
            "authority": (
                "ABI_F_lineage_plus_PALCompute_storage_family_binding"
            ),
        }
        self.abi_entry_storage_initializers_by_op[op_key] = contract
        return contract

    def _abi_index_entry_storage_initializers_v46b(self):
        for block in list(getattr(self.func, "blocks", []) or []):
            for op in list(getattr(block, "ops", []) or []):
                self._abi_entry_storage_initializer_contract_v46b(op)

    def _abi_note_entry_storage_initializer_v46b(self, op, rendered):
        if self._is_readable_render_v44():
            return
        contract = self._abi_entry_storage_initializer_contract_v46b(op)
        if not isinstance(contract, dict):
            return
        event = dict(contract)
        event.update({
            "projection": self.render_mode,
            "rendered": rendered,
            "must_print_consumed": True,
        })
        self._abi_record_event_v46(
            self.abi_entry_storage_initializer_events,
            event,
            ("entry_storage_initializer", contract.get("op_key")),
        )

    def _abi_entry_storage_initializer_expr_v46c(self, contract, fallback):
        """Render the lineage-owned entry root, never a legacy bridge name."""
        if self._is_readable_render_v44() or not isinstance(contract, dict):
            return fallback
        source_name = contract.get("source_name")
        return str(source_name) if source_name else fallback

    def _abi_fixed_argument_local_output_name_v46k(
        self,
        out,
        output_sid,
        source_name,
    ):
        """
        Recover the destination storage identity without passing through
        ``_var(out)``.

        ``_var`` is intentionally ABI-aware and may collapse the destination
        HighVariable back to the fixed argument name.  That is correct for
        reads, but incorrect for the LHS of the physical initialization:

            local_20 = param_3
        """
        descriptor = self._abi_storage_descriptor_for_output_v46c(
            out,
            output_sid,
        )
        representative = (
            dict(descriptor.get("representative") or {})
            if isinstance(descriptor, dict)
            else {}
        )

        candidates = [
            getattr(out, "name", None),
            (
                descriptor.get("high_name")
                if isinstance(descriptor, dict)
                else None
            ),
            representative.get("name"),
            representative.get("high_name"),
            self.var_map.get(output_sid),
            self.var_map.get(str(output_sid)),
        ]

        fixed_names = {
            self._sanitize_name(str(name))
            for name in self.abi_fixed_argument_names
            if name
        }
        source_name = self._sanitize_name(str(source_name))

        for candidate in candidates:
            if not candidate:
                continue
            name = self._sanitize_name(str(candidate))
            if (
                not name
                or name == source_name
                or name in fixed_names
            ):
                continue
            return name

        return None

    def _abi_fixed_argument_local_initializer_contract_v46k(self, op):
        """
        Preserve a fixed ABI argument copied into distinct local stack state.

        Ghidra may keep the parameter and local in one HighVariable family.
        Ordinary transparent/self-copy suppression then sees no semantic
        difference and deletes the instruction, even though ASM performs a
        real register-to-stack initialization.

        Authority:
          - source belongs to one published ABI-D fixed argument;
          - destination is stack-owned by PAL variable/storage metadata;
          - destination has a distinct local storage name;
          - operation is one transparent one-input transfer.

        This is not name-based ABI placement inference.
        """
        if not self.abi_active or op is None:
            return None

        op_key = self._op_key(op)
        if op_key in self.abi_fixed_argument_local_initializers_by_op:
            return self.abi_fixed_argument_local_initializers_by_op.get(
                op_key
            )

        opcode = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        inputs = list(getattr(op, "inputs", []) or [])

        if (
            opcode not in _TRANSPARENT
            or out is None
            or len(inputs) != 1
        ):
            return None

        source = inputs[0]
        source_sid = self._sid_of(source)
        output_sid = self._sid_of(out)

        if source_sid is None or output_sid is None:
            return None

        source_sid_text = str(source_sid)
        root = self._abi_unique_root_for_sid_v46c(source_sid)
        root_sid = (
            str(root.get("sid"))
            if isinstance(root, dict)
            and root.get("sid") is not None
            else None
        )

        fixed_owned = (
            source_sid_text in self.abi_fixed_argument_sids
            or (
                root_sid is not None
                and root_sid in self.abi_fixed_argument_sids
            )
        )
        if not fixed_owned:
            return None

        source_name = (
            self._abi_name_for_sid_v46(source_sid)
            or (
                self._abi_name_for_sid_v46(root_sid)
                if root_sid is not None
                else None
            )
        )
        if not source_name:
            return None

        descriptor = self._abi_storage_descriptor_for_output_v46c(
            out,
            output_sid,
        )
        representative = (
            dict(descriptor.get("representative") or {})
            if isinstance(descriptor, dict)
            else {}
        )
        storage_space = (
            descriptor.get("storage_space")
            if isinstance(descriptor, dict)
            else None
        ) or representative.get("space")

        stack_owned = (
            self._is_stack_local_var(out)
            or str(storage_space or "") == "stack"
        )
        if not stack_owned:
            return None

        output_name = (
            self._abi_fixed_argument_local_output_name_v46k(
                out,
                output_sid,
                source_name,
            )
        )
        if not output_name:
            return None

        contract = {
            "kind": (
                "emitter_abi_fixed_argument_local_initializer_v46k"
            ),
            "version": self.ABI_CUSTODY_VERSION,
            "op_key": op_key,
            "op_id": str(getattr(op, "op_id", None)),
            "opcode": opcode,
            "source_sid": source_sid_text,
            "source_root_sid": root_sid,
            "source_name": str(source_name),
            "output_sid": str(output_sid),
            "output_name": str(output_name),
            "storage_family_id": (
                descriptor.get("family_id")
                if isinstance(descriptor, dict)
                else None
            ),
            "storage_space": storage_space or "stack",
            "storage_offset": (
                descriptor.get("storage_offset")
                if isinstance(descriptor, dict)
                else getattr(out, "offset", None)
            ),
            "execution_policy": (
                "must_print_fixed_argument_to_distinct_local_state"
            ),
            "authority": (
                "ABI_D_fixed_argument_ownership_plus_"
                "PAL_stack_storage_identity"
            ),
        }

        self.abi_fixed_argument_local_initializers_by_op[
            op_key
        ] = contract
        return contract

    def _abi_index_fixed_argument_local_initializers_v46k(self):
        for op in self._iter_all_ops():
            self._abi_fixed_argument_local_initializer_contract_v46k(
                op
            )

    def _abi_fixed_argument_local_initializer_lhs_v46k(
        self,
        contract,
        fallback,
    ):
        if not isinstance(contract, dict):
            return fallback
        return str(contract.get("output_name") or fallback)

    def _abi_note_fixed_argument_local_initializer_v46k(
        self,
        op,
        rendered,
    ):
        contract = (
            self._abi_fixed_argument_local_initializer_contract_v46k(
                op
            )
        )
        if not isinstance(contract, dict):
            return

        event = dict(contract)
        event.update({
            "projection": self.render_mode,
            "rendered": rendered,
            "must_print_consumed": True,
        })
        self._abi_record_event_v46(
            self.abi_fixed_argument_local_initializer_events,
            event,
            (
                "fixed_argument_local_initializer",
                contract.get("op_key"),
                self.render_mode,
            ),
        )

    def _abi_add_materialization_v46(self, record, seen_sids):
        sid = record.get("sid")
        if sid is None or str(sid) in seen_sids:
            return
        seen_sids.add(str(sid))
        self.abi_entry_materialization_records.append(record)

    def _build_abi_custody_consumer_v46(self):
        if not self.abi_active:
            self.abi_context_required = False
            return

        if self.abi_function_entry_plan.get("downstream_reinference_allowed") is True:
            self.abi_render_warnings.append({
                "kind": "emitter_abi_authority_violation_v46",
                "reason": "entry_plan_permits_downstream_reinference",
                "plan_id": self.abi_function_entry_plan.get("plan_id"),
            })

        used_names = {}
        fixed = sorted(
            list(self.abi_function_entry_plan.get("fixed_arguments") or []),
            key=lambda item: (
                item.get("ordinal") is None,
                item.get("ordinal") if isinstance(item.get("ordinal"), int) else 0,
            ),
        )
        for fallback_ordinal, item in enumerate(fixed):
            if not isinstance(item, dict):
                continue
            ordinal = item.get("ordinal")
            if not isinstance(ordinal, int):
                ordinal = fallback_ordinal
            proposed = (
                item.get("name")
                or item.get("logical_name")
                or "abi_arg_%d" % ordinal
            )
            owner_sid = item.get("source_sid") or "argument:%d" % ordinal
            name = self._abi_unique_name_v46(proposed, owner_sid, used_names)
            self.abi_fixed_argument_names.append(name)
            owned_sids = [item.get("source_sid")]
            owned_sids.extend(list(item.get("physical_sids") or []))
            for sid in owned_sids:
                if sid is None:
                    continue
                sid_text = str(sid)
                self.abi_fixed_argument_sids.add(sid_text)
                self.abi_execution_name_by_sid[sid_text] = name

        if self.abi_context_name in used_names:
            self.abi_context_name = self._abi_unique_name_v46(
                self.abi_context_name + "_state", "abi_context", used_names
            )
        else:
            used_names[self.abi_context_name] = "abi_context"

        materialized = set()

        # Physical carriers are captured exactly as listed by ABI-D.  A
        # carrier already owned by a logical fixed argument is not re-read.
        register_area = dict(
            self.abi_function_entry_plan.get("variadic_register_save_area")
            or {}
        )
        for slot in list(register_area.get("slots") or []):
            if not isinstance(slot, dict):
                continue
            sid = slot.get("sid")
            if sid is None or str(sid) in self.abi_fixed_argument_sids:
                continue
            register = self._abi_register_text_v46(slot.get("register"))
            proposed = slot.get("canonical_alias")
            if not proposed and register:
                proposed = "abi_%s" % register.lower()
            name = self._abi_unique_name_v46(proposed, sid, used_names)
            self.abi_execution_name_by_sid[str(sid)] = name
            self._abi_add_materialization_v46({
                "kind": "emitter_abi_entry_materialization_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "sid": str(sid),
                "name": name,
                "source_kind": "registers",
                "source_key": register,
                "width_bits": slot.get("width_bits"),
                "materialization": slot.get("materialization"),
                "authority": slot.get("authority"),
                "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            }, materialized)

        for item in list(self.abi_function_entry_plan.get("implicit_inputs") or []):
            if not isinstance(item, dict):
                continue
            sid = item.get("sid")
            if sid is None or str(sid) in self.abi_fixed_argument_sids:
                continue
            register = self._abi_register_text_v46(item.get("register"))
            proposed = item.get("canonical_alias") or "abi_%s" % str(
                item.get("role") or sid
            )
            name = self.abi_execution_name_by_sid.get(str(sid))
            if not name:
                name = self._abi_unique_name_v46(proposed, sid, used_names)
                self.abi_execution_name_by_sid[str(sid)] = name
            if str(sid) in materialized:
                continue
            role = str(item.get("role") or "machine_live_in")
            destination = str(item.get("destination") or "abi_context.machine_state")
            source_kind = destination.rsplit(".", 1)[-1]
            source_key = register if register else item.get("canonical_alias")
            self._abi_add_materialization_v46({
                "kind": "emitter_abi_entry_materialization_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "sid": str(sid),
                "name": name,
                "role": role,
                "source_kind": source_kind,
                "source_key": source_key,
                "width_bits": item.get("width_bits"),
                "materialization": item.get("materialization"),
                "authority": item.get("authority"),
                "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            }, materialized)

        # ABI-F root records are the final ownership ledger.  Use them to
        # close any entry root omitted from the compact ABI-D lists, but never
        # invent a carrier: register/role evidence must be present in record.
        for key, root in self.abi_entry_roots_by_sid.items():
            if not isinstance(root, dict):
                continue
            sid = root.get("sid") or key
            if sid is None or str(sid) in self.abi_fixed_argument_sids:
                continue
            name = self.abi_execution_name_by_sid.get(str(sid))
            if not name:
                proposed = root.get("canonical_alias") or root.get("execution_name")
                name = self._abi_unique_name_v46(proposed, sid, used_names)
                self.abi_execution_name_by_sid[str(sid)] = name
            if str(sid) in materialized:
                continue
            register = self._abi_register_text_v46(root.get("register"))
            role = str(root.get("role") or "machine_live_in")
            destination = str(root.get("destination") or "abi_context.machine_state")
            source_kind = "registers" if register else destination.rsplit(".", 1)[-1]
            source_key = register if register else root.get("canonical_alias")
            if not register and not root.get("role") and not root.get("destination"):
                self.abi_render_warnings.append({
                    "kind": "emitter_abi_entry_root_unmaterialized_v46",
                    "sid": str(sid),
                    "root_id": root.get("root_id"),
                    "reason": "root_has_no_published_register_or_runtime_context_role",
                })
                continue
            self._abi_add_materialization_v46({
                "kind": "emitter_abi_entry_materialization_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "sid": str(sid),
                "name": name,
                "role": role,
                "source_kind": source_kind,
                "source_key": source_key,
                "width_bits": root.get("width_bits"),
                "materialization": root.get("materialization"),
                "authority": root.get("authority"),
                "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            }, materialized)

        # The overflow area is an ABI context region rather than an SSA
        # varnode, so ABI-F has no SID root for it.  Still consume the ABI-D
        # contract explicitly: this prevents a later harness from deriving
        # stack offsets from expression spelling and gives variadic consumers
        # one stable execution object.
        overflow = dict(
            self.abi_function_entry_plan.get("overflow_argument_area") or {}
        )
        if overflow.get("required") is True:
            overflow_name = self._abi_unique_name_v46(
                "abi_overflow_arguments",
                "abi_context:overflow_argument_area",
                used_names,
            )
            self.abi_entry_context_records.append({
                "kind": "emitter_abi_entry_context_materialization_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "sid": "abi_context:overflow_argument_area",
                "name": overflow_name,
                "source_kind": "overflow_argument_area",
                "source_key": None,
                "width_bits": None,
                "materialization": overflow.get("materialization"),
                "offset_inference_allowed": overflow.get(
                    "offset_inference_allowed"
                ),
                "authority": overflow.get("authority"),
                "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            })

        # Same-storage PHIs need no executable moves.  Raw SSA targets must,
        # however, render through the proven entry root or they would remain
        # textually unbound even though ABI-F proved their identity.
        for contract in self.abi_entry_convergence_contracts:
            if not isinstance(contract, dict):
                continue
            target_sid = contract.get("target_sid")
            root = self._abi_root_for_id_v46(contract.get("root_id")) or {}
            root_sid = root.get("sid") or contract.get("root_sid")
            root_name = self.abi_execution_name_by_sid.get(str(root_sid))
            if not contract.get("all_predecessors_owned"):
                self.abi_render_warnings.append({
                    "kind": "emitter_abi_convergence_unowned_v46",
                    "target_sid": target_sid,
                    "join_addr": contract.get("join_addr"),
                    "owned_predecessors": contract.get("owned_predecessor_count"),
                    "predecessors": contract.get("predecessor_count"),
                })
                continue
            paths = list(contract.get("paths") or [])
            requires_transition = any(
                path.get("transition_required") for path in paths
                if isinstance(path, dict)
            )
            target_name = str(contract.get("target_name") or target_sid or "")
            raw_target = bool(
                target_sid is not None
                and target_name in (str(target_sid), self._sanitize_name(str(target_sid)))
            )
            if (
                target_sid is not None
                and root_name
                and raw_target
                and not requires_transition
            ):
                self.abi_convergence_alias_by_sid[str(target_sid)] = root_name
                # For a raw SSA convergence target (TLS/frame/machine state),
                # each proven identity-passthrough predecessor must render
                # through that same root.  Address-tied locals deliberately do
                # not satisfy raw_target, so their storage reads remain intact.
                for path in paths:
                    if not isinstance(path, dict):
                        continue
                    source_sid = path.get("source_sid")
                    source_roots = set(
                        str(item) for item in (
                            path.get("source_root_ids") or []
                        ) if item is not None
                    )
                    if (
                        source_sid is not None
                        and path.get("transition_required") is not True
                        and path.get("source_matches_unique_root") is True
                        and str(contract.get("root_id")) in source_roots
                    ):
                        self.abi_executable_identity_alias_by_sid[
                            str(source_sid)
                        ] = root_name

        for key, plan in list(self.abi_call_site_plans_by_op.items()):
            if not isinstance(plan, dict):
                continue
            if plan.get("op_key") is not None:
                self.abi_call_site_plans_by_op[str(plan.get("op_key"))] = plan
            if plan.get("op_id") is not None:
                self.abi_call_plans_by_op_id[str(plan.get("op_id"))] = plan
            if plan.get("plan_id") is not None:
                self.abi_call_plans_by_plan_id[str(plan.get("plan_id"))] = plan
            if plan.get("downstream_reinference_allowed") is True:
                self.abi_render_warnings.append({
                    "kind": "emitter_abi_authority_violation_v46",
                    "reason": "call_plan_permits_downstream_reinference",
                    "plan_id": plan.get("plan_id"),
                })

        for boundary in list(
            self.abi_function_entry_plan.get("return_boundaries") or []
        ):
            if not isinstance(boundary, dict):
                continue
            block_addr = boundary.get("block_addr")
            if block_addr is not None:
                self.abi_return_boundaries_by_block[block_addr] = boundary
                self.abi_return_boundaries_by_block[str(block_addr)] = boundary

        return_contract = dict(
            self.abi_function_entry_plan.get("return_contract") or {}
        )
        return_carriers = list(return_contract.get("carrier_pieces") or [])
        self.abi_context_required = bool(
            self.abi_entry_materialization_records
            or self.abi_entry_context_records
            or self.abi_call_site_plans_by_op
            or return_carriers
            or overflow.get("required") is True
        )

        self._abi_build_raw_name_aliases_v46b()
        self._abi_index_immutable_context_v46p()
        self._abi_index_entry_storage_initializers_v46b()
        self._abi_index_fixed_argument_local_initializers_v46k()

        if self.abi_entry_path_unbound_records:
            self.abi_render_warnings.extend(
                copy.deepcopy(self.abi_entry_path_unbound_records)
            )
        self.abi_render_warnings.extend(
            copy.deepcopy(self.abi_entry_custody_warnings)
        )

    @staticmethod
    def _abi_raw_value_object_v46n(value):
        if value is None:
            return None
        raw = getattr(value, "var", None)
        return raw if raw is not None else value

    def _abi_node_for_sid_v46n(self, sid):
        if sid is None:
            return None
        nodes = getattr(self, "nodes", {}) or {}
        return nodes.get(sid) or nodes.get(str(sid))

    def _abi_mutable_state_rejection_v46n(self, value=None, sid=None):
        """Classify values which must retain mutable program-state identity."""
        raw = self._abi_raw_value_object_v46n(value)
        if sid is None:
            sid = self._sid_of(raw)
        sid_text = str(sid) if sid is not None else None
        reasons=[]
        name=(getattr(raw,"name",None) if raw is not None and not isinstance(raw,str) else None)
        rendered=(self._sanitize_name(str(name)) if name else None)
        if rendered and rendered.startswith("local_"):
            reasons.append("local_name")
        try:
            if raw is not None and self._is_stack_local_var(raw):
                reasons.append("stack_variable")
        except Exception:
            pass
        descriptor=None
        if sid is not None:
            try:
                descriptor=self._custody_descriptor_for_sid_v45(sid)
            except Exception:
                descriptor=None
        if isinstance(descriptor,dict):
            high=str(descriptor.get("high_name") or "")
            space=str(descriptor.get("storage_space") or descriptor.get("space") or "")
            cls=str(descriptor.get("storage_class") or descriptor.get("family_kind") or "")
            if high.startswith("local_"): reasons.append("custody_local_name")
            if space == "stack": reasons.append("custody_stack_storage")
            if cls in ("stack","local","mutable_local","state"): reasons.append("custody_mutable_state")
        node=self._abi_node_for_sid_v46n(sid)
        opcode=getattr(node,"opcode",None)
        if opcode == "MULTIEQUAL":
            reasons.append("phi_target")
        elif opcode in ("INDIRECT","LOAD","STORE","CALL","CALLIND"):
            reasons.append("stateful_opcode:%s" % opcode)
        elif opcode in _BINARY or opcode in _UNARY:
            reasons.append("computed_state:%s" % opcode)
        for label,values in (
            ("local_target_sid",getattr(self,"local_target_sids",set())),
            ("state_transition_sid",getattr(self,"state_transition_alias_sids",set())),
            ("phi_state_source_sid",getattr(self,"phi_source_alias_sids",set())),
            ("post_update_state_sid",getattr(self,"post_update_alias_sids",set())),
        ):
            values=values or set()
            if sid is not None and (sid in values or sid_text in values): reasons.append(label)
        if not reasons: return None
        return {"sid":sid_text,"name":rendered,"opcode":opcode,"reasons":sorted(set(reasons))}

    def _abi_identity_passthrough_proven_v46n(self, sid):
        """Require affirmative proof before a derived SID reuses an entry root."""
        if sid is None: return False
        records=(
            self._abi_lookup_sid_v46(self.abi_entry_lineage_by_sid,sid),
            self._abi_lookup_sid_v46(self.abi_entry_execution_owners_by_sid,sid),
            self._abi_lookup_sid_v46(self.abi_alias_contracts_by_sid,sid),
        )
        for record in records:
            if self._abi_identity_transition_rejected_v46j(record): return False
        positive=("identity_passthrough","same_storage","source_matches_unique_root","exact_identity","carrier_identity","entry_identity_passthrough")
        for record in records:
            if not isinstance(record,dict): continue
            if any(record.get(k) is True for k in positive): return True
            relation=str(record.get("relation") or record.get("identity_relation") or record.get("transition_kind") or "").lower()
            if relation in ("identity","same_storage","transparent_identity","entry_carrier"): return True
        return False

    def _abi_identity_alias_candidates_v46n(self, value, sid):
        out=[]
        for source,mapping in (
            ("executable_identity",getattr(self,"abi_executable_identity_alias_by_sid",{})),
            ("convergence",getattr(self,"abi_convergence_alias_by_sid",{})),
        ):
            alias=self._abi_lookup_sid_v46(mapping,sid)
            if alias: out.append({"source":source,"name":str(alias)})
        root=self._abi_unique_root_for_sid_v46c(sid)
        if isinstance(root,dict):
            rsid=root.get("sid")
            rname=self._abi_lookup_sid_v46(self.abi_execution_name_by_sid,rsid)
            if rname: out.append({"source":"entry_root","name":str(rname),"root_sid":str(rsid) if rsid is not None else None})
        raw=self._abi_raw_value_object_v46n(value)
        token=None
        if raw is not None and not isinstance(raw,str): token=self._abi_raw_identifier_token_v46j(getattr(raw,"name",None))
        aliases=self.abi_raw_name_alias_candidates.get(token) if token else None
        if isinstance(aliases,(set,frozenset,list,tuple)):
            for alias in aliases:
                if alias: out.append({"source":"raw_variable_alias","name":str(alias),"token":token})
        return out

    def _abi_note_identity_quarantine_v46n(self, value, sid, rejection, context):
        if not isinstance(rejection,dict): return
        candidates=self._abi_identity_alias_candidates_v46n(value,sid)
        if not candidates: return
        self._abi_record_event_v46(
            self.abi_identity_reuse_rejections,
            {"kind":"emitter_abi_entry_identity_state_quarantined_v46n","version":self.ABI_CUSTODY_VERSION,"projection":self.render_mode,"context":context,"candidate_aliases":candidates,"action":"preserve_mutable_program_state_identity",**rejection},
            ("entry_identity_state_quarantine",str(sid),context,tuple(rejection.get("reasons") or [])),
        )

    @staticmethod
    def _abi_identity_transition_rejected_v46j(record):
        """
        Reject lineage records which explicitly require a value/storage
        transition.  Missing flags are not invented; ABI-F root ownership is
        otherwise consumed as published.
        """
        if not isinstance(record, dict):
            return False

        for key in (
            "transition_required",
            "storage_transition_required",
            "value_transition_required",
            "conversion_required",
        ):
            if record.get(key) is True:
                return True

        for key in (
            "identity_passthrough",
            "same_storage",
            "source_matches_unique_root",
        ):
            if key in record and record.get(key) is False:
                return True

        return False

    def _abi_root_identity_alias_for_sid_v46j(self, sid):
        """
        Resolve a derived SSA value through its unique ABI-F entry root.

        This is identity reuse, not name inference.  The accepted root must be
        uniquely published by ABI-F lineage/execution ownership and must not
        carry an explicit transition requirement.
        """
        if not self.abi_active or sid is None:
            return None

        root = self._abi_unique_root_for_sid_v46c(sid)
        if not isinstance(root, dict):
            return None

        root_sid = root.get("sid")
        if root_sid is None:
            return None

        root_name = self._abi_lookup_sid_v46(
            self.abi_execution_name_by_sid,
            root_sid,
        )
        if not root_name:
            return None

        sid_text = str(sid)
        root_sid_text = str(root_sid)

        if sid_text != root_sid_text:
            if self._abi_mutable_state_rejection_v46n(value=None, sid=sid):
                return None
            if not self._abi_identity_passthrough_proven_v46n(sid):
                return None
            node = self._abi_node_for_sid_v46n(sid)
            opcode = getattr(node, "opcode", None)
            if opcode is not None and opcode not in _TRANSPARENT:
                return None

        return {
            "name": str(root_name),
            "root_id": root.get("root_id"),
            "root_sid": root_sid_text,
            "source_sid": sid_text,
            "authority": (
                "ABI_F_affirmative_transparent_entry_identity_v46n"
            ),
        }

    @staticmethod
    def _abi_raw_identifier_token_v46j(name):
        if name is None:
            return None
        token = re.sub(r"[^A-Za-z0-9_]", "_", str(name))
        if token and token[0].isdigit():
            token = "v_" + token
        return token or None

    @staticmethod
    def _abi_context_role_tokens_v46p(record):
        if not isinstance(record, dict):
            return set()

        tokens = set()
        for key in (
            "role",
            "root_id",
            "canonical_alias",
            "execution_name",
            "destination",
            "register",
            "source_kind",
            "source_key",
            "name",
        ):
            value = record.get(key)
            if value is None:
                continue
            text = re.sub(
                r"[^a-z0-9]+",
                "_",
                str(value).lower(),
            ).strip("_")
            if text:
                tokens.add(text)

        return tokens

    @classmethod
    def _abi_record_is_immutable_context_v46p(
        cls,
        record,
    ):
        if not isinstance(record, dict):
            return False

        tokens = cls._abi_context_role_tokens_v46p(record)
        joined = "|".join(sorted(tokens))

        tls = bool(
            "thread_local_storage_base" in joined
            or "tls_base" in joined
            or "abi_tls_base" in joined
            or "fs_offset" in joined
        )
        stack_context = bool(
            "stack_pointer" in joined
            or "abi_stack_pointer" in joined
            or re.search(r"(^|_)rsp($|_)", joined)
        )

        return tls or stack_context

    def _abi_index_immutable_context_v46p(self):
        names = set()
        roots = set()

        for record in list(
            self.abi_entry_materialization_records
        ):
            if not self._abi_record_is_immutable_context_v46p(
                record
            ):
                continue
            name = record.get("name")
            root_id = record.get("root_id")
            if name:
                names.add(str(name))
            if root_id:
                roots.add(str(root_id))

        for key, root in self.abi_entry_roots_by_sid.items():
            if not isinstance(root, dict):
                continue
            if not self._abi_record_is_immutable_context_v46p(
                root
            ):
                continue

            root_id = root.get("root_id")
            if root_id:
                roots.add(str(root_id))

            sid = root.get("sid") or key
            name = self._abi_lookup_sid_v46(
                self.abi_execution_name_by_sid,
                sid,
            )
            if name:
                names.add(str(name))

            for key_name in (
                "canonical_alias",
                "execution_name",
            ):
                value = root.get(key_name)
                if value:
                    names.add(str(value))

        self.abi_immutable_context_alias_names = names
        self.abi_immutable_context_root_ids = roots

    def _abi_immutable_context_candidate_v46p(
        self,
        value,
        sid,
    ):
        if not self.abi_active:
            return None

        candidates = []

        raw = getattr(value, "var", value)
        raw_name = (
            getattr(raw, "name", None)
            if raw is not None and not isinstance(raw, str)
            else (
                raw if isinstance(raw, str) else None
            )
        )
        token = self._abi_raw_identifier_token_v46j(
            raw_name
        )

        if (
            token
            and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*",
                str(raw_name or ""),
            )
            and token
            in self.abi_exact_machine_carrier_alias_sources
            and token
            not in self.abi_ambiguous_raw_name_aliases
        ):
            aliases = self.abi_raw_name_alias_candidates.get(
                token
            )
            if isinstance(
                aliases,
                (set, frozenset, list, tuple),
            ):
                ordered = sorted(
                    str(item)
                    for item in aliases
                    if item is not None
                )
                if len(ordered) == 1:
                    candidates.append({
                        "name": ordered[0],
                        "source": (
                            "exact_machine_carrier_token"
                        ),
                        "source_name": token,
                    })

        for source, mapping in (
            (
                "abi_f_convergence_alias",
                self.abi_convergence_alias_by_sid,
            ),
            (
                "abi_f_executable_identity",
                self.abi_executable_identity_alias_by_sid,
            ),
        ):
            alias = self._abi_lookup_sid_v46(
                mapping,
                sid,
            )
            if alias:
                candidates.append({
                    "name": str(alias),
                    "source": source,
                })

        contract = self._abi_lookup_sid_v46(
            self.abi_entry_convergence_by_target_sid,
            sid,
        )
        if isinstance(contract, dict):
            root = (
                self._abi_root_for_id_v46(
                    contract.get("root_id")
                )
                or {}
            )
            root_sid = (
                root.get("sid")
                or contract.get("root_sid")
            )
            root_name = self._abi_lookup_sid_v46(
                self.abi_execution_name_by_sid,
                root_sid,
            )
            if (
                root_name
                and contract.get(
                    "all_predecessors_owned"
                ) is True
            ):
                candidates.append({
                    "name": str(root_name),
                    "source": (
                        "abi_f_all_owned_convergence"
                    ),
                    "root_id": contract.get("root_id"),
                })

        descriptor = None
        if sid is not None:
            try:
                descriptor = (
                    self._custody_descriptor_for_sid_v45(sid)
                )
            except Exception:
                descriptor = None

        if isinstance(descriptor, dict):
            high_token = self._abi_raw_identifier_token_v46j(
                descriptor.get("high_name")
            )
            aliases = (
                self.abi_raw_name_alias_candidates.get(
                    high_token
                )
                if high_token
                else None
            )
            if (
                high_token
                in self.abi_exact_machine_carrier_alias_sources
                and isinstance(
                    aliases,
                    (set, frozenset, list, tuple),
                )
            ):
                ordered = sorted(
                    str(item)
                    for item in aliases
                    if item is not None
                )
                if len(ordered) == 1:
                    candidates.append({
                        "name": ordered[0],
                        "source": (
                            "storage_family_machine_carrier"
                        ),
                        "source_name": high_token,
                        "family_id": descriptor.get(
                            "family_id"
                        ),
                    })

        accepted = []
        for candidate in candidates:
            name = candidate.get("name")
            if (
                name
                and str(name)
                in self.abi_immutable_context_alias_names
            ):
                accepted.append(candidate)

        names = sorted({
            str(item.get("name"))
            for item in accepted
            if item.get("name")
        })
        if len(names) != 1:
            return None

        name = names[0]
        selected = next(
            item
            for item in accepted
            if str(item.get("name")) == name
        )

        return {
            "name": name,
            "source_sid": (
                str(sid)
                if sid is not None
                else None
            ),
            "authority": (
                "ABI_D_F_immutable_context_continuity_v46p"
            ),
            **selected,
        }

    def _abi_note_immutable_context_v46p(
        self,
        contract,
        context,
    ):
        if not isinstance(contract, dict):
            return

        event = {
            "kind": (
                "emitter_abi_immutable_context_reused_v46p"
            ),
            "version": self.ABI_CUSTODY_VERSION,
            "projection": self.render_mode,
            "context": context,
            **contract,
        }

        self._abi_record_event_v46(
            self.abi_immutable_context_events,
            event,
            (
                "immutable_context",
                contract.get("source_sid"),
                contract.get("name"),
                context,
                contract.get("source"),
            ),
        )

    def _abi_exact_machine_carrier_alias_v46o(
        self,
        value,
    ):
        """
        Resolve one exact Ghidra machine-entry carrier spelling.

        This authority is narrower than the general raw-name alias table:

          * the source token must have been published from an ABI record's
            register/source identity;
          * the token must resolve to exactly one candidate;
          * the target must be one canonical ABI-D execution identity;
          * plain strings are rejected, so rendered expression text is never
            globally rewritten.

        This deliberately runs before mutable-state quarantine.  A carrier
        object may share a SID family with later arithmetic or storage state,
        but its exact ``in_<register>`` spelling still identifies the machine
        entry value.
        """
        if not self.abi_active or value is None:
            return None

        raw = getattr(value, "var", value)

        token = self._abi_raw_identifier_token_v46j(
            getattr(raw, "name", None)
        )
        if not token:
            return None

        raw_name = (
            raw
            if isinstance(raw, str)
            else getattr(raw, "name", None)
        )
        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*",
            str(raw_name or ""),
        ):
            return None

        if (
            token
            not in self.abi_exact_machine_carrier_alias_sources
        ):
            return None

        if token in self.abi_ambiguous_raw_name_aliases:
            return None

        candidates = self.abi_raw_name_alias_candidates.get(token)
        if not isinstance(
            candidates,
            (set, frozenset, list, tuple),
        ):
            return None

        ordered = sorted(
            str(item)
            for item in candidates
            if item is not None
        )
        if len(ordered) != 1:
            return None

        target = ordered[0]
        canonical_targets = {
            str(item)
            for item in self.abi_execution_name_by_sid.values()
            if item
        }
        if target not in canonical_targets:
            return None

        return {
            "name": target,
            "source_name": token,
            "authority": (
                "ABI_C_D_exact_machine_carrier_spelling_v46o"
            ),
        }

    def _abi_exact_variable_alias_v46j(self, value):
        """
        Resolve an exact variable object through the already-built ABI alias
        contract table.

        This does not rewrite arbitrary strings or expressions.  It examines
        only the variable object's own legacy name, requires one canonical
        owner, and rejects every ambiguous spelling.
        """
        if not self.abi_active or value is None:
            return None

        raw = getattr(value, "var", value)

        # A plain string may be an expression fragment.  Never treat it as a
        # variable identity at this boundary.
        if isinstance(raw, str):
            return None

        if self._abi_mutable_state_rejection_v46n(value=value, sid=self._sid_of(value)):
            return None

        token = self._abi_raw_identifier_token_v46j(
            getattr(raw, "name", None)
        )
        if not token:
            return None

        # v46o: every in_<register> spelling is exclusively owned by the
        # exact ABI-published machine-carrier path above.  The general alias
        # fallback must not provide a second, weaker admission route.
        if token.startswith("in_"):
            return None

        if token in self.abi_ambiguous_raw_name_aliases:
            return None

        candidates = self.abi_raw_name_alias_candidates.get(token)
        if not isinstance(candidates, (set, frozenset, list, tuple)):
            return None

        ordered = sorted(
            str(item) for item in candidates
            if item is not None
        )
        if len(ordered) != 1:
            return None

        return {
            "name": ordered[0],
            "source_name": token,
            "authority": (
                "ABI_C_D_F_exact_unambiguous_variable_alias_contract"
            ),
        }

    def _abi_expr_for_value_v46j(self, value, context="expression"):
        """
        Resolve an ABI value at the variable/operand boundary.

        Order:
          1. exact SID-owned ABI identity;
          2. unique ABI-F entry-root lineage;
          3. exact unambiguous legacy name attached to this variable object.

        The third step is deliberately object-bound and never scans or rewrites
        rendered expression text.
        """
        if not self.abi_active or value is None:
            return None

        sid = self._sid_of(value)

        direct = self._abi_lookup_sid_v46(
            self.abi_execution_name_by_sid,
            sid,
        )
        if direct:
            return direct

        immutable_context = (
            self._abi_immutable_context_candidate_v46p(
                value,
                sid,
            )
        )
        if isinstance(immutable_context, dict):
            name = immutable_context.get("name")
            if name:
                self._abi_note_immutable_context_v46p(
                    immutable_context,
                    context,
                )
                return name

        machine_carrier = (
            self._abi_exact_machine_carrier_alias_v46o(value)
        )
        if isinstance(machine_carrier, dict):
            name = machine_carrier.get("name")
            if name:
                self._abi_record_event_v46(
                    self.abi_identity_reuse_events,
                    {
                        "kind": (
                            "emitter_abi_exact_machine_carrier_"
                            "reused_v46o"
                        ),
                        "version": self.ABI_CUSTODY_VERSION,
                        "projection": self.render_mode,
                        "context": context,
                        "source_sid": (
                            str(sid)
                            if sid is not None
                            else None
                        ),
                        **machine_carrier,
                    },
                    (
                        "exact_machine_carrier",
                        str(sid),
                        str(
                            machine_carrier.get(
                                "source_name"
                            )
                        ),
                        context,
                    ),
                )
                return name

        rejection = self._abi_mutable_state_rejection_v46n(
            value=value,
            sid=sid,
        )
        if isinstance(rejection, dict):
            self._abi_note_identity_quarantine_v46n(value, sid, rejection, context)
            return None

        exact = self._abi_expr_for_sid_v46(
            sid,
            context=context,
        )
        if exact is not None:
            return exact

        root_alias = self._abi_root_identity_alias_for_sid_v46j(sid)
        if isinstance(root_alias, dict):
            name = root_alias.get("name")
            if name:
                self._abi_record_event_v46(
                    self.abi_identity_reuse_events,
                    {
                        "kind": (
                            "emitter_abi_entry_root_identity_reused_v46j"
                        ),
                        "version": self.ABI_CUSTODY_VERSION,
                        "projection": self.render_mode,
                        "context": context,
                        **root_alias,
                    },
                    (
                        "entry_root_identity",
                        str(sid),
                        str(root_alias.get("root_id")),
                        context,
                    ),
                )
                return name

        variable_alias = self._abi_exact_variable_alias_v46j(value)
        if isinstance(variable_alias, dict):
            name = variable_alias.get("name")
            if name:
                self._abi_record_event_v46(
                    self.abi_identity_reuse_events,
                    {
                        "kind": (
                            "emitter_abi_exact_variable_identity_reused_v46j"
                        ),
                        "version": self.ABI_CUSTODY_VERSION,
                        "projection": self.render_mode,
                        "context": context,
                        "source_sid": (
                            str(sid) if sid is not None else None
                        ),
                        **variable_alias,
                    },
                    (
                        "exact_variable_identity",
                        str(sid),
                        str(variable_alias.get("source_name")),
                        context,
                    ),
                )
                return name

        return None

    def _abi_name_for_sid_v46(self, sid):
        if sid is None:
            return None
        alias = self._abi_lookup_sid_v46(self.abi_execution_name_by_sid, sid)
        if alias:
            return alias
        if self._abi_mutable_state_rejection_v46n(value=None, sid=sid):
            return None
        if not self._is_readable_render_v44():
            alias = self._abi_lookup_sid_v46(self.abi_executable_identity_alias_by_sid, sid)
            if alias:
                return alias
        alias = self._abi_lookup_sid_v46(self.abi_convergence_alias_by_sid, sid)
        if alias:
            return alias
        root_alias = self._abi_root_identity_alias_for_sid_v46j(sid)
        if isinstance(root_alias, dict):
            return root_alias.get("name")
        return None

    def _abi_expr_for_sid_v46(self, sid, context="expression"):
        if not self.abi_active or sid is None:
            return None
        alias = self._abi_name_for_sid_v46(sid)
        if not alias:
            return None
        if self._abi_lookup_sid_v46(self.abi_convergence_alias_by_sid, sid):
            self._abi_record_event_v46(
                self.abi_convergence_render_events,
                {
                    "kind": "emitter_abi_convergence_alias_consumed_v46",
                    "version": self.ABI_CUSTODY_VERSION,
                    "projection": self.render_mode,
                    "target_sid": str(sid),
                    "rendered_name": alias,
                    "context": context,
                    "authority": "PHIfolder_ABI_F_convergence_contract",
                },
                ("convergence_alias", str(sid), context),
            )
        return alias

    def _apply_abi_raw_alias_rewrites_v46(self, expr):
        if not self.abi_active or not isinstance(expr, str) or not expr:
            return expr
        out = str(expr)
        replacements = []
        for mapping in (
            self.abi_execution_name_by_sid,
            self.abi_convergence_alias_by_sid,
        ):
            for sid, name in mapping.items():
                if sid is None or not name:
                    continue
                for source in self._abi_sid_identifier_spellings_v46f(sid):
                    if source and str(source) != str(name):
                        replacements.append((str(source), str(name)))
        if not self._is_readable_render_v44():
            for source, target in self.abi_raw_name_aliases.items():
                if source and target and str(source) != str(target):
                    replacements.append((str(source), str(target)))
            for sid, name in self.abi_executable_identity_alias_by_sid.items():
                if sid and name and str(sid) != str(name):
                    replacements.append((str(sid), str(name)))
        for source, target in sorted(
            set(replacements), key=lambda item: len(item[0]), reverse=True
        ):
            out = re.sub(r"\b%s\b" % re.escape(source), target, out)
        return out

    def _abi_signature_parameters_v46(self):
        if not self.abi_active:
            return [self._var(param) for param in (
                getattr(self.func, "parameters", []) or []
            )]
        # ABI-C explicitly separates callable parameters from implicit
        # machine state.  The current invocation context is acquired inside
        # the function; it is never smuggled back into the Python signature.
        return list(self.abi_fixed_argument_names)

    def _emit_abi_context_binding_v46(self):
        if not self.abi_active or not self.abi_context_required:
            return
        plan_id = self.abi_function_entry_plan.get("plan_id")
        if self._is_readable_render_v44():
            expr = "ABI.current(%r)" % plan_id
        else:
            self.c_truth_required_helpers.add("c_abi_context")
            expr = "c_abi_context(%r)" % plan_id
        self._w(
            "%s = %s" % (self.abi_context_name, expr),
            provenance={
                "role": "abi_context_binding",
                "metadata_refs": ["abi:context", "abi:entry_plan"],
            },
        )

    def _abi_entry_materialization_expr_v46(self, record):
        source_kind = str(record.get("source_kind") or "machine_state")
        source_key = record.get("source_key")
        width = record.get("width_bits")
        context = self.abi_context_name
        if self._is_readable_render_v44():
            if source_kind == "registers" and source_key:
                return "%s.registers[%r]" % (context, str(source_key))
            if source_key and source_kind in (
                "register_save_area", "machine_state", "condition_flags"
            ):
                return "%s.%s[%r]" % (
                    context, self._sanitize_name(source_kind), str(source_key)
                )
            return "%s.%s" % (context, self._sanitize_name(source_kind))
        self.c_truth_required_helpers.add("c_abi_get")
        return "c_abi_get(%s, %r, %r, %r)" % (
            context, source_kind, source_key, width
        )

    def _emit_abi_entry_prologue_v46(self):
        if not self.abi_active:
            return
        self._emit_abi_context_binding_v46()
        records = list(self.abi_entry_materialization_records)
        records.extend(self.abi_entry_context_records)
        for record in records:
            name = record.get("name")
            if not name:
                continue
            expr = self._abi_entry_materialization_expr_v46(record)
            self._w(
                "%s = %s" % (name, expr),
                provenance={
                    "role": "abi_entry_materialization",
                    "definition_sids": [record.get("sid")],
                    "metadata_refs": [
                        "abi:entry:%s" % str(record.get("sid"))
                    ],
                },
            )
            self._abi_record_event_v46(
                self.abi_entry_materialization_events,
                dict(record, projection=self.render_mode, rendered=expr),
                ("entry", record.get("sid")),
            )

    def _abi_call_plan_for_op_v46(self, op):
        if not self.abi_active or op is None:
            return None
        direct = getattr(op, "call_site_abi_plan", None)
        if isinstance(direct, dict):
            return direct
        compute = self._c_truth_plan_for_op(op)
        if isinstance(compute, dict):
            direct = compute.get("call_site_abi_plan")
            if isinstance(direct, dict):
                return direct
            op_key = compute.get("op_key")
            if op_key is not None:
                plan = self.abi_call_site_plans_by_op.get(str(op_key))
                if isinstance(plan, dict):
                    return plan
        op_id = getattr(op, "op_id", None)
        if op_id is not None:
            plan = self.abi_call_plans_by_op_id.get(str(op_id))
            if isinstance(plan, dict):
                return plan
            # Some frozen object adapters do not retain the direct sidecar on
            # the reconstructed op.  Match the published op_id exactly; this
            # is metadata lookup, not argument/carrier inference.
            for candidate in self.abi_call_plans_by_plan_id.values():
                if (
                    isinstance(candidate, dict)
                    and str(candidate.get("op_id")) == str(op_id)
                ):
                    return candidate
        return None

    def _abi_fail_closed_call_expr_v46(self, op, reason):
        op_id = str(getattr(op, "op_id", None))
        message = "PAL ABI call emission blocked: %s op_id=%s" % (
            reason, op_id
        )
        if self._is_readable_render_v44():
            return "ABI.unplanned_call(%r)" % message
        # Keep this self-contained so a missing plan cannot itself require a
        # guessed runtime helper import.  Executing the expression raises at
        # the exact call boundary instead of silently using legacy placement.
        return "(_ for _ in ()).throw(RuntimeError(%r))" % message

    def _abi_call_values_v46(self, op, plan):
        inputs = list(getattr(op, "inputs", []) or [])
        values = inputs[1:] if inputs else []
        arguments = sorted(
            list(plan.get("arguments") or []),
            key=lambda item: (
                item.get("index") is None,
                item.get("index") if isinstance(item.get("index"), int) else 0,
            ),
        )
        if len(arguments) != len(values):
            return None, {
                "kind": "emitter_abi_call_argument_mismatch_v46",
                "plan_id": plan.get("plan_id"),
                "reason": "argument_count_mismatch",
                "planned": len(arguments),
                "observed": len(values),
            }
        pairs = []
        for fallback_index, (argument, value) in enumerate(zip(arguments, values)):
            index = argument.get("index")
            if not isinstance(index, int):
                index = fallback_index
            source_sid = argument.get("source_sid")
            observed_sid = self._sid_of(value)
            if source_sid is not None and str(source_sid) != str(observed_sid):
                return None, {
                    "kind": "emitter_abi_call_argument_mismatch_v46",
                    "plan_id": plan.get("plan_id"),
                    "reason": "argument_sid_mismatch",
                    "index": index,
                    "planned_sid": source_sid,
                    "observed_sid": observed_sid,
                }
            pairs.append((argument, value))
        return pairs, None

    @staticmethod
    def _abi_return_carrier_literal_v46(contract):
        contract = contract if isinstance(contract, dict) else {}
        pieces = []
        for piece in list(contract.get("carrier_pieces") or []):
            if not isinstance(piece, dict):
                continue
            register = piece.get("register")
            if isinstance(register, dict):
                register = register.get("name") or register.get("base_name")
            pieces.append((
                piece.get("kind"),
                register,
                piece.get("width_bits"),
                piece.get("storage_key"),
            ))
        return repr(tuple(pieces))

    def _abi_call_expr_from_op_v46(self, op):
        plan = self._abi_call_plan_for_op_v46(op)
        if not isinstance(plan, dict):
            if self.abi_active:
                self.abi_render_warnings.append({
                    "kind": "emitter_abi_call_plan_missing_v46",
                    "op_id": str(getattr(op, "op_id", None)),
                    "block_addr": getattr(self, "_current_block_addr", None),
                    "action": "emit_fail_closed_call_boundary_and_fail_ABI_gate",
                })
                return self._abi_fail_closed_call_expr_v46(
                    op, "missing call_site_abi_plan"
                )
            return None
        pairs, mismatch = self._abi_call_values_v46(op, plan)
        if mismatch:
            self.abi_render_warnings.append(mismatch)
            return self._abi_fail_closed_call_expr_v46(
                op, mismatch.get("reason") or "call plan mismatch"
            )

        inputs = list(getattr(op, "inputs", []) or [])
        target = dict(plan.get("target") or {})
        target_name = target.get("name")
        if getattr(op, "opcode", None) == "CALLIND":
            target_expr = self._expr(inputs[0]) if inputs else "None"
            readable_target = target_expr
        else:
            if not target_name and inputs:
                target_name = self._call_name(inputs[0])
            target_expr = repr(str(target_name or "sub_unknown"))
            readable_target = self._sanitize_name(str(target_name or "sub_unknown"))

        rendered_values = [
            self._readable_call_argument_expr_v46i(value)
            for _, value in pairs
        ]
        if self._is_readable_render_v44():
            expr = "%s(%s)" % (readable_target, ", ".join(rendered_values))
        else:
            # Runtime code transports values, not PAL metadata records.  The
            # frozen call_site_abi_plan remains authoritative and is selected
            # by plan_id inside the ABI harness.  This keeps source SIDs,
            # carrier allocation, linkage, widths, and no-return policy in the
            # icecube instead of replacing a Python argument with a dict.
            value_tuple = "(%s%s)" % (
                ", ".join(rendered_values),
                "," if len(rendered_values) == 1 else "",
            )
            self.c_truth_required_helpers.add("c_abi_call")
            expr = (
                "c_abi_call(%s, %s, %s, plan_id=%r)"
                % (
                    self.abi_context_name,
                    target_expr,
                    value_tuple,
                    plan.get("plan_id"),
                )
            )

        self._abi_record_event_v46(
            self.abi_call_render_events,
            {
                "kind": "emitter_abi_call_plan_rendered_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "projection": self.render_mode,
                "plan_id": plan.get("plan_id"),
                "op_key": plan.get("op_key"),
                "dispatch_class": plan.get("dispatch_class"),
                "argument_count": len(pairs),
                "argument_sid_match": True,
                "runtime_surface": "value_tuple_plus_plan_id",
                "no_return": bool(plan.get("no_return")),
                "rendered": expr,
                "authority": plan.get("authority"),
            },
            ("call", plan.get("plan_id")),
        )
        return expr

    def _abi_call_is_no_return_v46(self, op):
        plan = self._abi_call_plan_for_op_v46(op)
        return bool(isinstance(plan, dict) and plan.get("no_return") is True)

    def _abi_call_provenance_v46(self, op):
        plan = self._abi_call_plan_for_op_v46(op)
        if not isinstance(plan, dict):
            return None
        refs = []
        if plan.get("plan_id") is not None:
            refs.append("abi:call:%s" % str(plan.get("plan_id")))
        if plan.get("op_key") is not None:
            refs.append("abi:call_op:%s" % str(plan.get("op_key")))
        return {
            "role": "abi_call_boundary",
            "metadata_refs": refs,
        }

    def _abi_return_boundary_v46(self, block_or_addr):
        addr = (
            getattr(block_or_addr, "addr", None)
            if block_or_addr is not None and not isinstance(block_or_addr, (int, str))
            else block_or_addr
        )
        if addr in self.abi_return_boundaries_by_block:
            return self.abi_return_boundaries_by_block.get(addr)
        return self.abi_return_boundaries_by_block.get(str(addr))

    def _abi_return_is_suppressed_v46(self, block_or_addr):
        if not self.abi_active:
            return False
        boundary = self._abi_return_boundary_v46(block_or_addr)
        return bool(
            isinstance(boundary, dict)
            and (
                boundary.get("execution_suppressed") is True
                or boundary.get("reachable_return") is False
            )
        )

    def _abi_record_return_suppression_v46(self, block_or_addr, boundary=None):
        boundary = boundary or self._abi_return_boundary_v46(block_or_addr) or {}
        addr = getattr(block_or_addr, "addr", block_or_addr)
        self._abi_record_event_v46(
            self.abi_return_render_events,
            {
                "kind": "emitter_abi_unreachable_return_suppressed_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "projection": self.render_mode,
                "block_addr": addr,
                "return_reachability": boundary.get("return_reachability"),
                "cut_by_no_return_blocks": list(
                    boundary.get("cut_by_no_return_blocks") or []
                ),
                "authority": "PALCompute_return_boundary_reconciliation",
            },
            ("return_suppressed", addr),
        )

    def _abi_return_expr_v46(self, block_or_addr, expr):
        if not self.abi_active:
            return None
        boundary = self._abi_return_boundary_v46(block_or_addr) or {}
        contract = dict(
            self.abi_function_entry_plan.get("return_contract") or {}
        )
        width = (
            boundary.get("return_logical_width_bits")
            or contract.get("logical_result_width_bits")
            or contract.get("effective_result_width_bits")
            or boundary.get("return_transport_width_bits")
        )
        if self._is_readable_render_v44():
            rendered = expr
        else:
            carriers = list(contract.get("carrier_pieces") or [])
            if carriers and self.abi_context_required:
                self.c_truth_required_helpers.add("c_abi_return")
                rendered = (
                    "c_abi_return(%s, %s, %r, %s, plan_id=%r)"
                    % (
                        self.abi_context_name,
                        expr,
                        width,
                        self._abi_return_carrier_literal_v46(contract),
                        self.abi_function_entry_plan.get("plan_id"),
                    )
                )
            elif isinstance(width, int) and width > 0:
                self.c_truth_required_helpers.add("c_return_bits")
                rendered = "c_return_bits(%s, %s)" % (expr, width)
            else:
                rendered = expr
                self.abi_render_warnings.append({
                    "kind": "emitter_abi_return_width_deferred_v46",
                    "block_addr": getattr(block_or_addr, "addr", block_or_addr),
                    "return_contract_status": contract.get("status"),
                    "action": "preserve_raw_return_expression",
                })
        self._abi_record_event_v46(
            self.abi_return_render_events,
            {
                "kind": "emitter_abi_return_boundary_rendered_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "projection": self.render_mode,
                "block_addr": getattr(block_or_addr, "addr", block_or_addr),
                "width_bits": width,
                "carrier_count": len(contract.get("carrier_pieces") or []),
                "rendered": rendered,
                "authority": contract.get("authority"),
            },
            ("return", getattr(block_or_addr, "addr", block_or_addr)),
        )
        return rendered

    def _abi_projection_debug_v46(self, rendered_lines):
        text = "\n".join(str(line) for line in list(rendered_lines or []))
        identifier_uses = None
        parsed = None
        try:
            parsed = ast.parse(text)
            identifier_uses = {
                node.id for node in ast.walk(parsed)
                if isinstance(node, ast.Name)
            }
        except Exception:
            # Rendering diagnostics must not mask the primary emitter error.
            # Fall back to the legacy lexical probe when a partial projection
            # cannot yet be parsed.
            identifier_uses = None

        def contains_identifier(name):
            if identifier_uses is not None:
                return str(name) in identifier_uses
            return bool(re.search(r"\b%s\b" % re.escape(str(name)), text))
        required_entry_sids = {
            str(item.get("sid")) for item in (
                list(self.abi_entry_materialization_records)
                + list(self.abi_entry_context_records)
            )
            if item.get("sid") is not None
        }
        rendered_entry_sids = {
            str(item.get("sid")) for item in self.abi_entry_materialization_events
            if item.get("projection") == self.render_mode
            and item.get("sid") is not None
        }
        required_call_ids = {
            str(plan.get("plan_id"))
            for plan in self.abi_call_site_plans_by_op.values()
            if isinstance(plan, dict) and plan.get("plan_id") is not None
        }
        rendered_call_ids = {
            str(item.get("plan_id")) for item in self.abi_call_render_events
            if item.get("projection") == self.render_mode
            and item.get("plan_id") is not None
        }
        required_storage_initializer_keys = set()
        rendered_storage_initializer_keys = set()
        if not self._is_readable_render_v44():
            required_storage_initializer_keys = {
                str(key) for key in self.abi_entry_storage_initializers_by_op
                if key is not None
            }
            rendered_storage_initializer_keys = {
                str(item.get("op_key"))
                for item in self.abi_entry_storage_initializer_events
                if item.get("projection") == self.render_mode
                and item.get("op_key") is not None
            }
        missing_storage_initializers = sorted(
            required_storage_initializer_keys
            - rendered_storage_initializer_keys
        )

        required_fixed_local_initializer_keys = {
            str(key)
            for key in self.abi_fixed_argument_local_initializers_by_op
            if key is not None
        }
        rendered_fixed_local_initializer_keys = {
            str(item.get("op_key"))
            for item in self.abi_fixed_argument_local_initializer_events
            if item.get("projection") == self.render_mode
            and item.get("op_key") is not None
        }
        missing_fixed_local_initializers = sorted(
            required_fixed_local_initializer_keys
            - rendered_fixed_local_initializer_keys
        )
        required_phi_entry_seed_keys = {
            str(key)
            for key in self.abi_phi_entry_local_seed_contracts_by_key
            if key is not None
        }
        rendered_phi_entry_seed_keys = {
            str(item.get("dropin_key_text"))
            for item in self.abi_phi_entry_local_seed_events
            if item.get("projection") == self.render_mode
            and item.get("dropin_key_text") is not None
        }
        missing_phi_entry_seeds = sorted(
            required_phi_entry_seed_keys
            - rendered_phi_entry_seed_keys
        )

        rejected_storage_initializer_candidates = []
        if not self._is_readable_render_v44():
            rejected_storage_initializer_candidates = [
                copy.deepcopy(record)
                for _, record in sorted(
                    self.abi_entry_storage_initializer_rejections.items(),
                    key=lambda item: str(item[0]),
                )
            ]
        raw_convergence_leaks = []
        for sid, alias in self.abi_convergence_alias_by_sid.items():
            if contains_identifier(sid):
                raw_convergence_leaks.append({"sid": sid, "alias": alias})
        raw_identity_leaks = []
        if not self._is_readable_render_v44():
            for source, alias in sorted(self.abi_raw_name_aliases.items()):
                if contains_identifier(source):
                    raw_identity_leaks.append({
                        "source": source,
                        "alias": alias,
                    })
        ambiguous_raw_identity_uses = []
        if not self._is_readable_render_v44():
            fixed_names = {
                str(name) for name in self.abi_fixed_argument_names
            }
            for source, record in sorted(
                self.abi_ambiguous_raw_name_aliases.items()
            ):
                if source in fixed_names or not contains_identifier(source):
                    continue
                ambiguous_raw_identity_uses.append(dict(
                    record,
                    executable_identifier_observed=True,
                    action=(
                        "fail_closed_require_formula_SID_or_explicit_"
                        "logical_parameter_owner"
                    ),
                ))
        inline_call_descriptor_leaks = []
        if parsed is not None and not self._is_readable_render_v44():
            for node in ast.walk(parsed):
                if not isinstance(node, ast.Call):
                    continue
                if not (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "c_abi_call"
                ):
                    continue
                plan_keywords = [
                    item for item in node.keywords
                    if item.arg == "plan_id"
                ]
                dict_literals = [
                    item for item in ast.walk(node)
                    if isinstance(item, ast.Dict)
                ]
                values_is_tuple = bool(
                    len(node.args) >= 3
                    and isinstance(node.args[2], ast.Tuple)
                )
                if dict_literals or not values_is_tuple or len(plan_keywords) != 1:
                    inline_call_descriptor_leaks.append({
                        "line_number": getattr(node, "lineno", None),
                        "dict_literals": len(dict_literals),
                        "runtime_values_tuple": values_is_tuple,
                        "plan_id_references": len(plan_keywords),
                    })
        missing_entry = sorted(required_entry_sids - rendered_entry_sids)
        missing_calls = sorted(required_call_ids - rendered_call_ids)
        warnings = list(self.abi_render_warnings)
        if missing_entry:
            warnings.append({
                "kind": "emitter_abi_entry_materialization_missing_v46",
                "projection": self.render_mode,
                "sids": missing_entry,
            })
        if missing_calls:
            warnings.append({
                "kind": "emitter_abi_call_plan_unrendered_v46",
                "projection": self.render_mode,
                "plan_ids": missing_calls,
                "note": "may_be_structurally_unreachable_or_missing_from_ExecTree",
            })
        if missing_storage_initializers:
            warnings.append({
                "kind": "emitter_abi_entry_storage_initializer_missing_v46b",
                "projection": self.render_mode,
                "op_keys": missing_storage_initializers,
                "action": "fail_executable_ABI_storage_custody_gate",
            })
        if missing_fixed_local_initializers:
            warnings.append({
                "kind": (
                    "emitter_abi_fixed_argument_local_initializer_"
                    "missing_v46k"
                ),
                "projection": self.render_mode,
                "op_keys": missing_fixed_local_initializers,
                "action": (
                    "fail_ABI_entry_local_state_substantiation_gate"
                ),
            })
        if missing_phi_entry_seeds:
            warnings.append({
                "kind": (
                    "emitter_abi_phi_entry_local_seed_missing_v46m"
                ),
                "projection": self.render_mode,
                "dropin_keys": missing_phi_entry_seeds,
                "action": (
                    "fail_loop_entry_local_state_substantiation_gate"
                ),
            })
        if rejected_storage_initializer_candidates:
            warnings.append({
                "kind": "emitter_abi_entry_storage_candidates_rejected_v46d",
                "projection": self.render_mode,
                "candidates": rejected_storage_initializer_candidates,
                "action": "fail_executable_ABI_storage_custody_gate",
            })
        if raw_convergence_leaks:
            warnings.append({
                "kind": "emitter_abi_raw_convergence_target_leak_v46",
                "projection": self.render_mode,
                "targets": raw_convergence_leaks,
            })
        if raw_identity_leaks:
            warnings.append({
                "kind": "emitter_abi_raw_identity_name_leak_v46b",
                "projection": self.render_mode,
                "identities": raw_identity_leaks,
            })
        if ambiguous_raw_identity_uses:
            warnings.append({
                "kind": "emitter_abi_ambiguous_legacy_name_used_v46d",
                "projection": self.render_mode,
                "identities": ambiguous_raw_identity_uses,
                "action": "fail_executable_ABI_identity_gate",
            })
        if inline_call_descriptor_leaks:
            warnings.append({
                "kind": "emitter_abi_inline_call_metadata_leak_v46c",
                "projection": self.render_mode,
                "sites": inline_call_descriptor_leaks,
                "action": "fail_executable_ABI_call_surface_gate",
            })
        unplanned_call_boundaries = [
            item for item in warnings
            if isinstance(item, dict)
            and item.get("kind") in {
                "emitter_abi_call_plan_missing_v46",
                "emitter_abi_call_argument_mismatch_v46",
            }
        ]
        summary = {
            "kind": "emitter_abi_custody_inventory_v46",
            "version": self.ABI_CUSTODY_VERSION,
            "projection": self.render_mode,
            "active": bool(self.abi_active),
            "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
            "entry_plan_status": self.abi_function_entry_plan.get("status"),
            "fixed_arguments": len(self.abi_fixed_argument_names),
            "runtime_context_required": bool(self.abi_context_required),
            "runtime_context_transport": (
                "current_invocation_context_not_python_argument"
                if self.abi_context_required else "not_required"
            ),
            "entry_materializations_required": len(required_entry_sids),
            "entry_materializations_rendered": len(rendered_entry_sids),
            "entry_materializations_missing": len(missing_entry),
            "entry_storage_initializers_required": len(
                required_storage_initializer_keys
            ),
            "entry_storage_initializers_rendered": len(
                rendered_storage_initializer_keys
            ),
            "entry_storage_initializers_missing": len(
                missing_storage_initializers
            ),
            "entry_storage_initializer_candidates_rejected": len(
                rejected_storage_initializer_candidates
            ),
            "fixed_argument_local_initializers_required": len(
                required_fixed_local_initializer_keys
            ),
            "fixed_argument_local_initializers_rendered": len(
                rendered_fixed_local_initializer_keys
            ),
            "fixed_argument_local_initializers_missing": len(
                missing_fixed_local_initializers
            ),
            "phi_entry_local_seeds_required": len(
                required_phi_entry_seed_keys
            ),
            "phi_entry_local_seeds_rendered": len(
                rendered_phi_entry_seed_keys
            ),
            "phi_entry_local_seeds_missing": len(
                missing_phi_entry_seeds
            ),
            "call_plans_required": len(required_call_ids),
            "call_plans_rendered": len(rendered_call_ids),
            "call_plans_unrendered": len(missing_calls),
            "unplanned_call_boundaries": len(unplanned_call_boundaries),
            "convergence_contracts": len(self.abi_entry_convergence_contracts),
            "convergence_aliases": len(self.abi_convergence_alias_by_sid),
            "entry_identity_reuses": len([
                item for item in self.abi_identity_reuse_events
                if item.get("projection") == self.render_mode
            ]),
            "entry_identity_state_quarantines": len([
                item for item in self.abi_identity_reuse_rejections
                if item.get("projection") == self.render_mode
            ]),
            "immutable_context_reuses": len([
                item for item in self.abi_immutable_context_events
                if item.get("projection") == self.render_mode
            ]),
            "unresolved_identity_events": len(
                self.abi_unresolved_identity_events
            ),
            "exact_machine_carrier_reuses": len([
                item for item in self.abi_identity_reuse_events
                if (
                    item.get("projection") == self.render_mode
                    and item.get("kind")
                    == (
                        "emitter_abi_exact_machine_carrier_"
                        "reused_v46o"
                    )
                )
            ]),
            "raw_convergence_target_leaks": len(raw_convergence_leaks),
            "raw_ABI_identity_name_leaks": len(raw_identity_leaks),
            "ambiguous_legacy_aliases_declared": len(
                self.abi_ambiguous_raw_name_aliases
            ),
            "ambiguous_legacy_alias_uses": len(
                ambiguous_raw_identity_uses
            ),
            "inline_call_metadata_leaks": len(
                inline_call_descriptor_leaks
            ),
            "must_print_dropin_overrides": len(
                self.abi_entry_must_print_dropin_ids
            ),
            "path_sensitive_unbound_names": len(
                self.abi_entry_path_unbound_records
            ),
            "return_events": len([
                item for item in self.abi_return_render_events
                if item.get("projection") == self.render_mode
            ]),
            "warnings": len(warnings),
            "acceptance_gates": {
                "entry_state_fully_materialized": not missing_entry,
                "entry_shared_storage_fully_initialized": (
                    not missing_storage_initializers
                    and not rejected_storage_initializer_candidates
                ),
                "fixed_argument_local_state_substantiated": (
                    not missing_fixed_local_initializers
                ),
                "phi_entry_local_state_substantiated": (
                    not missing_phi_entry_seeds
                ),
                "all_call_plans_consumed": not missing_calls,
                "no_unplanned_call_boundaries": not unplanned_call_boundaries,
                "all_convergence_targets_canonicalized": not raw_convergence_leaks,
                "all_ABI_identity_names_canonicalized": not raw_identity_leaks,
                "no_ambiguous_legacy_alias_uses": (
                    not ambiguous_raw_identity_uses
                ),
                "call_surface_contains_runtime_values_only": (
                    not inline_call_descriptor_leaks
                ),
                "no_path_sensitive_unbound_names": not self.abi_entry_path_unbound_records,
                "implicit_state_not_python_argument": (
                    self.abi_context_name not in self.abi_fixed_argument_names
                ),
                "no_downstream_ABI_reinference": not any(
                    item.get("kind") == "emitter_abi_authority_violation_v46"
                    for item in warnings if isinstance(item, dict)
                ),
            },
            "rule": (
                "render_ABI_D_plans_and_ABI_F_execution_owners_without_"
                "carrier_or_signature_reinference"
            ),
        }
        return {
            "summary": summary,
            "entry_materializations": copy.deepcopy(
                self.abi_entry_materialization_events
            ),
            "entry_storage_initializers": copy.deepcopy(
                self.abi_entry_storage_initializer_events
            ),
            "entry_storage_initializer_rejections": (
                rejected_storage_initializer_candidates
            ),
            "fixed_argument_local_initializers": copy.deepcopy(
                self.abi_fixed_argument_local_initializer_events
            ),
            "phi_entry_local_seeds": copy.deepcopy(
                self.abi_phi_entry_local_seed_events
            ),
            "call_render_events": copy.deepcopy(self.abi_call_render_events),
            "convergence_render_events": copy.deepcopy(
                self.abi_convergence_render_events
            ),
            "identity_reuse_events": copy.deepcopy(
                self.abi_identity_reuse_events
            ),
            "identity_reuse_rejections": copy.deepcopy(
                self.abi_identity_reuse_rejections
            ),
            "immutable_context_events": copy.deepcopy(
                self.abi_immutable_context_events
            ),
            "unresolved_identity_events": copy.deepcopy(
                self.abi_unresolved_identity_events
            ),
            "return_render_events": copy.deepcopy(
                self.abi_return_render_events
            ),
            "raw_convergence_target_leaks": raw_convergence_leaks,
            "raw_ABI_identity_name_leaks": raw_identity_leaks,
            "ambiguous_legacy_aliases": copy.deepcopy(
                list(self.abi_ambiguous_raw_name_aliases.values())
            ),
            "ambiguous_legacy_alias_uses": ambiguous_raw_identity_uses,
            "inline_call_metadata_leaks": inline_call_descriptor_leaks,
            "warnings": warnings,
        }

    # =========================================================
    # v43 / INNING M C-TRUTH CONTRACT RENDERER
    # =========================================================

    def _c_truth_plan_for_sid(self, sid):
        if sid is None:
            return None

        for key in (sid, str(sid)):
            alias_binding = self.c_truth_alias_bindings_by_sid.get(key)
            if isinstance(alias_binding, dict):
                plan = alias_binding.get("source_compute_contract")
                if isinstance(plan, dict):
                    return plan

            binding = self.c_truth_bindings_by_sid.get(key)
            if isinstance(binding, dict):
                plan = binding.get("compute_contract")
                if isinstance(plan, dict):
                    return plan

            plan = self.c_truth_compute_plans_by_sid.get(key)
            if isinstance(plan, dict):
                return plan

        return None

    def _c_truth_plan_for_op(self, op):
        if op is None:
            return None

        plan = getattr(op, "compute_contract", None)
        if isinstance(plan, dict):
            return plan

        out = getattr(op, "output", None)
        plan = getattr(out, "compute_plan", None) if out is not None else None
        if isinstance(plan, dict):
            return plan

        sid = self._sid_of(out)
        plan = self._c_truth_plan_for_sid(sid)
        if isinstance(plan, dict):
            return plan

        # Outputless operations are keyed by PALCompute op_key, which is not
        # the same as the emitter's duplicate-suppression key.  Prefer the
        # contract attached directly to the op; otherwise match stable op_id.
        op_id = getattr(op, "op_id", None) or getattr(op, "hf_seqnum", None)
        opcode = getattr(op, "opcode", None)
        for contract in self.c_truth_outputless_contracts_by_op.values():
            if not isinstance(contract, dict):
                continue
            if opcode and contract.get("opcode") != opcode:
                continue
            if op_id is not None and str(contract.get("op_id")) == str(op_id):
                return contract

        return None

    def _c_truth_plan_for_node(self, node):
        if node is None:
            return None
        plan = getattr(node, "compute_contract", None)
        if isinstance(plan, dict):
            return plan
        binding = getattr(node, "phi_compute_binding", None)
        if isinstance(binding, dict):
            plan = binding.get("compute_contract")
            if isinstance(plan, dict):
                return plan
        return self._c_truth_plan_for_sid(self._sid_of(getattr(node, "var", None)))

    def _c_truth_contract_has_runtime_semantics(self, contract):
        if not self.c_truth_active or self._c_truth_rendering_disabled:
            return False
        if not isinstance(contract, dict):
            return False
        return bool(
            contract.get("runtime_helper")
            or contract.get("normalize_result_to_output_width")
            or str(contract.get("status") or "").startswith("deferred_")
        )

    def _c_truth_contract_for_sid_has_helper(self, sid):
        plan = self._c_truth_plan_for_sid(sid)
        return bool(
            self.c_truth_active
            and not self._c_truth_rendering_disabled
            and isinstance(plan, dict)
            and plan.get("runtime_helper")
        )

    def _c_truth_width(self, contract, input_index=None, output=False, fallback=32):
        if not isinstance(contract, dict):
            return fallback

        if output:
            width = contract.get("output_width_bits")
        else:
            widths = list(contract.get("input_widths_bits", []) or [])
            width = widths[input_index or 0] if len(widths) > (input_index or 0) else None
            if width is None:
                width = contract.get("output_width_bits")

        try:
            width = int(width)
        except Exception:
            width = fallback
        return width if width > 0 else fallback

    def _c_truth_operand_expr(self, value, seen=None):
        if getattr(value, "is_constant", False):
            # Helpers own signed/unsigned interpretation.  Preserve the raw
            # constant bits instead of pre-signing literals in the emitter.
            return self._const(value)

        abi_expr = self._abi_expr_for_value_v46j(
            value,
            context="c_truth_operand",
        )
        if abi_expr is not None:
            return abi_expr

        return self._expr_rvalue_v37(
            value, None, None, set(seen or set())
        )

    def _c_truth_helper_arguments(self, contract, rendered_inputs):
        """Return the stable PALhelpers ABI argument list."""

        helper = contract.get("runtime_helper")
        opcode = str(contract.get("opcode") or "")
        rendered = list(rendered_inputs or [])
        input_widths = list(contract.get("input_widths_bits", []) or [])
        output_width = self._c_truth_width(contract, output=True)

        if helper in ("c_zext", "c_sext", "c_resize", "c_cast_bits"):
            source_width = self._c_truth_width(contract, input_index=0)
            return rendered[:1] + [source_width, output_width]

        if helper == "c_subpiece":
            params = dict(contract.get("conversion_parameters", {}) or {})
            byte_offset = params.get("byte_offset")
            if byte_offset is None and len(rendered) >= 2:
                byte_offset = rendered[1]
            if byte_offset is None:
                byte_offset = 0
            source_width = params.get("source_width_bits") or self._c_truth_width(contract, input_index=0)
            target_width = params.get("output_width_bits") or output_width
            return rendered[:1] + [byte_offset, source_width, target_width]

        if helper == "c_piece":
            widths = [int(w) if isinstance(w, int) and w > 0 else 32 for w in input_widths]
            return rendered + widths + [output_width]

        if helper == "c_load":
            address = rendered[-1] if rendered else "0"
            return ["MEM", address, output_width]

        if helper == "c_store":
            address = rendered[-2] if len(rendered) >= 2 else "0"
            value = rendered[-1] if rendered else "0"
            value_width = input_widths[-1] if input_widths else output_width
            return ["MEM", address, value, value_width]

        if helper in ("c_ptradd", "c_ptrsub"):
            return rendered + [output_width]

        if opcode in (
            "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL",
            "INT_SLESS", "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY",
            "INT_SBORROW",
        ):
            return rendered + [self._c_truth_width(contract, input_index=0)]

        # Fixed-width arithmetic, bitwise, shifts, negation, and boolean-like
        # integer helpers all receive the result/value width last.
        return rendered + [output_width]

    # =========================================================
    # v44 DUAL-PATH RENDER POLICY
    # =========================================================

    def _readable_type_v44(self, width, signed=False, pointer=False):
        try:
            width = int(width)
        except Exception:
            width = 32
        if width <= 0:
            width = 32
        if pointer:
            return "ptr%d" % width
        return "%s%d" % ("s" if signed else "u", width)

    def _readable_cast_v44(self, expr, width, signed=False, pointer=False):
        if not self.readable_show_type_views:
            return str(expr)
        type_name = self._readable_type_v44(
            width, signed=signed, pointer=pointer
        )
        expr = str(expr)
        # A producer and its terminal boundary often carry the same raw-bit
        # width. Preserve both contracts in metadata without displaying
        # redundant wrappers such as u32(u32(...)).
        if expr.startswith(type_name + "(") and expr.endswith(")"):
            return expr
        return "%s(%s)" % (type_name, expr)

    def _readable_binary_v44(self, rendered, symbol, output_width):
        if len(rendered) < 2:
            return None
        return self._readable_cast_v44(
            "(%s %s %s)" % (rendered[0], symbol, rendered[1]),
            output_width,
        )

    def _c_truth_readable_contract_expr_v44(self, contract, rendered_inputs):
        """
        Project one PALCompute contract into non-executable, C-like
        pseudo-Python.

        This function never re-infers width or signedness.  It consumes the
        same helper name, opcode, widths, and conversion parameters used by the
        executable renderer.  uN()/sN()/ptrN() are visual type annotations,
        not runtime helper calls.
        """
        if not isinstance(contract, dict):
            return None

        helper = str(contract.get("runtime_helper") or "")
        opcode = str(contract.get("opcode") or "")
        rendered = [str(value) for value in list(rendered_inputs or [])]
        input_widths = list(contract.get("input_widths_bits", []) or [])
        output_width = self._c_truth_width(contract, output=True)

        def iw(index, fallback=None):
            try:
                value = int(input_widths[index])
                if value > 0:
                    return value
            except Exception:
                pass
            return output_width if fallback is None else fallback

        arithmetic = {
            "c_add": "+",
            "c_sub": "-",
            "c_mul": "*",
            "c_and": "&",
            "c_or": "|",
            "c_xor": "^",
            "c_shl": "<<",
        }
        if helper in arithmetic:
            return self._readable_binary_v44(
                rendered, arithmetic[helper], output_width
            )

        if helper in ("c_udiv", "c_urem") and len(rendered) >= 2:
            symbol = "//" if helper == "c_udiv" else "%"
            a = self._readable_cast_v44(rendered[0], iw(0))
            b = self._readable_cast_v44(rendered[1], iw(1))
            return self._readable_cast_v44(
                "(%s %s %s)" % (a, symbol, b), output_width
            )

        if helper in ("c_sdiv", "c_srem") and len(rendered) >= 2:
            # The readable path is explicitly non-executable.  `/` and `%`
            # here denote C signed division/remainder under the displayed
            # signed views; PALhelpers remains the executable authority.
            symbol = "/" if helper == "c_sdiv" else "%"
            a = self._readable_cast_v44(rendered[0], iw(0), signed=True)
            b = self._readable_cast_v44(rendered[1], iw(1), signed=True)
            return self._readable_cast_v44(
                "(%s %s %s)" % (a, symbol, b), output_width
            )

        if helper in ("c_lshr", "c_ashr") and len(rendered) >= 2:
            signed = helper == "c_ashr"
            value = self._readable_cast_v44(rendered[0], iw(0), signed=signed)
            return self._readable_cast_v44(
                "(%s >> %s)" % (value, rendered[1]), output_width
            )

        if helper in ("c_neg", "c_not") and rendered:
            symbol = "-" if helper == "c_neg" else "~"
            return self._readable_cast_v44(
                "(%s%s)" % (symbol, rendered[0]), output_width
            )

        if helper in ("c_eq", "c_ne") and len(rendered) >= 2:
            return "(%s %s %s)" % (
                rendered[0], "==" if helper == "c_eq" else "!=", rendered[1]
            )

        if helper in ("c_ult", "c_ule", "c_slt", "c_sle") and len(rendered) >= 2:
            signed = helper in ("c_slt", "c_sle")
            symbol = "<=" if helper in ("c_ule", "c_sle") else "<"
            a = self._readable_cast_v44(rendered[0], iw(0), signed=signed)
            b = self._readable_cast_v44(rendered[1], iw(1), signed=signed)
            return "(%s %s %s)" % (a, symbol, b)

        if helper in ("c_carry", "c_scarry", "c_sborrow") and len(rendered) >= 2:
            label = {
                "c_carry": "carry",
                "c_scarry": "signed_overflow_add",
                "c_sborrow": "signed_overflow_sub",
            }[helper]
            return "%s%d(%s, %s)" % (
                label, iw(0), rendered[0], rendered[1]
            )

        if helper in ("c_bits", "c_resize", "c_cast_bits") and rendered:
            return self._readable_cast_v44(rendered[0], output_width)

        if helper == "c_zext" and rendered:
            return self._readable_cast_v44(
                self._readable_cast_v44(rendered[0], iw(0)),
                output_width,
            )

        if helper == "c_sext" and rendered:
            return self._readable_cast_v44(
                self._readable_cast_v44(rendered[0], iw(0), signed=True),
                output_width,
            )

        if helper == "c_subpiece" and rendered:
            params = dict(contract.get("conversion_parameters", {}) or {})
            offset = params.get("byte_offset")
            if offset is None and len(rendered) >= 2:
                offset = rendered[1]
            if offset is None:
                offset = 0
            try:
                shift = int(offset) * 8
                shifted = rendered[0] if shift == 0 else "(%s >> %d)" % (rendered[0], shift)
            except Exception:
                shifted = "(%s >> ((%s) * 8))" % (rendered[0], offset)
            return self._readable_cast_v44(shifted, output_width)

        if helper == "c_piece" and len(rendered) >= 2:
            high_width = iw(0)
            low_width = iw(1)
            joined = "(%s << %d) | %s" % (
                self._readable_cast_v44(rendered[0], high_width),
                low_width,
                self._readable_cast_v44(rendered[1], low_width),
            )
            return self._readable_cast_v44("(%s)" % joined, output_width)

        if helper in ("c_ptradd", "c_ptrsub") and rendered:
            base = rendered[0]
            if helper == "c_ptradd" and len(rendered) >= 3:
                expr = "(%s + (%s * %s))" % (base, rendered[1], rendered[2])
            elif helper == "c_ptrsub" and len(rendered) >= 2:
                expr = "(%s - %s)" % (base, rendered[1])
            elif len(rendered) >= 2:
                expr = "(%s + %s)" % (base, rendered[1])
            else:
                expr = base
            return self._readable_cast_v44(expr, output_width, pointer=True)

        if helper == "c_load":
            address = rendered[-1] if rendered else "0"
            return "MEM%d[%s]" % (output_width, address)

        if helper == "c_store":
            address = rendered[-2] if len(rendered) >= 2 else "0"
            value = rendered[-1] if rendered else "0"
            value_width = iw(len(input_widths) - 1) if input_widths else output_width
            return "MEM%d[%s] <- %s" % (value_width, address, value)

        if helper == "c_return_bits" and rendered:
            return self._readable_cast_v44(rendered[0], output_width)

        # Preserve visibility instead of silently dropping an unrecognized C
        # semantic.  This remains non-executable and is reported in the dual
        # path diagnostics for the next vocabulary extension.
        if helper:
            self.c_truth_render_warnings.append({
                "kind": "emitter_readable_unknown_helper_v44",
                "op_key": contract.get("op_key"),
                "opcode": opcode,
                "helper": helper,
            })
            return "%s_readable(%s)" % (
                helper[2:] if helper.startswith("c_") else helper,
                ", ".join(rendered),
            )

        return None

    def _c_truth_render_helper_surface_v44(
        self, contract, rendered_inputs, context="expression"
    ):
        helper = contract.get("runtime_helper") if isinstance(contract, dict) else None
        if not helper:
            return None

        self._c_truth_record_helper_call(contract, context, helper)

        if self._is_readable_render_v44():
            projected = self._c_truth_readable_contract_expr_v44(
                contract, rendered_inputs
            )
            self.c_truth_readable_projection_events.append({
                "kind": "emitter_readable_contract_projection_v44",
                "op_key": contract.get("op_key"),
                "output_sid": contract.get("output_sid"),
                "opcode": contract.get("opcode"),
                "runtime_helper": helper,
                "context": context,
                "projection": projected,
            })
            self._imc_trace_operation_fragment(
                contract, helper, projected, context
            )
            return projected

        args = self._c_truth_helper_arguments(contract, rendered_inputs)
        self.c_truth_required_helpers.add(helper)
        projected = "%s(%s)" % (helper, ", ".join(str(arg) for arg in args))
        self._imc_trace_operation_fragment(
            contract, helper, projected, context
        )
        return projected

    def _c_truth_record_helper_call(self, contract, context, helper):
        key = (
            contract.get("op_key"),
            contract.get("output_sid"),
            helper,
            context,
        )
        if key in self.c_truth_helper_call_keys:
            return
        self.c_truth_helper_call_keys.add(key)
        self.c_truth_helper_calls.append({
            "kind": "emitter_c_truth_helper_call_v43",
            "op_key": contract.get("op_key"),
            "output_sid": contract.get("output_sid"),
            "opcode": contract.get("opcode"),
            "helper": helper,
            "context": context,
            "output_width_bits": contract.get("output_width_bits"),
        })

    def _c_truth_render_contract_expr(self, contract, inputs, seen=None, context="expression"):
        if not self._c_truth_contract_has_runtime_semantics(contract):
            return None

        helper = contract.get("runtime_helper")
        if not helper and contract.get("opcode") in ("CALL", "CALLIND", "CALLOTHER"):
            # The ordinary call renderer owns target/name/argument syntax.
            # It applies the contract's result normalization afterwards.
            return None
        rendered = [self._c_truth_operand_expr(value, seen) for value in list(inputs or [])]

        if helper:
            return self._c_truth_render_helper_surface_v44(
                contract, rendered, context=context
            )

        normalization = dict(contract.get("result_normalization", {}) or {})
        if normalization.get("mode") == "mask_to_output_width" and rendered:
            width = normalization.get("width_bits") or contract.get("output_width_bits")
            self._c_truth_record_helper_call(contract, context, "c_bits")
            if self._is_readable_render_v44():
                projected = self._readable_cast_v44(rendered[0], width)
                self.c_truth_readable_projection_events.append({
                    "kind": "emitter_readable_normalization_projection_v44",
                    "op_key": contract.get("op_key"),
                    "output_sid": contract.get("output_sid"),
                    "opcode": contract.get("opcode"),
                    "runtime_helper": "c_bits",
                    "context": context,
                    "projection": projected,
                })
                return projected
            self.c_truth_required_helpers.add("c_bits")
            return "c_bits(%s, %s)" % (rendered[0], width)

        return None

    def _c_truth_normalize_call_expr(self, contract, expr, context):
        if not self.c_truth_active or not isinstance(contract, dict):
            return expr
        normalization = dict(contract.get("result_normalization", {}) or {})
        if normalization.get("mode") != "mask_to_output_width":
            return expr
        width = normalization.get("width_bits") or contract.get("output_width_bits")
        self._c_truth_record_helper_call(contract, context, "c_bits")
        if self._is_readable_render_v44():
            projected = self._readable_cast_v44(expr, width)
            self.c_truth_readable_projection_events.append({
                "kind": "emitter_readable_normalization_projection_v44",
                "op_key": contract.get("op_key"),
                "output_sid": contract.get("output_sid"),
                "opcode": contract.get("opcode"),
                "runtime_helper": "c_bits",
                "context": context,
                "projection": projected,
            })
            return projected
        self.c_truth_required_helpers.add("c_bits")
        return "c_bits(%s, %s)" % (expr, width)

    def _c_truth_expr_for_op(self, op, inputs, context="op"):
        if not self.c_truth_active or self._c_truth_rendering_disabled:
            return None
        contract = self._c_truth_plan_for_op(op)
        return self._c_truth_render_contract_expr(contract, inputs, context=context)

    def _c_truth_expr_for_node(self, node, inputs, seen=None, context="node"):
        if not self.c_truth_active or self._c_truth_rendering_disabled:
            return None
        contract = self._c_truth_plan_for_node(node)
        return self._c_truth_render_contract_expr(contract, inputs, seen=seen, context=context)

    def _c_truth_required_helper_names(self):
        helpers = set()
        contracts = list(self.c_truth_contracts_by_op.values())
        contracts.extend(list(self.c_truth_outputless_contracts_by_op.values()))
        contracts.extend(list(self.c_truth_compute_plans_by_sid.values()))

        for binding in self.c_truth_alias_bindings_by_sid.values():
            if not isinstance(binding, dict):
                continue
            contract = binding.get("source_compute_contract")
            if isinstance(contract, dict):
                contracts.append(contract)

        for records in self.c_truth_control_contracts_by_block.values():
            contracts.extend(list(records or []))

        for contract in contracts:
            if not isinstance(contract, dict):
                continue
            helper = contract.get("runtime_helper")
            if helper:
                helpers.add(helper)
            normalization = dict(contract.get("result_normalization", {}) or {})
            if not helper and normalization.get("mode") == "mask_to_output_width":
                helpers.add("c_bits")

        # Return normalization is applied at the terminal observation rather
        # than represented as an ordinary PALCompute operation. Predict it
        # before _emit_header() so the executable import is complete even if
        # no explicit RETURN control contract exists.
        if self.return_vars and not self.abi_active:
            helpers.add("c_return_bits")

        # Storage-custody rendering is decided before the function header is
        # printed.  Predict its helpers here; expression-time discovery would
        # otherwise happen too late to update the import line.
        memory_families = [
            descriptor
            for descriptor in self.custody_family_descriptors.values()
            if isinstance(descriptor, dict)
            and descriptor.get("memory_backed")
            and descriptor.get("address_resolved")
        ]
        if memory_families:
            helpers.update(("c_load", "c_store"))
        if any(
            descriptor.get("storage_space") == "stack"
            for descriptor in memory_families
        ):
            helpers.add("c_ptrsub")

        # ABI-G transport helpers are selected from explicit ABI-D/F plans,
        # never from target spelling or expression form.
        if self.abi_active:
            if self.abi_context_required:
                helpers.add("c_abi_context")
            if (
                self.abi_entry_materialization_records
                or self.abi_entry_context_records
            ):
                helpers.add("c_abi_get")
            if self.abi_call_site_plans_by_op:
                helpers.add("c_abi_call")
            return_contract = dict(
                self.abi_function_entry_plan.get("return_contract") or {}
            )
            if (
                self.abi_context_required
                and list(return_contract.get("carrier_pieces") or [])
            ):
                helpers.add("c_abi_return")
            elif isinstance(
                return_contract.get("effective_result_width_bits"), int
            ):
                helpers.add("c_return_bits")

        return helpers

    def _c_truth_legacy_operand(self, value, parent_opcode=None, raw_constants=False, seen=None):
        seen = set(seen or set())
        if getattr(value, "is_constant", False):
            if raw_constants:
                return self._const(value)
            return self._const_for_context(value, parent_opcode, None)

        node = self._node_for(value)
        sid = self._sid_of(getattr(node, "var", None)) if node is not None else self._sid_of(value)
        abi_expr = self._abi_expr_for_value_v46j(
            value,
            context="raw_condition_legacy",
        )
        if abi_expr is not None:
            return abi_expr
        custody_expr = self._custody_read_expr_for_sid_v45(
            sid, context="raw_condition_legacy"
        )
        if custody_expr is not None:
            return custody_expr
        if sid is not None and (sid in seen or str(sid) in seen):
            return self._var(value)

        if node is None:
            return self._var(value)

        opcode = getattr(node, "opcode", None)
        if opcode in ("CALL", "CALLIND", "LOAD", "STORE", "MULTIEQUAL", "INDIRECT"):
            return self._var(getattr(node, "var", value))

        return self._c_truth_legacy_expr_for_node(node, raw_constants, seen)

    def _c_truth_legacy_expr_for_node(self, node, raw_constants=False, seen=None):
        seen = set(seen or set())
        if node is None:
            return None
        sid = self._sid_of(getattr(node, "var", None))
        if sid is not None:
            if sid in seen or str(sid) in seen:
                return self._var(getattr(node, "var", None))
            seen.add(sid)
            seen.add(str(sid))

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])
        operand = lambda value: self._c_truth_legacy_operand(
            value, opcode, raw_constants, seen.copy()
        )

        if opcode in _BINARY and len(inputs) == 2:
            a, b = operand(inputs[0]), operand(inputs[1])
            symbol = _BINARY[opcode]
            if symbol in ("<carry>", "<scarry>", "<sborrow>"):
                return "%s(%s, %s)" % (opcode.lower(), a, b)
            return "(%s %s %s)" % (a, symbol, b)
        if opcode in _UNARY and inputs:
            return "(%s%s)" % (_UNARY[opcode], operand(inputs[0]))
        if opcode in _TRANSPARENT and inputs:
            return operand(inputs[0])
        if opcode == "SUBPIECE" and inputs:
            return "subpiece(%s)" % ", ".join(operand(value) for value in inputs)
        if opcode == "PIECE" and inputs:
            return "piece(%s)" % ", ".join(operand(value) for value in inputs)
        return self._var(getattr(node, "var", None))

    def _c_truth_surface_operand(
        self, value, parent_opcode=None, operand_index=None,
        raw_constants=False, seen=None, elide_low_subpiece=False,
    ):
        seen = set(seen or set())
        if getattr(value, "is_constant", False):
            if raw_constants:
                return self._const(value)
            return self._const_for_context(value, parent_opcode, operand_index)

        sid = self._sid_of(value)
        custody_expr = self._custody_read_expr_for_sid_v45(
            sid, context="raw_condition_surface"
        )
        if custody_expr is not None:
            return custody_expr
        dynamic = self._dynamic_alias_target_for_source_sid(sid)
        if dynamic:
            return dynamic

        alias_name = self._alias_target_name_for_sid(sid)
        if alias_name:
            return alias_name

        if self._is_materialized_runtime_value_v41(value):
            return self._var(value)

        node = self._node_for(value)
        if node is None:
            return self._var(value)

        node_sid = self._sid_of(getattr(node, "var", value))
        if node_sid is not None and (
            node_sid in seen or str(node_sid) in seen
        ):
            return self._var(getattr(node, "var", value))

        opcode = getattr(node, "opcode", None)
        if opcode in ("CALL", "CALLIND", "LOAD", "STORE", "MULTIEQUAL", "INDIRECT"):
            return self._var(getattr(node, "var", value))

        expr = self._c_truth_surface_expr_for_node(
            node,
            raw_constants=raw_constants,
            seen=seen,
            elide_low_subpiece=elide_low_subpiece,
        )
        if expr:
            return expr
        return self._var(getattr(node, "var", value))

    def _c_truth_surface_expr_for_node(
        self, node, raw_constants=False, seen=None,
        elide_low_subpiece=False,
    ):
        """
        Render the legacy operator shape using the emitter's *current* value
        aliases.

        SGL textual conditions may refer to a state local after its producing
        helper has already been emitted, while the semantic graph still names
        the producer SSA temp.  Both are the same execution value.  Indexing
        this surface form lets the raw-condition transformer recover the
        authoritative helper contract without guessing from Python syntax.
        """
        if node is None:
            return None

        seen = set(seen or set())
        sid = self._sid_of(getattr(node, "var", None))
        if sid is not None:
            if sid in seen or str(sid) in seen:
                return self._var(getattr(node, "var", None))
            seen.add(sid)
            seen.add(str(sid))

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])
        rendered = []
        for index, value in enumerate(inputs):
            child_elision = bool(elide_low_subpiece)
            child_node = self._node_for(value)
            if (
                child_elision
                and getattr(child_node, "opcode", None) == "SUBPIECE"
            ):
                child_elision = self._c_truth_mask_makes_low_subpiece_redundant(
                    node, index, child_node
                )

            rendered.append(self._c_truth_surface_operand(
                value,
                parent_opcode=opcode,
                operand_index=index,
                raw_constants=raw_constants,
                seen=seen.copy(),
                elide_low_subpiece=child_elision,
            ))

        if opcode in _BINARY and len(rendered) == 2:
            symbol = _BINARY[opcode]
            if symbol in ("<carry>", "<scarry>", "<sborrow>"):
                return "%s(%s, %s)" % (
                    opcode.lower(), rendered[0], rendered[1]
                )
            return "(%s %s %s)" % (rendered[0], symbol, rendered[1])
        if opcode in _UNARY and rendered:
            return "(%s%s)" % (_UNARY[opcode], rendered[0])
        if opcode in _TRANSPARENT and rendered:
            return rendered[0]
        if opcode == "SUBPIECE" and rendered:
            if elide_low_subpiece:
                offset = self._const_int_value(inputs[1]) if len(inputs) >= 2 else 0
                if offset == 0:
                    return rendered[0]
            return "subpiece(%s)" % ", ".join(rendered)
        if opcode == "PIECE" and rendered:
            return "piece(%s)" % ", ".join(rendered)
        return None

    def _c_truth_mask_makes_low_subpiece_redundant(
        self, parent_node, input_index, subpiece_node
    ):
        """True only for `(SUBPIECE(x, 0) & mask)` with an in-width mask."""
        if getattr(parent_node, "opcode", None) != "INT_AND":
            return False

        parent_inputs = list(getattr(parent_node, "inputs", []) or [])
        if len(parent_inputs) != 2 or input_index not in (0, 1):
            return False

        other = parent_inputs[1 - input_index]
        mask = self._const_int_value(other)
        if not isinstance(mask, int) or mask < 0:
            return False

        sub_inputs = list(getattr(subpiece_node, "inputs", []) or [])
        offset = self._const_int_value(sub_inputs[1]) if len(sub_inputs) >= 2 else 0
        if offset != 0:
            return False

        contract = self._c_truth_plan_for_node(subpiece_node)
        width = (
            contract.get("output_width_bits")
            if isinstance(contract, dict)
            else self._width_bits_for_value(getattr(subpiece_node, "var", None), None)
        )
        if not isinstance(width, int) or width <= 0:
            return False

        return mask <= ((1 << width) - 1)

    def _c_truth_ast_signature(self, node):
        return ast.dump(node, annotate_fields=True, include_attributes=False)

    def _c_truth_build_raw_contract_index(self):
        index = {}

        for sid, binding in self.c_truth_bindings_by_sid.items():
            if not isinstance(binding, dict):
                continue
            contract = binding.get("compute_contract")
            if not isinstance(contract, dict) or not contract.get("runtime_helper"):
                continue

            node = self.nodes.get(sid) or self.nodes.get(str(sid))
            if node is None:
                continue

            indexed_forms = []
            for raw_constants in (False, True):
                indexed_forms.append((
                    self._c_truth_legacy_expr_for_node(node, raw_constants),
                    contract,
                ))
                indexed_forms.append((
                    self._c_truth_surface_expr_for_node(node, raw_constants),
                    contract,
                ))

                elided_text = self._c_truth_surface_expr_for_node(
                    node,
                    raw_constants,
                    elide_low_subpiece=True,
                )
                normal_text = self._c_truth_surface_expr_for_node(
                    node,
                    raw_constants,
                    elide_low_subpiece=False,
                )
                if elided_text and elided_text != normal_text:
                    elided_contract = dict(contract)
                    elided_contract["_emitter_semantic_chain_render"] = True
                    elided_contract["_emitter_surface_elision"] = "zero_offset_low_subpiece"
                    indexed_forms.append((elided_text, elided_contract))

            for text, indexed_contract in indexed_forms:
                if not text:
                    continue
                try:
                    parsed = ast.parse(str(text), mode="eval").body
                except Exception:
                    continue
                if not isinstance(parsed, (ast.BinOp, ast.UnaryOp, ast.Compare, ast.Call)):
                    continue
                key = self._c_truth_ast_signature(parsed)
                records = index.setdefault(key, [])
                if not any(
                    existing.get("op_key") == indexed_contract.get("op_key")
                    for existing in records
                ):
                    records.append(indexed_contract)

        self._c_truth_raw_contract_index = index
        return index

    def _c_truth_ast_operands(self, node):
        if isinstance(node, ast.BinOp):
            return [node.left, node.right]
        if isinstance(node, ast.Compare) and len(node.comparators) == 1:
            return [node.left, node.comparators[0]]
        if isinstance(node, ast.UnaryOp):
            return [node.operand]
        if isinstance(node, ast.Call):
            return list(node.args)
        return []

    def _c_truth_semantic_chain_operand(self, value, seen=None):
        seen = set(seen or set())
        if getattr(value, "is_constant", False):
            return self._const(value)

        sid = self._sid_of(value)
        custody_expr = self._custody_read_expr_for_sid_v45(
            sid, context="raw_condition_semantic_chain"
        )
        if custody_expr is not None:
            return custody_expr
        dynamic = self._dynamic_alias_target_for_source_sid(sid)
        if dynamic:
            return dynamic

        alias_name = self._alias_target_name_for_sid(sid)
        if alias_name:
            return alias_name

        if self._is_materialized_runtime_value_v41(value):
            return self._var(value)

        node = self._node_for(value)
        if node is None:
            return self._var(value)

        node_sid = self._sid_of(getattr(node, "var", value))
        if node_sid is not None and (
            node_sid in seen or str(node_sid) in seen
        ):
            return self._var(getattr(node, "var", value))

        opcode = getattr(node, "opcode", None)
        if opcode in (
            "CALL", "CALLIND", "LOAD", "STORE", "MULTIEQUAL", "INDIRECT"
        ):
            return self._var(getattr(node, "var", value))

        contract = self._c_truth_plan_for_node(node)
        if isinstance(contract, dict) and contract.get("runtime_helper"):
            nested_seen = set(seen)
            if node_sid is not None:
                nested_seen.add(node_sid)
                nested_seen.add(str(node_sid))
            return self._c_truth_semantic_chain_expr_for_node(
                node, contract, nested_seen
            )

        inputs = list(getattr(node, "inputs", []) or [])
        if opcode in _TRANSPARENT and inputs:
            return self._c_truth_semantic_chain_operand(inputs[0], seen)

        return self._var(getattr(node, "var", value))

    def _c_truth_semantic_chain_expr_for_node(
        self, node, contract=None, seen=None
    ):
        if node is None:
            return None
        if not isinstance(contract, dict):
            contract = self._c_truth_plan_for_node(node)
        if not isinstance(contract, dict):
            return None

        helper = contract.get("runtime_helper")
        if not helper:
            return None

        rendered_inputs = [
            self._c_truth_semantic_chain_operand(value, seen)
            for value in list(getattr(node, "inputs", []) or [])
        ]
        return self._c_truth_render_helper_surface_v44(
            contract,
            rendered_inputs,
            context="raw_condition_semantic_chain",
        )

    def _c_truth_ast_helper_call(self, contract, node, transformer):
        if contract.get("_emitter_semantic_chain_render"):
            output_sid = contract.get("output_sid")
            semantic_node = (
                self.nodes.get(output_sid)
                or self.nodes.get(str(output_sid))
            )
            semantic_expr = self._c_truth_semantic_chain_expr_for_node(
                semantic_node, contract, set()
            )
            if semantic_expr:
                try:
                    semantic_ast = ast.parse(semantic_expr, mode="eval").body
                    return ast.copy_location(semantic_ast, node)
                except Exception:
                    self.c_truth_render_warnings.append({
                        "kind": "emitter_c_truth_semantic_chain_parse_failed_v43c",
                        "op_key": contract.get("op_key"),
                        "expression": semantic_expr,
                    })

        helper = contract.get("runtime_helper")
        operands = [transformer.visit(value) for value in self._c_truth_ast_operands(node)]

        if self._is_readable_render_v44():
            try:
                rendered_operands = [ast.unparse(value) for value in operands]
                projected = self._c_truth_render_helper_surface_v44(
                    contract,
                    rendered_operands,
                    context="raw_condition",
                )
                if projected:
                    projected_ast = ast.parse(projected, mode="eval").body
                    return ast.copy_location(projected_ast, node)
            except Exception as exc:
                self.c_truth_render_warnings.append({
                    "kind": "emitter_readable_raw_condition_projection_failed_v44",
                    "op_key": contract.get("op_key"),
                    "helper": helper,
                    "error": str(exc),
                })

        args = self._c_truth_helper_arguments(contract, operands)
        ast_args = []
        for arg in args:
            if isinstance(arg, ast.AST):
                ast_args.append(arg)
            elif arg == "MEM":
                ast_args.append(ast.Name(id="MEM", ctx=ast.Load()))
            elif isinstance(arg, int):
                ast_args.append(ast.Constant(value=arg))
            else:
                try:
                    ast_args.append(ast.parse(str(arg), mode="eval").body)
                except Exception:
                    ast_args.append(ast.Constant(value=arg))

        self.c_truth_required_helpers.add(helper)
        self._c_truth_record_helper_call(contract, "raw_condition", helper)
        helper_ast = ast.Call(
            func=ast.Name(id=helper, ctx=ast.Load()),
            args=ast_args,
            keywords=[],
        )
        try:
            self._imc_trace_operation_fragment(
                contract, helper, ast.unparse(helper_ast), "raw_condition"
            )
        except Exception:
            pass
        return ast.copy_location(helper_ast, node)

    def _apply_c_truth_raw_condition_rewrites(self, expr):
        if (
            not (self.c_truth_active or self.custody_active)
            or self._c_truth_rendering_disabled
            or not isinstance(expr, str)
            or not expr.strip()
        ):
            return expr

        probe_context = dict(self._c_truth_condition_context or {})
        probe_before_calls = len(self.c_truth_helper_calls)

        # Rebuild against the current execution-surface aliases.  State aliases
        # become available as preceding assignments are emitted, so an index
        # frozen at the function's first predicate can be stale for a later
        # loop/body predicate.
        self._c_truth_build_raw_contract_index()
        index = self._c_truth_raw_contract_index or {}
        if not index:
            return self._apply_custody_raw_condition_reads_v45(expr)

        try:
            tree = ast.parse(expr, mode="eval")
        except Exception:
            self.c_truth_raw_probe_events.append({
                "kind": "emitter_c_truth_raw_condition_probe_v43c",
                "context": probe_context,
                "input": expr,
                "output": expr,
                "parse_error": True,
                "matched_op_keys": [],
            })
            return self._apply_custody_raw_condition_reads_v45(expr)

        ast_terms = []
        for candidate in ast.walk(tree):
            if not isinstance(candidate, (ast.BinOp, ast.UnaryOp, ast.Compare)):
                continue
            try:
                candidate_text = ast.unparse(candidate)
            except Exception:
                candidate_text = type(candidate).__name__
            ast_terms.append(candidate_text)

        emitter = self

        class ContractTransformer(ast.NodeTransformer):
            def generic_visit(self, node):
                key = emitter._c_truth_ast_signature(node)
                contracts = index.get(key, [])
                if contracts:
                    identities = {
                        (
                            record.get("runtime_helper"),
                            tuple(record.get("input_widths_bits", []) or []),
                            record.get("output_width_bits"),
                        )
                        for record in contracts
                    }
                    if len(identities) == 1:
                        return emitter._c_truth_ast_helper_call(contracts[0], node, self)

                    emitter.c_truth_render_warnings.append({
                        "kind": "emitter_c_truth_ambiguous_raw_expression_v43",
                        "expression": ast.unparse(node) if hasattr(ast, "unparse") else str(node),
                        "contracts": [record.get("op_key") for record in contracts],
                    })
                return super().generic_visit(node)

        rewritten = ContractTransformer().visit(tree)
        ast.fix_missing_locations(rewritten)

        try:
            text = ast.unparse(rewritten.body)
        except Exception:
            return self._apply_custody_raw_condition_reads_v45(expr)

        text = self._apply_custody_raw_condition_reads_v45(text)

        new_calls = self.c_truth_helper_calls[probe_before_calls:]
        self.c_truth_raw_probe_events.append({
            "kind": "emitter_c_truth_raw_condition_probe_v43c",
            "context": probe_context,
            "input": expr,
            "output": text,
            "parse_error": False,
            "ast_terms": ast_terms,
            "matched_op_keys": [
                record.get("op_key") for record in new_calls
                if str(record.get("context") or "").startswith("raw_condition")
            ],
        })

        if text != expr:
            self.c_truth_raw_rewrite_events.append({
                "kind": "emitter_c_truth_raw_condition_rewrite_v43",
                "before": expr,
                "after": text,
            })
        return text

    def _c_truth_unrendered_contract_details(self, op_keys):
        details = []
        contracts = dict(self.c_truth_contracts_by_op)
        contracts.update(self.c_truth_outputless_contracts_by_op)

        for op_key in list(op_keys or []):
            contract = contracts.get(op_key)
            if not isinstance(contract, dict):
                contract = next(
                    (
                        record for record in contracts.values()
                        if isinstance(record, dict)
                        and str(record.get("op_key")) == str(op_key)
                    ),
                    None,
                )
            if not isinstance(contract, dict):
                details.append({
                    "op_key": op_key,
                    "contract_found": False,
                })
                continue

            output_sid = contract.get("output_sid")
            node = (
                self.nodes.get(output_sid)
                or self.nodes.get(str(output_sid))
            )
            inputs = list(getattr(node, "inputs", []) or []) if node is not None else []
            input_details = []
            for value in inputs:
                sid = self._sid_of(value)
                input_details.append({
                    "sid": sid,
                    "execution_name": self._var(value),
                    "dynamic_alias": self._dynamic_alias_target_for_source_sid(sid),
                    "state_alias": self._alias_target_name_for_sid(sid),
                    "materialized": self._is_materialized_runtime_value_v41(value),
                    "constant": bool(getattr(value, "is_constant", False)),
                    "constant_text": self._const(value) if getattr(value, "is_constant", False) else None,
                })

            details.append({
                "op_key": contract.get("op_key", op_key),
                "contract_found": True,
                "block_addr": contract.get("block_addr"),
                "op_id": contract.get("op_id"),
                "opcode": contract.get("opcode"),
                "runtime_helper": contract.get("runtime_helper"),
                "output_sid": output_sid,
                "node_found": node is not None,
                "node_opcode": getattr(node, "opcode", None) if node is not None else None,
                "contract_input_sids": list(contract.get("input_sids", []) or []),
                "node_input_sids": [self._sid_of(value) for value in inputs],
                "input_details": input_details,
                "legacy_expr": self._c_truth_legacy_expr_for_node(node, True) if node is not None else None,
                "surface_expr": self._c_truth_surface_expr_for_node(node, True) if node is not None else None,
            })

        return details


    def _tree_has_blocks(self, node):

        if node is None:
            return False

        if getattr(node, "kind", None) == "block":
            return True

        for child in getattr(node, "children", []):
            if self._tree_has_blocks(child):
                return True

        return False

    def _count_tree_blocks(self, node):

        if node is None:
            return 0

        count = 1 if getattr(node, "kind", None) == "block" else 0

        for child in getattr(node, "children", []):
            count += self._count_tree_blocks(child)

        return count

    # =========================================================
    # IM-A/IM-B DOCUMENT, LINE PROVENANCE, AND FROZEN LOOKUP
    # =========================================================

    def _provenance_cfg_addr_for_node(self, node):
        if node is None:
            return None
        cfg_node = getattr(node, "cfg_node", None)
        if cfg_node is None:
            cfg_node = getattr(node, "header", None)
        return self._cfg_addr(cfg_node)

    def _provenance_occurrence_for_node(self, node, path):
        kind = getattr(node, "kind", None) or "node"
        cfg_addr = self._provenance_cfg_addr_for_node(node)
        occurrence_id = PALCodeDocument.occurrence_id(
            getattr(self.func, "func_name", "func"),
            tuple(path or ("root",)),
            kind,
            cfg_addr,
        )
        metadata_refs = []
        if cfg_addr is not None:
            addr_text = hex(cfg_addr) if isinstance(cfg_addr, int) else str(cfg_addr)
            metadata_refs.append("cfg:block:%s" % addr_text)
        self.code_document.register_occurrence(
            occurrence_id=occurrence_id,
            exec_path=tuple(path or ("root",)),
            node_kind=kind,
            cfg_block_addr=cfg_addr,
            projection=self.render_mode,
            metadata_refs=metadata_refs,
        )
        return occurrence_id, cfg_addr

    def _provenance_current_context(self):
        if not self._provenance_context_stack:
            return {}
        return dict(self._provenance_context_stack[-1])

    @contextmanager
    def _provenance_scope(self, **updates):
        context = self._provenance_current_context()
        for key, value in updates.items():
            if value is not None:
                if key == "metadata_refs":
                    merged = list(context.get(key, []) or []) + list(value or [])
                    context[key] = list(dict.fromkeys(str(item) for item in merged))
                else:
                    context[key] = value
        self._provenance_context_stack.append(context)
        try:
            yield context
        finally:
            self._provenance_context_stack.pop()

    def _provenance_sid_list(self, values):
        out = []
        seen = set()
        for value in list(values or []):
            sid = self._sid_of(value)
            if sid is None:
                continue
            key = str(sid)
            if key in seen:
                continue
            seen.add(key)
            out.append(sid)
        return out

    def _provenance_op_context(self, op, role="normal_op"):
        out = getattr(op, "output", None) if op is not None else None
        inputs = list(getattr(op, "inputs", []) or []) if op is not None else []
        contract = self._c_truth_plan_for_op(op) if op is not None else None
        op_key = contract.get("op_key") if isinstance(contract, dict) else None
        if op_key is None and op is not None:
            op_key = self._op_key(op)
        metadata_refs = []
        if op_key is not None:
            metadata_refs.append("operation:%s" % str(op_key))
        definitions = self._provenance_sid_list([out])
        uses = self._provenance_sid_list(inputs)
        metadata_refs.extend("variable:%s" % str(sid) for sid in definitions)
        metadata_refs.extend("variable:%s" % str(sid) for sid in uses)
        return {
            "role": role,
            "op_keys": [op_key] if op_key is not None else [],
            "definition_sids": definitions,
            "use_sids": uses,
            "metadata_refs": metadata_refs,
        }

    def _provenance_statement_id(self, context):
        occurrence_id = context.get("exec_occurrence_id")
        role = context.get("role") or "presentation"
        op_keys = list(context.get("op_keys", []) or [])
        ordinal_key = (
            occurrence_id or "presentation:%s" % self.render_mode,
            role,
            tuple(str(value) for value in op_keys),
        )
        ordinal = self._provenance_statement_ordinals.get(ordinal_key, 0)
        self._provenance_statement_ordinals[ordinal_key] = ordinal + 1
        return PALCodeDocument.statement_id(
            projection=self.render_mode,
            occurrence_id=occurrence_id,
            role=role,
            op_keys=op_keys,
            ordinal=ordinal,
        )

    def _record_provenance_line(self, text, provenance=None):
        context = self._provenance_current_context()
        for key, value in dict(provenance or {}).items():
            if key == "metadata_refs":
                merged = list(context.get(key, []) or []) + list(value or [])
                context[key] = list(dict.fromkeys(str(item) for item in merged))
            else:
                context[key] = value
        role = context.get("role") or "presentation"
        statement_id = context.get("statement_id") or self._provenance_statement_id(
            context
        )
        self.code_document.record_line(
            mode=self.render_mode,
            text=text,
            statement_id=statement_id,
            role=role,
            exec_occurrence_id=context.get("exec_occurrence_id"),
            block_occurrence_id=context.get("block_occurrence_id"),
            cfg_block_addr=context.get("cfg_block_addr"),
            op_keys=context.get("op_keys"),
            definition_sids=context.get("definition_sids"),
            use_sids=context.get("use_sids"),
            metadata_refs=context.get("metadata_refs"),
            operation_fragments=list(self._imc_pending_operation_fragments),
        )
        self._imc_pending_operation_fragments = []

    def _imc_trace_operation_fragment(self, contract, helper, surface, context):
        if not isinstance(contract, dict) or contract.get("op_key") is None:
            return
        if not surface:
            return
        self._imc_pending_operation_fragments.append({
            "kind": "rendered_operation_fragment_im_c",
            "op_key": str(contract.get("op_key")),
            "output_sid": (
                str(contract.get("output_sid"))
                if contract.get("output_sid") is not None else None
            ),
            "opcode": contract.get("opcode"),
            "helper": helper,
            "surface_expr": str(surface),
            "context": context,
            "projection": self.render_mode,
        })

    # =========================================================
    # IM-C DETACHED METADATA REGISTRY AND INLINE SPANS
    # =========================================================

    def _imc_sid_record_source(self, sid):
        variants = (sid, str(sid))
        for key in variants:
            if key in self.nodes:
                node = self.nodes.get(key)
                var = getattr(node, "var", None)
                if var is not None:
                    return var
                output = getattr(node, "output", None)
                if output is not None:
                    return output
        for var in dict(getattr(self.func, "vars", {}) or {}).values():
            if str(getattr(var, "ssa_id", "")) == str(sid):
                return var
        return None

    def _imc_display_name_for_sid(self, sid, source=None):
        for key in (sid, str(sid)):
            if key in self.var_map and self.var_map.get(key) is not None:
                return self._sanitize_name(str(self.var_map.get(key)))
        name = getattr(source, "name", None)
        if name:
            return self._sanitize_name(str(name))
        return self._sanitize_name(str(sid))

    def _imc_constant_literals(self, sid, source=None):
        value = None
        if source is not None and getattr(source, "is_constant", False):
            value = getattr(
                source, "const_value", getattr(source, "value", None)
            )
        match = re.match(r"^c_(-?\d+)_\d+$", str(sid))
        if value is None and match:
            try:
                value = int(match.group(1))
            except Exception:
                value = None
        if not isinstance(value, int):
            return []
        values = [str(value)]
        try:
            values.append(hex(value))
        except Exception:
            pass
        return list(dict.fromkeys(values))

    def _imc_variable_sids(self):
        values = set()
        for table in (
            getattr(self.func, "vars", {}) or {},
            getattr(self.func, "numeric_contracts_by_sid", {}) or {},
            getattr(self.func, "compute_plans_by_sid", {}) or {},
            self.var_map,
            self.nodes,
            self.c_truth_bindings_by_sid,
            self.c_truth_alias_bindings_by_sid,
        ):
            values.update(str(key) for key in dict(table).keys())
        for contract in list(self.c_truth_contracts_by_op.values()) + list(
            self.c_truth_outputless_contracts_by_op.values()
        ):
            if not isinstance(contract, dict):
                continue
            if contract.get("output_sid") is not None:
                values.add(str(contract.get("output_sid")))
            values.update(
                str(sid) for sid in list(contract.get("input_sids", []) or [])
                if sid is not None
            )
        return sorted(values)

    @staticmethod
    def _imc_table_value(table, key, default=None):
        table = dict(table or {})
        for variant in (key, str(key)):
            if variant in table:
                return table.get(variant)
        return default

    def _imc_detached_dropin(self, rec):
        if not isinstance(rec, dict):
            return self.code_document.freeze_metadata_value(rec)
        live_keys = {
            "target", "source", "source_node", "target_node", "pred_node",
            "join_node", "phi", "join_phi", "cfg_node",
        }
        data = {
            key: value for key, value in rec.items()
            if key not in live_keys
        }
        data["kind"] = data.get("kind") or "phi_dropin_contract"
        data["dropin_key"] = str(self._phi_dropin_key(rec))
        return self.code_document.freeze_metadata_value(data)

    def _imc_cfg_record(self, cfg_node):
        addr = getattr(cfg_node, "addr", None)
        def addr_value(node):
            return getattr(node, "addr", None) if node is not None else None
        edges = []
        for edge in list(getattr(cfg_node, "out_edges", []) or []):
            edges.append({
                "src": addr_value(getattr(edge, "src", None)),
                "dst": addr_value(getattr(edge, "dst", None)),
                "type": getattr(edge, "type", None),
                "raw_type": getattr(edge, "raw_type", None),
                "role": getattr(edge, "role", None),
                "is_backedge": bool(getattr(edge, "is_backedge", False)),
                "is_loop_exit": bool(getattr(edge, "is_loop_exit", False)),
                "is_latch_edge": bool(getattr(edge, "is_latch_edge", False)),
                "condition_polarity": getattr(edge, "condition_polarity", None),
                "condition_invert_for_edge": getattr(
                    edge, "condition_invert_for_edge", None
                ),
                "condition_polarity_reason": getattr(
                    edge, "condition_polarity_reason", None
                ),
                "meta": getattr(edge, "meta", {}) or {},
            })
        block = getattr(cfg_node, "block", None)
        return self.code_document.freeze_metadata_value({
            "kind": "cfg_block_metadata_im_c",
            "address": addr,
            "ipdom": addr_value(getattr(cfg_node, "ipdom", None)),
            "predecessors": [
                addr_value(getattr(edge, "src", None))
                for edge in list(getattr(cfg_node, "in_edges", []) or [])
            ],
            "successors": [edge.get("dst") for edge in edges],
            "edges": edges,
            "block_opcodes": [
                getattr(op, "opcode", None)
                for op in list(getattr(block, "ops", []) or [])
            ],
            "terminator_opcode": getattr(
                getattr(block, "terminator", None), "opcode", None
            ),
            "cfg_version": getattr(self.func, "cfg_version", None),
        })

    def _populate_code_document_metadata_im_c(self):
        registry = self.code_document.metadata
        numeric = dict(getattr(self.func, "numeric_contracts_by_sid", {}) or {})
        numeric_flows = dict(
            getattr(self.func, "numeric_type_flows_by_output_sid", {}) or {}
        )
        compute = dict(getattr(self.func, "compute_plans_by_sid", {}) or {})
        phi_bindings = dict(self.c_truth_bindings_by_sid or {})
        phi_aliases = dict(self.c_truth_alias_bindings_by_sid or {})
        parameter_bindings = dict(
            getattr(self.func, "parameter_bindings_by_sid", {}) or {}
        )
        parameter_aliases = dict(
            getattr(self.func, "parameter_aliases_by_sid", {}) or {}
        )
        human_aliases = dict(
            getattr(self.func, "human_alias_contracts_by_sid", {}) or {}
        )

        for sid in self._imc_variable_sids():
            source = self._imc_sid_record_source(sid)
            display_name = self._imc_display_name_for_sid(sid, source)
            original_name = getattr(source, "name", None)
            literal_candidates = self._imc_constant_literals(sid, source)
            record = {
                "kind": "variable_metadata_im_c",
                "sid": sid,
                "display_name": display_name,
                "display_names": list(dict.fromkeys([
                    value for value in (display_name, original_name, sid)
                    if value is not None
                ])),
                "original_name": original_name,
                "literal_candidates": literal_candidates,
                "is_constant": bool(
                    literal_candidates
                    or getattr(source, "is_constant", False)
                ),
                "resolver_contract": self._imc_table_value(numeric, sid),
                "resolver_type_flow": self._imc_table_value(numeric_flows, sid),
                "compute_plan": self._imc_table_value(compute, sid),
                "phi_compute_binding": self._imc_table_value(phi_bindings, sid),
                "phi_alias_binding": self._imc_table_value(phi_aliases, sid),
                "presentation_class": self._imc_table_value(
                    self.presentation_class_by_sid, sid
                ),
                "ssa_policy": self._imc_table_value(self.ssa_policy_by_sid, sid),
                "parameter_binding": self._imc_table_value(
                    parameter_bindings, sid
                ),
                "parameter_alias": self._imc_table_value(
                    parameter_aliases, sid
                ),
                "state_transition_alias": self._imc_table_value(
                    self.state_transition_aliases, sid
                ),
                "human_alias_contract": self._imc_table_value(
                    human_aliases, sid
                ),
                "storage_custody_binding": self._custody_binding_for_sid_v45(
                    sid
                ),
                "storage_family_descriptor": self._custody_descriptor_for_sid_v45(
                    sid
                ),
                "indirect_custody_contract": self._custody_contract_for_sid_v45(
                    sid
                ),
                "condition_storage_observation": bool(
                    sid in self.custody_condition_observation_sids
                    or str(sid) in {
                        str(value)
                        for value in self.custody_condition_observation_sids
                    }
                ),
                "parameter_storage_initializer": (
                    self.custody_parameter_initializers_by_output_sid.get(
                        str(sid)
                    )
                ),
                "abi_entry_root": self._abi_lookup_sid_v46(
                    self.abi_entry_roots_by_sid, sid
                ),
                "abi_entry_lineage": self._abi_lookup_sid_v46(
                    self.abi_entry_lineage_by_sid, sid
                ),
                "abi_execution_owner": self._abi_lookup_sid_v46(
                    self.abi_entry_execution_owners_by_sid, sid
                ),
                "abi_convergence_contract": self._abi_lookup_sid_v46(
                    self.abi_entry_convergence_by_target_sid, sid
                ) or next((
                    contract
                    for contract in self.abi_entry_convergence_contracts
                    if isinstance(contract, dict)
                    and str(contract.get("target_sid")) == str(sid)
                ), None),
                "abi_execution_name": self._abi_name_for_sid_v46(sid),
                "materialized": sid in {str(x) for x in self.materialize_sids},
                "inline_only": sid in {str(x) for x in self.inline_only_sids},
                "suppressed_assignment": sid in {
                    str(x) for x in self.suppress_assign_sids
                },
            }
            registry.register(
                "variable:%s" % sid,
                self.code_document.freeze_metadata_value(record),
            )
            alias_contract = self._imc_table_value(human_aliases, sid)
            if alias_contract:
                registry.register(
                    "alias:variable:%s" % sid,
                    self.code_document.freeze_metadata_value(alias_contract),
                )

        operations = {}
        operations.update(self.c_truth_contracts_by_op)
        operations.update(self.c_truth_outputless_contracts_by_op)
        for op_key, contract in operations.items():
            record = dict(contract or {}) if isinstance(contract, dict) else {
                "contract": contract
            }
            record["kind"] = record.get("kind") or "operation_metadata_im_c"
            record["metadata_reference"] = "operation:%s" % str(op_key)
            registry.register(
                "operation:%s" % str(op_key),
                self.code_document.freeze_metadata_value(record),
            )

        for op_key, contract in self.custody_indirect_contracts_by_op.items():
            frozen = self.code_document.freeze_metadata_value(contract)
            registry.register("custody:indirect:%s" % str(op_key), frozen)
            registry.register("operation:%s" % str(op_key), frozen)

        for op_key, effects in self.custody_effect_owners_by_op.items():
            registry.register(
                "custody:effect_owner:%s" % str(op_key),
                self.code_document.freeze_metadata_value(effects),
            )

        for family_key, descriptor in self.custody_family_descriptors.items():
            registry.register(
                "custody:storage_family:%s" % str(family_key),
                self.code_document.freeze_metadata_value(descriptor),
            )

        for ordinal, binding in enumerate(self.custody_condition_bindings):
            reference = (
                binding.get("provenance_ref")
                if isinstance(binding, dict) else None
            ) or "condition:%d" % ordinal
            registry.register(
                "custody:condition:%s" % str(reference),
                self.code_document.freeze_metadata_value(binding),
            )

        for initializer in self.custody_parameter_initializers:
            if not isinstance(initializer, dict):
                continue
            output_sid = initializer.get("output_sid")
            if output_sid is None:
                continue
            registry.register(
                "custody:parameter_initializer:%s" % str(output_sid),
                self.code_document.freeze_metadata_value(initializer),
            )

        for rec in list(self.phi_dropins or []):
            key = self._phi_dropin_key(rec)
            frozen = self._imc_detached_dropin(rec)
            registry.register("phi_dropin:%s" % str(key), frozen)
            # PHI/drop-in statements use the transition key as their op_key.
            registry.register("operation:%s" % str(key), frozen)

        cfg = getattr(self.func, "cfg", None)
        for addr, cfg_node in dict(getattr(cfg, "nodes", {}) or {}).items():
            addr_text = hex(addr) if isinstance(addr, int) else str(addr)
            registry.register(
                "cfg:block:%s" % addr_text,
                self._imc_cfg_record(cfg_node),
            )

        registry.register("cfg:branch_resolution_events", self.code_document.freeze_metadata_value(
            getattr(cfg, "branch_resolution_events", []) or []
        ))
        registry.register("cfg:repaired_edges", self.code_document.freeze_metadata_value(
            getattr(cfg, "repaired_edges", []) or []
        ))
        registry.register("cfg:loop_headers", self.code_document.freeze_metadata_value([
            getattr(node, "addr", node)
            for node in list(getattr(cfg, "loop_headers", set()) or set())
        ]))

        for block_addr, contracts in dict(
            self.c_truth_control_contracts_by_block or {}
        ).items():
            contract_list = (
                [contracts] if isinstance(contracts, dict)
                else list(contracts or [])
            )
            for ordinal, contract in enumerate(contract_list):
                registry.register(
                    "compute:control:%s:%d" % (str(block_addr), ordinal),
                    self.code_document.freeze_metadata_value(contract),
                )

        for ordinal, contract in enumerate(list(
            getattr(self.func, "phi_compute_transition_contracts", []) or []
        )):
            registry.register(
                "phi:compute_transition:%d" % ordinal,
                self.code_document.freeze_metadata_value(contract),
            )

        for occurrence_id, occurrence in self.code_document.exec_occurrences.items():
            frozen_occurrence = occurrence.as_dict()
            registry.register("exec:%s" % occurrence_id, frozen_occurrence)
            registry.register(occurrence_id, frozen_occurrence)

        for projection in self.code_document.projections.values():
            for statement in projection.statements:
                registry.register(statement.statement_id, statement.as_dict())

        registry.register("function:signature", self.code_document.freeze_metadata_value(
            getattr(self.func, "function_signature", {}) or {}
        ))
        registry.register("function:target_numeric_model", self.code_document.freeze_metadata_value(
            getattr(self.func, "target_numeric_model", {}) or {}
        ))
        resolver_debug = dict(
            getattr(self.func, "symbol_resolver_debug", {}) or {}
        )
        registry.register("resolver:summary", self.code_document.freeze_metadata_value({
            key: value for key, value in resolver_debug.items()
            if key not in {
                "numeric_contracts_by_sid", "numeric_type_flows",
                "numeric_same_width_recasts", "human_alias_contracts",
            }
        }))
        compute_debug = dict(getattr(self.func, "compute_debug", {}) or {})
        registry.register("compute:summary", self.code_document.freeze_metadata_value({
            "summary": compute_debug.get("summary") or (
                list(getattr(self.func, "compute_events", []) or [])[-1]
                if list(getattr(self.func, "compute_events", []) or []) else {}
            ),
            "warnings": compute_debug.get("warnings", []),
        }))
        phi_debug = dict(getattr(self.func, "phi_compute_debug", {}) or {})
        registry.register("phi:compute_consumer_summary", self.code_document.freeze_metadata_value({
            "summary": phi_debug.get("summary", {}),
            "warnings": phi_debug.get("warnings", []),
        }))
        registry.register(
            "custody:emitter_consumer",
            self.code_document.freeze_metadata_value({
                "kind": "emitter_storage_custody_metadata_im_c",
                "version": self.VERSION,
                "active": bool(self.custody_active),
                "storage_families": len(self.custody_family_descriptors),
                "indirect_contracts": len(
                    self.custody_indirect_contracts_by_output_sid
                ),
                "effect_owner_groups": len(self.custody_effect_owners_by_op),
                "condition_bindings": len(self.custody_condition_bindings),
                "parameter_storage_initializers": len(
                    self.custody_parameter_initializers
                ),
                "condition_storage_observation_sids": sorted(
                    self.custody_condition_observation_sids, key=str
                ),
            }),
        )

        # ABI-G metadata is frozen beside the dual projections.  The emitted
        # text contains only compact references; F3/cursor tooling can recover
        # the complete ABI-D plan and ABI-F ownership proof without keeping a
        # live PyGhidra object graph.
        registry.register(
            "abi:entry_plan",
            self.code_document.freeze_metadata_value(
                self.abi_function_entry_plan
            ),
        )
        registry.register(
            "abi:return_reconciliation",
            self.code_document.freeze_metadata_value(
                self.abi_return_boundary_reconciliation
            ),
        )
        registry.register(
            "abi:emitter_consumer",
            self.code_document.freeze_metadata_value({
                "kind": "emitter_abi_custody_metadata_im_c_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "active": bool(self.abi_active),
                "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
                "fixed_arguments": list(self.abi_fixed_argument_names),
                "runtime_context_name": self.abi_context_name,
                "runtime_context_required": bool(self.abi_context_required),
                "entry_materializations": len(
                    self.abi_entry_materialization_records
                ) + len(self.abi_entry_context_records),
                "call_site_plans": len(self.abi_call_plans_by_plan_id),
                "convergence_contracts": len(
                    self.abi_entry_convergence_contracts
                ),
                "must_print_dropin_overrides": len(
                    self.abi_entry_must_print_dropin_ids
                ),
                "path_sensitive_unbound_names": len(
                    self.abi_entry_path_unbound_records
                ),
                "rule": (
                    "frozen_ABI_D_plans_plus_ABI_F_execution_ownership_"
                    "without_downstream_reinference"
                ),
            }),
        )
        registry.register(
            "abi:context",
            self.code_document.freeze_metadata_value({
                "kind": "emitter_abi_runtime_context_binding_v46",
                "version": self.ABI_CUSTODY_VERSION,
                "name": self.abi_context_name,
                "required": bool(self.abi_context_required),
                "callable_argument": False,
                "transport": "current_invocation_context",
                "entry_plan_id": self.abi_function_entry_plan.get("plan_id"),
                "authority": "ABI_C_namespace_policy_plus_ABI_D_entry_plan",
            }),
        )

        for record in (
            list(self.abi_entry_materialization_records)
            + list(self.abi_entry_context_records)
        ):
            sid = record.get("sid") if isinstance(record, dict) else None
            if sid is None:
                continue
            registry.register(
                "abi:entry:%s" % str(sid),
                self.code_document.freeze_metadata_value(record),
            )

        for sid, root in self.abi_entry_roots_by_sid.items():
            registry.register(
                "abi:root:%s" % str(sid),
                self.code_document.freeze_metadata_value(root),
            )

        for plan_id, plan in self.abi_call_plans_by_plan_id.items():
            frozen_plan = self.code_document.freeze_metadata_value(plan)
            registry.register("abi:call:%s" % str(plan_id), frozen_plan)
            op_key = plan.get("op_key") if isinstance(plan, dict) else None
            if op_key is not None:
                registry.register(
                    "abi:call_op:%s" % str(op_key), frozen_plan
                )

        for ordinal, contract in enumerate(
            self.abi_entry_convergence_contracts
        ):
            if not isinstance(contract, dict):
                continue
            frozen_contract = self.code_document.freeze_metadata_value(contract)
            registry.register(
                "abi:convergence:%d" % ordinal, frozen_contract
            )
            target_sid = contract.get("target_sid")
            if target_sid is not None:
                registry.register(
                    "abi:convergence_target:%s" % str(target_sid),
                    frozen_contract,
                )
        return len(registry)

    # ---------------------------------------------------------
    # PUBLIC ENTRY
    # ---------------------------------------------------------

    def _custody_projection_debug_v45(self, rendered_lines):
        text = "\n".join(str(line) for line in list(rendered_lines or []))
        raw_indirect_leaks = [
            {"line_number": index, "text": line}
            for index, line in enumerate(list(rendered_lines or []))
            if re.search(r"\bindirect\s*\(", str(line))
        ]
        if raw_indirect_leaks:
            self.custody_warnings.append({
                "kind": "emitter_raw_indirect_expression_leak_v45",
                "projection": self.render_mode,
                "occurrences": len(raw_indirect_leaks),
                "lines": raw_indirect_leaks,
            })

        required_owner_keys = {
            contract.get("effect_owner_compute_op_key")
            for contract in self.custody_indirect_contracts_by_output_sid.values()
            if isinstance(contract, dict)
            and contract.get("effect_owner_compute_op_key") is not None
        }
        rendered_owner_keys = {
            event.get("owner_compute_op_key")
            for event in self.custody_owner_render_events
            if isinstance(event, dict)
            and event.get("owner_compute_op_key") is not None
        }
        unresolved_owner_keys = sorted(
            required_owner_keys - rendered_owner_keys, key=str
        )
        if unresolved_owner_keys:
            self.custody_warnings.append({
                "kind": "emitter_effect_owner_not_observed_in_projection_v45",
                "projection": self.render_mode,
                "owner_compute_op_keys": unresolved_owner_keys,
                "note": "may_be_structurally_unreachable_or_missing_from_ExecTree",
            })

        required_initializer_sids = {
            str(record.get("output_sid"))
            for record in self.custody_parameter_initializers
            if isinstance(record, dict) and record.get("output_sid") is not None
        }
        rendered_initializer_sids = {
            str(event.get("output_sid"))
            for event in self.custody_parameter_initializer_events
            if isinstance(event, dict) and event.get("output_sid") is not None
        }
        unrendered_initializer_sids = sorted(
            required_initializer_sids - rendered_initializer_sids, key=str
        )
        if unrendered_initializer_sids:
            self.custody_warnings.append({
                "kind": "emitter_parameter_storage_initializer_missing_v45b",
                "projection": self.render_mode,
                "output_sids": unrendered_initializer_sids,
                "action": "entry_storage_would_be_uninitialized",
            })

        descriptors = list(self.custody_family_descriptors.values())
        memory_backed = [
            rec for rec in descriptors if rec.get("memory_backed")
        ]
        resolved_memory = [
            rec for rec in memory_backed if rec.get("address_resolved")
        ]
        all_warnings = list(self.custody_warnings)
        summary = {
            "kind": "emitter_indirect_storage_custody_inventory_v45",
            "version": self.VERSION,
            "projection": self.render_mode,
            "active": bool(self.custody_active),
            "storage_families": len(descriptors),
            "memory_backed_families": len(memory_backed),
            "address_resolved_families": len(resolved_memory),
            "unresolved_address_families": len(
                self.custody_unresolved_address_families
            ),
            "indirect_contracts": len(
                self.custody_indirect_contracts_by_output_sid
            ),
            "indirect_metadata_transitions_consumed": len(
                self.custody_indirect_suppressions
            ),
            "effect_owners_required": len(required_owner_keys),
            "effect_owners_rendered": len(rendered_owner_keys),
            "effect_owners_unobserved": len(unresolved_owner_keys),
            "storage_reads": len(self.custody_read_events),
            "storage_write_throughs": len(self.custody_write_events),
            "condition_custody_bindings": len(self.custody_condition_bindings),
            "condition_storage_observation_sids": len(
                self.custody_condition_observation_sids
            ),
            "parameter_storage_initializers_required": len(
                required_initializer_sids
            ),
            "parameter_storage_initializers_rendered": len(
                rendered_initializer_sids
            ),
            "parameter_storage_initializers_missing": len(
                unrendered_initializer_sids
            ),
            "parameter_storage_initializers_preamble_rendered": len(
                self.custody_parameter_initializer_preamble_events
            ),
            "parameter_storage_initializer_preamble_rejections": len(
                self.custody_parameter_initializer_rejections
            ),
            "raw_indirect_expression_leaks": len(raw_indirect_leaks),
            "warnings": len(all_warnings),
            "rule": (
                "INDIRECT_is_metadata_only_effect_owner_executes_once_"
                "family_reads_and_writes_observe_shared_storage"
            ),
        }
        return {
            "summary": summary,
            "storage_family_descriptors": copy.deepcopy(descriptors),
            "indirect_suppressions": copy.deepcopy(
                self.custody_indirect_suppressions
            ),
            "effect_owner_render_events": copy.deepcopy(
                self.custody_owner_render_events
            ),
            "storage_read_events": copy.deepcopy(self.custody_read_events),
            "storage_write_events": copy.deepcopy(self.custody_write_events),
            "parameter_storage_initializer_events": copy.deepcopy(
                self.custody_parameter_initializer_events
            ),
            "parameter_initializer_preamble_events": copy.deepcopy(
                self.custody_parameter_initializer_preamble_events
            ),
            "parameter_initializer_rejections": copy.deepcopy(
                self.custody_parameter_initializer_rejections
            ),
            "raw_indirect_leaks": raw_indirect_leaks,
            "unobserved_effect_owner_op_keys": unresolved_owner_keys,
            "warnings": all_warnings,
        }

    # ---------------------------------------------------------
    # EXECUTABLE IDENTITY PUBLICATION GATE v46p
    # ---------------------------------------------------------

    @staticmethod
    def _unresolved_identity_name_v46p(name):
        return bool(
            re.fullmatch(
                r"(?:v_(?:v_)?[0-9]+|in_[A-Za-z0-9_]+)",
                str(name or ""),
            )
        )

    def _unresolved_executable_identities_v46p(
        self,
        rendered_lines,
    ):
        if self._is_readable_render_v44():
            return []

        text = "\n".join(rendered_lines or [])
        try:
            tree = ast.parse(text)
        except Exception:
            return []

        assigned = set()
        loaded = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.arg):
                assigned.add(node.arg)
            elif isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load):
                    loaded.add(node.id)
                elif isinstance(
                    node.ctx,
                    (ast.Store, ast.Param),
                ):
                    assigned.add(node.id)
            elif isinstance(node, ast.alias):
                assigned.add(
                    node.asname
                    or node.name.split(".", 1)[0]
                )
            elif isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                assigned.add(node.name)

        unresolved = sorted(
            name
            for name in loaded
            if (
                self._unresolved_identity_name_v46p(name)
                and name not in assigned
            )
        )
        return unresolved

    def _enforce_executable_identity_gate_v46p(
        self,
        rendered_lines,
    ):
        unresolved = (
            self._unresolved_executable_identities_v46p(
                rendered_lines
            )
        )
        if not unresolved:
            return

        event = {
            "kind": (
                "emitter_executable_unbound_identity_v46p"
            ),
            "version": self.VERSION,
            "projection": self.render_mode,
            "symbols": unresolved,
            "action": (
                "abort_function_publication_before_runtime"
            ),
        }
        self.abi_unresolved_identity_events.append(event)
        self.abi_render_warnings.append(event)
        setattr(
            self.func,
            "emitter_unresolved_identity_symbols",
            list(unresolved),
        )

        raise RuntimeError(
            "PAL emitter refused executable output with "
            "unbound identities: %s"
            % ", ".join(unresolved)
        )

    def emit_function(self, render_mode=None):

        if render_mode is not None:
            self.render_mode = self._normalize_render_mode_v44(render_mode)

        # Inline metadata: reset only this projection. Shared occurrence identities stay
        # in the document so the readable and executable passes can meet on
        # the same deterministic ExecTree path.
        self.code_document.begin_projection(self.render_mode)
        self._provenance_context_stack = []
        self._provenance_statement_ordinals = {}
        self._current_exec_path = None
        self._current_exec_occurrence_id = None
        self._current_block_occurrence_id = None
        self._imc_pending_operation_fragments = []

        # Optional targeted probe.  The old development build printed
        # local_18 metadata on every emission, which doubled console noise for
        # paired rendering and coupled the emitter to one specimen name.
        debug_probe = getattr(self.func, "emitter_debug_probe", None)
        if debug_probe:
            self.debug_dump_variable_metadata_core(debug_probe)


        self.lines = []
        self.indent = 0
        self.emitted_ops = set()
        self.emitted_blocks = set()
        self.emitted_returns = set()
        self.emitted_return_occurrences = set()
        self.return_must_print_events = []
        self.return_suppression_events = []
        self.emitted_phi_dropins = set()
        self.debug_events = []
        self._rendering_loop_condition = False
        self._current_structured_loop_condition = None
        self.loop_condition_alias_guard_events = []
        self._loop_condition_alias_guard_event_keys = set()
        self.dynamic_value_alias_by_sid = {}
        self._last_assignment = None
        self._last_value_expr_alias = None
        self._current_expr_op = None
        self._current_expr_block_addr = None
        self.c_truth_helper_calls = []
        self.c_truth_helper_call_keys = set()
        self.c_truth_render_warnings = []
        self.c_truth_raw_rewrite_events = []
        self.c_truth_raw_probe_events = []
        self.c_truth_readable_projection_events = []
        self.c_truth_required_helpers = set()
        self._c_truth_raw_contract_index = None
        self._c_truth_condition_context = None
        self.custody_indirect_suppressions = []
        self.custody_owner_render_events = []
        self.custody_read_events = []
        self.custody_write_events = []
        self.custody_parameter_initializer_events = []
        self.custody_parameter_initializer_preamble_events = []
        self.custody_parameter_initializer_rejections = []
        self.custody_parameter_initializer_preamble_output_sids = set()
        self.custody_parameter_initializer_preamble_records_by_output_sid = {}
        self.custody_warnings = list(self.custody_static_warnings)
        self._custody_event_keys = set()
        self.abi_entry_materialization_events = []
        self.abi_call_render_events = []
        self.abi_convergence_render_events = []
        self.abi_identity_reuse_events = []
        self.abi_identity_reuse_rejections = []
        self.abi_return_render_events = []
        self.abi_render_warnings = list(self.abi_static_warnings)
        self._abi_event_keys = set()

        self._emit_header()
        function_body_start = len(self.lines)

        root = getattr(self.func, "exec_root", None)

        if root is None:
            root = getattr(self.func, "exec_tree", None)

        if root is None:
            self._w("# WARNING: no execution tree available; using linear fallback")
            self._emit_fallback_linear()

        elif not self._tree_has_blocks(root):
            self._w("# WARNING: execution tree contains no blocks; using linear fallback")
            self._emit_fallback_linear()

        else:
            self._event("ExecTree block count: %d" % self._count_tree_blocks(root))
            self._emit_node(root, ("root",))

        if len(self.lines) == function_body_start:
            self._w("pass")

        rendered_lines = list(self.lines)
        self._enforce_executable_identity_gate_v46p(
            rendered_lines
        )
        custody_debug = self._custody_projection_debug_v45(rendered_lines)
        abi_debug = self._abi_projection_debug_v46(rendered_lines)
        projection = self.code_document.finalize_projection(
            self.render_mode,
            expected_lines=rendered_lines,
        )
        if projection.lines != rendered_lines:
            raise AssertionError("PAL document projection line identity failure")
        self._populate_code_document_metadata_im_c()
        self.code_document.build_inline_spans(self.render_mode)
        self.func.code_document = self.code_document
        self.func.code_document_debug = self.code_document.summary()
        pycode_by_mode = dict(getattr(self.func, "pycode_by_mode", {}) or {})
        pycode_by_mode[self.render_mode] = rendered_lines
        self.func.pycode_by_mode = pycode_by_mode
        if self._is_readable_render_v44():
            self.func.pycode_readable = rendered_lines
        else:
            # Backward-compatible authority: func.pycode remains the
            # executable/helper stream consumed by current callers.
            self.func.pycode_executable = rendered_lines
            self.func.pycode = rendered_lines
        self.func.emitter_debug = self.debug_events
        self.func.loop_condition_alias_guard_events = list(self.loop_condition_alias_guard_events)
        helper_names = sorted(self.c_truth_required_helpers)
        all_warnings = (
            list(self.c_truth_consumer_warnings)
            + list(self.c_truth_render_warnings)
            + list(custody_debug.get("warnings", []) or [])
            + list(abi_debug.get("warnings", []) or [])
        )
        audited_op_contracts = list(self.c_truth_contracts_by_op.values())
        audited_op_contracts.extend(
            list(self.c_truth_outputless_contracts_by_op.values())
        )
        required_contract_keys = {
            contract.get("op_key")
            for contract in audited_op_contracts
            if isinstance(contract, dict)
            and contract.get("runtime_helper")
            and contract.get("op_key") is not None
        }
        rendered_contract_keys = {
            record.get("op_key")
            for record in self.c_truth_helper_calls
            if record.get("op_key") is not None
        }
        unrendered_contract_keys = sorted(
            required_contract_keys - rendered_contract_keys,
            key=str,
        )
        self.func.emitter_c_truth_debug = {
            "summary": {
                "kind": "emitter_c_truth_inventory_v46",
                "version": self.VERSION,
                "render_mode": self.render_mode,
                "readable_type_views": bool(
                    self.readable_show_type_views
                ),
                "active": bool(self.c_truth_active),
                "helpers_included": helper_names,
                "helper_kinds": len(helper_names),
                "contract_render_sites": len(self.c_truth_helper_calls),
                "required_helper_contracts": len(required_contract_keys),
                "rendered_helper_contracts": len(required_contract_keys & rendered_contract_keys),
                "unrendered_helper_contracts": len(unrendered_contract_keys),
                "raw_condition_rewrites": len(self.c_truth_raw_rewrite_events),
                "readable_contract_projections": len(
                    self.c_truth_readable_projection_events
                ),
                "consumer_warnings": len(self.c_truth_consumer_warnings),
                "render_warnings": len(self.c_truth_render_warnings),
                "warnings": len(all_warnings),
                "return_must_print_overrides": len(self.return_must_print_events),
                "return_suppressions": len(self.return_suppression_events),
                "rule": "render_PHIfolder_owned_PALCompute_contracts_without_numeric_reinference",
            },
            "helper_calls": list(self.c_truth_helper_calls),
            "unrendered_helper_op_keys": unrendered_contract_keys,
            "unrendered_contract_details": self._c_truth_unrendered_contract_details(
                unrendered_contract_keys
            ),
            "raw_condition_rewrites": list(self.c_truth_raw_rewrite_events),
            "raw_condition_probes": list(self.c_truth_raw_probe_events),
            "readable_projections": list(
                self.c_truth_readable_projection_events
            ),
            "return_must_print_events": list(self.return_must_print_events),
            "return_suppression_events": list(self.return_suppression_events),
            "warnings": all_warnings,
            "storage_custody": copy.deepcopy(custody_debug),
            "abi_custody": copy.deepcopy(abi_debug),
        }
        self.func.emitter_storage_custody_debug = copy.deepcopy(custody_debug)
        self.func.emitter_abi_custody_debug = copy.deepcopy(abi_debug)
        custody_by_mode = dict(
            getattr(self.func, "emitter_storage_custody_debug_by_mode", {}) or {}
        )
        custody_by_mode[self.render_mode] = copy.deepcopy(custody_debug)
        self.func.emitter_storage_custody_debug_by_mode = custody_by_mode
        abi_by_mode = dict(
            getattr(self.func, "emitter_abi_custody_debug_by_mode", {}) or {}
        )
        abi_by_mode[self.render_mode] = copy.deepcopy(abi_debug)
        self.func.emitter_abi_custody_debug_by_mode = abi_by_mode
        debug_by_mode = dict(
            getattr(self.func, "emitter_c_truth_debug_by_mode", {}) or {}
        )
        debug_by_mode[self.render_mode] = copy.deepcopy(
            self.func.emitter_c_truth_debug
        )
        self.func.emitter_c_truth_debug_by_mode = debug_by_mode
        self.func.emitter_c_truth_version = self.VERSION
        self.func.emitter_storage_custody_version = self.VERSION
        self.func.emitter_abi_custody_version = self.ABI_CUSTODY_VERSION
        self.func.emitter_render_mode = self.render_mode

        return rendered_lines

    def _dual_path_control_signature_v44(self, lines):
        """Return a small expression-independent control skeleton."""
        signature = []
        for raw in list(lines or []):
            text = str(raw)
            stripped = text.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith("from PALhelpers import ")
                or stripped.startswith("from PALABI import ")
            ):
                continue
            indent = (len(text) - len(text.lstrip(" "))) // len(_INDENT)
            kind = None
            if stripped.startswith("def "):
                kind = "def"
            elif stripped.startswith("if "):
                kind = "if"
            elif stripped == "else:":
                kind = "else"
            elif stripped.startswith("while "):
                kind = "while"
            elif stripped == "break":
                kind = "break"
            elif stripped == "continue":
                kind = "continue"
            elif stripped == "pass":
                kind = "pass"
            elif stripped == "return" or stripped.startswith("return "):
                kind = "return"
            else:
                kind = "statement"
            signature.append((indent, kind))
        return signature

    def emit_function_pair(self):
        """
        Emit readable and executable presentations from this same emitter
        implementation and ExecTree.  Executable is emitted last and restored
        as the backward-compatible authoritative ``func.pycode`` stream.
        """
        readable_lines = list(self.emit_function(self.RENDER_READABLE))
        readable_debug = copy.deepcopy(self.func.emitter_c_truth_debug)
        readable_custody_debug = copy.deepcopy(
            self.func.emitter_storage_custody_debug
        )
        readable_abi_debug = copy.deepcopy(
            self.func.emitter_abi_custody_debug
        )

        executable_lines = list(self.emit_function(self.RENDER_EXECUTABLE))
        executable_debug = copy.deepcopy(self.func.emitter_c_truth_debug)
        executable_custody_debug = copy.deepcopy(
            self.func.emitter_storage_custody_debug
        )
        executable_abi_debug = copy.deepcopy(
            self.func.emitter_abi_custody_debug
        )

        readable_signature = self._dual_path_control_signature_v44(readable_lines)
        executable_signature = self._dual_path_control_signature_v44(executable_lines)
        readable_text = "\n".join(readable_lines)
        helper_leaks = sorted(set(re.findall(
            r"\b(c_[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            readable_text,
        )))
        document_pairing = self.code_document.pairing_summary()

        dual_debug = {
            "kind": "emitter_dual_path_inventory_v46",
            "version": self.VERSION,
            "single_core": True,
            "authoritative_mode": self.RENDER_EXECUTABLE,
            "readable_type_views": bool(self.readable_show_type_views),
            "readable_c_string_overlay_source": (
                self.readable_c_string_overlay_source
            ),
            "readable_c_string_overlay_selection": (
                self.readable_c_string_overlay_selection
            ),
            "readable_c_string_literals": len(
                self.readable_c_string_literals
            ),
            "readable_c_string_overlay_warnings": copy.deepcopy(
                self.readable_c_string_overlay_warnings
            ),
            "modes": list(self.RENDER_MODES),
            "readable_lines": len(readable_lines),
            "executable_lines": len(executable_lines),
            "readable_contract_projections": len(
                readable_debug.get("readable_projections", [])
            ),
            "control_signature_match": (
                readable_signature == executable_signature
            ),
            "document_semantic_statement_ids_match": document_pairing.get(
                "semantic_statement_ids_match"
            ),
            "document_paired_semantic_statements": document_pairing.get(
                "paired_semantic_statements"
            ),
            "document_readable_only_statement_ids": document_pairing.get(
                "readable_only_statement_ids"
            ),
            "document_executable_only_statement_ids": document_pairing.get(
                "executable_only_statement_ids"
            ),
            "document_line_cursor_lookup_ready": True,
            "document_frozen_bundle_ready": True,
            "document_inline_metadata_spans_ready": True,
            "document_f3_description_ready": True,
            "document_projection_sync_ready": True,
            "document_alias_projection_ready": True,
            "document_revisioned_edit_sidecars_ready": True,
            "document_bundle_schema_version": (
                self.code_document.BUNDLE_SCHEMA_VERSION
            ),
            "readable_helper_call_leaks": helper_leaks,
            "readable_raw_indirect_leaks": len(
                readable_custody_debug.get("raw_indirect_leaks", [])
            ),
            "executable_raw_indirect_leaks": len(
                executable_custody_debug.get("raw_indirect_leaks", [])
            ),
            "readable_storage_custody": readable_custody_debug.get(
                "summary", {}
            ),
            "executable_storage_custody": executable_custody_debug.get(
                "summary", {}
            ),
            "readable_abi_custody": readable_abi_debug.get("summary", {}),
            "executable_abi_custody": executable_abi_debug.get("summary", {}),
            "readable_warnings": list(readable_debug.get("warnings", []) or []),
            "executable_warnings": list(executable_debug.get("warnings", []) or []),
            "rule": "one_ExecTree_traversal_implementation_two_contract_render_policies",
        }

        self.func.pycode_readable = readable_lines
        self.func.pycode_executable = executable_lines
        self.func.pycode = executable_lines
        self.func.pycode_by_mode = {
            self.RENDER_READABLE: readable_lines,
            self.RENDER_EXECUTABLE: executable_lines,
        }
        self.func.emitter_c_truth_debug_by_mode = {
            self.RENDER_READABLE: readable_debug,
            self.RENDER_EXECUTABLE: executable_debug,
        }
        self.func.emitter_storage_custody_debug_by_mode = {
            self.RENDER_READABLE: readable_custody_debug,
            self.RENDER_EXECUTABLE: executable_custody_debug,
        }
        self.func.emitter_abi_custody_debug_by_mode = {
            self.RENDER_READABLE: readable_abi_debug,
            self.RENDER_EXECUTABLE: executable_abi_debug,
        }
        self.func.emitter_storage_custody_debug = executable_custody_debug
        self.func.emitter_abi_custody_debug = executable_abi_debug
        self.func.emitter_c_truth_debug = executable_debug
        self.func.emitter_dual_path_debug = dual_debug
        self.func.code_document = self.code_document
        self.func.code_document_debug = self.code_document.summary()
        self.func.emitter_render_mode = self.RENDER_EXECUTABLE
        self.render_mode = self.RENDER_EXECUTABLE
        self.lines = executable_lines

        return {
            self.RENDER_READABLE: readable_lines,
            self.RENDER_EXECUTABLE: executable_lines,
        }

    # Short convenience name for pipeline/UI callers.
    emit_both = emit_function_pair

    # ---------------------------------------------------------
    # WRITING
    # ---------------------------------------------------------

    def _w(self, s, provenance=None):

        text = _INDENT * self.indent + s
        self.lines.append(text)
        self._record_provenance_line(text, provenance=provenance)

    def _event(self, msg):

        self.debug_events.append(msg)

    # ---------------------------------------------------------
    # PAL STACK VERSION INVENTORY v46p
    # ---------------------------------------------------------

    @staticmethod
    def _pal_version_scalar_v46p(value):
        if value is None:
            return None
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            return text or None
        return None

    @classmethod
    def _pal_holder_version_v46p(cls, holder):
        if holder is None:
            return None

        preferred = (
            "BATCH_BUILD",
            "BUILD",
            "VERSION",
            "PIPELINE_VERSION",
            "LIFTER_VERSION",
            "CFG_VERSION",
            "RESOLVER_VERSION",
            "RAW_AUDIT_VERSION",
            "COMPUTE_VERSION",
            "SEMANTIC_VERSION",
            "SGL_VERSION",
            "PHI_VERSION",
            "EMITTER_VERSION",
            "DOCUMENT_VERSION",
            "HUMANIZER_VERSION",
        )

        for name in preferred:
            value = cls._pal_version_scalar_v46p(
                getattr(holder, name, None)
            )
            if value:
                return value

        try:
            names = sorted(dir(holder))
        except Exception:
            names = []

        for name in names:
            upper = str(name).upper()
            if not (
                upper.endswith("_VERSION")
                or upper.endswith("_BUILD")
            ):
                continue
            value = cls._pal_version_scalar_v46p(
                getattr(holder, name, None)
            )
            if value:
                return value

        return None

    @staticmethod
    def _pal_source_build_marker_v46p(module):
        path = getattr(module, "__file__", None)
        if not path:
            return None

        try:
            text = Path(path).read_text(
                encoding="utf-8",
                errors="replace",
            )[:8192]
        except Exception:
            return None

        patterns = (
            r"(?m)^\s*#\s*BUILD\s*:\s*(\S[^\r\n]*)$",
            r"(?m)^\s*#\s*VERSION\s*:\s*(\S[^\r\n]*)$",
            r"(?m)^\s*(?:BUILD|VERSION|BATCH_BUILD)\s*=\s*[\"']([^\"']+)[\"']",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return str(match.group(1)).strip()

        return None

    @classmethod
    def _pal_component_version_v46p(
        cls,
        module_name,
        class_name=None,
    ):
        module = sys.modules.get(module_name)
        if module is None:
            return "not_loaded"

        if class_name:
            version = cls._pal_holder_version_v46p(
                getattr(module, class_name, None)
            )
            if version:
                return version

        version = cls._pal_holder_version_v46p(module)
        if version:
            return version

        version = cls._pal_source_build_marker_v46p(module)
        if version:
            return version

        return "unknown"

    def _pal_stack_version_records_v46p(self):
        specs = (
            (
                "PALStaticStringPublisher",
                "PALStaticStringPublisher",
                None,
            ),
            (
                "PALBatchDecompiler",
                "PALBatchDecompiler",
                None,
            ),
            (
                "PALHumanizer",
                "PALHumanizer",
                "PALFunctionNameRegistry",
            ),
            (
                "PALDecompilerPipeline",
                "PALDecompilerPipeline",
                "PALDecompilerPipeline",
            ),
            (
                "PALlibrary.PALLifter",
                "PALlibrary",
                "PALLifter",
            ),
            (
                "PALlibrary.FunctionCFG",
                "PALlibrary",
                "FunctionCFG",
            ),
            (
                "PALSymbolResolver",
                "PALSymbolResolver",
                "PALSymbolResolver",
            ),
            (
                "PALRawAudit",
                "PALRawAudit",
                "PALRawAudit",
            ),
            (
                "PALCompute",
                "PALCompute",
                "PALComputeAnalyzer",
            ),
            (
                "PALSemanticGraphBuilder",
                "PALSemanticGraphBuilder",
                "PALSemanticGraphBuilder",
            ),
            (
                "PALSGLdecomp",
                "PALSGLdecomp",
                "PALSGLDecompiler",
            ),
            (
                "PALPHIfolder",
                "PALPHIfolder",
                "PALPHIfolder",
            ),
            (
                "PALemitter",
                "PALemitter",
                "PALemitter",
            ),
            (
                "PALCodeDocument",
                "PALCodeDocument",
                "PALCodeDocument",
            ),
        )

        out = []
        for label, module_name, class_name in specs:
            if label == "PALemitter":
                version = self.VERSION
            else:
                version = self._pal_component_version_v46p(
                    module_name,
                    class_name,
                )
            out.append((label, version))

        return out

    def _emit_pal_stack_version_block_v46p(self):
        self._w("#======= PAL stack versioning ======")
        for component, version in (
            self._pal_stack_version_records_v46p()
        ):
            self._w(
                "# %s = %s"
                % (
                    component,
                    str(version).replace("\n", " ").strip(),
                )
            )
        self._w("#====================================")
        self._w("")

    # ---------------------------------------------------------
    # HEADER
    # ---------------------------------------------------------

    def _emit_header(self):

        self._emit_pal_stack_version_block_v46p()

        if (
            (self.c_truth_active or self.custody_active or self.abi_active)
            and not self._is_readable_render_v44()
        ):
            helpers = sorted(self._c_truth_required_helper_names())
            self.c_truth_required_helpers.update(helpers)
            abi_helpers = [
                name for name in helpers if name in self.ABI_RUNTIME_HELPERS
            ]
            numeric_helpers = [
                name for name in helpers if name not in self.ABI_RUNTIME_HELPERS
            ]
            if abi_helpers:
                self._w("from PALABI import %s" % ", ".join(abi_helpers))
            if numeric_helpers:
                self._w("from PALhelpers import %s" % ", ".join(numeric_helpers))
            if helpers:
                self._w("")

        if self._is_readable_render_v44():
            self._w("# PAL readable projection (non-executable)")
            if self.readable_c_string_literals:
                self._w(
                    "# Static C-string call arguments projected from "
                    "PAL_stdio_strings.json"
                )
            if self.readable_show_type_views:
                self._w("# uN()/sN()/ptrN()/MEMN[] are PALCompute-backed type views")
            else:
                self._w("# Width/sign contracts remain available in PAL provenance metadata")
            self._w("")

        name = getattr(self.func, "func_name", "func")

        p = ", ".join(self._abi_signature_parameters_v46())

        self._w("def %s(%s):" % (name, p))

        self.indent += 1
        self._emit_abi_entry_prologue_v46()
        self._emit_custody_parameter_initializer_preamble_v46l()

    # =========================================================
    # EXEC TREE WALKER
    # =========================================================

    def _emit_node(self, node, path=None):

        if node is None:
            return

        if path is None:
            parent_path = tuple(self._current_exec_path or ("root",))
            path = parent_path + ("implicit",)
        else:
            path = tuple(path)

        occurrence_id, cfg_addr = self._provenance_occurrence_for_node(
            node, path
        )
        kind = getattr(node, "kind", None) or "node"
        old_path = self._current_exec_path
        old_occurrence = self._current_exec_occurrence_id
        old_block_occurrence = self._current_block_occurrence_id
        self._current_exec_path = path
        self._current_exec_occurrence_id = occurrence_id
        if kind == "block" or cfg_addr is not None:
            self._current_block_occurrence_id = occurrence_id

        metadata_refs = []
        if cfg_addr is not None:
            addr_text = hex(cfg_addr) if isinstance(cfg_addr, int) else str(cfg_addr)
            metadata_refs.append("cfg:block:%s" % addr_text)

        try:
            with self._provenance_scope(
                exec_occurrence_id=occurrence_id,
                block_occurrence_id=self._current_block_occurrence_id,
                cfg_block_addr=cfg_addr,
                role=kind,
                metadata_refs=metadata_refs,
            ):
                return self._emit_node_body(node, path)
        finally:
            self._current_exec_path = old_path
            self._current_exec_occurrence_id = old_occurrence
            self._current_block_occurrence_id = old_block_occurrence

    def _emit_node_body(self, node, path):

        if node is None:
            return

        kind = getattr(node, "kind", None)

        if kind is None:
            self._event("node without kind: %s" % str(node))
            return

        if kind in ("sequence", "then", "else", "loop_body"):

            for index, child in enumerate(list(getattr(node, "children", []))):
                self._emit_node(
                    child,
                    path + ("%s.children.%d" % (kind, index),),
                )

            return

        if kind == "block":
            self._emit_block(node)
            return

        # v19b: SGL control-transfer leaves are semantic nodes, not empty
        # containers.  If these are not printed, the emitter creates pass/pass
        # artifacts and destroys loop truth.
        if kind == "break":
            self._reset_assignment_boundary()
            self._w("break", provenance={"role": "break"})
            self._reset_assignment_boundary()
            return

        if kind == "continue":
            self._reset_assignment_boundary()
            self._w("continue", provenance={"role": "continue"})
            self._reset_assignment_boundary()
            return

        if kind == "return":
            self._reset_assignment_boundary()
            return_addr = self._cfg_addr(getattr(node, "cfg_node", None))
            if return_addr is None:
                return_addr = getattr(self, "_current_block_addr", None)
            if self._abi_return_is_suppressed_v46(return_addr):
                self._abi_record_return_suppression_v46(return_addr)
                self._reset_assignment_boundary()
                return
            rv = getattr(node, "value", None)
            if rv is None:
                self._w(
                    "return",
                    provenance={
                        "role": "return",
                        "metadata_refs": [
                            "abi:return_reconciliation", "abi:entry_plan"
                        ] if self.abi_active else [],
                    },
                )
            else:
                expr = self._return_expr(rv)
                abi_expr = self._abi_return_expr_v46(return_addr, expr)
                expr = (
                    abi_expr if abi_expr is not None
                    else self._c_truth_return_value_expr(rv, expr)
                )
                self._w(
                    "return %s" % expr,
                    provenance={
                        "role": "return",
                        "use_sids": self._provenance_sid_list([rv]),
                        "metadata_refs": [
                            "abi:return_reconciliation", "abi:entry_plan"
                        ] if self.abi_active else [],
                    },
                )
            self._reset_assignment_boundary()
            return

        if kind == "if":

            self._emit_condition_setup(node)

            # v35: SGL RawCond strings are already edge-oriented predicates.
            # In particular, metadata branch-mirror conditions deliberately
            # arrive as textual `not (...)`.  Preserve that NOT instead of
            # simplifying it into an opposite comparison, because the NOT is
            # PAL's metadata-level branch polarity fact.
            cond_var = getattr(node, "cond_var", None)
            old_c_truth_context = self._c_truth_condition_context
            self._c_truth_condition_context = {
                "kind": "if",
                "cfg_addr": self._cfg_addr(getattr(node, "cfg_node", None)),
                "condition_sid": self._sid_of(cond_var),
                "raw_condition": self._raw_condition_text(cond_var),
            }
            try:
                cond = self._struct_if_condition_text(cond_var)
            finally:
                self._c_truth_condition_context = old_c_truth_context

            self._w(
                "if %s:" % cond,
                provenance={
                    "role": "condition",
                    "use_sids": self._provenance_sid_list([cond_var]),
                },
            )
            self.indent += 1

            # v34: do not let duplicate-assignment suppression leak across
            # branch arms. Branches are alternative paths, not linear text.
            saved_assignment = self._last_assignment
            self._reset_assignment_boundary()

            before = len(self.lines)
            self._emit_node(
                getattr(node, "then_branch", None), path + ("if.then",)
            )
            if len(self.lines) == before:
                self._w("pass", provenance={"role": "synthetic_pass"})

            self.indent -= 1

            else_branch = getattr(node, "else_branch", None)
            else_children = getattr(else_branch, "children", []) if else_branch else []

            if else_children:
                self._w("else:", provenance={"role": "else"})
                self.indent += 1

                self._reset_assignment_boundary()
                before = len(self.lines)
                self._emit_node(else_branch, path + ("if.else",))
                if len(self.lines) == before:
                    self._w("pass", provenance={"role": "synthetic_pass"})

                self.indent -= 1

            # The merge point after an if is a control-flow boundary. A last
            # assignment inside either arm must not suppress a required join or
            # loop-epilogue assignment that follows the if.
            self._reset_assignment_boundary()
            return

        if kind == "loop":

            # Loop-header PHIs have two semantic classes:
            #   entry source  -> must be materialized before the first test
            #   backedge source -> belongs after the body/latch occurrence
            # This printer emits only the entry PHI drop-ins here.
            self._emit_loop_entry_phi_dropins(node)
            self._emit_condition_setup(node)

            # Generic printer mode: for/range recovery is source-level
            # reconstruction. Use only when explicitly enabled.
            if self.enable_for_loop_recovery and self._try_emit_for_loop(node):
                return

            old_loop_condition = self._current_structured_loop_condition
            self._current_structured_loop_condition = node
            try:
                cond = self._loop_cond_forced(node)
                # _loop_cond_forced already cleans most paths, but the final
                # normalization must remain in loop-header context too.  That
                # prevents a second cleaner pass from reapplying the very
                # post-update alias guarded by v42.
                cond = self._cond_clean(cond)
            finally:
                self._current_structured_loop_condition = old_loop_condition

            self._w(
                "while %s:" % cond,
                provenance={
                    "role": "loop_condition",
                    "use_sids": self._provenance_sid_list(
                        [getattr(node, "cond_var", None)]
                    ),
                },
            )
            self.indent += 1

            self._reset_assignment_boundary()
            before = len(self.lines)
            self._emit_node(getattr(node, "body", None), path + ("loop.body",))
            if len(self.lines) == before:
                self._w("pass", provenance={"role": "synthetic_pass"})

            self.indent -= 1
            self._reset_assignment_boundary()

            return

        for index, child in enumerate(getattr(node, "children", [])):
            self._emit_node(
                child,
                path + ("%s.children.%d" % (kind, index),),
            )

    # =========================================================
    # BLOCK EMISSION
    # =========================================================

    def _emit_block(self, exec_block):

        cfg_node = getattr(exec_block, "cfg_node", None)

        if cfg_node is None:
            self._event("ExecBlock without cfg_node")
            return

        block = getattr(cfg_node, "block", None)

        if block is None:
            self._event("CFGNode without block")
            return

        block_addr = getattr(block, "addr", None)

        # v19b: allow intentional repeated block occurrences from SGL, but
        # suppress duplicate ops within a single occurrence only.
        if block_addr in self._block_emit_stack:
            self._event("recursive block emission suppressed at %s" % (hex(block_addr) if isinstance(block_addr, int) else str(block_addr)))
            return

        self._block_emit_stack.append(block_addr)
        old_occurrence_ops = getattr(self, "_current_block_occurrence_ops", None)
        old_occurrence_dropins = getattr(self, "_current_block_occurrence_dropins", None)
        old_current_block_addr = getattr(self, "_current_block_addr", None)
        self._current_block_occurrence_ops = set()
        self._current_block_occurrence_dropins = set()
        self._current_block_addr = block_addr

        try:
            for op in getattr(block, "ops", []):
                self._emit_op(op)

            self._emit_phi_dropins_for_block(block)
            self._emit_terminator_if_needed(block)
        finally:
            self._current_block_occurrence_ops = old_occurrence_ops
            self._current_block_occurrence_dropins = old_occurrence_dropins
            self._current_block_addr = old_current_block_addr
            self._block_emit_stack.pop()
            self.emitted_blocks.add(block_addr)

    # ---------------------------------------------------------
    # CONDITION HEADER SETUP
    # ---------------------------------------------------------

    def _emit_condition_setup(self, struct_node):
        """
        Emit only execution-required setup before an if/loop header.

        This is not a pretty-printer layer.  It materializes values that are
        required by the condition or by side-effect-preserving snapshots in the
        condition block.

        Examples:
            v_1736 = feedback(local_20, local_10)   # condition dependency
            v_4658 = local_20                       # protected swap snapshot

        Pure compare/boolean/arithmetic condition builders are still rendered
        by _cond() and are not printed as standalone assignments unless
        PHIfolder explicitly marks them materialized.
        """

        if struct_node is None:
            return

        kind = getattr(struct_node, "kind", None)

        if kind == "loop" and getattr(struct_node, "cond_var", None) is None:
            return

        cfg_node = getattr(struct_node, "cfg_node", None)

        if cfg_node is None:
            cfg_node = getattr(struct_node, "header", None)

        if cfg_node is None:
            return

        # If a loop body explicitly contains its header block, setup emission
        # would duplicate body operations.  Let the body block print them.
        if kind == "loop":
            body = getattr(struct_node, "body", None)
            if self._exec_tree_contains_cfg_node(body, cfg_node):
                return

        block = getattr(cfg_node, "block", None)

        if block is None:
            return

        old_setup = getattr(self, "_in_condition_setup", False)
        self._in_condition_setup = True

        try:
            for op in getattr(block, "ops", []):
                if self._condition_setup_should_emit_op(struct_node, op):
                    self._emit_op(op)
        finally:
            self._in_condition_setup = old_setup

    def _condition_setup_should_emit_op(self, struct_node, op):
        if op is None:
            return False

        oc = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        sid = self._sid_of(out)

        if oc is None or oc in ("MULTIEQUAL", "INDIRECT"):
            return False

        if oc in ("CBRANCH", "BRANCH", "BRANCHIND", "RETURN"):
            return False

        # Required call results feeding conditions must be emitted.  This is
        # the v_1736 = feedback(...) class.
        if oc in ("CALL", "CALLIND"):
            return self._condition_setup_needs_call_result(struct_node, op)

        # Protected snapshots must be emitted even though they are COPYs and
        # even when not directly part of the boolean expression.  This is the
        # v_4658 = local_20 swap snapshot class.
        if sid in self.protected_copy_temp_sids:
            return True

        # PHIfolder v20 metadata closure: exact condition-temp definitions
        # consumed by a condition should be materialized before that condition.
        if self._condition_temp_def_applies(struct_node, sid):
            return True

        # PHIfolder may mark condition values/materialized temps as required.
        if sid in self.required_call_result_sids:
            return True
        if sid in self.protected_condition_value_sids:
            return True
        if sid in self.condition_dependency_sids and sid in self.materialize_sids:
            return True

        # Local initializers/state writes should be emitted by block emission,
        # not setup, unless setup is the only occurrence.  Avoid broad logic.
        return False

    def _condition_setup_needs_call_result(self, struct_node, op):
        out = getattr(op, "output", None)
        if out is None:
            return False

        sid = self._sid_of(out)

        if sid in self.required_call_result_sids:
            return True

        if sid in self.protected_condition_value_sids:
            return True

        if sid in self.condition_dependency_sids:
            return True

        cond = getattr(struct_node, "cond_var", None)
        if cond is None:
            return False

        if getattr(cond, "ssa_id", None) == sid:
            return True

        return False

    def _condition_temp_def_applies(self, struct_node, sid):
        if sid is None:
            return False

        if sid not in self.condition_temp_def_sids and str(sid) not in self.condition_temp_defs_by_sid:
            return False

        addr = self._condition_consumer_addr(struct_node)
        if addr is None:
            return True

        records = self.condition_temp_defs_by_sid.get(sid, []) + self.condition_temp_defs_by_sid.get(str(sid), [])
        if not records:
            return True

        for rec in records:
            caddr = rec.get("consumer_addr")
            if caddr == addr or str(caddr) == str(addr):
                return True

        return False

    def _condition_consumer_addr(self, struct_node):
        if struct_node is None:
            return None

        cfg_node = getattr(struct_node, "cfg_node", None)
        if cfg_node is None:
            cfg_node = getattr(struct_node, "header", None)

        return self._cfg_addr(cfg_node)


    def _exec_tree_contains_cfg_node(self, exec_node, cfg_node):
        if exec_node is None or cfg_node is None:
            return False

        if getattr(exec_node, "cfg_node", None) is cfg_node:
            return True

        if getattr(exec_node, "header", None) is cfg_node:
            return True

        for child in list(getattr(exec_node, "children", []) or []):
            if self._exec_tree_contains_cfg_node(child, cfg_node):
                return True

        # Common branch/container fields.
        for attr in ("body", "then_branch", "else_branch"):
            child = getattr(exec_node, attr, None)
            if child is not None and self._exec_tree_contains_cfg_node(child, cfg_node):
                return True

        return False

    # ---------------------------------------------------------
    # TERMINATOR EMISSION
    # ---------------------------------------------------------

    def _emit_terminator_if_needed(self, block):

        term = getattr(block, "terminator", None)

        if term is None:
            return

        opcode = getattr(term, "opcode", None)

        if opcode == "RETURN":
            self._emit_return_terminator(block, term)
            return

        return

    def _return_expr(self, x, seen=None):
        """
        Render a terminal RETURN value.

        RETURN is a terminal observation, so pure expression temps can be
        collapsed even when normal statement rendering would keep them as vars.

        Example:
            INT_ADD [local_1c, local_20] -> v_557
            COPY [v_557] -> v_1721
            RETURN v_1721

        should emit:
            return (local_1c + local_20)
        """

        if seen is None:
            seen = set()

        if x is None:
            return "None"

        if hasattr(x, "var") and hasattr(x, "opcode"):
            node = x
            sid = self._sid_of(getattr(node, "var", None))
        else:
            if getattr(x, "is_constant", False):
                return self._const(x)
            sid = self._sid_of(x)
            node = self.nodes.get(sid) or self.nodes.get(str(sid))

        abi_expr = self._abi_expr_for_sid_v46(
            sid, context="return_expression"
        )
        if abi_expr is not None:
            return abi_expr

        custody_expr = self._custody_read_expr_for_sid_v45(
            sid, context="return_expression"
        )
        if custody_expr is not None:
            return custody_expr

        if sid is not None:
            if sid in seen or str(sid) in seen:
                return self._expr(x)
            seen.add(sid)
            seen.add(str(sid))

        if node is None:
            return self._expr(x)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        c_truth_expr = self._c_truth_expr_for_node(
            node, inputs, seen=seen.copy(), context="return_expression"
        )
        if c_truth_expr:
            return c_truth_expr

        # Collapse terminal transparent bridge chains.
        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC"):
            if inputs:
                return self._return_expr(inputs[0], seen.copy())
            return self._expr(x)

        if opcode == "SUBPIECE":
            # Preserve current helper/width policy. If it was already mapped as
            # transparent, _expr will return the alias; otherwise render normally.
            alias = self._transparent_expr_alias_for_sid(sid)
            if alias:
                return alias
            return self._expr_from_node(node)

        if opcode in _BINARY and len(inputs) == 2:
            a = self._return_expr(inputs[0], seen.copy())
            b = self._return_expr(inputs[1], seen.copy())
            op = _BINARY[opcode]
            if op.startswith("<"):
                return "%s(%s, %s)" % (opcode.lower(), a, b)
            return "(%s %s %s)" % (a, op, b)

        if opcode in _UNARY and inputs:
            a = self._return_expr(inputs[0], seen.copy())
            op = _UNARY[opcode]
            if op.endswith(" "):
                return "(%s%s)" % (op, a)
            return "(%s%s)" % (op, a)

        # Do not re-execute calls at return; materialized call outputs remain vars.
        if opcode in ("CALL", "CALLIND"):
            return self._var(getattr(node, "var", x))

        return self._expr_from_node(node, seen.copy())



    def _return_occurrence_key_v44f(self, block, term):
        """Stable control-transfer identity for one structured occurrence."""
        occurrence_id = (
            getattr(self, "_current_block_occurrence_id", None)
            or getattr(self, "_current_exec_occurrence_id", None)
        )
        if occurrence_id is None:
            return None
        addr = getattr(block, "addr", id(block))
        try:
            op_key = self._op_key(term)
        except Exception:
            op_key = None
        return (str(occurrence_id), addr, str(op_key))

    def _return_must_print_decision_v44f(self, block, term):
        """Preserve suppressors while allowing occurrence-owned RETURNs.

        A repeated CFG return block is not duplicate execution when SGL places
        it in another structured branch occurrence.  Only the terminal RETURN
        receives this override.  Ordinary block operations, PHI bookkeeping,
        and SSA assignments continue through their existing suppressors.
        """
        addr = getattr(block, "addr", id(block))
        occurrence_key = self._return_occurrence_key_v44f(block, term)
        global_seen = addr in self.emitted_returns
        occurrence_seen = (
            occurrence_key is not None
            and occurrence_key in self.emitted_return_occurrences
        )

        if occurrence_seen:
            return {
                "emit": False,
                "must_print_override": False,
                "reason": "same_structured_return_occurrence_already_emitted",
                "block_addr": addr,
                "occurrence_key": occurrence_key,
            }

        if not global_seen:
            return {
                "emit": True,
                "must_print_override": False,
                "reason": "first_global_return_block_occurrence",
                "block_addr": addr,
                "occurrence_key": occurrence_key,
            }

        if occurrence_key is not None:
            return {
                "emit": True,
                "must_print_override": True,
                "reason": "distinct_structured_occurrence_owns_terminal_return",
                "block_addr": addr,
                "occurrence_key": occurrence_key,
            }

        return {
            "emit": False,
            "must_print_override": False,
            "reason": "legacy_global_return_suppressor_no_occurrence_contract",
            "block_addr": addr,
            "occurrence_key": None,
        }

    def _emit_return_terminator(self, block, term):

        addr = getattr(block, "addr", id(block))

        if self._abi_return_is_suppressed_v46(block):
            self._abi_record_return_suppression_v46(block)
            return

        decision = self._return_must_print_decision_v44f(block, term)
        if not decision.get("emit"):
            self.return_suppression_events.append(dict(decision))
            return

        self.emitted_returns.add(addr)
        occurrence_key = decision.get("occurrence_key")
        if occurrence_key is not None:
            self.emitted_return_occurrences.add(occurrence_key)
        if decision.get("must_print_override"):
            event = dict(decision)
            event["kind"] = "emitter_return_must_print_override_v44f"
            event["ssa_suppressors_unchanged"] = True
            self.return_must_print_events.append(event)

        inputs = list(getattr(term, "inputs", []) or [])

        if not inputs:
            self._w(
                "return",
                provenance={
                    "role": "return",
                    "metadata_refs": [
                        "abi:return_reconciliation", "abi:entry_plan"
                    ] if self.abi_active else [],
                },
            )
            return

        ret = inputs[-1]

        if ret is None:
            self._w(
                "return",
                provenance={
                    "role": "return",
                    "metadata_refs": [
                        "abi:return_reconciliation", "abi:entry_plan"
                    ] if self.abi_active else [],
                },
            )
            return

        expr = self._return_expr(ret)
        abi_expr = self._abi_return_expr_v46(block, expr)
        expr = (
            abi_expr if abi_expr is not None
            else self._c_truth_return_boundary_expr(block, term, expr, ret)
        )
        self._w(
            "return %s" % expr,
            provenance={
                "role": "return",
                "use_sids": self._provenance_sid_list([ret]),
                "op_keys": [self._op_key(term)],
                "metadata_refs": [
                    "abi:return_reconciliation", "abi:entry_plan"
                ] if self.abi_active else [],
            },
        )

    def _c_truth_return_control_contract(self, block):
        if not self.c_truth_active:
            return None
        addr = getattr(block, "addr", None) if block is not None else None
        records = (
            self.c_truth_control_contracts_by_block.get(addr)
            or self.c_truth_control_contracts_by_block.get(str(addr))
            or []
        )
        for contract in list(records or []):
            if isinstance(contract, dict) and contract.get("opcode") == "RETURN":
                return contract
        return None

    def _c_truth_return_value_expr(self, value, expr):
        if not self.c_truth_active:
            return expr
        plan = self._c_truth_plan_for_sid(self._sid_of(value))
        width = plan.get("output_width_bits") if isinstance(plan, dict) else None
        if width is None:
            width = self._width_bits_for_value(value, None)
        if not isinstance(width, int) or width <= 0:
            return expr
        if self._is_readable_render_v44():
            return self._readable_cast_v44(expr, width)
        self.c_truth_required_helpers.add("c_return_bits")
        return "c_return_bits(%s, %s)" % (expr, width)

    def _c_truth_return_boundary_expr(self, block, term, expr, value):
        contract = self._c_truth_return_control_contract(block)
        if not isinstance(contract, dict):
            return self._c_truth_return_value_expr(value, expr)
        helper = contract.get("runtime_helper")
        width = contract.get("return_value_width_bits")
        if not helper or not isinstance(width, int) or width <= 0:
            return expr
        self._c_truth_record_helper_call(contract, "return_boundary", helper)
        if self._is_readable_render_v44():
            projected = self._readable_cast_v44(expr, width)
            self.c_truth_readable_projection_events.append({
                "kind": "emitter_readable_contract_projection_v44",
                "op_key": contract.get("op_key"),
                "output_sid": contract.get("output_sid"),
                "opcode": contract.get("opcode"),
                "runtime_helper": helper,
                "context": "return_boundary",
                "projection": projected,
            })
            return projected
        self.c_truth_required_helpers.add(helper)
        return "%s(%s, %s)" % (helper, expr, width)

    # =========================================================
    # ABI PHI-ENTRY LOCAL SEED SUBSTANTIATION v46m
    # =========================================================

    @staticmethod
    def _raw_variable_object_v46m(value):
        if value is None:
            return None
        raw = getattr(value, "var", None)
        return raw if raw is not None else value

    def _raw_variable_name_v46m(self, value):
        raw = self._raw_variable_object_v46m(value)
        name = getattr(raw, "name", None) if raw is not None else None
        if not name:
            return None
        return self._sanitize_name(str(name))

    def _phi_entry_local_target_name_v46m(self, rec):
        """
        Recover the PHI target's storage/presentation identity without passing
        through ABI-aware ``_var(target)``.

        ABI identity projection is correct for value reads, but it must not
        rename a distinct loop-carried local target back to its entry
        parameter.  Serialization-safe record fields are accepted because the
        Icecube path can legitimately retain SID/name custody after the live
        PALVariable object is no longer contextable.
        """
        if not isinstance(rec, dict):
            return None

        target = rec.get("target")
        target_sid = rec.get("target_sid")
        raw_target = self._raw_variable_object_v46m(target)

        raw_space = (
            getattr(raw_target, "space", None)
            if raw_target is not None else None
        )
        raw_type = (
            getattr(raw_target, "var_type", None)
            if raw_target is not None else None
        )

        record_space = (
            rec.get("target_space")
            or rec.get("storage_space")
            or rec.get("space")
        )

        candidates = [
            rec.get("target_name"),
            self._raw_variable_name_v46m(target),
            self.var_map.get(target_sid),
            self.var_map.get(str(target_sid)),
        ]

        fixed_names = {
            self._sanitize_name(str(name))
            for name in self.abi_fixed_argument_names
            if name
        }

        for candidate in candidates:
            if not candidate:
                continue

            name = self._sanitize_name(str(candidate))
            if not name:
                continue
            if name in fixed_names:
                continue
            if name.startswith("abi_"):
                continue
            if name.startswith("v_"):
                continue
            if name.startswith("0x"):
                continue

            stack_proven = bool(
                name.startswith("local_")
                or str(raw_space or "") == "stack"
                or str(raw_type or "") == "stack"
                or str(record_space or "") == "stack"
                or rec.get("target_is_stack_local") is True
            )
            if not stack_proven:
                continue

            return name

        return None

    def _abi_fixed_argument_identity_v46m(self, value):
        """
        Return the canonical fixed-argument identity for one value, or None.

        This consumes existing ABI-D/F ownership only. It does not infer
        argument placement from names.
        """
        if value is None or not self.abi_active:
            return None

        sid = self._sid_of(value)
        if sid is None:
            return None

        sid_text = str(sid)
        fixed_sids = {
            str(item)
            for item in self.abi_fixed_argument_sids
            if item is not None
        }

        root = self._abi_unique_root_for_sid_v46c(sid)
        root_sid = (
            str(root.get("sid"))
            if isinstance(root, dict)
            and root.get("sid") is not None
            else None
        )

        owned = (
            sid_text in fixed_sids
            or (
                root_sid is not None
                and root_sid in fixed_sids
            )
        )

        name = (
            self._abi_name_for_sid_v46(sid)
            or (
                self._abi_name_for_sid_v46(root_sid)
                if root_sid is not None
                else None
            )
        )

        fixed_names = {
            str(item)
            for item in self.abi_fixed_argument_names
            if item
        }
        if not owned and name not in fixed_names:
            return None
        if not name:
            return None

        return {
            "source_leaf_sid": sid_text,
            "source_root_sid": root_sid,
            "source_name": str(name),
            "authority": (
                "ABI_D_fixed_argument_or_ABI_F_unique_entry_root"
            ),
        }

    def _phi_entry_fixed_argument_source_v46m(self, rec):
        """
        Follow only a one-input transparent entry bridge:

            param_N -> COPY/CAST/... -> v_seed

        The bridge's full expression is still rendered later; this traversal
        exists only to prove that the seed is owned by one fixed ABI argument.
        """
        if not isinstance(rec, dict) or not self.abi_active:
            return None

        source = rec.get("source")
        source_sid = rec.get("source_sid")
        source_node = rec.get("source_node")

        if source_node is None and source is not None:
            source_node = self._node_for(source)
        if source_node is None and source_sid is not None:
            source_node = (
                self.nodes.get(source_sid)
                or self.nodes.get(str(source_sid))
            )

        queue = []
        if source is not None:
            queue.append((source, source_node))
        elif source_node is not None:
            queue.append(
                (
                    getattr(source_node, "var", None),
                    source_node,
                )
            )

        seen = set()

        while queue:
            value, node = queue.pop(0)
            sid = self._sid_of(value)
            marker = (
                str(sid) if sid is not None
                else "node:%s" % id(node)
            )
            if marker in seen:
                continue
            seen.add(marker)

            identity = self._abi_fixed_argument_identity_v46m(value)
            if isinstance(identity, dict):
                identity.update({
                    "source_sid": (
                        str(source_sid)
                        if source_sid is not None
                        else (
                            str(sid)
                            if sid is not None
                            else None
                        )
                    ),
                    "source_bridge_opcode": (
                        getattr(source_node, "opcode", None)
                        if source_node is not None
                        else None
                    ),
                })
                return identity

            if node is None and value is not None:
                node = self._node_for(value)
            if node is None:
                continue

            opcode = getattr(node, "opcode", None)
            inputs = list(getattr(node, "inputs", []) or [])

            if opcode not in _TRANSPARENT or len(inputs) != 1:
                continue

            child = inputs[0]
            child_node = self._node_for(child)
            queue.append((child, child_node))

        return None

    def _abi_phi_entry_local_seed_contract_v46m(
        self,
        rec,
        loop_entry=False,
    ):
        """
        Recognize the two-stage parameter-to-loop-local initialization:

            entry: COPY [param_N] -> v_seed
            header: MULTIEQUAL [v_seed, local_backedge] -> local_M

        The record may be objectless as long as PHIfolder retained target/source
        SIDs, target_name, and source_node lineage.
        """
        if (
            not loop_entry
            or not self.abi_active
            or not isinstance(rec, dict)
        ):
            return None

        key = self._phi_dropin_key(rec)
        cache_key = str(key)

        cached = self.abi_phi_entry_local_seed_contracts_by_key.get(
            cache_key
        )
        if isinstance(cached, dict):
            return cached

        target_name = self._phi_entry_local_target_name_v46m(rec)
        if not target_name:
            return None

        source_identity = (
            self._phi_entry_fixed_argument_source_v46m(rec)
        )
        if not isinstance(source_identity, dict):
            return None

        source_name = source_identity.get("source_name")
        if not source_name or source_name == target_name:
            return None

        contract = {
            "kind": "emitter_abi_phi_entry_local_seed_v46m",
            "version": self.ABI_CUSTODY_VERSION,
            "dropin_key": key,
            "dropin_key_text": cache_key,
            "pred_addr": rec.get("pred_addr"),
            "join_addr": rec.get("join_addr"),
            "target_sid": (
                str(rec.get("target_sid"))
                if rec.get("target_sid") is not None
                else None
            ),
            "target_name": target_name,
            "source_sid": (
                str(rec.get("source_sid"))
                if rec.get("source_sid") is not None
                else None
            ),
            "execution_policy": (
                "must_print_before_first_loop_condition_evaluation"
            ),
            "presentation_policy": (
                "preserve_distinct_local_LHS_bypass_ABI_value_alias"
            ),
            "authority": (
                "PHIfolder_outside_predecessor_dropin_plus_"
                "ABI_D_F_fixed_argument_lineage"
            ),
            **source_identity,
        }

        self.abi_phi_entry_local_seed_contracts_by_key[
            cache_key
        ] = contract
        return contract

    def _abi_phi_entry_local_seed_expr_v46m(self, rec, contract):
        """
        Render the original bridge expression, not merely its root name.

        COPY produces the parameter directly; CAST/ZEXT/SEXT/TRUNC retain the
        existing C-truth width semantics.
        """
        if not isinstance(contract, dict):
            return None

        source = rec.get("source")
        source_node = rec.get("source_node")

        if source_node is None and source is not None:
            source_node = self._node_for(source)
        if source_node is None and rec.get("source_sid") is not None:
            source_node = (
                self.nodes.get(rec.get("source_sid"))
                or self.nodes.get(str(rec.get("source_sid")))
            )

        if source_node is not None:
            opcode = getattr(source_node, "opcode", None)
            if opcode in _TRANSPARENT:
                expr = self._expr_from_node(source_node)
                if expr:
                    return expr

        if source is not None:
            expr = self._abi_expr_for_value_v46j(
                source,
                context="phi_entry_local_seed",
            )
            if expr:
                return expr
            return self._expr(source)

        return contract.get("source_name")

    def _abi_note_phi_entry_local_seed_v46m(
        self,
        contract,
        rendered,
    ):
        if not isinstance(contract, dict):
            return

        event = dict(contract)
        event.update({
            "projection": self.render_mode,
            "rendered": rendered,
            "must_print_consumed": True,
            "objectless_target_supported": True,
        })

        self._abi_record_event_v46(
            self.abi_phi_entry_local_seed_events,
            event,
            (
                "phi_entry_local_seed",
                contract.get("dropin_key_text"),
                self.render_mode,
            ),
        )

    # =========================================================
    # LOOP-HEADER PHI ENTRY EMISSION
    # =========================================================

    def _emit_loop_entry_phi_dropins(self, loop_node):
        """
        Emit entry-source PHI transitions for a loop header before rendering
        the while condition.

        This is an SGL printer operation, not source reconstruction.  A loop
        header MULTIEQUAL represents current state at the top of the loop.  If
        one predecessor is outside the loop body, that incoming value must be
        assigned before the first condition evaluation.

        Example alpha_four:
            header 0x10124a: local_18 <- v_1736 on entry,
                             local_18 <- v_1743 on backedge
        The printer must emit local_18 = v_1736 before while local_18 >= 1.
        """

        if loop_node is None:
            return

        # Only body-tested loops need entry PHI materialization before the
        # first condition evaluation.  A role=true / while-True do-loop header
        # already has its initial state in the preheader; emitting header PHIs
        # there leaks backedge values such as local_14 = v_367 before the loop.
        role = (
            getattr(loop_node, "condition_role", None)
            or getattr(loop_node, "emit_condition_mode", None)
            or getattr(loop_node, "loop_condition_role", None)
        )
        cond_var = getattr(loop_node, "cond_var", None)
        if role in ("true", "forever", "while_true") or cond_var is None:
            return
        # v46m: both body-admit and exit-predicate presentations evaluate
        # their condition before the first body execution.  The PHI entry seed
        # therefore belongs before either form.  Only true/do-loop forms remain
        # excluded.
        if role not in ("body", "exit"):
            return

        header = getattr(loop_node, "header", None) or getattr(loop_node, "cfg_node", None)
        header_addr = self._cfg_addr(header)
        if header_addr is None:
            return

        records = list(self.phi_dropins_by_join.get(header_addr, []) or [])
        if not records:
            return

        body_addrs = self._exec_tree_block_addrs(getattr(loop_node, "body", None))
        body_addrs.add(header_addr)

        old_occurrence_dropins = getattr(self, "_current_block_occurrence_dropins", None)
        self._current_block_occurrence_dropins = set()
        try:
            for rec in records:
                pred_addr = rec.get("pred_addr")
                if pred_addr in body_addrs:
                    continue
                self._emit_phi_dropin_record(rec, loop_entry=True)
        finally:
            self._current_block_occurrence_dropins = old_occurrence_dropins

    def _cfg_addr(self, cfg_node):
        if cfg_node is None:
            return None
        addr = getattr(cfg_node, "addr", None)
        if isinstance(addr, int):
            return addr
        block = getattr(cfg_node, "block", None)
        if block is not None:
            baddr = getattr(block, "addr", None)
            if isinstance(baddr, int):
                return baddr
        return None

    def _exec_tree_block_addrs(self, node):
        out = set()
        self._collect_exec_tree_block_addrs(node, out)
        return out

    def _collect_exec_tree_block_addrs(self, node, out):
        if node is None:
            return

        cfg_node = getattr(node, "cfg_node", None)
        addr = self._cfg_addr(cfg_node)
        if addr is not None:
            out.add(addr)

        header = getattr(node, "header", None)
        haddr = self._cfg_addr(header)
        if haddr is not None:
            out.add(haddr)

        for child in list(getattr(node, "children", []) or []):
            self._collect_exec_tree_block_addrs(child, out)

        for attr in ("body", "then_branch", "else_branch"):
            child = getattr(node, attr, None)
            if child is not None:
                self._collect_exec_tree_block_addrs(child, out)

    # =========================================================
    # PHI DROP-IN EMISSION
    # =========================================================

    def _emit_phi_dropins_for_block(self, block):

        if block is None:
            return

        pred_addr = getattr(block, "addr", None)

        if pred_addr is None:
            return

        records = list(self.phi_dropins_by_pred.get(pred_addr, []) or [])

        for rec in records:
            self._emit_phi_dropin_record(rec)

    def _phi_dropin_key(self, rec):
        if rec is None:
            return None

        # Accept both tuple-style ids from PHIfolder v19 and legacy records.
        rid = rec.get("id") or rec.get("dropin_id") or rec.get("key")

        if rid is not None:
            try:
                return tuple(rid)
            except Exception:
                return rid

        return (
            rec.get("pred_addr"),
            rec.get("join_addr"),
            rec.get("target_sid"),
            rec.get("source_sid"),
        )

    def _dynamic_alias_target_for_source_sid(self, source_sid):
        if source_sid is None:
            return None
        if source_sid in self.dynamic_value_alias_by_sid:
            return self.dynamic_value_alias_by_sid.get(source_sid)
        return self.dynamic_value_alias_by_sid.get(str(source_sid))

    def _record_dynamic_value_alias(self, source_sid, target_name):
        if source_sid is None or not target_name:
            return
        name = self._sanitize_name(str(target_name))
        self.dynamic_value_alias_by_sid[source_sid] = name
        self.dynamic_value_alias_by_sid[str(source_sid)] = name
        self._event("dynamic alias: %s -> %s" % (source_sid, name))

    def _source_sid_matches(self, a, b):
        if a is None or b is None:
            return False
        return a == b or str(a) == str(b)

    def _branch_closure_record_for_source_sid(self, source_sid):
        """Return the PHI/drop-in record that closes a temp computed in the
        current block into a real state target.

        This is the branch-closure printer rule:
            v_1500 = local_1c + 5
            local_1c = v_1500
        may be printed directly as:
            local_1c = local_1c + 5
        """
        if source_sid is None:
            return None

        block_addr = getattr(self, "_current_block_addr", None)
        if block_addr is None:
            return None

        if source_sid in self.protected_copy_temp_sids:
            return None

        records = list(self.phi_dropins_by_pred.get(block_addr, []) or [])
        if not records:
            return None

        best = None
        for rec in records:
            if not self._source_sid_matches(rec.get("source_sid"), source_sid):
                continue

            if rec.get("target") is None:
                continue

            required = self._dropin_is_required(rec)
            aliasish = (
                rec.get("source_aliased_to_target")
                or rec.get("accounted_for_by_state_alias")
                or rec.get("dropin_suppressed_reason") in (
                    "normal_source_op_writes_phi_target",
                    "v19_source_alias_writes_phi_target",
                )
                or source_sid in self.state_transition_alias_sids
                or source_sid in self.phi_source_alias_sids
                or source_sid in self.executable_dropin_source_sids
                or source_sid in self.post_update_alias_sids
            )

            if required or aliasish:
                return rec

            if best is None:
                best = rec

        return best

    def _branch_closure_target_for_output(self, out):
        sid = self._sid_of(out)
        rec = self._branch_closure_record_for_source_sid(sid)
        if rec is None:
            return None, None
        target = rec.get("target")
        if target is None:
            return None, None
        return self._var(target), rec

    def _emit_phi_dropin_record(self, rec, loop_entry=False):

        if rec is None:
            return
        phi_key = self._phi_dropin_key(rec)
        contract = self._abi_phi_entry_local_seed_contract_v46m(
            rec,
            loop_entry=loop_entry,
        )
        target_sid = rec.get("target_sid") or self._sid_of(rec.get("target"))
        source_sid = rec.get("source_sid") or self._sid_of(rec.get("source"))
        use_sids = [source_sid] if source_sid is not None else []
        if (
            isinstance(contract, dict)
            and contract.get("source_leaf_sid") is not None
        ):
            use_sids.append(contract.get("source_leaf_sid"))
        metadata_refs = ["phi_dropin:%s" % str(phi_key)]
        if isinstance(contract, dict):
            metadata_refs.append(
                "abi:phi_entry_local_seed:%s"
                % contract.get("dropin_key_text")
            )
        if target_sid is not None:
            metadata_refs.append("variable:%s" % str(target_sid))
        if source_sid is not None:
            metadata_refs.append("variable:%s" % str(source_sid))
        with self._provenance_scope(
            role=(
                "abi_phi_entry_local_seed"
                if isinstance(contract, dict)
                else (
                    "loop_entry_phi"
                    if loop_entry
                    else "phi_dropin"
                )
            ),
            op_keys=[phi_key],
            definition_sids=[target_sid] if target_sid is not None else [],
            use_sids=use_sids,
            metadata_refs=metadata_refs,
        ):
            return self._emit_phi_dropin_record_body(
                rec,
                loop_entry=loop_entry,
                phi_entry_seed_contract=contract,
            )

    def _emit_phi_dropin_record_body(
        self,
        rec,
        loop_entry=False,
        phi_entry_seed_contract=None,
    ):

        if rec is None:
            return

        key = self._phi_dropin_key(rec)
        required = self._dropin_is_required(rec)
        if phi_entry_seed_contract is None:
            phi_entry_seed_contract = (
                self._abi_phi_entry_local_seed_contract_v46m(
                    rec,
                    loop_entry=loop_entry,
                )
            )
        phi_entry_seed = isinstance(
            phi_entry_seed_contract,
            dict,
        )
        abi_must_print = bool(
            phi_entry_seed
            or rec.get("must_print_override")
            or key in self.abi_entry_must_print_dropin_ids
        )

        occurrence_dropins = getattr(self, "_current_block_occurrence_dropins", None)

        # Source-aliased PHI records are already emitted by the source op under
        # the target name.  This must outrank required/non-suppressible flags,
        # otherwise we get stale moves such as local_20 = v_1728 after
        # local_20 = mutate(...).
        if not abi_must_print and self._dropin_accounted_for_by_source_alias(rec):
            if occurrence_dropins is not None:
                occurrence_dropins.add(key)
            if not required:
                self.emitted_phi_dropins.add(key)
            return

        # Required executable drop-ins are path/occurrence facts.  Do not use
        # the global emitted_phi_dropins set to suppress them across duplicated
        # SGL branch arms.  Suppress only duplicates inside the same occurrence.
        if required or loop_entry:
            if occurrence_dropins is not None and key in occurrence_dropins:
                return
        else:
            if key in self.emitted_phi_dropins:
                return

        target = rec.get("target")
        source = rec.get("source")
        source_node = rec.get("source_node", None)

        # v46m accepts a serialization-safe/objectless PHI entry record when
        # the target name/SID and fixed-argument source lineage are proven.
        if not phi_entry_seed and (target is None or source is None):
            return

        dyn_name = self._dynamic_alias_target_for_source_sid(rec.get("source_sid"))
        if (
            not phi_entry_seed
            and dyn_name
            and dyn_name == self._var(target)
        ):
            if occurrence_dropins is not None:
                occurrence_dropins.add(key)
            if not required and not loop_entry:
                self.emitted_phi_dropins.add(key)
            return

        if (
            not phi_entry_seed
            and self._should_skip_alias_backed_phi_dropin(rec)
        ):
            if occurrence_dropins is not None:
                occurrence_dropins.add(key)
            if not required:
                self.emitted_phi_dropins.add(key)
            return

        target_name = (
            phi_entry_seed_contract.get("target_name")
            if phi_entry_seed
            else self._var(target)
        )
        expr = None
        if phi_entry_seed:
            expr = self._abi_phi_entry_local_seed_expr_v46m(
                rec,
                phi_entry_seed_contract,
            )
        if not expr:
            expr = self._c_truth_phi_transition_expr(rec)
        if not expr:
            expr = self._phi_source_expr(source, source_node)

        if not expr:
            return

        if expr == target_name:
            return

        # Backedge PHI duplicate guard: if the immediately preceding real op
        # already assigned the same target from the same source, the PHI
        # transition is satisfied for this SGL occurrence.
        if self._last_assignment_matches(target_name, expr):
            if occurrence_dropins is not None:
                occurrence_dropins.add(key)
            if not required and not loop_entry:
                self.emitted_phi_dropins.add(key)
            return

        if occurrence_dropins is not None:
            occurrence_dropins.add(key)
        if not required and not loop_entry:
            self.emitted_phi_dropins.add(key)

        before_line_count = len(self.lines)
        target_sid = (
            rec.get("target_sid")
            or self._sid_of(target)
        )
        self._emit_assignment(
            target_name,
            expr,
            custody_sid=target_sid,
        )
        if target is not None:
            self._register_assignment_rewrite(
                target,
                source,
                source_node,
                target_name,
                expr,
            )
        if phi_entry_seed and len(self.lines) > before_line_count:
            self._abi_note_phi_entry_local_seed_v46m(
                phi_entry_seed_contract,
                self.lines[-1].strip(),
            )

    def _c_truth_phi_transition_expr(self, rec):
        if not self.c_truth_active or not isinstance(rec, dict):
            return None
        transition = rec.get("compute_transition_contract")
        if not isinstance(transition, dict):
            return None
        if transition.get("execution_owner") != "predecessor_phi_dropin":
            return None
        source_contract = transition.get("source_compute_contract")
        if not isinstance(source_contract, dict) or not source_contract.get("runtime_helper"):
            return None
        source_node = rec.get("source_node")
        if source_node is None:
            return None
        opcode = getattr(source_node, "opcode", None)
        if opcode in ("CALL", "CALLIND"):
            return None
        inputs = list(getattr(source_node, "inputs", []) or [])
        return self._c_truth_render_contract_expr(
            source_contract,
            inputs,
            context="predecessor_phi_dropin",
        )

    def _dropin_accounted_for_by_source_alias(self, rec):
        if rec is None:
            return False

        source_sid = rec.get("source_sid")
        target_sid = rec.get("target_sid")
        key = self._phi_dropin_key(rec)

        if rec.get("source_aliased_to_target"):
            return True
        if rec.get("accounted_for_by_state_alias"):
            return True
        if rec.get("dropin_suppressed_reason") in (
            "normal_source_op_writes_phi_target",
            "v19_source_alias_writes_phi_target",
        ):
            return True

        if source_sid in self.state_transition_alias_sids:
            info = self.state_transition_aliases.get(source_sid, {})
            if not info:
                return True
            if target_sid is None or info.get("target_sid") in (None, target_sid):
                return True

        if source_sid in self.phi_source_alias_sids:
            info = self.phi_source_aliases.get(source_sid, {})
            if not info:
                return True
            if target_sid is None or info.get("target_sid") in (None, target_sid):
                return True

        if source_sid in self.dropin_suppressed_by_source_alias:
            return True
        if key in self.dropin_suppressed_by_source_alias:
            return True

        # PHIfolder also stores a 4-tuple suppression marker in some cases:
        # (pred_addr, join_addr, target_sid, source_sid)
        short_key = (
            rec.get("pred_addr"),
            rec.get("join_addr"),
            target_sid,
            source_sid,
        )
        if short_key in self.dropin_suppressed_by_source_alias:
            return True

        return False

    def _dropin_is_required(self, rec):

        if rec is None:
            return False

        key = self._phi_dropin_key(rec)

        if key in self.required_phi_dropin_ids:
            return True

        if key in self.non_suppressible_dropin_ids:
            return True

        if key in self.abi_entry_must_print_dropin_ids:
            return True

        source_sid = rec.get("source_sid")
        if source_sid in self.executable_dropin_source_sids:
            return True

        if (
            rec.get("required")
            or rec.get("non_suppressible")
            or rec.get("executable")
            or rec.get("must_print_override")
        ):
            return True

        return False

    def _should_skip_alias_backed_phi_dropin(self, rec):
        """
        Avoid double-emitting value-selector PHIs.

        PHIfolder v7 may resolve a selector PHI by renaming one-shot source
        definitions to the PHI target through var_map. Example:

            MULTIEQUAL [v_2697, v_2690] -> v_5848

        becomes normal block output:

            v_5848 = transform_b(local_2c)
            v_5848 = transform_a(local_24)

        The PHI drop-in records remain useful as metadata, but printing them
        as well duplicates the same assignment/call. Therefore, when the
        source SID is aliased to the target name, the drop-in is skipped.
        """

        if rec is None:
            return False

        key = self._phi_dropin_key(rec)
        if (
            rec.get("must_print_override")
            or key in self.abi_entry_must_print_dropin_ids
        ):
            return False

        # v19f: source/state aliases are stronger than required flags because
        # the source op has already emitted the transition under target name.
        if self._dropin_accounted_for_by_source_alias(rec):
            return True

        # v19d: required executable drop-ins must not be skipped merely as
        # value-selector presentation aliases.
        if key in self.required_phi_dropin_ids or key in self.non_suppressible_dropin_ids:
            return False

        source_sid = rec.get("source_sid")
        if source_sid in self.executable_dropin_source_sids:
            return False

        if not rec.get("target_is_value_selector_phi", False):
            return False

        source_sid = rec.get("source_sid")
        target_sid = rec.get("target_sid")
        target_name = rec.get("target_name") or self._var(rec.get("target"))

        if source_sid is None or target_sid is None:
            return False

        if source_sid in self.temp_phi_source_alias_sids:
            return True

        if source_sid in self.temp_phi_source_aliases:
            return True

        if self.var_map.get(source_sid) == target_name:
            return True

        alias_info = self.temp_phi_source_aliases.get(source_sid)
        if isinstance(alias_info, dict):
            if alias_info.get("target_sid") == target_sid:
                return True
            if alias_info.get("target_name") == target_name:
                return True

        return False


    def _phi_source_expr(self, source, source_node=None):
        """
        Render PHI source for assignment to local target.

        Fold pure bridge formulas and explicitly foldable one-shot calls.
        Keep materialized reused calls as variables.
        """

        node = source_node

        if node is None:
            node = self._node_for(source)

        if node is None:
            return self._expr(source)

        sid = self._sid_of(node)
        opcode = getattr(node, "opcode", None)

        if opcode == "MULTIEQUAL":
            return self._var(getattr(node, "var", source))

        if opcode in ("CALL", "CALLIND"):
            if sid in self.phi_source_foldable_sids or sid in self.inline_only_sids:
                return self._call_expr_from_node(node)
            return self._var(getattr(node, "var", source))

        if sid in self.materialize_sids and sid not in self.executable_dropin_source_sids:
            return self._var(getattr(node, "var", source))

        # v19d: executable drop-in sources are the path-local value to assign
        # into the PHI target.  Render the formula unless it is a call result
        # that must remain materialized.
        if sid in self.executable_dropin_source_sids and opcode not in ("CALL", "CALLIND"):
            return self._expr_from_node(node)

        # Pure bridge or preferred formula source.
        if sid in self.inline_only_sids or sid in self.phi_source_foldable_sids:
            return self._expr_from_node(node)

        pref = self.preferred_expr_by_sid.get(sid)
        if isinstance(pref, dict):
            if pref.get("mode") == "formula":
                return self._expr_from_node(node)
            if pref.get("mode") == "var":
                return self._var(getattr(node, "var", source))

        return self._expr_from_node(node)

    def _call_expr_from_node(self, node):

        if node is None:
            return "call_unknown()"

        abi_expr = self._abi_call_expr_from_op_v46(node)
        if abi_expr is not None:
            if self._abi_call_is_no_return_v46(node):
                return abi_expr
            contract = self._c_truth_plan_for_node(node)
            return self._c_truth_normalize_call_expr(
                contract, abi_expr, "inline_call_result"
            )

        inputs = list(getattr(node, "inputs", []) or [])

        if not inputs:
            return "call_unknown()"

        name = self._call_name(inputs[0])
        args = ", ".join(
            self._readable_call_argument_expr_v46i(i)
            for i in inputs[1:]
        )
        expr = "%s(%s)" % (name, args)
        contract = self._c_truth_plan_for_node(node)
        return self._c_truth_normalize_call_expr(contract, expr, "inline_call_result")

    # =========================================================
    # OP EMISSION
    # =========================================================

    def _emit_assignment(
        self, lhs, expr, custody_sid=None, provenance=None
    ):
        lhs = str(lhs).strip()
        expr = str(expr).strip()
        if self._last_assignment == (lhs, expr):
            return
        if expr == lhs:
            return
        rendered_expr = self._custody_wrap_assignment_expr_v45(
            lhs, expr, sid=custody_sid
        )
        self._w("%s = %s" % (lhs, rendered_expr), provenance=provenance)
        self._last_assignment = (lhs, expr)

        # v40: any real assignment invalidates the previous linear expression
        # reuse candidate.  Specific op-emission paths may immediately record
        # a new safe candidate after this call.
        self._last_value_expr_alias = None

    def _record_materialized_runtime_value_v41(self, out, opcode=None):
        """
        Remember that an SSA value was emitted as a concrete assignment and may
        safely be referenced by name in later expressions in the same structured
        stream.

        This is intentionally narrow: it protects materialized LOAD/CALL-like
        or explicitly printed payload temps from being re-expanded after their
        assignment has already executed.  It does not change PHI ownership or
        force any new assignment to appear.
        """
        sid = self._sid_of(out)
        if sid is None:
            return
        self.materialized_runtime_value_sids.add(sid)
        self.materialized_runtime_value_sids.add(str(sid))

    def _is_materialized_runtime_value_v41(self, x):
        sid = self._sid_of(x)
        return sid is not None and (sid in self.materialized_runtime_value_sids or str(sid) in self.materialized_runtime_value_sids)

    def _is_materialized_condition_reuse_candidate_v40(self, out, opcode, expr):
        """
        True when an emitted assignment may be reused by the immediately
        following condition as a textual CSE alias.

        Example:
            v_1041 = ((local_28 + local_2c) % 0xa)
            if ((local_28 + local_2c) % 0xa) != 7:

        may render as:
            if v_1041 != 7:

        This is deliberately emitter-local and presentation-only.  It does not
        change PHI/drop-in ownership; v_1041 may still be copied to local_28 in
        path-local tails.
        """
        if out is None or not expr:
            return False

        sid = self._sid_of(out)
        if sid is None:
            return False

        if self._is_stack_local_var(out):
            return False

        lhs_name = self._var(out)
        if not str(lhs_name).startswith("v_"):
            return False

        if str(lhs_name) in str(expr):
            return False

        if opcode in ("CALL", "CALLIND", "LOAD", "STORE", "MULTIEQUAL", "INDIRECT", "CBRANCH", "BRANCH", "BRANCHIND", "RETURN"):
            return False

        if sid in self.condition_temp_def_sids or str(sid) in self.condition_temp_def_sids:
            return False
        if sid in self.required_call_result_sids or str(sid) in self.required_call_result_sids:
            return False
        if sid in self.protected_condition_value_sids or str(sid) in self.protected_condition_value_sids:
            return False
        if sid in self.protected_copy_temp_sids or str(sid) in self.protected_copy_temp_sids:
            return False
        if sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()):
            return False
        if sid in self.post_update_alias_sids or str(sid) in self.post_update_alias_sids:
            return False
        if sid in self.state_transition_alias_sids or str(sid) in self.state_transition_alias_sids:
            return False
        if sid in self.phi_source_alias_sids or str(sid) in self.phi_source_alias_sids:
            return False

        # Side-effect-free expression classes only.  Materialized status is
        # allowed here because the temp has just been emitted as a real value.
        if opcode in _BINARY or opcode in _UNARY or opcode in _TRANSPARENT or opcode in ("PIECE", "SUBPIECE", "CONST"):
            return True

        return False

    def _record_last_value_expr_alias_v40(self, out, lhs, expr, opcode=None):
        if not self._is_materialized_condition_reuse_candidate_v40(out, opcode, expr):
            return

        sid = self._sid_of(out)
        rec = {
            "sid": sid,
            "lhs": str(lhs).strip(),
            "expr": str(expr).strip(),
            "block_addr": getattr(self, "_current_block_addr", None),
            "opcode": opcode,
        }
        self._last_value_expr_alias = rec
        try:
            self._event("v40 materialized condition alias: %s := %s" % (rec["lhs"], rec["expr"]))
        except Exception:
            pass

    def _apply_last_value_expr_alias_v40(self, s):
        if not s:
            return s

        rec = getattr(self, "_last_value_expr_alias", None)
        if not isinstance(rec, dict):
            return s

        expr = rec.get("expr")
        lhs = rec.get("lhs")
        if not expr or not lhs:
            return s

        before = str(s)
        after = self._replace_exact_expr_occurrences(before, expr, lhs)
        if after != before:
            try:
                self._event("v40 condition reused materialized expr: %s -> %s" % (expr, lhs))
            except Exception:
                pass
        return after

    def _last_assignment_matches(self, lhs, expr):
        if not self._last_assignment:
            return False
        return self._last_assignment == (str(lhs).strip(), str(expr).strip())

    def _emit_op(self, op):

        if op is None:
            return
        context = self._provenance_op_context(op, role="normal_op")
        with self._provenance_scope(**context):
            return self._emit_op_body(op)

    def _emit_op_body(self, op):

        if op is None:
            return

        oc = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        ins = list(getattr(op, "inputs", []) or [])

        if oc is None:
            return

        # INDIRECT is Ghidra SSA custody scaffolding, not a runtime operation.
        # Consume its owner/family contract before any legacy expression path
        # can render ``indirect(...)``.
        if oc == "INDIRECT":
            op_key = self._op_key(op)
            occurrence_ops = getattr(self, "_current_block_occurrence_ops", None)
            if occurrence_ops is not None:
                if op_key in occurrence_ops:
                    return
            elif op_key in self.emitted_ops:
                return
            self._custody_consume_indirect_op_v45(op)
            self._mark_op_emitted(op_key)
            return

        if oc in _SKIP_OPS:
            return

        if oc in ("CBRANCH", "BRANCH", "BRANCHIND"):
            return

        if oc == "RETURN":
            return_addr = getattr(self, "_current_block_addr", None)
            if self._abi_return_is_suppressed_v46(return_addr):
                self._abi_record_return_suppression_v46(return_addr)
                return
            if ins:
                expr = self._return_expr(ins[-1])
                abi_expr = self._abi_return_expr_v46(return_addr, expr)
                expr = (
                    abi_expr if abi_expr is not None
                    else self._c_truth_return_value_expr(ins[-1], expr)
                )
                self._w(
                    "return %s" % expr,
                    provenance={
                        "role": "return",
                        "use_sids": self._provenance_sid_list([ins[-1]]),
                        "metadata_refs": [
                            "abi:return_reconciliation", "abi:entry_plan"
                        ] if self.abi_active else [],
                    },
                )
            else:
                self._w(
                    "return",
                    provenance={
                        "role": "return",
                        "metadata_refs": [
                            "abi:return_reconciliation", "abi:entry_plan"
                        ] if self.abi_active else [],
                    },
                )
            return

        op_key = self._op_key(op)

        occurrence_ops = getattr(self, "_current_block_occurrence_ops", None)

        if occurrence_ops is not None:
            if op_key in occurrence_ops:
                return
        else:
            if op_key in self.emitted_ops:
                return

        # v46l: the resolver/compute sidecar may have already materialized
        # this exact parameter-to-local COPY in the function preamble.  The
        # live op, when it survives SGL, is then bookkeeping only.
        if self._custody_parameter_initializer_op_materialized_v46l(op):
            self._mark_op_emitted(op_key)
            return

        # Condition compare expressions are rendered by _cond().
        if out is not None and self._is_condition_var(out):
            if self._is_pure_condition_op(oc):
                self._mark_op_emitted(op_key)
                return

        old_current_expr_op = getattr(self, "_current_expr_op", None)
        old_current_expr_block_addr = getattr(self, "_current_expr_block_addr", None)
        self._current_expr_op = op
        self._current_expr_block_addr = getattr(self, "_current_block_addr", None)

        # Branch-closure driven target assignment.  If this op defines a temp
        # that immediately feeds a PHI/drop-in target for this block occurrence,
        # print the defining expression directly into the target local and
        # remember temp -> target for later conditions in the same structured
        # path.
        closure_lhs = None
        closure_rec = None
        if out is not None:
            closure_lhs, closure_rec = self._branch_closure_target_for_output(out)

        if oc in ("CALL", "CALLIND"):
            if self._abi_call_is_no_return_v46(op):
                self._mark_op_emitted(op_key)
                self._emit_call(op)
                return
            if closure_lhs:
                call_expr = self._call_expr_from_op(op)
                self._mark_op_emitted(op_key)
                self._emit_assignment(
                    closure_lhs,
                    call_expr,
                    custody_sid=self._sid_of(closure_rec.get("target")),
                    provenance=self._abi_call_provenance_v46(op),
                )
                self._record_dynamic_value_alias(self._sid_of(out), closure_lhs)
                self._register_assignment_rewrite(closure_rec.get("target"), out, self._node_for(out), closure_lhs, call_expr, op=op)
                self._custody_note_effect_owner_emitted_v45(op)
                return
            if (
                self._should_suppress_assignment(op)
                and not self._custody_effects_owned_by_op_v45(op)
            ):
                self._mark_op_emitted(op_key)
                return
            self._mark_op_emitted(op_key)
            self._emit_call(op)
            return

        if out is None:
            c_truth_expr = self._c_truth_expr_for_op(
                op, ins, context="outputless_op"
            )
            self._mark_op_emitted(op_key)
            if c_truth_expr:
                self._w(c_truth_expr)
                self._last_assignment = None
                self._custody_note_effect_owner_emitted_v45(op)
            return

        if closure_lhs:
            expr = self._expr_from_op(oc, ins, current_op=op)
            self._mark_op_emitted(op_key)
            abi_storage_initializer = (
                self._abi_entry_storage_initializer_contract_v46b(op)
                if not self._is_readable_render_v44() else None
            )
            expr = self._abi_entry_storage_initializer_expr_v46c(
                abi_storage_initializer, expr
            )
            before_line_count = len(self.lines)
            self._emit_assignment(
                closure_lhs,
                expr,
                custody_sid=self._sid_of(closure_rec.get("target")),
                provenance={
                    "role": "abi_entry_storage_initializer",
                    "metadata_refs": [
                        "abi:entry_storage:%s" % str(
                            abi_storage_initializer.get("op_key")
                        )
                    ],
                } if abi_storage_initializer else None,
            )
            if abi_storage_initializer and len(self.lines) > before_line_count:
                self._abi_note_entry_storage_initializer_v46b(
                    op, self.lines[-1].strip()
                )
            self._record_dynamic_value_alias(self._sid_of(out), closure_lhs)
            self._register_assignment_rewrite(closure_rec.get("target"), out, self._node_for(out), closure_lhs, expr, op=op)
            return

        if self._should_suppress_assignment(op):
            self._mark_op_emitted(op_key)
            return

        if oc in _TRANSPARENT and ins:
            sid = self._sid_of(out)
            fixed_argument_local_initializer = (
                self._abi_fixed_argument_local_initializer_contract_v46k(
                    op
                )
            )
            parameter_initializer = (
                self._custody_parameter_initializer_for_op_v45(op)
            )
            if (
                not fixed_argument_local_initializer
                and not parameter_initializer
                and not (
                    sid in getattr(self, "snapshot_copy_temp_sids", set())
                    or str(sid) in getattr(
                        self, "snapshot_copy_temp_sids", set()
                    )
                )
            ):
                if self._can_suppress_transparent_assign(out, ins[0]):
                    self._mark_op_emitted(op_key)
                    return

        # Use compound assignment only for real materialized target outputs.
        if self._try_emit_compound_assignment(op):
            self._mark_op_emitted(op_key)
            return

        expr = self._expr_from_op(oc, ins, current_op=op)

        self._mark_op_emitted(op_key)
        fixed_argument_local_initializer = (
            self._abi_fixed_argument_local_initializer_contract_v46k(
                op
            )
        )
        lhs = self._abi_fixed_argument_local_initializer_lhs_v46k(
            fixed_argument_local_initializer,
            self._var(out),
        )
        abi_storage_initializer = (
            self._abi_entry_storage_initializer_contract_v46b(op)
            if not self._is_readable_render_v44() else None
        )
        expr = self._abi_entry_storage_initializer_expr_v46c(
            abi_storage_initializer, expr
        )
        before_line_count = len(self.lines)
        self._emit_assignment(
            lhs,
            expr,
            custody_sid=self._sid_of(out),
            provenance=(
                {
                    "role": "abi_entry_storage_initializer",
                    "metadata_refs": [
                        "abi:entry_storage:%s" % str(
                            abi_storage_initializer.get("op_key")
                        )
                    ],
                }
                if abi_storage_initializer
                else (
                    {
                        "role": (
                            "abi_fixed_argument_local_initializer"
                        ),
                        "metadata_refs": [
                            "abi:fixed_argument_local:%s" % str(
                                fixed_argument_local_initializer.get(
                                    "op_key"
                                )
                            )
                        ],
                    }
                    if fixed_argument_local_initializer
                    else None
                )
            ),
        )
        if abi_storage_initializer and len(self.lines) > before_line_count:
            self._abi_note_entry_storage_initializer_v46b(
                op, self.lines[-1].strip()
            )
        if (
            fixed_argument_local_initializer
            and len(self.lines) > before_line_count
        ):
            self._abi_note_fixed_argument_local_initializer_v46k(
                op,
                self.lines[-1].strip(),
            )
        self._custody_note_parameter_initializer_emitted_v45(op, lhs)
        self._record_materialized_runtime_value_v41(out, opcode=oc)
        self._record_last_value_expr_alias_v40(out, lhs, expr, opcode=oc)
        src = ins[0] if len(ins) == 1 else None
        self._register_assignment_rewrite(out, src, self._node_for(src), lhs, expr, op=op)

    def _mark_op_emitted(self, op_key):
        if op_key is None:
            return

        occurrence_ops = getattr(self, "_current_block_occurrence_ops", None)

        if occurrence_ops is not None:
            occurrence_ops.add(op_key)

        self.emitted_ops.add(op_key)

    def _op_key(self, op):

        if op is None:
            return None

        op_id = getattr(op, "op_id", None)

        if op_id is not None:
            return ("op_id", op_id)

        return ("id", id(op))

    # ---------------------------------------------------------
    # PRESENTATION / SUPPRESSION HELPERS
    # ---------------------------------------------------------

    def _sid_of(self, x):

        if x is None:
            return None

        if isinstance(x, str):
            return x

        if hasattr(x, "var"):
            return getattr(x.var, "ssa_id", None)

        return getattr(x, "ssa_id", None)

    def _op_output_sid(self, op):

        return self._sid_of(getattr(op, "output", None))

    def _is_stack_local_var(self, v):

        if v is None:
            return False

        if hasattr(v, "var"):
            v = v.var

        return bool(getattr(v, "is_stack", False) or getattr(v, "space", None) == "stack")

    def _is_local_initializer(self, op):
        """
        Protect entry-style local initializers:
            local_1c = 0
            local_18 = 0

        Folder may mark COPY const bridges as suppressible, but stack-local
        initializers must remain visible.
        """

        if op is None:
            return False

        oc = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        ins = list(getattr(op, "inputs", []) or [])

        if oc != "COPY":
            return False

        if not self._is_stack_local_var(out):
            return False

        if not ins:
            return False

        return bool(getattr(ins[0], "is_constant", False))

    # =========================================================
    # PHIFOLDER PRESENTATION POLICY
    # =========================================================

    def _policy_for_sid(self, sid):
        if sid is None:
            return {}
        return dict(self.ssa_policy_by_sid.get(sid, {}) or {})

    def _policy_emit_assignment(self, sid):
        if sid is None:
            return True

        policy = self._policy_for_sid(sid)
        if policy:
            return bool(policy.get("emit", True))

        # Compatibility fallback for older PHIfolder outputs.
        if sid in self.suppress_assign_sids and sid not in self.materialize_sids:
            return False

        return True

    def _policy_expr_mode(self, sid):
        policy = self._policy_for_sid(sid)
        if policy:
            return policy.get("expr_mode")
        if sid in self.inline_only_sids:
            return "inline"
        return "var"

    def _pretty_parens(self, s):
        if s is None:
            return s

        s = str(s).strip()

        changed = True
        while changed:
            changed = False
            if len(s) >= 4 and s.startswith("((") and s.endswith("))"):
                inner = s[1:-1]
                if self._balanced_parens(inner):
                    s = inner
                    changed = True

        return s

    def _balanced_parens(self, s):
        depth = 0
        for ch in str(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return False
        return depth == 0

    def _is_sgl_raw_condition(self, cond_var):
        """
        True for RawCond-style objects created by SGL v18e/v19.

        They usually expose a string const_value and optional polarity reason.
        Treat them as already-oriented predicates.
        """
        if cond_var is None:
            return False

        reason = getattr(cond_var, "reason", None)
        if reason:
            return True

        if getattr(cond_var, "is_constant", False):
            cv = getattr(cond_var, "const_value", None)
            if isinstance(cv, str):
                # Numeric constants are not SGL predicates; expressions are.
                try:
                    int(cv, 0)
                    return False
                except Exception:
                    return True

        return False

    def _raw_condition_text(self, cond_var):
        """
        Return the literal predicate text carried by an SGL RawCond-like object.

        SGL owns branch-edge orientation.  When SGL builds a RawCond from PAL
        edge metadata, its text may intentionally include a leading NOT.  The
        emitter must treat that as semantic polarity, not as a prettification
        opportunity.
        """
        if cond_var is None:
            return None

        for attr in ("const_value", "value", "offset", "name"):
            val = getattr(cond_var, attr, None)
            if isinstance(val, str) and val.strip():
                return val.strip()

        return None

    def _sgl_raw_condition_preserve_not(self, cond_var):
        """
        True only for SGL RawCond predicates whose leading NOT is an explicit
        PAL metadata branch-mirror fact.

        v35 preserved every RawCond beginning with `not `.  That was too broad:
        ordinary loop-exit predicates and tail tests also arrive from SGL as
        RawCond strings beginning with NOT, and those should keep using the
        normal emitter cleanup path that can render `not (4 < x)` as `4 >= x`.

        Narrow generic rule:
            preserve a literal leading NOT only when SGL marks the condition
            reason as metadata_branch_mirror*.

        This keeps branch arm ownership in SGL and keeps presentation cleanup
        available for all non-mirror predicates.
        """
        if not self._is_sgl_raw_condition(cond_var):
            return False

        text = self._raw_condition_text(cond_var)
        if not text or not str(text).strip().startswith("not "):
            return False

        reason = str(getattr(cond_var, "reason", "") or "").lower()

        # Razor-thin trigger: only the SGL/PAL edge-truth mirror contract.
        # Do not include generic "inverted", "edge", "loop", or "latch"
        # reasons here, because those ordinary predicates should still pass
        # through _simplify_not_compare().
        return "metadata_branch_mirror" in reason

    def _cond_clean_preserve_sgl_not(self, expr):
        """
        Clean an SGL already-oriented RawCond without simplifying leading NOT.

        Keep the broad alias/metadata cleanup passes so temps such as v_4082 can
        still become local_18, and post-update expressions can still collapse to
        their committed local names.  Only the compare-inversion prettifier is
        skipped.
        """
        s = self._pretty_parens(expr)

        if s is None:
            return s

        s = str(s).strip()
        s = self._apply_transparent_expr_alias_rewrites(s)
        s = self._apply_abi_raw_alias_rewrites_v46(s)
        s = self._apply_metadata_post_update_aliases(s)
        s = self._apply_dynamic_value_alias_rewrites(s)
        s = self._apply_last_value_expr_alias_v40(s)
        s = self._apply_c_truth_raw_condition_rewrites(s)
        s = self._pretty_parens(s)
        return s

    def _struct_if_condition_text(self, cond_var):
        """
        Render an ExecIf predicate.

        Normal conditions use the existing cleaner.  Only SGL RawCond predicates
        explicitly tagged as metadata branch mirrors preserve a leading NOT.
        All other RawCond NOT predicates continue through ordinary cleanup.
        """
        if self._sgl_raw_condition_preserve_not(cond_var):
            text = self._raw_condition_text(cond_var)
            if text:
                self._event("preserve SGL metadata branch-mirror NOT: %s" % text)
                return self._cond_clean_preserve_sgl_not(text)

        return self._cond_clean(self._cond(cond_var))

    def _cond_clean(self, expr):
        s = self._pretty_parens(expr)

        if s is None:
            return s

        s = str(s).strip()
        if self.c_truth_active or self.custody_active:
            # Alias first so the textual predicate uses the same state names
            # as the contract index.  Replace numeric operations before the
            # legacy NOT/comparison prettifier can erase opcode identity.
            s = self._apply_transparent_expr_alias_rewrites(s)
            s = self._apply_abi_raw_alias_rewrites_v46(s)
            s = self._apply_metadata_post_update_aliases(s)
            s = self._apply_dynamic_value_alias_rewrites(s)
            s = self._apply_last_value_expr_alias_v40(s)
            s = self._apply_c_truth_raw_condition_rewrites(s)
            s = self._simplify_not_compare(s)
        else:
            s = self._simplify_not_compare(s)
            s = self._apply_transparent_expr_alias_rewrites(s)
            s = self._apply_abi_raw_alias_rewrites_v46(s)
            s = self._apply_metadata_post_update_aliases(s)
            s = self._apply_dynamic_value_alias_rewrites(s)
            s = self._apply_last_value_expr_alias_v40(s)
        s = self._pretty_parens(s)
        return s


    def _simplify_not_compare(self, s):
        if s is None:
            return s

        raw = str(s).strip()
        inner = raw

        if not inner.startswith("not "):
            return raw

        inner = inner[4:].strip()
        inner = self._strip_outer_parens(inner)

        # Try only simple binary comparisons.  Avoid boolean expressions
        # containing and/or, because De Morgan belongs in a later pretty pass.
        if " and " in inner or " or " in inner:
            return raw

        inv = {
            "==": "!=",
            "!=": "==",
            "<": ">=",
            ">": "<=",
            "<=": ">",
            ">=": "<",
        }

        for op in ("==", "!=", "<=", ">=", "<", ">"):
            parts = inner.split(op)
            if len(parts) == 2:
                a = parts[0].strip()
                b = parts[1].strip()
                if a and b:
                    return "%s %s %s" % (a, inv[op], b)

        return raw

    def _strip_outer_parens(self, s):
        s = str(s).strip()
        changed = True

        while changed and len(s) >= 2 and s[0] == "(" and s[-1] == ")":
            changed = False
            depth = 0
            ok = True

            for i, ch in enumerate(s):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and i != len(s) - 1:
                        ok = False
                        break

            if ok:
                s = s[1:-1].strip()
                changed = True

        return s


    def _register_assignment_rewrite(self, target, source, source_node=None, target_name=None, expr=None, op=None):
        """
        v21: no broad expression registration.

        Metadata closure is provided by PHIfolder.  The only runtime alias
        retained here is dynamic temp->target aliasing from branch closure.
        """

        return

    def _apply_metadata_post_update_aliases(self, s):
        if not s or not self.post_update_condition_aliases:
            return s

        out = str(s)
        records = []

        for rec in self.post_update_condition_aliases:
            source = rec.get("source_expr")
            target = rec.get("target_name")
            if not source or not target:
                continue
            if self._loop_header_must_keep_preupdate_expr_v42(rec):
                self._record_loop_condition_alias_guard_v42(rec)
                continue
            records.append((str(source), self._sanitize_name(str(target))))

        for source, target in sorted(set(records), key=lambda t: len(t[0]), reverse=True):
            out = self._replace_exact_expr_occurrences(out, source, target)

        return out

    def _loop_header_must_keep_preupdate_expr_v42(self, rec):
        """
        True when a post-update alias would change execution order in a
        structured Python ``while`` header.

        PAL/SGL may represent a source block like::

            next_j = j + 1
            if next_j < 3: body

        as a loop whose emitted body contains the update block and whose
        header predicate is ``(j + 1) < 3``.  A normal post-update alias may
        render ``next_j`` as committed state ``j`` *after that update has
        executed*.  Python evaluates ``while`` before the emitted body, so
        collapsing the header to ``j < 3`` executes one extra iteration.

        Keep the full source expression only when metadata identifies this
        condition as the current loop consumer and the update producer is
        owned by the emitted loop body.  Conditions outside loop headers and
        updates materialized before the header retain the existing alias rule.
        """

        loop_node = getattr(self, "_current_structured_loop_condition", None)
        if loop_node is None or not isinstance(rec, dict):
            return False

        consumer_kind = rec.get("consumer_kind")
        if consumer_kind not in (None, "loop"):
            return False

        header_addr = self._condition_consumer_addr(loop_node)
        consumer_addr = rec.get("consumer_addr")

        if header_addr is None:
            return False

        if consumer_addr is not None:
            if not (self._addr_variants(header_addr) & self._addr_variants(consumer_addr)):
                return False

        body = getattr(loop_node, "body", None)
        body_addrs = self._exec_tree_block_addrs(body)
        if not body_addrs:
            return False

        producer_addr = (
            rec.get("producer_addr")
            if rec.get("producer_addr") is not None
            else rec.get("source_addr")
        )

        if producer_addr is None:
            source_sid = rec.get("source_sid")
            source_node = self._node_for_sid_variants_v42(source_sid)
            producer_addr = self._node_block_addr_v37(source_node)

        if producer_addr is None:
            return False

        producer_variants = self._addr_variants(producer_addr)
        return any(producer_variants & self._addr_variants(addr) for addr in body_addrs)

    def _node_for_sid_variants_v42(self, sid):
        if sid is None:
            return None

        for key in self._sid_variants(sid):
            if key in self.nodes:
                return self.nodes.get(key)

        return None

    def _record_loop_condition_alias_guard_v42(self, rec):
        source_sid = rec.get("source_sid")
        producer_addr = rec.get("producer_addr") or rec.get("source_addr")
        if producer_addr is None:
            producer_addr = self._node_block_addr_v37(
                self._node_for_sid_variants_v42(source_sid)
            )

        event = {
            "kind": "loop_header_preupdate_expr_preserved_v42",
            "source_sid": source_sid,
            "source_expr": rec.get("source_expr"),
            "target_name": rec.get("target_name"),
            "producer_addr": producer_addr,
            "consumer_addr": rec.get("consumer_addr"),
            "consumer_role": rec.get("consumer_role"),
            "reason": "post_update_producer_executes_in_emitted_loop_body",
        }

        key = (
            event.get("source_sid"),
            event.get("source_expr"),
            event.get("target_name"),
            event.get("producer_addr"),
            event.get("consumer_addr"),
        )
        if key in self._loop_condition_alias_guard_event_keys:
            return

        self._loop_condition_alias_guard_event_keys.add(key)
        self.loop_condition_alias_guard_events.append(event)
        self._event(
            "loop header kept pre-update expression: %s -> %s at %s"
            % (event.get("source_expr"), event.get("target_name"), event.get("consumer_addr"))
        )

    def _replace_exact_expr_occurrences(self, text, expr, replacement):
        if not text or not expr or not replacement:
            return text

        out = str(text)
        for pat in self._expr_pattern_variants(expr):
            out = self._replace_token_safe(out, pat, replacement)
        return out

    def _expr_pattern_variants(self, expr):
        s = str(expr).strip()
        if not s:
            return []

        variants = []
        seen = set()

        def add(x):
            x = str(x).strip()
            if x and x not in seen:
                seen.add(x)
                variants.append(x)

        add(s)
        stripped = self._strip_outer_parens(s)
        add(stripped)
        add("(%s)" % stripped)
        add("((%s))" % stripped)
        add("(%s)" % s)
        return sorted(variants, key=len, reverse=True)

    def _replace_token_safe(self, text, pattern, replacement):
        if not pattern or pattern not in text:
            return text

        out = []
        i = 0
        n = len(pattern)

        while True:
            j = text.find(pattern, i)
            if j < 0:
                out.append(text[i:])
                break

            before = text[j - 1] if j > 0 else ""
            after = text[j + n] if j + n < len(text) else ""

            if self._safe_replacement_boundary(before, after):
                out.append(text[i:j])
                out.append(replacement)
                i = j + n
            else:
                out.append(text[i:j + n])
                i = j + n

        return "".join(out)

    def _safe_replacement_boundary(self, before, after):
        def wordish(ch):
            return bool(ch and (ch.isalnum() or ch == "_"))

        return not (wordish(before) or wordish(after))

    def _apply_dynamic_value_alias_rewrites(self, s):
        """
        Apply branch-closure temp aliases inside RawCond/string conditions.

        This is the v_1743 leak class:
            local_18 = mutate(...)
            if v_1743 == 0xf:   # stale temp in RawCond string

        Once branch closure has recorded v_1743 -> local_18, condition strings
        should render against the stable target representation.
        """

        if not s or not self.dynamic_value_alias_by_sid:
            return s

        out = str(s)

        # Normalize to textual v_N names; avoid replacing substrings inside
        # longer identifiers by using word boundaries.
        pairs = []

        for sid, target in list(self.dynamic_value_alias_by_sid.items()):
            if sid is None or not target:
                continue

            # Numeric SSA ids usually render as v_<sid>.  String keys may
            # already be "v_1743" or "1743".
            raw = str(sid)
            names = {raw}

            if raw.isdigit():
                names.add("v_%s" % raw)
            elif not raw.startswith("v_") and raw.replace("_", "").isdigit():
                names.add("v_%s" % raw)

            for name in names:
                if name and name != target:
                    pairs.append((name, str(target)))

        # Longest first protects v_1743-like names from partial rewrite.
        for name, target in sorted(set(pairs), key=lambda kv: len(kv[0]), reverse=True):
            out = re.sub(r"\b%s\b" % re.escape(name), target, out)

        return out


    def _is_real_stack_write_override_op(self, op):
        """
        Narrow suppressor override for executable writes into real stack locals.

        Suppressors stay active for SSA noise and transparent bridge temps.
        This override fires only when suppressing the op would delete a real
        program-state write.

        Protected classes:

            1. Snapshot/temp restore or local move:
                   local_M = v_N
                   local_M = local_N

               Example swap:
                   v_4658 = local_20
                   local_20 = local_1c
                   local_1c = v_4658

            2. Real local formula update:
                   local_O = <expr involving locals/temps/constants/calls>

        Rejected classes:
            local_X = local_X
            local_X = CAST(local_X)
            local_X = ZEXT(local_X)
            other transparent no-op/self bridges
        """

        if op is None:
            return False

        oc = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        ins = list(getattr(op, "inputs", []) or [])

        if out is None:
            return False

        if oc in ("MULTIEQUAL", "INDIRECT", "CBRANCH", "BRANCH", "BRANCHIND", "RETURN"):
            return False

        if not self._is_stack_local_var(out):
            return False

        # Initializers are real stack writes and are protected elsewhere too.
        if self._is_local_initializer(op):
            return True

        # No-op/self bridge: not a real state change.
        if len(ins) == 1 and self._same_logical_var(out, ins[0]):
            return False

        # Transparent bridge into the same logical local is not a real write.
        if oc in ("CAST", "INT_ZEXT", "INT_SEXT", "TRUNC", "SUBPIECE") and len(ins) >= 1:
            if self._same_logical_var(out, ins[0]):
                return False

        # Case 1: direct move into a stack local.
        if oc == "COPY" and len(ins) == 1:
            src = ins[0]
            src_sid = self._sid_of(src)

            # local_M = local_N, with M != N by no-op guard above.
            if self._is_stack_local_var(src):
                return True

            # local_M = protected snapshot temp.
            if (
                src_sid in getattr(self, "snapshot_copy_temp_sids", set())
                or str(src_sid) in getattr(self, "snapshot_copy_temp_sids", set())
                or src_sid in getattr(self, "protected_copy_temp_sids", set())
                or str(src_sid) in getattr(self, "protected_copy_temp_sids", set())
            ):
                return True

            # local_M = non-stack temp is a real write unless it is a known
            # transparent bridge that resolves to local_M itself.
            alias = self._transparent_expr_alias_for_sid(src_sid)
            if alias and alias == self._var(out):
                return False

            return True

        # Case 2: formula/call/load into a real stack local.
        if oc in _BINARY or oc in _UNARY:
            return True

        if oc in ("CALL", "CALLIND", "LOAD"):
            return True

        # Conservative fallback for any non-transparent op writing local state.
        if oc not in _TRANSPARENT:
            return True

        return False

    # Backward-compatible name for any older internal call sites.
    def _is_concrete_stack_local_write_op(self, op):
        return self._is_real_stack_write_override_op(op)




    def _should_suppress_assignment(self, op):

        out = getattr(op, "output", None)
        sid = self._sid_of(out)

        if sid is None:
            return False

        # v46k: a fixed ABI argument copied into distinct local stack state
        # is executable initialization even when Ghidra merges both values
        # into one HighVariable family.
        if self._abi_fixed_argument_local_initializer_contract_v46k(
            op
        ):
            return False

        # v46b executable-only must-print: an entry GP carrier copied into a
        # memory-backed stack family initializes the SysV variadic register
        # save area.  Same-HighVariable identity does not authorize deleting
        # this memory effect.
        if (
            not self._is_readable_render_v44()
            and self._abi_entry_storage_initializer_contract_v46b(op)
        ):
            return False
        if (
            not self._is_readable_render_v44()
            and self._op_key(op)
            in self.abi_entry_storage_initializer_rejections
        ):
            return False

        # v45b: parameter -> address-tied storage COPYs establish the initial
        # contents of escaped C locals.  Resolver/Compute provenance is the
        # authority; apparent SSA/parameter equivalence must not erase them.
        if self._custody_parameter_initializer_for_op_v45(op):
            return False

        # v19g: source/state aliases are executable source ops whose LHS is
        # renamed to the PHI target.  They must emit as the target assignment,
        # not as pre-collapse SSA fragments and not as suppressed ghosts.
        if sid in self.state_transition_alias_sids or sid in self.phi_source_alias_sids:
            return False

        # v34: SGL-declared latch/update epilogue source ops are executable
        # state transitions.  They may also be present in post_update_alias_sids
        # because later conditions should render their SSA value as the target
        # variable.  Do not let that presentation alias suppress the actual
        # iterator/state update at a duplicated loop epilogue occurrence.
        if self._is_sgl_latch_epilogue_override_op(op):
            return False

        # A post-update alias that is *not* backed by a source/state alias is
        # presentation-only.  If it is backed by a source/state alias, the
        # previous rule has already kept it visible under the target name.
        if sid in self.post_update_alias_sids:
            return True

        if sid in self.condition_temp_def_sids:
            return False

        if sid in self.required_call_result_sids:
            return False
        if sid in self.protected_condition_value_sids:
            return False
        if sid in self.protected_copy_temp_sids:
            return False
        if sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()):
            return False
        if sid in self.executable_dropin_source_sids:
            return False

        # Never hide local initializers.
        if self._is_local_initializer(op):
            return False

        # v32: keep normal suppressors, but override them for narrow classes of
        # real executable writes into stack locals.  This protects swap/restores
        # and local formula updates without turning off SSA-noise suppression.
        if self._is_real_stack_write_override_op(op):
            return False

        # PHIfolder v18d+/v19: post-update bridge temps are aliases of an
        # already materialized state update and must not print as standalone:
        #     v_367 = local_14 + 1
        if sid in self.post_update_alias_sids:
            return True

        # PHIfolder v8 owns presentation decisions.
        if self.ssa_policy_by_sid:
            return not self._policy_emit_assignment(sid)

        # Compatibility fallback.
        if sid in self.materialize_sids:
            return False

        if sid in self.suppress_assign_sids:
            return True

        return False

    # ---------------------------------------------------------
    # CALLS
    # ---------------------------------------------------------

    def _call_expr_from_op(self, op):
        abi_expr = self._abi_call_expr_from_op_v46(op)
        if abi_expr is not None:
            if self.c_truth_active and not self._abi_call_is_no_return_v46(op):
                contract = self._c_truth_plan_for_op(op)
                abi_expr = self._c_truth_normalize_call_expr(
                    contract, abi_expr, "call_result"
                )
            return abi_expr

        ins = list(getattr(op, "inputs", []) or [])
        if not ins:
            return "call_unknown()"
        name = self._call_name(ins[0])
        args = ", ".join(
            self._readable_call_argument_expr_v46i(x)
            for x in ins[1:]
        )
        expr = "%s(%s)" % (name, args)

        if self.c_truth_active:
            contract = self._c_truth_plan_for_op(op)
            expr = self._c_truth_normalize_call_expr(contract, expr, "call_result")

        return expr

    def _emit_call(self, op):

        out = getattr(op, "output", None)
        call_expr = self._call_expr_from_op(op)
        provenance = self._abi_call_provenance_v46(op)

        if self._abi_call_is_no_return_v46(op):
            self._w(call_expr, provenance=provenance)
            self._last_assignment = None
            self._custody_note_effect_owner_emitted_v45(op)
            return

        if out is not None:
            self._emit_assignment(
                self._var(out), call_expr, custody_sid=self._sid_of(out),
                provenance=provenance,
            )
            self._record_materialized_runtime_value_v41(out, opcode=getattr(op, "opcode", None))
        else:
            self._w(call_expr, provenance=provenance)
            self._last_assignment = None
        self._custody_note_effect_owner_emitted_v45(op)

    # ---------------------------------------------------------
    # COMPOUND ASSIGNMENT
    # ---------------------------------------------------------

    def _try_emit_compound_assignment(self, op):

        oc = getattr(op, "opcode", None)
        out = getattr(op, "output", None)
        ins = list(getattr(op, "inputs", []) or [])

        if out is None or len(ins) != 2:
            return False

        # A storage-family write must pass through the executable c_store
        # wrapper in _emit_assignment().  A Python augmented assignment would
        # mutate only the presentation local and sever memory custody.
        descriptor = self._custody_descriptor_for_sid_v45(self._sid_of(out))
        if isinstance(descriptor, dict) and descriptor.get("memory_backed"):
            return False

        if self.c_truth_active:
            plan = self._c_truth_plan_for_op(op)
            if isinstance(plan, dict) and (
                plan.get("runtime_helper")
                or plan.get("normalize_result_to_output_width")
            ):
                return False

        if oc not in ("INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR"):
            return False

        # Avoid producing nonsense like v_996 &= 2 for hidden/internal temps.
        # Compound assignment is only safe for real mutable lvalues.  SSA temps
        # such as v_479 = v_451 + 0x1f must remain ordinary assignments, even
        # if alias metadata makes the input look logically related.
        sid = self._sid_of(out)
        if not (self._is_stack_local_var(out) or bool(getattr(out, "is_global", False))):
            return False
        if sid in self.inline_only_sids or sid in self.suppress_assign_sids:
            return False

        lhs = self._var(out)

        a = ins[0]
        b = ins[1]

        av = self._expr_rvalue_v37(a, oc, 0)
        bv = self._expr_rvalue_v37(b, oc, 1)

        if self._same_logical_var(out, a):

            if oc == "INT_ADD":
                if self._is_negative_int_literal(bv):
                    self._w("%s -= %s" % (lhs, self._abs_negative_literal(bv)))
                else:
                    self._w("%s += %s" % (lhs, bv))
                return True

            if oc == "INT_SUB":
                if self._is_negative_int_literal(bv):
                    self._w("%s += %s" % (lhs, self._abs_negative_literal(bv)))
                else:
                    self._w("%s -= %s" % (lhs, bv))
                return True

            if oc == "INT_MULT":
                self._w("%s *= %s" % (lhs, bv))
                return True

            if oc == "INT_AND":
                self._w("%s &= %s" % (lhs, bv))
                return True

            if oc == "INT_OR":
                self._w("%s |= %s" % (lhs, bv))
                return True

            if oc == "INT_XOR":
                self._w("%s ^= %s" % (lhs, bv))
                return True

        if oc in _COMMUTATIVE and self._same_logical_var(out, b):

            if oc == "INT_ADD":
                if self._is_negative_int_literal(av):
                    self._w("%s -= %s" % (lhs, self._abs_negative_literal(av)))
                else:
                    self._w("%s += %s" % (lhs, av))
                return True

            if oc == "INT_MULT":
                self._w("%s *= %s" % (lhs, av))
                return True

            if oc == "INT_AND":
                self._w("%s &= %s" % (lhs, av))
                return True

            if oc == "INT_OR":
                self._w("%s |= %s" % (lhs, av))
                return True

            if oc == "INT_XOR":
                self._w("%s ^= %s" % (lhs, av))
                return True

        return False

    # =========================================================
    # EXPRESSIONS
    # =========================================================

    # ---------------------------------------------------------
    # v37 RHS formula recovery / signed literal helpers
    # ---------------------------------------------------------

    def _const_int_value(self, v):
        if v is None:
            return None
        if hasattr(v, "var"):
            v = v.var
        for attr in ("const_value", "value", "offset", "address"):
            val = getattr(v, attr, None)
            if isinstance(val, int):
                return val
        return None

    def _width_bits_for_value(self, v, fallback=32):
        if v is None:
            return fallback
        if hasattr(v, "var"):
            v = v.var
        for attr in ("width_bits", "bit_length"):
            val = getattr(v, attr, None)
            if isinstance(val, int) and val > 0:
                return val
        size = getattr(v, "size", None) or getattr(v, "width_bytes", None)
        if isinstance(size, int) and size > 0:
            return size * 8
        val = self._const_int_value(v)
        if isinstance(val, int) and val > 0xffffffff:
            return 64
        return fallback

    def _signed_int_value_for_const(self, v, width_bits=None):
        val = self._const_int_value(v)
        if val is None:
            return None
        width = width_bits or self._width_bits_for_value(v, 32)
        try:
            width = int(width)
        except Exception:
            width = 32
        if width <= 0:
            width = 32
        mask = (1 << width) - 1
        sval = int(val) & mask
        sign = 1 << (width - 1)
        if sval & sign:
            return sval - (1 << width)
        return sval

    def _const_for_context(self, v, parent_opcode=None, operand_index=None):
        """
        Render constants using signed interpretation only in contexts where C
        integer semantics require it.  This fixes executable-Python cases like:
            0xffffffff < local_20      -> -1 < local_20
            local_1c + 0xfffffffe      -> local_1c - 2
        while preserving masks in bitwise contexts such as 0xff and 0x1f.
        """
        if v is None:
            return "None"

        opcode = str(parent_opcode or "")
        val = self._const_int_value(v)
        if val is None:
            return self._const(v)

        signed_context = opcode in (
            "INT_SLESS", "INT_SLESSEQUAL", "INT_SDIV", "INT_SREM",
        )
        arithmetic_delta_context = opcode in ("INT_ADD", "INT_SUB")

        if signed_context or arithmetic_delta_context:
            sval = self._signed_int_value_for_const(v)
            if isinstance(sval, int) and sval < 0:
                return str(sval)

        return self._const(v)

    def _is_negative_int_literal(self, s):
        try:
            return str(s).strip().startswith("-") and int(str(s).strip(), 0) < 0
        except Exception:
            return False

    def _abs_negative_literal(self, s):
        try:
            return str(abs(int(str(s).strip(), 0)))
        except Exception:
            return str(s).strip().lstrip("-")

    def _format_binary_expr_v37(self, opcode, a, b):
        op = _BINARY.get(opcode)
        if op is None:
            return "%s(%s, %s)" % (str(opcode).lower(), a, b)

        if op.startswith("<"):
            return "%s(%s, %s)" % (str(opcode).lower(), a, b)

        # Render negative additive constants as subtraction/addition so Python
        # code preserves C signed intent without helper wrapping.
        if opcode == "INT_ADD":
            if self._is_negative_int_literal(b):
                return "(%s - %s)" % (a, self._abs_negative_literal(b))
            if self._is_negative_int_literal(a):
                return "(%s - %s)" % (b, self._abs_negative_literal(a))

        if opcode == "INT_SUB" and self._is_negative_int_literal(b):
            return "(%s + %s)" % (a, self._abs_negative_literal(b))

        return "(%s %s %s)" % (a, op, b)

    def _node_block_addr_v37(self, node):
        if node is None:
            return None
        for attr in ("block_addr", "addr"):
            val = getattr(node, attr, None)
            if isinstance(val, int):
                return val
        block = getattr(node, "block", None) or getattr(node, "block_region", None)
        if block is not None:
            val = getattr(block, "addr", None)
            if isinstance(val, int):
                return val
        return None

    def _is_safe_rvalue_transparent_bridge_v39(self, node):
        """
        True for non-state transparent bridge temps that may be peeled in RHS
        expression context.

        This is narrower than ordinary transparent aliasing.  It refuses stack
        local outputs and protected snapshot/materialized/state temps, then lets
        _expr_rvalue_v37 continue on the bridge source so a chain like:
            v_6665 -> v_475 -> (local_28 + local_2c)
        becomes the formula, not the literal alias string v_475.
        """
        if node is None:
            return False

        opcode = getattr(node, "opcode", None)
        if opcode not in _TRANSPARENT and opcode != "SUBPIECE":
            return False

        if self._c_truth_contract_for_sid_has_helper(self._sid_of(getattr(node, "var", None))):
            return False

        inputs = list(getattr(node, "inputs", []) or [])
        if not inputs:
            return False

        var = getattr(node, "var", None)
        sid = self._sid_of(var)

        if sid is None:
            return False
        if self._is_stack_local_var(var):
            return False
        if sid in self.materialize_sids or str(sid) in self.materialize_sids:
            return False
        if sid in self.condition_temp_def_sids or str(sid) in self.condition_temp_def_sids:
            return False
        if sid in self.required_call_result_sids or str(sid) in self.required_call_result_sids:
            return False
        if sid in self.protected_condition_value_sids or str(sid) in self.protected_condition_value_sids:
            return False
        if sid in self.protected_copy_temp_sids or str(sid) in self.protected_copy_temp_sids:
            return False
        if sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()):
            return False
        if sid in self.post_update_alias_sids or str(sid) in self.post_update_alias_sids:
            return False

        # Preserve SUBPIECE's existing policy: only low-piece extraction is
        # considered transparent here.
        if opcode == "SUBPIECE" and len(inputs) >= 2:
            off = inputs[1]
            if getattr(off, "is_constant", False):
                try:
                    oval = int(getattr(off, "const_value", getattr(off, "value", getattr(off, "offset", 0))))
                    if oval != 0:
                        return False
                except Exception:
                    return False

        return True

    def _is_pure_rhs_inlineable_node_v37(self, node):
        """
        True for side-effect-free non-stack temps that can be expanded inside
        an assignment RHS when otherwise they would print as undefined v_N.

        This deliberately rejects CALL/LOAD/STORE/MULTIEQUAL and protected
        snapshot/materialized/condition temps.  It is not a prettifier; it is a
        programmatic-truth fallback for suppressed arithmetic temps.
        """
        if node is None:
            return False
        var = getattr(node, "var", None)
        sid = self._sid_of(var)
        opcode = getattr(node, "opcode", None)

        if sid is None or self._is_stack_local_var(var):
            return False
        if opcode in ("CALL", "CALLIND", "LOAD", "STORE", "MULTIEQUAL", "INDIRECT"):
            return False
        if sid in self.materialize_sids or str(sid) in self.materialize_sids:
            return False
        if sid in self.condition_temp_def_sids or str(sid) in self.condition_temp_def_sids:
            return False
        if sid in self.required_call_result_sids or str(sid) in self.required_call_result_sids:
            return False
        if sid in self.protected_condition_value_sids or str(sid) in self.protected_condition_value_sids:
            return False
        if sid in self.protected_copy_temp_sids or str(sid) in self.protected_copy_temp_sids:
            return False
        if sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()):
            return False
        if sid in self.post_update_alias_sids or str(sid) in self.post_update_alias_sids:
            return False
        if opcode in _BINARY or opcode in _UNARY or opcode in _TRANSPARENT or opcode in ("PIECE", "SUBPIECE", "CONST"):
            return True
        return False

    def _expr(self, x, seen=None):

        if seen is None:
            seen = set()

        if x is None:
            return "None"

        if hasattr(x, "var") and hasattr(x, "opcode"):
            return self._expr_from_node(x, seen)

        sid = getattr(x, "ssa_id", None)

        if getattr(x, "is_constant", False):
            return self._const(x)

        abi_expr = self._abi_expr_for_value_v46j(
            x,
            context="expression",
        )
        if abi_expr is not None:
            return abi_expr

        if sid is None:
            return str(x)

        custody_expr = self._custody_read_expr_for_sid_v45(
            sid, context="expression"
        )
        if custody_expr is not None:
            return custody_expr

        if sid in seen or str(sid) in seen:
            return self._var(x)

        if (
            not self._is_stack_local_var(x)
            and not (sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()))
        ):
            transparent_alias = self._transparent_expr_alias_for_sid(sid)
            if transparent_alias:
                return transparent_alias

        # v25 guarded SID-backed condition-consumer alias.  If the current compare
        # consumes a post-update source temp, render it as the committed target.
        target = self._post_update_target_for_source_sid(sid, getattr(self, "_current_condition_consumer_sid", None))
        if target:
            return target

        # v19 post-update / consumer aliases: prefer the canonical variable
        # name over formula expansion in all expression paths.
        if sid in self.prefer_var_expr_sids or str(sid) in self.prefer_var_expr_sids or sid in self.post_update_alias_sids or str(sid) in self.post_update_alias_sids:
            return self._var(x)

        node = self.nodes.get(sid) or self.nodes.get(str(sid))

        if node is None:
            return self._var(x)

        if self._is_materialized_runtime_value_v41(x):
            return self._var(x)

        if sid in self.condition_temp_def_sids or str(sid) in self.condition_temp_def_sids:
            return self._var(x)

        if sid in self.materialize_sids or str(sid) in self.materialize_sids:
            return self._var(x)

        if self._policy_expr_mode(sid) == "var" and sid not in self.inline_only_sids and str(sid) not in self.inline_only_sids:
            return self._var(x)

        if getattr(node, "opcode", None) in ("CALL", "CALLIND"):
            return self._var(x)

        return self._expr_from_node(node, seen)

    def _expr_rvalue_v37(self, x, parent_opcode=None, operand_index=None, seen=None):
        """Render an expression operand in assignment-RHS context."""
        if seen is None:
            seen = set()

        if x is None:
            return "None"

        if getattr(x, "is_constant", False):
            return self._const_for_context(x, parent_opcode, operand_index)

        node = x if hasattr(x, "var") and hasattr(x, "opcode") else self._node_for(x)
        sid = self._sid_of(getattr(node, "var", None)) if node is not None else self._sid_of(x)

        if sid is not None and (sid in seen or str(sid) in seen):
            return self._var(getattr(node, "var", x) if node is not None else x)

        # v39 transparent-chain recovery:
        # A transparent/width bridge may map v_bridge -> v_source, and the
        # source itself may be the pure formula we need.  If we call
        # _expr_from_node(v_bridge), the normal transparent alias table returns
        # the literal text "v_source" and stops, recreating the undefined-temp
        # leak.  In RHS context, peel safe non-state transparent bridges and
        # continue recovery on their source input.
        if node is not None and self._is_safe_rvalue_transparent_bridge_v39(node):
            inputs = list(getattr(node, "inputs", []) or [])
            if inputs:
                try:
                    self._event("v39 rhs peel transparent bridge: sid=%s -> source_sid=%s opcode=%s" % (
                        sid,
                        self._sid_of(inputs[0]),
                        getattr(node, "opcode", None),
                    ))
                except Exception:
                    pass
                new_seen = set(seen)
                if sid is not None:
                    new_seen.add(sid)
                    new_seen.add(str(sid))
                return self._expr_rvalue_v37(inputs[0], parent_opcode, operand_index, new_seen)

        # If this value has already been emitted as a concrete assignment in
        # the current linear stream, prefer that materialized value over
        # re-expanding its defining expression.  This prevents duplicate LOADs
        # and keeps condition-header payload temps like v_416/v_479 usable.
        if self._is_materialized_runtime_value_v41(getattr(node, "var", x) if node is not None else x):
            return self._var(getattr(node, "var", x) if node is not None else x)

        # Narrow same-block recovery: if a pure temp was suppressed and is now
        # used by a real assignment in the same block, inline its formula so the
        # emitted Python does not reference an undefined v_N.
        if node is not None and self._is_pure_rhs_inlineable_node_v37(node):
            naddr = self._node_block_addr_v37(node)
            cur_addr = getattr(self, "_current_expr_block_addr", None) or getattr(self, "_current_block_addr", None)
            if naddr is None or cur_addr is None or naddr == cur_addr:
                try:
                    self._event("v39 rhs inline pure temp: sid=%s opcode=%s block=%s" % (sid, getattr(node, "opcode", None), hex(naddr) if isinstance(naddr, int) else naddr))
                except Exception:
                    pass
                new_seen = set(seen)
                # Do not add this node's own SID before expanding it.
                # _expr_from_node() owns the cycle guard; pre-adding the SID
                # makes it immediately fall back to v_N and defeats recovery.
                return self._expr_from_node(node, new_seen)

        return self._expr(x, seen)

    def _expr_from_node(self, node, seen=None):

        if seen is None:
            seen = set()

        if node is None:
            return "None"

        var = getattr(node, "var", None)
        sid = getattr(var, "ssa_id", None)

        if sid is not None:
            if sid in seen:
                return self._var(var)
            seen.add(sid)

        abi_expr = self._abi_expr_for_value_v46j(
            var,
            context="formula_node",
        )
        if abi_expr is not None:
            return abi_expr

        custody_expr = self._custody_read_expr_for_sid_v45(
            sid, context="formula_node"
        )
        if custody_expr is not None:
            return custody_expr

        if sid in self.condition_temp_def_sids:
            return self._var(var)

        if (
            not self._is_stack_local_var(var)
            and not (sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()))
        ):
            transparent_alias = self._transparent_expr_alias_for_sid(sid)
            if transparent_alias:
                return transparent_alias

        target = self._post_update_target_for_source_sid(sid, getattr(self, "_current_condition_consumer_sid", None))
        if target:
            return target

        if sid in self.prefer_var_expr_sids or sid in self.post_update_alias_sids:
            return self._var(var)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode is None:
            return self._var(var)

        if opcode == "INDIRECT":
            # Defensive path for a FormulaNode reached without a family
            # descriptor.  INDIRECT itself is still not executable; preserve
            # the prior SSA value and make the missing sidecar visible.
            self.custody_warnings.append({
                "kind": "emitter_indirect_formula_prior_value_fallback_v45",
                "sid": sid,
                "action": "render_prior_value_without_runtime_INDIRECT",
            })
            if inputs:
                return self._expr(inputs[0], seen)
            return self._var(var)

        # Materialized nodes render by variable name inside larger exprs.
        if sid in self.materialize_sids:
            return self._var(var)

        c_truth_expr = self._c_truth_expr_for_node(
            node, inputs, seen=seen.copy(), context="inline_node"
        )
        if c_truth_expr:
            return c_truth_expr

        if opcode == "CONST":
            if inputs:
                return self._expr(inputs[0], seen)
            return self._var(var)

        if opcode in _TRANSPARENT:
            if inputs:
                return self._expr(inputs[0], seen)
            return self._var(var)

        if opcode in _BINARY and len(inputs) == 2:

            a = self._expr_rvalue_v37(inputs[0], opcode, 0, seen.copy())
            b = self._expr_rvalue_v37(inputs[1], opcode, 1, seen.copy())
            return self._format_binary_expr_v37(opcode, a, b)

        if opcode in _UNARY and len(inputs) >= 1:

            a = self._expr_rvalue_v37(inputs[0], opcode, 0, seen.copy())
            op = _UNARY[opcode]

            if op.endswith(" "):
                return "(%s%s)" % (op, a)

            return "(%s%s)" % (op, a)

        if opcode in ("CALL", "CALLIND"):
            # Normal expression rendering never re-executes calls.
            return self._var(var)

        if opcode == "LOAD":
            if len(inputs) >= 2:
                return "MEM[%s]" % self._expr_rvalue_v37(inputs[-1], opcode, len(inputs) - 1, seen.copy())
            if inputs:
                return "MEM[%s]" % self._expr_rvalue_v37(inputs[0], opcode, 0, seen.copy())
            return "MEM[?]"

        if opcode == "STORE":
            return "STORE"

        if opcode == "PIECE":
            parts = ", ".join(self._expr(i, seen.copy()) for i in inputs)
            return "piece(%s)" % parts

        if opcode == "SUBPIECE":
            if len(inputs) >= 2:
                return "subpiece(%s, %s)" % (
                    self._expr(inputs[0], seen.copy()),
                    self._expr(inputs[1], seen.copy()),
                )
            return "subpiece(%s)" % ", ".join(self._expr(i, seen.copy()) for i in inputs)

        if opcode == "MULTIEQUAL":
            return self._var(var)

        if inputs:
            args = ", ".join(self._expr(i, seen.copy()) for i in inputs)
            return "%s(%s)" % (opcode.lower(), args)

        return self._var(var)

    def _expr_from_op(self, opcode, inputs, current_op=None):

        inputs = list(inputs or [])

        if opcode == "INDIRECT":
            # Same defensive invariant as _expr_from_node(): no call-like
            # ``indirect(...)`` expression may enter either projection.
            if inputs:
                return self._expr(inputs[0])
            return "0"

        if current_op is not None:
            c_truth_expr = self._c_truth_expr_for_op(
                current_op, inputs, context="emitted_op"
            )
            if c_truth_expr:
                return c_truth_expr

        if opcode in _BINARY and len(inputs) == 2:
            old_current_expr_op = getattr(self, "_current_expr_op", None)
            if current_op is not None:
                self._current_expr_op = current_op
            try:
                a = self._expr_rvalue_v37(inputs[0], opcode, 0)
                b = self._expr_rvalue_v37(inputs[1], opcode, 1)
                return self._format_binary_expr_v37(opcode, a, b)
            finally:
                if current_op is not None:
                    self._current_expr_op = old_current_expr_op

        if opcode in _UNARY and len(inputs) >= 1:
            a = self._expr_rvalue_v37(inputs[0], opcode, 0)
            op = _UNARY[opcode]
            if op.endswith(" "):
                return "(%s%s)" % (op, a)
            return "(%s%s)" % (op, a)

        if opcode in _TRANSPARENT and inputs:
            return self._expr(inputs[0])

        if opcode == "LOAD":
            if len(inputs) >= 2:
                return "MEM[%s]" % self._expr_rvalue_v37(inputs[-1], opcode, len(inputs) - 1)
            if inputs:
                return "MEM[%s]" % self._expr_rvalue_v37(inputs[0], opcode, 0)
            return "MEM[?]"

        if opcode == "PIECE":
            return "piece(%s)" % ", ".join(self._expr(i) for i in inputs)

        if opcode == "SUBPIECE":
            return "subpiece(%s)" % ", ".join(self._expr(i) for i in inputs)

        if inputs:
            return "%s(%s)" % (
                opcode.lower(),
                ", ".join(self._expr(i) for i in inputs)
            )

        return "0"

    # =========================================================
    # FORCED LOOP CONDITION NORMALIZATION
    # =========================================================

    def _loop_cond_forced(self, loop_node):
        """
        Render Python while condition from SGL loop metadata.

        v19c printer contract:
        If SGL exposes loop.condition_role / loop.emit_condition_mode, consume
        it mechanically and do not infer deeper source structure.

            role=true  -> while True
            role=body  -> while cond
            role=exit  -> while not(cond)

        Fallback inference remains only for older SGL trees.
        """

        cond_var = getattr(loop_node, "cond_var", None)

        role = (
            getattr(loop_node, "condition_role", None)
            or getattr(loop_node, "emit_condition_mode", None)
            or getattr(loop_node, "loop_condition_role", None)
        )

        if role in ("true", "forever", "while_true"):
            return "True"

        if cond_var is None:
            return "True"

        if role == "body":
            return self._cond_clean(self._cond(cond_var))

        if role == "exit":
            return self._cond_clean(self._invert_cond(cond_var))

        # -----------------------------------------------------------------
        # Compatibility fallback for pre-v19b SGL trees only.
        # -----------------------------------------------------------------

        header = getattr(loop_node, "header", None)
        if header is None:
            header = getattr(loop_node, "cfg_node", None)

        body_node = self._first_cfg_node(getattr(loop_node, "body", None))
        explicit_target = self._explicit_branch_target_node(header)

        reason = getattr(cond_var, "reason", None)
        if isinstance(reason, str) and (
            "induction_loop_body_predicate" in reason
            or "loop_body" in reason
            or "body_predicate" in reason
        ):
            return self._cond_clean(self._cond(cond_var))

        if self._is_sgl_raw_condition(cond_var):
            if explicit_target is not None and body_node is not None:
                if explicit_target is not body_node:
                    return self._cond_clean(self._invert_cond(cond_var))
                return self._cond_clean(self._cond(cond_var))
            return self._cond_clean(self._cond(cond_var))

        if self._loop_exit_test_pattern_var(cond_var):
            return self._cond_clean(self._invert_cond(cond_var))

        if explicit_target is not None and body_node is not None:
            if explicit_target is not body_node:
                return self._cond_clean(self._invert_cond(cond_var))
            return self._cond_clean(self._cond(cond_var))

        old = self._rendering_loop_condition
        self._rendering_loop_condition = True
        try:
            return self._cond_clean(self._cond(cond_var))
        finally:
            self._rendering_loop_condition = old


    def _loop_exit_test_pattern_var(self, cond_var):
        """
        Same test as _loop_exit_test_pattern(), but starts from a condition var.
        """

        node = self._node_for(cond_var)

        if node is None:
            return False

        return self._loop_exit_test_pattern(node)


    def _loop_exit_test_pattern(self, node):
        """
        True for the narrow optimized loop-exit pattern:
            const < variable
        """

        if node is None:
            return False

        node = self._resolve_transparent_node(node)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
            return False

        if len(inputs) != 2:
            return False

        left = inputs[0]
        right = inputs[1]

        return bool(getattr(left, "is_constant", False) and not getattr(right, "is_constant", False))


    def _first_cfg_node(self, exec_node):

        if exec_node is None:
            return None

        kind = getattr(exec_node, "kind", None)

        if kind == "block":
            return getattr(exec_node, "cfg_node", None)

        if kind == "loop":
            header = getattr(exec_node, "header", None)
            if header is not None:
                return header

        if kind == "if":
            cfg_node = getattr(exec_node, "cfg_node", None)
            if cfg_node is not None:
                return cfg_node

        for child in getattr(exec_node, "children", []):
            found = self._first_cfg_node(child)
            if found is not None:
                return found

        return None


    def _explicit_branch_target_node(self, cfg_node):

        if cfg_node is None:
            return None

        block = getattr(cfg_node, "block", None)

        if block is None:
            return None

        term = getattr(block, "terminator", None)

        if term is None or getattr(term, "opcode", None) != "CBRANCH":
            return None

        target_addr = self._terminator_target_addr(term)

        if target_addr is None:
            return None

        for e in getattr(cfg_node, "out_edges", []):
            dst = getattr(e, "dst", None)
            if dst is not None and getattr(dst, "addr", None) == target_addr:
                return dst

        return None


    def _terminator_target_addr(self, term):

        for attr in ("target", "true_target"):
            target = getattr(term, attr, None)
            if target is not None:
                addr = getattr(target, "addr", None)
                if isinstance(addr, int):
                    return addr

                for vattr in ("address", "offset", "value"):
                    val = getattr(target, vattr, None)
                    if isinstance(val, int):
                        return val

        inputs = list(getattr(term, "inputs", []) or [])

        if not inputs:
            return None

        target = inputs[0]

        addr = getattr(target, "addr", None)
        if isinstance(addr, int):
            return addr

        for attr in ("address", "offset", "value"):
            val = getattr(target, attr, None)
            if isinstance(val, int):
                return val

        return None


    def _invert_cond(self, var):

        if var is None:
            return "False"

        if hasattr(var, "var") and hasattr(var, "opcode"):
            node = var
        else:
            sid = getattr(var, "ssa_id", None)
            node = self.nodes.get(sid)

        if node is None:
            return self._cond_clean("not (%s)" % self._cond(var))

        node = self._resolve_transparent_node(node)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        c_truth_expr = self._c_truth_expr_for_node(
            node, inputs, context="inverted_condition"
        )
        if c_truth_expr:
            return "not (%s)" % c_truth_expr

        inv = {
            "INT_EQUAL": "!=",
            "INT_NOTEQUAL": "==",
            "INT_LESS": ">=",
            "INT_SLESS": ">=",
            "INT_LESSEQUAL": ">",
            "INT_SLESSEQUAL": ">",
        }

        if opcode in inv and len(inputs) == 2:
            consumer_sid = self._sid_of(getattr(node, "var", None))
            old = self._current_condition_consumer_sid
            self._current_condition_consumer_sid = consumer_sid
            try:
                a = self._expr_rvalue_v37(inputs[0], opcode, 0)
                b = self._expr_rvalue_v37(inputs[1], opcode, 1)
            finally:
                self._current_condition_consumer_sid = old
            return "%s %s %s" % (a, inv[opcode], b)

        if opcode == "BOOL_NEGATE" and inputs:
            return self._cond(inputs[0])

        return "not (%s)" % self._cond(var)


    # =========================================================
    # CONDITIONS
    # =========================================================

    def _cond(self, var):

        if var is None:
            return "True"

        if hasattr(var, "var") and hasattr(var, "opcode"):
            node = var
        else:
            sid = getattr(var, "ssa_id", None)
            node = self.nodes.get(sid)

        if node is None:
            if getattr(var, "is_constant", False):
                return self._const(var)
            return self._var(var)

        node = self._resolve_transparent_node(node)

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode in ("CALL", "CALLIND"):
            return self._var(getattr(node, "var", None))

        c_truth_expr = self._c_truth_expr_for_node(
            node, inputs, context="condition"
        )
        if c_truth_expr:
            return self._cond_clean(c_truth_expr)

        if opcode in _COMPARE_OPS and len(inputs) == 2:
            if self._rendering_loop_condition and self._loop_exit_test_pattern(node):
                return self._invert_cond(node)

            consumer_sid = self._sid_of(getattr(node, "var", None))
            old = self._current_condition_consumer_sid
            self._current_condition_consumer_sid = consumer_sid
            try:
                a = self._expr_rvalue_v37(inputs[0], opcode, 0)
                b = self._expr_rvalue_v37(inputs[1], opcode, 1)
            finally:
                self._current_condition_consumer_sid = old
            return self._cond_clean("%s %s %s" % (a, _BINARY[opcode], b))

        if opcode == "BOOL_NEGATE" and inputs:
            return self._cond_clean("not (%s)" % self._cond(inputs[0]))

        return self._cond_clean(self._expr_from_node(node))

    def _resolve_transparent_node(self, node):

        seen = set()
        cur = node

        while cur is not None:

            sid = getattr(getattr(cur, "var", None), "ssa_id", None)

            if sid is not None:
                if sid in seen:
                    return cur
                seen.add(sid)

            opcode = getattr(cur, "opcode", None)

            if opcode not in _TRANSPARENT:
                return cur

            if self._c_truth_contract_for_sid_has_helper(sid):
                return cur

            inputs = list(getattr(cur, "inputs", []) or [])

            if not inputs:
                return cur

            nxt = inputs[0]

            if hasattr(nxt, "var") and hasattr(nxt, "opcode"):
                cur = nxt
                continue

            nsid = getattr(nxt, "ssa_id", None)

            if nsid is not None and nsid in self.nodes:
                cur = self.nodes[nsid]
                continue

            return cur

        return node

    # =========================================================
    # FOR LOOP RECOVERY
    # =========================================================

    def _try_emit_for_loop(self, loop_node):

        if not self.enable_for_loop_recovery:
            return False

        role = (
            getattr(loop_node, "condition_role", None)
            or getattr(loop_node, "emit_condition_mode", None)
            or getattr(loop_node, "loop_condition_role", None)
        )

        if role not in (None, "body"):
            return False

        cond_var = getattr(loop_node, "cond_var", None)

        if cond_var is None:
            return False

        cond_node = self._node_for(cond_var)

        if cond_node is None:
            return False

        cond_node = self._resolve_transparent_node(cond_node)

        opcode = getattr(cond_node, "opcode", None)

        if opcode not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
            return False

        inputs = list(getattr(cond_node, "inputs", []) or [])

        if len(inputs) != 2:
            return False

        left = inputs[0]
        right = inputs[1]

        left_var = self._to_var(left)

        if left_var is None:
            return False

        left_node = self._node_for(left_var)

        if left_node is not None:
            is_induction = bool(getattr(left_node, "is_induction", False))
        else:
            is_induction = False

        if not is_induction and not getattr(left_var, "is_induction_variable", False):
            return False

        name = self._var(left_var)
        end = self._expr(right)
        start = "0"

        if opcode in ("INT_LESSEQUAL", "INT_SLESSEQUAL"):
            end = "(%s + 1)" % end

        self._w("for %s in range(%s, %s):" % (name, start, end))

        self.indent += 1

        before = len(self.lines)
        self._emit_node(
            getattr(loop_node, "body", None),
            tuple(self._current_exec_path or ("root",)) + ("for.body",),
        )
        if len(self.lines) == before:
            self._w("pass")

        self.indent -= 1

        return True

    # =========================================================
    # VARIABLE / NAME HELPERS
    # =========================================================

    def _alias_target_name_for_sid(self, sid):
        """
        Return the canonical target name for source-state aliases.

        This is the emitter-side collapse of pre-PHI fragments:
            v_1500 = local_1c + 5; local_1c = v_1500
        becomes:
            local_1c = local_1c + 5

        It is still only a printer operation: PHIfolder owns the metadata that
        says a source SID is allowed to write the PHI target.
        """
        if sid is None:
            return None

        # SID-backed post-update aliases from PHIfolder v20h+.
        # Only condition-scoped aliases may fire when a condition consumer
        # context is active.  Outside that context, use only global state
        # transition/post-update maps built from explicit PHI state-write
        # metadata.  This prevents condition masks from rewriting assignment
        # LHS names.
        ctx = getattr(self, "_current_condition_consumer_sid", None)
        if ctx is not None:
            name = self._post_update_target_for_source_sid(sid, ctx)
            if name:
                return self._sanitize_name(str(name))
        else:
            name = (
                self.post_update_source_target_by_sid.get(sid)
                or self.post_update_source_target_by_sid.get(str(sid))
            )
            if name:
                return self._sanitize_name(str(name))

        for table in (
            self.state_transition_aliases,
            self.phi_source_aliases,
            self.temp_phi_source_aliases,
            self.post_update_aliases,
            self.post_update_consumer_aliases,
        ):
            for rec_sid, info in self._iter_sid_info_records(table):
                if not self._source_sid_matches(rec_sid, sid):
                    continue

                if isinstance(info, dict):
                    name = info.get("target_name")
                else:
                    name = info

                if name:
                    return self._sanitize_name(str(name))

        return None

    def _var(self, v):

        if v is None:
            return "None"

        if hasattr(v, "var"):
            v = v.var

        if getattr(v, "is_constant", False):
            return self._const(v)

        sid = getattr(v, "ssa_id", None)

        # ABI-D/F owns physical carriers, implicit machine inputs, and raw
        # same-storage convergence targets.  Consume that identity before the
        # older HighVariable presentation tables can reintroduce names such as
        # param_7, in_AL, or v_789.
        abi_name = self._abi_expr_for_value_v46j(
            v,
            context="variable",
        )
        if abi_name is not None:
            return abi_name

        # v45: every SSA version in an INDIRECT family presents through the
        # family's HighVariable name.  RHS execution reads are handled by
        # _expr(); _var() remains the canonical lvalue/name projection.
        custody_descriptor = self._custody_descriptor_for_sid_v45(sid)
        if isinstance(custody_descriptor, dict) and custody_descriptor.get("high_name"):
            return custody_descriptor.get("high_name")

        # v33: a stack-local var name is the state target.  Never replace the
        # LHS/local name through transparent bridge aliases.
        if (
            not self._is_stack_local_var(v)
            and not (sid in getattr(self, "snapshot_copy_temp_sids", set()) or str(sid) in getattr(self, "snapshot_copy_temp_sids", set()))
        ):
            transparent_alias = self._transparent_expr_alias_for_sid(sid)
            if transparent_alias:
                return transparent_alias

        if sid is not None:
            dyn_alias = self._dynamic_alias_target_for_source_sid(sid)
            if dyn_alias:
                return dyn_alias

        if sid is not None:
            alias_name = self._alias_target_name_for_sid(sid)
            if alias_name:
                return alias_name

        if sid is not None and sid in self.var_map:
            return self.var_map[sid]

        name = getattr(v, "name", None)

        if name:
            return self._sanitize_name(name)

        if sid is not None:
            return self._sanitize_name(str(sid))

        return self._sanitize_name(str(v))

    def _const(self, v):

        if v is None:
            return "None"

        if hasattr(v, "const_value"):
            val = getattr(v, "const_value")
        elif hasattr(v, "value"):
            val = getattr(v, "value")
        elif hasattr(v, "offset"):
            val = getattr(v, "offset")
        else:
            val = 0

        try:
            if isinstance(val, int) and abs(val) >= 10:
                return hex(val)
        except Exception:
            pass

        return str(val)

    def _sanitize_name(self, name):

        if name is None:
            return "v_unknown"

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
            s = "v_unknown"

        if s[0].isdigit():
            s = "v_" + s

        while s.startswith("v_v_"):
            s = s[2:]

        return s

    def _call_name(self, target):

        if target is None:
            return "sub_unknown"

        if hasattr(target, "var"):
            target = target.var

        name = getattr(target, "name", None)

        if name:
            return self._sanitize_name(name)

        symbol = getattr(target, "symbol", None)

        if symbol:
            return self._sanitize_name(symbol)

        off = getattr(target, "offset", None)

        if off is not None:
            return "sub_%x" % off

        return "sub_unknown"

    # =========================================================
    # LOGICAL IDENTITY HELPERS
    # =========================================================

    def _node_for(self, x):

        if x is None:
            return None

        if hasattr(x, "var") and hasattr(x, "opcode"):
            return x

        sid = getattr(x, "ssa_id", None)

        if sid is None:
            return None

        return self.nodes.get(sid)

    def _to_var(self, x):

        if x is None:
            return None

        if hasattr(x, "var"):
            return x.var

        return x

    def _same_logical_var(self, a, b):

        av = self._to_var(a)
        bv = self._to_var(b)

        if av is None or bv is None:
            return False

        if av is bv:
            return True

        if getattr(av, "ssa_id", None) == getattr(bv, "ssa_id", None):
            return True

        asid = getattr(av, "ssa_id", None)
        bsid = getattr(bv, "ssa_id", None)

        if asid in self.var_map and bsid in self.var_map:
            if self.var_map[asid] == self.var_map[bsid]:
                return True

        ak = (
            getattr(av, "space", None),
            getattr(av, "offset", None),
            getattr(av, "size", None),
            getattr(av, "address", None),
        )

        bk = (
            getattr(bv, "space", None),
            getattr(bv, "offset", None),
            getattr(bv, "size", None),
            getattr(bv, "address", None),
        )

        if ak == bk and any(x is not None for x in ak):
            return True

        return False

    def _is_condition_var(self, v):

        if v is None:
            return False

        if hasattr(v, "var"):
            v = v.var

        if getattr(v, "is_condition", False):
            return True

        sid = getattr(v, "ssa_id", None)

        node = self.nodes.get(sid)

        if node is not None and getattr(node, "is_condition", False):
            return True

        for cv in self.condition_vars:
            if getattr(cv, "ssa_id", None) == sid:
                return True

        return False

    def _is_pure_condition_op(self, opcode):

        return opcode in _COMPARE_OPS or opcode == "BOOL_NEGATE"

    def _can_suppress_transparent_assign(self, out, src):

        if out is None or src is None:
            return False

        if self._abi_fixed_argument_local_initializer_contract_v46k(
            getattr(self._node_for(out), "op", None)
        ):
            return False

        if str(self._sid_of(out)) in self.custody_parameter_initializers_by_output_sid:
            return False

        if (
            not self._is_readable_render_v44()
            and str(self._sid_of(out))
            in self.abi_entry_storage_initializer_rejected_output_sids
        ):
            return False

        if not self._is_readable_render_v44() and self.abi_active:
            source_root = self._abi_unique_root_for_sid_v46c(
                self._sid_of(src),
                required_role="variadic_entry_gp_carrier",
            )
            descriptor = self._abi_storage_descriptor_for_output_v46c(
                out, self._sid_of(out)
            )
            if (
                isinstance(source_root, dict)
                and self._is_stack_local_var(out)
                and isinstance(descriptor, dict)
                and descriptor.get("memory_backed") is True
            ):
                return False

        if self._is_condition_var(out):
            return True

        if self._same_logical_var(out, src):
            return True

        return False

    # =========================================================
    # FALLBACK LINEAR EMISSION
    # =========================================================

    def _emit_fallback_linear(self):

        for block in getattr(self.func, "blocks", []):

            try:
                addr = hex(block.addr)
            except Exception:
                addr = str(getattr(block, "addr", "?"))

            self._w("# block %s" % addr)

            for op in getattr(block, "ops", []):
                self._emit_op(op)

            self._emit_phi_dropins_for_block(block)
            self._emit_terminator_if_needed(block)

    # =========================================================
    # DEBUG
    # =========================================================

    def debug_summary(self):

        if not self._debug_reporting_enabled_v46g():
            return

        print("\n[EMITTER SUMMARY]")
        print("-" * 60)
        print("Lines          :", len(self.lines))
        print("Formula Nodes  :", len(self.nodes))
        print("PHI Nodes      :", len(self.phi_nodes))
        print("Var Map Entries:", len(self.var_map))
        print("Events         :", len(self.debug_events))
        print("Suppress Assign:", len(self.suppress_assign_sids))
        print("Inline Only    :", len(self.inline_only_sids))
        print("Materialize    :", len(self.materialize_sids))
        print("Foldable PHI   :", len(self.phi_source_foldable_sids))
        print("Temp PHI Aliases:", len(self.temp_phi_source_alias_sids))
        print("SSA Policy     :", len(self.ssa_policy_by_sid))
        print("Condition Temp Defs:", len(self.condition_temp_defs))
        print("Post-update Cond Aliases:", len(self.post_update_condition_aliases))
        print("Transparent Expr Aliases:", len(getattr(self, "transparent_expr_alias_by_sid", {}) or {}))
        print("Snapshot COPY SIDs:", len(getattr(self, "snapshot_copy_temp_sids", set()) or set()))
        print("SGL latch/update blocks:", len(getattr(self, "sgl_latch_update_block_addrs", set()) or set()))
        print("SGL latch/update source SIDs:", len(getattr(self, "sgl_latch_update_source_sids", set()) or set()))
        print("Real stack-write override: enabled")
        print("Emitter Build  :", self.VERSION)

    def debug_dump_events(self):

        if not self._debug_reporting_enabled_v46g():
            return

        print("\n[EMITTER EVENTS]")
        print("-" * 60)

        for e in self.debug_events:
            print(e)

        print("-" * 60)
    # =========================================================
    # DEBUG
    # =========================================================

    def debug_summary(self):

        if not self._debug_reporting_enabled_v46g():
            return

        print("\n[EMITTER SUMMARY]")
        print("-" * 60)
        print("Lines          :", len(self.lines))
        print("Formula Nodes  :", len(self.nodes))
        print("PHI Nodes      :", len(self.phi_nodes))
        print("Var Map Entries:", len(self.var_map))
        print("Events         :", len(self.debug_events))
        print("Suppress Assign:", len(self.suppress_assign_sids))
        print("Inline Only    :", len(self.inline_only_sids))
        print("Materialize    :", len(self.materialize_sids))
        print("Foldable PHI   :", len(self.phi_source_foldable_sids))
        print("Temp PHI Aliases:", len(self.temp_phi_source_alias_sids))
        print("SSA Policy     :", len(self.ssa_policy_by_sid))
        print("Condition Temp Defs:", len(self.condition_temp_defs))
        print("Post-update Cond Aliases:", len(self.post_update_condition_aliases))
        print("Transparent Expr Aliases:", len(getattr(self, "transparent_expr_alias_by_sid", {}) or {}))
        print("Snapshot COPY SIDs:", len(getattr(self, "snapshot_copy_temp_sids", set()) or set()))
        print("SGL latch/update blocks:", len(getattr(self, "sgl_latch_update_block_addrs", set()) or set()))
        print("SGL latch/update source SIDs:", len(getattr(self, "sgl_latch_update_source_sids", set()) or set()))
        print("Real stack-write override: enabled")
        print("Emitter Build  :", self.VERSION)

    def debug_dump_events(self):

        if not self._debug_reporting_enabled_v46g():
            return

        print("\n[EMITTER EVENTS]")
        print("-" * 60)

        for e in self.debug_events:
            print(e)

        print("-" * 60)

    def debug_dump_variable_metadata_core(self, focus=None):

        if not self._debug_reporting_enabled_v46g():
            return
        """
        PAL emitter metadata core dump.

        Purpose:
            Show the variable/transformation metadata that directly affects
            whether a temp like v_367 becomes local_14 in emitted code.

        Use:
            emitter.debug_dump_variable_metadata_core()
            emitter.debug_dump_variable_metadata_core("local_14")
            emitter.debug_dump_variable_metadata_core("v_367")

        This is emitter-side only. It prints what the emitter actually sees
        after PHIfolder has exposed metadata onto func.
        """

        def sid_key(x):
            if x is None:
                return None
            return str(x)

        def want(*vals):
            if focus is None:
                return True
            f = str(focus)
            for v in vals:
                if v is None:
                    continue
                if f in str(v):
                    return True
            return False

        def dump_table(title, obj, max_items=80):
            print("\n[%s]" % title)
            print("-" * 72)

            if obj is None:
                print("<None>")
                return

            if isinstance(obj, dict):
                items = list(obj.items())
            elif isinstance(obj, (list, tuple, set)):
                items = list(enumerate(obj))
            else:
                print(repr(obj))
                return

            shown = 0
            for k, v in items:
                if isinstance(v, dict):
                    blob = " ".join("%s=%r" % (kk, vv) for kk, vv in sorted(v.items(), key=lambda kv: str(kv[0])))
                else:
                    blob = repr(v)

                if not want(k, blob):
                    continue

                print("%r :: %s" % (k, blob))
                shown += 1
                if shown >= max_items:
                    print("... truncated at %d items ..." % max_items)
                    break

            if shown == 0:
                print("<no matching entries>")

        def dump_set(title, obj, max_items=120):
            print("\n[%s]" % title)
            print("-" * 72)

            vals = sorted(list(obj or []), key=lambda x: str(x))
            shown = 0
            for v in vals:
                if not want(v):
                    continue
                print(repr(v))
                shown += 1
                if shown >= max_items:
                    print("... truncated at %d items ..." % max_items)
                    break

            if shown == 0:
                print("<no matching entries>")

        def node_summary(sid):
            node = self.nodes.get(sid)
            if node is None:
                node = self.nodes.get(str(sid))

            if node is None:
                return "<no node>"

            op = getattr(node, "opcode", None)
            var = getattr(node, "var", None)
            out_sid = getattr(var, "ssa_id", None)
            ins = []

            for i in list(getattr(node, "inputs", []) or []):
                isid = getattr(i, "ssa_id", None)
                name = None
                try:
                    name = self._var(i)
                except Exception:
                    name = getattr(i, "name", None) or str(i)

                if getattr(i, "is_constant", False):
                    try:
                        name = self._const(i)
                    except Exception:
                        pass

                ins.append("%s/%s" % (name, isid))

            try:
                expr = self._expr_from_node(node)
            except Exception as e:
                expr = "<expr error: %s>" % e

            return "opcode=%r out_sid=%r var=%r inputs=[%s] expr=%r" % (
                op,
                out_sid,
                self._var(var) if var is not None else None,
                ", ".join(ins),
                expr,
            )

        print("\n" + "=" * 80)
        print("PAL EMITTER VARIABLE METADATA CORE")
        print("focus =", repr(focus))
        print("=" * 80)

        print("\n[COUNTS]")
        print("-" * 72)
        print("nodes                         :", len(getattr(self, "nodes", {}) or {}))
        print("var_map                       :", len(getattr(self, "var_map", {}) or {}))
        print("phi_dropins                   :", len(getattr(self, "phi_dropins", []) or []))
        print("post_update_condition_aliases :", len(getattr(self, "post_update_condition_aliases", []) or []))
        print("post_update_alias_sids        :", len(getattr(self, "post_update_alias_sids", set()) or set()))
        print("state_transition_alias_sids   :", len(getattr(self, "state_transition_alias_sids", set()) or set()))
        print("prefer_var_expr_sids          :", len(getattr(self, "prefer_var_expr_sids", set()) or set()))
        print("suppress_assign_sids          :", len(getattr(self, "suppress_assign_sids", set()) or set()))
        print("materialize_sids              :", len(getattr(self, "materialize_sids", set()) or set()))

        dump_table("var_map", getattr(self, "var_map", {}))
        dump_table("transparent_expr_alias_by_sid", getattr(self, "transparent_expr_alias_by_sid", {}))
        dump_set("snapshot_copy_temp_sids", getattr(self, "snapshot_copy_temp_sids", set()))
        dump_set("post_update_alias_sids", getattr(self, "post_update_alias_sids", set()))
        dump_table("post_update_aliases", getattr(self, "post_update_aliases", {}))
        dump_table("post_update_condition_aliases", getattr(self, "post_update_condition_aliases", []))
        dump_table("post_update_consumer_aliases", getattr(self, "post_update_consumer_aliases", {}))
        dump_set("post_update_condition_alias_sids", getattr(self, "post_update_condition_alias_sids", set()))
        dump_set("post_update_consumer_sids", getattr(self, "post_update_consumer_sids", set()))
        dump_set("prefer_var_expr_sids", getattr(self, "prefer_var_expr_sids", set()))
        dump_set("state_transition_alias_sids", getattr(self, "state_transition_alias_sids", set()))
        dump_table("state_transition_aliases", getattr(self, "state_transition_aliases", {}))
        dump_set("phi_source_alias_sids", getattr(self, "phi_source_alias_sids", set()))
        dump_table("phi_source_aliases", getattr(self, "phi_source_aliases", {}))
        dump_table("phi_dropins", getattr(self, "phi_dropins", []))

        if hasattr(self, "post_update_source_target_by_sid"):
            dump_table("emitter.post_update_source_target_by_sid", self.post_update_source_target_by_sid)

        if hasattr(self, "post_update_consumer_sources_by_sid"):
            dump_table("emitter.post_update_consumer_sources_by_sid", self.post_update_consumer_sources_by_sid)

        print("\n[NODE DETAILS FOR MATCHING SIDS]")
        print("-" * 72)

        interesting = set()

        for sid in getattr(self, "post_update_alias_sids", set()) or set():
            interesting.add(sid)

        for sid in getattr(self, "post_update_condition_alias_sids", set()) or set():
            interesting.add(sid)

        for sid in getattr(self, "post_update_consumer_sids", set()) or set():
            interesting.add(sid)

        for sid in getattr(self, "prefer_var_expr_sids", set()) or set():
            interesting.add(sid)

        for rec in getattr(self, "post_update_condition_aliases", []) or []:
            if isinstance(rec, dict):
                for k in ("source_sid", "consumer_sid", "condition_consumer_sid", "target_sid"):
                    if rec.get(k) is not None:
                        interesting.add(rec.get(k))

        var_map_obj = getattr(self, "var_map", {}) or {}

        if isinstance(var_map_obj, dict):
            var_map_items = list(var_map_obj.items())
        elif isinstance(var_map_obj, (list, tuple, set)):
            var_map_items = []
            for item in var_map_obj:
                if isinstance(item, dict):
                    sid = item.get("sid")
                    name = item.get("name") or item.get("target_name") or item.get("var")
                    if sid is not None:
                        var_map_items.append((sid, name))
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    var_map_items.append((item[0], item[1]))
        else:
            var_map_items = []

        for sid, name in var_map_items:
            if want(sid, name):
                interesting.add(sid)

        shown = 0
        for sid in sorted(interesting, key=lambda x: str(x)):
            if not want(sid, node_summary(sid)):
                continue
            print("%r :: %s" % (sid, node_summary(sid)))
            shown += 1

        if shown == 0:
            print("<no matching node details>")

        print("\n[ALIAS RESOLUTION PROBE]")
        print("-" * 72)

        probe_sids = sorted(interesting, key=lambda x: str(x))
        for sid in probe_sids:
            if not want(sid):
                continue

            try:
                alias = self._alias_target_name_for_sid(sid)
            except Exception as e:
                alias = "<alias error: %s>" % e

            try:
                post_any = self._post_update_target_for_source_sid(sid, None) if hasattr(self, "_post_update_target_for_source_sid") else None
            except Exception as e:
                post_any = "<post-any error: %s>" % e

            print("sid=%r alias_target=%r post_update_global=%r" % (sid, alias, post_any))

            if hasattr(self, "post_update_consumer_sources_by_sid"):
                for csid, bucket in sorted(self.post_update_consumer_sources_by_sid.items(), key=lambda kv: str(kv[0])):
                    if not isinstance(bucket, dict):
                        continue
                    target = bucket.get(sid) or bucket.get(str(sid))
                    if target:
                        print("    under consumer %r -> %r" % (csid, target))

        print("=" * 80)

    def debug_dump_c_truth(self, verbose=False):

        if not self._debug_reporting_enabled_v46g():
            return
        try:
            from pprint import pprint
        except Exception:
            pprint = print

        debug = getattr(self.func, "emitter_c_truth_debug", {}) or {}
        print("\n===== PAL EMITTER C-TRUTH =====")
        pprint(debug.get("summary", {}))
        print("\n[WARNINGS]")
        pprint(debug.get("warnings", []))
        print("\n[UNRENDERED HELPER CONTRACTS]")
        pprint(debug.get("unrendered_helper_op_keys", []))
        print("\n[UNRENDERED CONTRACT DETAILS]")
        pprint(debug.get("unrendered_contract_details", []))
        if verbose:
            print("\n[HELPER CALL SITES]")
            pprint(debug.get("helper_calls", []))
            print("\n[RAW CONDITION REWRITES]")
            pprint(debug.get("raw_condition_rewrites", []))
            print("\n[RAW CONDITION PROBES]")
            pprint(debug.get("raw_condition_probes", []))
        print("===== END PAL EMITTER C-TRUTH =====")

    def debug_dump_storage_custody(self, verbose=False):

        if not self._debug_reporting_enabled_v46g():
            return
        try:
            from pprint import pprint
        except Exception:
            pprint = print

        debug = getattr(self.func, "emitter_storage_custody_debug", {}) or {}
        print("\n===== PAL EMITTER INDIRECT STORAGE CUSTODY =====")
        pprint(debug.get("summary", {}))
        print("\n[WARNINGS]")
        pprint(debug.get("warnings", []))
        print("\n[RAW INDIRECT LEAKS]")
        pprint(debug.get("raw_indirect_leaks", []))
        print("\n[UNOBSERVED EFFECT OWNERS]")
        pprint(debug.get("unobserved_effect_owner_op_keys", []))
        if verbose:
            print("\n[STORAGE FAMILIES]")
            pprint(debug.get("storage_family_descriptors", []))
            print("\n[INDIRECT METADATA TRANSITIONS]")
            pprint(debug.get("indirect_suppressions", []))
            print("\n[EFFECT OWNERS]")
            pprint(debug.get("effect_owner_render_events", []))
            print("\n[STORAGE READS]")
            pprint(debug.get("storage_read_events", []))
            print("\n[STORAGE WRITES]")
            pprint(debug.get("storage_write_events", []))
            print("\n[PARAMETER STORAGE INITIALIZERS]")
            pprint(debug.get("parameter_storage_initializer_events", []))
        print("===== END PAL EMITTER INDIRECT STORAGE CUSTODY =====")

    def debug_dump_abi_custody(self, verbose=False):

        if not self._debug_reporting_enabled_v46g():
            return
        """Print the final ABI-D/ABI-F emitter-consumer audit."""
        try:
            from pprint import pprint
        except Exception:
            pprint = print

        debug = getattr(self.func, "emitter_abi_custody_debug", {}) or {}
        print("\n===== PAL EMITTER ABI ENTRY / CALL / RETURN CUSTODY =====")
        pprint(debug.get("summary", {}))
        print("\n[WARNINGS]")
        pprint(debug.get("warnings", []))
        print("\n[RAW CONVERGENCE TARGET LEAKS]")
        pprint(debug.get("raw_convergence_target_leaks", []))
        print("\n[AMBIGUOUS LEGACY ABI ALIASES]")
        pprint(debug.get("ambiguous_legacy_aliases", []))
        print("\n[AMBIGUOUS LEGACY ABI ALIAS USES]")
        pprint(debug.get("ambiguous_legacy_alias_uses", []))
        print("\n[INLINE CALL METADATA LEAKS]")
        pprint(debug.get("inline_call_metadata_leaks", []))
        if verbose:
            print("\n[ENTRY MATERIALIZATIONS]")
            pprint(debug.get("entry_materializations", []))
            print("\n[ENTRY SHARED-STORAGE INITIALIZERS]")
            pprint(debug.get("entry_storage_initializers", []))
            print("\n[REJECTED ENTRY STORAGE CANDIDATES]")
            pprint(debug.get("entry_storage_initializer_rejections", []))
            print("\n[CALL SITE RENDER EVENTS]")
            pprint(debug.get("call_render_events", []))
            print("\n[CONVERGENCE ALIASES]")
            pprint(debug.get("convergence_render_events", []))
            print("\n[RETURN BOUNDARIES]")
            pprint(debug.get("return_render_events", []))
        print("===== END PAL EMITTER ABI ENTRY / CALL / RETURN CUSTODY =====")
