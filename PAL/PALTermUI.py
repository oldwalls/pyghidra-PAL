# ============================================================
# PAL TERMINAL UI / ONCS
# BUILD: termui_v10_glitter_stable_linkage_function_filter
# FOUR-PANE MODE: statement_linkage_decoupled_from_object_highlight
# Curses/VT100 PAL root/project/function browser with project-global ONCS
# ============================================================

import argparse
import ast
import builtins
import curses
import curses.textpad
import gzip
import hashlib
import io
import json
import keyword
import os
import re
import sys
import token
import tokenize

# PAL is executed directly from its repository root:
#     cd ../PAL
#     python PALTermUI.py
# Keep that directory first on sys.path and use one-way absolute imports.
PAL_EXEC_ROOT = os.path.dirname(os.path.abspath(__file__))
if PAL_EXEC_ROOT not in sys.path:
    sys.path.insert(0, PAL_EXEC_ROOT)

from PALIcecube import load_document_or_icecube, IcecubeMetadataView
import PALHumanizer
from PALUIDigest import (
    TruthDigestDaily,
    line_from_document_position,
    percentage_document_position,
    projection_hotspots,
)
from PALsplash_v3 import draw_splash, logo_print

PROJECTS_DIRECTORY = "project"
PROJECT_MANIFEST = "PAL_function_manifest.json"
PROJECT_JUMP_TABLE = "PAL_jump_table.json"
PROJECT_DISPATCH = "PAL_dispatch.py"
PROJECT_FUNCTIONS_DIRECTORY = "functions"
PROJECT_NAME_REGISTRY = PALHumanizer.FUNCTION_REGISTRY_FILENAME
ONCS_SIDECAR_FORMAT = "pal_oncs_variable_sidecar"  # standalone-icecube fallback only
ONCS_SIDECAR_SCHEMA = 1

# Common terminal encodings for Ctrl-Tab.  Shift-Tab remains a portable
# fallback because legacy terminals cannot distinguish Ctrl-Tab from Tab.
KEY_CTRL_TAB = 0x1FE
CTRL_TAB_SEQUENCES = (
    "\x1b[27;5;9~",  # xterm modifyOtherKeys
    "\x1b[9;5u",     # CSI-u / kitty keyboard protocol
)


def _display_naming_label(naming):
    mode = str(naming or "humanizer").lower()
    return "humanized" if mode == "humanizer" else mode


def _base_variable_name(contract, naming="humanizer"):
    """Resolve one of the three non-operator ONCS base projections."""
    contract = dict(contract or {})
    mode = str(naming or "humanizer").lower()
    if mode == "ssa":
        return (
            contract.get("canonical_ssa_name")
            or contract.get("pal_name")
            or contract.get("active_name")
        )
    if mode == "pal":
        return (
            contract.get("pal_name")
            or contract.get("canonical_ssa_name")
            or contract.get("active_name")
        )
    if mode == "humanizer":
        return (
            contract.get("generated_human_alias")
            or contract.get("pal_name")
            or contract.get("canonical_ssa_name")
            or contract.get("active_name")
        )
    raise ValueError("unsupported ONCS base naming mode %r" % naming)


# ============================================================================
# DETACHED ONCS NAME LAYER
# ============================================================================


def _read_json_file(path, default=None):
    if not path or not os.path.isfile(path):
        return default
    opener = gzip.open if str(path).lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def _sha256_text(text):
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _oncs_sidecar_path(source_path):
    if not source_path:
        return None
    path = os.path.abspath(os.fspath(source_path))
    lower = path.lower()
    for suffix in (".icecube.json.gz", ".icecube.json", ".json.gz", ".json"):
        if lower.endswith(suffix):
            return path[:-len(suffix)] + ".oncs.json"
    return path + ".oncs.json"


def _mapping_value(value):
    if isinstance(value, dict):
        return value
    if hasattr(value, "as_dict") and callable(value.as_dict):
        try:
            result = value.as_dict()
            return result if isinstance(result, dict) else None
        except Exception:
            return None
    return None


def _walk_contracts(value, depth=0, seen=None):
    if depth > 7:
        return
    if seen is None:
        seen = set()
    marker = id(value)
    if marker in seen:
        return
    seen.add(marker)

    mapping = _mapping_value(value)
    if mapping is not None:
        if (
            mapping.get("canonical_ssa_name")
            and mapping.get("pal_name")
            and (
                mapping.get("kind", "").startswith("resolver_human_alias_contract")
                or "oncs" in mapping
                or "generated_human_alias" in mapping
            )
        ):
            yield dict(mapping)
        for child in mapping.values():
            yield from _walk_contracts(child, depth + 1, seen)
        return

    if isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _walk_contracts(child, depth + 1, seen)


def _existing_oncs_contracts(document):
    roots = []
    for name in (
        "human_alias_contracts", "variable_alias_contracts", "alias_contracts",
        "oncs_contracts", "humanizer_contracts", "metadata",
    ):
        value = getattr(document, name, None)
        if value is not None:
            roots.append(value)
    dictionary = getattr(document, "__dict__", None)
    if isinstance(dictionary, dict):
        for name in (
            "human_alias_contracts", "variable_alias_contracts", "alias_contracts",
            "oncs_contracts", "metadata",
        ):
            if name in dictionary:
                roots.append(dictionary[name])

    contracts = {}
    for root in roots:
        for contract in _walk_contracts(root):
            sid = str(contract.get("canonical_ssa_name") or contract.get("sid") or "")
            if sid:
                contracts[sid] = contract
    return contracts


def _metadata_variable_records(document):
    """Best-effort variable records; ONCS does not require icecube metadata."""
    metadata = getattr(document, "metadata", None)
    references = set()

    projections = getattr(document, "projections", {})
    views = projections.values() if isinstance(projections, dict) else []
    for view in list(views or []):
        for statement in list(getattr(view, "statements", []) or []):
            for reference in list(getattr(statement, "metadata_refs", []) or []):
                references.add(str(reference))
            for attr in ("definition_sids", "use_sids"):
                for sid in list(getattr(statement, attr, []) or []):
                    references.add("variable:%s" % sid)

    roots = []
    resolver = getattr(metadata, "resolve", None)
    if callable(resolver):
        for reference in sorted(references):
            try:
                value = resolver(reference, None)
            except TypeError:
                try:
                    value = resolver(reference)
                except Exception:
                    value = None
            except Exception:
                value = None
            if value is not None:
                roots.append(value)

    for owner in (document, metadata):
        if owner is None:
            continue
        for attr in (
            "records", "entries", "payload", "data", "_records", "_entries",
            "variables", "variable_records", "metadata",
        ):
            value = getattr(owner, attr, None)
            if value is not None:
                roots.append(value)
        dictionary = getattr(owner, "__dict__", None)
        if isinstance(dictionary, dict):
            roots.append(dictionary)

    found = {}
    seen = set()

    def walk(value, depth=0):
        if depth > 7 or id(value) in seen:
            return
        seen.add(id(value))
        mapping = _mapping_value(value)
        if mapping is not None:
            sid = (
                mapping.get("sid")
                or mapping.get("canonical_ssa_name")
                or mapping.get("ssa_id")
            )
            name = (
                mapping.get("pal_name")
                or mapping.get("display_name")
                or mapping.get("name")
                or mapping.get("original_name")
            )
            if sid is not None and name is not None:
                key = str(sid)
                prior = found.setdefault(key, {})
                prior.update(mapping)
                prior.setdefault("sid", key)
                prior.setdefault("display_name", str(name))
            for child in mapping.values():
                walk(child, depth + 1)
        elif isinstance(value, (list, tuple, set)):
            for child in value:
                walk(child, depth + 1)

    for root in roots:
        walk(root)
    return found


def _document_projection_lines(document, projection):
    for call in (
        lambda: document.export_lines(projection, naming="pal", include_edits=True),
        lambda: document.export_lines(projection, naming="pal"),
        lambda: document.project_alias_lines(projection, naming="pal"),
    ):
        try:
            result = call()
            if result is not None:
                return [str(line) for line in list(result)]
        except Exception:
            pass
    view = document.projection(projection)
    return [str(line) for line in list(getattr(view, "lines", []) or [])]


def _python_name_facts(lines):
    source = "\n".join(str(line) for line in lines)
    parameters = []
    parameter_set = set()
    function_defs = set()
    call_targets = set()
    names = set()

    try:
        tree = ast.parse(source or "pass\n")
    except SyntaxError:
        tree = None

    if tree is not None:
        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                function_defs.add(node.name)
                ordered = (
                    list(getattr(node.args, "posonlyargs", []) or [])
                    + list(node.args.args)
                    + list(node.args.kwonlyargs)
                )
                if node.args.vararg is not None:
                    ordered.append(node.args.vararg)
                if node.args.kwarg is not None:
                    ordered.append(node.args.kwarg)
                for argument in ordered:
                    if argument.arg not in parameter_set:
                        parameter_set.add(argument.arg)
                        parameters.append(argument.arg)
                self.generic_visit(node)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    call_targets.add(node.func.id)
                self.generic_visit(node)

            def visit_Name(self, node):
                names.add(node.id)

        Visitor().visit(tree)

    ordered_names = []
    seen = set()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source + "\n").readline)
        for item in tokens:
            if item.type != token.NAME:
                continue
            value = item.string
            if value not in seen:
                seen.add(value)
                ordered_names.append(value)
    except (IndentationError, SyntaxError, tokenize.TokenError):
        ordered_names = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", source)

    excluded = (
        set(keyword.kwlist)
        | set(dir(builtins))
        | function_defs
        | call_targets
        | {"True", "False", "None", "MEM", "self", "cls"}
    )
    variables = []
    for value in parameters + ordered_names:
        if value in variables or value in excluded:
            continue
        if value.startswith("c_"):
            continue
        if value not in names and value not in parameter_set:
            continue
        variables.append(value)
    return {
        "parameters": parameters,
        "function_defs": function_defs,
        "call_targets": call_targets,
        "variables": variables,
    }


def _replace_name_tokens(lines, mapping):
    lines = [str(line) for line in list(lines or [])]
    if not mapping:
        return lines
    source = "\n".join(lines) + "\n"
    replacements = {}
    try:
        for item in tokenize.generate_tokens(io.StringIO(source).readline):
            if item.type != token.NAME or item.string not in mapping:
                continue
            if item.start[0] != item.end[0]:
                continue
            replacements.setdefault(item.start[0] - 1, []).append(
                (item.start[1], item.end[1], str(mapping[item.string]))
            )
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return [
            re.sub(
                r"\b(?:%s)\b" % "|".join(
                    re.escape(name) for name in sorted(mapping, key=len, reverse=True)
                ),
                lambda match: mapping.get(match.group(0), match.group(0)),
                line,
            ) if mapping else line
            for line in lines
        ]

    output = list(lines)
    for line_number, spans in replacements.items():
        text = output[line_number]
        for start, end, replacement in sorted(spans, reverse=True):
            text = text[:start] + replacement + text[end:]
        output[line_number] = text
    return output


def _line_token_spans(line, mapping):
    spans = []
    try:
        for item in tokenize.generate_tokens(io.StringIO(str(line) + "\n").readline):
            if item.type == token.NAME and item.string in mapping:
                spans.append((item.start[1], item.end[1], str(mapping[item.string])))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        pass
    delta = 0
    result = []
    for start, end, replacement in sorted(spans):
        display_start = start + delta
        display_end = display_start + len(replacement)
        result.append((start, end, display_start, display_end))
        delta += len(replacement) - (end - start)
    return result


class ONCSNameState:
    """Humanizer-backed ONCS projections with project-global persistence."""

    NAMING_MODES = ("ssa", "pal", "humanizer")

    def __init__(
        self, document, source_path=None, function_record=None,
        project_store=None,
    ):
        self.document = document
        self.source_path = os.fspath(source_path) if source_path else None
        self.project_store = project_store
        self.sidecar_path = (
            project_store.path if project_store is not None
            else _oncs_sidecar_path(self.source_path)
        )
        self.function_record = dict(function_record or {})
        self.function_id = str(
            self.function_record.get("function_id")
            or (
                project_store.function_id_for_record(self.function_record)
                if project_store is not None and self.function_record
                else PALHumanizer.function_identity(
                    self.function_record or {
                        "name": getattr(document, "function_name", "function")
                    }
                )
            )
        )
        self.function_names = (
            project_store.function_names() if project_store is not None else set()
        )
        self.existing_contracts = _existing_oncs_contracts(document)
        self.operator_aliases = {
            sid: str(contract.get("operator_alias"))
            for sid, contract in self.existing_contracts.items()
            if contract.get("operator_alias")
        }
        self.revisions = []
        self.revision = 0
        self.status = "ONCS generated"
        self._base_cache = {}
        self._load_operator_state()
        self._build_variables()
        self._rebuild()

    def _load_operator_state(self):
        if self.project_store is not None:
            self.operator_aliases.update(
                self.project_store.variable_operator_aliases(self.function_id)
            )
            state = dict(
                self.project_store.variable_state.get(self.function_id, {}) or {}
            )
            self.revisions = list(state.get("revisions", []) or [])
            self.revision = int(state.get("revision", 0) or 0)
            self.status = "project PAL_ONCS loaded"
            return

        payload = _read_json_file(self.sidecar_path, {}) or {}
        if not payload:
            return
        if payload.get("format") != ONCS_SIDECAR_FORMAT:
            raise ValueError("unsupported ONCS sidecar format: %s" % self.sidecar_path)
        owner = str(payload.get("function_identity") or "")
        if owner and owner != self.function_id:
            raise ValueError(
                "ONCS sidecar belongs to %s, not %s" % (owner, self.function_id)
            )
        self.operator_aliases.update({
            str(key): str(value)
            for key, value in dict(payload.get("operator_aliases", {}) or {}).items()
            if value
        })
        self.revisions = list(payload.get("revisions", []) or [])
        self.revision = int(payload.get("revision", 0) or 0)
        self.status = "standalone ONCS sidecar loaded"

    def base_lines(self, projection):
        projection = str(projection)
        if projection not in self._base_cache:
            self._base_cache[projection] = _document_projection_lines(
                self.document, projection
            )
        return list(self._base_cache[projection])

    def _build_variables(self):
        combined = []
        projections = getattr(self.document, "projections", {})
        names = list(projections) if isinstance(projections, dict) else []
        if not names:
            names = ["readable", "executable"]
        for projection in names:
            try:
                combined.extend(self.base_lines(projection))
            except Exception:
                pass
        facts = _python_name_facts(combined)
        parameter_index = {
            name: index for index, name in enumerate(facts["parameters"])
        }

        metadata_records = _metadata_variable_records(self.document)
        existing_by_name = {}
        for sid, record in (
            list(metadata_records.items()) + list(self.existing_contracts.items())
        ):
            for key in (
                "pal_name", "display_name", "name", "original_name",
                "canonical_ssa_name", "ssa_id", "generated_human_alias",
                "operator_alias", "active_name",
            ):
                value = record.get(key)
                if value:
                    existing_by_name.setdefault(str(value), str(sid))

        variables = []
        used_sids = set()
        for name in facts["variables"]:
            sid = str(existing_by_name.get(name) or name)
            if sid in used_sids:
                continue
            used_sids.add(sid)
            metadata_record = dict(metadata_records.get(sid, {}) or {})
            prior = dict(self.existing_contracts.get(sid, {}) or {})
            pal_name = str(
                prior.get("pal_name")
                or metadata_record.get("pal_name")
                or metadata_record.get("display_name")
                or metadata_record.get("name")
                or name
            )
            index = prior.get("parameter_index")
            if not isinstance(index, int):
                for key in ("parameter_index", "ordinal", "parameter_ordinal"):
                    value = metadata_record.get(key)
                    if isinstance(value, int):
                        index = value
                        break
            if not isinstance(index, int):
                index = parameter_index.get(name)

            item = dict(metadata_record)
            item.update({
                "sid": sid,
                "display_name": pal_name,
                "is_parameter": bool(
                    index is not None
                    or prior.get("is_parameter")
                    or metadata_record.get("is_parameter")
                    or metadata_record.get("is_callable_parameter")
                ),
                "parameter_index": index,
            })
            if (
                prior.get("rename_locked")
                or prior.get("humanization_eligible") is False
            ):
                item["is_abi_physical_carrier"] = True
            variables.append(item)

        for sid, prior in sorted(self.existing_contracts.items()):
            if sid in used_sids:
                continue
            pal_name = str(prior.get("pal_name") or sid)
            variables.append({
                "sid": sid,
                "display_name": pal_name,
                "is_parameter": bool(prior.get("is_parameter")),
                "parameter_index": prior.get("parameter_index"),
                "is_abi_physical_carrier": bool(
                    prior.get("rename_locked")
                    or prior.get("humanization_eligible") is False
                ),
            })
        self.variables = variables
        self.call_targets = set(facts["call_targets"])
        self.function_defs = set(facts["function_defs"])

    def set_function_names(self, names):
        self.function_names = set(str(value) for value in (names or ()) if value)
        self._rebuild()

    def _rebuild(self, proposed_sid=None):
        contracts, inventory = PALHumanizer.build_variable_alias_contracts(
            self.variables,
            self.function_id,
            operator_aliases=self.operator_aliases,
            function_names=self.function_names,
        )
        if proposed_sid is not None:
            contract = contracts.get(str(proposed_sid), {})
            if not contract.get("operator_alias"):
                conflicts = [
                    item for item in inventory.get("operator_alias_conflicts", [])
                    if str(item.get("sid")) == str(proposed_sid)
                ]
                reason = (
                    conflicts[0].get("reason")
                    if conflicts else "operator alias rejected"
                )
                raise ValueError(reason)
        self.contracts = contracts
        self.inventory = inventory
        self._index_contract_names()
        return contracts

    def _index_contract_names(self):
        owners = {}
        ambiguous = set()
        for sid, contract in self.contracts.items():
            names = {
                contract.get("canonical_ssa_name"),
                contract.get("pal_name"),
                contract.get("generated_human_alias"),
                contract.get("operator_alias"),
                contract.get("active_name"),
            }
            for value in names:
                if not value:
                    continue
                value = str(value)
                prior = owners.get(value)
                if prior is not None and prior != sid:
                    ambiguous.add(value)
                else:
                    owners[value] = sid
        for value in ambiguous:
            owners.pop(value, None)
        self.name_owner = owners

    def variable_mapping(self, naming, operator_overlay=False):
        naming = str(naming or "humanizer").lower()
        if naming not in self.NAMING_MODES:
            raise ValueError("unsupported ONCS naming mode %r" % naming)
        mapping = {}
        for contract in self.contracts.values():
            pal = contract.get("pal_name")
            if not pal:
                continue
            target = _base_variable_name(contract, naming)
            if operator_overlay and contract.get("operator_alias"):
                target = contract.get("operator_alias")
            if pal != target:
                mapping[str(pal)] = str(target)
        return mapping

    def function_mapping(self, naming, operator_overlay=False):
        if self.project_store is None:
            return {}
        mapping = self.project_store.function_mapping(
            naming=naming, current_function_id=self.function_id
        )
        if not operator_overlay:
            return mapping

        # Overlay only explicit operator names.  Unedited function names keep
        # the selected SSA/PAL/Humanizer base projection.
        registry = getattr(self.project_store, "function_registry", None)
        records = getattr(registry, "records", {}) if registry is not None else {}
        for fid, record in dict(records or {}).items():
            target = record.get("operator_name")
            if not target:
                continue
            for source in (
                record.get("ssa_name"), record.get("original_name"),
                record.get("qualified_name"), record.get("python_symbol"),
            ):
                if source:
                    mapping[str(source)] = str(target)
        return mapping

    def display_mapping(self, naming, operator_overlay=False):
        mapping = self.variable_mapping(naming, operator_overlay)
        for source, target in self.function_mapping(naming, operator_overlay).items():
            if source not in mapping:
                mapping[source] = target
        return mapping

    def render_lines(self, projection, naming, operator_overlay=False):
        return _replace_name_tokens(
            self.base_lines(projection),
            self.display_mapping(naming, operator_overlay),
        )

    def display_to_pal_column(
        self, projection, naming, line, column, operator_overlay=False
    ):
        base = self.base_lines(projection)
        if not base or line < 0 or line >= len(base):
            return max(0, int(column))
        spans = _line_token_spans(
            base[line], self.display_mapping(naming, operator_overlay)
        )
        column = max(0, int(column))
        delta = 0
        for base_start, base_end, display_start, display_end in spans:
            if column < display_start:
                return max(0, column - delta)
            if display_start <= column <= display_end:
                return base_start + min(
                    column - display_start, base_end - base_start
                )
            delta += (display_end - display_start) - (base_end - base_start)
        return max(0, column - delta)

    def pal_to_display_column(
        self, projection, naming, line, column, operator_overlay=False
    ):
        base = self.base_lines(projection)
        if not base or line < 0 or line >= len(base):
            return max(0, int(column))
        spans = _line_token_spans(
            base[line], self.display_mapping(naming, operator_overlay)
        )
        column = max(0, int(column))
        delta = 0
        for base_start, base_end, display_start, display_end in spans:
            if column < base_start:
                return max(0, column + delta)
            if base_start <= column <= base_end:
                return display_start + min(
                    column - base_start, display_end - display_start
                )
            delta += (display_end - display_start) - (base_end - base_start)
        return max(0, column + delta)

    def contract_for_identifier(self, identifier):
        sid = self.name_owner.get(str(identifier or ""))
        return self.contracts.get(sid) if sid else None

    def contract_at(
        self, projection, naming, line, column, operator_overlay=False
    ):
        lines = self.render_lines(projection, naming, operator_overlay)
        if not lines or line < 0 or line >= len(lines):
            return None
        identifier = PALHumanizer.identifier_at_column(lines[line], column)
        return self.contract_for_identifier(identifier)

    def rename(self, sid, alias, author="human"):
        sid = str(sid)
        contract = self.contracts.get(sid)
        if contract is None:
            raise KeyError("unknown ONCS variable identity %s" % sid)
        if contract.get("rename_locked"):
            raise ValueError("rename locked: %s" % (
                contract.get("humanization_exclusion_reason")
                or "structural semantic identity"
            ))
        previous = self.operator_aliases.get(sid)
        self.operator_aliases[sid] = str(alias)
        try:
            self._rebuild(proposed_sid=sid)
        except Exception:
            if previous is None:
                self.operator_aliases.pop(sid, None)
            else:
                self.operator_aliases[sid] = previous
            self._rebuild()
            raise
        normalized = self.contracts[sid].get("operator_alias")
        self.operator_aliases[sid] = normalized
        self.revision += 1
        self.revisions.append({
            "kind": "pal_oncs_variable_revision_v2",
            "revision": self.revision,
            "sid": sid,
            "previous": previous,
            "current": normalized,
            "author": str(author or "human"),
        })
        self.status = "%s -> %s" % (sid, normalized)
        return normalized

    def clear(self, sid, author="human"):
        sid = str(sid)
        previous = self.operator_aliases.pop(sid, None)
        if previous is None:
            return None
        self._rebuild()
        self.revision += 1
        self.revisions.append({
            "kind": "pal_oncs_variable_revision_v2",
            "revision": self.revision,
            "sid": sid,
            "previous": previous,
            "current": None,
            "author": str(author or "human"),
        })
        self.status = "%s reverted to Humanizer" % sid
        return previous

    def as_dict(self):
        return {
            "format": ONCS_SIDECAR_FORMAT,
            "schema_version": ONCS_SIDECAR_SCHEMA,
            "humanizer_version": PALHumanizer.HUMANIZER_VERSION,
            "function_identity": self.function_id,
            "source_icecube": self.source_path,
            "revision": self.revision,
            "operator_aliases": dict(sorted(self.operator_aliases.items())),
            "revisions": list(self.revisions),
            "inventory": self.inventory,
            "contracts": {
                sid: dict(contract)
                for sid, contract in sorted(self.contracts.items())
            },
            "icecube_metadata_mutated": False,
            "rule": "ONCS projections over immutable PAL/SSA identities",
        }

    def save(self, path=None):
        if self.project_store is not None:
            self.project_store.set_variable_operator_aliases(
                self.function_id, self.operator_aliases
            )
            target = self.project_store.save()
            self.status = "project PAL_ONCS saved; icecube unchanged"
            return _sha256_file(target)

        target = os.path.abspath(
            os.fspath(path or self.sidecar_path or "pal.oncs.json")
        )
        _atomic_write_json(target, self.as_dict())
        self.sidecar_path = target
        self.status = "standalone ONCS sidecar saved %s" % target
        return _sha256_file(target)



def format_truth_digest_panel(data, panel="variables"):
    data = dict(data or {})
    panels = dict(data.get("panels", {}) or {})
    function = dict(data.get("function", {}) or {})
    cursor = dict(data.get("cursor", {}) or {})
    title = {
        "c_code": "F1 C CODE",
        "function_definition": "F2 FUNCTION DEFINITION",
        "variables": "F3 VARIABLES / ONCS",
        "abi_custody": "F4 ABI CUSTODY INTERFACES",
    }.get(panel, str(panel).upper())
    lines = [
        "TRUTH DIGEST DAILY",
        "==================",
        "%s | function=%s | %s/%s | line=%s col=%s" % (
            title,
            function.get("active_name") or function.get("pal_name")
            or function.get("original_name") or "function",
            cursor.get("projection", "-"), cursor.get("naming", "-"),
            int(cursor.get("line", 0)) + 1, int(cursor.get("column", 0)) + 1,
        ),
        "",
    ]
    if panel != "variables":
        lines.extend(str(value) for value in list(panels.get(panel, []) or []))
        lines.extend([
            "",
            "Metadata source is deferred; this panel is an explicit sim shim.",
        ])
        return lines

    variables = list(panels.get("variables", []) or [])
    selected = [item for item in variables if item.get("selected")]
    if selected:
        item = selected[0]
        lines.extend([
            "FOCUS",
            "-----",
            "SSA=%s | PAL=%s | HUMAN=%s | OPERATOR=%s" % (
                item.get("sid"), item.get("pal"),
                item.get("humanizer") or "-", item.get("operator") or "-",
            ),
            "ACTIVE=%s [%s]%s" % (
                item.get("active"), item.get("source"),
                " LOCKED: %s" % item.get("lock_reason")
                if item.get("rename_locked") else "",
            ),
            "",
        ])
    else:
        lines.extend(["FOCUS", "-----", "cursor is not on an ONCS variable", ""])

    lines.extend(["VARIABLE DIGEST", "---------------"])
    for item in variables:
        marker = ">" if item.get("selected") else " "
        role = (
            "p%d" % item.get("parameter_index")
            if isinstance(item.get("parameter_index"), int) else "var"
        )
        lock = "LOCK" if item.get("rename_locked") else item.get("source") or "pal"
        lines.append(
            "%s %-4s %-16s -> %-16s [%s]" % (
                marker, role, item.get("pal") or item.get("sid"),
                item.get("active") or item.get("pal") or item.get("sid"), lock,
            )
        )
    inventory = dict(data.get("inventory", {}) or {})
    lines.extend([
        "",
        "count=%s parameters=%s editable=%s locked=%s operator=%s" % (
            inventory.get("variables", len(variables)),
            inventory.get("parameters", 0), inventory.get("eligible", 0),
            inventory.get("excluded", 0), inventory.get("operator_aliases", 0),
        ),
        "",
        "F1 C code | F2 function | F3 variables | F4 ABI | R raw | Esc close",
    ])
    return lines

def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path, payload):
    path = os.path.abspath(os.fspath(path))
    temp = "%s.tmp.%d" % (path, os.getpid())
    try:
        with open(temp, "wt", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return path


class PALTerminalModel:
    """Terminal-independent ONCS view over a detached PAL document."""

    PROJECTIONS = ("readable", "executable")
    NAMING_MODES = ONCSNameState.NAMING_MODES

    def __init__(
        self, document, source_path=None, function_record=None,
        project_store=None,
    ):
        self.document = document
        self.source_path = os.fspath(source_path) if source_path else None
        self.projection = (
            "readable" if document.projection("readable") is not None
            else sorted(document.projections)[0]
        )
        self.naming = "pal"
        self.operator_overlay = True
        self.line = 0
        self.column = 0
        self.top_line = 0
        self.left_column = 0
        self.status = "icecube loaded; ONCS active; Truth Digest ready"
        self.warning = None
        self.function_record = dict(function_record or {})
        self.project_store = project_store
        self.oncs = ONCSNameState(
            document,
            source_path=self.source_path,
            function_record=self.function_record,
            project_store=project_store,
        )
        self.highlight_sid = None
        self.object_focus = None
        self.cursor_context = {}
        self.cursor_contract_sid = None
        self.update_cursor_context()

    @classmethod
    def from_path(
        cls, path, verify=True, function_record=None, project_store=None
    ):
        return cls(
            load_document_or_icecube(path, verify=verify),
            source_path=path,
            function_record=function_record,
            project_store=project_store,
        )

    def naming_label(self):
        base = {
            "ssa": "SSA", "pal": "PAL", "humanizer": "HUMANIZED",
        }.get(self.naming, _display_naming_label(self.naming))
        return "%s+Oper" % base if self.operator_overlay else base

    def lines(self):
        self.warning = None
        try:
            return self.oncs.render_lines(
                self.projection, self.naming, self.operator_overlay
            )
        except Exception as exc:
            self.warning = "ONCS projection failed: %s" % exc
            return self.oncs.base_lines(self.projection)

    def current_line_text(self):
        lines = self.lines()
        if not lines:
            return ""
        self.line = min(max(self.line, 0), len(lines) - 1)
        return lines[self.line]

    def clamp(self):
        lines = self.lines()
        if not lines:
            self.line = self.column = 0
            return
        self.line = min(max(self.line, 0), len(lines) - 1)
        self.column = min(max(self.column, 0), len(lines[self.line]))

    def switch_projection(self):
        target = "executable" if self.projection == "readable" else "readable"
        if self.document.projection(target) is None:
            self.status = "projection %s is unavailable" % target
            return False
        source_base_column = self.oncs.display_to_pal_column(
            self.projection, self.naming, self.line, self.column,
            self.operator_overlay,
        )
        target_line = self.line
        target_base_column = source_base_column
        reason = "same_line_fallback"
        try:
            mapping = self.document.sync_cursor(
                self.projection,
                target,
                self.line,
                source_base_column,
                source_naming="pal",
                target_naming="pal",
            )
            if mapping.get("matched"):
                target_line = int(mapping["target_view"]["line"])
                target_base_column = int(mapping["target_view"]["column"])
                reason = mapping.get("reason") or "paired_statement"
        except Exception:
            pass
        self.projection = target
        target_lines = self.oncs.base_lines(target)
        if target_lines:
            self.line = min(max(target_line, 0), len(target_lines) - 1)
            self.column = self.oncs.pal_to_display_column(
                target, self.naming, self.line, target_base_column,
                self.operator_overlay,
            )
        else:
            self.line = self.column = 0
        self.status = "F1 %s (%s)" % (target, reason)
        self.clamp()
        return True

    def cycle_naming(self):
        index = self.NAMING_MODES.index(self.naming)
        self.naming = self.NAMING_MODES[(index + 1) % len(self.NAMING_MODES)]
        self.column = min(self.column, len(self.current_line_text()))
        suffix = "+OPER" if self.operator_overlay else ""
        self.status = "F2 ONCS naming: %s%s" % (
            _display_naming_label(self.naming), suffix
        )
        return self.naming

    def toggle_operator_overlay(self, enabled=None):
        if enabled is None:
            self.operator_overlay = not self.operator_overlay
        else:
            self.operator_overlay = bool(enabled)
        self.column = min(self.column, len(self.current_line_text()))
        self.status = (
            "operator labels ON over %s" % _display_naming_label(self.naming)
            if self.operator_overlay
            else "operator labels OFF; base=%s" % _display_naming_label(self.naming)
        )
        return self.operator_overlay

    def current_contract(self):
        """Return the exact editable variable identity under the cursor.

        Display spellings such as ``local_14`` are not globally unique: several
        SSA identities may intentionally collapse into one PAL local.  The ONCS
        spelling index therefore rejects ambiguous names.  When that happens,
        recover the exact SID from the object-aware Icecube hotspot beneath the
        cursor instead of pretending the displayed token has no contract.
        """
        contract = self.oncs.contract_at(
            self.projection, self.naming, self.line, self.column,
            self.operator_overlay,
        )
        if contract is not None:
            return contract
        focus = self.cursor_object_context(
            self.projection, self.line, self.column
        )
        if not focus or str(focus.get("kind") or "") != "variable":
            return None
        sid = str(focus.get("sid") or focus.get("identity") or "")
        return self.oncs.contracts.get(sid)

    def current_mode_variable_name(self, contract=None):
        """Name shown by the active SSA/PAL/Humanized + operator projection."""
        contract = dict(contract or self.current_contract() or {})
        if not contract:
            return None
        if self.operator_overlay and contract.get("operator_alias"):
            return str(contract.get("operator_alias"))
        value = _base_variable_name(contract, self.naming)
        return str(value) if value else None

    def rename_current_variable(self, alias, author="human"):
        contract = self.current_contract()
        if contract is None:
            raise ValueError(
                "cursor is not on an editable variable; function calls and structural labels are locked"
            )
        value = self.oncs.rename(contract["sid"], alias, author=author)
        self.operator_overlay = True
        self.oncs.save()
        self.status = "operator alias saved: %s" % value
        return value

    def revert_current_variable(self, author="human"):
        contract = self.current_contract()
        if contract is None:
            self.status = "cursor is not on an ONCS variable"
            return None
        previous = self.oncs.clear(contract["sid"], author=author)
        if previous is not None:
            self.oncs.save()
        self.status = (
            "operator alias reverted and saved" if previous
            else "variable has no operator alias"
        )
        return previous

    def toggle_highlight(self):
        self.object_focus = None
        contract = self.current_contract()
        if contract is None:
            self.highlight_sid = None
            self.status = "focus cleared; cursor is not on an ONCS variable"
            return None
        sid = contract["sid"]
        self.highlight_sid = None if self.highlight_sid == sid else sid
        self.status = (
            "focus cleared" if self.highlight_sid is None
            else "focus variable %s" % sid
        )
        return self.highlight_sid

    def highlight_name(self):
        if self.highlight_sid is None:
            return None
        contract = self.oncs.contracts.get(self.highlight_sid, {})
        if self.operator_overlay and contract.get("operator_alias"):
            return contract.get("operator_alias")
        return _base_variable_name(contract, self.naming)

    def _display_identifier_at(self, projection, line, column):
        try:
            lines = self.oncs.render_lines(
                projection, self.naming, self.operator_overlay
            )
            if line < 0 or line >= len(lines):
                return None
            return PALHumanizer.identifier_at_column(lines[line], column)
        except Exception:
            return None

    @staticmethod
    def _focus_key(focus):
        focus = dict(focus or {})
        return (
            str(focus.get("kind") or "object"),
            str(focus.get("identity") or focus.get("metadata_ref") or ""),
        )

    def cursor_object_context(self, projection=None, line=None, column=None):
        """Resolve the stable object identity under a rendered cursor.

        Variable contracts are authoritative.  Other objects are resolved from
        the object-aware Icecube hotspot map and therefore remain tied to frozen
        metadata rather than to a coincidentally matching token spelling.
        """
        projection = projection or self.projection
        line = self.line if line is None else int(line)
        column = self.column if column is None else int(column)
        try:
            contract = self.oncs.contract_at(
                projection, self.naming, line, column,
                self.operator_overlay,
            )
        except Exception:
            contract = None
        if contract is not None:
            return {
                "kind": "variable",
                "identity": str(contract.get("sid")),
                "sid": str(contract.get("sid")),
                "names": [
                    str(value) for value in (
                        contract.get("canonical_ssa_name"),
                        contract.get("pal_name"),
                        contract.get("generated_human_alias"),
                        contract.get("operator_alias"),
                        contract.get("active_name"),
                    ) if value
                ],
            }

        try:
            base_column = self.oncs.display_to_pal_column(
                projection, self.naming, line, column,
                self.operator_overlay,
            )
        except Exception:
            base_column = column
        identifier = self._display_identifier_at(projection, line, column)
        candidates = [
            item for item in list(projection_hotspots(
                self.document, projection
            ) or [])
            if int(item.get("line", -1)) == line
            and dict(item.get("object_context", {}) or {})
        ]
        chosen = None
        for item in candidates:
            start = int(item.get("column", 0))
            end = max(start + 1, int(item.get("end_column", start + 1)))
            if start <= base_column < end:
                chosen = item
                break
        if chosen is None and identifier:
            for item in candidates:
                token_name = item.get("token")
                context = dict(item.get("object_context", {}) or {})
                names = set(str(value) for value in context.get("names", []) or [])
                if identifier == token_name or identifier in names:
                    chosen = item
                    break
        if chosen is not None:
            context = dict(chosen.get("object_context", {}) or {})
            focus = {
                "kind": str(context.get("kind") or "object"),
                "identity": str(
                    context.get("identity")
                    or context.get("metadata_ref")
                    or chosen.get("token")
                ),
                "metadata_ref": context.get("metadata_ref"),
                "role": context.get("role"),
                "names": list(context.get("names", []) or []),
                "token": chosen.get("token") or identifier,
            }
            if focus["kind"] == "variable":
                focus["sid"] = focus["identity"]
            return focus

        # Some newer Icecubes expose the object directly through describe_cursor
        # even when the projection statement did not freeze an explicit span.
        try:
            described = self.document.describe_cursor(
                projection, line, base_column, line_base=0
            )
            raw = dict(described.get("context", {}) or {})
        except Exception:
            raw = {}
        for key in ("object_context", "tagged_object", "object"):
            context = raw.get(key)
            if not isinstance(context, dict):
                continue
            identity = (
                context.get("identity") or context.get("object_id")
                or context.get("sid") or context.get("id")
            )
            if identity is None:
                continue
            return {
                "kind": str(context.get("kind") or "object"),
                "identity": str(identity),
                "metadata_ref": context.get("metadata_ref"),
                "names": [
                    str(value) for value in list(context.get("names", []) or [])
                    if value
                ],
                "token": identifier,
            }
        return None

    def update_cursor_context(self):
        """Commit cursor position into metadata/rename/truth-preview context."""
        self.clamp()
        try:
            contract = self.current_contract()
        except Exception:
            contract = None
        self.cursor_contract_sid = (
            str(contract.get("sid")) if contract is not None else None
        )
        try:
            self.cursor_context = self._cursor_context()
        except Exception:
            self.cursor_context = {
                "projection": self.projection,
                "line": self.line,
                "column": self.column,
            }
        return dict(self.cursor_context)

    def toggle_object_focus(self, projection=None, line=None, column=None):
        focus = self.cursor_object_context(projection, line, column)
        if focus is None:
            # ENTER on untagged space is an explicit clear operation.  Clear the
            # legacy SID highlight too; otherwise four-pane rendering continues
            # to paint the previous variable after object_focus has disappeared.
            self.object_focus = None
            self.highlight_sid = None
            self.status = "object-context focus cleared; no tag under cursor"
            return None
        if self._focus_key(self.object_focus) == self._focus_key(focus):
            old = dict(self.object_focus or {})
            self.object_focus = None
            if (
                old.get("kind") == "variable"
                and self.highlight_sid == str(old.get("sid") or "")
            ):
                self.highlight_sid = None
            self.status = "object-context focus cleared"
            return None
        self.object_focus = focus
        if focus.get("kind") == "variable" and focus.get("sid"):
            self.highlight_sid = str(focus["sid"])
        else:
            self.highlight_sid = None
        self.status = "object focus: %s %s" % self._focus_key(focus)
        return dict(focus)

    def object_focus_names(self, projection=None):
        focus = dict(self.object_focus or {})
        names = set(str(value) for value in focus.get("names", []) or [] if value)
        if focus.get("token"):
            names.add(str(focus["token"]))
        sid = focus.get("sid")
        if sid:
            contract = dict(self.oncs.contracts.get(str(sid), {}) or {})
            for key in (
                "canonical_ssa_name", "pal_name", "generated_human_alias",
                "operator_alias", "active_name",
            ):
                value = contract.get(key)
                if value:
                    names.add(str(value))
            value = (
                contract.get("operator_alias")
                if self.operator_overlay and contract.get("operator_alias")
                else _base_variable_name(contract, self.naming)
            )
            if value:
                names.add(str(value))
        try:
            mapping = self.oncs.display_mapping(
                self.naming, self.operator_overlay
            )
        except Exception:
            mapping = {}
        for source, target in dict(mapping or {}).items():
            if str(source) in names or str(target) in names:
                names.add(str(source))
                names.add(str(target))
        return {
            value for value in names
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)
        }

    def object_focus_label(self):
        if not self.object_focus:
            return None
        kind, identity = self._focus_key(self.object_focus)
        return "%s:%s" % (kind, identity)

    def hotspots(self, projection=None):
        return projection_hotspots(
            self.document, projection or self.projection
        )

    def move_hotspot(self, step=1):
        hotspots = list(self.hotspots() or [])
        if not hotspots:
            self.status = "icecube has no active hotspots for %s" % self.projection
            return None
        current = (int(self.line), int(self.column))
        if int(step) >= 0:
            candidates = [
                item for item in hotspots
                if (int(item.get("line", 0)), int(item.get("column", 0))) > current
            ]
            target = candidates[0] if candidates else hotspots[0]
        else:
            candidates = [
                item for item in hotspots
                if (int(item.get("line", 0)), int(item.get("column", 0))) < current
            ]
            target = candidates[-1] if candidates else hotspots[-1]
        self.line = int(target.get("line", 0))
        base_column = int(target.get("column", 0))
        try:
            self.column = self.oncs.pal_to_display_column(
                self.projection, self.naming, self.line, base_column,
                self.operator_overlay,
            )
        except Exception:
            self.column = base_column
        self.clamp()
        self.update_cursor_context()
        self.status = "hotspot %d/%d: %s line %d" % (
            hotspots.index(target) + 1,
            len(hotspots),
            self.projection,
            self.line + 1,
        )
        return target

    def _cursor_context(self):
        context = {
            "projection": self.projection,
            "naming": self.naming_label(),
            "line": self.line,
            "column": self.column,
            "cfg_block_addr": None,
            "source_path": self.source_path,
            "percentage_document_position": percentage_document_position(
                self.line, len(self.lines())
            ),
        }
        try:
            base_column = self.oncs.display_to_pal_column(
                self.projection, self.naming, self.line, self.column,
                self.operator_overlay,
            )
            described = self.document.describe_cursor(
                self.projection, self.line, base_column, line_base=0
            )
            raw_context = dict(described.get("context", {}) or {})
            context.update({
                "cfg_block_addr": raw_context.get("cfg_block_addr"),
                "statement_id": raw_context.get("statement_id"),
                "op_keys": list(raw_context.get("op_keys", []) or []),
                "metadata_refs": list(
                    raw_context.get("metadata_refs", []) or []
                ),
                "object_context": raw_context.get("object_context"),
            })
        except Exception:
            pass
        contract = self.current_contract()
        if contract is not None:
            context["variable_sid"] = contract.get("sid")
        if self.object_focus is not None:
            context["focused_object"] = dict(self.object_focus)
        return context

    def oncs_digest_rows(self):
        contract = self.current_contract()
        current_sid = contract.get("sid") if contract else None
        rows = []
        for sid, item in sorted(
            self.oncs.contracts.items(),
            key=lambda pair: (
                not bool(pair[1].get("is_parameter")),
                pair[1].get("parameter_index")
                if isinstance(pair[1].get("parameter_index"), int)
                else 1 << 30,
                str(pair[1].get("active_name") or pair[0]),
            ),
        ):
            rows.append({
                "selected": sid == current_sid,
                "ssa": sid,
                "pal": item.get("pal_name"),
                "humanizer": item.get("generated_human_alias"),
                "operator": item.get("operator_alias"),
                "active": (
                    item.get("operator_alias")
                    if self.operator_overlay and item.get("operator_alias")
                    else _base_variable_name(item, self.naming)
                ),
                "source": (
                    "operator" if self.operator_overlay and item.get("operator_alias")
                    else self.naming
                ),
                "parameter_index": item.get("parameter_index"),
                "rename_locked": bool(item.get("rename_locked")),
                "lock_reason": item.get("humanization_exclusion_reason"),
            })
        return rows

    def truth_digest(self):
        metadata_view = IcecubeMetadataView(
            self.document, function_record=self.function_record
        )
        return TruthDigestDaily(
            metadata_view,
            oncs_rows=self.oncs_digest_rows(),
            cursor=self._cursor_context(),
        )

    def save(self, path=None):
        digest = self.oncs.save(path)
        self.status = "PAL_ONCS saved; icecube unchanged"
        return digest

    def export(self, path):
        text = "\n".join(self.lines()) + "\n"
        path = os.fspath(path)
        temp = "%s.tmp.%d" % (path, os.getpid())
        try:
            with open(temp, "wt", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        self.status = "exported %s" % path
        return path

class PALFunctionManifestModel:
    """Function catalog backed by one project-global PAL_ONCS.json."""

    FORMAT = "pal_function_bundle"

    def __init__(self, payload, source_path=None, single_icecube=False):
        self.payload = payload
        self.source_path = (
            os.path.abspath(os.fspath(source_path)) if source_path else None
        )
        self.root = (
            os.path.dirname(self.source_path) if self.source_path
            else os.getcwd()
        )
        self.single_icecube = bool(single_icecube)
        self.records = list(payload.get("functions", []) or [])
        self.line = 0
        self.top_line = 0
        self.status = "function manifest loaded; project PAL_ONCS active"
        self._models = {}
        # Function list and function viewers deliberately have independent
        # naming focus.  The module catalog opens at SSA+OPER; code viewers
        # open at PAL+OPER unless the viewer preference is changed in-session.
        self.function_naming = "ssa"
        self.function_operator_overlay = True
        self.viewer_naming = "pal"
        self.viewer_operator_overlay = True
        self.function_filter = ""
        self.oncs_path = os.path.join(self.root, PROJECT_NAME_REGISTRY)
        self.oncs_store = PALHumanizer.ProjectONCSStore.load(
            self.oncs_path,
            manifest_records=self.records,
            program=dict(payload.get("program", {}) or {}),
        )
        self.function_registry = self.oncs_store.function_registry

    @classmethod
    def from_path(cls, path):
        path = os.path.abspath(os.fspath(path))
        opener = gzip.open if path.lower().endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("format") != cls.FORMAT:
            raise ValueError("not a PAL function manifest: %s" % path)
        if not isinstance(payload.get("functions"), list):
            raise ValueError("PAL function manifest has no function inventory")
        return cls(payload, source_path=path)

    @classmethod
    def from_icecube(cls, path):
        path = os.path.abspath(os.fspath(path))
        name = os.path.basename(path)
        record = {
            "ordinal": 0,
            "name": name,
            "qualified_name": name,
            "entry": None,
            "entry_hex": None,
            "status": "decompiled",
            "external": False,
            "artifacts": {
                "icecube": {"path": path, "sha256": None},
            },
        }
        payload = {
            "format": cls.FORMAT,
            "schema_version": 1,
            "status": "single_icecube",
            "program": {"name": "detached icecube"},
            "functions": [record],
        }
        pseudo_manifest = os.path.join(
            os.path.dirname(path), "PAL_detached_manifest.json"
        )
        return cls(payload, source_path=pseudo_manifest, single_icecube=True)

    @property
    def program_name(self):
        return str(dict(self.payload.get("program", {}) or {}).get(
            "name", "unknown program"
        ))

    def _function_search_text(self, record):
        """Return all known function-name spellings for filtering."""
        record = dict(record or {})
        values = []
        for key in (
            "name", "qualified_name", "display_name", "original_name",
            "symbol", "label", "entry_hex",
        ):
            value = record.get(key)
            if value is not None:
                values.append(str(value))
        try:
            fid = self.function_id(record)
            contract = dict(self.function_registry.record(fid) or {})
        except Exception:
            contract = {}
        for key in (
            "ssa_name", "canonical_ssa_name", "pal_name",
            "generated_human_alias", "humanized_name",
            "operator_name", "active_name", "name",
        ):
            value = contract.get(key)
            if value is not None:
                values.append(str(value))
        return "\n".join(values).casefold()

    def visible_records(self):
        keyword = str(self.function_filter or "").strip().casefold()
        if not keyword:
            return list(self.records)
        return [
            record for record in self.records
            if keyword in self._function_search_text(record)
        ]

    def set_function_filter(self, keyword):
        self.function_filter = str(keyword or "").strip()
        self.line = 0
        self.top_line = 0
        visible = len(self.visible_records())
        if self.function_filter:
            self.status = "function filter %r: %d/%d matches" % (
                self.function_filter, visible, len(self.records)
            )
        else:
            self.status = "function filter cleared; %d entries" % len(self.records)
        return self.function_filter

    def clear_function_filter(self):
        return self.set_function_filter("")

    def clamp(self):
        records = self.visible_records()
        if not records:
            self.line = self.top_line = 0
            return
        self.line = min(max(int(self.line), 0), len(records) - 1)
        self.top_line = min(
            max(int(self.top_line), 0), max(0, len(records) - 1)
        )

    def selected_record(self):
        self.clamp()
        records = self.visible_records()
        return records[self.line] if records else None

    @staticmethod
    def _artifact(record):
        artifacts = dict(record.get("artifacts", {}) or {})
        artifact = artifacts.get("icecube")
        if isinstance(artifact, str):
            return {"path": artifact, "sha256": None}
        if isinstance(artifact, dict):
            return artifact
        fallback = record.get("icecube_path")
        if fallback:
            return {"path": fallback, "sha256": None}
        return None

    def icecube_path(self, record=None):
        record = record or self.selected_record()
        artifact = self._artifact(record or {})
        if not artifact or not artifact.get("path"):
            return None
        declared = os.fspath(artifact["path"])
        primary = (
            os.path.abspath(declared) if os.path.isabs(declared)
            else os.path.abspath(os.path.join(self.root, declared))
        )
        candidates = [primary]
        function_root = os.path.join(self.root, PROJECT_FUNCTIONS_DIRECTORY)
        if not os.path.isabs(declared):
            normalized = os.path.normpath(declared)
            first = normalized.split(os.sep, 1)[0]
            if first != PROJECT_FUNCTIONS_DIRECTORY:
                candidates.append(os.path.join(function_root, normalized))
        candidates.append(os.path.join(function_root, os.path.basename(declared)))
        seen = set()
        for candidate in candidates:
            candidate = os.path.abspath(candidate)
            if candidate in seen:
                continue
            seen.add(candidate)
            if os.path.isfile(candidate):
                return candidate
        return primary

    def can_open(self, record=None):
        record = record or self.selected_record()
        path = self.icecube_path(record)
        return bool(
            record
            and record.get("status") == "decompiled"
            and path
            and os.path.isfile(path)
        )

    def function_id(self, record=None):
        record = record or self.selected_record() or {}
        return self.oncs_store.function_id_for_record(record)

    def function_name(self, record=None, naming=None):
        fid = self.function_id(record)
        base = naming or self.function_naming
        contract = self.function_registry.record(fid) or {}
        if self.function_operator_overlay and contract.get("operator_name"):
            return str(contract.get("operator_name"))
        return self.function_registry.effective_name(fid, base)

    def function_naming_label(self):
        base = {
            "ssa": "SSA", "pal": "PAL", "humanizer": "HUMANIZED",
        }.get(
            self.function_naming,
            _display_naming_label(self.function_naming),
        )
        return "%s+Oper" % base if self.function_operator_overlay else base

    def cycle_function_naming(self):
        modes = ("ssa", "pal", "humanizer")
        index = modes.index(self.function_naming)
        self.function_naming = modes[(index + 1) % len(modes)]
        suffix = "+OPER" if self.function_operator_overlay else ""
        self.status = "module ONCS naming: %s%s" % (
            _display_naming_label(self.function_naming), suffix
        )
        return self.function_naming

    def toggle_function_operator_overlay(self, enabled=None):
        if enabled is None:
            self.function_operator_overlay = not self.function_operator_overlay
        else:
            self.function_operator_overlay = bool(enabled)
        self.status = (
            "module operator labels ON"
            if self.function_operator_overlay
            else "module operator labels OFF"
        )
        return self.function_operator_overlay

    def save_oncs(self):
        path = self.oncs_store.save()
        for model in self._models.values():
            model.oncs.function_names = self.oncs_store.function_names()
            current = self.function_registry.record(model.oncs.function_id) or {}
            model.function_record.update(current)
            model.oncs.function_record = dict(model.function_record)
            model.oncs._rebuild()
        self.status = "PAL_ONCS saved"
        return _sha256_file(path)

    def rename_selected_function(self, alias):
        fid = self.function_id()
        value = self.oncs_store.set_function_operator_name(fid, alias)
        self.function_operator_overlay = True
        self.save_oncs()
        self.status = "function operator alias saved: %s" % value
        return value

    def clear_selected_function(self):
        fid = self.function_id()
        previous = self.oncs_store.clear_function_operator_name(fid)
        if previous is not None:
            self.save_oncs()
            self.status = "function alias reverted"
        else:
            self.status = "function has no operator alias"
        return previous

    def open_selected(
        self, verify=True, projection=None, naming=None,
        operator_overlay=None,
    ):
        naming = naming or self.viewer_naming
        if naming not in ONCSNameState.NAMING_MODES:
            naming = "pal"
        if operator_overlay is None:
            operator_overlay = self.viewer_operator_overlay

        record = self.selected_record()
        if record is None:
            raise ValueError("function manifest is empty")
        if record.get("status") != "decompiled":
            raise ValueError(
                "function status is %s" % record.get("status", "unknown")
            )
        path = self.icecube_path(record)
        if not path:
            raise ValueError("function has no icecube artifact")
        if not os.path.isfile(path):
            raise ValueError("icecube is missing: %s" % path)

        artifact = self._artifact(record) or {}
        expected = artifact.get("sha256")
        if verify and expected:
            actual = _sha256_file(path)
            if actual != str(expected):
                raise ValueError(
                    "manifest icecube SHA-256 mismatch for %s" % path
                )

        fid = self.function_id(record)
        function_record = dict(self.function_registry.record(fid) or {})
        function_record.update({
            "function_id": fid,
            "manifest_record": dict(record),
        })
        model = self._models.get(path)
        if model is None:
            model = PALTerminalModel.from_path(
                path,
                verify=verify,
                function_record=function_record,
                project_store=self.oncs_store,
            )
            if projection and model.document.projection(projection) is not None:
                model.projection = projection
            model.naming = naming
            model.operator_overlay = bool(operator_overlay)
            self._models[path] = model
        else:
            model.function_record = function_record
            model.oncs.function_record = function_record
            model.oncs.function_names = self.oncs_store.function_names()
            model.oncs._rebuild()
            model.naming = naming
            model.operator_overlay = bool(operator_overlay)
        self.viewer_naming = model.naming
        self.viewer_operator_overlay = model.operator_overlay
        self.status = "opened %s" % self.function_name(record)
        return model

    def save_model(self, model):
        digest = model.save()
        self.status = "saved project PAL_ONCS; icecube unchanged"
        model.status = self.status
        return digest

class PALProjectWorkspaceModel:
    """PAL-root project catalog with lazy per-project manifest loading."""

    def __init__(self, pal_root):
        root = os.path.abspath(os.fspath(pal_root))
        if os.path.basename(root) == PROJECTS_DIRECTORY:
            self.root = os.path.dirname(root)
            self.projects_root = root
        else:
            self.root = root
            self.projects_root = os.path.join(root, PROJECTS_DIRECTORY)
        self.records = []
        self.line = 0
        self.top_line = 0
        self.status = "PAL project workspace loaded"
        self._catalogs = {}
        self.refresh()

    @staticmethod
    def _read_manifest_summary(path):
        opener = gzip.open if path.lower().endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("format") != PALFunctionManifestModel.FORMAT:
            raise ValueError("unsupported manifest format")
        functions = payload.get("functions")
        if not isinstance(functions, list):
            raise ValueError("manifest has no function inventory")
        program = dict(payload.get("program", {}) or {})
        counts = dict(payload.get("counts", {}) or {})
        decompiled = counts.get("decompiled")
        if not isinstance(decompiled, int):
            decompiled = sum(
                record.get("status") == "decompiled" for record in functions
            )
        return {
            "program_name": str(program.get("name") or "unknown program"),
            "status": str(payload.get("status") or "unknown"),
            "functions": len(functions),
            "decompiled": int(decompiled),
        }

    def refresh(self):
        selected = None
        if self.records and 0 <= self.line < len(self.records):
            selected = self.records[self.line].get("project_path")

        records = []
        if os.path.isdir(self.projects_root):
            names = sorted(
                entry for entry in os.listdir(self.projects_root)
                if os.path.isdir(os.path.join(self.projects_root, entry))
            )
            for name in names:
                project_path = os.path.join(self.projects_root, name)
                manifest_path = os.path.join(project_path, PROJECT_MANIFEST)
                record = {
                    "project_name": name,
                    "project_path": project_path,
                    "manifest_path": manifest_path,
                    "program_name": name,
                    "status": "missing_manifest",
                    "functions": 0,
                    "decompiled": 0,
                    "error": None,
                    "artifacts": {
                        "manifest": os.path.isfile(manifest_path),
                        "jump_table": os.path.isfile(os.path.join(
                            project_path, PROJECT_JUMP_TABLE
                        )),
                        "dispatch": os.path.isfile(os.path.join(
                            project_path, PROJECT_DISPATCH
                        )),
                        "functions": os.path.isdir(os.path.join(
                            project_path, PROJECT_FUNCTIONS_DIRECTORY
                        )),
                        "oncs": os.path.isfile(os.path.join(
                            project_path, PROJECT_NAME_REGISTRY
                        )),
                    },
                }
                if os.path.isfile(manifest_path):
                    try:
                        record.update(self._read_manifest_summary(manifest_path))
                    except Exception as exc:
                        record["status"] = "invalid_manifest"
                        record["error"] = str(exc)
                records.append(record)

        self.records = records
        if selected:
            for index, record in enumerate(records):
                if record.get("project_path") == selected:
                    self.line = index
                    break
        self.clamp()
        if not os.path.isdir(self.projects_root):
            self.status = "project directory is missing: %s" % self.projects_root
        elif not self.records:
            self.status = "no PAL projects found beneath %s" % self.projects_root
        else:
            self.status = "discovered %d PAL project(s)" % len(self.records)
        return self.records

    def clamp(self):
        if not self.records:
            self.line = self.top_line = 0
            return
        self.line = min(max(int(self.line), 0), len(self.records) - 1)
        self.top_line = max(int(self.top_line), 0)

    def selected_record(self):
        self.clamp()
        return self.records[self.line] if self.records else None

    def can_open(self, record=None):
        record = record or self.selected_record()
        return bool(
            record
            and record.get("status") not in (
                "missing_manifest", "invalid_manifest"
            )
            and os.path.isfile(record.get("manifest_path", ""))
        )

    def open_selected(self):
        record = self.selected_record()
        if record is None:
            raise ValueError("PAL project workspace is empty")
        if not self.can_open(record):
            detail = record.get("error") or record.get("status") or "unavailable"
            raise ValueError("project cannot open: %s" % detail)
        path = os.path.abspath(record["manifest_path"])
        catalog = self._catalogs.get(path)
        if catalog is None:
            catalog = PALFunctionManifestModel.from_path(path)
            self._catalogs[path] = catalog
        self.status = "opened project %s" % record.get("project_name")
        return catalog


class PythonTerminalHighlighter:
    """VS Code Dark+-inspired syntax roles mapped onto terminal colors."""

    ROLE_DEFAULT = "default"
    ROLE_KEYWORD = "keyword"
    ROLE_HELPER = "helper"
    ROLE_STRING = "string"
    ROLE_COMMENT = "comment"
    ROLE_NUMBER = "number"
    ROLE_FUNCTION = "function"
    ROLE_OPERATOR = "operator"

    @staticmethod
    def segments(text):
        tokens = []
        try:
            stream = io.StringIO(str(text) + "\n").readline
            tokens = list(tokenize.generate_tokens(stream))
        except (IndentationError, SyntaxError, tokenize.TokenError):
            tokens = []
        out = []
        previous_name = None
        significant = [
            item for item in tokens
            if item.type not in (
                token.INDENT, token.DEDENT, token.NEWLINE, tokenize.NL,
                token.ENDMARKER, token.ENCODING,
            )
        ]
        for index, item in enumerate(significant):
            value = item.string
            start, end = item.start[1], item.end[1]
            role = PythonTerminalHighlighter.ROLE_DEFAULT
            if item.type == token.COMMENT:
                role = PythonTerminalHighlighter.ROLE_COMMENT
            elif item.type == token.STRING:
                role = PythonTerminalHighlighter.ROLE_STRING
            elif item.type == token.NUMBER:
                role = PythonTerminalHighlighter.ROLE_NUMBER
            elif item.type == token.OP:
                role = PythonTerminalHighlighter.ROLE_OPERATOR
            elif item.type == token.NAME:
                if keyword.iskeyword(value):
                    role = PythonTerminalHighlighter.ROLE_KEYWORD
                elif value.startswith("c_"):
                    role = PythonTerminalHighlighter.ROLE_HELPER
                else:
                    next_value = (
                        significant[index + 1].string
                        if index + 1 < len(significant) else None
                    )
                    if previous_name == "def" or next_value == "(":
                        role = PythonTerminalHighlighter.ROLE_FUNCTION
                previous_name = value
            out.append((start, end, role))
        if not out:
            comment = str(text).find("#")
            if comment >= 0:
                out.append((comment, len(str(text)), PythonTerminalHighlighter.ROLE_COMMENT))
            for match in re.finditer(r"\bc_[A-Za-z_][A-Za-z0-9_]*\b", str(text)):
                out.append((match.start(), match.end(), PythonTerminalHighlighter.ROLE_HELPER))
        return out


class PALCursesUI:
    def __init__(self, screen, model, save_handler=None):
        self.screen = screen
        self.model = model
        self.save_handler = save_handler
        self.running = True
        self.exit_reason = None
        self.pairs = {}

        # Additive F9 truth-comparison mode.  The ordinary single-pane editor
        # remains the default and keeps its original cursor/scroll state.
        self.side_by_side = False
        self.side_active = 0
        self.side_panes = ("asm", "readable", "c_code", "executable")
        self.side_titles = {
            "asm": "ASM / MACHINE TRUTH",
            "readable": "READ.PY",
            "c_code": "GHIDRA C",
            "executable": "EXEC.PY",
        }
        self.side_state = {
            name: {"line": 0, "column": 0, "top": 0, "left": 0}
            for name in self.side_panes
        }
        self.last_python_pane = self.model.projection
        self._init_terminal()

    def _init_terminal(self):
        curses.curs_set(1)
        self.screen.keypad(True)
        for sequence in CTRL_TAB_SEQUENCES:
            try:
                curses.define_key(sequence, KEY_CTRL_TAB)
            except Exception:
                pass
        try:
            curses.use_default_colors()
        except Exception:
            pass
        if not curses.has_colors():
            return
        curses.start_color()
        if curses.COLORS >= 256:
            palette = {
                "default": 252, "keyword": 176, "helper": 81,
                "string": 173, "comment": 108, "number": 151,
                "function": 222, "operator": 245, "modified": 214,
                "status": 231, "highlight": 16, "active_header": 16,
            }
            status_background = 24
            highlight_background = 220
            active_header_background = 196
        else:
            palette = {
                "default": curses.COLOR_WHITE,
                "keyword": curses.COLOR_MAGENTA,
                "helper": curses.COLOR_CYAN,
                "string": curses.COLOR_RED,
                "comment": curses.COLOR_GREEN,
                "number": curses.COLOR_GREEN,
                "function": curses.COLOR_YELLOW,
                "operator": curses.COLOR_WHITE,
                "modified": curses.COLOR_YELLOW,
                "status": curses.COLOR_WHITE,
                "highlight": curses.COLOR_BLACK,
                "active_header": curses.COLOR_BLACK,
            }
            status_background = curses.COLOR_BLUE
            highlight_background = curses.COLOR_YELLOW
            active_header_background = curses.COLOR_RED
        for pair_id, role in enumerate(palette, 1):
            background = (
                status_background if role == "status"
                else highlight_background if role == "highlight"
                else active_header_background if role == "active_header"
                else -1
            )
            try:
                curses.init_pair(pair_id, palette[role], background)
                self.pairs[role] = curses.color_pair(pair_id)
            except Exception:
                self.pairs[role] = 0

    def _attr(self, role, selected=False, bold=False):
        value = self.pairs.get(role, 0)
        if selected and role != "highlight":
            value |= curses.A_REVERSE
        if bold or role in (
            "keyword", "helper", "function", "highlight", "active_header"
        ):
            value |= curses.A_BOLD
        return value

    def _safe_addstr(self, y, x, text, attr=0, width=None):
        height, screen_width = self.screen.getmaxyx()
        if y < 0 or y >= height or x >= screen_width:
            return
        text = str(text)
        maximum = max(0, screen_width - x - 1)
        if width is not None:
            maximum = min(maximum, max(0, int(width)))
        try:
            self.screen.addnstr(y, x, text, maximum, attr)
        except curses.error:
            pass

    def _focus_spans(self, pane, text):
        names = set(self.model.object_focus_names(pane))
        legacy = self.model.highlight_name()
        if legacy:
            names.add(str(legacy))
        if not names:
            return []
        spans = []
        try:
            stream = io.StringIO(str(text) + "\n").readline
            for item in tokenize.generate_tokens(stream):
                if item.type == token.NAME and item.string in names:
                    spans.append((item.start[1], item.end[1]))
        except (IndentationError, SyntaxError, tokenize.TokenError):
            pattern = r"\b(?:%s)\b" % "|".join(
                re.escape(value) for value in sorted(names, key=len, reverse=True)
            )
            spans = [match.span() for match in re.finditer(pattern, str(text))]
        return spans

    def _draw_code_line(self, y, line_number, text, selected, code_x, width):
        visible = text[self.model.left_column:self.model.left_column + width]
        self._safe_addstr(
            y, code_x, visible.ljust(width), self._attr("default", selected), width
        )
        for start, end, role in PythonTerminalHighlighter.segments(text):
            clipped_start = max(start, self.model.left_column)
            clipped_end = min(end, self.model.left_column + width)
            if clipped_start >= clipped_end:
                continue
            fragment = text[clipped_start:clipped_end]
            self._safe_addstr(
                y,
                code_x + clipped_start - self.model.left_column,
                fragment,
                self._attr(role, selected),
                clipped_end - clipped_start,
            )
        for start, end in self._focus_spans(self.model.projection, text):
            clipped_start = max(start, self.model.left_column)
            clipped_end = min(end, self.model.left_column + width)
            if clipped_start >= clipped_end:
                continue
            self._safe_addstr(
                y,
                code_x + clipped_start - self.model.left_column,
                text[clipped_start:clipped_end],
                self._attr("highlight", bold=True),
                clipped_end - clipped_start,
            )

    # ------------------------------------------------------------------
    # F9 FOUR-PANE TRUTH COMPARISON (ADDITIVE)
    # ------------------------------------------------------------------

    def _side_active_name(self):
        return self.side_panes[self.side_active % len(self.side_panes)]

    def _side_lines(self, pane):
        """Return display lines for one comparison pane."""
        if pane in ("readable", "executable"):
            try:
                return [
                    str(value) for value in self.model.oncs.render_lines(
                        pane,
                        self.model.naming,
                        self.model.operator_overlay,
                    )
                ]
            except Exception:
                try:
                    return [
                        str(value) for value in self.model.oncs.base_lines(pane)
                    ]
                except Exception as exc:
                    return ["%s projection unavailable: %s" % (pane, exc)]

        digest_panel = "asm" if pane == "asm" else "c_code"
        try:
            digest = self.model.truth_digest()
            # Four-pane C/ASM is the frozen source-machine metadata itself: no
            # digest header, report footer, line-number commentary, or summary.
            return [
                str(value) for value in list(
                    digest.source_lines(digest_panel) or []
                )
            ]
        except Exception as exc:
            return [
                "%s truth panel unavailable" % digest_panel.upper(),
                "%s: %s" % (type(exc).__name__, exc),
            ]

    def _side_python_peer(self, pane):
        if pane == "readable":
            return "executable"
        if pane == "executable":
            return "readable"
        return None

    def _side_soft_sync_c(self, source_pane):
        if source_pane not in ("readable", "executable"):
            return False
        source_lines = self._side_lines(source_pane)
        c_lines = self._side_lines("c_code")
        position = percentage_document_position(
            self.side_state[source_pane]["line"], len(source_lines)
        )
        c_state = self.side_state["c_code"]
        c_state["line"] = line_from_document_position(position, len(c_lines))
        c_state["column"] = 0
        return True

    def _side_object_hotspot(
        self, pane, focus, preferred_line=None, preferred_column=None
    ):
        if not focus:
            return None
        focus_key = self.model._focus_key(focus)
        matches = []
        for item in list(projection_hotspots(self.model.document, pane) or []):
            context = dict(item.get("object_context", {}) or {})
            if not context:
                continue
            candidate = {
                "kind": context.get("kind"),
                "identity": context.get("identity") or context.get("metadata_ref"),
            }
            if self.model._focus_key(candidate) == focus_key:
                matches.append(item)
        if not matches:
            return None
        if preferred_line is not None:
            same_line = [
                item for item in matches
                if int(item.get("line", -1)) == int(preferred_line)
            ]
            if same_line:
                if preferred_column is None:
                    return same_line[0]
                return min(
                    same_line,
                    key=lambda item: abs(
                        int(item.get("column", 0)) - int(preferred_column)
                    ),
                )
            return min(
                matches,
                key=lambda item: abs(
                    int(item.get("line", 0)) - int(preferred_line)
                ),
            )
        return matches[0]

    def _side_sync_python_pair(self, source_pane, soft_c=True):
        peer = self._side_python_peer(source_pane)
        if peer is None:
            return False

        source = self.side_state[source_pane]
        target = self.side_state[peer]
        source_lines = self._side_lines(source_pane)
        target_lines = self._side_lines(peer)
        source_line = min(
            max(0, int(source["line"])), max(0, len(source_lines) - 1)
        )
        source_column = min(
            max(0, int(source["column"])),
            len(source_lines[source_line]) if source_lines else 0,
        )
        source["line"] = source_line
        source["column"] = source_column
        target_line = line_from_document_position(
            percentage_document_position(source_line, len(source_lines)),
            len(target_lines),
        )
        target_base_column = 0
        reason = "percentage_fallback"
        try:
            source_base_column = self.model.oncs.display_to_pal_column(
                source_pane,
                self.model.naming,
                source_line,
                source_column,
                self.model.operator_overlay,
            )
            mapping = self.model.document.sync_cursor(
                source_pane,
                peer,
                source_line,
                source_base_column,
                source_naming="pal",
                target_naming="pal",
            )
            if mapping.get("matched"):
                target_line = int(mapping["target_view"]["line"])
                target_base_column = int(mapping["target_view"]["column"])
                reason = mapping.get("reason") or "paired_statement"
        except Exception:
            pass

        target_line = min(
            max(0, target_line), max(0, len(target_lines) - 1)
        )
        try:
            target_column = self.model.oncs.pal_to_display_column(
                peer,
                self.model.naming,
                target_line,
                target_base_column,
                self.model.operator_overlay,
            )
        except Exception:
            target_column = 0
        if target_lines:
            target_column = min(
                max(0, target_column), len(target_lines[target_line])
            )
        else:
            target_column = 0
        target["line"] = target_line
        target["column"] = target_column
        self.last_python_pane = source_pane
        if soft_c:
            self._side_soft_sync_c(source_pane)

        # Keep Truth Digest / ASM block lookup anchored to the active Python
        # statement without changing the ordinary single-view scroll state.
        self.model.projection = source_pane
        self.model.line = source_line
        self.model.column = source_column
        self.model.clamp()
        self.model.update_cursor_context()
        self.model.status = "READ/EXEC linked (%s); C soft-sync %.1f%%" % (
            reason,
            percentage_document_position(source_line, len(source_lines)) * 100.0,
        )
        return True

    def _side_soft_sync_from_c(self):
        c_lines = self._side_lines("c_code")
        position = percentage_document_position(
            self.side_state["c_code"]["line"], len(c_lines)
        )
        anchor = self.last_python_pane
        if anchor not in ("readable", "executable"):
            anchor = "readable"
        anchor_lines = self._side_lines(anchor)
        self.side_state[anchor]["line"] = line_from_document_position(
            position, len(anchor_lines)
        )
        self.side_state[anchor]["column"] = 0
        self._side_sync_python_pair(anchor, soft_c=False)
        self.model.status = "C soft area sync %.1f%%" % (position * 100.0)
        return True

    def _side_refresh_linkage(self, source_pane):
        if source_pane in ("readable", "executable"):
            return self._side_sync_python_pair(source_pane)
        if source_pane == "c_code":
            return self._side_soft_sync_from_c()
        return False

    def _side_hotspot_projection(self):
        pane = self._side_active_name()
        if pane in ("readable", "executable"):
            return pane
        if self.last_python_pane in ("readable", "executable"):
            return self.last_python_pane
        return "readable"

    def _side_move_hotspot(self, step=1):
        pane = self._side_hotspot_projection()
        hotspots = list(projection_hotspots(self.model.document, pane) or [])
        if not hotspots:
            self.model.status = "no active Icecube hotspots for %s" % pane
            return False
        state = self.side_state[pane]
        try:
            current_base_column = self.model.oncs.display_to_pal_column(
                pane,
                self.model.naming,
                int(state["line"]),
                int(state["column"]),
                self.model.operator_overlay,
            )
        except Exception:
            current_base_column = int(state["column"])
        current = (int(state["line"]), int(current_base_column))
        if int(step) >= 0:
            candidates = [
                item for item in hotspots
                if (int(item.get("line", 0)), int(item.get("column", 0))) > current
            ]
            target = candidates[0] if candidates else hotspots[0]
        else:
            candidates = [
                item for item in hotspots
                if (int(item.get("line", 0)), int(item.get("column", 0))) < current
            ]
            target = candidates[-1] if candidates else hotspots[-1]
        state["line"] = int(target.get("line", 0))
        target_base_column = int(target.get("column", 0))
        try:
            state["column"] = self.model.oncs.pal_to_display_column(
                pane,
                self.model.naming,
                state["line"],
                target_base_column,
                self.model.operator_overlay,
            )
        except Exception:
            state["column"] = target_base_column
        self._side_refresh_linkage(pane)
        self.model.status = "hotspot %d/%d | %s line %d" % (
            hotspots.index(target) + 1,
            len(hotspots),
            pane,
            state["line"] + 1,
        )
        return True

    def _side_capture_model_cursor(self):
        pane = self.model.projection
        if pane not in ("readable", "executable"):
            return
        state = self.side_state[pane]
        state.update({
            "line": int(self.model.line),
            "column": int(self.model.column),
            "top": int(self.model.top_line),
            "left": int(self.model.left_column),
        })

    def _side_sync_model_cursor(self, pane=None):
        pane = pane or self._side_active_name()
        if pane not in ("readable", "executable"):
            return False
        state = self.side_state[pane]
        self.model.projection = pane
        self.model.line = int(state["line"])
        self.model.column = int(state["column"])
        self.model.top_line = int(state["top"])
        self.model.left_column = int(state["left"])
        self.model.clamp()
        state.update({
            "line": int(self.model.line),
            "column": int(self.model.column),
            "top": int(self.model.top_line),
            "left": int(self.model.left_column),
        })
        self.model.update_cursor_context()
        return True

    def _toggle_side_by_side(self):
        if not self.side_by_side:
            self._side_capture_model_cursor()
            source = (
                self.model.projection
                if self.model.projection in ("readable", "executable")
                else "readable"
            )
            self.last_python_pane = source
            self.side_active = self.side_panes.index(source)
            self.side_by_side = True
            self._side_sync_python_pair(source)
            self.model.status = (
                "F9 four-pane active; F8 pane; TAB hotspots; arrows cursor"
            )
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            return True

        active = self._side_active_name()
        return_pane = (
            active if active in ("readable", "executable")
            else self.last_python_pane
        )
        self._side_sync_model_cursor(return_pane)
        self.side_by_side = False
        self.model.status = "returned to single edit view"
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        return False

    def _cycle_side_pane(self, step=1):
        self.side_active = (
            self.side_active + int(step)
        ) % len(self.side_panes)
        pane = self._side_active_name()
        if pane in ("readable", "executable"):
            self.last_python_pane = pane
            self._side_sync_model_cursor(pane)
        self.model.status = "active comparison pane: %s" % self.side_titles[pane]
        return pane

    @staticmethod
    def _side_rectangles(height, width):
        """Return y/x/h/w rectangles for ASM, READ, C, EXEC quadrants."""
        body_height = max(0, int(height) - 2)
        top_height = body_height // 2
        bottom_height = body_height - top_height
        left_width = int(width) // 2
        right_width = int(width) - left_width
        return {
            "asm": (0, 0, top_height, left_width),
            "readable": (0, left_width, top_height, right_width),
            "c_code": (top_height, 0, bottom_height, left_width),
            "executable": (top_height, left_width, bottom_height, right_width),
        }

    def _draw_side_border(self, pane, rect, line_count):
        y, x, height, width = rect
        if height < 2 or width < 2:
            return
        active = pane == self._side_active_name()
        border_attr = self._attr("helper", bold=active)
        horizontal = "=" if active else "-"
        vertical = "|"
        self._safe_addstr(y, x, "+" + horizontal * max(0, width - 2) + "+", border_attr, width)
        self._safe_addstr(
            y + height - 1,
            x,
            "+" + horizontal * max(0, width - 2) + "+",
            border_attr,
            width,
        )
        for row in range(y + 1, y + height - 1):
            self._safe_addstr(row, x, vertical, border_attr, 1)
            self._safe_addstr(row, x + width - 1, vertical, border_attr, 1)

        state = self.side_state[pane]
        title = " %s%s | %d lines | %d:%d " % (
            self.side_titles[pane],
            " [ACTIVE]" if active else "",
            int(line_count),
            int(state["line"]) + 1,
            int(state["column"]),
        )
        self._safe_addstr(
            y,
            x + 2,
            title,
            self._attr("active_header", bold=True)
            if active else self._attr("operator"),
            max(0, width - 4),
        )

    def _draw_side_pane(self, pane, rect, lines):
        y, x, height, width = rect
        lines = list(lines or [])
        self._draw_side_border(pane, rect, len(lines))
        if height < 3 or width < 8:
            return

        state = self.side_state[pane]
        maximum_line = max(0, len(lines) - 1)
        state["line"] = min(max(int(state["line"]), 0), maximum_line)
        state["left"] = max(0, int(state["left"]))
        inner_height = max(1, height - 2)
        if state["line"] < state["top"]:
            state["top"] = state["line"]
        if state["line"] >= state["top"] + inner_height:
            state["top"] = state["line"] - inner_height + 1
        state["top"] = min(
            max(0, int(state["top"])),
            max(0, len(lines) - inner_height),
        )

        digits = max(3, len(str(max(1, len(lines)))))
        gutter = min(width - 3, digits + 2)
        text_width = max(1, width - gutter - 2)
        active = pane == self._side_active_name()

        for row in range(inner_height):
            line_index = state["top"] + row
            screen_y = y + 1 + row
            if line_index >= len(lines):
                self._safe_addstr(
                    screen_y, x + 1, " " * max(0, width - 2),
                    self._attr("default"), max(0, width - 2)
                )
                continue

            selected = (
                line_index == state["line"]
                and (active or pane in ("readable", "executable"))
            )
            number = ("%*d " % (digits, line_index + 1))[-gutter:]
            self._safe_addstr(
                screen_y,
                x + 1,
                number,
                self._attr("operator", selected),
                gutter,
            )
            source = str(lines[line_index])
            left = int(state["left"])
            visible = source[left:left + text_width]
            code_x = x + 1 + gutter
            self._safe_addstr(
                screen_y,
                code_x,
                visible.ljust(text_width),
                self._attr("default", selected),
                text_width,
            )

            if pane not in ("readable", "executable"):
                continue
            for start, end, role in PythonTerminalHighlighter.segments(source):
                clipped_start = max(start, left)
                clipped_end = min(end, left + text_width)
                if clipped_start >= clipped_end:
                    continue
                self._safe_addstr(
                    screen_y,
                    code_x + clipped_start - left,
                    source[clipped_start:clipped_end],
                    self._attr(role, selected),
                    clipped_end - clipped_start,
                )

            # ENTER object focus is painted after syntax in both Python panes.
            for start, end in self._focus_spans(pane, source):
                clipped_start = max(start, left)
                clipped_end = min(end, left + text_width)
                if clipped_start >= clipped_end:
                    continue
                self._safe_addstr(
                    screen_y,
                    code_x + clipped_start - left,
                    source[clipped_start:clipped_end],
                    self._attr("highlight", bold=True),
                    clipped_end - clipped_start,
                )

            # Four-pane mode hides the hardware cursor.  Paint the committed
            # semantic column explicitly: red for active, yellow for its linked
            # READ/EXEC peer.
            if line_index == state["line"]:
                cursor_column = int(state["column"])
                if left <= cursor_column < left + text_width:
                    cursor_text = (
                        source[cursor_column:cursor_column + 1]
                        if cursor_column < len(source) else " "
                    )
                    self._safe_addstr(
                        screen_y,
                        code_x + cursor_column - left,
                        cursor_text,
                        self._attr(
                            "active_header" if active else "highlight",
                            bold=True,
                        ),
                        1,
                    )

    def _draw_side_by_side(self):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        if height < 14 or width < 72:
            warning = (
                "F9 SIDE-BY-SIDE NEEDS AT LEAST 72x14; current terminal=%dx%d"
                % (width, height)
            )
            self._safe_addstr(0, 0, warning, self._attr("modified", bold=True), width - 1)
            self._safe_addstr(
                2, 0, "F9 or Esc returns to single view", self._attr("default"), width - 1
            )
            self.screen.refresh()
            return

        rectangles = self._side_rectangles(height, width)
        pane_lines = {
            pane: self._side_lines(pane) for pane in self.side_panes
        }
        for pane in self.side_panes:
            self._draw_side_pane(pane, rectangles[pane], pane_lines[pane])

        active = self._side_active_name()
        status = (
            " FOUR-PANE | active=%s | ENTER object focus | F4 rename | "
            "F8 pane | TAB hotspot | Ctrl/Shift-TAB previous | "
            "F9/Esc/q single | arrows cursor | j/k horizontal "
            % self.side_titles[active]
        )
        self._safe_addstr(
            height - 2, 0, status.ljust(width),
            self._attr("status", bold=True), width - 1
        )
        message = "%s | labels=%s | object=%s" % (
            self.model.warning or self.model.status or "",
            self.model.naming_label(),
            self.model.object_focus_label() or "-",
        )
        self._safe_addstr(
            height - 1, 0, message.ljust(width), self._attr("default"), width - 1
        )
        self.screen.refresh()

    def _handle_side_navigation(self, key):
        pane = self._side_active_name()
        state = self.side_state[pane]
        lines = self._side_lines(pane)
        height, width = self.screen.getmaxyx()
        rectangles = self._side_rectangles(height, width)
        rect = rectangles.get(pane, (0, 0, 3, 8))
        inner_height = max(1, rect[2] - 2)
        maximum_line = max(0, len(lines) - 1)
        cursor_changed = False
        viewport_only = False

        if key == curses.KEY_DOWN:
            state["line"] = min(maximum_line, state["line"] + 1)
            cursor_changed = True
        elif key == curses.KEY_UP:
            state["line"] = max(0, state["line"] - 1)
            cursor_changed = True
        elif key == curses.KEY_NPAGE:
            state["line"] = min(maximum_line, state["line"] + inner_height)
            cursor_changed = True
        elif key == curses.KEY_PPAGE:
            state["line"] = max(0, state["line"] - inner_height)
            cursor_changed = True
        elif key == curses.KEY_LEFT:
            state["column"] = max(0, state["column"] - 1)
            cursor_changed = True
        elif key == curses.KEY_RIGHT:
            source = str(lines[state["line"]]) if lines else ""
            state["column"] = min(len(source), state["column"] + 1)
            cursor_changed = True
        elif key in ("j", "h"):
            state["left"] = max(0, state["left"] - 4)
            viewport_only = True
        elif key in ("k", "l"):
            state["left"] += 4
            viewport_only = True
        elif key == curses.KEY_HOME:
            state["column"] = 0
            cursor_changed = True
        elif key == curses.KEY_END:
            source = str(lines[state["line"]]) if lines else ""
            state["column"] = len(source)
            cursor_changed = True
        elif key == "g":
            state["line"] = 0
            state["top"] = 0
            cursor_changed = True
        elif key == "G":
            state["line"] = maximum_line
            cursor_changed = True
        else:
            return False

        source = str(lines[state["line"]]) if lines else ""
        state["column"] = min(max(0, int(state["column"])), len(source))
        if state["line"] < state["top"]:
            state["top"] = state["line"]
        elif state["line"] >= state["top"] + inner_height:
            state["top"] = state["line"] - inner_height + 1

        # Arrow keys move the semantic cursor.  Horizontal viewport movement is
        # deliberately isolated on j/k (h/l aliases retained) and never changes
        # the linked position.
        if cursor_changed:
            digits = max(3, len(str(max(1, len(lines)))))
            gutter = min(rect[3] - 3, digits + 2)
            text_width = max(1, rect[3] - gutter - 2)
            if state["column"] < state["left"]:
                state["left"] = state["column"]
            elif state["column"] >= state["left"] + text_width:
                state["left"] = state["column"] - text_width + 1
            self._side_refresh_linkage(pane)
            if pane in ("readable", "executable"):
                self._side_sync_model_cursor(pane)
        elif viewport_only and pane in ("readable", "executable"):
            # Preserve horizontal scroll when returning to single view.
            self.side_state[pane]["left"] = state["left"]
        return True

    def _rename_committed_variable(self, pane=None):
        if pane in ("readable", "executable"):
            self._side_sync_model_cursor(pane)
        contract = self.model.current_contract()
        if contract is None:
            self.model.status = "cursor is not on an editable ONCS variable"
            return False
        if contract.get("rename_locked"):
            self.model.status = "rename locked: %s" % (
                contract.get("humanization_exclusion_reason")
                or "semantic identity"
            )
            return False
        projection = self.model.projection
        line = self.model.line
        try:
            base_column = self.model.oncs.display_to_pal_column(
                projection,
                self.model.naming,
                line,
                self.model.column,
                self.model.operator_overlay,
            )
        except Exception:
            base_column = self.model.column
        initial = contract.get("operator_alias") or ""
        displayed_name = (
            self.model.current_mode_variable_name(contract)
            or contract.get("pal_name")
            or contract.get("canonical_ssa_name")
            or contract.get("active_name")
            or "variable"
        )
        edited = self._prompt(
            "%s change-to: " % displayed_name, initial
        )
        if edited is None or not edited.strip():
            return False
        try:
            saved_alias = self.model.rename_current_variable(edited.strip())
        except Exception as exc:
            self.model.status = "rename failed: %s" % exc
            return False
        try:
            self.model.column = self.model.oncs.pal_to_display_column(
                projection,
                self.model.naming,
                line,
                base_column,
                self.model.operator_overlay,
            )
        except Exception:
            pass
        self.model.update_cursor_context()
        if pane in ("readable", "executable"):
            state = self.side_state[pane]
            state["line"] = self.model.line
            state["column"] = self.model.column
            self._side_sync_python_pair(pane)
        self.model.status = "operator alias saved: %s" % saved_alias
        return True

    def _handle_side_key(self, key):
        if key == getattr(curses, "KEY_F8", curses.KEY_F0 + 8):
            self._cycle_side_pane(1)
            return True
        if key == "\t":
            return self._side_move_hotspot(1)
        if key in (KEY_CTRL_TAB, getattr(curses, "KEY_BTAB", -99999)):
            return self._side_move_hotspot(-1)
        if key in ("\x1b", "q", "Q"):
            self._toggle_side_by_side()
            return True
        if key in ("\n", "\r", curses.KEY_ENTER):
            pane = self._side_active_name()
            if pane not in ("readable", "executable"):
                self.model.status = "object focus requires READ.PY or EXEC.PY active"
                return True
            self._side_sync_model_cursor(pane)
            focused = self.model.toggle_object_focus(
                pane,
                self.side_state[pane]["line"],
                self.side_state[pane]["column"],
            )
            # ENTER changes only object-context paint state. READ/EXEC cursor
            # linkage remains statement-owned and is updated exclusively by
            # cursor/hotspot navigation, never by the highlighted object.
            self.model.status = (
                "object focus: %s" % self.model.object_focus_label()
                if focused is not None
                else "object-context focus cleared"
            )
            return True
        if key == curses.KEY_F1:
            self.model.status = "both READ.PY and EXEC.PY are already visible"
            return True
        if key == curses.KEY_F2:
            self.model.cycle_naming()
            self._side_refresh_linkage(self.last_python_pane)
            return True
        if key == "\x0f":
            self.model.toggle_operator_overlay()
            self._side_refresh_linkage(self.last_python_pane)
            return True
        if key == curses.KEY_F3:
            self._metadata_overlay()
            return True
        if key == curses.KEY_F4:
            pane = self._side_active_name()
            if pane not in ("readable", "executable"):
                self.model.status = "rename requires READ.PY or EXEC.PY active"
                return True
            self._rename_committed_variable(pane)
            return True
        if self._handle_side_navigation(key):
            return True
        return False

    def draw(self):
        if self.side_by_side:
            self._draw_side_by_side()
            return
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        lines = self.model.lines()
        body_height = max(1, height - 2)
        self.model.clamp()
        if self.model.line < self.model.top_line:
            self.model.top_line = self.model.line
        if self.model.line >= self.model.top_line + body_height:
            self.model.top_line = self.model.line - body_height + 1
        digits = max(4, len(str(max(1, len(lines)))))
        code_x = digits + 3
        code_width = max(1, width - code_x)
        for row in range(body_height):
            line_number = self.model.top_line + row
            if line_number >= len(lines):
                break
            selected = line_number == self.model.line
            number = (" %*d " % (digits, line_number + 1))
            self._safe_addstr(
                row, 0, number, self._attr("operator", selected), code_x - 1
            )
            self._draw_code_line(
                row, line_number, lines[line_number], selected, code_x, code_width
            )
        focus = (
            self.model.object_focus_label()
            or self.model.highlight_name()
            or "-"
        )
        status = (
            " %s | LABELS:%s | line %d col %d | ENTER object focus F1 view F2 base ^O operator "
            "TAB hotspot F3 truth F4 rename F5 revert F6 export F9 four-pane x focus ^S save q functions "
            % (
                self.model.projection,
                self.model.naming_label(),
                self.model.line + 1,
                self.model.column + 1,
            )
        )
        self._safe_addstr(
            height - 2, 0, status.ljust(width),
            self._attr("status", bold=True), width - 1
        )
        message = "%s | focus=%s" % (
            self.model.warning or self.model.status or "", focus
        )
        self._safe_addstr(
            height - 1, 0, message.ljust(width), self._attr("default"), width - 1
        )
        cursor_x = code_x + self.model.column - self.model.left_column
        if 0 <= cursor_x < width:
            try:
                self.screen.move(self.model.line - self.model.top_line, cursor_x)
            except curses.error:
                pass
        self.screen.refresh()

    def _prompt(self, label, initial=""):
        height, width = self.screen.getmaxyx()
        buffer = list(str(initial))
        cursor = len(buffer)
        while True:
            text = "".join(buffer)
            available = max(1, width - len(label) - 2)
            left = max(0, cursor - available + 1)
            self._safe_addstr(
                height - 1, 0, " " * (width - 1),
                self._attr("default"), width - 1
            )
            self._safe_addstr(
                height - 1, 0, label, self._attr("keyword", bold=True)
            )
            self._safe_addstr(
                height - 1, len(label), text[left:left + available],
                self._attr("default"), available
            )
            try:
                self.screen.move(height - 1, len(label) + cursor - left)
            except curses.error:
                pass
            self.screen.refresh()
            key = self.screen.get_wch()
            if key in ("\n", "\r", curses.KEY_ENTER):
                return "".join(buffer)
            if key == "\x1b":
                return None
            if key in (curses.KEY_LEFT,):
                cursor = max(0, cursor - 1)
            elif key in (curses.KEY_RIGHT,):
                cursor = min(len(buffer), cursor + 1)
            elif key == curses.KEY_HOME:
                cursor = 0
            elif key == curses.KEY_END:
                cursor = len(buffer)
            elif key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                if cursor:
                    del buffer[cursor - 1]
                    cursor -= 1
            elif key == curses.KEY_DC:
                if cursor < len(buffer):
                    del buffer[cursor]
            elif isinstance(key, str) and key.isprintable():
                buffer.insert(cursor, key)
                cursor += 1

    def _metadata_overlay(self):
        digest = self.model.truth_digest()
        top = 0
        while True:
            lines = digest.lines()
            height, width = self.screen.getmaxyx()
            box_h = max(8, height - 4)
            box_w = max(30, width - 6)
            y, x = 2, 3
            window = curses.newwin(box_h, box_w, y, x)
            window.keypad(True)
            window.erase()
            try:
                window.box()
            except curses.error:
                pass
            title = (
                " TRUTH DIGEST RAW | R curated | arrows scroll | Esc closes "
                if digest.raw else
                " TRUTH DIGEST DAILY | F1 C F2 defs F3 calls F4 ABI F5 ASM R raw "
            )
            try:
                window.addnstr(
                    0, 2, title, box_w - 4, self._attr("helper", bold=True)
                )
            except curses.error:
                pass
            visible_h = box_h - 2
            for row, value in enumerate(lines[top:top + visible_h], 1):
                try:
                    window.addnstr(
                        row, 1, value, box_w - 2, self._attr("default")
                    )
                except curses.error:
                    pass
            window.refresh()
            key = window.get_wch()
            if key in ("\x1b", "q", "Q"):
                break
            if key in ("r", "R"):
                digest.toggle_raw()
                top = 0
                continue
            if key == curses.KEY_F1:
                digest.select("c_code")
                top = 0
            elif key == curses.KEY_F2:
                digest.select("function_definition")
                top = 0
            elif key == curses.KEY_F3:
                digest.select("called_functions")
                top = 0
            elif key == curses.KEY_F4:
                digest.select("abi_custody")
                top = 0
            elif key == curses.KEY_F5:
                digest.select("asm")
                top = 0
            elif key in (curses.KEY_DOWN, "j"):
                top = min(max(0, len(lines) - visible_h), top + 1)
            elif key in (curses.KEY_UP, "k"):
                top = max(0, top - 1)
            elif key == curses.KEY_NPAGE:
                top = min(max(0, len(lines) - visible_h), top + visible_h)
            elif key == curses.KEY_PPAGE:
                top = max(0, top - visible_h)

    def handle_key(self, key):
        if key == getattr(curses, "KEY_F9", curses.KEY_F0 + 9):
            self._toggle_side_by_side()
            return
        if self.side_by_side and self._handle_side_key(key):
            return

        lines = self.model.lines()
        height, width = self.screen.getmaxyx()
        page = max(1, height - 3)
        if key in ("q", "Q"):
            self.exit_reason = "function_list"
            self.running = False
        elif key == curses.KEY_F1:
            self.model.switch_projection()
        elif key == curses.KEY_F2:
            self.model.cycle_naming()
        elif key == "\x0f":
            self.model.toggle_operator_overlay()
        elif key == "\t":
            self.model.move_hotspot(1)
        elif key in (KEY_CTRL_TAB, getattr(curses, "KEY_BTAB", -99999)):
            self.model.move_hotspot(-1)
        elif key in ("\n", "\r", curses.KEY_ENTER):
            self.model.update_cursor_context()
            self.model.toggle_object_focus()
        elif key == curses.KEY_F3:
            self._metadata_overlay()
        elif key == curses.KEY_F4:
            self._rename_committed_variable()
        elif key == curses.KEY_F5:
            self.model.revert_current_variable()
        elif key == curses.KEY_F6:
            default = "%s.%s.%s.py" % (
                getattr(self.model.document, "function_name", "function"),
                self.model.projection,
                self.model.naming_label(),
            )
            path = self._prompt("export> ", default)
            if path:
                try:
                    self.model.export(path)
                except Exception as exc:
                    self.model.status = "export failed: %s" % exc
        elif key in ("x", "X"):
            self.model.toggle_highlight()
        elif key == "\x13":
            try:
                if callable(self.save_handler):
                    self.save_handler(self.model)
                else:
                    self.model.save()
            except Exception as exc:
                self.model.status = "save failed: %s" % exc
        elif key in (curses.KEY_DOWN, "j"):
            self.model.line = min(max(0, len(lines) - 1), self.model.line + 1)
        elif key in (curses.KEY_UP, "k"):
            self.model.line = max(0, self.model.line - 1)
        elif key == curses.KEY_NPAGE:
            self.model.line = min(max(0, len(lines) - 1), self.model.line + page)
        elif key == curses.KEY_PPAGE:
            self.model.line = max(0, self.model.line - page)
        elif key == curses.KEY_LEFT:
            self.model.column = max(0, self.model.column - 1)
        elif key == curses.KEY_RIGHT:
            self.model.column = min(
                len(self.model.current_line_text()), self.model.column + 1
            )
        elif key == curses.KEY_HOME:
            self.model.column = 0
        elif key == curses.KEY_END:
            self.model.column = len(self.model.current_line_text())
        elif key == curses.KEY_RESIZE:
            pass
        self.model.clamp()
        if key in (
            curses.KEY_F1, curses.KEY_F2, "\x0f",
            curses.KEY_DOWN, curses.KEY_UP, curses.KEY_NPAGE,
            curses.KEY_PPAGE, curses.KEY_LEFT, curses.KEY_RIGHT,
            curses.KEY_HOME, curses.KEY_END,
        ):
            self.model.update_cursor_context()
        code_width = max(1, width - 10)
        if self.model.column < self.model.left_column:
            self.model.left_column = self.model.column
        elif self.model.column >= self.model.left_column + code_width:
            self.model.left_column = self.model.column - code_width + 1
        if self.side_by_side:
            self._side_capture_model_cursor()

    def run(self):
        while self.running:
            self.draw()
            self.handle_key(self.screen.get_wch())
        return self.exit_reason


class PALProjectBrowserUI:
    """Top-level PAL project browser. Enter descends; q exits PALTermUI."""

    def __init__(self, screen, workspace):
        self.screen = screen
        self.workspace = workspace
        self.screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    def _safe_addstr(self, y, x, text, attr=0, width=None):
        height, screen_width = self.screen.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= screen_width:
            return
        maximum = max(0, screen_width - x - 1)
        if width is not None:
            maximum = min(maximum, max(0, int(width)))
        try:
            self.screen.addnstr(y, x, str(text), maximum, attr)
        except curses.error:
            pass

    @staticmethod
    def _row_text(record):
        artifacts = dict(record.get("artifacts", {}) or {})
        flags = "".join((
            "M" if artifacts.get("manifest") else "-",
            "J" if artifacts.get("jump_table") else "-",
            "D" if artifacts.get("dispatch") else "-",
            "F" if artifacts.get("functions") else "-",
            "O" if artifacts.get("oncs") else "-",
        ))
        count = "%d/%d" % (
            int(record.get("decompiled") or 0),
            int(record.get("functions") or 0),
        )
        return "%-24s  %-24s  %-11s  %-9s  %s" % (
            record.get("project_name") or "unnamed",
            record.get("program_name") or "unknown",
            record.get("status") or "unknown",
            count,
            flags,
        )

    def draw(self):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        self.workspace.clamp()
        body_height = max(1, height - 3)
        if self.workspace.line < self.workspace.top_line:
            self.workspace.top_line = self.workspace.line
        if self.workspace.line >= self.workspace.top_line + body_height:
            self.workspace.top_line = self.workspace.line - body_height + 1

        header = " PAL PROJECTS | %s | %d projects " % (
            self.workspace.projects_root, len(self.workspace.records)
        )
        self._safe_addstr(0, 0, header.ljust(width), curses.A_BOLD, width - 1)

        for row in range(body_height):
            index = self.workspace.top_line + row
            if index >= len(self.workspace.records):
                break
            selected = index == self.workspace.line
            marker = ">" if selected else " "
            text = "%s %s" % (
                marker, self._row_text(self.workspace.records[index])
            )
            attr = curses.A_REVERSE | curses.A_BOLD if selected else 0
            self._safe_addstr(row + 1, 0, text.ljust(width), attr, width - 1)

        help_text = (
            " arrows/j/k browse | Enter open project | "
            "r refresh | M/J/D/F/O artifacts | q system prompt "
        )
        self._safe_addstr(
            height - 2, 0, help_text.ljust(width), curses.A_BOLD, width - 1
        )
        self._safe_addstr(
            height - 1, 0, str(self.workspace.status or "").ljust(width),
            0, width - 1
        )
        self.screen.refresh()

    def _open(self):
        try:
            return self.workspace.open_selected()
        except Exception as exc:
            self.workspace.status = "open failed: %s" % exc
            return None

    def run(self):
        while True:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            self.draw()
            key = self.screen.get_wch()
            height, unused_width = self.screen.getmaxyx()
            page = max(1, height - 4)
            if key in ("q", "Q"):
                return None
            if key in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
                catalog = self._open()
                if catalog is not None:
                    return catalog
            elif key in ("r", "R"):
                self.workspace.refresh()
            elif key in (curses.KEY_DOWN, "j"):
                self.workspace.line += 1
            elif key in (curses.KEY_UP, "k"):
                self.workspace.line -= 1
            elif key == curses.KEY_NPAGE:
                self.workspace.line += page
            elif key == curses.KEY_PPAGE:
                self.workspace.line -= page
            elif key in (curses.KEY_HOME, "g"):
                self.workspace.line = 0
            elif key in (curses.KEY_END, "G"):
                self.workspace.line = max(0, len(self.workspace.records) - 1)
            elif key == curses.KEY_RESIZE:
                pass
            self.workspace.clamp()


class PALFunctionBrowserUI:
    """Manifest/module browser; the only place function aliases may be edited."""

    def __init__(
        self, screen, catalog, verify=True, projection=None, naming="humanizer"
    ):
        self.screen = screen
        self.catalog = catalog
        self.verify = bool(verify)
        self.projection = projection
        self.naming = naming
        self.screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    def _safe_addstr(self, y, x, text, attr=0, width=None):
        height, screen_width = self.screen.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= screen_width:
            return
        maximum = max(0, screen_width - x - 1)
        if width is not None:
            maximum = min(maximum, max(0, int(width)))
        try:
            self.screen.addnstr(y, x, str(text), maximum, attr)
        except curses.error:
            pass

    def _prompt(self, label, initial=""):
        height, width = self.screen.getmaxyx()
        buffer = list(str(initial))
        cursor = len(buffer)
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        try:
            while True:
                text = "".join(buffer)
                available = max(1, width - len(label) - 2)
                left = max(0, cursor - available + 1)
                self._safe_addstr(height - 1, 0, " " * (width - 1), 0, width - 1)
                self._safe_addstr(height - 1, 0, label, curses.A_BOLD)
                self._safe_addstr(
                    height - 1, len(label), text[left:left + available], 0, available
                )
                try:
                    self.screen.move(height - 1, len(label) + cursor - left)
                except curses.error:
                    pass
                self.screen.refresh()
                key = self.screen.get_wch()
                if key in ("\n", "\r", curses.KEY_ENTER):
                    return "".join(buffer)
                if key == "\x1b":
                    return None
                if key == curses.KEY_LEFT:
                    cursor = max(0, cursor - 1)
                elif key == curses.KEY_RIGHT:
                    cursor = min(len(buffer), cursor + 1)
                elif key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                    if cursor:
                        del buffer[cursor - 1]
                        cursor -= 1
                elif key == curses.KEY_DC and cursor < len(buffer):
                    del buffer[cursor]
                elif isinstance(key, str) and key.isprintable():
                    buffer.insert(cursor, key)
                    cursor += 1
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass

    def _row_text(self, record):
        address = record.get("entry_hex")
        if not address and isinstance(record.get("entry"), int):
            address = hex(record["entry"])
        address = address or "-"
        status = str(record.get("status") or "unknown")
        name = self.catalog.function_name(record)
        icecube = "I" if PALFunctionManifestModel._artifact(record) else "-"
        return "%-18s  %-16s  %s  %s" % (
            address, status, icecube, name
        )

    def draw(self):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        self.catalog.clamp()
        records = self.catalog.visible_records()
        body_height = max(1, height - 3)
        if self.catalog.line < self.catalog.top_line:
            self.catalog.top_line = self.catalog.line
        if self.catalog.line >= self.catalog.top_line + body_height:
            self.catalog.top_line = self.catalog.line - body_height + 1

        filter_label = self.catalog.function_filter or "-"
        header = " PAL FUNCTIONS | %s | %d/%d entries | ONCS:%s | FILTER:%s " % (
            self.catalog.program_name, len(records), len(self.catalog.records),
            self.catalog.function_naming_label(), filter_label,
        )
        self._safe_addstr(0, 0, header.ljust(width), curses.A_BOLD, width - 1)

        for row in range(body_height):
            index = self.catalog.top_line + row
            if index >= len(records):
                break
            selected = index == self.catalog.line
            marker = ">" if selected else " "
            text = "%s %s" % (
                marker, self._row_text(records[index])
            )
            attr = curses.A_REVERSE | curses.A_BOLD if selected else 0
            self._safe_addstr(row + 1, 0, text.ljust(width), attr, width - 1)

        help_text = (
            " arrows/j/k browse | Enter open | / filter (empty clears) | "
            "^X clear | F2 base names | ^O operator | F4 rename | F5 revert | q project "
        )
        self._safe_addstr(
            height - 2, 0, help_text.ljust(width), curses.A_BOLD, width - 1
        )
        self._safe_addstr(
            height - 1, 0, str(self.catalog.status or "").ljust(width),
            0, width - 1
        )
        self.screen.refresh()

    def _open(self):
        try:
            return self.catalog.open_selected(
                verify=self.verify,
                projection=self.projection,
                naming=self.catalog.viewer_naming,
                operator_overlay=self.catalog.viewer_operator_overlay,
            )
        except Exception as exc:
            self.catalog.status = "open failed: %s" % exc
            return None

    def run(self):
        while True:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            self.draw()
            key = self.screen.get_wch()
            height, unused_width = self.screen.getmaxyx()
            page = max(1, height - 4)
            if key in ("q", "Q"):
                return None
            if key == "/":
                value = self._prompt(
                    "filter function names> ", self.catalog.function_filter
                )
                if value is not None:
                    self.catalog.set_function_filter(value)
                continue
            if key == "\x18":
                self.catalog.clear_function_filter()
                continue
            if key in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
                model = self._open()
                if model is not None:
                    return model
            elif key == curses.KEY_F2:
                self.catalog.cycle_function_naming()
            elif key == "\x0f":
                self.catalog.toggle_function_operator_overlay()
            elif key == curses.KEY_F4:
                fid = self.catalog.function_id()
                record = self.catalog.function_registry.record(fid) or {}
                initial = record.get("operator_name") or ""
                value = self._prompt(
                    "rename %s> " % self.catalog.function_name(),
                    initial,
                )
                if value is not None and value.strip():
                    try:
                        self.catalog.rename_selected_function(value.strip())
                    except Exception as exc:
                        self.catalog.status = "function rename failed: %s" % exc
            elif key == curses.KEY_F5:
                try:
                    self.catalog.clear_selected_function()
                except Exception as exc:
                    self.catalog.status = "function revert failed: %s" % exc
            elif key in (curses.KEY_DOWN, "j"):
                self.catalog.line += 1
            elif key in (curses.KEY_UP, "k"):
                self.catalog.line -= 1
            elif key == curses.KEY_NPAGE:
                self.catalog.line += page
            elif key == curses.KEY_PPAGE:
                self.catalog.line -= page
            elif key in (curses.KEY_HOME, "g"):
                self.catalog.line = 0
            elif key in (curses.KEY_END, "G"):
                self.catalog.line = max(0, len(self.catalog.records) - 1)
            elif key == curses.KEY_RESIZE:
                pass
            self.catalog.clamp()


def _run_curses(screen, catalog, verify=True, projection=None, naming="pal", show_splash=True):
    if naming in ONCSNameState.NAMING_MODES:
        catalog.viewer_naming = naming
    if show_splash:
        draw_splash(screen)
    while True:
        browser = PALFunctionBrowserUI(
            screen,
            catalog,
            verify=verify,
            projection=projection,
            naming=naming,
        )
        model = browser.run()
        if model is None:
            return

        editor = PALCursesUI(
            screen,
            model,
            save_handler=catalog.save_model,
        )
        editor.run()
        # Viewer naming is session state, but the module catalog retains its
        # independent SSA+OPER focus.
        catalog.viewer_naming = model.naming
        catalog.viewer_operator_overlay = model.operator_overlay
        record = catalog.selected_record() or {}
        catalog.status = "returned from %s" % (
            record.get("qualified_name")
            or record.get("name")
            or model.document.function_name
        )


def _run_project_curses(
    screen, workspace, verify=True, projection=None, naming="pal"
):
    draw_splash(screen)
    while True:
        project_browser = PALProjectBrowserUI(screen, workspace)
        catalog = project_browser.run()
        if catalog is None:
            return
        _run_curses(
            screen,
            catalog,
            verify=verify,
            projection=projection,
            naming=naming,
            show_splash=False,
        )
        record = workspace.selected_record() or {}
        workspace.status = "returned from project %s" % (
            record.get("project_name") or catalog.program_name
        )



# ============================================================================
# PALTERMUI COORDINATOR FACADE
# ============================================================================


class PALTermUI:
    """Root/project coordinator matching the PAL UI layer definition."""

    project_metadata = {}
    terminal_state = {}
    UI_state = {}
    ONCS = {}

    METADATA_FILES = (
        PROJECT_DISPATCH,
        PROJECT_MANIFEST,
        PROJECT_JUMP_TABLE,
        PROJECT_NAME_REGISTRY,
    )

    def __init__(self, root_dir=None):
        self.PALUI = self
        self.project_metadata = {}
        self.terminal_state = {
            "projection": "readable",
            "naming": "humanizer",
            "line": 0,
            "column": 0,
        }
        self.UI_state = {
            "view": "projects",
            "digest_panel": "function_definition",
            "digest_raw": False,
        }
        self.ONCS = {}
        self.root_dir = self.establish_root_PAL_dir(root_dir)
        self.project_root = self.establish_root_PAL_project_dir()
        self.project_name = None
        self.project_dir = None

    def establish_root_PAL_dir(self, candidate=None):
        path = os.path.abspath(os.fspath(
            candidate or os.path.dirname(os.path.abspath(__file__))
        ))
        if os.path.isfile(path):
            path = os.path.dirname(path)
        if os.path.basename(path) == PROJECTS_DIRECTORY:
            return os.path.dirname(path)
        current = path
        while True:
            if os.path.isdir(os.path.join(current, PROJECTS_DIRECTORY)):
                return current
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return path

    def establish_root_PAL_project_dir(self):
        return os.path.join(self.root_dir, PROJECTS_DIRECTORY)

    def display_projects_in_dir(self):
        workspace = PALProjectWorkspaceModel(self.root_dir)
        self.UI_state["view"] = "projects"
        self.UI_state["project_count"] = len(workspace.records)
        return workspace.records

    def establish_project_name(self, project=None):
        if isinstance(project, dict):
            name = project.get("project_name") or project.get("program_name")
        else:
            name = project
        if not name and self.project_name:
            name = self.project_name
        if not name:
            raise ValueError("project name is required")
        name = os.path.basename(os.path.normpath(os.fspath(name)))
        if not name or name in (".", ".."):
            raise ValueError("invalid PAL project name")
        return name

    def load_parse_project_metadata_files(self, project_dir, filenames=None):
        project_dir = os.path.abspath(os.fspath(project_dir))
        result = {}
        for filename in tuple(filenames or self.METADATA_FILES):
            path = os.path.join(project_dir, filename)
            item = {
                "path": path,
                "exists": os.path.isfile(path),
                "sha256": _sha256_file(path) if os.path.isfile(path) else None,
                "content": None,
                "error": None,
            }
            if item["exists"]:
                try:
                    if filename.lower().endswith(".json"):
                        item["content"] = _read_json_file(path, {})
                    else:
                        with open(path, "rt", encoding="utf-8") as handle:
                            head = handle.read(8192)
                        item["content"] = {
                            "kind": "python_dispatch_source",
                            "bytes": os.path.getsize(path),
                            "header": head.splitlines()[:20],
                        }
                except Exception as exc:
                    item["error"] = "%s: %s" % (type(exc).__name__, exc)
            result[filename] = item
        return result

    def load_project_metadata(self, project=None):
        self.project_name = self.establish_project_name(project)
        self.project_dir = os.path.join(self.project_root, self.project_name)
        self.project_metadata = self.load_parse_project_metadata_files(
            self.project_dir
        )
        oncs_item = dict(self.project_metadata.get(PROJECT_NAME_REGISTRY, {}) or {})
        self.ONCS = dict(oncs_item.get("content", {}) or {})
        self.UI_state.update({
            "view": "project",
            "project_name": self.project_name,
            "project_dir": self.project_dir,
        })
        return self.project_metadata

    def display_project_metadata(self, project=None):
        if project is not None or not self.project_metadata:
            self.load_project_metadata(project)
        summary = {
            "project_name": self.project_name,
            "project_dir": self.project_dir,
            "files": {},
        }
        for name, item in self.project_metadata.items():
            content = item.get("content")
            summary["files"][name] = {
                "exists": item.get("exists"),
                "sha256": item.get("sha256"),
                "error": item.get("error"),
                "kind": content.get("format") if isinstance(content, dict) else None,
            }
        manifest = dict(
            self.project_metadata.get(PROJECT_MANIFEST, {}).get("content", {}) or {}
        )
        summary["program"] = dict(manifest.get("program", {}) or {})
        summary["counts"] = dict(manifest.get("counts", {}) or {})
        return summary

    def display_function_metadata(self, function):
        record = dict(function or {})
        project_dir = self.project_dir or self.root_dir
        artifacts = {}
        for key, value in dict(record.get("artifacts", {}) or {}).items():
            item = {"declared": value, "path": None, "exists": False}
            declared = value.get("path") if isinstance(value, dict) else value
            if declared:
                path = (
                    os.path.abspath(declared) if os.path.isabs(declared)
                    else os.path.abspath(os.path.join(project_dir, declared))
                )
                item.update({"path": path, "exists": os.path.isfile(path)})
            artifacts[key] = item
        return {
            "identity": {
                "name": record.get("name"),
                "qualified_name": record.get("qualified_name"),
                "entry": record.get("entry"),
                "entry_hex": record.get("entry_hex"),
                "function_id": record.get("function_id"),
            },
            "status": record.get("status"),
            "external": bool(record.get("external")),
            "thunk": bool(record.get("thunk")),
            "artifacts": artifacts,
        }

    def display_digest_panel(self, model):
        self.UI_state["view"] = "truth_digest_daily"
        return model.truth_digest()


def _looks_like_manifest(path):
    path = os.fspath(path)
    opener = gzip.open if path.lower().endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8") as handle:
            head = handle.read(65536)
    except Exception:
        return False
    return bool(re.search(
        r'"format"\s*:\s*"pal_function_bundle"', head
    ))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Detached VT100/curses PAL function browser and ONCS variable-name editor"
        )
    )
    parser.add_argument(
        "source",
        nargs="?",
        help=(
            "PAL root (default: directory containing PALTermUI), project "
            "directory, project directory, function manifest, or detached "
            "PAL .icecube.json[.gz] snapshot"
        ),
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="skip SHA-256 verification"
    )
    parser.add_argument(
        "--projection", choices=PALTerminalModel.PROJECTIONS,
        help="initial projection"
    )
    parser.add_argument(
        "--naming", choices=PALTerminalModel.NAMING_MODES,
        default="pal", help="initial code-view ONCS base projection"
    )
    args = parser.parse_args(argv)
    source = os.path.abspath(os.fspath(
        args.source or os.path.dirname(os.path.abspath(__file__))
    ))

    if os.path.isdir(source):
        direct_manifest = os.path.join(source, PROJECT_MANIFEST)
        if os.path.isfile(direct_manifest):
            catalog = PALFunctionManifestModel.from_path(direct_manifest)
            curses.wrapper(
                _run_curses,
                catalog,
                not args.no_verify,
                args.projection,
                args.naming,
            )
        else:
            workspace = PALProjectWorkspaceModel(source)
            curses.wrapper(
                _run_project_curses,
                workspace,
                not args.no_verify,
                args.projection,
                args.naming,
            )
    elif os.path.isfile(source):
        if _looks_like_manifest(source):
            catalog = PALFunctionManifestModel.from_path(source)
        else:
            catalog = PALFunctionManifestModel.from_icecube(source)
        curses.wrapper(
            _run_curses,
            catalog,
            not args.no_verify,
            args.projection,
            args.naming,
        )
    else:
        parser.error("PAL source does not exist: %s" % source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
