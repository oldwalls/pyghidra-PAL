# ============================================================
# PAL TERMINAL UI / ONCS
# BUILD: PALTermUI mars v0.24a finalizer_overview_line_focus_asm_context_keys
# BASELINE-V35E: PALTermUI mars v0.35e usable_temp_materialization_classification
# FINALIZER: overview EXEC/READ swap; line-focus metadata path; ASM 33pct context; pane-local h/c fixes
# FINAL CLOSURE: persistent independent histories; pane-local H/C/0; unfolded full PHI blades
# BASELINE-V35A: PALTermUI mars v0.35a independent_phi_asm_history_compact_dropin_blade
# STATIC DEBUG PHI VIEW: storage + semantically used temps; exact drop-in blocks only
# BASELINE-V35: PALTermUI mars v0.35 block_grouped_dropins_narrow_phi_cursor_overlay_order / sha256 5bcb26c8357634e727ac362c94ec9bef53074270be7ff31602c85290410e491c
# STATIC DEBUG HISTORY: PHI and ASM own independent angle-bracket frame ledgers
# STATIC DEBUG PHI: verbose assignment facts removed before each custody blade
# BASELINE: PALTermUI mars v0.33a stable ctrl_e_export_header_prefix_hotfix / sha256 99958b0a983d22d3f02f1eb1696e363bfdab15d558f345d15feeabacd90947b8
# ORIGIN: PALTermUI neptune v0.23r final / sha256 20abe638914139f7311fb4a3e27fa68ff91a7df84953e34a4b5ea00f15778b7e
# PYTHON CODE: Ctrl-E replaces EXEC only; exported primary function drops UI-only f_ prefix
# STATIC DEBUG: one_active_phi_chain_and_exact_active_transition_own_dark_red
# STATIC DEBUG PHI: materialized variables only; exact drop-in blocks; no virtual PHI-path expansion
# STATIC DEBUG LINKAGE: active pane owns focus; other two panes refresh without focus theft
# RENDER ORDER: base -> red cursor bar -> final semantic/search overlays; text repainted at every layer
# STATIC DEBUG PHI TAIL: drop-in execution replaces misleading Final State termination row
# ASM DISPLAY: hovered_block_group_owns_full_width_dark_red_surface
# RETAINED-V30: phi_single_authority_full_asm_hover_surface
# RETAINED: semantic_phi_cursor_and_block_cursor_jump_relay
# RETAINED-V27: full_topology_block_navigation_with_yellow_on_dark_red_link_hover
# Curses/VT100 PAL root/project/function browser with project-global ONCS
# ============================================================

import argparse
import ast
import builtins
import curses
import curses.textpad
import functools
import gzip
import hashlib
import io
import json
import keyword
import os
import re
import signal
import stat
import sys
import time
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
from PALsplash_v4 import draw_splash, logo_print

PROJECTS_DIRECTORY = "project"
PROJECT_MANIFEST = "PAL_function_manifest.json"
PROJECT_JUMP_TABLE = "PAL_jump_table.json"
PROJECT_DISPATCH = "PAL_dispatch.py"
PROJECT_FUNCTIONS_DIRECTORY = "functions"
PROJECT_EXECUTE_DIRECTORY = "execute"
PROJECT_EXECUTE_FUNCTIONS_DIRECTORY = os.path.join(
    PROJECT_EXECUTE_DIRECTORY, "functions"
)
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

LARGE_FUNCTION_LOC_THRESHOLD_V35 = 175


def _count_text_lines_v35(path, ceiling=200000):
    """Count text lines cheaply for pre-open loader decisions."""
    if not path or not os.path.isfile(path):
        return 0
    opener = gzip.open if str(path).lower().endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            count = 0
            for count, unused in enumerate(handle, 1):
                if count >= int(ceiling):
                    break
            return int(count)
    except Exception:
        return 0


def _resolve_artifact_path_v35(root, declared):
    if not declared:
        return None
    declared = os.fspath(declared)
    candidates = []
    if os.path.isabs(declared):
        candidates.append(declared)
    else:
        candidates.extend((
            os.path.join(root, declared),
            os.path.join(root, PROJECT_FUNCTIONS_DIRECTORY, declared),
            os.path.join(root, PROJECT_FUNCTIONS_DIRECTORY, os.path.basename(declared)),
        ))
    for candidate in candidates:
        candidate = os.path.abspath(candidate)
        if os.path.isfile(candidate):
            return candidate
    return os.path.abspath(candidates[0]) if candidates else None


def _function_record_loc_v35(catalog, record):
    """Best-effort LOC estimate available before Icecube initialization."""
    record = dict(record or {})
    for key in (
        "loc", "line_count", "source_line_count", "python_line_count",
        "readable_line_count", "executable_line_count",
    ):
        value = record.get(key)
        if isinstance(value, int) and value >= 0:
            return int(value)
    root = os.path.abspath(getattr(catalog, "root", os.getcwd()))
    declared = []
    def collect(value):
        if isinstance(value, str):
            declared.append(value)
        elif isinstance(value, dict):
            for key in ("path", "filename", "file"):
                if value.get(key):
                    declared.append(value[key])
            for child in value.values():
                if isinstance(child, (dict, list, tuple)):
                    collect(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child)
    collect(record.get("artifacts", {}))
    if record.get("icecube_path"):
        declared.append(record["icecube_path"])
    paths = []
    for item in declared:
        path = _resolve_artifact_path_v35(root, item)
        if path and path not in paths:
            paths.append(path)
        lower = str(path or "").lower()
        for suffix in (".icecube.json.gz", ".icecube.json", ".json.gz", ".json"):
            if lower.endswith(suffix):
                stem = str(path)[:-len(suffix)]
                for extra in (".read.py", ".exec.py", ".readable.py", ".executable.py", ".c"):
                    candidate = stem + extra
                    if os.path.isfile(candidate) and candidate not in paths:
                        paths.append(candidate)
                break
    counts = []
    for path in paths:
        lower = str(path).lower()
        if lower.endswith((".py", ".c", ".cc", ".cpp", ".txt", ".asm", ".s")):
            counts.append(_count_text_lines_v35(path))
    return max(counts or [0])


def _model_loc_v35(model):
    """Stable processed-function LOC used by pane loader warnings."""
    cached = getattr(model, "_processed_loc_v35", None)
    if isinstance(cached, int) and cached >= 0:
        return cached
    counts = []
    for projection in ("readable", "executable"):
        try:
            counts.append(len(model.oncs.base_lines(projection)))
        except Exception:
            pass
    value = max(counts or [0])
    model._processed_loc_v35 = int(value)
    return int(value)


def _show_large_metadata_loader_v35(screen, loc, target="FUNCTION"):
    """Paint and flush a visible warning before expensive UI construction."""
    try:
        loc = int(loc)
    except Exception:
        return False
    if loc <= LARGE_FUNCTION_LOC_THRESHOLD_V35:
        return False
    height, width = screen.getmaxyx()
    screen.erase()
    line = "=" * max(0, width - 1)
    message = " LARGE FUNCTION METADATA - THIS MIGHT TAKE TIME | LOC=%d " % loc
    target_line = " PAL // LOADING %s " % str(target).upper()
    try:
        screen.addnstr(0, 0, line, max(0, width - 1), curses.A_BOLD)
        screen.addnstr(max(1, height // 2 - 2), max(0, (width - len(target_line)) // 2), target_line, max(0, width - 1), curses.A_REVERSE | curses.A_BOLD)
        screen.addnstr(max(2, height // 2), max(0, (width - len(message)) // 2), message, max(0, width - 1), curses.A_BOLD)
        screen.addnstr(max(3, height // 2 + 2), 0, line, max(0, width - 1), curses.A_BOLD)
        screen.touchwin()
        screen.noutrefresh()
        curses.doupdate()
    except Exception:
        try:
            screen.refresh()
        except Exception:
            pass
    return True


def _environment_truth(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in (
        "1", "true", "yes", "on", "full", "enabled",
    )


# v11 defaults to a light ONCS/metadata path.  Deep per-variable metadata
# discovery can still be requested for forensic UI work, but ordinary browse,
# rename, highlight and READ/EXEC block linkage do not pay that cost.
TERMUI_MINIMAL_VARIABLE_METADATA = not _environment_truth(
    "PAL_TERMUI_FULL_VARIABLE_METADATA",
    False,
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


_LOCAL_STACK_NAME_RE = re.compile(r"^local_[0-9a-f]+$", re.IGNORECASE)


def _contract_has_local_stack_name(contract, fallback=None):
    """Return true for PAL stack-local spellings intentionally operator-editable.

    PAL keeps canonical SSA linkage immutable.  This exception applies only to
    the presentation/operator layer so names such as ``local_1c`` may receive
    human or operator aliases without weakening SSA or ABI custody.
    """
    contract = dict(contract or {})
    values = [fallback]
    values.extend(contract.get(key) for key in (
        "pal_name", "display_name", "active_name", "original_name",
        "generated_human_alias", "operator_alias",
    ))
    return any(
        value is not None and _LOCAL_STACK_NAME_RE.fullmatch(str(value).strip())
        for value in values
    )


_SYSTEM_OPERATOR_NAME_RE_V34 = re.compile(
    r"^(?:abi(?:_|$)|c_abi_|ptr(?:_|$)|.*_ptr$|va_list$|varargs?$|variadic$|"
    r"rsp$|rbp$|esp$|ebp$|sp$|fp$|stack_pointer$|frame_pointer$|"
    r"return_address$|this$|self$|cls$)",
    re.IGNORECASE,
)


def _contract_operator_rename_protected_v34(contract, fallback=None):
    """Protect physical/system carriers while permitting operator-level aliases.

    F4 is deliberately powerful, but it must never relabel ABI carriers,
    variadic machinery, physical pointer/register names, or call-system objects.
    Canonical SSA identities remain immutable regardless of this policy.
    """
    contract = dict(contract or {})
    if any(bool(contract.get(key)) for key in (
        "is_abi_physical_carrier", "is_variadic", "is_varargs",
        "is_pointer_carrier", "is_stack_pointer", "is_frame_pointer",
        "is_return_address", "is_function", "is_callee",
        "is_call_target", "is_function_symbol",
    )):
        return True
    names = [fallback]
    names.extend(contract.get(key) for key in (
        "canonical_ssa_name", "pal_name", "display_name", "active_name",
        "original_name", "generated_human_alias", "operator_alias",
    ))
    for value in names:
        text = str(value or "").strip()
        if text and _SYSTEM_OPERATOR_NAME_RE_V34.search(text):
            return True
    role_text = " ".join(
        str(contract.get(key) or "").casefold() for key in (
            "kind", "record_kind", "semantic_role", "object_kind",
            "category", "type", "role", "humanization_exclusion_reason",
        )
    )
    return any(token in role_text for token in (
        "abi carrier", "physical carrier", "variadic", "vararg",
        "stack pointer", "frame pointer", "return address",
        "pointer carrier", "call target", "function symbol",
    ))


def _operator_admin_rename_eligible_v34(contract, fallback=None):
    return not _contract_operator_rename_protected_v34(contract, fallback)


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


def _metadata_sid_text_v13(value):
    """Return a stable SSA-like identity from metadata-shaped values."""
    if value is None:
        return None

    mapping = _mapping_value(value)
    if mapping is None:
        dictionary = getattr(value, "__dict__", None)
        if isinstance(dictionary, dict):
            mapping = dictionary

    if mapping is not None:
        for key in (
            "sid", "canonical_ssa_name", "ssa_id", "output_sid",
            "target_sid", "source_sid", "identity", "name",
        ):
            candidate = mapping.get(key)
            if candidate is not None and candidate is not value:
                resolved = _metadata_sid_text_v13(candidate)
                if resolved:
                    return resolved
        return None

    for attr in (
        "sid", "canonical_ssa_name", "ssa_id", "output_sid",
        "target_sid", "source_sid", "identity", "name",
    ):
        candidate = getattr(value, attr, None)
        if candidate is not None and candidate is not value:
            resolved = _metadata_sid_text_v13(candidate)
            if resolved:
                return resolved

    if isinstance(value, (str, int)):
        text = str(value).strip()
        return text or None
    return None


def _metadata_sid_list_v13(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            sid = _metadata_sid_text_v13(item)
            if sid and sid not in out:
                out.append(sid)
        return out
    sid = _metadata_sid_text_v13(value)
    return [sid] if sid else []


def _metadata_phi_records(document):
    """Discover frozen PHI/MULTIEQUAL custody records on demand.

    Icecube generations have used several record layouts.  This collector is
    intentionally schema-tolerant but semantically narrow: it accepts explicit
    MULTIEQUAL records and records whose kind identifies PHI custody and which
    expose both an incoming and resulting SID.
    """
    metadata = getattr(document, "metadata", None)
    references = set()
    roots = []

    projections = getattr(document, "projections", {})
    views = projections.values() if isinstance(projections, dict) else []
    for view in list(views or []):
        for statement in list(getattr(view, "statements", []) or []):
            for reference in list(
                getattr(statement, "metadata_refs", []) or []
            ):
                references.add(str(reference))

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
            "records", "entries", "payload", "data", "_records",
            "_entries", "operations", "pcode_ops", "high_pcode_ops",
            "formula_nodes", "phi_nodes", "phi_records", "metadata",
        ):
            value = getattr(owner, attr, None)
            if value is not None:
                roots.append(value)
        dictionary = getattr(owner, "__dict__", None)
        if isinstance(dictionary, dict):
            roots.append(dictionary)

    records = []
    seen_objects = set()
    seen_records = set()

    def first_sid(mapping, keys):
        for key in keys:
            sid = _metadata_sid_text_v13(mapping.get(key))
            if sid:
                return sid
        return None

    def input_sids(mapping):
        out = []
        for key in (
            "input_sids", "source_sids", "incoming_sids",
            "phi_input_sids", "inputs", "sources", "incoming",
        ):
            for sid in _metadata_sid_list_v13(mapping.get(key)):
                if sid not in out:
                    out.append(sid)
        for key in (
            "source_sid", "incoming_sid", "entry_source_sid",
            "backedge_source_sid", "value_sid",
        ):
            sid = _metadata_sid_text_v13(mapping.get(key))
            if sid and sid not in out:
                out.append(sid)
        return out

    def walk(value, depth=0):
        if value is None or depth > 10:
            return
        if isinstance(value, (str, bytes, int, float, bool)):
            return
        marker = id(value)
        if marker in seen_objects:
            return
        seen_objects.add(marker)

        mapping = _mapping_value(value)
        if mapping is None:
            dictionary = getattr(value, "__dict__", None)
            if isinstance(dictionary, dict):
                mapping = dictionary

        if mapping is not None:
            opcode = str(
                mapping.get("opcode")
                or mapping.get("op_name")
                or mapping.get("mnemonic")
                or ""
            ).upper()
            kind = str(
                mapping.get("kind")
                or mapping.get("record_kind")
                or mapping.get("semantic_role")
                or ""
            ).lower()
            is_phi = (
                opcode == "MULTIEQUAL"
                or bool(mapping.get("is_phi"))
                or "phi" in kind
                or "multiequal" in kind
            )

            if is_phi:
                output_sid = first_sid(mapping, (
                    "output_sid", "target_sid", "phi_output_sid",
                    "join_sid", "destination_sid", "output", "target",
                ))
                inputs = input_sids(mapping)
                if output_sid and inputs:
                    block_addr = (
                        mapping.get("block_addr")
                        or mapping.get("join_addr")
                        or mapping.get("header_addr")
                        or mapping.get("target_block_addr")
                        or mapping.get("address")
                    )
                    predecessor = (
                        mapping.get("pred_addr")
                        or mapping.get("predecessor_addr")
                        or mapping.get("source_block_addr")
                    )
                    seqnum = mapping.get("seqnum") or mapping.get("op_key")
                    record = {
                        "opcode": opcode or "PHI",
                        "kind": kind or "phi_custody",
                        "output_sid": str(output_sid),
                        "input_sids": [str(item) for item in inputs],
                        "block_addr": block_addr,
                        "predecessor_addr": predecessor,
                        "seqnum": seqnum,
                    }
                    record_key = (
                        record["output_sid"],
                        tuple(record["input_sids"]),
                        str(block_addr),
                        str(predecessor),
                        str(seqnum),
                    )
                    if record_key not in seen_records:
                        seen_records.add(record_key)
                        records.append(record)

            for child in mapping.values():
                walk(child, depth + 1)
            return

        if isinstance(value, (list, tuple, set)):
            for child in value:
                walk(child, depth + 1)

    for root in roots:
        walk(root)

    return records


def _human_join_v13(values):
    values = [str(value) for value in list(values or []) if value is not None]
    if not values:
        return "no incoming values"
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return "%s and %s" % (values[0], values[1])
    return "%s, and %s" % (", ".join(values[:-1]), values[-1])


def _display_address_v13(value):
    if value is None or value == "":
        return "an unlabelled block"
    if isinstance(value, int):
        return "block %s" % hex(value)
    text = str(value).strip()
    try:
        return "block %s" % hex(int(text, 0))
    except Exception:
        return "block %s" % text


_PHI_VOID_ADDRESS_TOKENS_V24 = frozenset({
    "", "-", "void", "<void>", "none", "<none>", "null", "<null>",
    "nil", "<nil>", "nan", "unknown", "<unknown>", "unavailable",
})


def _display_address_token_v14(value):
    """Compact address token used by the PHI custody blade.

    mars v0.29 treats metadata sentinels such as ``<void>`` as absent
    transition evidence.  Rows without a real machine address are suppressed
    entirely and never become visible or clickable pseudo-transitions.
    """
    if value is None or value == "":
        return "-"
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip()
    if text.casefold() in _PHI_VOID_ADDRESS_TOKENS_V24:
        return "-"
    try:
        return hex(int(text, 0))
    except Exception:
        match = re.search(r"0x[0-9A-Fa-f]+", text)
        if match:
            return match.group(0).lower()
        bare = re.search(r"\b[0-9A-Fa-f]{6,16}\b", text)
        if bare:
            return "0x" + bare.group(0).lower()
        return "-"


def _phi_clickable_address_v24(value):
    token = _display_address_token_v14(value)
    return token if token and token != "-" else None


def _phi_merge_values_v14(values):
    values = [str(value) for value in list(values or []) if value is not None]
    if not values:
        return "[]"
    if len(values) == 1:
        return values[0]
    return "[%s]" % _human_join_v13(values)


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
        self.minimal_variable_metadata = TERMUI_MINIMAL_VARIABLE_METADATA
        self._render_cache = {}
        self._mapping_cache = {}
        self._line_span_cache = {}
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

    def _invalidate_projection_caches(self):
        self._render_cache.clear()
        self._mapping_cache.clear()
        self._line_span_cache.clear()

    def base_lines(self, projection):
        projection = str(projection)
        if projection not in self._base_cache:
            self._base_cache[projection] = tuple(
                _document_projection_lines(self.document, projection)
            )
        return self._base_cache[projection]

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

        metadata_records = (
            {}
            if self.minimal_variable_metadata
            else _metadata_variable_records(self.document)
        )
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
            if _contract_has_local_stack_name(prior, pal_name):
                item["is_abi_physical_carrier"] = False
                item["operator_rename_eligible"] = True
            if (
                prior.get("rename_locked")
                or prior.get("humanization_eligible") is False
            ) and not _contract_has_local_stack_name(prior, pal_name):
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
                    (prior.get("rename_locked")
                    or prior.get("humanization_eligible") is False)
                    and not _contract_has_local_stack_name(prior, pal_name)
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
        # Presentation-level stack locals are intentionally operator-editable.
        # Canonical SSA identity and all frozen metadata remain unchanged.
        requested_aliases = {
            str(sid): str(value).strip()
            for sid, value in dict(self.operator_aliases or {}).items()
            if value is not None and str(value).strip()
        }
        alias_counts = {}
        for value in requested_aliases.values():
            alias_counts[value] = alias_counts.get(value, 0) + 1
        for sid, contract in dict(contracts or {}).items():
            local_stack = _contract_has_local_stack_name(contract)
            requested = requested_aliases.get(str(sid))
            admin_eligible = _operator_admin_rename_eligible_v34(contract)
            if local_stack or (requested and admin_eligible):
                contract["rename_locked"] = False
                contract["humanization_eligible"] = True
                contract["operator_rename_eligible"] = True
                if local_stack:
                    contract["is_abi_physical_carrier"] = False
                reason = str(contract.get("humanization_exclusion_reason") or "")
                if local_stack and ("local" in reason.casefold() or "stack" in reason.casefold()):
                    contract["humanization_exclusion_reason"] = None
            if (
                requested and admin_eligible and requested.isidentifier()
                and not keyword.iskeyword(requested)
                and alias_counts.get(requested, 0) == 1
                and requested not in self.function_names
            ):
                contract["operator_alias"] = requested
                contract["active_name"] = requested
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
        self._invalidate_projection_caches()
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
        key = (str(naming or "humanizer").lower(), bool(operator_overlay))
        cached = self._mapping_cache.get(key)
        if cached is not None:
            return cached
        mapping = self.variable_mapping(naming, operator_overlay)
        for source, target in self.function_mapping(naming, operator_overlay).items():
            if source not in mapping:
                mapping[source] = target
        self._mapping_cache[key] = mapping
        return mapping

    def render_lines(self, projection, naming, operator_overlay=False):
        key = (
            str(projection),
            str(naming or "humanizer").lower(),
            bool(operator_overlay),
        )
        cached = self._render_cache.get(key)
        if cached is None:
            cached = tuple(_replace_name_tokens(
                self.base_lines(projection),
                self.display_mapping(naming, operator_overlay),
            ))
            self._render_cache[key] = cached
        return cached

    def _line_spans(self, projection, naming, line, operator_overlay=False):
        key = (
            str(projection),
            str(naming or "humanizer").lower(),
            bool(operator_overlay),
            int(line),
        )
        cached = self._line_span_cache.get(key)
        if cached is not None:
            return cached
        base = self.base_lines(projection)
        if not base or line < 0 or line >= len(base):
            cached = ()
        else:
            cached = tuple(_line_token_spans(
                base[line],
                self.display_mapping(naming, operator_overlay),
            ))
        self._line_span_cache[key] = cached
        return cached

    def display_to_pal_column(
        self, projection, naming, line, column, operator_overlay=False
    ):
        base = self.base_lines(projection)
        if not base or line < 0 or line >= len(base):
            return max(0, int(column))
        spans = self._line_spans(
            projection, naming, line, operator_overlay
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
        spans = self._line_spans(
            projection, naming, line, operator_overlay
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

    def rename(self, sid, alias, author="human", admin=False):
        sid = str(sid)
        contract = self.contracts.get(sid)
        if contract is None:
            raise KeyError("unknown ONCS variable identity %s" % sid)
        if contract.get("rename_locked") and not _contract_has_local_stack_name(contract):
            if not admin or _contract_operator_rename_protected_v34(contract):
                raise ValueError("rename locked: %s" % (
                    contract.get("humanization_exclusion_reason")
                    or "protected ABI/system semantic identity"
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
        "variables": "VARIABLES / ONCS",
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
        self._hotspot_cache = {}
        self._cursor_block_cache = {}
        self._projection_sync_cache = {}
        self._truth_source_lines_cache = {}
        # PHI data remains lazy: the graphic DETAILS workspace opens it on demand
        # with PHI as a first-class panel; metadata is collected only on entry.
        self._phi_metadata_cache_v14 = None
        self._phi_inventory_cache_v14 = {}
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

    def canonical_phi_sid_v33(self, value):
        """Resolve any active/PAL/Humanized/operator spelling to canonical SSA."""
        raw = str(value or "").strip()
        if not raw:
            return raw
        try:
            graph = self._phi_graph_v14()
            mapped = dict(graph.get("canonical_by_name", {}) or {}).get(raw)
            if mapped:
                return str(mapped)
        except Exception:
            pass
        owner = dict(getattr(self.oncs, "name_owner", {}) or {}).get(raw)
        if owner:
            return str(owner)
        for sid, contract in dict(getattr(self.oncs, "contracts", {}) or {}).items():
            contract = dict(contract or {})
            names = {
                str(candidate) for candidate in (
                    sid, contract.get("canonical_ssa_name"),
                    contract.get("pal_name"), contract.get("active_name"),
                    contract.get("generated_human_alias"),
                    contract.get("operator_alias"),
                ) if candidate
            }
            if raw in names:
                return str(contract.get("canonical_ssa_name") or sid)
        return raw
    def active_name_contract_v38(self, value):
        """Resolve any SSA/PAL/Humanized/operator spelling to one ONCS contract.

        RC2 centralizes name ownership here so PHI, search/highlight and every
        reconstructed pane consult the same live overlay rather than a cached
        pre-rename spelling such as ``local_14``.
        """
        raw = str(value or "").strip()
        canonical = self.canonical_phi_sid_v33(raw)
        contracts = dict(getattr(self.oncs, "contracts", {}) or {})
        for candidate in (canonical, raw):
            if candidate in contracts:
                return str(candidate), dict(contracts[candidate] or {})
        owner = dict(getattr(self.oncs, "name_owner", {}) or {}).get(raw)
        if owner and owner in contracts:
            return str(owner), dict(contracts[owner] or {})
        for sid, contract in contracts.items():
            contract = dict(contract or {})
            names = {
                str(item) for item in (
                    sid, contract.get("sid"), contract.get("canonical_ssa_name"),
                    contract.get("pal_name"), contract.get("display_name"),
                    contract.get("generated_human_alias"),
                    contract.get("operator_alias"), contract.get("active_name"),
                    contract.get("original_name"),
                ) if item
            }
            if raw in names or canonical in names:
                return str(sid), contract
        return canonical or raw, {}

    def active_display_name_v38(self, value):
        """Return the live ``SSA|PAL|HUMANIZED + Oper`` presentation name."""
        canonical, contract = self.active_name_contract_v38(value)
        if contract:
            if self.operator_overlay and contract.get("operator_alias"):
                return str(contract.get("operator_alias"))
            projected = _base_variable_name(contract, self.naming)
            if projected:
                return str(projected)
        return str(canonical or value or "")

    def active_name_overlay_mapping_v38(self):
        """Map every known spelling to the current live display name.

        Mapping every alias, not only PAL names, prevents frozen PHI strings and
        refreshed metadata labels from leaking an earlier local/SSA spelling.
        """
        mapping = {}
        for sid, raw_contract in dict(getattr(self.oncs, "contracts", {}) or {}).items():
            contract = dict(raw_contract or {})
            target = self.active_display_name_v38(sid)
            for source in (
                sid, contract.get("sid"), contract.get("canonical_ssa_name"),
                contract.get("pal_name"), contract.get("display_name"),
                contract.get("generated_human_alias"),
                contract.get("operator_alias"), contract.get("active_name"),
                contract.get("original_name"),
            ):
                if source and str(source) != target:
                    mapping[str(source)] = target
        try:
            mapping.update(self.oncs.function_mapping(
                self.naming, self.operator_overlay
            ))
        except Exception:
            pass
        return mapping

    def apply_active_name_overlay_v38(self, text):
        values = _replace_name_tokens(
            [str(text or "")], self.active_name_overlay_mapping_v38()
        )
        return values[0] if values else str(text or "")

    def phi_display_name_v30(self, value):
        """Render a PHI identity through the single active-name resolver."""
        return self.active_display_name_v38(value)

    def phi_display_expression_v30(self, values):
        return " + ".join(
            self.active_display_name_v38(value)
            for value in list(values or ())
        )

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
            mapping = self.sync_projection_cursor(
                self.projection,
                target,
                self.line,
                source_base_column,
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

    def current_contract(self, advanced=False):
        """Return the editable variable identity beneath the cursor.

        v11 keeps ordinary cursor movement lexical and cached.  The expensive
        object/hotspot recovery path is entered only for explicit variable
        operations such as rename, revert and highlight.
        """
        contract = self.oncs.contract_at(
            self.projection, self.naming, self.line, self.column,
            self.operator_overlay,
        )
        if contract is not None or not advanced:
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
        contract = dict(contract or self.current_contract(advanced=False) or {})
        if not contract:
            return None
        if self.operator_overlay and contract.get("operator_alias"):
            return str(contract.get("operator_alias"))
        value = _base_variable_name(contract, self.naming)
        return str(value) if value else None

    def rename_current_variable(self, alias, author="human", admin=False):
        contract = self.current_contract(advanced=True)
        if contract is None:
            raise ValueError(
                "cursor is not on an editable variable; function calls and structural labels are locked"
            )
        value = self.oncs.rename(
            contract["sid"], alias, author=author, admin=admin
        )
        self.operator_overlay = True
        self.oncs.save()
        self.status = "operator alias saved: %s" % value
        return value

    def rename_variable_sid_v34(self, sid, alias, author="operator-admin"):
        sid = str(sid or "")
        contract = dict(self.oncs.contracts.get(sid, {}) or {})
        if not contract:
            raise ValueError("unknown ONCS variable identity %s" % (sid or "-"))
        if _contract_operator_rename_protected_v34(contract):
            raise ValueError(
                "protected ABI/system variable cannot be renamed: %s"
                % (contract.get("pal_name") or sid)
            )
        value = self.oncs.rename(
            sid, alias, author=author, admin=True
        )
        self.operator_overlay = True
        self.oncs.save()
        self.status = "F4 operator alias saved: %s" % value
        return value

    def revert_current_variable(self, author="human"):
        contract = self.current_contract(advanced=True)
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
        contract = self.current_contract(advanced=True)
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
            item for item in list(self.hotspots(projection) or [])
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
        """Commit block/statement allegiance without deep variable lookup."""
        self.clamp()
        try:
            contract = self.current_contract(advanced=False)
        except Exception:
            contract = None
        self.cursor_contract_sid = (
            str(contract.get("sid")) if contract is not None else None
        )
        try:
            self.cursor_context = self._cursor_context(
                include_variable=False
            )
        except Exception:
            self.cursor_context = {
                "projection": self.projection,
                "line": self.line,
                "column": self.column,
            }
        if self.cursor_contract_sid is not None:
            self.cursor_context["variable_sid"] = self.cursor_contract_sid
        return dict(self.cursor_context)

    def toggle_object_focus(self, projection=None, line=None, column=None):
        focus = self.cursor_object_context(projection, line, column)
        if focus is None:
            # ENTER on untagged space is an explicit clear operation.  Clear the
            # legacy SID highlight too; otherwise OVERVIEW rendering continues
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
        projection = str(projection or self.projection)
        if projection not in self._hotspot_cache:
            self._hotspot_cache[projection] = tuple(
                projection_hotspots(self.document, projection) or ()
            )
        return self._hotspot_cache[projection]

    def sync_projection_cursor(
        self, source_projection, target_projection, line, base_column
    ):
        """Cached statement/block allegiance mapping for READ/EXEC linkage."""
        key = (
            str(source_projection),
            str(target_projection),
            int(line),
        )
        cached = self._projection_sync_cache.get(key)
        if cached is not None:
            return dict(cached)
        mapping = self.document.sync_cursor(
            source_projection,
            target_projection,
            int(line),
            int(base_column),
            source_naming="pal",
            target_naming="pal",
        )
        mapping = dict(mapping or {})
        self._projection_sync_cache[key] = mapping
        return dict(mapping)

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

    def _cursor_context(self, include_variable=False):
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
            cache_key = (self.projection, int(self.line))
            raw_context = self._cursor_block_cache.get(cache_key)
            if raw_context is None:
                described = self.document.describe_cursor(
                    self.projection, self.line, base_column, line_base=0
                )
                raw_context = dict(described.get("context", {}) or {})
                self._cursor_block_cache[cache_key] = raw_context
            context.update({
                "cfg_block_addr": raw_context.get("cfg_block_addr"),
                "statement_id": raw_context.get("statement_id"),
                "op_keys": list(raw_context.get("op_keys", []) or []),
                "metadata_refs": list(
                    raw_context.get("metadata_refs", []) or []
                ),
            })
            if not TERMUI_MINIMAL_VARIABLE_METADATA:
                context["object_context"] = raw_context.get("object_context")
        except Exception:
            pass
        if include_variable:
            contract = self.current_contract(advanced=True)
            if contract is not None:
                context["variable_sid"] = contract.get("sid")
        if self.object_focus is not None:
            context["focused_object"] = dict(self.object_focus)
        return context

    def oncs_digest_rows(self):
        contract = self.current_contract(advanced=True)
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

    def truth_source_lines(self, panel):
        """Frozen C/ASM source lines without ONCS variable-digest construction."""
        panel = str(panel)
        cached = self._truth_source_lines_cache.get(panel)
        if cached is not None:
            return cached
        metadata_view = IcecubeMetadataView(
            self.document, function_record=self.function_record
        )
        digest = TruthDigestDaily(
            metadata_view,
            oncs_rows=(),
            cursor=self._cursor_context(include_variable=False),
        )
        cached = tuple(
            str(value) for value in list(
                digest.source_lines(panel) or []
            )
        )
        self._truth_source_lines_cache[panel] = cached
        return cached

    @staticmethod
    def _block_cache_key_v12(block_addr):
        if block_addr is None:
            return None
        if isinstance(block_addr, int):
            return hex(block_addr)
        text = str(block_addr).strip()
        if not text:
            return None
        try:
            return hex(int(text, 0))
        except Exception:
            return text

    def cursor_block_addr_v12(
        self, projection=None, line=None, column=None
    ):
        """Return only CFG block allegiance for a rendered Python cursor.

        This deliberately avoids object/variable lookup.  It reuses the same
        line-addressed describe_cursor cache as the v11 minimal sidecar path.
        """
        projection = str(projection or self.projection)
        line = self.line if line is None else int(line)
        column = self.column if column is None else int(column)

        try:
            base_column = self.oncs.display_to_pal_column(
                projection,
                self.naming,
                line,
                column,
                self.operator_overlay,
            )
        except Exception:
            base_column = column

        cache_key = (projection, int(line))
        raw_context = self._cursor_block_cache.get(cache_key)
        if raw_context is None:
            try:
                described = self.document.describe_cursor(
                    projection,
                    line,
                    base_column,
                    line_base=0,
                )
                raw_context = dict(
                    described.get("context", {}) or {}
                )
            except Exception:
                raw_context = {}
            self._cursor_block_cache[cache_key] = raw_context

        return raw_context.get("cfg_block_addr")

    def truth_block_asm_lines_v12(self, block_addr):
        """Return one frozen ASM block, cached by canonical CFG address."""
        key = self._block_cache_key_v12(block_addr)
        cache_key = ("asm:block", key)
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        cursor = self._cursor_context(include_variable=False)
        cursor["cfg_block_addr"] = block_addr

        metadata_view = IcecubeMetadataView(
            self.document, function_record=self.function_record
        )
        digest = TruthDigestDaily(
            metadata_view,
            oncs_rows=(),
            cursor=cursor,
        )
        cached = tuple(
            str(value) for value in list(
                digest.source_lines("asm") or []
            )
        )
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def _phi_metadata_v14(self):
        if self._phi_metadata_cache_v14 is None:
            self._phi_metadata_cache_v14 = (
                _metadata_variable_records(self.document),
                _metadata_phi_records(self.document),
            )
        return self._phi_metadata_cache_v14

    def _phi_graph_v14(self):
        """Return the filtered, sector-ordered frozen variable/PHI graph.

        v17 retains the lazy Icecube path while tightening the microscope
        inventory contract:

        * function/callee objects are not variables and never enter the list;
        * active PHI merge outputs form the top sector;
        * constants and non-PHI/frozen variables form the bottom sector;
        * each sector is alphabetized independently by PAL name, then SSA SID.
        """
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cached = self._phi_inventory_cache_v14.get(revision)
        if cached is not None:
            return cached

        variable_records, phi_records = self._phi_metadata_v14()
        variable_records = dict(variable_records or {})
        phi_records = [dict(value) for value in list(phi_records or [])]

        name_by_sid = {}
        names_by_sid = {}
        canonical_by_name = {}
        candidate_sids = set()
        function_object_sids = set()
        constant_sids = set()

        function_object_names = set()
        for values in (
            getattr(self.oncs, "call_targets", set()),
            getattr(self.oncs, "function_defs", set()),
            getattr(self.oncs, "function_names", set()),
        ):
            for value in list(values or []):
                if value:
                    function_object_names.add(str(value))

        def record_role_text(record):
            record = dict(record or {})
            parts = []
            for key in (
                "kind", "record_kind", "semantic_role", "object_kind",
                "category", "type", "role",
            ):
                value = record.get(key)
                if value is not None:
                    parts.append(str(value).strip().lower())
            return " ".join(parts)

        def is_function_object(record, aliases):
            record = dict(record or {})
            if any(bool(record.get(key)) for key in (
                "is_function", "is_callee", "is_call_target",
                "is_function_symbol", "is_callable_object",
            )):
                return True
            role = record_role_text(record)
            compact = re.sub(r"[^a-z0-9]+", "_", role).strip("_")
            exact_roles = {
                "function", "function_symbol", "function_object",
                "callee", "call_target", "called_function",
                "external_function", "callable_object",
            }
            if compact in exact_roles:
                return True
            if any(token in compact for token in (
                "call_target", "called_function", "function_symbol",
                "function_object", "callee_object",
            )):
                return True

            # AST/project call-target names are the strongest practical signal
            # for legacy Icecubes that froze a callable as a generic object.
            for alias in aliases:
                alias = str(alias or "")
                if alias and alias in function_object_names:
                    return True
            return False

        def is_constant_record(record, aliases):
            record = dict(record or {})
            if bool(record.get("is_constant")) or bool(record.get("constant")):
                return True
            role = record_role_text(record)
            if "constant" in role or "literal" in role:
                return True
            return any(str(value or "").startswith("c_") for value in aliases)

        def remember_name(sid, value, canonical=None):
            if sid is None or not value:
                return
            sid = str(sid)
            value = str(value)
            canonical = str(canonical or sid)
            names_by_sid.setdefault(canonical, set()).add(value)
            name_by_sid.setdefault(canonical, value)
            canonical_by_name.setdefault(value, canonical)
            canonical_by_name.setdefault(sid, canonical)

        # ONCS contracts are authoritative for canonical SSA identity and PAL
        # naming.  Function objects remain name-resolvable but are excluded from
        # the selectable variable inventory.
        for sid, contract in dict(self.oncs.contracts or {}).items():
            contract = dict(contract or {})
            canonical = str(
                contract.get("canonical_ssa_name")
                or contract.get("sid")
                or sid
            )
            pal_name = str(
                contract.get("pal_name")
                or contract.get("active_name")
                or canonical
            )
            aliases = [
                sid,
                canonical,
                contract.get("canonical_ssa_name"),
                contract.get("pal_name"),
                contract.get("generated_human_alias"),
                contract.get("operator_alias"),
                contract.get("active_name"),
            ]
            name_by_sid[canonical] = pal_name
            for value in aliases:
                remember_name(canonical, value, canonical)
            if is_function_object(contract, aliases):
                function_object_sids.add(canonical)
            else:
                candidate_sids.add(canonical)
            if is_constant_record(contract, aliases):
                constant_sids.add(canonical)

        # Fold metadata-only variable spellings into known ONCS canonical SIDs.
        for raw_sid, record in variable_records.items():
            record = dict(record or {})
            aliases = [
                raw_sid,
                record.get("sid"),
                record.get("canonical_ssa_name"),
                record.get("ssa_id"),
                record.get("pal_name"),
                record.get("display_name"),
                record.get("name"),
                record.get("original_name"),
                record.get("active_name"),
            ]
            canonical = None
            for value in aliases:
                if value is not None and str(value) in canonical_by_name:
                    canonical = canonical_by_name[str(value)]
                    break
            canonical = str(canonical or raw_sid)
            for value in aliases:
                remember_name(canonical, value, canonical)
            for key in (
                "pal_name", "display_name", "name", "original_name",
                "active_name",
            ):
                value = record.get(key)
                if value:
                    name_by_sid.setdefault(canonical, str(value))
                    break
            if is_function_object(record, aliases):
                function_object_sids.add(canonical)
            else:
                candidate_sids.add(canonical)
            if is_constant_record(record, aliases):
                constant_sids.add(canonical)

        def canonical_sid(value):
            value = str(value)
            return str(canonical_by_name.get(value, value))

        by_output = {}
        for record in phi_records:
            output_sid = canonical_sid(record.get("output_sid") or "")
            if not output_sid or output_sid in function_object_sids:
                continue
            inputs = []
            for value in list(record.get("input_sids", []) or []):
                if value is None:
                    continue
                source_sid = canonical_sid(value)
                if source_sid in function_object_sids:
                    continue
                inputs.append(source_sid)
            if not inputs:
                continue
            record["output_sid"] = output_sid
            record["input_sids"] = inputs
            by_output.setdefault(output_sid, []).append(record)
            candidate_sids.add(output_sid)
            remember_name(output_sid, output_sid, output_sid)
            for source_sid in inputs:
                candidate_sids.add(source_sid)
                remember_name(source_sid, source_sid, source_sid)

        candidate_sids.difference_update(function_object_sids)

        for records in by_output.values():
            records.sort(key=lambda item: (
                _display_address_token_v14(item.get("block_addr")),
                _display_address_token_v14(item.get("predecessor_addr")),
                tuple(item.get("input_sids", []) or []),
            ))

        def roots_for(sid, trail=None):
            sid = str(sid)
            trail = set(trail or ())
            if sid in trail:
                return {sid}
            records = by_output.get(sid, [])
            if not records:
                return {sid}
            next_trail = set(trail)
            next_trail.add(sid)
            roots = set()
            for record in records:
                for source_sid in record.get("input_sids", []) or []:
                    roots.update(roots_for(str(source_sid), next_trail))
            return roots or {sid}

        entries = []
        for output_sid in candidate_sids:
            roots = tuple(sorted(roots_for(output_sid)))
            pal_name = str(name_by_sid.get(output_sid, output_sid))
            names = {output_sid, pal_name}
            names.update(roots)
            for record in by_output.get(output_sid, []):
                names.update(record.get("input_sids", []) or [])
            for sid in list(names):
                names.update(names_by_sid.get(str(sid), set()))
            has_phi = bool(by_output.get(output_sid))
            is_constant = (
                output_sid in constant_sids
                or pal_name.startswith("c_")
                or output_sid.startswith("c_")
            )
            root_expression = " + ".join(roots) if roots else output_sid
            entries.append({
                "output_sid": output_sid,
                "roots": roots,
                "root_expression": root_expression,
                "pal_name": pal_name,
                "names": frozenset(str(value) for value in names if value),
                "has_phi": has_phi,
                "is_constant": is_constant,
                "sector": "phi_active" if has_phi else "frozen",
                "row": "%s == [%s]" % (pal_name, root_expression),
            })

        # Separate alphabetical order inside each sector.  Active PHI merges are
        # always above constants/non-PHI frozen variables.
        entries.sort(key=lambda item: (
            0 if item.get("has_phi") else 1,
            str(item.get("pal_name") or "").casefold(),
            str(item.get("output_sid") or "").casefold(),
        ))
        for node_number, item in enumerate(entries, 1):
            item["node_number"] = node_number
        index_by_sid = {
            str(item.get("output_sid")): index
            for index, item in enumerate(entries)
        }
        cached = {
            "entries": tuple(entries),
            "by_output": by_output,
            "index_by_sid": index_by_sid,
            "canonical_by_name": canonical_by_name,
            "function_object_sids": frozenset(function_object_sids),
        }
        self._phi_inventory_cache_v14[revision] = cached
        return cached

    def phi_custody_inventory_v14(self, filter_text=None):
        # Return live-name copies.  The frozen graph remains canonical, while
        # every UI consumer receives the current F2 + Oper projection.
        entries = []
        for frozen in list(self._phi_graph_v14()["entries"]):
            entry = dict(frozen or {})
            output_sid = str(entry.get("output_sid") or "")
            roots = tuple(entry.get("roots", ()) or ())
            display_name = self.active_display_name_v38(output_sid)
            root_expression = self.phi_display_expression_v30(roots) or display_name
            names = set(str(value) for value in entry.get("names", ()) or ())
            names.update((display_name, root_expression))
            entry.update({
                "pal_name": display_name,
                "root_expression": root_expression,
                "row": "%s == [%s]" % (display_name, root_expression),
                "names": frozenset(value for value in names if value),
            })
            entries.append(entry)
        query = str(filter_text or "").strip().casefold()
        if not query:
            return tuple(entries)
        filtered = []
        for entry in entries:
            haystack = set(str(value) for value in entry.get("names", ()) or ())
            haystack.update((
                str(entry.get("output_sid") or ""),
                str(entry.get("pal_name") or ""),
                str(entry.get("row") or ""),
            ))
            if any(query in value.casefold() for value in haystack if value):
                filtered.append(entry)
        return tuple(filtered)

    def phi_custody_index_for_sid_v16(self, sid):
        if sid is None:
            return None
        graph = self._phi_graph_v14()
        canonical = str(
            graph.get("canonical_by_name", {}).get(str(sid), str(sid))
        )
        return graph.get("index_by_sid", {}).get(canonical)

    def phi_custody_detail_sid_v15(self, detail_line, fallback_sid=None):
        """Resolve the exact variable identity named by one selected DETAIL row."""
        graph = self._phi_graph_v14()
        entries = list(graph.get("entries", ()) or ())
        if not entries:
            return None

        tokens = set(re.findall(
            r"\b[A-Za-z_][A-Za-z0-9_]*\b",
            str(detail_line or ""),
        ))
        best = None
        for index, entry in enumerate(entries):
            output_sid = str(entry.get("output_sid") or "")
            pal_name = str(entry.get("pal_name") or "")
            roots = set(str(value) for value in entry.get("roots", ()) or ())
            names = set(str(value) for value in entry.get("names", ()) or ())
            score = 0
            if output_sid in tokens:
                score = max(score, 120)
            if pal_name in tokens:
                score = max(score, 115)
            exact_names = names & tokens
            if exact_names:
                score = max(score, 105)
            if roots & tokens:
                score = max(score, 95)
            if fallback_sid and str(fallback_sid) == output_sid:
                score = max(score, 70)
            candidate = (score, -index)
            if score and (best is None or candidate > best[0]):
                best = (candidate, output_sid)

        if best is not None:
            return best[1]

        fallback = str(fallback_sid or "")
        if fallback:
            canonical = str(
                graph.get("canonical_by_name", {}).get(fallback, fallback)
            )
            if canonical in graph.get("index_by_sid", {}):
                return canonical
        return None

    def phi_custody_link_index_v14(self, detail_line, fallback_sid=None):
        """Return the exact all-variable row for the selected DETAIL variable.

        Unlike v14, failure never degrades to row zero.  Returning ``None`` is
        intentional: unrelated PHI custody must never be shown for a row whose
        identity could not be established.
        """
        graph = self._phi_graph_v14()
        sid = self.phi_custody_detail_sid_v15(
            detail_line,
            fallback_sid=fallback_sid,
        )
        if sid is None:
            return None
        return graph.get("index_by_sid", {}).get(str(sid))

    def phi_custody_related_indices_v16(self, selected_index):
        """Selected variable first, then every PHI output depending on it."""
        graph = self._phi_graph_v14()
        entries = list(graph.get("entries", ()) or ())
        by_output = dict(graph.get("by_output", {}) or {})
        if not entries:
            return ()
        selected_index = min(max(int(selected_index or 0), 0), len(entries) - 1)
        selected_sid = str(entries[selected_index].get("output_sid") or "")

        dependency_cache = {}

        def depends_on(output_sid, target_sid, trail=None):
            key = (str(output_sid), str(target_sid))
            if key in dependency_cache:
                return dependency_cache[key]
            output_sid = str(output_sid)
            target_sid = str(target_sid)
            if output_sid == target_sid:
                dependency_cache[key] = True
                return True
            trail = set(trail or ())
            if output_sid in trail:
                dependency_cache[key] = False
                return False
            next_trail = set(trail)
            next_trail.add(output_sid)
            for record in by_output.get(output_sid, []) or []:
                for source_sid in record.get("input_sids", []) or []:
                    source_sid = str(source_sid)
                    if source_sid == target_sid or depends_on(
                        source_sid, target_sid, next_trail
                    ):
                        dependency_cache[key] = True
                        return True
            dependency_cache[key] = False
            return False

        related = [selected_index]
        others = []
        for index, entry in enumerate(entries):
            if index == selected_index or not entry.get("has_phi"):
                continue
            output_sid = str(entry.get("output_sid") or "")
            if depends_on(output_sid, selected_sid):
                others.append(index)
        others.sort(key=lambda index: (
            str(entries[index].get("pal_name") or "").casefold(),
            str(entries[index].get("output_sid") or "").casefold(),
        ))
        related.extend(others)
        return tuple(related)

    def phi_custody_blade_bundle_v16(self, selected_index):
        """Selected variable plus only PHI nodes transitively containing it.

        Every returned node is rendered through the same v17 singular-node ASCII
        template.  The selected inventory row remains the microscope anchor.
        """
        graph = self._phi_graph_v14()
        entries = list(graph.get("entries", ()) or ())
        if not entries:
            return {
                "selected_sid": None,
                "indices": (),
                "entries": (),
                "items": ({"kind": "empty", "text": "No variables are frozen."},),
            }
        selected_index = min(max(int(selected_index or 0), 0), len(entries) - 1)
        related_indices = self.phi_custody_related_indices_v16(selected_index)
        items = []
        related_entries = []
        for position, index in enumerate(related_indices):
            if position:
                items.append({"kind": "blank", "text": ""})
            related_entries.append(entries[index])
            items.extend(self.phi_custody_blade_v14(index))
        return {
            "selected_sid": str(entries[selected_index].get("output_sid") or ""),
            "indices": tuple(related_indices),
            "entries": tuple(related_entries),
            "items": tuple(items),
        }

    def phi_custody_blade_v14(self, index):
        """Build one live-name singular PHI-node record for every UI surface.

        mars v0.29 preserves recursive PHI depth in the rendered custody blade.
        Deeper prerequisite merges are indented two columns per cycle depth.
        Metadata sentinels such as ``<void>`` and records without a concrete
        address are omitted from the blade rather than rendered as placeholders.
        """
        graph = self._phi_graph_v14()
        entries = list(graph.get("entries", ()) or ())
        by_output = dict(graph.get("by_output", {}) or {})
        if not entries:
            return ({"kind": "empty", "text": "No variables are frozen."},)

        index = min(max(int(index or 0), 0), len(entries) - 1)
        entry = entries[index]
        output_sid = str(entry.get("output_sid") or "")
        roots = list(entry.get("roots", ()) or ())
        root_expression = (
            self.phi_display_expression_v30(roots)
            or self.phi_display_name_v30(output_sid)
        )
        display_name = self.phi_display_name_v30(output_sid)
        node_number = int(entry.get("node_number") or (index + 1))
        node_prefix = "   #%d " % node_number
        name_offset = len(node_prefix)
        header_width = max(
            54, name_offset + len(display_name) + len(root_expression) + 8
        )

        rows = [
            {
                "kind": "header_top", "text": " " * header_width,
                "header_name_offset": name_offset,
                "header_name_width": len(display_name),
            },
            {
                "kind": "header",
                "text": "%s%s <= [%s]" % (
                    node_prefix, display_name, root_expression
                ),
                "header_name_offset": name_offset,
                "header_name_width": len(display_name),
            },
            {
                "kind": "header_bottom", "text": " " * header_width,
                "header_name_offset": name_offset,
                "header_name_width": len(display_name),
            },
            {"kind": "blank", "text": ""},
            {"kind": "trunk", "text": "        |", "phi_depth": 0},
        ]

        emitted = set()
        first_event = [True]

        def event_glyph():
            glyph = "|" if first_event[0] else "│"
            first_event[0] = False
            return glyph

        def depth_indent(depth):
            return "  " * max(0, int(depth or 0))

        def append_event(kind, raw_address, body, sid=None, depth=0):
            address = _phi_clickable_address_v24(raw_address)
            if address is None:
                # mars v0.29: an absent/void address is not a transition row.
                # Keep it in frozen metadata, but do not manufacture a visible
                # placeholder that can displace the PHI cursor.
                return False
            glyph = event_glyph()
            prefix = "        %s%s " % (glyph, depth_indent(depth))
            text = "%s%-21s %s" % (prefix, address, body)
            rows.append({
                "kind": kind,
                "address": address,
                "address_display": address,
                "address_missing": False,
                "glyph": glyph,
                "address_offset": len(prefix),
                "text": text,
                "event_sid": sid,
                "block_hotspot": True,
                "phi_depth": int(depth or 0),
            })
            return True

        def append_cycle(source_sid, block_addr=None, depth=0):
            display_source = self.phi_display_name_v30(source_sid)
            address = _phi_clickable_address_v24(block_addr)
            if address is None:
                return False
            prefix = "        |%s " % depth_indent(depth)
            text = (
                "%s%-21s ----> PHI custody cycles back through %s"
                % (prefix, address, display_source)
            )
            rows.append({
                "kind": "cycle",
                "address": address,
                "address_display": address,
                "address_missing": False,
                "address_offset": len(prefix),
                "text": text,
                "cycle_target": True,
                "block_hotspot": True,
                "phi_depth": int(depth or 0),
            })
            return True

        def emit_sid(sid, trail=None, depth=0):
            sid = str(sid)
            trail = tuple(trail or ())
            if sid in trail:
                append_cycle(sid, depth=depth)
                return
            records = list(by_output.get(sid, []) or [])
            if not records:
                return
            next_trail = trail + (sid,)
            for record in records:
                record_key = (
                    sid,
                    tuple(record.get("input_sids", []) or []),
                    str(record.get("block_addr")),
                    str(record.get("predecessor_addr")),
                )
                if record_key in emitted:
                    continue

                cycle_sources = []
                for source_sid in record.get("input_sids", []) or []:
                    source_sid = str(source_sid)
                    if source_sid in next_trail:
                        cycle_sources.append(source_sid)
                    elif source_sid in by_output:
                        emit_sid(source_sid, next_trail, depth + 1)

                predecessor = record.get("predecessor_addr")
                if predecessor is not None:
                    append_event(
                        "incoming", predecessor,
                        "= value arrives", sid=sid, depth=depth,
                    )

                for source_sid in cycle_sources:
                    append_cycle(
                        source_sid, record.get("block_addr"), depth=depth + 1
                    )

                inputs = [
                    self.phi_display_name_v30(value)
                    for value in list(record.get("input_sids", []) or [])
                ]
                append_event(
                    "merge", record.get("block_addr"),
                    "PHI merges %s into %s" % (
                        _phi_merge_values_v14(inputs),
                        self.phi_display_name_v30(sid),
                    ),
                    sid=sid, depth=depth,
                )
                emitted.add(record_key)

        emit_sid(output_sid, depth=0)
        if not by_output.get(output_sid):
            rows.append({
                "kind": "body",
                "text": "        | No PHI custody chain is frozen for %s"
                % display_name,
                "phi_depth": 0,
            })
        rows.extend((
            {"kind": "trunk", "text": "        |", "phi_depth": 0},
            {
                "kind": "final",
                "final_sid": display_name,
                "canonical_final_sid": output_sid,
                "text": "        |--------> Final State: %s" % display_name,
                "phi_depth": 0,
            },
        ))
        for row in rows:
            row.setdefault("phi_template", True)
            row.setdefault("node_index", index)
            row.setdefault("node_number", node_number)
            row.setdefault("output_sid", output_sid)
            row.setdefault("sid", output_sid)
            row.setdefault("pal_name", display_name)
            row.setdefault("root_expression", root_expression)
        return tuple(rows)


    def asm_blocks_v17(self):
        """Return frozen ASM blocks with normalized entry/terminator addresses.

        Some Icecubes key blocks with symbolic labels such as ``A/B/C``.  UI
        linkage must never expose those labels as machine addresses.  The block
        entry is therefore resolved from explicit address fields, then the first
        instruction, then the first address-bearing rendered line.  The
        terminator address follows the same rule from the final instruction.
        """
        cache_key = ("asm:all_blocks:v31",)
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        raw = None
        metadata = getattr(self.document, "metadata", None)
        resolver = getattr(metadata, "resolve", None)
        if callable(resolver):
            try:
                raw = resolver("asm:blocks", None)
            except TypeError:
                try:
                    raw = resolver("asm:blocks")
                except Exception:
                    raw = None
            except Exception:
                raw = None

        def address_token(value):
            if value is None:
                return None
            text = str(value).strip()
            match = re.search(r"0x[0-9A-Fa-f]+", text)
            if match:
                return self._canonical_block_addr_v21(match.group(0))
            if re.fullmatch(r"[0-9A-Fa-f]{6,16}", text):
                return self._canonical_block_addr_v21("0x" + text)
            return None

        def first_address(values):
            for value in values:
                token = address_token(value)
                if token:
                    return token
            return None

        def flatten_references(value):
            out = []
            if value is None:
                return out
            mapping = _mapping_value(value)
            if mapping is not None:
                for key in (
                    "addr", "address", "block_addr", "entry", "entry_addr",
                    "target", "target_addr", "destination", "destination_addr",
                ):
                    if mapping.get(key) is not None:
                        out.extend(flatten_references(mapping.get(key)))
                return out
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    out.extend(flatten_references(item))
                return out
            token = address_token(value)
            text = str(value).strip()
            if token:
                out.append(token)
            elif text:
                out.append(text)
            return out

        mapping = _mapping_value(raw)
        blocks = []
        if mapping is not None:
            def address_sort(value):
                token = address_token(value)
                if token:
                    try:
                        return (0, int(token, 0))
                    except Exception:
                        pass
                return (1, str(value).casefold())

            for raw_addr in sorted(mapping, key=address_sort):
                record = _mapping_value(mapping.get(raw_addr)) or {}
                instructions = [
                    _mapping_value(item) or {}
                    for item in list(record.get("instructions", []) or [])
                ]
                lines = [str(value) for value in list(record.get("lines", []) or [])]
                instruction_addrs = []
                for item in instructions:
                    token = address_token(item.get("addr") or item.get("address"))
                    if token and token not in instruction_addrs:
                        instruction_addrs.append(token)
                if not lines:
                    for item in instructions:
                        instruction_addr = str(item.get("addr") or item.get("address") or "-")
                        assembly = str(item.get("assembly") or item.get("mnemonic") or "")
                        lines.append("%-18s %s" % (instruction_addr, assembly))
                if not instruction_addrs:
                    for line in lines:
                        token = address_token(line)
                        if token and token not in instruction_addrs:
                            instruction_addrs.append(token)

                explicit_entry = first_address(
                    record.get(key) for key in (
                        "entry_addr", "start_addr", "block_start", "address", "block_addr"
                    )
                )
                instruction_entries = [
                    item.get("addr") or item.get("address") for item in instructions
                ]
                line_entries = [line for line in lines]
                entry_addr = (
                    explicit_entry
                    or first_address(instruction_entries)
                    or first_address(line_entries)
                    or address_token(raw_addr)
                    or str(raw_addr)
                )

                explicit_term = first_address(
                    record.get(key) for key in (
                        "terminator_addr", "terminal_addr", "last_addr", "end_addr"
                    )
                )
                terminator_addr = (
                    explicit_term
                    or first_address(reversed(instruction_entries))
                    or first_address(reversed(line_entries))
                    or entry_addr
                )

                references = []
                successors = []
                for key in (
                    "terminal_successors", "successors", "flows", "flow_targets",
                    "next_block_start",
                ):
                    values = flatten_references(record.get(key))
                    references.extend(values)
                    if key in ("terminal_successors", "successors", "flow_targets", "next_block_start"):
                        successors.extend(values)
                references = list(dict.fromkeys(value for value in references if value))
                successors = list(dict.fromkeys(value for value in successors if value))
                search_text = "\n".join(
                    [str(entry_addr), str(terminator_addr)] + lines + references
                ).casefold()
                blocks.append({
                    "addr": str(entry_addr),
                    "entry_addr": str(entry_addr),
                    "terminator_addr": str(terminator_addr),
                    "raw_block_id": str(raw_addr),
                    "lines": tuple(lines),
                    "instruction_addrs": tuple(instruction_addrs),
                    "references": tuple(references),
                    "successors": tuple(successors),
                    "search_text": search_text,
                })

            raw_to_entry = {
                str(block.get("raw_block_id") or "").casefold(): str(block.get("addr"))
                for block in blocks if block.get("raw_block_id")
            }
            for block in blocks:
                def normalize_reference(value):
                    raw_value = str(value or "").strip()
                    mapped = raw_to_entry.get(raw_value.casefold())
                    if mapped:
                        return mapped
                    return address_token(raw_value) or raw_value
                block["references"] = tuple(dict.fromkeys(
                    normalize_reference(value)
                    for value in list(block.get("references", ()) or ())
                    if normalize_reference(value)
                ))
                block["successors"] = tuple(dict.fromkeys(
                    normalize_reference(value)
                    for value in list(block.get("successors", ()) or ())
                    if normalize_reference(value)
                ))
                block["search_text"] = "\n".join(
                    [str(block.get("addr")), str(block.get("terminator_addr"))]
                    + list(block.get("lines", ()) or ())
                    + list(block.get("references", ()) or ())
                ).casefold()

        if not blocks:
            metadata_view = IcecubeMetadataView(
                self.document, function_record=self.function_record
            )
            try:
                panel = dict(metadata_view.asm(None) or {})
                fallback_lines = [str(value) for value in list(panel.get("lines", []) or [])]
            except Exception:
                fallback_lines = []
            if fallback_lines:
                blocks.append({
                    "addr": "all", "entry_addr": "all", "terminator_addr": "all",
                    "raw_block_id": "all", "lines": tuple(fallback_lines),
                    "instruction_addrs": tuple(
                        token for token in (address_token(line) for line in fallback_lines)
                        if token
                    ),
                    "references": (), "successors": (),
                    "search_text": "\n".join(fallback_lines).casefold(),
                })

        cached = tuple(blocks)
        self._truth_source_lines_cache[cache_key] = cached
        return cached


    def asm_detail_lines_v17(self, full_scope=False, filter_text=None):
        """Render current-block or full-function ASM, filtered by block content."""
        blocks = list(self.asm_blocks_v17() or ())
        current_addr = self._block_cache_key_v12(self.cursor_block_addr_v12())
        if not full_scope and current_addr is not None:
            selected = [
                item for item in blocks
                if self._block_cache_key_v12(item.get("addr")) == current_addr
            ]
            blocks = selected

        query = str(filter_text or "").strip().casefold()
        terms = [term for term in query.split() if term]
        if terms:
            blocks = [
                item for item in blocks
                if all(term in str(item.get("search_text") or "") for term in terms)
            ]

        lines = []
        for position, block in enumerate(blocks):
            if position:
                lines.append("")
            lines.append("BLOCK %s" % str(block.get("addr") or "-"))
            lines.append("-" * 44)
            lines.extend(str(value) for value in list(block.get("lines", ()) or ()))
        if not lines:
            scope = "all blocks" if full_scope else "current block"
            if query:
                lines.append("No %s match /%s" % (scope, filter_text))
            else:
                lines.append("No frozen ASM is available for %s." % scope)
        return tuple(lines)

    @staticmethod
    def _canonical_block_addr_v21(value):
        """Canonical address token shared by PHI, ASM and code linkage."""
        if value is None or value == "":
            return None
        token = _display_address_token_v14(value)
        if token in (None, "", "-"):
            return None
        return str(token).strip().casefold()

    def phi_path_focus_rows_v21(self):
        """Return cached incoming-block PHI path rows.

        v22 hotfix deliberately bypasses the transitive PHI root graph.  Path
        Focus needs only frozen predecessor/merge custody, not recursive root
        expansion; using the smaller record inventory prevents a dense loop-PHI
        graph from delaying the first modal frame.
        """
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = ("phi:path_rows:v38", revision, str(self.naming), bool(self.operator_overlay))
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        variable_records, phi_records = self._phi_metadata_v14()
        variable_records = dict(variable_records or {})
        phi_records = [dict(value) for value in list(phi_records or ())]

        canonical_by_name = {}
        pal_by_sid = {}

        def remember(canonical, value):
            if canonical and value:
                canonical_by_name.setdefault(str(value), str(canonical))

        for sid, contract in dict(self.oncs.contracts or {}).items():
            contract = dict(contract or {})
            canonical = str(
                contract.get("canonical_ssa_name")
                or contract.get("sid")
                or sid
            )
            pal_by_sid[canonical] = str(
                contract.get("pal_name")
                or contract.get("active_name")
                or canonical
            )
            for value in (
                sid, canonical, contract.get("canonical_ssa_name"),
                contract.get("pal_name"),
                contract.get("generated_human_alias"),
                contract.get("operator_alias"), contract.get("active_name"),
            ):
                remember(canonical, value)

        for raw_sid, record in variable_records.items():
            record = dict(record or {})
            aliases = (
                raw_sid, record.get("sid"), record.get("canonical_ssa_name"),
                record.get("ssa_id"), record.get("pal_name"),
                record.get("display_name"), record.get("name"),
                record.get("original_name"), record.get("active_name"),
            )
            canonical = next((
                canonical_by_name[str(value)] for value in aliases
                if value is not None and str(value) in canonical_by_name
            ), str(raw_sid))
            for value in aliases:
                remember(canonical, value)
            for key in (
                "pal_name", "display_name", "name", "original_name",
                "active_name",
            ):
                value = record.get(key)
                if value:
                    pal_by_sid.setdefault(canonical, str(value))
                    break

        def canonical_sid(value):
            value = str(value or "")
            return str(canonical_by_name.get(value, value))

        rows = []
        seen = set()
        for record in phi_records:
            output_sid = canonical_sid(record.get("output_sid"))
            if not output_sid:
                continue
            incoming = self._canonical_block_addr_v21(
                record.get("predecessor_addr")
            )
            merge = self._canonical_block_addr_v21(record.get("block_addr"))
            if incoming is None:
                incoming = merge
                incoming_role = "merge_fallback"
            else:
                incoming_role = "incoming"
            if incoming is None:
                continue
            inputs = tuple(
                canonical_sid(value)
                for value in list(record.get("input_sids", ()) or ())
                if value is not None
            )
            key = (incoming, merge, output_sid, inputs)
            if key in seen:
                continue
            seen.add(key)
            pal_name = self.active_display_name_v38(output_sid)
            rows.append({
                "kind": "phi_path",
                "incoming_addr": incoming,
                "incoming_role": incoming_role,
                "merge_addr": merge,
                "output_sid": output_sid,
                "pal_name": pal_name,
                "input_sids": inputs,
                "record": dict(record),
                "text": "%s => %s @ %s [%d in]" % (
                    incoming, pal_name, merge or "-", len(inputs)
                ),
            })

        def address_key(value):
            value = str(value or "")
            try:
                return (0, int(value, 0))
            except Exception:
                return (1, value.casefold())

        rows.sort(key=lambda item: (
            address_key(item.get("incoming_addr")),
            str(item.get("pal_name") or "").casefold(),
            address_key(item.get("merge_addr")),
            str(item.get("output_sid") or "").casefold(),
        ))
        cached = tuple(rows)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def phi_path_indices_for_block_v21(self, block_addr, rows=None):
        focus = self._canonical_block_addr_v21(block_addr)
        if focus is None:
            return ()
        rows = list(rows if rows is not None else self.phi_path_focus_rows_v21())
        return tuple(
            index for index, row in enumerate(rows)
            if self._canonical_block_addr_v21(row.get("incoming_addr")) == focus
        )

    def _asm_address_index_v22(self):
        """Index normalized ASM blocks by owned, referenced and mentioned address."""
        cache_key = ("asm:address_index:v31",)
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        blocks = tuple(self.asm_blocks_v17() or ())
        index = {}
        owner_by_address = {}
        for position, block in enumerate(blocks):
            addresses = set()
            for value in list(block.get("instruction_addrs", ()) or ()):
                owned = self._canonical_block_addr_v21(value)
                if owned and owned not in owner_by_address:
                    owner_by_address[owned] = position
            for key in ("addr", "entry_addr", "terminator_addr"):
                own = self._canonical_block_addr_v21(block.get(key))
                if own:
                    addresses.add(own)
            for value in list(block.get("references", ()) or ()):
                address = self._canonical_block_addr_v21(value)
                if address:
                    addresses.add(address)
            haystack = str(block.get("search_text") or "").casefold()
            for value in re.findall(r"0x[0-9a-f]+|\b[0-9a-f]{6,16}\b", haystack):
                address = self._canonical_block_addr_v21(value)
                if address:
                    addresses.add(address)
            for address in addresses:
                index.setdefault(address, []).append(position)

        by_entry = {
            self._canonical_block_addr_v21(block.get("addr")): position
            for position, block in enumerate(blocks)
            if self._canonical_block_addr_v21(block.get("addr"))
        }
        predecessors = {address: [] for address in by_entry}
        successors = {address: [] for address in by_entry}
        for position, block in enumerate(blocks):
            source = self._canonical_block_addr_v21(block.get("addr"))
            if not source:
                continue
            explicit = [
                self._canonical_block_addr_v21(value)
                for value in list(block.get("successors", ()) or ())
            ]
            targets = [value for value in explicit if value in by_entry]
            if not targets:
                targets = [
                    self._canonical_block_addr_v21(value)
                    for value in list(block.get("references", ()) or ())
                    if self._canonical_block_addr_v21(value) in by_entry
                ]
            for target in dict.fromkeys(value for value in targets if value):
                successors.setdefault(source, []).append(target)
                predecessors.setdefault(target, []).append(source)

        cached = {
            "blocks": blocks,
            "index": {
                address: tuple(positions) for address, positions in index.items()
            },
            "by_entry": by_entry,
            "owner_by_address": owner_by_address,
            "predecessors": {
                address: tuple(dict.fromkeys(values))
                for address, values in predecessors.items()
            },
            "successors": {
                address: tuple(dict.fromkeys(values))
                for address, values in successors.items()
            },
        }
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def asm_blocks_containing_address_v21(self, block_addr):
        """Return indexed ASM blocks owning or mentioning block_addr."""
        focus = self._canonical_block_addr_v21(block_addr)
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        if focus is None:
            return blocks
        positions = tuple(
            dict(catalog.get("index", {}) or {}).get(focus, ()) or ()
        )
        return tuple(
            blocks[index] for index in positions
            if 0 <= int(index) < len(blocks)
        )

    @classmethod
    def asm_instruction_semantics_v33(cls, text):
        """Classify one rendered ASM instruction and resolve direct jump target."""
        text = str(text or "")
        match = re.match(
            r"^\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})\s+"
            r"([A-Za-z][A-Za-z0-9_.]*)\b(.*)$",
            text,
        )
        if not match:
            return {
                "instruction_addr": None, "mnemonic": None,
                "asm_role": None, "jump_target": None,
            }
        instruction_addr = cls._canonical_block_addr_v21(match.group(1))
        mnemonic = str(match.group(2) or "").upper()
        operands = str(match.group(3) or "")
        jump = mnemonic.startswith("J") or mnemonic.startswith("LOOP")
        compare = mnemonic.startswith((
            "CMP", "TEST", "CMPS", "COMIS", "UCOMIS", "VCMP", "PCMP",
        ))
        jump_target = None
        if jump:
            target_match = re.search(r"0x[0-9A-Fa-f]+|\b[0-9A-Fa-f]{6,16}\b", operands)
            if target_match and "[" not in operands[:target_match.start()]:
                jump_target = cls._canonical_block_addr_v21(target_match.group(0))
        unconditional = mnemonic in ("JMP", "JMPQ", "LJMP")
        conditional = bool(jump and not unconditional)
        returning = bool(
            mnemonic.startswith("RET")
            or mnemonic.startswith("IRET")
            or mnemonic in ("SYSRET", "SYSEXIT")
        )
        return {
            "instruction_addr": instruction_addr,
            "mnemonic": mnemonic,
            "asm_role": "jump" if jump else "compare" if compare else None,
            "jump_target": jump_target,
            "conditional_jump": conditional,
            "unconditional_jump": bool(jump and unconditional),
            "return_instruction": returning,
        }

    def asm_instruction_row_v33(self, block_addr, text, **extra):
        row = {
            "kind": "asm", "addr": self._canonical_block_addr_v21(block_addr),
            "text": str(text),
        }
        row.update(self.asm_instruction_semantics_v33(text))
        row.update(extra)
        return row

    def asm_single_block_rows_v33(self, address, relation=None):
        """Render the exact block owning address, used by direct jump focus."""
        focus = self._canonical_block_addr_v21(address)
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        position = dict(catalog.get("by_entry", {}) or {}).get(focus)
        if position is None:
            position = dict(catalog.get("owner_by_address", {}) or {}).get(focus)
        if position is None or not (0 <= int(position) < len(blocks)):
            return ({
                "kind": "empty",
                "text": "No exact frozen ASM block owns %s." % (focus or "-"),
            },)
        block = blocks[int(position)]
        entry = self._canonical_block_addr_v21(block.get("addr")) or str(block.get("addr") or "-")
        rows = []
        if relation:
            rows.append({"kind": "asm_relation", "relation_role": "current", "text": str(relation), "addr": entry})
        rows.extend((
            {"kind": "block", "addr": entry, "text": "BLOCK %s" % entry,
             "search_text": str(block.get("search_text") or "")},
            {"kind": "rule", "text": "-" * 52},
        ))
        rows.extend(self.asm_instruction_row_v33(entry, value) for value in list(block.get("lines", ()) or ()))
        return tuple(rows)
    def _asm_next_address_block_v38(self, address):
        """Return the next machine-address block without asserting a CFG edge."""
        focus = self._canonical_block_addr_v21(address)
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        candidates = []
        try:
            focus_value = int(str(focus), 0)
        except Exception:
            focus_value = None
        for block in blocks:
            entry = self._canonical_block_addr_v21(block.get("addr"))
            if not entry or entry == focus:
                continue
            try:
                value = int(str(entry), 0)
            except Exception:
                continue
            if focus_value is not None and value > focus_value:
                candidates.append((value, dict(block or {})))
        return min(candidates, key=lambda item: item[0])[1] if candidates else None

    def _asm_block_is_auto_fallthrough_candidate_v38(self, block):
        """True only when a block owns neither jump nor return termination."""
        semantics = [
            self.asm_instruction_semantics_v33(value)
            for value in list(dict(block or {}).get("lines", ()) or ())
            if str(value).strip()
        ]
        if not semantics:
            return False
        if any(item.get("asm_role") == "jump" for item in semantics):
            return False
        if any(item.get("return_instruction") for item in semantics):
            return False
        return True

    def _append_auto_sequential_fallthrough_v38(self, rows, address):
        """Append UI-only next-address context for a non-terminal OPS block."""
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        by_entry = dict(catalog.get("by_entry", {}) or {})
        focus = self._canonical_block_addr_v21(address)
        position = by_entry.get(focus)
        if position is None or not (0 <= int(position) < len(blocks)):
            return rows
        current = dict(blocks[int(position)] or {})
        if not self._asm_block_is_auto_fallthrough_candidate_v38(current):
            return rows
        following = self._asm_next_address_block_v38(focus)
        if following is None:
            return rows
        next_entry = self._canonical_block_addr_v21(following.get("addr"))
        if not next_entry:
            return rows
        # Avoid a duplicate if another narrow context already rendered it.
        if any(
            dict(row or {}).get("kind") == "block"
            and self._canonical_block_addr_v21(dict(row or {}).get("addr")) == next_entry
            for row in rows
        ):
            return rows
        if rows:
            rows.append({"kind": "blank", "text": ""})
        rows.append({
            "kind": "asm_relation", "relation_role": "next",
            "addr": next_entry, "auto_sequential": True,
            "text": "AUTO-SEQUENTIAL FALLTHROUGH -> BLOCK %s" % next_entry,
        })
        rows.extend((
            {"kind": "block", "addr": next_entry, "text": "BLOCK %s" % next_entry,
             "auto_sequential": True},
            {"kind": "rule", "relation_role": "next", "text": "-" * 52,
             "auto_sequential": True},
        ))
        rows.extend(
            self.asm_instruction_row_v33(
                next_entry, value, relation_role="next", auto_sequential=True
            )
            for value in list(following.get("lines", ()) or ())
        )
        return rows

    @staticmethod
    def _asm_address_sort_v34(value):
        text = str(value or "")
        try:
            return (0, int(text, 0))
        except Exception:
            match = re.search(r"0x[0-9A-Fa-f]+", text)
            if match:
                try:
                    return (0, int(match.group(0), 16))
                except Exception:
                    pass
            return (1, text.casefold())

    def asm_branch_forks_rows_v35(self, source_block, jump_target):
        """Render both conditional-branch forks through their nearest completion.

        mars v0.24 freezes explicit display roles into every row:
        ``focus`` is the selected jump target, ``join`` is the nearest common
        completion, and ``fork`` covers source/path context.  All branch rows
        remain ASM records so every surface can paint the same evidence.
        """
        source = self._canonical_block_addr_v21(source_block)
        target = self._canonical_block_addr_v21(jump_target)
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        by_entry = dict(catalog.get("by_entry", {}) or {})
        successors = {
            self._canonical_block_addr_v21(key): tuple(
                self._canonical_block_addr_v21(value)
                for value in list(values or ())
                if self._canonical_block_addr_v21(value)
            )
            for key, values in dict(catalog.get("successors", {}) or {}).items()
        }

        def block_for(addr):
            pos = by_entry.get(self._canonical_block_addr_v21(addr))
            if pos is None or not (0 <= int(pos) < len(blocks)):
                return None
            return dict(blocks[int(pos)] or {})

        forks = list(dict.fromkeys(
            value for value in successors.get(source, ()) if value
        ))
        fallthrough_inferred = False
        if target and target not in forks:
            forks.insert(0, target)
        if len(forks) < 2 and source in by_entry:
            position = int(by_entry[source])
            if position + 1 < len(blocks):
                inferred = self._canonical_block_addr_v21(
                    blocks[position + 1].get("addr")
                )
                if inferred and inferred not in forks:
                    forks.append(inferred)
                    fallthrough_inferred = True
        if target in forks:
            forks = [target] + [value for value in forks if value != target]
        forks = forks[:2]
        if len(forks) < 2:
            fallback = list(self.asm_debug_focus_rows_v34(
                target or source, relation="CONDITIONAL BRANCH TARGET"
            ) or ())
            for row in fallback:
                row.setdefault("branch_display_role", "focus")
                row.setdefault("branch_focus_addr", target or source)
                row.setdefault("branch_join_addr", None)
            return tuple(fallback)

        def reach(start, limit=64):
            queue = [(start, 0)]
            seen = {}
            while queue and len(seen) < limit:
                node, depth = queue.pop(0)
                if node in seen:
                    continue
                seen[node] = depth
                for child in successors.get(node, ()):
                    if child not in seen:
                        queue.append((child, depth + 1))
            return seen

        reach_a, reach_b = reach(forks[0]), reach(forks[1])
        common = set(reach_a) & set(reach_b)
        join = None
        if common:
            join = min(common, key=lambda node: (
                max(reach_a[node], reach_b[node]),
                reach_a[node] + reach_b[node],
                self._asm_address_sort_v34(node),
            ))

        def path_to(start, destination=None, limit=12):
            if destination is not None:
                queue = [(start, [start])]
                seen = set()
                while queue:
                    node, path = queue.pop(0)
                    if node in seen or len(path) > limit:
                        continue
                    seen.add(node)
                    if node == destination:
                        return path
                    for child in successors.get(node, ()):
                        queue.append((child, path + [child]))
            path = [start]
            seen = {start}
            node = start
            while len(path) < limit:
                children = [
                    child for child in successors.get(node, ())
                    if child not in seen
                ]
                if len(children) != 1:
                    break
                node = children[0]
                path.append(node)
                seen.add(node)
            return path

        paths = [path_to(fork, join) for fork in forks]
        if join is not None:
            paths = [
                path[:-1] if path and path[-1] == join else path
                for path in paths
            ]

        rows = []

        def add_block(addr, label, relation_role, display_role):
            block = block_for(addr)
            if block is None:
                return
            entry = (
                self._canonical_block_addr_v21(block.get("addr"))
                or str(block.get("addr") or "-")
            )
            common_row = {
                "relation_role": relation_role,
                "branch_display_role": display_role,
                "branch_focus_addr": target,
                "branch_join_addr": join,
            }
            if rows:
                rows.append({"kind": "blank", "text": "", **common_row})
            rows.append({
                "kind": "asm_relation", "text": label, "addr": entry,
                **common_row,
            })
            rows.append({
                "kind": "block", "addr": entry,
                "text": "BLOCK %s" % entry, **common_row,
            })
            rows.append({
                "kind": "rule", "text": "-" * 52, **common_row,
            })
            for value in list(block.get("lines", ()) or ()):
                instruction = self.asm_instruction_row_v33(
                    entry, value, relation_role=relation_role
                )
                instruction.update(common_row)
                rows.append(instruction)

        add_block(source, "BRANCH SOURCE", "previous", "fork")
        labels = (
            ("TAKEN", "previous"),
            (
                "FALLTHROUGH (INFERRED ADDRESS ORDER)"
                if fallthrough_inferred else "FALLTHROUGH",
                "next",
            ),
        )
        for fork_index, path in enumerate(paths):
            label, relation_role = labels[fork_index]
            for ordinal, addr in enumerate(path, 1):
                display_role = (
                    "focus"
                    if fork_index == 0 and self._canonical_block_addr_v21(addr) == target
                    else "fork"
                )
                add_block(
                    addr,
                    "FORK [%s] %d/%d" % (label, ordinal, len(path)),
                    relation_role,
                    display_role,
                )
        if join is not None:
            add_block(join, "FORK COMPLETION / JOIN", "current", "join")
        return tuple(rows)

    def asm_branch_topology_for_block_v26(self, block_addr):
        """Return the smallest conditional branch topology containing block_addr.

        CODE focus uses this lookup to become a true root refresher.  Rather
        than showing only the selected block, STATIC DEBUG recovers the full
        source/taken/fallthrough/join evidence surface that owns that code line.
        The complete per-function topology index is built once and then reused.
        """
        focus = self._canonical_block_addr_v21(block_addr)
        if focus is None:
            return None
        cache_key = ("asm:branch_topology_index:v26",)
        index = self._truth_source_lines_cache.get(cache_key)
        if index is None:
            candidates_by_block = {}
            for block in tuple(self.asm_blocks_v17() or ()):
                source = self._canonical_block_addr_v21(block.get("addr"))
                if source is None:
                    continue
                for text in list(block.get("lines", ()) or ()):
                    semantic = self.asm_instruction_semantics_v33(text)
                    target = self._canonical_block_addr_v21(
                        semantic.get("jump_target")
                    )
                    if not semantic.get("conditional_jump") or target is None:
                        continue
                    rows = tuple(
                        self.asm_branch_forks_rows_v35(source, target) or ()
                    )
                    role_map = {}
                    priority = {"fork": 1, "join": 2, "focus": 3}
                    for raw in rows:
                        row = dict(raw or {})
                        role = str(row.get("branch_display_role") or "")
                        if role not in priority:
                            continue
                        address = self._canonical_block_addr_v21(
                            row.get("addr") or row.get("address")
                        )
                        if address is None:
                            continue
                        prior = role_map.get(address)
                        if (
                            prior is None
                            or priority[role] >= priority.get(prior, 0)
                        ):
                            role_map[address] = role
                    if not role_map:
                        continue
                    distinct_count = len(role_map)
                    for owned_block, role in role_map.items():
                        ownership_rank = (
                            0 if owned_block == source else
                            1 if owned_block == target else
                            2 if role == "join" else 3
                        )
                        payload = {
                            "source": source, "target": target,
                            "focus": owned_block, "focus_role": role,
                            "rows": rows, "role_map": dict(role_map),
                        }
                        candidates_by_block.setdefault(
                            owned_block, []
                        ).append((
                            ownership_rank, distinct_count,
                            self._asm_address_sort_v34(source), payload,
                        ))
            index = {
                owned_block: min(values, key=lambda item: item[:3])[3]
                for owned_block, values in candidates_by_block.items()
                if values
            }
            self._truth_source_lines_cache[cache_key] = index
        result = dict(index or {}).get(focus)
        return dict(result) if result else None

    def asm_debug_focus_rows_v34(self, address, relation="ASM DEBUG FOCUS"):
        """Show exact focus, expanding one-op non-jump blocks by CFG adjacency.

        A single-op block with no branch is semantically opaque in isolation.
        In that narrow case the viewer shows every direct predecessor above and
        every direct successor below, while keeping the selected block central.
        """
        focus = self._canonical_block_addr_v21(address)
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        position = dict(catalog.get("by_entry", {}) or {}).get(focus)
        if position is None:
            position = dict(catalog.get("owner_by_address", {}) or {}).get(focus)
        if position is None or not (0 <= int(position) < len(blocks)):
            return self.asm_single_block_rows_v33(address, relation=relation)
        current = dict(blocks[int(position)] or {})
        entry = self._canonical_block_addr_v21(current.get("addr")) or focus
        current_lines = [str(value) for value in list(current.get("lines", ()) or ()) if str(value).strip()]
        has_jump = any(
            self.asm_instruction_semantics_v33(value).get("asm_role") == "jump"
            for value in current_lines
        )
        has_return = any(
            self.asm_instruction_semantics_v33(value).get("return_instruction")
            for value in current_lines
        )
        if has_jump or has_return:
            return self.asm_single_block_rows_v33(entry, relation=relation)
        if len(current_lines) != 1:
            rows = list(self.asm_single_block_rows_v33(entry, relation=relation))
            return tuple(self._append_auto_sequential_fallthrough_v38(rows, entry))

        by_entry = dict(catalog.get("by_entry", {}) or {})
        predecessor_addrs = sorted(
            set(catalog.get("predecessors", {}).get(entry, ()) or ()),
            key=self._asm_address_sort_v34,
        )
        successor_addrs = sorted(
            set(catalog.get("successors", {}).get(entry, ()) or ()),
            key=self._asm_address_sort_v34,
        )

        rows = []
        def add_section(addr, label, role):
            pos = by_entry.get(self._canonical_block_addr_v21(addr))
            if pos is None or not (0 <= int(pos) < len(blocks)):
                return
            block = dict(blocks[int(pos)] or {})
            block_entry = self._canonical_block_addr_v21(block.get("addr")) or str(block.get("addr") or "-")
            if rows:
                rows.append({"kind": "blank", "text": ""})
            rows.append({
                "kind": "asm_relation", "relation_role": role,
                "text": label, "addr": block_entry,
            })
            rows.extend((
                {"kind": "block", "addr": block_entry, "text": "BLOCK %s" % block_entry},
                {"kind": "rule", "relation_role": role, "text": "-" * 52},
            ))
            rows.extend(
                self.asm_instruction_row_v33(block_entry, value, relation_role=role)
                for value in list(block.get("lines", ()) or ())
            )

        for ordinal, addr in enumerate(predecessor_addrs, 1):
            add_section(
                addr, "EXECUTION PATH [-1] PREDECESSOR %d/%d"
                % (ordinal, len(predecessor_addrs)), "previous"
            )
        add_section(entry, "EXECUTION PATH [0] CURRENT", "current")
        # For a one-op non-jump block, predecessor context remains useful,
        # but the bottom continuation is the next-address UI fallthrough rather
        # than a claim that frozen CFG metadata owns that edge.
        rows = self._append_auto_sequential_fallthrough_v38(rows, entry)
        return tuple(rows)

    def asm_path_focus_rows_v21(self, block_addr):
        rows = []
        for position, block in enumerate(self.asm_blocks_containing_address_v21(block_addr)):
            if position:
                rows.append({"kind": "blank", "text": ""})
            addr = self._canonical_block_addr_v21(block.get("addr")) or str(block.get("addr") or "-")
            term = self._canonical_block_addr_v21(block.get("terminator_addr")) or "-"
            rows.append({
                "kind": "block", "addr": addr, "terminator_addr": term,
                "text": "BLOCK %s" % addr,
                "search_text": str(block.get("search_text") or ""),
            })
            rows.append({"kind": "rule", "text": "-" * 44})
            rows.extend(
                self.asm_instruction_row_v33(addr, value)
                for value in list(block.get("lines", ()) or ())
            )
        if not rows:
            rows.append({
                "kind": "empty",
                "text": "No frozen ASM block owns or references %s."
                % (self._canonical_block_addr_v21(block_addr) or "the focus"),
            })
        else:
            rows = self._append_auto_sequential_fallthrough_v38(
                rows, self._canonical_block_addr_v21(block_addr)
            )
        return tuple(rows)

    def asm_exact_phi_block_rows_v30(
        self, block_addr, predecessor=None, successor=None
    ):
        """Render predecessor, selected and successor ASM blocks around PHI focus.

        Explicit PHI-chain predecessor/successor addresses are preferred.  If a
        clicked address is itself the chain endpoint, CFG adjacency supplies the
        missing outer context.  Every header uses the normalized machine entry
        and terminator addresses, never a symbolic block label such as ``C``.
        """
        focus = self._canonical_block_addr_v21(block_addr)
        predecessor = self._canonical_block_addr_v21(predecessor)
        successor = self._canonical_block_addr_v21(successor)
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        by_entry = dict(catalog.get("by_entry", {}) or {})
        graph_pred = list(dict(catalog.get("predecessors", {}) or {}).get(focus, ()) or ())
        graph_succ = list(dict(catalog.get("successors", {}) or {}).get(focus, ()) or ())

        def block_for(address):
            address = self._canonical_block_addr_v21(address)
            position = by_entry.get(address)
            if position is None:
                return None
            return blocks[position] if 0 <= int(position) < len(blocks) else None

        pred_addresses = []
        if predecessor and predecessor != focus:
            pred_addresses.append(predecessor)
        pred_addresses.extend(value for value in graph_pred if value != focus)
        succ_addresses = []
        if successor and successor != focus:
            succ_addresses.append(successor)
        succ_addresses.extend(value for value in graph_succ if value != focus)
        pred_addresses = list(dict.fromkeys(value for value in pred_addresses if block_for(value)))
        succ_addresses = list(dict.fromkeys(value for value in succ_addresses if block_for(value)))

        def append_block(rows, block, relation):
            addr = self._canonical_block_addr_v21(block.get("addr")) or str(block.get("addr") or "-")
            term = self._canonical_block_addr_v21(block.get("terminator_addr")) or "-"
            rows.append({
                "kind": "asm_relation", "addr": addr,
                "text": relation,
            })
            rows.append({
                "kind": "block", "addr": addr, "terminator_addr": term,
                "text": "BLOCK %s" % addr,
                "search_text": str(block.get("search_text") or ""),
            })
            rows.append({"kind": "rule", "text": "-" * 44})
            rows.extend(
                self.asm_instruction_row_v33(addr, value)
                for value in list(block.get("lines", ()) or ())
            )

        rows = []
        for address in pred_addresses:
            append_block(rows, block_for(address), "PHI CHAIN PREDECESSOR ASM")
            rows.append({"kind": "blank", "text": ""})

        current = block_for(focus)
        if current is not None:
            append_block(rows, current, "SELECTED PHI ASM BLOCK")
        else:
            rows.append({
                "kind": "empty",
                "text": "No exact frozen ASM block for %s." % (focus or "-"),
            })

        for address in succ_addresses:
            rows.append({"kind": "blank", "text": ""})
            append_block(rows, block_for(address), "PHI CHAIN SUCCESSOR ASM")
        return tuple(rows)

    def asm_phi_stack_zoom_rows_v32(self, previous, current, following):
        """Render at most three exact ASM blocks in PHI blade order.

        This is intentionally not a CFG expansion.  The PHI custody blade is
        treated as an execution-address stack and the selected hotspot is the
        stack pointer.  Only stack_ptr-1, stack_ptr and stack_ptr+1 are shown.
        """
        catalog = self._asm_address_index_v22()
        blocks = tuple(catalog.get("blocks", ()) or ())
        by_entry = dict(catalog.get("by_entry", {}) or {})
        owner_by_address = dict(catalog.get("owner_by_address", {}) or {})

        def block_for(address):
            address = self._canonical_block_addr_v21(address)
            position = by_entry.get(address)
            if position is None:
                position = owner_by_address.get(address)
            if position is not None and 0 <= int(position) < len(blocks):
                return blocks[int(position)]
            # Legacy PHI records may freeze only a referenced target.  This is
            # the last-resort compatibility path after exact entry/owner lookup.
            containing = tuple(self.asm_blocks_containing_address_v21(address) or ())
            return containing[0] if containing else None

        slots = (
            (-1, "PHI TRANSITION [-1] PREVIOUS", previous, "previous"),
            (0, "PHI TRANSITION [0] CURRENT", current, "current"),
            (1, "PHI TRANSITION [+1] NEXT", following, "next"),
        )
        resolved = []
        for slot, label, address, role in slots:
            block = block_for(address)
            entry = (
                self._canonical_block_addr_v21(block.get("addr"))
                if block is not None else None
            )
            resolved.append((slot, label, address, role, block, entry))
        current_entry = next((
            entry for slot, label, address, role, block, entry in resolved
            if slot == 0 and entry
        ), None)

        rows = []
        emitted_entries = set()
        for slot, label, address, role, block, entry in resolved:
            if block is None or entry is None:
                continue
            # The selected stack frame is authoritative.  Adjacent instruction
            # pointers that resolve into the same machine block are suppressed
            # so they cannot displace or duplicate stack_ptr itself.
            if slot != 0 and entry == current_entry:
                continue
            if entry in emitted_entries:
                continue
            emitted_entries.add(entry)
            if rows:
                rows.append({"kind": "blank", "text": ""})
            term = self._canonical_block_addr_v21(block.get("terminator_addr")) or "-"
            rows.append({
                "kind": "asm_relation", "relation_role": role,
                "stack_slot": slot, "addr": entry, "text": label,
            })
            rows.append({
                "kind": "block", "relation_role": role, "stack_slot": slot,
                "addr": entry, "terminator_addr": term,
                "text": "BLOCK %s" % (entry or "-"),
                "search_text": str(block.get("search_text") or ""),
            })
            rows.append({
                "kind": "rule", "relation_role": role, "stack_slot": slot,
                "text": "-" * 52,
            })
            rows.extend(
                self.asm_instruction_row_v33(
                    entry, value, relation_role=role, stack_slot=slot,
                )
                for value in list(block.get("lines", ()) or ())
            )
        if not rows:
            rows.append({
                "kind": "empty",
                "text": "No exact frozen ASM block for the selected PHI stack pointer.",
            })
        return tuple(rows)

    @staticmethod
    def _statement_value_v22(statement, name, default=None):
        if isinstance(statement, dict):
            return statement.get(name, default)
        return getattr(statement, name, default)

    @classmethod
    def _statement_line_span_v22(cls, statement, ordinal):
        start = None
        for key in (
            "line", "line_number", "line_index", "source_line",
            "start_line", "line_start", "rendered_line", "projection_line",
        ):
            value = cls._statement_value_v22(statement, key)
            if isinstance(value, int):
                start = max(0, int(value))
                break
        span = cls._statement_value_v22(statement, "source_span")
        if start is None and isinstance(span, dict):
            for key in ("line", "start_line", "line_start"):
                value = span.get(key)
                if isinstance(value, int):
                    start = max(0, int(value))
                    break
        if start is None:
            start = max(0, int(ordinal))

        end = start
        for key in (
            "end_line", "line_end", "stop_line", "rendered_end_line",
            "projection_end_line",
        ):
            value = cls._statement_value_v22(statement, key)
            if isinstance(value, int):
                end = max(start, int(value))
                break
        if isinstance(span, dict):
            for key in ("end_line", "line_end"):
                value = span.get(key)
                if isinstance(value, int):
                    end = max(end, int(value))
                    break
        return start, end

    def projection_block_map_v21(
        self, projection=None, allow_cursor_fallback=True
    ):
        """Return canonical CFG ownership without a projection-wide deep scan.

        v21 called ``describe_cursor`` once for every rendered line before the
        first linked-view frame.  On a real Icecube that can become effectively
        unbounded.  v22 consumes the block ownership already frozen on
        projection statements/hotspots, then performs at most one cached cursor
        lookup for the currently committed line as a legacy fallback.
        """
        projection = str(projection or self.projection)
        cache_key = (
            "projection:block_map:v23", projection,
            bool(allow_cursor_fallback),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            lines = tuple(self.oncs.base_lines(projection) or ())
        except Exception:
            lines = ()
        mapping = [None] * len(lines)

        try:
            view = self.document.projection(projection)
        except Exception:
            projections = getattr(self.document, "projections", {})
            view = projections.get(projection) if isinstance(projections, dict) else None
        statements = list(getattr(view, "statements", ()) or ()) if view is not None else []

        for ordinal, statement in enumerate(statements):
            raw = (
                self._statement_value_v22(statement, "cfg_block_addr")
                or self._statement_value_v22(statement, "block_addr")
            )
            block = self._canonical_block_addr_v21(raw)
            if block is None:
                continue
            start, end = self._statement_line_span_v22(statement, ordinal)
            if not mapping:
                continue
            start = min(max(0, start), len(mapping) - 1)
            end = min(max(start, end), len(mapping) - 1)
            for line in range(start, end + 1):
                mapping[line] = block

        # Hotspots provide another frozen, non-deep ownership path for legacy
        # projections whose statement objects omit direct block attributes.
        if mapping and allow_cursor_fallback:
            try:
                for item in list(self.hotspots(projection) or ()):
                    line = int(item.get("line", -1))
                    if not (0 <= line < len(mapping)) or mapping[line] is not None:
                        continue
                    block = self._canonical_block_addr_v21(
                        item.get("cfg_block_addr")
                    )
                    if block is not None:
                        mapping[line] = block
            except Exception:
                pass

        # One bounded fallback preserves the current cursor's block on very old
        # Icecubes.  Never sweep every line from inside a modal UI.
        if (
            allow_cursor_fallback
            and mapping
            and projection == self.projection
        ):
            current = min(max(0, int(self.line)), len(mapping) - 1)
            if mapping[current] is None:
                try:
                    mapping[current] = self._canonical_block_addr_v21(
                        self.cursor_block_addr_v12(
                            projection=projection,
                            line=current,
                            column=int(self.column),
                        )
                    )
                except Exception:
                    pass

        cached = tuple(mapping)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def code_line_indices_for_block_v21(
        self, block_addr, projection=None, allow_cursor_fallback=True
    ):
        focus = self._canonical_block_addr_v21(block_addr)
        if focus is None:
            return ()
        return tuple(
            index for index, value in enumerate(
                self.projection_block_map_v21(
                    projection,
                    allow_cursor_fallback=allow_cursor_fallback,
                )
            ) if value == focus
        )

    @staticmethod
    def _statement_mapping_v33(statement):
        if isinstance(statement, dict):
            return dict(statement)
        data = getattr(statement, "__dict__", None)
        mapping = dict(data) if isinstance(data, dict) else {}
        for key in (
            "statement_id", "id", "cfg_block_addr", "block_addr",
            "definition_sids", "use_sids", "metadata_refs",
            "destination_sids", "source_sids", "input_sids",
            "dropin_destination_sids", "dropin_source_sids",
            "drop_in_destination_sids", "drop_in_source_sids",
            "assignment_destination_sids", "assignment_source_sids",
            "state_write_destination_sids", "state_write_source_sids",
            "dropin_destination_sid", "dropin_source_sid",
            "drop_in_destination_sid", "drop_in_source_sid",
            "assignment_destination_sid", "assignment_source_sid",
            "state_write_destination_sid", "state_write_source_sid",
            "destination_sid", "source_sid", "output_sid", "input_sid",
            "kind", "record_kind", "semantic_role", "event_kind",
            "receipt_kind", "transaction_kind",
            "source_span", "line", "line_number", "line_index",
            "start_line", "end_line",
        ):
            value = getattr(statement, key, None)
            if value is not None and key not in mapping:
                mapping[key] = value
        return mapping

    def _collect_statement_sid_fields_v33(self, value, destination, source, depth=0, seen=None):
        if value is None or depth > 6:
            return
        if seen is None:
            seen = set()
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        mapping = _mapping_value(value)
        if mapping is None:
            data = getattr(value, "__dict__", None)
            mapping = data if isinstance(data, dict) else None
        if mapping is None:
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    self._collect_statement_sid_fields_v33(item, destination, source, depth + 1, seen)
            return
        destination_keys = (
            "definition_sids", "destination_sids", "target_sids", "output_sids",
            "dropin_destination_sids", "drop_in_destination_sids",
            "assignment_destination_sids", "definition_sid", "destination_sid",
            "dest_sid", "target_sid", "output_sid", "result_sid",
            "dropin_destination_sid", "drop_in_destination_sid",
            "assignment_destination_sid",
        )
        source_keys = (
            "use_sids", "source_sids", "input_sids", "incoming_sids",
            "dropin_source_sids", "drop_in_source_sids", "value_sids",
            "use_sid", "source_sid", "input_sid", "incoming_sid", "value_sid",
            "dropin_source_sid", "drop_in_source_sid",
        )
        for key in destination_keys:
            for sid in _metadata_sid_list_v13(mapping.get(key)):
                canonical = self.canonical_phi_sid_v33(sid)
                if canonical:
                    destination.add(canonical)
        for key in source_keys:
            for sid in _metadata_sid_list_v13(mapping.get(key)):
                canonical = self.canonical_phi_sid_v33(sid)
                if canonical:
                    source.add(canonical)
        for child in mapping.values():
            if isinstance(child, (dict, list, tuple, set)) or hasattr(child, "__dict__"):
                self._collect_statement_sid_fields_v33(child, destination, source, depth + 1, seen)

    def _collect_dropin_statement_fields_v44(
        self, value, destination, source, evidence, depth=0, seen=None
    ):
        """Collect explicit emitter/drop-in custody without broadening semantics.

        PALDocument/Icecube generations use several field spellings.  This
        collector is additive and schema-tolerant: it records only fields whose
        names explicitly identify drop-ins, assignment rewrites or state writes.
        Generic definition/use evidence remains available separately as the
        compatibility fallback in ``projection_dropins_for_block_v44``.
        """
        if value is None or depth > 7:
            return
        if seen is None:
            seen = set()
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)

        mapping = _mapping_value(value)
        if mapping is None:
            data = getattr(value, "__dict__", None)
            mapping = data if isinstance(data, dict) else None
        if mapping is None:
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    self._collect_dropin_statement_fields_v44(
                        item, destination, source, evidence,
                        depth + 1, seen,
                    )
            return

        destination_groups = {
            "frozen_dropin_fields": (
                "dropin_destination_sids", "drop_in_destination_sids",
                "dropin_destination_sid", "drop_in_destination_sid",
                "phi_dropin_destination_sids", "phi_dropin_destination_sid",
            ),
            "frozen_assignment_fields": (
                "assignment_destination_sids", "assignment_destination_sid",
                "assignment_target_sids", "assignment_target_sid",
                "rewrite_destination_sids", "rewrite_destination_sid",
            ),
            "frozen_state_write_fields": (
                "state_write_destination_sids", "state_write_destination_sid",
                "placement_destination_sids", "placement_destination_sid",
                "commit_destination_sids", "commit_destination_sid",
            ),
        }
        source_groups = {
            "frozen_dropin_fields": (
                "dropin_source_sids", "drop_in_source_sids",
                "dropin_source_sid", "drop_in_source_sid",
                "phi_dropin_source_sids", "phi_dropin_source_sid",
            ),
            "frozen_assignment_fields": (
                "assignment_source_sids", "assignment_source_sid",
                "assignment_value_sids", "assignment_value_sid",
                "rewrite_source_sids", "rewrite_source_sid",
            ),
            "frozen_state_write_fields": (
                "state_write_source_sids", "state_write_source_sid",
                "placement_source_sids", "placement_source_sid",
                "commit_source_sids", "commit_source_sid",
            ),
        }

        for label, keys in destination_groups.items():
            found = False
            for key in keys:
                if key not in mapping:
                    continue
                for sid in _metadata_sid_list_v13(mapping.get(key)):
                    canonical = self.canonical_phi_sid_v33(sid)
                    if canonical:
                        destination.add(canonical)
                        found = True
            if found:
                evidence.add(label)

        for label, keys in source_groups.items():
            found = False
            for key in keys:
                if key not in mapping:
                    continue
                for sid in _metadata_sid_list_v13(mapping.get(key)):
                    canonical = self.canonical_phi_sid_v33(sid)
                    if canonical:
                        source.add(canonical)
                        found = True
            if found:
                evidence.add(label)

        role_text = " ".join(
            str(mapping.get(key) or "").strip().casefold()
            for key in (
                "kind", "record_kind", "semantic_role", "event_kind",
                "receipt_kind", "transaction_kind", "status", "reason",
            )
        )
        compact = re.sub(r"[^a-z0-9]+", "_", role_text).strip("_")
        if "dropin" in compact or "drop_in" in compact:
            evidence.add("frozen_dropin_record")
        if "assignment" in compact or "rewrite" in compact:
            evidence.add("frozen_assignment_record")
        if (
            "state_write" in compact or "placement_commit" in compact
            or "terminal_commit" in compact
        ):
            evidence.add("frozen_state_write_record")

        for child in mapping.values():
            if (
                isinstance(child, (dict, list, tuple, set))
                or hasattr(child, "__dict__")
            ):
                self._collect_dropin_statement_fields_v44(
                    child, destination, source, evidence,
                    depth + 1, seen,
                )

    def _lexical_assignment_sids_v33(self, text):
        destination = set()
        source = set()
        try:
            tree = ast.parse(str(text or "").strip() or "pass")
        except Exception:
            return destination, source
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for child in ast.walk(target):
                        if isinstance(child, ast.Name):
                            destination.add(self.canonical_phi_sid_v33(child.id))
                value = getattr(node, "value", None)
                if value is not None:
                    for child in ast.walk(value):
                        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                            source.add(self.canonical_phi_sid_v33(child.id))
        destination.discard("")
        source.discard("")
        return destination, source

    def projection_statement_contexts_v33(self, projection=None):
        """Return line-owned block, SID and explicit drop-in evidence.

        v44 keeps the v33 return contract and adds explicit emitter-custody
        fields.  Existing consumers continue to use destination/source SIDs;
        the humanized PHI pane can prefer frozen drop-in evidence and fall back
        to lexical Python assignments for older Icecubes.
        """
        projection = str(projection or self.projection)
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = (
            "projection:statement_context:v44", projection, revision,
            str(self.naming), bool(self.operator_overlay),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            rendered = tuple(self.oncs.render_lines(
                projection, self.naming, self.operator_overlay
            ) or ())
        except Exception:
            rendered = tuple(self.oncs.base_lines(projection) or ())
        blocks = tuple(self.projection_block_map_v21(
            projection, allow_cursor_fallback=False
        ) or ())
        contexts = [{
            "block": blocks[index] if index < len(blocks) else None,
            "definition_sids": set(), "destination_sids": set(),
            "use_sids": set(), "source_sids": set(),
            "dropin_destination_sids": set(),
            "dropin_source_sids": set(),
            "dropin_evidence": set(),
            "metadata_refs": set(), "statement_ids": set(),
        } for index in range(len(rendered))]
        try:
            view = self.document.projection(projection)
        except Exception:
            projections = getattr(self.document, "projections", {})
            view = (
                projections.get(projection)
                if isinstance(projections, dict) else None
            )
        statements = (
            list(getattr(view, "statements", ()) or ())
            if view is not None else []
        )
        resolver = getattr(
            getattr(self.document, "metadata", None), "resolve", None
        )
        for ordinal, statement in enumerate(statements):
            start, end = self._statement_line_span_v22(statement, ordinal)
            if not contexts:
                continue
            start = min(max(0, start), len(contexts) - 1)
            end = min(max(start, end), len(contexts) - 1)
            destination = set()
            source = set()
            dropin_destination = set()
            dropin_source = set()
            dropin_evidence = set()
            mapping = self._statement_mapping_v33(statement)
            self._collect_statement_sid_fields_v33(
                mapping, destination, source
            )
            self._collect_dropin_statement_fields_v44(
                mapping, dropin_destination, dropin_source,
                dropin_evidence,
            )
            refs = [
                str(value)
                for value in list(mapping.get("metadata_refs", ()) or ())
            ]
            if callable(resolver):
                for reference in refs:
                    try:
                        record = resolver(reference, None)
                    except TypeError:
                        try:
                            record = resolver(reference)
                        except Exception:
                            record = None
                    except Exception:
                        record = None
                    self._collect_statement_sid_fields_v33(
                        record, destination, source
                    )
                    self._collect_dropin_statement_fields_v44(
                        record, dropin_destination, dropin_source,
                        dropin_evidence,
                    )
            for line_index in range(start, end + 1):
                lexical_dest, lexical_source = (
                    self._lexical_assignment_sids_v33(
                        rendered[line_index]
                    )
                )
                context = contexts[line_index]
                context["definition_sids"].update(
                    self.canonical_phi_sid_v33(value)
                    for value in _metadata_sid_list_v13(
                        mapping.get("definition_sids")
                    )
                    if value
                )
                context["use_sids"].update(
                    self.canonical_phi_sid_v33(value)
                    for value in _metadata_sid_list_v13(
                        mapping.get("use_sids")
                    )
                    if value
                )
                context["destination_sids"].update(destination)
                context["destination_sids"].update(lexical_dest)
                context["source_sids"].update(source)
                context["source_sids"].update(lexical_source)
                context["dropin_destination_sids"].update(
                    dropin_destination
                )
                context["dropin_source_sids"].update(dropin_source)
                context["dropin_evidence"].update(dropin_evidence)
                context["metadata_refs"].update(refs)
                statement_id = (
                    mapping.get("statement_id") or mapping.get("id")
                )
                if statement_id is not None:
                    context["statement_ids"].add(str(statement_id))

        # Lexical assignment evidence remains available even when old
        # projections contain no statement objects.
        for index, context in enumerate(contexts):
            lexical_dest, lexical_source = (
                self._lexical_assignment_sids_v33(rendered[index])
            )
            context["destination_sids"].update(lexical_dest)
            context["source_sids"].update(lexical_source)

        frozen = []
        for context in contexts:
            destination = (
                set(context["definition_sids"])
                | set(context["destination_sids"])
            )
            source = set(context["use_sids"]) | set(context["source_sids"])
            frozen.append({
                "block": context.get("block"),
                "definition_sids": tuple(
                    sorted(context["definition_sids"])
                ),
                "destination_sids": tuple(sorted(destination)),
                "use_sids": tuple(sorted(context["use_sids"])),
                "source_sids": tuple(sorted(source)),
                "all_sids": tuple(sorted(destination | source)),
                "dropin_destination_sids": tuple(sorted(
                    context["dropin_destination_sids"]
                )),
                "dropin_source_sids": tuple(sorted(
                    context["dropin_source_sids"]
                )),
                "dropin_evidence": tuple(sorted(
                    context["dropin_evidence"]
                )),
                "metadata_refs": tuple(sorted(context["metadata_refs"])),
                "statement_ids": tuple(sorted(context["statement_ids"])),
            })
        cached = tuple(frozen)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def projection_dropins_for_block_v44(
        self, block_addr, projection=None
    ):
        """Return assignment/drop-in records owned by one focal CFG block.

        Explicit frozen drop-in/assignment/state-write custody wins.  Older
        Icecubes fall back to a real Python assignment on a line owned by the
        same block.  This does not infer new semantic transitions; it only
        exposes already-published PALDocument evidence in a human workbench.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        if focus is None:
            return ()
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = (
            "projection:block_dropins:v44", projection, focus, revision,
            str(self.naming), bool(self.operator_overlay),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            rendered = tuple(self.oncs.render_lines(
                projection, self.naming, self.operator_overlay
            ) or ())
        except Exception:
            rendered = tuple(self.oncs.base_lines(projection) or ())
        contexts = tuple(
            self.projection_statement_contexts_v33(projection) or ()
        )
        function_names = set()
        for values in (
            getattr(self.oncs, "call_targets", set()),
            getattr(self.oncs, "function_defs", set()),
            getattr(self.oncs, "function_names", set()),
        ):
            function_names.update(str(value) for value in list(values or ()))

        candidates = {}
        for line_index, raw_context in enumerate(contexts):
            context = dict(raw_context or {})
            owned = self._canonical_block_addr_v21(
                context.get("block")
            )
            if owned != focus or line_index >= len(rendered):
                continue
            text_value = str(rendered[line_index])
            lexical_dest, lexical_source = (
                self._lexical_assignment_sids_v33(text_value)
            )
            explicit_dest = {
                self.canonical_phi_sid_v33(value)
                for value in list(
                    context.get("dropin_destination_sids", ()) or ()
                ) if value
            }
            explicit_source = {
                self.canonical_phi_sid_v33(value)
                for value in list(
                    context.get("dropin_source_sids", ()) or ()
                ) if value
            }
            context_dest = {
                self.canonical_phi_sid_v33(value)
                for value in list(
                    context.get("destination_sids", ()) or ()
                ) if value
            }
            context_source = {
                self.canonical_phi_sid_v33(value)
                for value in list(
                    context.get("source_sids", ()) or ()
                ) if value
            }

            destinations = (
                explicit_dest or set(lexical_dest) or context_dest
            )
            # A generic definition with no Python assignment is not displayed
            # as a drop-in unless explicit frozen custody says it is one.
            if not destinations or (
                not explicit_dest and not lexical_dest
            ):
                continue
            sources = (
                explicit_source or set(lexical_source) or context_source
            )
            sources = {
                value for value in sources
                if str(value) not in function_names
            }
            destinations.discard("")
            sources.discard("")
            if not destinations:
                continue

            evidence = tuple(
                str(value) for value in list(
                    context.get("dropin_evidence", ()) or ()
                ) if value
            )
            if any("dropin" in value for value in evidence):
                evidence_label = "frozen drop-in"
            elif evidence:
                evidence_label = "frozen assignment/state write"
            else:
                evidence_label = "projection assignment"

            statement_ids = tuple(
                str(value) for value in list(
                    context.get("statement_ids", ()) or ()
                ) if value
            )
            identity_root = (
                ("statement",) + statement_ids
                if statement_ids else ("line", str(line_index))
            )
            key = (
                identity_root,
                tuple(sorted(destinations)),
            )
            item = {
                "kind": "dropin",
                "dropin_id": "%s:%s:%s" % (
                    projection, focus,
                    ",".join(identity_root + tuple(sorted(destinations))),
                ),
                "projection": projection,
                "block": focus,
                "line": int(line_index),
                "line_number": int(line_index) + 1,
                "text": text_value.strip(),
                "destination_sids": tuple(sorted(destinations)),
                "source_sids": tuple(sorted(sources)),
                "destination_names": tuple(
                    self.active_display_name_v38(value)
                    for value in sorted(destinations)
                ),
                "source_names": tuple(
                    self.active_display_name_v38(value)
                    for value in sorted(sources)
                ),
                "evidence": evidence,
                "evidence_label": evidence_label,
                "metadata_refs": tuple(
                    str(value) for value in list(
                        context.get("metadata_refs", ()) or ()
                    ) if value
                ),
                "statement_ids": statement_ids,
                "lexical_assignment": bool(lexical_dest),
            }
            prior = candidates.get(key)
            if prior is None or (
                item["lexical_assignment"]
                and not prior.get("lexical_assignment")
            ):
                candidates[key] = item

        ordered = sorted(
            candidates.values(),
            key=lambda item: (
                int(item.get("line", 0)),
                tuple(item.get("destination_sids", ()) or ()),
                str(item.get("dropin_id") or ""),
            ),
        )
        for ordinal, item in enumerate(ordered, 1):
            item["ordinal"] = ordinal
        cached = tuple(ordered)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def phi_dropin_focus_rows_v44(
        self, block_addr, projection=None
    ):
        """Humanized PHI pane for one focal ASM address.

        Layout:
            1. assignments/drop-ins executed by the focal block;
            2. the frozen PHI block sequence leading to each drop-in;
            3. the actual drop-in execution row.

        The historical ``Final State`` tail is intentionally omitted because it
        describes a result variable, not the execution event under inspection.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        dropins = list(self.projection_dropins_for_block_v44(
            focus, projection=projection
        ) or ())
        if focus is None or not dropins:
            return ()

        rows = [{
            "kind": "phi_section",
            "text": "DROP-INS EXECUTED @ %s [%d]"
            % (focus, len(dropins)),
            "dropin_mode": True,
            "focus_addr": focus,
        }]
        for item in dropins:
            destinations = tuple(item.get("destination_names", ()) or ())
            sources = tuple(item.get("source_names", ()) or ())
            target_text = ", ".join(destinations) or "-"
            source_text = ", ".join(sources) or "expression"
            code = str(item.get("text") or "").strip()
            rows.append({
                "kind": "dropin_summary",
                "dropin_mode": True,
                "dropin_id": item.get("dropin_id"),
                "dropin_index": int(item.get("ordinal", 0)),
                "output_sid": (
                    item.get("destination_sids", (None,))[0]
                    if item.get("destination_sids") else None
                ),
                "destination_sids": tuple(
                    item.get("destination_sids", ()) or ()
                ),
                "source_sids": tuple(
                    item.get("source_sids", ()) or ()
                ),
                "address": focus,
                "addr": focus,
                "line": int(item.get("line", 0)),
                "line_number": int(item.get("line_number", 0)),
                "evidence_label": item.get("evidence_label"),
                "text": "[%d] PY L%-4d %s <= [%s] :: %s"
                % (
                    int(item.get("ordinal", 0)),
                    int(item.get("line_number", 0)),
                    target_text, source_text, code,
                ),
            })

        for item in dropins:
            ordinal = int(item.get("ordinal", 0))
            dropin_id = str(item.get("dropin_id") or "")
            destinations = tuple(
                item.get("destination_sids", ()) or ()
            )
            code = str(item.get("text") or "").strip()
            rows.extend((
                {"kind": "blank", "text": "", "dropin_mode": True},
                {
                    "kind": "dropin_sequence_header",
                    "dropin_mode": True,
                    "dropin_sequence_id": dropin_id,
                    "dropin_id": dropin_id,
                    "dropin_index": ordinal,
                    "text": "BLOCK SEQUENCE -> DROP-IN [%d]"
                    % ordinal,
                },
            ))
            for destination in destinations:
                index = self.phi_custody_index_for_sid_v16(
                    destination
                )
                if index is None:
                    rows.append({
                        "kind": "phi_sequence_note",
                        "dropin_mode": True,
                        "dropin_sequence_id": dropin_id,
                        "dropin_id": dropin_id,
                        "dropin_index": ordinal,
                        "output_sid": destination,
                        "text": "  %s: direct materialization; "
                        "no PHI custody chain is frozen."
                        % self.phi_display_name_v30(destination),
                    })
                    continue
                for raw in self.phi_custody_blade_v14(index):
                    row = dict(raw or {})
                    if row.get("kind") in (
                        "header_top", "header_bottom", "blank",
                        "trunk", "final",
                    ):
                        continue
                    row["dropin_mode"] = True
                    row["dropin_sequence_id"] = dropin_id
                    row["dropin_id"] = dropin_id
                    row["dropin_index"] = ordinal
                    row["phi_template"] = bool(
                        row.get("phi_template", True)
                    )
                    rows.append(row)
            first_destination = (
                destinations[0] if destinations else None
            )
            prefix = "        | "
            rows.append({
                "kind": "dropin_exec",
                "dropin_mode": True,
                "dropin_sequence_id": dropin_id,
                "dropin_id": dropin_id,
                "dropin_index": ordinal,
                "output_sid": first_destination,
                "event_sid": first_destination,
                "address": focus,
                "address_display": focus,
                "address_offset": len(prefix),
                "block_hotspot": True,
                "phi_template": True,
                "text": "%s%-21s DROP-IN EXECUTES: %s"
                % (prefix, focus, code),
            })
        return tuple(rows)


    def projection_dropin_groups_for_block_v45(
        self, block_addr, projection=None
    ):
        """GROUP BY exact ASM block while retaining distinct assignments.

        The emitter may publish several execution occurrences of one Python
        drop-in because several control-flow paths enter the same machine block.
        The PHI workbench is block-centric: it shows that block once, records
        how many occurrences were collapsed, and retains every distinct
        assignment inside the block exactly once.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        if focus is None:
            return ()
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = (
            "projection:block_dropin_groups:v45", projection, focus,
            revision, str(self.naming), bool(self.operator_overlay),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        groups = {}
        for raw in list(self.projection_dropins_for_block_v44(
            focus, projection=projection
        ) or ()):
            item = dict(raw or {})
            block = self._canonical_block_addr_v21(
                item.get("block") or focus
            ) or focus
            group = groups.setdefault(block, {
                "kind": "dropin_block_group",
                "projection": projection,
                "block": block,
                "dropin_id": "%s:%s:block" % (projection, block),
                "occurrence_count": 0,
                "destination_sids": set(),
                "source_sids": set(),
                "assignments": {},
            })
            group["occurrence_count"] += 1
            destinations = tuple(sorted(
                self.canonical_phi_sid_v33(value)
                for value in list(item.get("destination_sids", ()) or ())
                if value
            ))
            sources = tuple(sorted(
                self.canonical_phi_sid_v33(value)
                for value in list(item.get("source_sids", ()) or ())
                if value
            ))
            group["destination_sids"].update(destinations)
            group["source_sids"].update(sources)
            code_text = str(item.get("text") or "").strip()
            # Same code + custody inside the same ASM block is one drop-in,
            # regardless of how many branch occurrences reached it.
            signature = (code_text, destinations, sources)
            assignment = group["assignments"].get(signature)
            if assignment is None:
                assignment = {
                    "kind": "dropin_assignment",
                    "block": block,
                    "text": code_text,
                    "destination_sids": destinations,
                    "source_sids": sources,
                    "destination_names": tuple(
                        self.active_display_name_v38(value)
                        for value in destinations
                    ),
                    "source_names": tuple(
                        self.active_display_name_v38(value)
                        for value in sources
                    ),
                    "occurrence_count": 0,
                    "line_numbers": set(),
                    "evidence": set(),
                    "metadata_refs": set(),
                    "statement_ids": set(),
                }
                group["assignments"][signature] = assignment
            assignment["occurrence_count"] += 1
            line_number = int(item.get("line_number", 0) or 0)
            if line_number > 0:
                assignment["line_numbers"].add(line_number)
            assignment["evidence"].update(
                str(value) for value in list(item.get("evidence", ()) or ())
                if value
            )
            assignment["metadata_refs"].update(
                str(value) for value in list(
                    item.get("metadata_refs", ()) or ()
                ) if value
            )
            assignment["statement_ids"].update(
                str(value) for value in list(
                    item.get("statement_ids", ()) or ()
                ) if value
            )

        ordered_groups = []
        for block, group in sorted(
            groups.items(), key=lambda pair: self._asm_address_sort_v34(pair[0])
        ):
            assignments = list(group["assignments"].values())
            assignments.sort(key=lambda item: (
                min(item["line_numbers"] or {1 << 30}),
                str(item.get("text") or ""),
                tuple(item.get("destination_sids", ()) or ()),
            ))
            for ordinal, assignment in enumerate(assignments, 1):
                assignment["ordinal"] = ordinal
                assignment["line_numbers"] = tuple(sorted(
                    assignment["line_numbers"]
                ))
                assignment["evidence"] = tuple(sorted(
                    assignment["evidence"]
                ))
                assignment["metadata_refs"] = tuple(sorted(
                    assignment["metadata_refs"]
                ))
                assignment["statement_ids"] = tuple(sorted(
                    assignment["statement_ids"]
                ))
            group["assignments"] = tuple(assignments)
            group["assignment_count"] = len(assignments)
            group["destination_sids"] = tuple(sorted(
                group["destination_sids"]
            ))
            group["source_sids"] = tuple(sorted(group["source_sids"]))
            group["destination_names"] = tuple(
                self.active_display_name_v38(value)
                for value in group["destination_sids"]
            )
            group["source_names"] = tuple(
                self.active_display_name_v38(value)
                for value in group["source_sids"]
            )
            ordered_groups.append(group)

        for ordinal, group in enumerate(ordered_groups, 1):
            group["ordinal"] = ordinal
        cached = tuple(ordered_groups)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def _is_materialized_storage_sid_v48(self, sid):
        """Return true only for human-facing materialized state variables.

        Drop-in metadata may also expose pure SSA carriers such as ``v_4453``.
        Those identities remain valid provenance, but they are not a useful
        variable inventory for the PHI workbench.  A destination is admitted
        when it has concrete storage evidence or when its live presentation
        name is not a raw SSA/static carrier spelling.
        """
        canonical, contract = self.active_name_contract_v38(sid)
        contract = dict(contract or {})
        if any(bool(contract.get(key)) for key in (
            "is_function", "is_callee", "is_call_target",
            "is_function_symbol", "is_constant",
        )):
            return False
        role_text = " ".join(
            str(contract.get(key) or "").casefold()
            for key in (
                "kind", "record_kind", "semantic_role", "object_kind",
                "category", "type", "role",
            )
        )
        if "constant" in role_text or "function" in role_text:
            return False
        storage_evidence = any(
            contract.get(key) not in (None, False, "", (), [], {})
            for key in (
                "storage", "storage_id", "storage_kind", "stack_offset",
                "stack_slot", "frame_offset", "address", "memory_address",
                "is_stack_local", "is_parameter", "is_global",
                "is_materialized", "materialized_storage",
            )
        )
        display = self.active_display_name_v38(canonical or sid)
        pal_name = str(contract.get("pal_name") or "")
        canonical = str(canonical or sid or "")
        names = [display, pal_name, canonical]
        if any(str(value).startswith("c_") for value in names if value):
            return False
        raw_ssa = re.compile(r"^v_[0-9a-f]+$", re.IGNORECASE)
        if storage_evidence:
            return True
        return not all(
            raw_ssa.fullmatch(str(value or "").strip())
            for value in names if value
        )


    def _projection_temp_usability_index_v50(self, projection=None):
        """Classify emitted ``v_*`` destinations by actual downstream usability.

        A one-definition temporary is not automatically SSA traffic.  Temps such
        as token lengths, loaded sentinels, call results and selector values are
        real readable variables when their emitted value is consumed later.

        The one narrow exclusion retained for readability is a repeated
        state-alias carrier: one definition is copied into the same human-facing
        storage destination across several placements/blocks.  That is the
        ``v_4453 -> local_24`` class and should collapse to the storage identity
        rather than occupy a second PHI/materialization row.
        """
        projection = str(projection or self.projection)
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = (
            "projection:temp_usability_index:v50", projection, revision,
            str(self.naming), bool(self.operator_overlay),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            rendered = tuple(self.oncs.render_lines(
                projection, self.naming, self.operator_overlay
            ) or ())
        except Exception:
            rendered = tuple(self.oncs.base_lines(projection) or ())
        contexts = tuple(
            self.projection_statement_contexts_v33(projection) or ()
        )
        raw_ssa = re.compile(r"^v_[0-9a-f]+$", re.IGNORECASE)
        index = {}

        def record_for(value):
            canonical = self.canonical_phi_sid_v33(value)
            canonical = str(canonical or value or "")
            display = self.active_display_name_v38(canonical)
            aliases = {canonical, str(display or "")}
            try:
                unused, contract = self.active_name_contract_v38(canonical)
            except Exception:
                contract = {}
            contract = dict(contract or {})
            for key in (
                "sid", "canonical_ssa_name", "pal_name", "display_name",
                "active_name", "generated_human_alias", "operator_alias",
                "original_name",
            ):
                candidate = contract.get(key)
                if candidate:
                    aliases.add(str(candidate))
            if not any(raw_ssa.fullmatch(alias.strip()) for alias in aliases if alias):
                return None
            return index.setdefault(canonical, {
                "sid": canonical,
                "aliases": set(alias for alias in aliases if alias),
                "definition_lines": set(),
                "definition_blocks": set(),
                "definition_texts": set(),
                "use_lines": set(),
                "use_blocks": set(),
                "use_roles": set(),
                "storage_sink_destinations": set(),
                "storage_sink_blocks": set(),
                "storage_sink_assignments": set(),
            })

        def semantic_role(text):
            stripped = str(text or "").strip()
            lowered = stripped.casefold()
            if lowered.startswith(("if ", "elif ", "while ")) or lowered.startswith("assert "):
                return "condition"
            if lowered.startswith("return"):
                return "return"
            if "<-" in stripped or re.search(r"\bMEM(?:8|16|32|64)?\s*\[", stripped):
                return "memory"
            if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", stripped):
                return "call_or_expression"
            return "expression"

        for line_index, text in enumerate(rendered):
            context = dict(
                contexts[line_index] if line_index < len(contexts) else {}
                or {}
            )
            block = self._canonical_block_addr_v21(context.get("block"))
            destinations = {
                self.canonical_phi_sid_v33(value)
                for value in list(
                    context.get("destination_sids", ()) or ()
                ) if value
            }
            sources = {
                self.canonical_phi_sid_v33(value)
                for value in list(context.get("source_sids", ()) or ())
                if value
            }

            lexical_dest, lexical_source = self._lexical_assignment_sids_v33(
                str(text)
            )
            destinations.update(
                self.canonical_phi_sid_v33(value)
                for value in lexical_dest if value
            )
            sources.update(
                self.canonical_phi_sid_v33(value)
                for value in lexical_source if value
            )

            # Legacy/invalid-Python projection rows (for example MEM32[x] <- y)
            # may not expose lexical source metadata.  Recover raw temp tokens
            # conservatively and exclude an obvious direct assignment target.
            raw_tokens = set(re.findall(
                r"\bv_[0-9A-Fa-f]+\b", str(text), flags=re.IGNORECASE
            ))
            direct_target = None
            target_match = re.match(
                r"^\s*(v_[0-9A-Fa-f]+)\s*=", str(text), flags=re.IGNORECASE
            )
            if target_match:
                direct_target = self.canonical_phi_sid_v33(
                    target_match.group(1)
                )
                destinations.add(direct_target)
            for token_name in raw_tokens:
                canonical_token = self.canonical_phi_sid_v33(token_name)
                if canonical_token != direct_target:
                    sources.add(canonical_token)

            for destination in destinations:
                record = record_for(destination)
                if record is None:
                    continue
                record["definition_lines"].add(int(line_index))
                if block is not None:
                    record["definition_blocks"].add(block)
                record["definition_texts"].add(str(text).strip())

            role = semantic_role(text)
            for source in sources:
                record = record_for(source)
                if record is None:
                    continue
                record["use_lines"].add(int(line_index))
                if block is not None:
                    record["use_blocks"].add(block)
                record["use_roles"].add(role)

                for destination in destinations:
                    if destination == source:
                        continue
                    if not self._is_materialized_storage_sid_v48(destination):
                        continue
                    record["storage_sink_destinations"].add(str(destination))
                    if block is not None:
                        record["storage_sink_blocks"].add(block)
                    record["storage_sink_assignments"].add((
                        block,
                        str(destination),
                        str(text).strip(),
                    ))

        frozen = {}
        for sid, raw_record in index.items():
            record = dict(raw_record)
            for key in (
                "aliases", "definition_lines", "definition_blocks",
                "definition_texts", "use_lines", "use_blocks", "use_roles",
                "storage_sink_destinations", "storage_sink_blocks",
                "storage_sink_assignments",
            ):
                record[key] = tuple(sorted(
                    record.get(key, ()),
                    key=lambda value: str(value),
                ))
            record["definition_count"] = len(record["definition_texts"])
            record["definition_block_count"] = len(record["definition_blocks"])
            record["use_count"] = len(record["use_lines"])
            record["use_block_count"] = len(record["use_blocks"])
            record["storage_sink_count"] = len(
                record["storage_sink_destinations"]
            )
            record["storage_sink_block_count"] = len(
                record["storage_sink_blocks"]
            )
            record["storage_sink_assignment_count"] = len(
                record["storage_sink_assignments"]
            )
            frozen[sid] = record

        self._truth_source_lines_cache[cache_key] = frozen
        return frozen

    def _is_valid_control_temp_v50(self, sid, record=None):
        """Admit semantically used emitted temps; reject repeated alias traffic.

        Valid classes include:

        * several emitted definitions or definition blocks;
        * several frozen PHI incoming values;
        * one emitted definition whose value is consumed by a condition, call,
          return, memory operation or later expression.

        The one-definition carrier is hidden only when it repeatedly
        materializes into the same stable storage destination across multiple
        assignments/blocks.  This preserves real temps such as ``v_424`` and
        ``v_724`` while continuing to suppress ``v_4453``-style storage aliases.
        """
        canonical, contract = self.active_name_contract_v38(sid)
        canonical = str(canonical or sid or "")
        contract = dict(contract or {})
        if any(bool(contract.get(key)) for key in (
            "is_function", "is_callee", "is_call_target",
            "is_function_symbol", "is_constant",
        )):
            return False

        display = self.active_display_name_v38(canonical)
        raw_ssa = re.compile(r"^v_[0-9a-f]+$", re.IGNORECASE)
        names = {
            str(value) for value in (
                display, canonical, contract.get("pal_name"),
                contract.get("canonical_ssa_name"),
            ) if value
        }
        if not any(raw_ssa.fullmatch(value.strip()) for value in names):
            return False

        record = dict(record or {})
        evidence = dict(
            self._projection_temp_usability_index_v50(
                projection=self.projection
            ).get(canonical, {}) or {}
        )

        definition_count = max(
            int(record.get("assignment_count", 0) or 0),
            int(evidence.get("definition_count", 0) or 0),
        )
        definition_blocks = max(
            int(record.get("block_count", 0) or 0),
            int(evidence.get("definition_block_count", 0) or 0),
        )

        try:
            phi_records = list(
                dict(self._phi_graph_v14().get("by_output", {}) or {}).get(
                    canonical, ()
                ) or ()
            )
        except Exception:
            phi_records = []
        incoming = {
            self.canonical_phi_sid_v33(value)
            for phi_record in phi_records
            for value in list(
                dict(phi_record or {}).get("input_sids", ()) or ()
            )
            if value
        }

        # Multi-definition and PHI selector temps remain unconditionally useful.
        if definition_count >= 2 or definition_blocks >= 2 or len(incoming) >= 2:
            return True

        # No downstream consumer means no readable materialization purpose.
        if int(evidence.get("use_count", 0) or 0) < 1:
            return False

        # A repeated one-source -> one-storage relay is readability alias
        # traffic, not a second human variable.  Requiring repeated placements
        # preserves genuine swap/address/result temps that materialize once.
        repeated_single_sink_alias = (
            int(evidence.get("storage_sink_count", 0) or 0) == 1
            and (
                int(evidence.get("storage_sink_assignment_count", 0) or 0) >= 2
                or int(evidence.get("storage_sink_block_count", 0) or 0) >= 2
            )
        )
        if definition_count <= 1 and repeated_single_sink_alias:
            return False

        return True

    def projection_materialization_groups_v48(
        self, block_addr=None, projection=None, full_scope=False
    ):
        """Return exact drop-in block groups for focal or full-function scope."""
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = (
            "projection:materialization_groups:v48", projection,
            focus, bool(full_scope), revision,
            str(self.naming), bool(self.operator_overlay),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        if full_scope:
            blocks = {
                self._canonical_block_addr_v21(
                    dict(context or {}).get("block")
                )
                for context in self.projection_statement_contexts_v33(
                    projection
                )
            }
            blocks.discard(None)
        else:
            blocks = {focus} if focus is not None else set()

        groups = []
        for block in sorted(blocks, key=self._asm_address_sort_v34):
            groups.extend(
                dict(group or {})
                for group in self.projection_dropin_groups_for_block_v45(
                    block, projection=projection
                )
            )
        cached = tuple(groups)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def materialized_variable_inventory_v48(
        self, block_addr=None, projection=None, full_scope=False
    ):
        """Aggregate concrete storage destinations and valid emitted temps.

        Human-facing storage remains the primary inventory.  A raw ``v_*`` destination is retained when publication proves either a
        multi-definition/PHI selector or a one-definition value with a real
        downstream consumer.  Repeated one-source-to-one-storage alias traffic
        remains provenance-only.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        revision = int(getattr(self.oncs, "revision", 0) or 0)
        cache_key = (
            "projection:materialized_inventory:v50", projection,
            focus, bool(full_scope), revision,
            str(self.naming), bool(self.operator_overlay),
        )
        cached = self._truth_source_lines_cache.get(cache_key)
        if cached is not None:
            return cached

        variables = {}
        for raw_group in self.projection_materialization_groups_v48(
            focus, projection=projection, full_scope=full_scope
        ):
            group = dict(raw_group or {})
            block = self._canonical_block_addr_v21(group.get("block"))
            if block is None:
                continue
            for raw_assignment in list(group.get("assignments", ()) or ()):
                assignment = dict(raw_assignment or {})
                destinations = tuple(
                    self.canonical_phi_sid_v33(value)
                    for value in list(
                        assignment.get("destination_sids", ()) or ()
                    )
                    if value
                )
                for sid in destinations:
                    record = variables.setdefault(sid, {
                        "output_sid": sid,
                        "sid": sid,
                        "pal_name": self.active_display_name_v38(sid),
                        "blocks": {},
                        "occurrence_count": 0,
                        "assignment_count": 0,
                    })
                    block_record = record["blocks"].setdefault(block, {
                        "block": block,
                        "assignments": {},
                        "occurrence_count": 0,
                    })
                    code = str(assignment.get("text") or "").strip()
                    sources = tuple(
                        self.canonical_phi_sid_v33(value)
                        for value in list(
                            assignment.get("source_sids", ()) or ()
                        )
                        if value
                    )
                    identity = (code, destinations, sources)
                    prior = block_record["assignments"].get(identity)
                    count = max(1, int(
                        assignment.get("occurrence_count", 0) or 0
                    ))
                    if prior is None:
                        prior = dict(assignment)
                        prior["occurrence_count"] = count
                        block_record["assignments"][identity] = prior
                        record["assignment_count"] += 1
                    else:
                        prior["occurrence_count"] = max(
                            int(prior.get("occurrence_count", 0) or 0), count
                        )
                    block_record["occurrence_count"] += count
                    record["occurrence_count"] += count

        inventory = []
        for sid, raw_record in variables.items():
            record = dict(raw_record or {})
            block_rows = []
            for block, raw_block in sorted(
                record["blocks"].items(),
                key=lambda pair: self._asm_address_sort_v34(pair[0]),
            ):
                block_record = dict(raw_block or {})
                assignments = list(
                    dict(value or {})
                    for value in block_record.get("assignments", {}).values()
                )
                assignments.sort(key=lambda item: (
                    min(item.get("line_numbers", ()) or (1 << 30,)),
                    str(item.get("text") or ""),
                ))
                block_record["assignments"] = tuple(assignments)
                block_record["assignment_count"] = len(assignments)
                block_rows.append(block_record)
            record["blocks"] = tuple(block_rows)
            record["block_count"] = len(block_rows)

            storage = self._is_materialized_storage_sid_v48(sid)
            valid_temp = self._is_valid_control_temp_v50(sid, record)
            if not storage and not valid_temp:
                continue
            record["materialization_kind"] = (
                "storage" if storage else "control_temp"
            )
            inventory.append(record)

        inventory.sort(key=lambda item: (
            str(item.get("pal_name") or "").casefold(),
            str(item.get("output_sid") or "").casefold(),
        ))
        for ordinal, item in enumerate(inventory, 1):
            item["ordinal"] = ordinal
        cached = tuple(inventory)
        self._truth_source_lines_cache[cache_key] = cached
        return cached

    def phi_dropin_focus_rows_v45(
        self, block_addr, projection=None
    ):
        """Compact block-grouped drop-in view for the one-third PHI pane.

        Human reading order is vertical:

            block summary
            assignment facts, one fact per line
            block sequence once
            executed code, one complete data item per line

        Code expressions are never broken or rewritten merely to fit the pane;
        horizontal scrolling remains available for an intrinsically long item.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        groups = list(self.projection_dropin_groups_for_block_v45(
            focus, projection=projection
        ) or ())
        if focus is None or not groups:
            return ()

        rows = [{
            "kind": "phi_section",
            "text": "DROP-IN BLOCKS @ %s [%d]" % (focus, len(groups)),
            "dropin_mode": True,
            "focus_addr": focus,
        }]

        for group in groups:
            group_id = str(group.get("dropin_id") or "")
            block = self._canonical_block_addr_v21(
                group.get("block")
            ) or focus
            group_index = int(group.get("ordinal", 0) or 0)
            assignments = list(group.get("assignments", ()) or ())
            destinations = tuple(group.get("destination_sids", ()) or ())
            sources = tuple(group.get("source_sids", ()) or ())
            rows.append({
                "kind": "dropin_summary",
                "dropin_mode": True,
                "dropin_id": group_id,
                "dropin_index": group_index,
                "output_sid": destinations[0] if destinations else None,
                "destination_sids": destinations,
                "source_sids": sources,
                "address": block,
                "addr": block,
                "line_number": min((
                    line for assignment in assignments
                    for line in list(assignment.get("line_numbers", ()) or ())
                ), default=0),
                "text": "BLOCK %s | %d assignment%s | %d occurrence%s" % (
                    block,
                    int(group.get("assignment_count", len(assignments)) or 0),
                    "" if len(assignments) == 1 else "s",
                    int(group.get("occurrence_count", 0) or 0),
                    "" if int(group.get("occurrence_count", 0) or 0) == 1 else "s",
                ),
            })

            # v0.35a: the top summary already names the grouped ASM block.
            # Do not repeat PY line, occurrence, writes, reads, evidence, and
            # code prose before the custody blade.  The blade starts directly,
            # while the complete executed code remains at its terminal event.
            rows.extend((
                {"kind": "blank", "text": "", "dropin_mode": True},
                {
                    "kind": "dropin_sequence_header",
                    "dropin_mode": True,
                    "dropin_sequence_id": group_id,
                    "dropin_id": group_id,
                    "dropin_index": group_index,
                    "text": "PHI BLADE @ %s" % block,
                },
            ))

            emitted_path_rows = set()
            any_path = False
            for destination in destinations:
                index = self.phi_custody_index_for_sid_v16(destination)
                if index is None:
                    note_key = ("direct", str(destination))
                    if note_key not in emitted_path_rows:
                        emitted_path_rows.add(note_key)
                        rows.append({
                            "kind": "phi_sequence_note",
                            "dropin_mode": True,
                            "dropin_sequence_id": group_id,
                            "dropin_id": group_id,
                            "dropin_index": group_index,
                            "output_sid": destination,
                            "text": "  direct: %s" % self.phi_display_name_v30(destination),
                        })
                    continue
                for raw in self.phi_custody_blade_v14(index):
                    row = dict(raw or {})
                    if row.get("kind") in (
                        "header_top", "header_bottom", "blank",
                        "trunk", "final",
                    ):
                        continue
                    semantic_key = (
                        str(row.get("kind") or ""),
                        str(row.get("address") or ""),
                        str(row.get("event_sid") or ""),
                        str(row.get("output_sid") or ""),
                        str(row.get("text") or ""),
                    )
                    if semantic_key in emitted_path_rows:
                        continue
                    emitted_path_rows.add(semantic_key)
                    any_path = True
                    row["dropin_mode"] = True
                    row["dropin_sequence_id"] = group_id
                    row["dropin_id"] = group_id
                    row["dropin_index"] = group_index
                    row["phi_template"] = bool(
                        row.get("phi_template", True)
                    )
                    rows.append(row)
            if not any_path and not destinations:
                rows.append({
                    "kind": "phi_sequence_note",
                    "dropin_mode": True,
                    "dropin_sequence_id": group_id,
                    "dropin_id": group_id,
                    "dropin_index": group_index,
                    "text": "  no PHI custody chain is frozen",
                })

            prefix = "        | "
            rows.extend((
                {"kind": "blank", "text": "", "dropin_mode": True},
                {
                    "kind": "dropin_exec",
                    "dropin_mode": True,
                    "dropin_sequence_id": group_id,
                    "dropin_id": group_id,
                    "dropin_index": group_index,
                    "output_sid": destinations[0] if destinations else None,
                    "event_sid": destinations[0] if destinations else None,
                    "address": block,
                    "address_display": block,
                    "address_offset": len(prefix),
                    "block_hotspot": True,
                    "phi_template": True,
                    "text": "%s%-21s DROP-IN BLOCK EXECUTES"
                    % (prefix, block),
                },
            ))
            for assignment in assignments:
                rows.append({
                    "kind": "dropin_code",
                    "dropin_mode": True,
                    "dropin_sequence_id": group_id,
                    "dropin_id": group_id,
                    "dropin_index": group_index,
                    "assignment_index": int(
                        assignment.get("ordinal", 0) or 0
                    ),
                    "full_data_item": True,
                    "text": "          [%d] %s" % (
                        int(assignment.get("ordinal", 0) or 0),
                        str(assignment.get("text") or ""),
                    ),
                })
        return tuple(rows)

    def phi_paths_for_code_context_v33(self, block_addr, context, rows=None):
        """Select statement-owned PHI outputs before falling back to block scope."""
        focus = self._canonical_block_addr_v21(block_addr)
        rows = [dict(row or {}) for row in list(rows if rows is not None else self.phi_path_focus_rows_v21())]
        context = dict(context or {})
        destination = {
            self.canonical_phi_sid_v33(value)
            for value in list(context.get("destination_sids", ()) or ())
            if value
        }
        source = {
            self.canonical_phi_sid_v33(value)
            for value in list(context.get("source_sids", ()) or ())
            if value
        }
        all_sids = destination | source
        graph = self._phi_graph_v14()
        entries = {
            str(entry.get("output_sid") or ""): dict(entry or {})
            for entry in list(graph.get("entries", ()) or ())
        }
        selected = []
        seen = set()
        for row in rows:
            output = self.canonical_phi_sid_v33(row.get("output_sid"))
            inputs = {
                self.canonical_phi_sid_v33(value)
                for value in list(row.get("input_sids", ()) or ())
                if value
            }
            roots = {
                self.canonical_phi_sid_v33(value)
                for value in list(entries.get(output, {}).get("roots", ()) or ())
                if value
            }
            block_match = focus in {
                self._canonical_block_addr_v21(row.get("incoming_addr")),
                self._canonical_block_addr_v21(row.get("merge_addr")),
            }
            if destination:
                implicated = output in destination
            elif all_sids:
                implicated = block_match and (
                    output in all_sids or bool(inputs & all_sids) or bool(roots & all_sids)
                )
            else:
                implicated = self._canonical_block_addr_v21(row.get("incoming_addr")) == focus
            if implicated and output not in seen:
                selected.append(row)
                seen.add(output)
        # A drop-in destination can be statement-owned without a PHI edge whose
        # address equals the rendered assignment block.  Add a narrow synthetic
        # authority row only for destinations that have frozen PHI custody.
        for output in sorted(destination):
            entry = entries.get(output, {})
            if output in seen or not entry.get("has_phi"):
                continue
            selected.append({
                "kind": "phi_path", "incoming_addr": focus,
                "incoming_role": "statement_destination",
                "merge_addr": focus, "output_sid": output,
                "pal_name": entry.get("pal_name") or output,
                "input_sids": tuple(entry.get("roots", ()) or ()),
                "statement_owned": True,
                "text": "%s => %s [statement destination]" % (
                    focus or "-", self.phi_display_name_v30(output),
                ),
            })
            seen.add(output)
        return tuple(selected)
    def projection_block_activity_v47(
        self, block_addr, projection=None, statement_context=None
    ):
        """Return exact Python/drop-in SID activity for one CFG block.

        A PHI merge may be attached to a block entry without being consumed by
        the instructions rendered in that block.  This inventory keeps those
        concepts separate.  It uses only already-frozen PALDocument evidence:
        statement definitions/uses and explicit drop-in source/destination
        custody.  It does not infer new PHI semantics from CFG shape alone.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        buckets = {
            "definition_sids": set(),
            "destination_sids": set(),
            "use_sids": set(),
            "source_sids": set(),
            "dropin_destination_sids": set(),
            "dropin_source_sids": set(),
            "line_indices": set(),
        }
        if focus is None:
            return {
                "block": None, "projection": projection,
                "active_sids": (), "read_sids": (), "write_sids": (),
                "dropin_sids": (), "line_indices": (),
                **{key: () for key in buckets if key != "line_indices"},
            }

        try:
            contexts = list(
                self.projection_statement_contexts_v33(projection) or ()
            )
        except Exception:
            contexts = []
        try:
            blocks = list(self.projection_block_map_v21(
                projection, allow_cursor_fallback=False
            ) or ())
        except Exception:
            blocks = []

        selected_contexts = []
        for index, raw in enumerate(contexts):
            context = dict(raw or {})
            owned = self._canonical_block_addr_v21(
                context.get("block")
                or (blocks[index] if index < len(blocks) else None)
            )
            if owned != focus:
                continue
            selected_contexts.append(context)
            buckets["line_indices"].add(index)
        if statement_context:
            selected_contexts.append(dict(statement_context or {}))

        sid_keys = (
            "definition_sids", "destination_sids", "use_sids",
            "source_sids", "dropin_destination_sids",
            "dropin_source_sids",
        )
        for context in selected_contexts:
            for key in sid_keys:
                for value in list(context.get(key, ()) or ()):
                    canonical = self.canonical_phi_sid_v33(value)
                    if canonical:
                        buckets[key].add(canonical)
            # Older contexts may publish only all_sids.  Treat them as reads;
            # this is display relevance, not a write/materialization claim.
            for value in list(context.get("all_sids", ()) or ()):
                canonical = self.canonical_phi_sid_v33(value)
                if canonical:
                    buckets["source_sids"].add(canonical)

        write_sids = (
            buckets["definition_sids"]
            | buckets["destination_sids"]
            | buckets["dropin_destination_sids"]
        )
        read_sids = (
            buckets["use_sids"]
            | buckets["source_sids"]
            | buckets["dropin_source_sids"]
        )
        dropin_sids = (
            buckets["dropin_destination_sids"]
            | buckets["dropin_source_sids"]
        )
        active_sids = read_sids | write_sids
        result = {
            "block": focus,
            "projection": projection,
            "active_sids": tuple(sorted(active_sids)),
            "read_sids": tuple(sorted(read_sids)),
            "write_sids": tuple(sorted(write_sids)),
            "dropin_sids": tuple(sorted(dropin_sids)),
            "line_indices": tuple(sorted(buckets["line_indices"])),
        }
        for key in sid_keys:
            result[key] = tuple(sorted(buckets[key]))
        return result

    def phi_paths_for_focal_block_v47(
        self, block_addr, statement_context=None, rows=None,
        projection=None,
    ):
        """Classify PHI custody as active block work or passive entry state.

        Address coincidence alone is not sufficient evidence that a PHI value
        is read, written or materialized by the focused machine block.  The
        returned rows retain true PHI custody while tagging its relationship to
        the current ASM/Python scope.
        """
        projection = str(projection or self.projection)
        focus = self._canonical_block_addr_v21(block_addr)
        activity = self.projection_block_activity_v47(
            focus, projection=projection,
            statement_context=statement_context,
        )
        active_sids = set(activity.get("active_sids", ()) or ())
        read_sids = set(activity.get("read_sids", ()) or ())
        write_sids = set(activity.get("write_sids", ()) or ())
        dropin_sids = set(activity.get("dropin_sids", ()) or ())
        rows = [
            dict(row or {}) for row in list(
                rows if rows is not None
                else self.phi_path_focus_rows_v21()
            )
        ]
        graph = self._phi_graph_v14()
        entries = {
            str(entry.get("output_sid") or ""): dict(entry or {})
            for entry in list(graph.get("entries", ()) or ())
        }

        active = []
        passive = []
        seen = set()
        for raw in rows:
            row = dict(raw or {})
            incoming = self._canonical_block_addr_v21(
                row.get("incoming_addr")
            )
            merge = self._canonical_block_addr_v21(row.get("merge_addr"))
            if focus not in (incoming, merge):
                continue
            output = self.canonical_phi_sid_v33(row.get("output_sid"))
            inputs = {
                self.canonical_phi_sid_v33(value)
                for value in list(row.get("input_sids", ()) or ())
                if value
            }
            roots = {
                self.canonical_phi_sid_v33(value)
                for value in list(entries.get(output, {}).get("roots", ()) or ())
                if value
            }
            relation = (
                "merge_at_entry" if merge == focus
                else "carried_from_block" if incoming == focus
                else "block_context"
            )
            relevant = {output} | inputs | roots
            intersection = relevant & active_sids
            is_active = bool(intersection or row.get("statement_owned"))
            if output in write_sids:
                block_use = "READ+WRITE" if output in read_sids else "WRITE"
            elif output in read_sids or bool((inputs | roots) & read_sids):
                block_use = "READ"
            elif bool(relevant & dropin_sids):
                block_use = "DROP-IN"
            elif is_active:
                block_use = "RELATED"
            else:
                block_use = "NONE"

            if relation == "merge_at_entry":
                tag = (
                    "MERGES AT BLOCK ENTRY — ACTIVE HERE"
                    if is_active else "ENTRY STATE — UNUSED HERE"
                )
                short = (
                    "ACTIVE: %s" % block_use
                    if is_active else "PASSIVE ENTRY"
                )
            elif relation == "carried_from_block":
                tag = (
                    "CARRIED FROM BLOCK — ACTIVE HERE"
                    if is_active else "CHAIN CONTEXT ONLY — UNUSED HERE"
                )
                short = (
                    "ACTIVE: %s" % block_use
                    if is_active else "PASSIVE CARRY"
                )
            else:
                tag = "FOCAL BLOCK ACTIVITY" if is_active else "CHAIN CONTEXT ONLY"
                short = "ACTIVE" if is_active else "PASSIVE"

            row.update({
                "output_sid": output,
                "input_sids": tuple(sorted(inputs)),
                "incoming_addr": incoming,
                "merge_addr": merge,
                "focal_relation_v47": relation,
                "block_activity_v47": "active" if is_active else "passive",
                "block_use_v47": block_use,
                "activity_tag_v47": tag,
                "activity_short_v47": short,
                "activity_intersection_v47": tuple(sorted(intersection)),
            })
            identity = (
                output, incoming, merge, tuple(sorted(inputs)), relation,
            )
            if identity in seen:
                continue
            seen.add(identity)
            (active if is_active else passive).append(row)

        # A statement-owned drop-in destination may not expose an edge record
        # whose merge address equals the rendered assignment block.  Retain the
        # narrow synthetic authority row used by v0.35, but tag it explicitly as
        # a block write rather than a CFG merge.
        destination_sids = set(activity.get("write_sids", ()) or ())
        existing_outputs = {
            str(row.get("output_sid") or "") for row in active + passive
        }
        for output in sorted(destination_sids):
            entry = entries.get(output, {})
            if output in existing_outputs or not entry.get("has_phi"):
                continue
            active.append({
                "kind": "phi_path",
                "incoming_addr": focus,
                "incoming_role": "statement_destination",
                "merge_addr": focus,
                "output_sid": output,
                "pal_name": entry.get("pal_name") or output,
                "input_sids": tuple(entry.get("roots", ()) or ()),
                "statement_owned": True,
                "focal_relation_v47": "statement_destination",
                "block_activity_v47": "active",
                "block_use_v47": "WRITE",
                "activity_tag_v47": "MATERIALIZES HERE",
                "activity_short_v47": "ACTIVE: WRITE",
                "activity_intersection_v47": (output,),
                "text": "%s => %s [MATERIALIZES HERE]" % (
                    focus or "-", self.phi_display_name_v30(output),
                ),
            })

        def sort_key(row):
            return (
                0 if row.get("focal_relation_v47") == "merge_at_entry" else 1,
                str(self.phi_display_name_v30(row.get("output_sid"))).casefold(),
                str(row.get("output_sid") or "").casefold(),
            )
        active.sort(key=sort_key)
        passive.sort(key=sort_key)
        return {
            "focus": focus,
            "activity": activity,
            "active": tuple(active),
            "passive": tuple(passive),
            "all": tuple(active + passive),
        }

    def truth_digest(self):
        metadata_view = IcecubeMetadataView(
            self.document, function_record=self.function_record
        )
        return TruthDigestDaily(
            metadata_view,
            oncs_rows=self.oncs_digest_rows(),
            cursor=self._cursor_context(include_variable=True),
        )

    def save(self, path=None):
        digest = self.oncs.save(path)
        self.status = "PAL_ONCS saved; icecube unchanged"
        return digest

    @staticmethod
    def _artifact_paths_v41(value, depth=0):
        """Collect path-shaped strings from schema-tolerant manifest artifacts."""
        if value is None or depth > 7:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            found = []
            for key in ("path", "filename", "file"):
                candidate = value.get(key)
                if isinstance(candidate, str):
                    found.append(candidate)
            for child in value.values():
                if isinstance(child, (dict, list, tuple, set)):
                    found.extend(PALTerminalModel._artifact_paths_v41(
                        child, depth + 1
                    ))
            return found
        if isinstance(value, (list, tuple, set)):
            found = []
            for child in value:
                found.extend(PALTerminalModel._artifact_paths_v41(
                    child, depth + 1
                ))
            return found
        return []

    @staticmethod
    def _python_export_filename_v41(value):
        """Normalize one PAL function artifact to its deployed .py basename."""
        text = os.path.basename(os.fspath(value or "")).strip()
        if not text:
            return None
        lower = text.lower()
        for suffix in (
            ".icecube.json.gz", ".icecube.json", ".json.gz", ".json",
        ):
            if lower.endswith(suffix):
                text = text[:-len(suffix)] + ".py"
                lower = text.lower()
                break
        for suffix in (
            ".executable.py", ".readable.py", ".exec.py", ".read.py",
        ):
            if lower.endswith(suffix):
                text = text[:-len(suffix)] + ".py"
                lower = text.lower()
                break
        if not lower.endswith(".py"):
            text += ".py"
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", text[:-3]).strip("._")
        if not stem:
            return None
        if stem[0].isdigit():
            stem = "f_" + stem
        return stem + ".py"

    def _project_root_for_execute_export_v41(self):
        """Resolve the owning PAL project directory, never the PAL repo root."""
        store_path = getattr(self.project_store, "path", None)
        if store_path:
            return os.path.dirname(os.path.abspath(os.fspath(store_path)))

        record = dict(self.function_record or {})
        manifest_record = dict(record.get("manifest_record", {}) or {})
        for owner in (record, manifest_record):
            for key in ("project_root", "project_dir", "root"):
                value = owner.get(key)
                if value:
                    return os.path.abspath(os.fspath(value))

        source = os.path.abspath(os.fspath(self.source_path)) if self.source_path else None
        if source:
            parent = os.path.dirname(source)
            if os.path.basename(parent).casefold() == PROJECT_FUNCTIONS_DIRECTORY.casefold():
                return os.path.dirname(parent)
            return parent
        raise ValueError("cannot resolve the owning PAL project directory")

    def _execute_export_candidate_names_v41(self):
        """Return names derived only from executable/function identity evidence."""
        record = dict(self.function_record or {})
        manifest_record = dict(record.get("manifest_record", {}) or {})
        artifacts = dict(manifest_record.get("artifacts", {}) or {})
        candidates = []

        def add(value):
            filename = self._python_export_filename_v41(value)
            if filename and filename not in candidates:
                candidates.append(filename)

        # READ artifacts are deliberately excluded.  Ctrl-E owns only the
        # executable projection and deployed execute/functions replacement.
        for key, value in sorted(artifacts.items(), key=lambda pair: str(pair[0]).casefold()):
            key_text = str(key).casefold()
            declared = self._artifact_paths_v41(value)
            executable_key = any(token in key_text for token in (
                "exec", "executable", "python_exec", "runtime",
            ))
            executable_path = any(
                str(path).casefold().endswith((".exec.py", ".executable.py"))
                for path in declared
            )
            if executable_key or executable_path:
                for path in declared:
                    add(path)

        for owner in (manifest_record, record):
            for key in (
                "executable_path", "exec_path", "runtime_path",
                "python_symbol", "qualified_name", "active_name",
                "pal_name", "name", "original_name",
            ):
                if owner.get(key):
                    add(owner[key])
        add(self.source_path)
        try:
            add(getattr(self.document, "function_name", None))
        except Exception:
            pass
        return tuple(candidates)

    def _execute_export_filename_v41(self, target_directory):
        """Resolve one existing deployed module in the live execute/functions scaffold.

        The exporter is intentionally replacement-only.  A missing or ambiguous
        scaffold is an error; silently creating a neighboring path caused the stale-file defect; v0.33 binds to the
        existing case-sensitive project scaffold.
        """
        if not os.path.isdir(target_directory):
            raise ValueError(
                "project execution directory is missing: %s" % target_directory
            )
        existing_names = sorted(
            name for name in os.listdir(target_directory)
            if name.lower().endswith(".py")
            and os.path.isfile(os.path.join(target_directory, name))
        )
        if not existing_names:
            raise ValueError(
                "no deployed Python functions in %s" % target_directory
            )
        existing = {name.casefold(): name for name in existing_names}
        candidates = self._execute_export_candidate_names_v41()

        # Exact deployed basename wins.
        for candidate in candidates:
            found = existing.get(candidate.casefold())
            if found:
                return found

        # Compare normalized .exec/.executable identities while retaining the
        # exact on-disk replacement filename.
        normalized = {}
        for name in existing_names:
            key = self._python_export_filename_v41(name)
            if key:
                normalized.setdefault(key.casefold(), []).append(name)
        for candidate in candidates:
            matches = normalized.get(candidate.casefold(), ())
            if len(matches) == 1:
                return matches[0]

        record = dict(self.function_record or {})
        manifest_record = dict(record.get("manifest_record", {}) or {})
        strong_tokens = []
        weak_tokens = []
        for owner in (manifest_record, record):
            for key in ("entry_hex", "entry"):
                value = owner.get(key)
                if value is not None:
                    token_value = re.sub(r"[^A-Za-z0-9]+", "", str(value)).casefold()
                    token_value = token_value.removeprefix("0x")
                    if len(token_value) >= 4 and token_value not in strong_tokens:
                        strong_tokens.append(token_value)
            for key in ("name", "qualified_name", "python_symbol", "pal_name"):
                value = owner.get(key)
                if value is not None:
                    token_value = re.sub(r"[^A-Za-z0-9]+", "", str(value)).casefold()
                    if len(token_value) >= 3 and token_value not in weak_tokens:
                        weak_tokens.append(token_value)
        for candidate in candidates:
            token_value = re.sub(r"[^A-Za-z0-9]+", "", candidate).casefold()
            token_value = token_value.removesuffix("py")
            if len(token_value) >= 4 and token_value not in weak_tokens:
                weak_tokens.append(token_value)

        def compact(name):
            return re.sub(r"[^A-Za-z0-9]+", "", name).casefold()

        strong_matches = [
            name for name in existing_names
            if any(token in compact(name) for token in strong_tokens)
        ]
        if len(strong_matches) == 1:
            return strong_matches[0]
        weak_matches = [
            name for name in existing_names
            if any(token in compact(name) for token in weak_tokens)
        ]
        if len(weak_matches) == 1:
            return weak_matches[0]

        preview = ", ".join(existing_names[:8])
        raise ValueError(
            "cannot uniquely resolve deployed function in %s; candidates=%s; existing=%s"
            % (target_directory, ",".join(candidates) or "-", preview or "-")
        )

    def _execute_functions_directory_v42(self):
        """Resolve the existing case-sensitive project execution scaffold.

        PAL publication currently emits ``execute/functions`` on Linux.  The
        exact lowercase path is authoritative.  A narrow case-insensitive
        discovery fallback supports pre-existing alternate-case scaffolds, but
        this exporter never creates a neighboring directory and never guesses
        when more than one case variant exists.
        """
        project_root = self._project_root_for_execute_export_v41()
        canonical = os.path.abspath(os.path.join(
            project_root, PROJECT_EXECUTE_FUNCTIONS_DIRECTORY
        ))
        if os.path.isdir(canonical):
            return canonical

        matches = []
        try:
            root_entries = os.listdir(project_root)
        except OSError as exc:
            raise ValueError(
                "cannot inspect project directory %s: %s"
                % (project_root, exc)
            )
        for execute_name in root_entries:
            if str(execute_name).casefold() != "execute":
                continue
            execute_root = os.path.join(project_root, execute_name)
            if not os.path.isdir(execute_root):
                continue
            try:
                function_entries = os.listdir(execute_root)
            except OSError:
                continue
            for functions_name in function_entries:
                if str(functions_name).casefold() != "functions":
                    continue
                candidate = os.path.abspath(os.path.join(
                    execute_root, functions_name
                ))
                if os.path.isdir(candidate) and candidate not in matches:
                    matches.append(candidate)

        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(
                "ambiguous execution scaffolds beneath %s: %s"
                % (project_root, ", ".join(matches))
            )
        raise ValueError(
            "project execution directory is missing: %s" % canonical
        )

    def execute_export_target_v41(self):
        directory = self._execute_functions_directory_v42()
        filename = self._execute_export_filename_v41(directory)
        return os.path.abspath(os.path.join(directory, filename))

    @staticmethod
    def _normalize_execute_function_header_v43(lines):
        """Remove the UI-only ``f_`` prefix from the primary exported symbol.

        PAL's deployed filename remains unchanged (for example
        ``f_0000000000101129_PALexec.py``).  This normalization affects only
        Python identifier tokens in the exported source.  Renaming every token
        equal to the primary top-level function symbol also preserves recursive
        self-calls without touching strings, comments, or unrelated identifiers.
        """
        rendered = tuple(str(line) for line in list(lines or ()))
        if not rendered:
            return rendered, None, None
        source = "\n".join(rendered) + "\n"
        try:
            tree = ast.parse(source)
        except SyntaxError:
            # The ordinary export compile gate reports malformed Python.  Do
            # not conceal that error behind header normalization.
            return rendered, None, None

        primary = next((
            node for node in list(getattr(tree, "body", ()) or ())
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ), None)
        if primary is None:
            return rendered, None, None

        old_name = str(primary.name or "")
        if not old_name.startswith("f_"):
            return rendered, old_name, old_name
        new_name = old_name[2:]
        if (
            not new_name
            or not new_name.isidentifier()
            or keyword.iskeyword(new_name)
        ):
            return rendered, old_name, old_name

        normalized = tuple(_replace_name_tokens(
            rendered, {old_name: new_name}
        ))
        return normalized, old_name, new_name

    def export_execute_function_v41(self, projection=None):
        """Replace only the project's deployed EXEC projection.

        The source projection is always ``executable``.  The current
        SSA/PAL/HUMANIZED naming mode and operator overlay are still honored,
        allowing Codium debugging with the augmented names currently shown by
        the UI.  READ.PY is never rendered or modified by this operation.
        """
        projection = "executable"
        if self.document.projection(projection) is None:
            raise ValueError("executable projection is unavailable")

        rendered_lines = tuple(self.oncs.render_lines(
            projection, self.naming, self.operator_overlay
        ) or ())
        if not rendered_lines:
            raise ValueError("executable Python projection is empty")
        lines, header_before, header_after = (
            self._normalize_execute_function_header_v43(rendered_lines)
        )
        body = "\n".join(str(line) for line in lines) + "\n"
        source = body if body.startswith("#!") else "#!/usr/bin/env python3\n" + body
        target = self.execute_export_target_v41()

        # Compile before touching the deployed function.
        compile(source, target, "exec")
        if not os.path.isfile(target):
            raise ValueError("deployed execution function is missing: %s" % target)

        before_digest = _sha256_file(target)
        before_stat = os.stat(target)
        existing_mode = stat.S_IMODE(before_stat.st_mode)
        mode = existing_mode | 0o755
        temporary = "%s.tmp.%d" % (target, os.getpid())
        try:
            with open(temporary, "wt", encoding="utf-8", newline="\n") as handle:
                handle.write(source)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, target)
            try:
                directory_fd = os.open(os.path.dirname(target), os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

        after_digest = _sha256_file(target)
        after_stat = os.stat(target)
        installed_mode = stat.S_IMODE(after_stat.st_mode)
        if not (installed_mode & stat.S_IXUSR):
            raise RuntimeError("installed function is not executable: %s" % target)
        with open(target, "rt", encoding="utf-8") as handle:
            if handle.read() != source:
                raise RuntimeError("post-install verification failed: %s" % target)

        combo = self.naming_label().upper()
        project_root = self._project_root_for_execute_export_v41()
        relative = os.path.relpath(target, project_root)
        changed = before_digest != after_digest
        header_note = (
            "%s->%s" % (header_before, header_after)
            if header_before and header_after and header_before != header_after
            else str(header_after or "unchanged")
        )
        self.status = (
            "Ctrl-E PY.EXEC EXEC/%s -> %s [LIVE-PATH=YES, REPLACED=YES, header=%s, content=%s, executable, sha256=%s]"
            % (
                combo, relative, header_note,
                "CHANGED" if changed else "IDENTICAL", after_digest[:12],
            )
        )
        return {
            "path": target,
            "relative_path": relative,
            "projection": projection,
            "naming": self.naming,
            "operator_overlay": bool(self.operator_overlay),
            "naming_label": combo,
            "sha256": after_digest,
            "previous_sha256": before_digest,
            "changed": changed,
            "mode": installed_mode,
            "line_count": len(lines),
            "function_header_before": header_before,
            "function_header_after": header_after,
            "function_header_prefix_removed": bool(
                header_before and header_after and header_before != header_after
            ),
            "mtime_ns": int(after_stat.st_mtime_ns),
        }

    # Compatibility entry points retained for external callers of v0.31.
    def execute_export_target_v40(self):
        return self.execute_export_target_v41()

    def export_execute_function_v40(self, projection=None):
        return self.export_execute_function_v41(projection=projection)

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
    @functools.lru_cache(maxsize=16384)
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

    @staticmethod
    @functools.lru_cache(maxsize=16384)
    def identifier_spans(text):
        spans = []
        try:
            stream = io.StringIO(str(text) + "\n").readline
            for item in tokenize.generate_tokens(stream):
                if item.type == token.NAME:
                    spans.append((
                        item.start[1], item.end[1], item.string
                    ))
        except (IndentationError, SyntaxError, tokenize.TokenError):
            for match in re.finditer(
                r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                str(text),
            ):
                spans.append((
                    match.start(), match.end(), match.group(0)
                ))
        return tuple(spans)


class PALCursesUI:
    def __init__(self, screen, model, save_handler=None):
        self.screen = screen
        self.model = model
        self.save_handler = save_handler
        self.running = True
        self.exit_reason = None
        self.pairs = {}

        # Four-pane truth-comparison state.  The ordinary single-pane editor
        # remains the default and keeps its original cursor/scroll state.
        self.side_by_side = False
        self.side_active = 0
        self.side_panes = ("asm", "executable", "c_code", "readable")
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
        self._side_static_lines_cache = {}
        # v12: C is immutable/static; ASM is block-specific and keyed by the
        # CFG allegiance of the last active READ/EXEC pane.
        self._side_asm_block_lines_cache = {}
        self._side_asm_block_addr = None
        self._last_layout = None
        self._dirty = True
        # v26 SPECOPS HIT: the editor and every menu pane share literal search
        # highlighting.  Enter owns focus highlighting; F clears search only.
        self.code_search_v26 = ""
        self.code_focus_line_v26 = None
        # v28 keeps graphic-menu selection and pane cursors stable across
        # returns to the root editor.
        self._specops_ui_v28 = None
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
                "phi_header": 34, "phi_merge_addr": 88,
                "phi_incoming_addr": 22, "phi_final": 25,
                "phi_final_sid": 196, "phi_cycle": 231,
                "phi_list": 231, "asm_block_header": 220,
                "asm_relation": 231, "asm_relation_current": 231,
                "asm_transition_orange": 166,
                "asm_compare": 141,
                "asm_instruction_addr": 81,
                "asm_instruction_addr_on_hover": 81,
                "asm_focus_block": 231,
                "asm_join_block": 16,
                "asm_fork_block": 16,
                "link_hover_reverse": 220,
                "asm_jump_red": 196,
                "asm_jump_on_focus": 52,
                "asm_jump_on_join": 196,
                "asm_jump_on_fork": 196,
                "asm_jump_on_hover": 196,
            }
            status_background = 24
            highlight_background = 220
            active_header_background = 196
            phi_final_background = 25
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
                "phi_header": curses.COLOR_GREEN,
                "phi_merge_addr": curses.COLOR_RED,
                "phi_incoming_addr": curses.COLOR_GREEN,
                "phi_final": curses.COLOR_BLUE,
                "phi_final_sid": curses.COLOR_RED, "phi_cycle": curses.COLOR_WHITE,
                "phi_list": curses.COLOR_WHITE,
                "asm_block_header": curses.COLOR_YELLOW,
                "asm_relation": curses.COLOR_WHITE,
                "asm_relation_current": curses.COLOR_WHITE,
                "asm_transition_orange": curses.COLOR_YELLOW,
                "asm_compare": curses.COLOR_MAGENTA,
                "asm_instruction_addr": curses.COLOR_CYAN,
                "asm_instruction_addr_on_hover": curses.COLOR_CYAN,
                "asm_focus_block": curses.COLOR_WHITE,
                "asm_join_block": curses.COLOR_BLACK,
                "asm_fork_block": curses.COLOR_BLACK,
                "link_hover_reverse": curses.COLOR_YELLOW,
                "asm_jump_red": curses.COLOR_RED,
                "asm_jump_on_focus": curses.COLOR_RED,
                "asm_jump_on_join": curses.COLOR_RED,
                "asm_jump_on_fork": curses.COLOR_RED,
                "asm_jump_on_hover": curses.COLOR_RED,
            }
            status_background = curses.COLOR_BLUE
            highlight_background = curses.COLOR_YELLOW
            active_header_background = curses.COLOR_RED
            phi_final_background = curses.COLOR_BLUE
        for pair_id, role in enumerate(palette, 1):
            background = (
                status_background if role == "status"
                else highlight_background if role == "highlight"
                else active_header_background if role == "active_header"
                else phi_final_background if role == "phi_final_sid"
                else 25 if role == "phi_cycle" and curses.COLORS >= 256
                else curses.COLOR_BLUE if role == "phi_cycle"
                else 24 if role == "phi_list" and curses.COLORS >= 256
                else curses.COLOR_BLUE if role == "phi_list"
                else 24 if role == "asm_relation" and curses.COLORS >= 256
                else curses.COLOR_BLUE if role == "asm_relation"
                else 196 if role == "asm_relation_current" and curses.COLORS >= 256
                else curses.COLOR_RED if role == "asm_relation_current"
                else 196 if role == "asm_focus_block" and curses.COLORS >= 256
                else curses.COLOR_RED if role == "asm_focus_block"
                else 220 if role == "asm_join_block" and curses.COLORS >= 256
                else curses.COLOR_YELLOW if role == "asm_join_block"
                else 34 if role == "asm_fork_block" and curses.COLORS >= 256
                else curses.COLOR_GREEN if role == "asm_fork_block"
                else 52 if role == "link_hover_reverse" and curses.COLORS >= 256
                else curses.COLOR_RED if role == "link_hover_reverse"
                else 196 if role == "asm_jump_on_focus" and curses.COLORS >= 256
                else curses.COLOR_RED if role == "asm_jump_on_focus"
                else 220 if role == "asm_jump_on_join" and curses.COLORS >= 256
                else curses.COLOR_YELLOW if role == "asm_jump_on_join"
                else 34 if role == "asm_jump_on_fork" and curses.COLORS >= 256
                else curses.COLOR_GREEN if role == "asm_jump_on_fork"
                else 52 if role == "asm_jump_on_hover" and curses.COLORS >= 256
                else curses.COLOR_RED if role == "asm_jump_on_hover"
                else 52 if role == "asm_instruction_addr_on_hover" and curses.COLORS >= 256
                else curses.COLOR_RED if role == "asm_instruction_addr_on_hover"
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

    def _prepare_frame(self, layout):
        height, width = self.screen.getmaxyx()
        signature = (str(layout), int(height), int(width))
        if signature != self._last_layout:
            self.screen.erase()
            self._last_layout = signature
        return height, width

    def _present(self):
        try:
            self.screen.noutrefresh()
            curses.doupdate()
        except Exception:
            self.screen.refresh()

    def _focus_spans(self, pane, text):
        names = set(self.model.object_focus_names(pane))
        legacy = self.model.highlight_name()
        if legacy:
            names.add(str(legacy))
        if not names:
            return []
        return [
            (start, end)
            for start, end, value in PythonTerminalHighlighter.identifier_spans(
                str(text)
            )
            if value in names
        ]

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
        for start, end in self._search_spans_v20(text, self.code_search_v26):
            clipped_start = max(start, self.model.left_column)
            clipped_end = min(end, self.model.left_column + width)
            if clipped_start >= clipped_end:
                continue
            self._safe_addstr(
                y,
                code_x + clipped_start - self.model.left_column,
                text[clipped_start:clipped_end],
                self._attr("active_header" if selected else "highlight", bold=True),
                clipped_end - clipped_start,
            )
        if selected:
            self._safe_addstr(
                y, code_x, visible.ljust(width),
                self._attr("active_header", bold=True), width,
            )

    # ------------------------------------------------------------------
    # FOUR-PANE TRUTH COMPARISON SUPPORT
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

        if pane == "asm":
            key = self.model._block_cache_key_v12(
                self._side_asm_block_addr
            )
            cached = self._side_asm_block_lines_cache.get(key)
            if cached is not None:
                return cached
            try:
                if self._side_asm_block_addr is None:
                    cached = tuple(
                        self.model.truth_source_lines("asm")
                    )
                else:
                    cached = tuple(
                        self.model.truth_block_asm_lines_v12(
                            self._side_asm_block_addr
                        )
                    )
            except Exception as exc:
                cached = (
                    "ASM truth panel unavailable",
                    "%s: %s" % (type(exc).__name__, exc),
                )
            self._side_asm_block_lines_cache[key] = cached
            return cached

        digest_panel = "c_code"
        cached = self._side_static_lines_cache.get(digest_panel)
        if cached is not None:
            return cached
        try:
            # Source-only path: do not build the all-variable Truth Digest just
            # to paint immutable C.  ASM uses its block-specific v12 path above.
            cached = tuple(self.model.truth_source_lines(digest_panel))
        except Exception as exc:
            cached = (
                "%s truth panel unavailable" % digest_panel.upper(),
                "%s: %s" % (type(exc).__name__, exc),
            )
        self._side_static_lines_cache[digest_panel] = cached
        return cached

    def _side_python_peer(self, pane):
        if pane == "readable":
            return "executable"
        if pane == "executable":
            return "readable"
        return None

    def _side_line_block_v52(self, pane, line):
        """Return CFG allegiance for one Python line without token metadata.

        OVERVIEW is line-focused.  It must not build object hotspots or resolve
        a variable beneath a column merely to synchronize READ/EXEC/ASM.
        Direct statement block ownership is authoritative; one bounded
        describe_cursor lookup is retained only for the active legacy line.
        """
        pane = str(pane)
        line = max(0, int(line))
        try:
            mapping = tuple(self.model.projection_block_map_v21(
                pane, allow_cursor_fallback=False
            ) or ())
        except Exception:
            mapping = ()
        if 0 <= line < len(mapping):
            block = self.model._canonical_block_addr_v21(mapping[line])
            if block is not None:
                return block
        try:
            return self.model._canonical_block_addr_v21(
                self.model.cursor_block_addr_v12(
                    projection=pane, line=line, column=0
                )
            )
        except Exception:
            return None

    def _side_lock_asm_v12(self, source_pane):
        """Lock ASM contents to the CFG block under the active Python line."""
        if source_pane not in ("readable", "executable"):
            return False

        source = self.side_state[source_pane]
        block_addr = self._side_line_block_v52(
            source_pane, int(source["line"])
        )
        if block_addr is None:
            # Synthetic/presentation lines may own no CFG block.  Retain the
            # last proven block rather than replacing machine truth with noise.
            return False

        new_key = self.model._block_cache_key_v12(block_addr)
        old_key = self.model._block_cache_key_v12(
            self._side_asm_block_addr
        )
        self._side_asm_block_addr = block_addr

        asm_state = self.side_state["asm"]
        if new_key != old_key:
            asm_state["line"] = 0
            asm_state["column"] = 0
            asm_state["top"] = 0
            asm_state["left"] = 0
        return True

    @staticmethod
    def _side_rectangles(height, width):
        """Legacy OVERVIEW geometry contract retained by linkage helpers.

        SPECOPS HIT draws its own body-relative grid, but the shared READ/EXEC
        linkage path still needs the original full-screen C-pane height to
        compute a stable percentage-following viewport.  v26 removed this
        helper while retaining its caller, causing OVERVIEW entry to fail.
        """
        body_height = max(0, int(height) - 2)
        top_height = body_height // 2
        bottom_height = body_height - top_height
        left_width = int(width) // 2
        right_width = int(width) - left_width
        return {
            "asm": (0, 0, top_height, left_width),
            "executable": (0, left_width, top_height, right_width),
            "c_code": (top_height, 0, bottom_height, left_width),
            "readable": (top_height, left_width, bottom_height, right_width),
        }

    def _side_soft_sync_c(self, source_pane):
        """Map active Python position directly onto the full C viewport.

        The C pane is a passive 0-100% follower.  Its viewport top moves across
        the complete available C range, rather than waiting for a selected line
        to collide with a page edge.
        """
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

        height, width = self.screen.getmaxyx()
        rect = self._side_rectangles(height, width).get(
            "c_code", (0, 0, 3, 8)
        )
        inner_height = max(1, int(rect[2]) - 2)
        maximum_top = max(0, len(c_lines) - inner_height)
        c_state["top"] = min(
            maximum_top,
            max(0, int(round(position * maximum_top))),
        )
        return True

    def _side_object_hotspot(
        self, pane, focus, preferred_line=None, preferred_column=None
    ):
        if not focus:
            return None
        focus_key = self.model._focus_key(focus)
        matches = []
        for item in list(self.model.hotspots(pane) or []):
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
        """Synchronize READ/EXEC by statement line and CFG block only.

        The former path delegated to column-sensitive ``sync_cursor`` and could
        wake legacy object-hotspot metadata for a line whose whole row is now
        the focus unit.  v0.24a finalizer maps the source line to its peer block,
        preserves relative line position inside that block, and falls back to
        document percentage only when frozen block ownership is unavailable.
        """
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
            max(0, int(source.get("column", 0))),
            len(source_lines[source_line]) if source_lines else 0,
        )
        source["line"] = source_line
        source["column"] = source_column

        target_line = line_from_document_position(
            percentage_document_position(source_line, len(source_lines)),
            len(target_lines),
        )
        reason = "line_percentage_fallback"
        source_block = self._side_line_block_v52(source_pane, source_line)

        try:
            source_map = tuple(self.model.projection_block_map_v21(
                source_pane, allow_cursor_fallback=False
            ) or ())
            target_map = tuple(self.model.projection_block_map_v21(
                peer, allow_cursor_fallback=False
            ) or ())
        except Exception:
            source_map = ()
            target_map = ()

        if source_block is not None and target_map:
            source_indices = [
                index for index, value in enumerate(source_map)
                if self.model._canonical_block_addr_v21(value) == source_block
            ]
            target_indices = [
                index for index, value in enumerate(target_map)
                if self.model._canonical_block_addr_v21(value) == source_block
            ]
            if target_indices:
                if len(source_indices) <= 1 or source_line not in source_indices:
                    relative = 0.0
                else:
                    relative = (
                        float(source_indices.index(source_line))
                        / float(len(source_indices) - 1)
                    )
                target_position = int(round(
                    relative * float(max(0, len(target_indices) - 1))
                ))
                target_line = target_indices[
                    min(max(0, target_position), len(target_indices) - 1)
                ]
                reason = "line_block_allegiance"

        target_line = min(
            max(0, int(target_line)), max(0, len(target_lines) - 1)
        )
        # The focus unit is the line, not a token.  Place the passive peer cursor
        # at indentation rather than performing variable-position recovery.
        target_column = 0
        if target_lines:
            target_text = str(target_lines[target_line])
            target_column = len(target_text) - len(target_text.lstrip())
        target["line"] = target_line
        target["column"] = target_column

        self.last_python_pane = source_pane
        self._side_lock_asm_v12(source_pane)
        if soft_c:
            self._side_soft_sync_c(source_pane)

        # Preserve the active Python cursor without invoking object metadata.
        self.model.projection = source_pane
        self.model.line = source_line
        self.model.column = source_column
        self.model.clamp()
        block_label = (
            self.model._block_cache_key_v12(self._side_asm_block_addr) or "-"
        )
        self.model.cursor_contract_sid = None
        self.model.cursor_context = {
            "projection": source_pane,
            "line": source_line,
            "column": source_column,
            "cfg_block_addr": source_block,
            "percentage_document_position": percentage_document_position(
                source_line, len(source_lines)
            ),
            "overview_line_focus_v52": True,
        }
        self.model.status = (
            "READ/EXEC linked (%s); ASM=%s; C direct %.1f%%; token metadata bypassed"
            % (
                reason,
                block_label,
                percentage_document_position(source_line, len(source_lines))
                * 100.0,
            )
        )
        return True

    def _side_soft_sync_from_c(self):
        """C is free-browse locally and never drives Python allegiance."""
        anchor = self.last_python_pane
        if anchor not in ("readable", "executable"):
            anchor = "readable"
        self.model.status = (
            "C free browse; direct soft-scroll resumes from highlighted %s"
            % anchor.upper()
        )
        return True

    def _side_refresh_linkage(self, source_pane):
        if source_pane in ("readable", "executable"):
            return self._side_sync_python_pair(source_pane)
        if source_pane == "c_code":
            return self._side_soft_sync_from_c()
        if source_pane == "asm":
            self.model.status = (
                "ASM free browse; Python movement restores block lock"
            )
            return True
        return False



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

    def _line_variable_contracts_v35(self, projection=None, line=None):
        """Return editable variables present on one rendered Python line."""
        projection = str(projection or self.model.projection)
        line = self.model.line if line is None else int(line)
        try:
            lines = self.model.oncs.render_lines(
                projection, self.model.naming, self.model.operator_overlay
            )
        except Exception:
            lines = self.model.oncs.base_lines(projection)
        if not lines or line < 0 or line >= len(lines):
            return []
        text = str(lines[line])
        out = []
        seen = set()
        for unused_start, unused_end, identifier in PythonTerminalHighlighter.identifier_spans(text):
            contract = self.model.oncs.contract_for_identifier(identifier)
            if not contract:
                canonical = self.model.canonical_phi_sid_v33(identifier)
                contract = self.model.oncs.contracts.get(canonical)
            contract = dict(contract or {})
            if not contract or _contract_operator_rename_protected_v34(contract):
                continue
            sid = str(contract.get("canonical_ssa_name") or contract.get("sid") or "")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            out.append(contract)
        return out

    def _select_line_variable_v35(self, contracts, title="VARIABLES ON CODE LINE"):
        contracts = [dict(value or {}) for value in list(contracts or ())]
        if not contracts:
            return None
        selected = 0
        top = 0
        while True:
            height, width = self.screen.getmaxyx()
            box_h = max(6, min(max(8, len(contracts) + 4), max(6, height - 2)))
            desired_w = max(48, max(len(self.model.current_mode_variable_name(c) or str(c.get("pal_name") or c.get("sid") or "")) for c in contracts) + 20)
            box_w = max(12, min(desired_w, max(12, width - 2)))
            y = max(0, (height - box_h) // 2)
            x = max(0, (width - box_w) // 2)
            window = curses.newwin(box_h, box_w, y, x)
            window.keypad(True)
            window.erase()
            try:
                window.box()
            except curses.error:
                pass
            try:
                window.addnstr(0, 2, " %s " % title, max(0, box_w - 4), self._attr("helper", bold=True))
            except curses.error:
                pass
            visible = max(1, box_h - 3)
            if selected < top:
                top = selected
            elif selected >= top + visible:
                top = selected - visible + 1
            top = min(max(0, top), max(0, len(contracts) - visible))
            for row, contract in enumerate(contracts[top:top + visible], 1):
                index = top + row - 1
                sid = str(contract.get("canonical_ssa_name") or contract.get("sid") or "-")
                name = self.model.current_mode_variable_name(contract) or contract.get("pal_name") or sid
                label = "%s  [SSA=%s]" % (name, sid)
                attr = self._attr("active_header", bold=True) if index == selected else self._attr("default")
                try:
                    window.addnstr(row, 1, label.ljust(max(0, box_w - 2)), max(0, box_w - 2), attr)
                except curses.error:
                    pass
            footer = " UP/DOWN SELECT | ENTER RENAME | ESC CANCEL "
            try:
                window.addnstr(box_h - 1, 1, footer, max(0, box_w - 2), self._attr("operator", bold=True))
            except curses.error:
                pass
            window.refresh()
            key = window.get_wch()
            if key in ("\x1b", "q", "Q"):
                return None
            if key in ("\n", "\r", curses.KEY_ENTER):
                return contracts[selected]
            if key in (curses.KEY_DOWN, "j"):
                selected = min(len(contracts) - 1, selected + 1)
            elif key in (curses.KEY_UP, "k"):
                selected = max(0, selected - 1)
            elif key == curses.KEY_NPAGE:
                selected = min(len(contracts) - 1, selected + visible)
            elif key == curses.KEY_PPAGE:
                selected = max(0, selected - visible)
            elif key in (curses.KEY_HOME, "g"):
                selected = 0
            elif key in (curses.KEY_END, "G"):
                selected = len(contracts) - 1

    def _rename_line_variable_v35(self, projection=None, line=None):
        projection = str(projection or self.model.projection)
        line = self.model.line if line is None else int(line)
        contracts = self._line_variable_contracts_v35(projection, line)
        if not contracts:
            self.model.status = "F4: no editable variables on this code line"
            return False
        contract = self._select_line_variable_v35(contracts)
        if contract is None:
            self.model.status = "F4 rename cancelled"
            return False
        sid = str(contract.get("canonical_ssa_name") or contract.get("sid") or "")
        shown = self.model.current_mode_variable_name(contract) or contract.get("pal_name") or sid
        value = self._prompt(
            "F4 sudo rename %s> " % shown,
            str(contract.get("operator_alias") or ""),
        )
        if value is None or not value.strip():
            return False
        try:
            saved = self.model.rename_variable_sid_v34(
                sid, value.strip(), author="operator-admin"
            )
        except Exception as exc:
            self.model.status = "F4 rename failed: %s" % exc
            return False
        self.model.status = "F4 renamed %s -> %s" % (shown, saved)
        return True

    @staticmethod
    def _metadata_lines_without_daily_banner_v12(lines):
        """Remove the duplicated report masthead from a detail sub-pane."""
        lines = [str(value) for value in list(lines or [])]
        if (
            len(lines) >= 2
            and lines[0].strip().upper() == "TRUTH DIGEST DAILY"
            and set(lines[1].strip()) <= {"="}
        ):
            lines = lines[2:]
            while lines and not lines[0].strip():
                lines.pop(0)
        return lines

    @classmethod
    def _detail_text_without_menu_artifacts_v13(cls, lines):
        """Strip menu/footer text frozen into detail-pane artifacts."""
        lines = cls._metadata_lines_without_daily_banner_v12(lines)
        while lines and not lines[-1].strip():
            lines.pop()
        menu_pattern = re.compile(
            r"(?:^|\|)\s*F1\b.*\bF2\b|"
            r"\bEsc\s+(?:close|closes|return)|"
            r"\barrows\s+scroll\b|"
            r"\bR\s+raw\b",
            re.IGNORECASE,
        )
        while lines and menu_pattern.search(lines[-1]):
            lines.pop()
            while lines and not lines[-1].strip():
                lines.pop()
        return lines

    @staticmethod
    def _search_spans_v20(text, query):
        """Return case-insensitive literal search spans for terminal painting."""
        query = str(query or "")
        if not query:
            return ()
        try:
            return tuple(
                (match.start(), match.end())
                for match in re.finditer(re.escape(query), str(text), re.IGNORECASE)
            )
        except re.error:
            return ()










    # Compatibility name retained for callers or local patches based on v18.

    def _move_code_search_v26(self, step=1, include_current=False):
        query = str(self.code_search_v26 or "").casefold()
        lines = list(self.model.lines() or ())
        matches = [
            index for index, value in enumerate(lines)
            if query and query in str(value).casefold()
        ]
        if not matches:
            self.model.status = (
                "no code matches for /%s" % self.code_search_v26
                if self.code_search_v26 else "enter / search text first"
            )
            return False
        current = int(self.model.line)
        if int(step) >= 0:
            candidates = [
                value for value in matches
                if (value >= current if include_current else value > current)
            ]
            target = candidates[0] if candidates else matches[0]
        else:
            candidates = [
                value for value in matches
                if (value <= current if include_current else value < current)
            ]
            target = candidates[-1] if candidates else matches[-1]
        self.model.line = int(target)
        self.model.column = min(
            int(self.model.column), len(str(lines[target]))
        )
        self.model.update_cursor_context()
        self.model.status = "code match %d/%d" % (
            matches.index(target) + 1, len(matches)
        )
        return True

    def _specops_console_v28(self):
        console = self._specops_ui_v28
        if console is None:
            console = PALSpecOpsHitUI(self)
            self._specops_ui_v28 = console
        return console

    def _editor_command_v26(self):
        value = self._prompt(": ", "")
        if value is None:
            return False
        command, separator, argument = value.strip().partition(" ")
        command = command.casefold()
        argument = argument.strip()
        try:
            if command in ("rename", "name"):
                if not argument:
                    raise ValueError("usage: rename NEW_NAME")
                self.model.rename_current_variable(argument)
            elif command in ("revert", "clearname"):
                self.model.revert_current_variable()
            elif command == "find":
                self.code_search_v26 = argument
                if argument:
                    self._move_code_search_v26(1, include_current=True)
                else:
                    self.model.status = "code search cleared"
            elif command in ("full", "clear"):
                self.code_search_v26 = ""
                self.model.status = "full unfiltered code view"
            elif command == "save":
                if callable(self.save_handler):
                    self.save_handler(self.model)
                else:
                    self.model.save()
            elif command == "export":
                if not argument:
                    raise ValueError("usage: export PATH")
                self.model.export(argument)
            elif command in ("menu", "workbench"):
                self._specops_console_v28().run()
            elif command in ("help", "?"):
                self.model.status = (
                    "commands: rename, revert, find, full, save, export, menu"
                )
            elif command:
                raise ValueError("unknown command %s" % command)
            return True
        except Exception as exc:
            self.model.status = "command failed: %s" % exc
            return True

    def draw(self):
        height, width = self._prepare_frame("single-v26")
        lines = self.model.lines()
        # v0.24a final closure: menu, key map, then live status/name line.
        # The lower edge is now a separator only; status never disappears below
        # a tall function listing.
        body_top = 6
        body_height = max(1, height - 7)
        self.model.clamp()
        if self.model.line < self.model.top_line:
            self.model.top_line = self.model.line
        if self.model.line >= self.model.top_line + body_height:
            self.model.top_line = self.model.line - body_height + 1
        self.model.top_line = min(
            max(0, int(self.model.top_line)),
            max(0, len(lines) - body_height),
        )

        separator = "=" * max(0, width - 1)
        self._safe_addstr(
            0, 0, separator, self._attr("helper", bold=True), width - 1
        )
        labels = (
            " DETAIL | ASM | C | OVERVIEW | STATIC DEBUG | PHI | CALLS | ABI | PROJECT METADATA "
        )
        self._safe_addstr(
            1, 0, labels.ljust(width), self._attr("helper", bold=True), width - 1
        )
        self._safe_addstr(
            2, 0, separator, self._attr("helper", bold=True), width - 1
        )
        command = (
            " M MENU | F1 PY VIEW | F2 PY NAMES | ^O OPER | F4 RENAME | TAB PY PANE | "
            "/ FIND | n/N HIT | F FULL | ENTER FOCUS | ^E EXEC->execute/functions | ^S SAVE | q BACK "
        )
        self._safe_addstr(
            3, 0, command.ljust(width),
            self._attr("status", bold=True), width - 1,
        )
        focus = self.model.object_focus_label() or self.model.highlight_name() or "-"
        message = (
            " %s | %s | labels=%s | %d:%d | find=/%s | focus=%s "
            % (
                self.model.warning or self.model.status or "PAL editor",
                self.model.projection.upper(), self.model.naming_label(),
                self.model.line + 1, self.model.column + 1,
                self.code_search_v26 or "-", focus,
            )
        )
        self._safe_addstr(
            4, 0, message.ljust(width),
            self._attr("operator", bold=True), width - 1,
        )
        self._safe_addstr(
            5, 0, separator, self._attr("helper", bold=True), width - 1
        )

        digits = max(4, len(str(max(1, len(lines)))))
        code_x = digits + 3
        code_width = max(1, width - code_x)
        for row in range(body_height):
            line_number = self.model.top_line + row
            y = body_top + row
            if line_number >= len(lines):
                self._safe_addstr(
                    y, 0, " " * max(0, width - 1),
                    self._attr("default"), max(0, width - 1)
                )
                continue
            selected = line_number == self.model.line
            number = " %*d " % (digits, line_number + 1)
            self._safe_addstr(
                y, 0, number, self._attr("operator", selected), code_x - 1
            )
            self._draw_code_line(
                y, line_number, lines[line_number], selected, code_x, code_width
            )

        footer_row = max(body_top, height - 1)
        self._safe_addstr(
            footer_row, 0, separator,
            self._attr("helper", bold=True), width - 1,
        )
        cursor_x = code_x + self.model.column - self.model.left_column
        cursor_y = body_top + self.model.line - self.model.top_line
        if 0 <= cursor_x < width and body_top <= cursor_y < footer_row:
            try:
                self.screen.move(cursor_y, cursor_x)
            except curses.error:
                pass
        self._present()

    def handle_key(self, key):
        lines = self.model.lines()
        height, width = self.screen.getmaxyx()
        page = max(1, height - 8)
        before = (
            self.model.projection, self.model.naming,
            bool(self.model.operator_overlay), int(self.model.line),
            int(self.model.column), int(self.model.top_line),
            int(self.model.left_column), str(self.code_search_v26),
        )
        explicit_redraw = False
        cursor_action = False

        if key in ("q", "Q"):
            self.exit_reason = "function_list"
            self.running = False
            return False
        if key == curses.KEY_F1:
            explicit_redraw = bool(self.model.switch_projection())
            cursor_action = explicit_redraw
        elif key == curses.KEY_F2:
            self.model.cycle_naming(); explicit_redraw = True; cursor_action = True
        elif key == "\x0f":
            self.model.toggle_operator_overlay(); explicit_redraw = True; cursor_action = True
        elif key == curses.KEY_F4:
            self._rename_line_variable_v35(
                projection=self.model.projection, line=self.model.line
            )
            explicit_redraw = True
        elif key in ("\t", KEY_CTRL_TAB, getattr(curses, "KEY_BTAB", -99999)):
            explicit_redraw = bool(self.model.switch_projection())
            cursor_action = explicit_redraw
        elif key in ("m", "M"):
            self._specops_console_v28().run()
            self._last_layout = None
            explicit_redraw = True
        elif key == "/":
            value = self._prompt("/ find in code: ", self.code_search_v26)
            if value is not None:
                self.code_search_v26 = value.strip()
                if self.code_search_v26:
                    self._move_code_search_v26(1, include_current=True)
                else:
                    self.model.status = "code search cleared"
            explicit_redraw = True
        elif key == "n":
            explicit_redraw = self._move_code_search_v26(1)
        elif key == "N":
            explicit_redraw = self._move_code_search_v26(-1)
        elif key == "F":
            self.code_search_v26 = ""
            self.model.status = "full unfiltered code view"
            explicit_redraw = True
        elif key in ("\n", "\r", curses.KEY_ENTER):
            self.model.update_cursor_context()
            self.model.toggle_object_focus()
            explicit_redraw = True
        elif key == ".":
            explicit_redraw = self.model.move_hotspot(1) is not None
        elif key == ",":
            explicit_redraw = self.model.move_hotspot(-1) is not None
        elif key == "\x05":
            try:
                self.model.export_execute_function_v41()
            except Exception as exc:
                self.model.status = "Ctrl-E PY.EXEC failed: %s" % exc
            explicit_redraw = True
        elif key == "\x13":
            try:
                if callable(self.save_handler):
                    self.save_handler(self.model)
                else:
                    self.model.save()
            except Exception as exc:
                self.model.status = "save failed: %s" % exc
            explicit_redraw = True
        elif key in (curses.KEY_DOWN, "j"):
            self.model.line = min(max(0, len(lines) - 1), self.model.line + 1)
            cursor_action = True
        elif key in (curses.KEY_UP, "k"):
            self.model.line = max(0, self.model.line - 1)
            cursor_action = True
        elif key == curses.KEY_NPAGE:
            self.model.line = min(max(0, len(lines) - 1), self.model.line + page)
            cursor_action = True
        elif key == curses.KEY_PPAGE:
            self.model.line = max(0, self.model.line - page)
            cursor_action = True
        elif key == curses.KEY_LEFT:
            self.model.column = max(0, self.model.column - 1); cursor_action = True
        elif key == curses.KEY_RIGHT:
            self.model.column = min(len(self.model.current_line_text()), self.model.column + 1)
            cursor_action = True
        elif key == curses.KEY_HOME:
            self.model.column = 0; cursor_action = True
        elif key == curses.KEY_END:
            self.model.column = len(self.model.current_line_text()); cursor_action = True
        elif key == curses.KEY_RESIZE:
            self._last_layout = None; explicit_redraw = True
        else:
            return False

        self.model.clamp()
        after_cursor = (
            self.model.projection, self.model.naming,
            bool(self.model.operator_overlay), int(self.model.line),
            int(self.model.column),
        )
        if cursor_action and after_cursor != before[:5]:
            self.model.update_cursor_context()
        code_width = max(1, width - 10)
        if self.model.column < self.model.left_column:
            self.model.left_column = self.model.column
        elif self.model.column >= self.model.left_column + code_width:
            self.model.left_column = self.model.column - code_width + 1
        after = (
            self.model.projection, self.model.naming,
            bool(self.model.operator_overlay), int(self.model.line),
            int(self.model.column), int(self.model.top_line),
            int(self.model.left_column), str(self.code_search_v26),
        )
        return bool(explicit_redraw or after != before)

    def run(self):
        while self.running:
            if self._dirty:
                self.draw()
                self._dirty = False
            changed = self.handle_key(self.screen.get_wch())
            if changed:
                self._dirty = True
        return self.exit_reason


class PALSpecOpsHitUI:
    """Graphic PAL evidence menu and linked workbench.

    Function keys are not used for menu navigation.  F1, F2 and Ctrl-O retain
    their sole meaning as Python display controls.  Top-level views are selected
    with [ / ] (or Tab in a one-pane view); Tab always switches the currently
    visible pane when a view contains multiple panes.
    """

    VIEWS = (
        "detail", "asm", "c_code", "four", "three",
        "phi", "calls", "abi", "project",
    )
    LABELS = {
        "detail": "DETAIL",
        "asm": "ASM",
        "c_code": "C",
        "four": "OVERVIEW",
        "three": "STATIC DEBUG",
        "phi": "PHI",
        "calls": "CALLS",
        "abi": "ABI",
        "project": "PROJECT METADATA",
    }
    DESCRIPTIONS = {
        "detail": "Variable name matrix with PHI Detail and STATIC DEBUG destinations.",
        "asm": "Full frozen assembly evidence.",
        "c_code": "Frozen Ghidra C source evidence.",
        "four": "Linked ASM / READ.PY / C / EXEC.PY matrix.",
        "three": "Strict PHI / ASM / Python block cross-section.",
        "phi": "Materialized-variable drop-in blades.",
        "calls": "Module call relationships.",
        "abi": "ABI custody interfaces and carriers.",
        "project": "Unified project metadata digest.",
    }

    def __init__(self, owner):
        self.owner = owner
        self.screen = owner.screen
        self.model = owner.model
        try:
            readable_available = self.model.document.projection("readable") is not None
        except Exception:
            readable_available = False
        self._initial_model_state = {
            "projection": "readable" if readable_available else self.model.projection,
            "line": int(getattr(self.model, "line", 0) or 0),
            "column": int(getattr(self.model, "column", 0) or 0),
            "top_line": int(getattr(self.model, "top_line", 0) or 0),
            "left_column": int(getattr(self.model, "left_column", 0) or 0),
        }
        self.view_index = 0
        # The graphic menu is a real parent node.  M/Esc returns from a view to
        # this menu before returning to the root editor.
        self.menu_mode = True
        self.states = {
            name: {"line": 0, "top": 0, "left": 0, "focus": None}
            for name in self.VIEWS
        }
        self.searches = {name: "" for name in self.VIEWS}
        self.highlight_modes = {}
        self.full_snapshots = {}
        self._asm_jump_focus = None
        self._asm_branch_focus_v35 = None
        self._four_asm_focus_v34 = None
        self._four_asm_rows_v34 = None
        self._four_asm_branch_rows_v35 = None
        self._asm_history_v34 = []
        self._asm_history_index_v34 = -1
        # v0.35a: PHI history is a separate visual-frame ledger.  Angle
        # brackets dispatch by the active STATIC DEBUG pane; PHI never mutates
        # or replays the ASM jump ledger, and ASM never replays PHI frames.
        self._phi_history_v46 = []
        self._phi_history_index_v46 = -1
        self._asm_branch_focus_v35 = None
        self._four_asm_branch_rows_v35 = None
        self._large_loader_seen_v35 = set()
        self.status = "PAL evidence workbench online"
        self._digest = None
        self._one_cache = {}
        self._project_cache = None
        self._four_ready = False
        self._code_view_initialized = {"four": False, "three": False}
        self._four_active = 1
        self._four_focus = {name: None for name in self.owner.side_panes}
        self._three = None
        self._phi_menu_selected_sid = None
        self._phi_full_listing_v35 = False
        self._phi_menu_rows_cache_v29 = []
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    @property
    def view(self):
        return self.VIEWS[self.view_index % len(self.VIEWS)]

    def _attr(self, role, selected=False, bold=False):
        return self.owner._attr(role, selected=selected, bold=bold)

    def _add(self, y, x, text, attr=0, width=None):
        self.owner._safe_addstr(y, x, text, attr, width)

    def _present(self):
        self.owner._present()

    def _separator(self, row, width):
        self._add(
            row, 0, "=" * max(0, width - 1),
            self._attr("helper", bold=True), max(0, width - 1),
        )

    def _draw_menu(self, row, width):
        x = 1
        for index, name in enumerate(self.VIEWS):
            label = " %s " % self.LABELS[name]
            if x + len(label) >= width:
                break
            role = "active_header" if index == self.view_index else "helper"
            self._add(row, x, label, self._attr(role, bold=True), len(label))
            x += len(label) + 1

    def _active_subpane_label(self):
        if self.view == "four":
            return self.owner.side_titles[
                self.owner.side_panes[self._four_active]
            ]
        if self.view == "three" and self._three is not None:
            return self._three["panes"][self._three["active"]].upper()
        return self.LABELS[self.view]

    def _active_search_key(self):
        if self.view == "four":
            pane = self.owner.side_panes[self._four_active]
            return "four:%s" % pane
        if self.view == "three":
            pane = (
                self._three["panes"][self._three["active"]]
                if self._three is not None else "phi"
            )
            return "three:%s" % pane
        return self.view

    def _search(self):
        return self.searches.get(self._active_search_key(), "")

    def _set_search(self, value):
        key = self._active_search_key()
        value = str(value or "").strip()
        # SECAM: FULL is a persistent browsing surface.  Search may operate on
        # the complete listing, but only F may restore the focused snapshot.
        self.searches[key] = value
        self.highlight_modes[key] = bool(value)

    def _highlight_mode(self):
        return bool(self.highlight_modes.get(self._active_search_key(), False))

    def _paint_query_v39(self, key=None):
        """Return search text only while visual highlighting is enabled.

        Search ownership survives H=OFF so n/N can continue traversing hits,
        but no pane may paint stale highlight spans after the toggle is cleared.
        """
        key = str(key or self._active_search_key())
        if not bool(self.highlight_modes.get(key, False)):
            return ""
        return str(self.searches.get(key, "") or "")

    def _toggle_highlight_mode(self):
        key = self._active_search_key()
        pane = self._active_subpane_label()
        query = str(self.searches.get(key, "") or "")
        if not query:
            self.highlight_modes[key] = False
            self.status = "%s highlight lock requires an active / search" % pane
            return False
        self.highlight_modes[key] = not bool(self.highlight_modes.get(key, False))
        self.status = (
            "%s highlight lock ON; movement follows /%s" % (pane, query)
            if self.highlight_modes[key]
            else "%s highlight lock OFF; cursor movement unrestricted" % pane
        )
        return self.highlight_modes[key]

    def _force_readable_projection(self):
        try:
            available = self.model.document.projection("readable") is not None
        except Exception:
            available = False
        if available and self.model.projection != "readable":
            self.model.projection = "readable"
            self.model.clamp()
        return self.model.projection

    def _draw_chrome(self):
        height, width = self.screen.getmaxyx()
        self.screen.erase()
        self._separator(0, width)
        self._draw_menu(1, width)
        self._separator(2, width)
        if self.menu_mode:
            command = (
                " UP/DOWN SELECT | ENTER OPEN | F1 PY VIEW | F2 PY NAMES | "
                "^O OPER | M/Esc ROOT "
            )
        else:
            command = (
                " TAB PANE | F1 PY VIEW | F2 PY NAMES | ^O OPER | F4 RENAME | "
                "/ FIND | H HILITE/MOVE | C CLEAR SEARCH | 0 CLEAR HIST | "
                "F FULL/RESTORE | ENTER FOCUS | ^E EXEC->execute/functions | "
                "< EARLIER | > FORWARD | M/Esc MENU "
            )
        self._add(
            3, 0, command.ljust(width),
            self._attr("status", bold=True), max(0, width - 1),
        )

        naming = _display_naming_label(self.model.naming).upper()
        projection = "READ" if self.model.projection == "readable" else "EXEC"
        key = self._active_search_key()
        if self.menu_mode:
            status_line = (
                " menu=%s | PY=%s | NAMES=%s | OPER=%s | FIND=/%s | "
                "H=%s | FULL=%s | PHI-HIST=%s | ASM-HIST=%s | %s "
            ) % (
                self.LABELS[self.view], projection, naming,
                "ON" if self.model.operator_overlay else "OFF",
                self.searches.get(key, "") or "-",
                "ON" if self.highlight_modes.get(key, False) else "OFF",
                "ON" if key in self.full_snapshots else "OFF",
                self._phi_history_label_v46(), self._asm_history_label_v34(),
                self.status,
            )
        else:
            status_line = (
                " active=%s | PY=%s | NAMES=%s | OPER=%s | FIND=/%s | "
                "H=%s | FULL=%s | PHI-HIST=%s | ASM-HIST=%s | %s "
            ) % (
                self._active_subpane_label(), projection, naming,
                "ON" if self.model.operator_overlay else "OFF",
                self._search() or "-",
                "ON" if self._highlight_mode() else "OFF",
                "ON" if key in self.full_snapshots else "OFF",
                self._phi_history_label_v46(), self._asm_history_label_v34(),
                self.status,
            )
        self._add(
            4, 0, status_line.ljust(width),
            self._attr("operator", bold=True), max(0, width - 1),
        )
        self._separator(5, width)
        self._separator(max(6, height - 1), width)
        return 6, max(1, height - 7), width

    def _draw_menu_view(self, body_top, body_height, width):
        rows = []
        for index, name in enumerate(self.VIEWS):
            marker = ">" if index == self.view_index else " "
            rows.append(
                "%s %-18s  %s" % (
                    marker, self.LABELS[name], self.DESCRIPTIONS.get(name, ""),
                )
            )
        start = body_top + max(0, (body_height - len(rows) - 4) // 2)
        title = "PAL // MENU VIEW"
        self._add(
            start, 2, title, self._attr("active_header", bold=True),
            max(0, width - 4),
        )
        self._add(
            start + 1, 2, "-" * min(max(0, width - 4), len(title) + 28),
            self._attr("helper", bold=True), max(0, width - 4),
        )
        for offset, text in enumerate(rows, start + 3):
            selected = (offset - (start + 3)) == self.view_index
            role = "active_header" if selected else "default"
            self._add(
                offset, 2, text.ljust(max(1, width - 4)),
                self._attr(role, bold=selected), max(1, width - 4),
            )

    @staticmethod
    def _search_spans(text, query):
        query = str(query or "")
        if not query:
            return ()
        return tuple(
            (match.start(), match.end())
            for match in re.finditer(re.escape(query), str(text), re.IGNORECASE)
        )

    @staticmethod
    def _row_text(row):
        return str(dict(row or {}).get("text") or "")

    @staticmethod
    def _asm_branch_paint_role_v24(row):
        """Return the universal branch/fork palette role for one ASM row."""
        role = str(dict(row or {}).get("branch_display_role") or "")
        return {
            "focus": "asm_focus_block",
            "join": "asm_join_block",
            "fork": "asm_fork_block",
        }.get(role)

    def _asm_branch_role_map_v25(self, rows=None):
        """Return canonical block -> branch palette role for one ASM listing.

        The map is derived from frozen ASM row evidence rather than from screen
        position.  This lets PHI and Python panes paint the same red/yellow/green
        branch topology while the ASM cursor walks through the listing.
        """
        roles = {}
        priority = {"fork": 1, "join": 2, "focus": 3}
        for raw in list(rows or ()):
            row = dict(raw or {})
            role = str(row.get("branch_display_role") or "")
            if role not in priority:
                continue
            address = self.model._canonical_block_addr_v21(
                row.get("addr") or row.get("address")
            )
            if address is None:
                continue
            prior = roles.get(address)
            if prior is None or priority[role] >= priority.get(prior, 0):
                roles[address] = role
        return roles

    def _asm_cursor_block_v25(self, rows, state):
        """Resolve the machine block currently under the ASM selection cursor."""
        rows = list(rows or ())
        if not rows:
            return None
        index = min(max(0, int(dict(state or {}).get("line", 0))), len(rows) - 1)
        for cursor in range(index, -1, -1):
            row = dict(rows[cursor] or {})
            address = self.model._canonical_block_addr_v21(
                row.get("addr") or row.get("address")
            )
            if address is not None:
                return address
        return None

    def _three_phi_branch_role_v25(self, row):
        """Resolve PHI color without granting hover authority to every chain.

        mars v0.25 projected the ASM hover block onto every PHI summary whose
        incoming/merge evidence mentioned that block.  When several possible
        PHI chains intersected one ASM block, the complete list became dark red
        and no longer communicated which result-variable chain was selected.

        v0.30 separates two authorities:

        * exactly one selected ``phi_summary`` owns the dark-red chain marker;
        * inside its custody blade, only the exact address-bearing transition
          whose machine block equals the ASM hover root owns dark red.

        Other implicated PHI chains retain ordinary join/fork role colors and
        never borrow the active hover overlay merely because they share a CFG
        block with the selected chain.
        """
        three = self._three or {}
        role_map = dict(three.get("branch_role_by_block_v25", {}) or {})
        row = dict(row or {})
        candidates = []
        for key in (
            "address", "addr", "incoming_addr", "merge_addr",
            "block_addr", "predecessor_addr",
        ):
            canonical = self.model._canonical_block_addr_v21(row.get(key))
            if canonical is not None and canonical not in candidates:
                candidates.append(canonical)

        hover = self.model._canonical_block_addr_v21(
            three.get("asm_hover_block_v25")
        )
        selected_sid = str(three.get("selected_phi_sid") or "")
        row_sid = str(
            row.get("output_sid") or row.get("sid")
            or row.get("canonical_final_sid") or ""
        )
        active_chain = bool(selected_sid and row_sid == selected_sid)
        priority = {"focus": 3, "join": 2, "fork": 1}
        matches = [role_map[value] for value in candidates if value in role_map]
        ordinary_role = (
            max(matches, key=lambda value: priority.get(value, 0))
            if matches else None
        )

        # Legacy metadata rows without PHI identity cannot participate in the
        # single-chain authority rule.  Preserve their historical exact-block
        # hover behavior rather than silently losing linkage.
        if not row_sid and hover in candidates and hover in role_map:
            return role_map[hover], True

        # One active list item: the selected result-variable chain.
        if row.get("kind") == "phi_summary" and active_chain:
            return (
                role_map.get(hover) or ordinary_role or "focus",
                True,
            )

        # One active transition: exact address + selected chain + ASM root.
        address = self.model._canonical_block_addr_v21(
            row.get("address") or row.get("addr")
        )
        if (
            active_chain and bool(row.get("block_hotspot"))
            and hover is not None and address == hover
        ):
            return role_map.get(hover) or ordinary_role or "focus", True

        return ordinary_role, False

    def _branch_palette_attr_v25(self, role, hovered=False):
        paint_role = {
            "focus": "asm_focus_block",
            "join": "asm_join_block",
            "fork": "asm_fork_block",
        }.get(str(role or ""))
        if not paint_role:
            return None
        if hovered:
            return self._link_hover_attr_v26()
        return self._attr(paint_role, bold=True)

    def _link_hover_attr_v26(self):
        """Medium-yellow text on dark red for the shared linkage root.

        v0.26 synthesized the dark-red surface with ``A_REVERSE``.  That made
        the resulting foreground terminal-dependent and commonly black.  mars
        v0.27 owns the pair explicitly: medium yellow foreground, dark-red
        background.  ASM jump mnemonics are repainted bright red afterward.
        """
        return self._attr("link_hover_reverse", bold=True)

    def _asm_row_block_v26(self, row):
        row = dict(row or {})
        return self.model._canonical_block_addr_v21(
            row.get("addr") or row.get("address")
        )

    @staticmethod
    def _asm_mnemonic_span_v26(text):
        match = re.match(
            r"^\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})\s+"
            r"([A-Za-z][A-Za-z0-9_.]*)\b",
            str(text or ""),
        )
        return (match.start(1), match.end(1)) if match else None

    def _asm_jump_attr_v26(self, row, hovered=False):
        if hovered:
            return self._attr("asm_jump_on_hover", bold=True)
        role = str(dict(row or {}).get("branch_display_role") or "")
        return self._attr({
            "focus": "asm_jump_on_focus",
            "join": "asm_jump_on_join",
            "fork": "asm_jump_on_fork",
        }.get(role, "asm_jump_red"), bold=True)

    def _paint_asm_jump_mnemonic_v26(
        self, y, text_x, text, left, text_width, row, hovered=False
    ):
        if dict(row or {}).get("asm_role") != "jump":
            return
        span = self._asm_mnemonic_span_v26(text)
        if span is None:
            return
        start, end = span
        a = max(start, left); b = min(end, left + text_width)
        if a < b:
            self._add(
                y, text_x + a - left, str(text)[a:b],
                self._asm_jump_attr_v26(row, hovered=hovered), b - a,
            )

    def _phi_template_rows(self, path_rows=None, pointer_hotspots=False):
        """Return canonical singular PHI records for all or selected nodes."""
        entries = list(self.model.phi_custody_inventory_v14() or ())
        if not entries:
            return [{"kind": "empty", "text": "No frozen PHI nodes."}]

        selected = []
        path_by_sid = {}
        if path_rows is None:
            selected = list(range(len(entries)))
        else:
            for path in list(path_rows or ()):
                path = dict(path or {})
                sid = str(path.get("output_sid") or "")
                index = self.model.phi_custody_index_for_sid_v16(sid)
                if index is None or index in selected:
                    continue
                selected.append(index)
                path_by_sid[sid] = path

        rows = []
        for position, index in enumerate(selected):
            entry = dict(entries[index] or {})
            sid = str(entry.get("output_sid") or "")
            path = dict(path_by_sid.get(sid, {}) or {})
            if position:
                rows.append({
                    "kind": "blank", "text": "", "phi_template": True,
                    "node_index": index, "output_sid": sid, "sid": sid,
                })
            for item in self.model.phi_custody_blade_v14(index):
                row = dict(item or {})
                row["phi_template"] = True
                row.setdefault("node_index", index)
                row.setdefault("output_sid", sid)
                row.setdefault("sid", sid)
                row.setdefault("pal_name", self.model.phi_display_name_v30(sid))
                row.setdefault(
                    "root_expression",
                    self.model.phi_display_expression_v30(entry.get("roots", ()) or (sid,)),
                )
                row.setdefault("incoming_addr", path.get("incoming_addr"))
                row.setdefault("merge_addr", path.get("merge_addr"))
                row["node_anchor"] = row.get("kind") == "header"
                if pointer_hotspots and row.get("block_hotspot") and row.get("address"):
                    address = str(row["address"])
                    old = str(row.get("text") or "")
                    offset = int(row.get("address_offset", old.find(address)))
                    if 0 <= offset and old[offset:offset + len(address)] == address:
                        wrapped = "<%s>" % address
                        row["text"] = old[:offset] + wrapped + old[offset + len(address):]
                        row["address_offset"] = offset + 1
                        row["pointer_display"] = wrapped
                rows.append(row)
        return rows or [{"kind": "empty", "text": "No frozen PHI nodes."}]

    def _phi_dependency_rows(self, output_sid, pointer_hotspots=False):
        index = self.model.phi_custody_index_for_sid_v16(output_sid)
        if index is None:
            return [{"kind": "empty", "text": "No PHI custody for %s." % output_sid}]
        bundle = self.model.phi_custody_blade_bundle_v16(index)
        rows = []
        for item in list(bundle.get("items", ()) or ()):
            row = dict(item or {})
            row["phi_template"] = True
            if pointer_hotspots and row.get("block_hotspot") and row.get("address"):
                address = str(row["address"])
                old = str(row.get("text") or "")
                offset = int(row.get("address_offset", old.find(address)))
                if 0 <= offset and old[offset:offset + len(address)] == address:
                    wrapped = "<%s>" % address
                    row["text"] = old[:offset] + wrapped + old[offset + len(address):]
                    row["address_offset"] = offset + 1
                    row["pointer_display"] = wrapped
            rows.append(row)
        return rows or [{"kind": "empty", "text": "No dependent PHI nodes."}]

    def _digest_lines(self, panel):
        if self._digest is None:
            self._digest = self.model.truth_digest()
        try:
            self._digest.select(panel)
            self._digest.raw = False
            values = self._digest.lines()
        except Exception as exc:
            values = [
                "%s detail unavailable" % panel,
                "%s: %s" % (type(exc).__name__, exc),
            ]
        return self.owner._detail_text_without_menu_artifacts_v13(values)

    def _phi_menu_rows_v31(self):
        """Mirror STATIC DEBUG PHI while preserving its semantic cursor."""
        state = self.states.get("phi")
        old_rows = list(self._phi_menu_rows_cache_v29 or ())
        snapshot = (
            dict(state.get("_phi_cursor_v29") or {})
            if state is not None and state.get("_phi_cursor_v29")
            else self._phi_cursor_snapshot_v29(old_rows, state or {})
        )
        entries = [
            dict(entry or {}) for entry in list(self.model.phi_custody_inventory_v14() or ())
            if dict(entry or {}).get("has_phi")
        ]
        if not entries:
            return [{"kind": "empty", "text": "No frozen PHI nodes."}]
        valid = {str(entry.get("output_sid") or "") for entry in entries}
        selected = str(self._phi_menu_selected_sid or "")
        if selected not in valid:
            selected = str(entries[0].get("output_sid") or "")
        self._phi_menu_selected_sid = selected
        paths = list(self.model.phi_path_focus_rows_v21() or ())
        path_by_sid = {}
        for path_row in paths:
            sid = str(dict(path_row or {}).get("output_sid") or "")
            if sid and sid not in path_by_sid:
                path_by_sid[sid] = dict(path_row or {})
        rows = [{"kind": "phi_section", "text": "PHI node list"}]
        for entry in entries:
            sid = str(entry.get("output_sid") or "")
            display_name = self.model.phi_display_name_v30(sid)
            roots = self.model.phi_display_expression_v30(entry.get("roots", ()) or (sid,))
            path_row = path_by_sid.get(sid, {})
            node_number = int(entry.get("node_number") or (len(rows)))
            rows.append({
                "kind": "phi_summary", "phi_list": True,
                "text": "#%d %s <= [%s]" % (node_number, display_name, roots),
                "node_number": node_number,
                "output_sid": sid, "sid": sid, "pal_name": display_name,
                "incoming_addr": path_row.get("incoming_addr"),
                "merge_addr": path_row.get("merge_addr"),
            })
        rows.extend((
            {"kind": "blank", "text": ""},
            {"kind": "phi_section", "text": "Selected PHI custody"},
        ))
        rows.extend(self._phi_dependency_rows(selected, pointer_hotspots=True))
        if state is not None:
            self._phi_restore_cursor_v29(
                rows, state, snapshot=snapshot, preferred_sid=selected
            )
        self._phi_menu_rows_cache_v29 = [dict(row or {}) for row in rows]
        return rows

    def _open_three_from_phi_v31(self, sid, address=None):
        """Open the linked STATIC DEBUG view carrying PHI node/address focus."""
        self._maybe_show_large_loader_v35("STATIC DEBUG")
        sid = str(sid or "")
        address = self.model._canonical_block_addr_v21(address)
        paths = [
            dict(row) for row in list(self.model.phi_path_focus_rows_v21() or ())
            if str(dict(row or {}).get("output_sid") or "") == sid
        ]
        path = next((
            row for row in paths
            if address and address in (
                self.model._canonical_block_addr_v21(row.get("incoming_addr")),
                self.model._canonical_block_addr_v21(row.get("merge_addr")),
            )
        ), paths[0] if paths else {})
        base_focus = self.model._canonical_block_addr_v21(path.get("incoming_addr"))
        if base_focus is None:
            base_focus = address
        self.view_index = self.VIEWS.index("three")
        self._three = None
        self._code_view_initialized["three"] = False
        self._three_prepare()
        if base_focus:
            self._three_set_focus(base_focus, "phi", initialize=True)
        self._three["selected_phi_sid"] = sid
        self._three_rebuild_phi_rows(preferred_sid=sid)
        if address:
            pointer_row = next((
                dict(row) for row in self._three.get("phi_rows", ())
                if row.get("block_hotspot")
                and self.model._canonical_block_addr_v21(row.get("address")) == address
                and (not sid or str(row.get("output_sid") or row.get("sid") or "") == sid)
            ), {
                "address": address, "output_sid": sid, "sid": sid,
                "incoming_addr": path.get("incoming_addr"),
                "merge_addr": path.get("merge_addr"),
            })
            self._three_toggle_pointer_focus(pointer_row)
            self._three["active"] = self._three["panes"].index("asm")
            self.status = "opened linked ASM focus %s; history retained at %s" % (
                address, self._asm_history_label_v34()
            )
        else:
            self._three["active"] = self._three["panes"].index("phi")
            self.status = "opened linked PHI node %s" % sid
        self.menu_mode = False

    def _project_digest_lines(self):
        if self._project_cache is not None:
            return self._project_cache
        project_store = getattr(self.model, "project_store", None)
        root = (
            os.path.dirname(os.path.abspath(project_store.path))
            if project_store is not None and getattr(project_store, "path", None)
            else os.path.dirname(os.path.abspath(self.model.source_path or os.getcwd()))
        )
        manifest_path = os.path.join(root, PROJECT_MANIFEST)
        payload = _read_json_file(manifest_path, {}) or {}
        program = dict(payload.get("program", {}) or {})
        functions = list(payload.get("functions", []) or [])
        counts = dict(payload.get("counts", {}) or {})
        decompiled = counts.get("decompiled")
        if not isinstance(decompiled, int):
            decompiled = sum(
                dict(record or {}).get("status") == "decompiled"
                for record in functions
            )
        record = {
            "project_name": os.path.basename(root),
            "project_path": root,
            "manifest_path": manifest_path,
            "program_name": program.get("name") or os.path.basename(root),
            "status": payload.get("status") or "unknown",
            "functions": len(functions),
            "decompiled": int(decompiled or 0),
            "artifacts": {
                "manifest": os.path.isfile(manifest_path),
                "jump_table": os.path.isfile(os.path.join(root, PROJECT_JUMP_TABLE)),
                "dispatch": os.path.isfile(os.path.join(root, PROJECT_DISPATCH)),
                "functions": os.path.isdir(os.path.join(root, PROJECT_FUNCTIONS_DIRECTORY)),
                "oncs": os.path.isfile(os.path.join(root, PROJECT_NAME_REGISTRY)),
            },
        }
        lines = [
            "PAL PROJECT METADATA DIGEST",
            "===========================",
            "root: %s" % root,
            "",
        ]
        try:
            views = _viewer_project_views(record)
        except Exception as exc:
            views = ({
                "title": "PROJECT",
                "curated_lines": (
                    "metadata digest failed: %s: %s"
                    % (type(exc).__name__, exc),
                ),
            },)
        for view in views:
            title = str(view.get("title") or view.get("key") or "SECTION")
            lines.extend((title, "-" * min(72, max(8, len(title)))))
            lines.extend(
                str(value) for value in list(view.get("curated_lines", ()) or ())
            )
            lines.append("")
        self._project_cache = tuple(lines)
        return self._project_cache

    @staticmethod
    def _detail_matrix_text_v32(row):
        row = dict(row or {})
        if row.get("kind") == "var_header":
            return "| PHI DETAIL | STATIC DEBUG | SSA                | PAL                | HUMANIZED          | OPER               |"
        if row.get("kind") == "var_rule":
            return "+------------+--------+--------------------+--------------------+--------------------+--------------------+"
        return (
            "|    <*>     |  <*>   | %-18s | %-18s | %-18s | %-18s |"
            % (
                str(row.get("ssa") or "-")[:18],
                str(row.get("pal") or "-")[:18],
                str(row.get("humanizer") or "-")[:18],
                str(row.get("operator") or "-")[:18],
            )
        )

    def _detail_variable_rows_v32(self):
        """One row per ONCS variable; no locked/exclusion appendix."""
        rows = [
            {"kind": "var_header"},
            {"kind": "var_rule"},
        ]
        for item in list(self.model.oncs_digest_rows() or ()):
            sid = str(item.get("ssa") or "")
            rows.append({
                "kind": "var_row", "sid": sid,
                "ssa": sid or "-",
                "pal": item.get("pal") or "-",
                "humanizer": item.get("humanizer") or "-",
                "operator": item.get("operator") or "-",
            })
        for row in rows:
            row["text"] = self._detail_matrix_text_v32(row)
            if row.get("kind") == "var_row":
                text_value = row["text"]
                first = text_value.find("<*>")
                second = text_value.find("<*>", first + 3)
                row["action_spans"] = ((first, first + 3), (second, second + 3))
                # Fixed-format name-cell spans used for color decoration.
                bars = [index for index, char in enumerate(text_value) if char == "|"]
                row["name_spans"] = tuple(
                    (bars[index] + 2, bars[index + 1] - 1)
                    for index in range(2, 6)
                )
        state = self.states.get("detail")
        first_var = next((i for i, row in enumerate(rows) if row.get("kind") == "var_row"), 0)
        if state is not None:
            state.setdefault("action", 0)
            if not (
                0 <= int(state.get("line", 0)) < len(rows)
                and rows[int(state.get("line", 0))].get("kind") == "var_row"
            ):
                state["line"] = first_var
                state["top"] = max(0, first_var - 2)
        return rows

    @staticmethod
    def _materialized_activity_sort_v51(item):
        item = dict(item or {})
        blocks = int(item.get("block_count", 0) or 0)
        writes = int(item.get("occurrence_count", 0) or 0)
        name = str(item.get("pal_name") or item.get("output_sid") or "")
        # Most structurally active first: requested block/write sum, then writes,
        # then blocks, then stable human name.
        return (-(blocks + writes), -writes, -blocks, name.casefold())

    def _phi_materialized_full_blades_v51(self, inventory=None):
        """Unfold every materialized Φ into its complete drop-in blade."""
        if inventory is None:
            inventory = list(self.model.materialized_variable_inventory_v48(
                projection=self.model.projection, full_scope=True
            ) or ())
        inventory = sorted(
            (dict(item or {}) for item in list(inventory or ())),
            key=self._materialized_activity_sort_v51,
        )
        rows = [{
            "kind": "phi_section",
            "text": "ALL MATERIALIZED Φ | %d variable%s" % (
                len(inventory), "" if len(inventory) == 1 else "s"
            ),
        }]
        for rank, item in enumerate(inventory, 1):
            sid = str(item.get("output_sid") or "")
            display_name = str(item.get("pal_name") or sid)
            block_count = int(item.get("block_count", 0) or 0)
            write_count = int(item.get("occurrence_count", 0) or 0)
            first_block = next((
                dict(block or {}).get("block")
                for block in list(item.get("blocks", ()) or ())
                if dict(block or {}).get("block")
            ), None)
            if len(rows) > 1:
                rows.append({"kind": "blank", "text": ""})
            rows.append({
                "kind": "phi_summary",
                "text": "Φ-%d %s | %d block%s | %d write%s" % (
                    rank, display_name,
                    block_count, "" if block_count == 1 else "s",
                    write_count, "" if write_count == 1 else "s",
                ),
                "output_sid": sid,
                "sid": sid,
                "pal_name": display_name,
                "incoming_addr": first_block,
                "merge_addr": first_block,
                "node_index": rank - 1,
                "node_number": rank,
                "phi_list": False,
                "phi_full_blade_v51": True,
                "materialized_v48": True,
                "materialization_kind": item.get("materialization_kind"),
                "materialization_blocks_v48": tuple(
                    dict(block or {}) for block in list(item.get("blocks", ()) or ())
                ),
            })
            detail = self._phi_materialization_detail_rows_v48(sid, item)
            rows.extend(detail or ({
                "kind": "phi_truth_note",
                "output_sid": sid,
                "text": "          no materialization blocks are published",
            },))
        if not inventory:
            rows.append({
                "kind": "empty",
                "text": "No materialized variables are published in this projection.",
            })
        return rows


    def _one_rows(self, name):
        if name == "phi":
            if self._phi_full_listing_v35:
                return self._phi_materialized_full_blades_v51()
            return self._phi_menu_rows_v31()
        if name == "asm":
            if self._asm_branch_focus_v35:
                data = dict(self._asm_branch_focus_v35 or {})
                return list(self.model.asm_branch_forks_rows_v35(
                    data.get("source"), data.get("target")
                ))
            if self._asm_jump_focus:
                return list(self.model.asm_debug_focus_rows_v34(
                    self._asm_jump_focus, relation="DIRECT JUMP TARGET"
                ))
            values = self.model.asm_detail_lines_v17(full_scope=True, filter_text=None)
            rows = []
            current_block = None
            for value in values:
                text = str(value)
                if text.startswith("BLOCK "):
                    current_block = self.model._canonical_block_addr_v21(
                        text.split(None, 1)[1]
                    )
                    rows.append({"kind": "block", "addr": current_block, "text": text})
                elif set(text.strip()) <= {"-"} and text.strip():
                    rows.append({"kind": "rule", "text": text})
                else:
                    rows.append(self.model.asm_instruction_row_v33(current_block, text))
            return rows or [{"kind": "empty", "text": "No data is available."}]
        if name in self._one_cache:
            return self._one_cache[name]
        if name == "detail":
            rows = self._detail_variable_rows_v32()
        elif name == "c_code":
            try:
                values = self.model.truth_source_lines("c_code")
            except Exception as exc:
                values = ["C unavailable: %s: %s" % (type(exc).__name__, exc)]
            rows = [{"kind": "c", "text": str(value)} for value in values]
        elif name == "calls":
            rows = [{"kind": "text", "text": str(value)} for value in self._digest_lines("called_functions")]
        elif name == "abi":
            rows = [{"kind": "text", "text": str(value)} for value in self._digest_lines("abi_custody")]
        elif name == "project":
            rows = [{"kind": "project", "text": str(value)} for value in self._project_digest_lines()]
        else:
            rows = [{"kind": "empty", "text": "Unsupported view %s" % name}]
        if not rows:
            rows = [{"kind": "empty", "text": "No data is available."}]
        self._one_cache[name] = rows
        return rows

    def _full_asm_rows_v35(self):
        values = self.model.asm_detail_lines_v17(full_scope=True, filter_text=None)
        rows = []
        current_block = None
        for value in values:
            text = str(value)
            if text.startswith("BLOCK "):
                current_block = self.model._canonical_block_addr_v21(text.split(None, 1)[1])
                rows.append({"kind": "block", "addr": current_block, "text": text})
            elif set(text.strip()) <= {"-"} and text.strip():
                rows.append({"kind": "rule", "text": text})
            else:
                rows.append(self.model.asm_instruction_row_v33(current_block, text))
        return rows or [{"kind": "empty", "text": "No frozen ASM is available."}]

    def _matching(self, rows, query, selectable=None):
        query = str(query or "").casefold()
        if not query:
            return []
        allowed = set(selectable) if selectable is not None else None
        return [
            index for index, row in enumerate(rows)
            if (allowed is None or index in allowed)
            and query in self._row_text(row).casefold()
        ]

    def _paint_search(self, y, x, text, query, left, width, current=False):
        for start, end in self._search_spans(text, query):
            clipped_start = max(start, left)
            clipped_end = min(end, left + width)
            if clipped_start >= clipped_end:
                continue
            role = "active_header" if current else "highlight"
            self._add(
                y, x + clipped_start - left,
                text[clipped_start:clipped_end],
                self._attr(role, bold=True), clipped_end - clipped_start,
            )

    def _paint_active_cursor_bar_v45(
        self, y, x, text, left, width, active, underline=False
    ):
        """Paint the red cursor surface before final semantic overlays.

        The visible text is repainted together with the background.  This is
        essential: a background-only rectangle would hide the font and turn
        the cursor into an opaque block graphic.  Address, search, mnemonic and
        linkage highlights are intentionally painted afterward.
        """
        if not active:
            return
        visible = str(text)[left:left + width]
        attr = self._attr("active_header", bold=True)
        if underline:
            attr |= curses.A_UNDERLINE
        self._add(
            y, x, visible.ljust(width), attr, width,
        )

    def _overlay_active_line_v30(self, y, x, text, left, width, active):
        """Compatibility alias for the v45 cursor-surface painter."""
        return self._paint_active_cursor_bar_v45(
            y, x, text, left, width, active
        )

    def _draw_phi_template_line(
        self, y, x, row, text, left, width, selected=False, focused=False,
        query="", base_attr=None,
    ):
        """Paint PHI rows as base → red cursor → final overlays.

        Every full-width layer repaints the visible characters with its
        background.  Final address/search/SID overlays are fragment paints, so
        the cursor remains a readable red bar rather than an opaque rectangle.
        """
        row = dict(row or {})
        kind = str(row.get("kind") or "body")
        visible = text[left:left + width]

        if kind in ("header_top", "header", "header_bottom"):
            base = (
                base_attr if base_attr is not None
                else self._attr("phi_header", bold=True) | curses.A_REVERSE
            )
            if focused:
                base |= curses.A_UNDERLINE
            self._add(y, x, visible.ljust(width), base, width)
            self._paint_active_cursor_bar_v45(
                y, x, text, left, width, selected
            )
            name_offset = int(row.get("header_name_offset", 0) or 0)
            name_width = int(row.get("header_name_width", 0) or 0)
            a = max(name_offset, left)
            b = min(name_offset + name_width, left + width)
            if a < b:
                fragment = text[a:b] if kind == "header" else " " * (b - a)
                self._add(
                    y, x + a - left, fragment,
                    self._attr("active_header", bold=True), b - a,
                )
            self._paint_search(
                y, x, text, query, left, width, current=selected
            )
            return

        attr = (
            base_attr if base_attr is not None
            else self._attr("default", bold=focused)
        )
        if focused:
            attr |= curses.A_UNDERLINE
        if base_attr is None:
            if kind in ("blade", "trunk"):
                attr = self._attr("helper", bold=focused)
            elif kind == "cycle":
                attr = self._attr("phi_cycle", bold=True)
            elif kind == "final":
                attr = self._attr("phi_final", bold=True) | curses.A_REVERSE
            elif kind in ("dropin_fact", "dropin_value", "dropin_code"):
                attr = self._attr(
                    "helper" if kind != "dropin_code" else "default",
                    bold=(kind == "dropin_fact"),
                )
        self._add(y, x, visible.ljust(width), attr, width)

        # Cursor bar is deliberately below the final semantic overlays.
        self._paint_active_cursor_bar_v45(
            y, x, text, left, width, selected
        )

        if kind in ("merge", "incoming", "cycle", "dropin_exec"):
            address = str(row.get("address") or "")
            offset = int(row.get("address_offset", 0) or 0)
            if address and text[offset:offset + len(address)] == address:
                a = max(offset, left)
                b = min(offset + len(address), left + width)
                if a < b:
                    role = (
                        "phi_cycle" if kind == "cycle"
                        else "phi_merge_addr" if kind == "merge"
                        else "phi_incoming_addr"
                    )
                    extra = 0 if kind == "cycle" else curses.A_REVERSE
                    self._add(
                        y, x + a - left, text[a:b],
                        self._attr(role, bold=True) | extra, b - a,
                    )

        if kind == "final":
            sid = str(row.get("final_sid") or "")
            sid_offset = text.rfind(sid) if sid else -1
            if sid_offset >= 0:
                a = max(sid_offset, left)
                b = min(sid_offset + len(sid), left + width)
                if a < b:
                    self._add(
                        y, x + a - left, text[a:b],
                        self._attr("phi_final_sid", bold=True), b - a,
                    )

        # Search is the final overlay and therefore remains visible through the
        # cursor bar and every semantic surface.
        self._paint_search(
            y, x, text, query, left, width, current=selected
        )


    def _draw_one(self, body_top, body_height, width):
        name = self.view
        rows = self._one_rows(name)
        state = self.states[name]
        if name == "asm":
            self._asm_align_viewport_v27(rows, state, body_height)
        maximum = max(0, len(rows) - 1)
        state["line"] = min(max(0, int(state["line"])), maximum)
        if state["line"] < state["top"]:
            state["top"] = state["line"]
        elif state["line"] >= state["top"] + body_height:
            state["top"] = state["line"] - body_height + 1
        state["top"] = min(max(0, int(state["top"])), max(0, len(rows) - body_height))
        digits = max(4, len(str(max(1, len(rows)))))
        text_x = digits + 3
        text_width = max(1, width - text_x)
        left = max(0, int(state["left"]))
        query = self._paint_query_v39()
        selected_phi_sid = str(self._phi_menu_selected_sid or "") if name == "phi" else ""
        for offset in range(body_height):
            index = int(state["top"]) + offset
            y = body_top + offset
            if index >= len(rows):
                self._add(y, 0, " " * max(0, width - 1), self._attr("default"), width - 1)
                continue
            row = dict(rows[index] or {})
            text = self._row_text(row)
            selected = index == int(state["line"])
            focused = index == state.get("focus")
            number = " %*d " % (digits, index + 1)
            self._add(y, 0, number, self._attr("operator", selected=selected), text_x - 1)
            if name == "detail" and row.get("kind") in ("var_header", "var_rule", "var_row"):
                if row.get("kind") == "var_header":
                    self._add(
                        y, text_x, text[left:left + text_width].ljust(text_width),
                        self._attr("phi_list", bold=True), text_width,
                    )
                elif row.get("kind") == "var_rule":
                    self._add(
                        y, text_x, text[left:left + text_width].ljust(text_width),
                        self._attr("helper", bold=True), text_width,
                    )
                else:
                    self._add(
                        y, text_x, text[left:left + text_width].ljust(text_width),
                        self._attr("default"), text_width,
                    )
                    # Both destinations remain visible.  The active destination
                    # on the selected variable is red-negative; its peer is
                    # blue-negative.  Left/Right changes only this action cursor.
                    action = int(state.get("action", 0) or 0) % 2
                    for action_index, span in enumerate(row.get("action_spans", ()) or ()):
                        start, end = span
                        a = max(start, left); b = min(end, left + text_width)
                        if a >= b:
                            continue
                        role = (
                            "active_header"
                            if selected and action_index == action
                            else "phi_list"
                        )
                        self._add(
                            y, text_x + a - left, text[a:b],
                            self._attr(role, bold=True), b - a,
                        )
                    name_roles = ("helper", "default", "comment", "modified")
                    for span, role in zip(row.get("name_spans", ()) or (), name_roles):
                        start, end = span
                        a = max(start, left); b = min(end, left + text_width)
                        if a < b:
                            self._add(
                                y, text_x + a - left, text[a:b],
                                self._attr(role, bold=selected), b - a,
                            )
                    self._paint_search(
                        y, text_x, text, query, left, text_width,
                        current=selected,
                    )
                continue
            if row.get("kind") == "phi_section":
                self._add(y, text_x, text[left:left + text_width].ljust(text_width), self._attr("phi_header", bold=True) | curses.A_REVERSE, text_width)
                continue
            if row.get("kind") == "phi_summary":
                authority = str(row.get("output_sid") or "") == selected_phi_sid
                base = self._attr("active_header", bold=True) if authority else self._attr("phi_list", bold=True)
                self._add(y, text_x, text[left:left + text_width].ljust(text_width), base, text_width)
                self._paint_active_cursor_bar_v45(
                    y, text_x, text, left, text_width, selected
                )
                self._paint_search(
                    y, text_x, text, query, left, text_width,
                    current=selected,
                )
                continue
            if row.get("phi_template"):
                self._draw_phi_template_line(y, text_x, row, text, left, text_width, selected=selected, focused=focused, query=query)
                continue
            branch_paint = self._asm_branch_paint_role_v24(row) if name == "asm" else None
            if branch_paint:
                role = branch_paint
            elif name == "asm" and row.get("kind") == "asm_relation":
                relation_role = str(row.get("relation_role") or "")
                role = "asm_relation_current" if relation_role == "current" else "asm_transition_orange"
            elif name == "asm" and row.get("kind") == "rule" and row.get("relation_role"):
                role = "asm_transition_orange"
            elif row.get("kind") == "block" or (name == "asm" and text.startswith("BLOCK ")):
                role = "asm_block_header"
            elif name == "asm" and row.get("asm_role") == "jump":
                role = "asm_jump_red"
            elif name == "asm" and row.get("asm_role") == "compare":
                role = "asm_compare"
            else:
                role = "phi_final" if focused else "default"
            self._add(
                y, text_x, text[left:left + text_width].ljust(text_width),
                self._attr(
                    role, selected=False,
                    bold=(focused or role in (
                        "asm_block_header", "asm_transition_orange",
                        "asm_jump_red", "asm_compare", "asm_relation_current",
                        "asm_focus_block", "asm_join_block", "asm_fork_block",
                    )),
                ), text_width,
            )
            self._paint_active_cursor_bar_v45(
                y, text_x, text, left, text_width, selected,
                underline=bool(branch_paint),
            )
            if name == "asm" and row.get("kind") == "asm":
                match = re.match(r"\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})", text)
                if match:
                    a = max(match.start(1), left); b = min(match.end(1), left + text_width)
                    if a < b:
                        self._add(
                            y, text_x + a - left, text[a:b],
                            self._attr("asm_instruction_addr", bold=True), b - a,
                        )
                self._paint_asm_jump_mnemonic_v26(
                    y, text_x, text, left, text_width, row, hovered=False
                )
            self._paint_search(
                y, text_x, text, query, left, text_width,
                current=selected,
            )

    def _ensure_four(self):
        if self._four_ready:
            return
        if not self._code_view_initialized.get("four"):
            self._force_readable_projection()
            self._code_view_initialized["four"] = True
        self.owner._side_capture_model_cursor()
        source = (
            self.model.projection
            if self.model.projection in ("readable", "executable")
            else "readable"
        )
        self.owner.last_python_pane = source
        self._four_active = self.owner.side_panes.index(source)
        self.owner.side_active = self._four_active
        self.owner._side_sync_python_pair(source)
        self._four_ready = True

    @staticmethod
    def _grid_rectangles(body_top, body_height, width):
        top_h = body_height // 2
        bottom_h = body_height - top_h
        left_w = width // 2
        right_w = width - left_w
        return {
            "asm": (body_top, 0, top_h, left_w),
            "executable": (body_top, left_w, top_h, right_w),
            "c_code": (body_top + top_h, 0, bottom_h, left_w),
            "readable": (body_top + top_h, left_w, bottom_h, right_w),
        }

    def _draw_grid_pane(
        self, pane, rect, lines, active, query, state, linked_lines=(),
        row_records=(),
    ):
        y, x, pane_h, pane_w = rect
        if pane_h < 3 or pane_w < 8:
            return
        lines = [str(value) for value in list(lines or ())]
        row_records = [dict(value or {}) for value in list(row_records or ())]
        inner_h = max(1, pane_h - 2)
        if pane == "asm":
            navigation_rows = row_records or [
                {"kind": "asm", "text": value} for value in lines
            ]
            self._asm_align_viewport_v27(
                navigation_rows, state, inner_h
            )
        maximum = max(0, len(lines) - 1)
        state["line"] = min(max(0, int(state.get("line", 0))), maximum)
        if state["line"] < state["top"]:
            state["top"] = state["line"]
        elif state["line"] >= state["top"] + inner_h:
            state["top"] = state["line"] - inner_h + 1
        state["top"] = min(
            max(0, int(state.get("top", 0))), max(0, len(lines) - inner_h)
        )
        border_role = "active_header" if active else "helper"
        horizontal = "=" if active else "-"
        self._add(y, x, "+" + horizontal * max(0, pane_w - 2) + "+", self._attr(border_role, bold=True), pane_w)
        self._add(y + pane_h - 1, x, "+" + horizontal * max(0, pane_w - 2) + "+", self._attr(border_role, bold=True), pane_w)
        for row in range(y + 1, y + pane_h - 1):
            self._add(row, x, "|", self._attr(border_role, bold=True), 1)
            self._add(row, x + pane_w - 1, "|", self._attr(border_role, bold=True), 1)
        title = " %s%s | %d " % (
            self.owner.side_titles.get(pane, pane.upper()),
            " [ACTIVE]" if active else "", len(lines),
        )
        self._add(y, x + 2, title, self._attr(border_role, bold=True), max(0, pane_w - 4))
        digits = max(3, len(str(max(1, len(lines)))))
        gutter = min(pane_w - 3, digits + 2)
        text_x = x + 1 + gutter
        text_w = max(1, pane_w - gutter - 2)
        left = max(0, int(state.get("left", 0)))
        linked = set(int(value) for value in linked_lines)
        for offset in range(inner_h):
            index = int(state["top"]) + offset
            sy = y + 1 + offset
            if index >= len(lines):
                continue
            selected = index == int(state["line"])
            linked_line = index in linked
            number = ("%*d " % (digits, index + 1))[-gutter:]
            self._add(sy, x + 1, number, self._attr("operator", selected=selected), gutter)
            text = lines[index]
            row_record = row_records[index] if index < len(row_records) else {}
            semantic = (
                self.model.asm_instruction_semantics_v33(text)
                if pane == "asm" else {}
            )
            branch_paint = self._asm_branch_paint_role_v24(row_record) if pane == "asm" else None
            if branch_paint:
                role = branch_paint
            elif semantic.get("asm_role") == "jump":
                role = "asm_jump_red"
            elif semantic.get("asm_role") == "compare":
                role = "asm_compare"
            else:
                role = "highlight" if linked_line else "default"
            self._add(
                sy, text_x, text[left:left + text_w].ljust(text_w),
                self._attr(
                    role, selected=selected and not active,
                    bold=(linked_line or (selected and active) or semantic.get("asm_role") is not None),
                ), text_w,
            )
            self._paint_active_cursor_bar_v45(
                sy, text_x, text, left, text_w, selected and active,
                underline=bool(branch_paint),
            )
            if pane == "asm" and semantic.get("instruction_addr"):
                match = re.match(r"\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})", text)
                if match:
                    a = max(match.start(1), left); b = min(match.end(1), left + text_w)
                    if a < b:
                        self._add(
                            sy, text_x + a - left, text[a:b],
                            self._attr("asm_instruction_addr", bold=True), b - a,
                        )
                semantic_row = dict(row_record or {})
                semantic_row.update(semantic)
                self._paint_asm_jump_mnemonic_v26(
                    sy, text_x, text, left, text_w, semantic_row, hovered=False
                )
            self._paint_search(
                sy, text_x, text, query, left, text_w,
                current=selected and active,
            )

    def _draw_four(self, body_top, body_height, width):
        self._ensure_four()
        self.owner.side_active = self._four_active
        rects = self._grid_rectangles(body_top, body_height, width)
        for index, pane in enumerate(self.owner.side_panes):
            row_records = ()
            if pane == "asm" and self._four_asm_branch_rows_v35 is not None:
                row_records = [dict(row or {}) for row in self._four_asm_branch_rows_v35]
                lines = [self._row_text(row) for row in row_records]
            elif pane == "asm" and self._four_asm_rows_v34 is not None:
                row_records = [dict(row or {}) for row in self._four_asm_rows_v34]
                lines = [self._row_text(row) for row in row_records]
            else:
                if pane == "asm":
                    row_records = self._four_asm_navigation_rows_v27()
                    lines = [self._row_text(row) for row in row_records]
                else:
                    lines = self.owner._side_lines(pane)
            query = self._paint_query_v39("four:%s" % pane)
            linked = ()
            if pane in ("readable", "executable"):
                linked = (int(self.owner.side_state[pane]["line"]),)
            self._draw_grid_pane(
                pane, rects[pane], lines, index == self._four_active,
                query, self.owner.side_state[pane], linked_lines=linked,
                row_records=row_records,
            )

    def _three_prepare(self):
        if self._three is not None:
            return
        # A newly constructed STATIC DEBUG workspace starts two fresh,
        # independent navigation ledgers.  Existing workspaces retain both
        # histories across Tab focus changes and menu round-trips.
        self._phi_history_v46 = []
        self._phi_history_index_v46 = -1
        if not self._code_view_initialized.get("three"):
            self._force_readable_projection()
            self._code_view_initialized["three"] = True
        lines = [str(value) for value in list(self.model.lines() or ())]
        blocks = list(self.model.projection_block_map_v21(
            self.model.projection, allow_cursor_fallback=False
        ) or ())
        paths = list(self.model.phi_path_focus_rows_v21() or ())
        statement_contexts = list(self.model.projection_statement_contexts_v33(
            self.model.projection
        ) or ())
        current = min(max(0, int(self.model.line)), max(0, len(blocks) - 1))
        focus = blocks[current] if blocks else None
        if focus is None:
            first = next((row for row in paths if row.get("incoming_addr")), None)
            focus = first.get("incoming_addr") if first else None
        self._three = {
            "panes": ("phi", "asm", "code"),
            "active": 2,
            "states": {
                "phi": {"line": 0, "top": 0, "left": 0, "focus": None},
                "asm": {"line": 0, "top": 0, "left": 0, "focus": None},
                "code": {
                    "line": int(self.model.line), "top": int(self.model.top_line),
                    "left": int(self.model.left_column), "column": int(self.model.column),
                    "focus": None,
                },
            },
            "lines": lines,
            "blocks": blocks,
            "statement_contexts": statement_contexts,
            "all_paths": paths,
            "phi_matches": [],
            "phi_active_matches_v47": [],
            "phi_passive_matches_v47": [],
            "block_activity_v47": {},
            "phi_list_rows": [],
            "phi_detail_rows": [],
            "phi_rows": [],
            "selected_phi_sid": None,
            "selected_dropin_id": None,
            "phi_mode": "legacy_custody",
            "phi_materialization_full_v48": False,
            "asm_base_rows": [],
            "asm_rows": [],
            "base_focus": None,
            "pointer_focus": None,
            "phi_stack_zoom": None,
            "code_highlight_block": None,
            "branch_role_by_block_v25": {},
            "asm_hover_block_v25": None,
            "asm_hover_role_v25": None,
            "focus": None,
            "source": "code",
        }
        self._three_set_focus(focus, "code", initialize=True)

    def _three_refresh_code(self):
        self._three["lines"] = [str(value) for value in list(self.model.lines() or ())]
        self._three["blocks"] = list(self.model.projection_block_map_v21(
            self.model.projection, allow_cursor_fallback=False
        ) or ())
        self._three["statement_contexts"] = list(
            self.model.projection_statement_contexts_v33(self.model.projection) or ()
        )

    def _asm_block_groups_v27(self, rows):
        """Partition one rendered ASM surface into semantic block records.

        The selectable cursor belongs to a machine block, never to an
        individual instruction.  Relation labels immediately above a block are
        retained as that block's viewport preface, while the cursor anchor is
        the ``BLOCK`` header itself.  Legacy single-block surfaces without an
        explicit header degrade to one block, not one selectable instruction
        per line.
        """
        rows = [dict(row or {}) for row in list(rows or ())]
        anchors = []
        relation_before = {}
        pending_relation = None
        last_address = None

        for index, row in enumerate(rows):
            kind = str(row.get("kind") or "")
            text = self._row_text(row).strip()
            if kind == "asm_relation":
                pending_relation = index
                continue

            explicit_block = kind == "block" or text.startswith("BLOCK ")
            if explicit_block:
                address = self.model._canonical_block_addr_v21(
                    row.get("addr") or row.get("address")
                    or (text.split(None, 1)[1] if text.startswith("BLOCK ") and len(text.split(None, 1)) == 2 else None)
                )
                anchors.append((index, address))
                if pending_relation is not None and pending_relation == index - 1:
                    relation_before[index] = pending_relation
                pending_relation = None
                last_address = address
                continue

            # Compatibility for structured ASM rows whose producer omitted a
            # visible BLOCK header.  A changed owner address begins a new block.
            address = self.model._canonical_block_addr_v21(
                row.get("block_addr") or row.get("owner_block_addr")
            )
            if address is not None and address != last_address:
                anchors.append((index, address))
                last_address = address
                pending_relation = None

        if not anchors:
            first = next((
                index for index, row in enumerate(rows)
                if self._row_text(row).strip()
            ), None)
            if first is None:
                return ()
            anchors = [(first, self.model._canonical_block_addr_v21(
                rows[first].get("addr") or rows[first].get("address")
            ))]

        prepared = [
            {
                "anchor": int(anchor_index),
                "start": int(relation_before.get(anchor_index, anchor_index)),
                "address": address,
            }
            for anchor_index, address in anchors
        ]
        groups = []
        for ordinal, item in enumerate(prepared):
            next_start = (
                prepared[ordinal + 1]["start"]
                if ordinal + 1 < len(prepared) else len(rows)
            )
            group = dict(item)
            group["end"] = int(max(group["anchor"] + 1, next_start))
            groups.append(group)
        return tuple(groups)

    def _asm_block_choices_v27(self, rows):
        return [group["anchor"] for group in self._asm_block_groups_v27(rows)]

    def _asm_hover_group_indices_v30(self, rows, hover_block):
        """Return every rendered row owned by the active ASM block section.

        Block navigation makes the ``BLOCK`` header the cursor anchor, but the
        visual linkage root is the complete section: relation heading, block
        header, rule and every instruction.  Row-local address checks cannot
        color relation/rule rows because those rows intentionally carry no
        machine address.  Resolve the semantic block group once and paint its
        full row interval instead.
        """
        hover = self.model._canonical_block_addr_v21(hover_block)
        if hover is None:
            return frozenset()
        for group in self._asm_block_groups_v27(rows):
            address = self.model._canonical_block_addr_v21(
                group.get("address")
            )
            if address != hover:
                continue
            return frozenset(range(
                int(group.get("start", group.get("anchor", 0))),
                int(group.get("end", group.get("anchor", 0) + 1)),
            ))
        return frozenset()

    def _asm_block_action_row_v28(self, rows, line):
        """Relay one selected BLOCK cursor to its actionable jump instruction.

        mars v0.27 deliberately collapsed ASM navigation from instruction rows
        to one cursor stop per machine block.  The missing half of that change
        was action inheritance: ENTER on the BLOCK header still saw only the
        header record, so a terminal ``JMP``/``Jcc`` inside the block could no
        longer open its direct target or complete branch/fork/join topology.

        This resolver keeps block-level browsing while borrowing the last
        direct jump instruction from the selected block as its activation
        record.  A basic block normally has one terminal control transfer; the
        reverse scan is nevertheless intentional for tolerant legacy surfaces.
        Indirect jumps without a frozen direct target remain visible but cannot
        manufacture a destination.
        """
        rows = [dict(row or {}) for row in list(rows or ())]
        groups = list(self._asm_block_groups_v27(rows))
        if not groups:
            return None
        try:
            line = int(line)
        except Exception:
            line = 0
        group = next((
            item for item in groups
            if int(item["start"]) <= line < int(item["end"])
        ), None)
        if group is None:
            group = min(groups, key=lambda item: abs(int(item["anchor"]) - line))

        source_block = self.model._canonical_block_addr_v21(
            group.get("address")
        )
        for row_index in range(
            min(len(rows), int(group["end"])) - 1,
            max(-1, int(group["start"]) - 1),
            -1,
        ):
            candidate = dict(rows[row_index] or {})
            semantics = self.model.asm_instruction_semantics_v33(
                candidate.get("text")
            )
            target = candidate.get("jump_target") or semantics.get("jump_target")
            if target is None:
                continue
            target = self.model._canonical_block_addr_v21(target)
            if target is None:
                continue
            action = dict(candidate)
            action.update({
                "addr": source_block or self.model._canonical_block_addr_v21(
                    candidate.get("addr")
                ),
                "jump_target": target,
                "asm_role": semantics.get("asm_role") or candidate.get("asm_role"),
                "conditional_jump": bool(
                    semantics.get("conditional_jump")
                    or candidate.get("conditional_jump")
                ),
                "unconditional_jump": bool(
                    semantics.get("unconditional_jump")
                    or candidate.get("unconditional_jump")
                ),
                "block_action_relay_v28": True,
                "block_anchor_v28": int(group["anchor"]),
                "block_action_index_v28": int(row_index),
            })
            return action
        return None

    def _asm_block_action_status_v28(self, rows, state):
        """Advertise the inherited branch command for the selected block."""
        action = self._asm_block_action_row_v28(
            rows, dict(state or {}).get("line", 0)
        )
        if not action:
            return False
        semantics = self.model.asm_instruction_semantics_v33(action.get("text"))
        mnemonic = str(semantics.get("mnemonic") or "JUMP")
        source = self.model._canonical_block_addr_v21(action.get("addr")) or "-"
        target = self.model._canonical_block_addr_v21(
            action.get("jump_target")
        ) or "-"
        suffix = "ENTER %s %s -> %s" % (mnemonic, source, target)
        current = str(self.status or "")
        if suffix not in current:
            self.status = "%s | %s" % (current, suffix) if current else suffix
        return True

    def _asm_block_matches_v27(self, rows, query):
        """Return block anchors whose complete block body contains query."""
        needle = str(query or "").casefold()
        if not needle:
            return []
        rows = [dict(row or {}) for row in list(rows or ())]
        matches = []
        for group in self._asm_block_groups_v27(rows):
            body = "\n".join(
                self._row_text(rows[index])
                for index in range(group["start"], min(group["end"], len(rows)))
            ).casefold()
            if needle in body:
                matches.append(group["anchor"])
        return matches

    def _asm_align_viewport_v27(self, rows, state, viewport_rows=None):
        """Anchor ASM selection while preserving visual context above it.

        Earlier builds placed the selected block at the first visible row.
        That destroyed continuity while walking blocks.  When pane height is
        known, the selected ``BLOCK`` header is now placed about one-third down
        the viewport, leaving predecessor/context rows visible above it.
        """
        groups = list(self._asm_block_groups_v27(rows))
        if not groups:
            return False
        line = int(dict(state or {}).get("line", 0) or 0)
        group = next((
            item for item in groups
            if item["start"] <= line < item["end"]
        ), None)
        if group is None:
            group = min(groups, key=lambda item: abs(item["anchor"] - line))
        anchor = int(group["anchor"])
        state["line"] = anchor
        if viewport_rows is None:
            state["top"] = int(group["start"])
        else:
            context_rows = max(0, int(viewport_rows) // 3)
            state["top"] = max(0, anchor - context_rows)
        return True

    def _four_asm_navigation_rows_v27(self):
        if self._four_asm_branch_rows_v35 is not None:
            return [dict(row or {}) for row in self._four_asm_branch_rows_v35]
        if self._four_asm_rows_v34 is not None:
            return [dict(row or {}) for row in self._four_asm_rows_v34]
        rows = []
        current_block = None
        for value in self.owner._side_lines("asm"):
            text = str(value)
            if text.startswith("BLOCK "):
                current_block = self.model._canonical_block_addr_v21(
                    text.split(None, 1)[1]
                )
                rows.append({"kind": "block", "addr": current_block, "text": text})
            elif set(text.strip()) <= {"-"} and text.strip():
                rows.append({"kind": "rule", "text": text})
            else:
                rows.append(self.model.asm_instruction_row_v33(current_block, text))
        return rows

    def _three_selectable(self, pane, rows):
        if pane == "asm":
            return self._asm_block_choices_v27(rows)
        if pane == "phi":
            return [
                index for index, row in enumerate(rows)
                if row.get("kind") in ("phi_summary", "dropin_summary")
                or bool(row.get("block_hotspot"))
            ]
        return list(range(len(rows)))

    @staticmethod
    def _three_row_identity(row):
        row = dict(row or {})
        return (
            str(row.get("kind") or ""),
            str(row.get("output_sid") or row.get("sid") or ""),
            str(row.get("addr") or row.get("incoming_addr") or row.get("block") or ""),
            str(row.get("dropin_id") or row.get("dropin_sequence_id") or ""),
            str(row.get("text") or ""),
        )

    @classmethod
    def _three_find_identity(cls, rows, identity):
        if identity is None:
            return None
        for index, row in enumerate(rows):
            if cls._three_row_identity(row) == identity:
                return index
        return None

    @staticmethod
    def _phi_cursor_identity_v29(row):
        """Stable semantic identity for one selectable PHI row."""
        row = dict(row or {})
        return (
            str(row.get("kind") or ""),
            str(row.get("output_sid") or row.get("sid") or row.get("canonical_final_sid") or ""),
            str(row.get("address") or row.get("incoming_addr") or row.get("merge_addr") or ""),
            str(row.get("event_sid") or ""),
            int(row.get("node_index") or -1),
            int(row.get("node_number") or -1),
            int(row.get("phi_depth") or 0),
            str(row.get("dropin_id") or ""),
            str(row.get("dropin_sequence_id") or ""),
            int(row.get("dropin_index") or -1),
            int(row.get("line_number") or -1),
        )

    @classmethod
    def _phi_cursor_snapshot_v29(cls, rows, state):
        """Capture PHI cursor by semantic row identity, not transient index."""
        rows = [dict(row or {}) for row in list(rows or ())]
        state = dict(state or {})
        if not rows:
            return None
        line = min(max(0, int(state.get("line", 0) or 0)), len(rows) - 1)
        identity = cls._phi_cursor_identity_v29(rows[line])
        occurrence = sum(
            cls._phi_cursor_identity_v29(rows[index]) == identity
            for index in range(line)
        )
        focus = state.get("focus")
        focus_identity = None
        focus_occurrence = 0
        if isinstance(focus, int) and 0 <= focus < len(rows):
            focus_identity = cls._phi_cursor_identity_v29(rows[focus])
            focus_occurrence = sum(
                cls._phi_cursor_identity_v29(rows[index]) == focus_identity
                for index in range(focus)
            )
        return {
            "identity": identity,
            "occurrence": int(occurrence),
            "relative": max(0, line - int(state.get("top", 0) or 0)),
            "focus_identity": focus_identity,
            "focus_occurrence": int(focus_occurrence),
        }

    @classmethod
    def _phi_restore_cursor_v29(
        cls, rows, state, snapshot=None, preferred_sid=None
    ):
        """Restore PHI selection after rebuild, Tab focus, or Enter action."""
        rows = [dict(row or {}) for row in list(rows or ())]
        if not rows:
            state.update({"line": 0, "top": 0, "focus": None})
            state.pop("_phi_cursor_v29", None)
            return None
        snapshot = dict(snapshot or state.get("_phi_cursor_v29") or {})

        def locate(identity, occurrence=0):
            if identity is None:
                return None
            matches = [
                index for index, row in enumerate(rows)
                if cls._phi_cursor_identity_v29(row) == tuple(identity)
            ]
            occurrence = max(0, int(occurrence or 0))
            return matches[min(occurrence, len(matches) - 1)] if matches else None

        target = locate(snapshot.get("identity"), snapshot.get("occurrence", 0))
        if target is None and preferred_sid:
            wanted = str(preferred_sid)
            target = next((
                index for index, row in enumerate(rows)
                if row.get("kind") in ("phi_summary", "dropin_summary")
                and (
                    str(row.get("output_sid") or row.get("sid") or "") == wanted
                    or wanted in {
                        str(value) for value in list(
                            row.get("destination_sids", ()) or ()
                        )
                    }
                )
            ), None)
        if target is None:
            choices = [
                index for index, row in enumerate(rows)
                if row.get("kind") in ("phi_summary", "dropin_summary")
                or bool(row.get("block_hotspot"))
            ]
            target = choices[0] if choices else 0
        relative = max(0, int(snapshot.get("relative", 0) or 0))
        state["line"] = int(target)
        state["top"] = max(0, int(target) - relative)
        focus = locate(
            snapshot.get("focus_identity"), snapshot.get("focus_occurrence", 0)
        )
        state["focus"] = focus
        state["_phi_cursor_v29"] = cls._phi_cursor_snapshot_v29(rows, state)
        return int(target)

    @classmethod
    def _phi_remember_cursor_v29(cls, rows, state):
        snapshot = cls._phi_cursor_snapshot_v29(rows, state)
        if snapshot is not None:
            state["_phi_cursor_v29"] = snapshot
        return snapshot

    def _phi_truth_detail_rows_v47(
        self, selected_sid, selected_paths, focus
    ):
        """Tag one selected custody chain without pretending PHI is ASM work.

        The underlying PHI rows remain frozen evidence.  Exact events at the
        focal address are consolidated into a compact truth blade that states
        whether the variable is actually read/written by the displayed block or
        merely converges at its entry.
        """
        selected_sid = str(selected_sid or "")
        focus = self.model._canonical_block_addr_v21(focus)
        paths = [
            dict(row or {}) for row in list(selected_paths or ())
            if str(dict(row or {}).get("output_sid") or "") == selected_sid
        ]
        rows = [
            dict(row or {}) for row in self._phi_dependency_rows(
                selected_sid, pointer_hotspots=True
            )
        ]
        if not rows or not paths or focus is None:
            return rows

        active = any(
            str(path.get("block_activity_v47") or "") == "active"
            for path in paths
        )
        uses = {
            str(path.get("block_use_v47") or "NONE") for path in paths
        }
        uses.discard("NONE")
        block_use = "+".join(sorted(uses)) if uses else "NONE"
        relations = {
            str(path.get("focal_relation_v47") or "") for path in paths
        }
        input_sids = sorted({
            self.model.canonical_phi_sid_v33(value)
            for path in paths
            for value in list(path.get("input_sids", ()) or ())
            if value
        })
        display_name = self.model.phi_display_name_v30(selected_sid)
        input_names = [
            self.model.phi_display_name_v30(value) for value in input_sids
        ]
        input_text = _phi_merge_values_v14(input_names)

        synthetic = []
        prefix = "        | "
        if "merge_at_entry" in relations:
            synthetic.append({
                "kind": "merge",
                "address": focus,
                "address_display": focus,
                "address_missing": False,
                "address_offset": len(prefix),
                "block_hotspot": True,
                "phi_template": True,
                "output_sid": selected_sid,
                "sid": selected_sid,
                "event_sid": selected_sid,
                "block_activity_v47": "active" if active else "passive",
                "activity_tag_v47": (
                    "MERGES AT BLOCK ENTRY — ACTIVE HERE"
                    if active else "ENTRY STATE — UNUSED HERE"
                ),
                "text": "%s%-21s MERGES AT BLOCK ENTRY" % (prefix, focus),
            })
            synthetic.append({
                "kind": "phi_truth_note",
                "output_sid": selected_sid,
                "block_activity_v47": "active" if active else "passive",
                "text": "          BLOCK USE: %s" % block_use,
            })
            synthetic.append({
                "kind": "phi_truth_note",
                "output_sid": selected_sid,
                "block_activity_v47": "active" if active else "passive",
                "text": "          %s <= %s" % (display_name, input_text),
            })
        if "carried_from_block" in relations:
            synthetic.append({
                "kind": "incoming",
                "address": focus,
                "address_display": focus,
                "address_missing": False,
                "address_offset": len(prefix),
                "block_hotspot": True,
                "phi_template": True,
                "output_sid": selected_sid,
                "sid": selected_sid,
                "event_sid": selected_sid,
                "block_activity_v47": "active" if active else "passive",
                "activity_tag_v47": (
                    "CARRIED FROM BLOCK — ACTIVE HERE"
                    if active else "CHAIN CONTEXT ONLY — UNUSED HERE"
                ),
                "text": "%s%-21s CARRIES STATE FROM THIS BLOCK" % (
                    prefix, focus
                ),
            })
            synthetic.append({
                "kind": "phi_truth_note",
                "output_sid": selected_sid,
                "block_activity_v47": "active" if active else "passive",
                "text": "          BLOCK USE: %s" % block_use,
            })

        output = []
        inserted = False
        seen = set()
        for raw in rows:
            row = dict(raw or {})
            row_sid = str(
                row.get("output_sid") or row.get("sid")
                or row.get("event_sid") or ""
            )
            address = self.model._canonical_block_addr_v21(
                row.get("address") or row.get("addr")
            )
            if (
                synthetic and address == focus
                and row_sid == selected_sid
                and row.get("kind") in ("incoming", "merge", "cycle")
            ):
                if not inserted:
                    output.extend(dict(item) for item in synthetic)
                    inserted = True
                continue
            identity = (
                str(row.get("kind") or ""),
                str(row.get("address") or row.get("addr") or ""),
                row_sid,
                str(row.get("text") or ""),
            )
            if identity in seen:
                continue
            seen.add(identity)
            output.append(row)
        if synthetic and not inserted:
            insert_at = next((
                index for index, row in enumerate(output)
                if dict(row or {}).get("kind") == "final"
            ), len(output))
            output[insert_at:insert_at] = [dict(item) for item in synthetic]
        return output

    def _phi_materialization_detail_rows_v48(self, selected_sid, entry):
        """Render only blocks where the selected variable materializes."""
        selected_sid = str(selected_sid or "")
        entry = dict(entry or {})
        display_name = self.model.active_display_name_v38(selected_sid)
        rows = []
        prefix = "        | "
        for raw_block in list(entry.get("blocks", ()) or ()):
            block_record = dict(raw_block or {})
            block = self.model._canonical_block_addr_v21(
                block_record.get("block")
            )
            if block is None:
                continue
            assignments = list(
                dict(value or {})
                for value in list(
                    block_record.get("assignments", ()) or ()
                )
            )
            rows.append({
                "kind": "dropin_exec",
                "phi_template": True,
                "block_hotspot": True,
                "address": block,
                "address_display": block,
                "address_offset": len(prefix),
                "output_sid": selected_sid,
                "sid": selected_sid,
                "event_sid": selected_sid,
                "text": "%s%-21s MATERIALIZES %s" % (
                    prefix, block, display_name
                ),
            })
            occurrences = int(
                block_record.get("occurrence_count", 0) or 0
            )
            if occurrences > len(assignments):
                rows.append({
                    "kind": "phi_truth_note",
                    "output_sid": selected_sid,
                    "text": "          %d execution occurrences" % occurrences,
                })
            for ordinal, assignment in enumerate(assignments, 1):
                code = str(assignment.get("text") or "").strip()
                count = int(assignment.get("occurrence_count", 0) or 0)
                suffix = "  [x%d]" % count if count > 1 else ""
                rows.append({
                    "kind": "dropin_code",
                    "output_sid": selected_sid,
                    "sid": selected_sid,
                    "address": block,
                    "full_data_item": True,
                    "text": "          [%d] %s%s" % (
                        ordinal, code, suffix
                    ),
                })
            rows.append({"kind": "blank", "text": ""})
        while rows and dict(rows[-1] or {}).get("kind") == "blank":
            rows.pop()
        return rows

    def _phi_focal_dropin_rows_v49(self, focus, inventory):
        """Render every accepted drop-in in the focal block directly.

        There is deliberately no root-variable menu in focal mode.  The section
        header carries aggregate write/occurrence counts and the body lists each
        distinct emitted assignment once beneath its exact machine block.
        """
        inventory = [dict(item or {}) for item in list(inventory or ())]
        allowed = {
            str(item.get("output_sid") or "") for item in inventory
            if item.get("output_sid")
        }
        groups = list(self.model.projection_materialization_groups_v48(
            focus,
            projection=self.model.projection,
            full_scope=False,
        ) or ())

        accepted_groups = []
        total_writes = 0
        total_occurrences = 0
        ordered_sids = []
        for raw_group in groups:
            group = dict(raw_group or {})
            block = self.model._canonical_block_addr_v21(
                group.get("block") or focus
            )
            assignments = []
            for raw_assignment in list(group.get("assignments", ()) or ()):
                assignment = dict(raw_assignment or {})
                destinations = tuple(
                    self.model.canonical_phi_sid_v33(value)
                    for value in list(
                        assignment.get("destination_sids", ()) or ()
                    )
                    if value
                )
                visible_destinations = tuple(
                    sid for sid in destinations if sid in allowed
                )
                if not visible_destinations:
                    continue
                assignment["visible_destination_sids_v49"] = visible_destinations
                assignments.append(assignment)
                total_writes += 1
                total_occurrences += max(1, int(
                    assignment.get("occurrence_count", 0) or 0
                ))
                for sid in visible_destinations:
                    if sid not in ordered_sids:
                        ordered_sids.append(sid)
            if assignments and block is not None:
                accepted_groups.append({
                    "block": block,
                    "assignments": tuple(assignments),
                })

        header = "MATERIALIZED IN FOCAL BLOCK | %d write%s | %d occurrence%s" % (
            total_writes, "" if total_writes == 1 else "s",
            total_occurrences, "" if total_occurrences == 1 else "s",
        )
        rows = [{"kind": "phi_section", "text": header}]
        if not accepted_groups:
            rows.append({
                "kind": "empty",
                "text": "No accepted assignment materializes in this block.",
            })
            return rows, tuple(ordered_sids)

        for group_index, group in enumerate(accepted_groups, 1):
            block = str(group["block"])
            assignments = list(group["assignments"])
            if group_index > 1:
                rows.append({"kind": "blank", "text": ""})
            rows.append({
                "kind": "dropin_exec",
                "phi_template": True,
                "block_hotspot": True,
                "address": block,
                "address_display": block,
                "address_offset": len("        | "),
                "addr": block,
                "dropin_id": "%s:%s:focal-v49" % (
                    self.model.projection, block
                ),
                "dropin_index": group_index,
                "output_sid": (
                    assignments[0].get("visible_destination_sids_v49", (None,))[0]
                    if assignments else None
                ),
                "text": "        | %-21s MATERIALIZATION BLOCK" % block,
            })
            for ordinal, assignment in enumerate(assignments, 1):
                destinations = tuple(
                    assignment.get("visible_destination_sids_v49", ()) or ()
                )
                count = max(1, int(
                    assignment.get("occurrence_count", 0) or 0
                ))
                suffix = "  [x%d]" % count if count > 1 else ""
                rows.append({
                    "kind": "dropin_code",
                    "block_hotspot": True,
                    "address": block,
                    "addr": block,
                    "output_sid": destinations[0] if destinations else None,
                    "sid": destinations[0] if destinations else None,
                    "destination_sids": destinations,
                    "dropin_id": "%s:%s:focal-v49" % (
                        self.model.projection, block
                    ),
                    "dropin_index": group_index,
                    "line_number": min(
                        assignment.get("line_numbers", ()) or (0,)
                    ),
                    "full_data_item": True,
                    "text": "          [%d] %s%s" % (
                        ordinal,
                        str(assignment.get("text") or "").strip(),
                        suffix,
                    ),
                })
        return rows, tuple(ordered_sids)

    def _three_rebuild_phi_rows(self, preferred_sid=None):
        """Build direct focal drop-ins or the full materialized inventory.

        Focal scope has no variable-root menu: all accepted assignments in the
        current block are displayed immediately.  FULL scope unfolds every
        materialized Φ into its own drop-in blade, ordered by block/write activity.
        """
        three = self._three
        if three is None:
            return
        state = three["states"]["phi"]
        old_rows = list(three.get("phi_rows", ()) or ())
        cursor_snapshot = self._phi_remember_cursor_v29(old_rows, state)
        focus = self.model._canonical_block_addr_v21(
            three.get("base_focus") or three.get("focus")
        )
        full_scope = bool(three.get("phi_materialization_full_v48"))
        inventory = list(self.model.materialized_variable_inventory_v48(
            block_addr=focus,
            projection=self.model.projection,
            full_scope=full_scope,
        ) or ())

        if not full_scope:
            rows, ordered_sids = self._phi_focal_dropin_rows_v49(
                focus, inventory
            )
            selected = str(preferred_sid or three.get("selected_phi_sid") or "")
            if selected not in set(ordered_sids):
                selected = str(ordered_sids[0]) if ordered_sids else ""
            three["selected_phi_sid"] = selected or None
            three["selected_dropin_id"] = None
            three["phi_mode"] = "materialized_focal_direct_v49"
            three["phi_list_rows"] = list(rows)
            three["phi_detail_rows"] = []
            three["phi_rows"] = list(rows)
            self._phi_restore_cursor_v29(
                rows,
                state,
                snapshot=cursor_snapshot,
                preferred_sid=three.get("selected_phi_sid"),
            )
            return

        inventory = sorted(
            (dict(item or {}) for item in inventory),
            key=self._materialized_activity_sort_v51,
        )
        valid = {str(item.get("output_sid") or "") for item in inventory}
        selected = str(preferred_sid or three.get("selected_phi_sid") or "")
        if selected not in valid:
            selected = str(inventory[0].get("output_sid") if inventory else "")
        three["selected_phi_sid"] = selected or None
        three["selected_dropin_id"] = None
        three["phi_mode"] = "materialized_full_blades_v51"
        rows = self._phi_materialized_full_blades_v51(inventory)
        three["phi_list_rows"] = list(rows)
        three["phi_detail_rows"] = []
        three["phi_rows"] = list(rows)
        self._phi_restore_cursor_v29(
            rows,
            state,
            snapshot=cursor_snapshot,
            preferred_sid=three.get("selected_phi_sid"),
        )

    def _three_clear_pointer_focus(self):
        three = self._three
        if three is None:
            return False
        three["pointer_focus"] = None
        three["code_highlight_block"] = None
        three["phi_stack_zoom"] = None
        three["asm_rows"] = list(three.get("asm_base_rows", ()) or ())
        state = three["states"]["asm"]
        choices = self._three_selectable("asm", three["asm_rows"])
        if choices:
            state["line"] = choices[0]
            state["top"] = max(0, choices[0] - 1)
        return True

    def _three_toggle_pointer_focus(self, row_or_address):
        three = self._three
        row = dict(row_or_address or {}) if isinstance(row_or_address, dict) else {}
        address = row.get("address") if row else row_or_address
        canonical = self.model._canonical_block_addr_v21(address)
        if canonical is None:
            self.status = "selected PHI row has no block pointer"
            return False
        if three.get("pointer_focus") == canonical:
            self._three_clear_pointer_focus()
            self.status = "PHI block focus cleared; cumulative ASM restored"
            return False

        # The rendered PHI custody blade is the execution-address stack.
        # Find the selected hotspot and expose only its nearest distinct
        # predecessor/current/successor blocks in that literal display order.
        phi_rows = list(three.get("phi_rows", ()) or ())
        cursor_index = int(three["states"]["phi"].get("line", 0) or 0)

        # A dependency bundle can contain several singular PHI blades.  The
        # transition slider must not jump across node boundaries: find the
        # current three-row authority header and stop at the next one.
        segment_start = 0
        for index in range(min(cursor_index, len(phi_rows) - 1), -1, -1):
            if dict(phi_rows[index] or {}).get("kind") in (
                "header_top", "dropin_summary", "dropin_sequence_header"
            ):
                segment_start = index
                break
        segment_end = len(phi_rows)
        for index in range(cursor_index + 1, len(phi_rows)):
            if dict(phi_rows[index] or {}).get("kind") in (
                "header_top", "dropin_summary", "dropin_sequence_header"
            ):
                segment_end = index
                break

        hotspots = []
        for index in range(segment_start, segment_end):
            candidate_row = dict(phi_rows[index] or {})
            if not candidate_row.get("block_hotspot"):
                continue
            candidate = self.model._canonical_block_addr_v21(candidate_row.get("address"))
            if candidate is not None:
                hotspots.append((index, candidate))
        current_pos = next((
            position for position, (index, address) in enumerate(hotspots)
            if index == cursor_index and address == canonical
        ), None)
        if current_pos is None:
            current_pos = next((
                position for position, (index, address) in enumerate(hotspots)
                if address == canonical and index >= cursor_index
            ), None)
        if current_pos is None:
            current_pos = next((
                position for position, (index, address) in enumerate(hotspots)
                if address == canonical
            ), 0)

        previous = None
        for position in range(int(current_pos) - 1, -1, -1):
            candidate = hotspots[position][1]
            if candidate != canonical:
                previous = candidate
                break
        following = None
        for position in range(int(current_pos) + 1, len(hotspots)):
            candidate = hotspots[position][1]
            if candidate != canonical:
                following = candidate
                break

        selected_sid = three.get("selected_phi_sid")
        self._three_set_focus(
            canonical, "phi", source_row=row,
            source_index=int(three["states"]["phi"].get("line", 0) or 0),
            initialize=False,
        )
        if selected_sid:
            three["selected_phi_sid"] = str(selected_sid)
            self._three_rebuild_phi_rows(preferred_sid=str(selected_sid))
        three["pointer_focus"] = canonical
        three["code_highlight_block"] = canonical

        if three.get("branch_focus_v35"):
            # A PHI hotspot becomes the new linkage root, but conditional branch
            # mode remains a complete source/forks/join ASM surface.
            branch_rows = list(three.get("asm_rows", ()) or ())
            three["branch_role_by_block_v25"] = self._asm_branch_role_map_v25(
                branch_rows
            )
            three["asm_hover_block_v25"] = canonical
            three["asm_hover_role_v25"] = dict(
                three.get("branch_role_by_block_v25", {}) or {}
            ).get(canonical)
            asm_state = three["states"]["asm"]
            choices = self._three_selectable("asm", branch_rows)
            preferred = next((
                index for index in choices
                if self.model._canonical_block_addr_v21(
                    dict(branch_rows[index] or {}).get("addr")
                ) == canonical
            ), None)
            if preferred is not None:
                asm_state["line"] = preferred
                asm_state["top"] = max(0, preferred - 2)
                asm_state["focus"] = preferred
            three["phi_stack_zoom"] = None
            self.status = (
                "PHI root %s linked into persistent branch ASM; CODE refreshed"
                % canonical
            )
            return True

        three["phi_stack_zoom"] = {
            "previous": previous, "current": canonical, "next": following,
            "position": int(current_pos), "size": len(hotspots),
        }
        three["asm_rows"] = list(self.model.asm_phi_stack_zoom_rows_v32(
            previous, canonical, following,
        ) or ())
        state = three["states"]["asm"]
        choices = self._three_selectable("asm", three["asm_rows"])
        preferred = next((
            index for index in choices
            if self.model._canonical_block_addr_v21(
                three["asm_rows"][index].get("addr")
            ) == canonical
        ), choices[0] if choices else 0)
        state["line"] = preferred
        state["top"] = max(0, preferred - 2)
        self.status = "PHI transition zoom %s [%d/%d]" % (
            canonical, int(current_pos) + 1, max(1, len(hotspots)),
        )
        return True


    def _three_link_from_asm_cursor_v25(self, rows=None, state=None):
        """Refresh PHI and CODE from the ASM row under the keyboard cursor.

        This is deliberately additive.  It never rebuilds or narrows the ASM
        listing, so a conditional branch continues to show source, both forks,
        and the completion/join while cursor movement changes the linked root.
        """
        three = self._three
        if three is None:
            return False
        rows = list(rows if rows is not None else three.get("asm_rows", ()) or ())
        state = state if state is not None else three["states"]["asm"]
        block = self._asm_cursor_block_v25(rows, state)
        if block is None:
            self.status = "ASM cursor row owns no machine block; linkage retained"
            return False

        role_map = self._asm_branch_role_map_v25(rows)
        role = role_map.get(block)
        three["branch_role_by_block_v25"] = role_map
        three["asm_hover_block_v25"] = block
        three["asm_hover_role_v25"] = role
        three["base_focus"] = block
        three["focus"] = block
        three["source"] = "asm"
        three["pointer_focus"] = None
        three["phi_stack_zoom"] = None
        three["code_highlight_block"] = block
        three["statement_context"] = {}

        code_matches = [
            index for index, owner in enumerate(three.get("blocks", ()) or ())
            if self.model._canonical_block_addr_v21(owner) == block
        ]
        if code_matches:
            code_state = three["states"]["code"]
            code_state["line"] = code_matches[0]
            code_state["top"] = max(0, code_matches[0] - 2)
            code_state["focus"] = code_matches[0]
            self._refresh_model_code_for_block_v24(
                block,
                projection=self.model.projection,
                preferred_line=code_matches[0],
            )

        classification = self.model.phi_paths_for_focal_block_v47(
            block,
            statement_context=None,
            rows=three.get("all_paths", ()),
            projection=self.model.projection,
        )
        phi_active = list(classification.get("active", ()) or ())
        phi_passive = list(classification.get("passive", ()) or ())
        phi_matches = list(classification.get("all", ()) or ())
        three["block_activity_v47"] = dict(
            classification.get("activity", {}) or {}
        )
        three["phi_active_matches_v47"] = phi_active
        three["phi_passive_matches_v47"] = phi_passive
        three["phi_matches"] = phi_matches
        selected_sid = str(three.get("selected_phi_sid") or "")
        active_sids = {
            str(row.get("output_sid") or "") for row in phi_active
        }
        preferred_sid = (
            selected_sid if selected_sid in active_sids
            else str(phi_active[0].get("output_sid") or "")
            if phi_active else selected_sid or None
        )
        self._three_rebuild_phi_rows(preferred_sid=preferred_sid)

        suffix = ""
        if role:
            suffix = " [%s]" % role.upper()
        self.status = (
            "ASM hover root %s%s -> PHI %d chain(s), CODE %d line(s); "
            "branch ASM retained"
        ) % (block, suffix, len(phi_matches), len(code_matches))
        return True


    def _three_set_focus(
        self, value, source, source_row=None, source_index=None, initialize=False
    ):
        canonical = self.model._canonical_block_addr_v21(value)
        if canonical is None:
            self.status = "focus retained; selected row owns no CFG block"
            return False
        three = self._three
        source_state = dict(three["states"].get(source, {}) or {})
        old_line = int(source_state.get("line", 0))
        old_top = int(source_state.get("top", 0))
        relative_row = max(0, old_line - old_top)
        source_identity = self._three_row_identity(source_row) if source_row else None

        three["base_focus"] = canonical
        three["focus"] = canonical
        three["source"] = str(source)
        self._three_clear_pointer_focus()
        code_matches = [
            index for index, block in enumerate(three["blocks"])
            if block == canonical
        ]
        direct_jump = bool(dict(source_row or {}).get("jump_target")) if source == "asm" else False
        code_topology = (
            self.model.asm_branch_topology_for_block_v26(canonical)
            if source == "code" else None
        )
        existing_role_map = dict(three.get("branch_role_by_block_v25", {}) or {})
        existing_branch_contains_focus = bool(
            three.get("branch_focus_v35")
            and three.get("asm_rows")
            and canonical in existing_role_map
        )
        branch_resident = bool(code_topology or existing_branch_contains_focus)
        if code_topology:
            asm_rows = list(code_topology.get("rows", ()) or ())
            three["branch_focus_v35"] = {
                "source": code_topology.get("source"),
                "target": code_topology.get("target"),
            }
            three["branch_role_by_block_v25"] = dict(
                code_topology.get("role_map", {}) or {}
            )
            three["asm_hover_block_v25"] = canonical
            three["asm_hover_role_v25"] = dict(
                three.get("branch_role_by_block_v25", {}) or {}
            ).get(canonical)
        elif existing_branch_contains_focus:
            asm_rows = list(three.get("asm_rows", ()) or ())
            three["branch_role_by_block_v25"] = self._asm_branch_role_map_v25(asm_rows)
            three["asm_hover_block_v25"] = canonical
            three["asm_hover_role_v25"] = dict(
                three.get("branch_role_by_block_v25", {}) or {}
            ).get(canonical)
        elif direct_jump:
            three["branch_focus_v35"] = None
            three["branch_role_by_block_v25"] = {}
            asm_rows = list(self.model.asm_debug_focus_rows_v34(
                canonical, relation="DIRECT JUMP TARGET"
            ) or ())
        else:
            three["branch_focus_v35"] = None
            three["branch_role_by_block_v25"] = {}
            three["asm_hover_block_v25"] = canonical
            three["asm_hover_role_v25"] = None
            asm_rows = list(self.model.asm_path_focus_rows_v21(canonical) or ())
        asm_headers = [
            index for index, row in enumerate(asm_rows)
            if row.get("kind") == "block"
        ]
        context = {}
        if source == "code":
            context = dict(dict(source_row or {}).get("statement_context") or {})
            if not context and source_index is not None:
                contexts = list(three.get("statement_contexts", ()) or ())
                if 0 <= int(source_index) < len(contexts):
                    context = dict(contexts[int(source_index)] or {})
        classification = self.model.phi_paths_for_focal_block_v47(
            canonical,
            statement_context=context,
            rows=three["all_paths"],
            projection=self.model.projection,
        )
        phi_active = list(classification.get("active", ()) or ())
        phi_passive = list(classification.get("passive", ()) or ())
        phi_matches = list(classification.get("all", ()) or ())
        three["statement_context"] = context
        three["block_activity_v47"] = dict(
            classification.get("activity", {}) or {}
        )
        if not code_matches or not asm_headers:
            phi_active = []
            phi_passive = []
            phi_matches = []
        three["phi_active_matches_v47"] = phi_active
        three["phi_passive_matches_v47"] = phi_passive
        three["phi_matches"] = phi_matches
        if branch_resident:
            # Conditional branch mode is a persistent evidence surface.  PHI or
            # CODE focus may move its cursor, but must not collapse the listing.
            three["asm_rows"] = list(asm_rows)
            three["asm_base_rows"] = list(asm_rows)
        else:
            three["asm_base_rows"] = asm_rows or [{
                "kind": "empty", "text": "No ASM containment for %s." % canonical,
            }]
            three["asm_rows"] = list(three["asm_base_rows"])
        preferred_sid = next(iter(
            dict(three.get("statement_context") or {}).get(
                "destination_sids", ()
            ) or ()
        ), None)
        if preferred_sid is None and phi_active:
            preferred_sid = str(phi_active[0].get("output_sid") or "") or None
        self._three_rebuild_phi_rows(preferred_sid=preferred_sid)

        if source != "code" and code_matches:
            code_state = three["states"]["code"]
            code_state["line"] = code_matches[0]
            code_state["top"] = max(0, code_matches[0] - 2)
            code_state["focus"] = None
        if source != "asm" and asm_headers:
            asm_state = three["states"]["asm"]
            exact_header = next((
                index for index in asm_headers
                if self.model._canonical_block_addr_v21(
                    dict(asm_rows[index] or {}).get("addr")
                ) == canonical
            ), asm_headers[0])
            asm_state["line"] = exact_header
            asm_state["top"] = max(0, exact_header - 1)
            asm_state["focus"] = exact_header if branch_resident else None
            if branch_resident:
                three["asm_hover_block_v25"] = canonical
                three["asm_hover_role_v25"] = dict(
                    three.get("branch_role_by_block_v25", {}) or {}
                ).get(canonical)

        if source in three["states"]:
            rows = self._three_rows(source)
            target = self._three_find_identity(rows, source_identity)
            if target is None and source == "code":
                candidate = old_line if source_index is None else int(source_index)
                if 0 <= candidate < len(rows):
                    target = candidate
            if target is None:
                choices = self._three_selectable(source, rows)
                target = choices[0] if choices else 0
            state = three["states"][source]
            state.update(source_state)
            state["line"] = int(target)
            state["top"] = max(0, int(target) - relative_row)
            if source == "asm":
                self._asm_align_viewport_v27(rows, state)
        topology_suffix = (
            " [full branch/fork/join ASM]" if code_topology else
            " [statement-owned PHI]" if source == "code" else ""
        )
        self.status = "cross-section %s from %s%s" % (
            canonical, source, topology_suffix,
        )
        return True

    @staticmethod
    def _vertical_rectangles(body_top, body_height, width):
        left = int(width * 0.31)
        center = int(width * 0.35)
        return {
            "phi": (body_top, 0, body_height, left),
            "asm": (body_top, left, body_height, center),
            "code": (body_top, left + center, body_height, width - left - center),
        }

    def _three_rows(self, pane):
        if pane == "phi":
            return self._three["phi_rows"]
        if pane == "asm":
            return self._three["asm_rows"]
        contexts = list(self._three.get("statement_contexts", ()) or ())
        return [
            {
                "kind": "code", "text": value,
                "block": self._three["blocks"][index]
                if index < len(self._three["blocks"]) else None,
                "statement_context": contexts[index] if index < len(contexts) else {},
            }
            for index, value in enumerate(self._three["lines"])
        ]

    def _draw_vertical_pane(self, pane, rect, rows, active):
        y, x, pane_h, pane_w = rect
        if pane_h < 3 or pane_w < 8:
            return
        state = self._three["states"][pane]
        inner_h = max(1, pane_h - 2)
        if pane == "asm":
            self._asm_align_viewport_v27(rows, state, inner_h)
        choices = self._three_selectable(pane, rows)
        if choices and state["line"] not in choices:
            state["line"] = choices[0]
        if state["line"] < state["top"]:
            state["top"] = state["line"]
        elif state["line"] >= state["top"] + inner_h:
            state["top"] = state["line"] - inner_h + 1
        state["top"] = min(max(0, int(state["top"])), max(0, len(rows) - inner_h))
        role = "active_header" if active else "phi_header" if pane == "phi" else "helper"
        horizontal = "=" if active else "-"
        self._add(y, x, "+" + horizontal * max(0, pane_w - 2) + "+", self._attr(role, bold=True), pane_w)
        self._add(y + pane_h - 1, x, "+" + horizontal * max(0, pane_w - 2) + "+", self._attr(role, bold=True), pane_w)
        for row_y in range(y + 1, y + pane_h - 1):
            self._add(row_y, x, "|", self._attr(role, bold=True), 1)
            self._add(row_y, x + pane_w - 1, "|", self._attr(role, bold=True), 1)
        focus_label = self._three.get("pointer_focus") or self._three.get("base_focus") or "-"
        code_title = "READ.PY" if self.model.projection == "readable" else "EXEC.PY"
        asm_title = (
            "ASM / BRANCH FORKS + JOIN [BLOCK NAV]"
            if pane == "asm" and self._three.get("branch_focus_v35")
            else "ASM / PHI TRANSITION ZOOM [BLOCK NAV]"
            if pane == "asm" and self._three.get("pointer_focus")
            else "ASM CONTAINMENT [BLOCK NAV]"
        )
        phi_title = (
            "PHI MATERIALIZATION [FULL]"
            if self._three.get("phi_mode") in (
                "materialized_full_v48", "materialized_full_v49",
                "materialized_full_blades_v51",
            )
            else "PHI MATERIALIZATION"
            if self._three.get("phi_mode") in (
                "materialized_focal_v48", "materialized_focal_direct_v49",
            )
            else "PHI DROP-IN PATHS"
            if self._three.get("phi_mode") == "focal_dropin_paths"
            else "PHI FOCAL BLOCK"
            if self._three.get("phi_mode") == "focal_block_truth"
            else "PHI CROSS-SECTION"
        )
        title = " %s%s | focus=%s " % (
            phi_title if pane == "phi"
            else asm_title if pane == "asm" else code_title,
            " [ACTIVE]" if active else "", focus_label,
        )
        self._add(y, x + 2, title, self._attr(role, bold=True), max(0, pane_w - 4))
        text_x = x + 2
        text_w = max(1, pane_w - 4)
        left = max(0, int(state["left"]))
        query = self._paint_query_v39("three:%s" % pane)
        base_focus = self._three.get("base_focus")
        pointer_focus = self._three.get("code_highlight_block")
        branch_roles = dict(self._three.get("branch_role_by_block_v25", {}) or {})
        hover_block = self.model._canonical_block_addr_v21(
            self._three.get("asm_hover_block_v25")
        )
        asm_hover_indices = (
            self._asm_hover_group_indices_v30(rows, hover_block)
            if pane == "asm" else frozenset()
        )
        code_base = {index for index, block in enumerate(self._three["blocks"]) if block == base_focus} if pane == "code" else set()
        code_pointer = {index for index, block in enumerate(self._three["blocks"]) if block == pointer_focus} if pane == "code" and pointer_focus else set()
        for offset in range(inner_h):
            index = int(state["top"]) + offset
            sy = y + 1 + offset
            if index >= len(rows):
                continue
            row = dict(rows[index] or {})
            text = self._row_text(row)
            selected = index == int(state["line"])
            focused = index == state.get("focus")

            if pane == "phi" and row.get("kind") == "phi_section":
                self._add(sy, text_x, text[left:left + text_w].ljust(text_w), self._attr("phi_header", bold=True) | curses.A_REVERSE, text_w)
                continue
            if pane == "phi" and row.get("kind") == "phi_summary":
                authority_selected = str(row.get("output_sid") or "") == str(self._three.get("selected_phi_sid") or "")
                base = self._attr("active_header", bold=True) if authority_selected else self._attr("phi_list", bold=True)
                phi_role, phi_hovered = self._three_phi_branch_role_v25(row)
                phi_attr = self._branch_palette_attr_v25(
                    phi_role, hovered=phi_hovered
                )
                self._add(
                    sy, text_x, text[left:left + text_w].ljust(text_w),
                    phi_attr if phi_attr is not None else base, text_w,
                )
                # Top layers: readable red cursor surface, then final highlights.
                self._paint_active_cursor_bar_v45(
                    sy, text_x, text, left, text_w, selected and active
                )
                self._paint_search(
                    sy, text_x, text, query, left, text_w,
                    current=selected and active,
                )
                continue
            if pane == "phi" and row.get("kind") == "dropin_summary":
                authority_selected = (
                    str(row.get("dropin_id") or "")
                    == str(self._three.get("selected_dropin_id") or "")
                )
                base = (
                    self._attr("active_header", bold=True)
                    if authority_selected
                    else self._attr("phi_list", bold=True)
                )
                self._add(
                    sy, text_x,
                    text[left:left + text_w].ljust(text_w),
                    base, text_w,
                )
                self._paint_active_cursor_bar_v45(
                    sy, text_x, text, left, text_w,
                    selected and active,
                )
                self._paint_search(
                    sy, text_x, text, query, left, text_w,
                    current=selected and active,
                )
                continue
            if pane == "phi" and row.get("kind") == "dropin_sequence_header":
                self._add(
                    sy, text_x,
                    text[left:left + text_w].ljust(text_w),
                    self._attr("phi_header", bold=True)
                    | curses.A_REVERSE,
                    text_w,
                )
                continue
            if pane == "phi" and row.get("kind") == "phi_sequence_note":
                self._add(
                    sy, text_x,
                    text[left:left + text_w].ljust(text_w),
                    self._attr("helper", bold=False),
                    text_w,
                )
                continue
            if pane == "phi" and row.get("kind") == "phi_truth_note":
                truth_active = str(
                    row.get("block_activity_v47") or ""
                ) == "active"
                self._add(
                    sy, text_x,
                    text[left:left + text_w].ljust(text_w),
                    self._attr(
                        "phi_incoming_addr" if truth_active else "helper",
                        bold=truth_active,
                    ),
                    text_w,
                )
                self._paint_active_cursor_bar_v45(
                    sy, text_x, text, left, text_w,
                    selected and active,
                )
                self._paint_search(
                    sy, text_x, text, query, left, text_w,
                    current=selected and active,
                )
                continue
            if pane == "phi" and row.get("phi_template"):
                phi_role, phi_hovered = self._three_phi_branch_role_v25(row)
                phi_attr = self._branch_palette_attr_v25(
                    phi_role, hovered=phi_hovered
                )
                self._draw_phi_template_line(
                    sy, text_x, row, text, left, text_w,
                    selected=selected and active,
                    focused=focused,
                    query=query,
                    base_attr=phi_attr,
                )
                continue

            branch_paint = self._asm_branch_paint_role_v24(row) if pane == "asm" else None
            asm_hovered = bool(pane == "asm" and index in asm_hover_indices)
            code_block = (
                self.model._canonical_block_addr_v21(row.get("block"))
                if pane == "code" else None
            )
            code_hovered = bool(
                pane == "code" and hover_block is not None
                and code_block == hover_block
            )
            if asm_hovered:
                # Semantic block/linkage paint is a base surface.  The active
                # cursor and final token overlays are rendered above it.
                paint = self._link_hover_attr_v26()
            elif branch_paint:
                paint = self._attr(branch_paint, bold=True)
            elif pane == "asm" and row.get("kind") == "asm_relation":
                relation_role = str(row.get("relation_role") or "")
                paint = self._attr(
                    "asm_relation_current"
                    if relation_role == "current"
                    else "asm_transition_orange",
                    bold=True,
                )
            elif pane == "asm" and row.get("kind") == "rule" and row.get("relation_role"):
                paint = self._attr("asm_transition_orange", bold=True)
            elif pane == "code" and code_block in branch_roles:
                paint = self._branch_palette_attr_v25(
                    branch_roles.get(code_block), hovered=code_hovered
                )
            elif pane == "code" and index in code_pointer:
                paint = self._attr("phi_incoming_addr", bold=True) | curses.A_REVERSE
            elif pane == "code" and index in code_base:
                paint = self._attr("highlight", bold=True)
            elif pane == "asm" and row.get("kind") == "block":
                paint = self._attr("asm_block_header", bold=True)
            elif pane == "asm" and row.get("asm_role") == "jump":
                paint = self._attr("asm_jump_red", bold=True)
            elif pane == "asm" and row.get("asm_role") == "compare":
                paint = self._attr("asm_compare", bold=True)
            elif focused:
                paint = self._attr("phi_final", bold=True)
            else:
                paint = self._attr("default")
            self._add(
                sy, text_x, text[left:left + text_w].ljust(text_w),
                paint, text_w,
            )

            # Rendering stack, bottom to top:
            #   semantic/base surface
            #   red cursor bar with the font repainted
            #   final address/mnemonic/search overlays
            self._paint_active_cursor_bar_v45(
                sy, text_x, text, left, text_w,
                selected and active,
                underline=bool(
                    asm_hovered or branch_paint or code_hovered
                ),
            )

            if pane == "asm" and row.get("kind") == "asm":
                match = re.match(
                    r"\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})",
                    text,
                )
                if match:
                    a = max(match.start(1), left)
                    b = min(match.end(1), left + text_w)
                    if a < b:
                        self._add(
                            sy, text_x + a - left, text[a:b],
                            self._attr(
                                "asm_instruction_addr_on_hover"
                                if asm_hovered else "asm_instruction_addr",
                                bold=True,
                            ), b - a,
                        )
                self._paint_asm_jump_mnemonic_v26(
                    sy, text_x, text, left, text_w,
                    row, hovered=asm_hovered,
                )

            # Preserve the historical atomic ASM-hover surface.  Search remains
            # the final overlay everywhere else.
            if not (pane == "asm" and asm_hovered):
                self._paint_search(
                    sy, text_x, text, query, left, text_w,
                    current=selected and active,
                )


    def _draw_three(self, body_top, body_height, width):
        self._three_prepare()
        rects = self._vertical_rectangles(body_top, body_height, width)
        for index, pane in enumerate(self._three["panes"]):
            self._draw_vertical_pane(
                pane, rects[pane], self._three_rows(pane),
                index == self._three["active"],
            )

    def _switch_top(self, step):
        self.view_index = (self.view_index + int(step)) % len(self.VIEWS)
        self.status = "view %s" % self.LABELS[self.view]

    def _commit_active_history_cursor_v51(self):
        """Persist the current cursor into the active pane-owned history frame."""
        if self.menu_mode:
            return False
        if self.view == "three":
            self._three_prepare()
            pane = self._three["panes"][self._three["active"]]
            if pane == "phi":
                self._phi_remember_cursor_v29(
                    self._three_rows("phi"), self._three["states"]["phi"]
                )
                return self._phi_commit_history_frame_v46()
            if pane == "asm":
                return self._asm_commit_history_cursor_v24()
            return False
        if self.view == "asm":
            return self._asm_commit_history_cursor_v24()
        if self.view == "phi":
            return self._phi_commit_history_frame_v46()
        if self.view == "four":
            self._ensure_four()
            if self.owner.side_panes[self._four_active] == "asm":
                return self._asm_commit_history_cursor_v24()
        return False

    def _switch_pane(self, step):
        if self.view == "four":
            self._ensure_four()
            old_pane = self.owner.side_panes[self._four_active]
            if old_pane == "asm":
                self._asm_commit_history_cursor_v24()
            self._four_active = (
                self._four_active + int(step)
            ) % len(self.owner.side_panes)
            self.owner.side_active = self._four_active
            pane = self.owner.side_panes[self._four_active]
            if pane in ("readable", "executable"):
                self.owner.last_python_pane = pane
                self.owner._side_sync_model_cursor(pane)
                self.owner._side_sync_python_pair(pane)
            self.status = "pane %s | ASM history retained at %s" % (
                self.owner.side_titles[pane], self._asm_history_label_v34()
            )
            return
        if self.view == "three":
            self._three_prepare()
            old_pane = self._three["panes"][self._three["active"]]
            if old_pane == "phi":
                self._phi_remember_cursor_v29(
                    self._three_rows("phi"), self._three["states"]["phi"]
                )
                self._phi_commit_history_frame_v46()
            elif old_pane == "asm":
                self._asm_commit_history_cursor_v24()
            self._three["active"] = (
                self._three["active"] + int(step)
            ) % len(self._three["panes"])
            pane = self._three["panes"][self._three["active"]]
            if pane == "phi":
                phi_rows = self._three_rows("phi")
                phi_state = self._three["states"]["phi"]
                self._phi_restore_cursor_v29(
                    phi_rows,
                    phi_state,
                    snapshot=phi_state.get("_phi_cursor_v29"),
                    preferred_sid=self._three.get("selected_phi_sid"),
                )
                self.status = (
                    "pane PHI | cursor row %d | PHI history retained at %s"
                    % (int(phi_state.get("line", 0)) + 1,
                       self._phi_history_label_v46())
                )
            elif pane == "asm":
                self.status = "pane ASM | history retained at %s" % (
                    self._asm_history_label_v34()
                )
            else:
                self.status = "pane %s" % pane
            return
        self.status = "%s is a single-pane view" % self.LABELS[self.view]

    def _active_rows_state(self):
        if self.view == "four":
            self._ensure_four()
            pane = self.owner.side_panes[self._four_active]
            if pane == "asm" and self._four_asm_branch_rows_v35 is not None:
                rows = [dict(row or {}) for row in self._four_asm_branch_rows_v35]
            elif pane == "asm" and self._four_asm_rows_v34 is not None:
                rows = [dict(row or {}) for row in self._four_asm_rows_v34]
            else:
                rows = (
                    self._four_asm_navigation_rows_v27()
                    if pane == "asm"
                    else [{"kind": pane, "text": value} for value in self.owner._side_lines(pane)]
                )
            return pane, rows, self.owner.side_state[pane]
        if self.view == "three":
            self._three_prepare()
            pane = self._three["panes"][self._three["active"]]
            return pane, self._three_rows(pane), self._three["states"][pane]
        return self.view, self._one_rows(self.view), self.states[self.view]

    def _sync_four_after_selection(self, pane):
        if pane in ("readable", "executable"):
            self._four_asm_focus_v34 = None
            self._four_asm_rows_v34 = None
            self._four_asm_branch_rows_v35 = None
            self.owner.last_python_pane = pane
            self.owner._side_sync_model_cursor(pane)
        self.owner._side_refresh_linkage(pane)

    def _sync_three_after_selection(self, pane, rows, state):
        """Live-link ASM cursor movement into PHI and Python without collapsing ASM.

        STATIC DEBUG treats the selected ASM block as a transient root refresher.
        The complete branch/fork/join listing remains resident while PHI and CODE
        move to and repaint the block currently under the ASM cursor.
        """
        if pane != "asm" or self._three is None:
            return False
        return self._three_link_from_asm_cursor_v25(rows=rows, state=state)

    def _move(self, key):
        pane, rows, state = self._active_rows_state()
        if not rows:
            return
        if pane == "asm":
            choices = self._asm_block_choices_v27(rows)
        elif self.view == "three":
            choices = self._three_selectable(pane, rows)
        elif self.view == "phi":
            choices = [
                index for index, row in enumerate(rows)
                if row.get("kind") == "phi_summary" or row.get("block_hotspot")
            ]
        elif self.view == "detail":
            choices = [
                index for index, row in enumerate(rows)
                if row.get("kind") == "var_row"
            ]
        else:
            choices = list(range(len(rows)))
        if not choices:
            return
        try:
            position = choices.index(int(state["line"]))
        except ValueError:
            position = 0
        height, unused_width = self.screen.getmaxyx()
        page = max(1, height - 9)
        changed = False
        if key in (curses.KEY_DOWN, "j"):
            position = min(len(choices) - 1, position + 1); changed = True
        elif key in (curses.KEY_UP, "k"):
            position = max(0, position - 1); changed = True
        elif key == curses.KEY_NPAGE:
            position = min(len(choices) - 1, position + page); changed = True
        elif key == curses.KEY_PPAGE:
            position = max(0, position - page); changed = True
        elif key in (curses.KEY_HOME, "g"):
            position = 0; changed = True
        elif key in (curses.KEY_END, "G"):
            position = len(choices) - 1; changed = True
        elif key == curses.KEY_LEFT:
            if self.view == "detail":
                state["action"] = max(0, int(state.get("action", 0)) - 1)
                self.status = "variable destination: %s" % (
                    "PHI DETAIL" if int(state["action"]) == 0 else "STATIC DEBUG"
                )
            else:
                state["left"] = max(0, int(state.get("left", 0)) - 4)
        elif key in (curses.KEY_RIGHT, "l"):
            if self.view == "detail":
                state["action"] = min(1, int(state.get("action", 0)) + 1)
                self.status = "variable destination: %s" % (
                    "PHI DETAIL" if int(state["action"]) == 0 else "STATIC DEBUG"
                )
            else:
                state["left"] = int(state.get("left", 0)) + 4
        else:
            return
        if changed:
            state["line"] = choices[position]
            if pane == "phi":
                self._phi_remember_cursor_v29(rows, state)
            if pane == "asm":
                self._asm_align_viewport_v27(rows, state)
            if self.view == "four":
                self._sync_four_after_selection(pane)
            elif self.view == "three":
                self._sync_three_after_selection(pane, rows, state)
            if pane == "asm":
                self._asm_block_action_status_v28(rows, state)

    def _move_match(self, step):
        pane, rows, state = self._active_rows_state()
        # Search is literal and complete in every pane; a hit on a custody or
        # instruction line preserves that exact local cursor while linkage uses
        # the row's frozen address.
        if pane == "asm":
            matches = self._asm_block_matches_v27(rows, self._search())
        else:
            selectable = list(range(len(rows)))
            matches = self._matching(rows, self._search(), selectable=selectable)
        if not matches:
            self.status = "no matches for /%s" % (self._search() or "-")
            return
        current = int(state["line"])
        if int(step) >= 0:
            candidates = [value for value in matches if value > current]
            target = candidates[0] if candidates else matches[0]
        else:
            candidates = [value for value in matches if value < current]
            target = candidates[-1] if candidates else matches[-1]
        state["line"] = target
        if pane == "phi":
            self._phi_remember_cursor_v29(rows, state)
        if pane == "asm":
            self._asm_align_viewport_v27(rows, state)
        self.status = "%s match %d/%d" % (
            "ASM block" if pane == "asm" else "match",
            matches.index(target) + 1, len(matches),
        )
        if self.view == "four":
            self._sync_four_after_selection(pane)
        elif self.view == "three":
            self._sync_three_after_selection(pane, rows, state)
        if pane == "asm":
            self._asm_block_action_status_v28(rows, state)

    def _commit_code_cursor(self):
        if self.view == "four":
            self._ensure_four()
            pane = self.owner.side_panes[self._four_active]
            if pane in ("readable", "executable"):
                self.owner._side_sync_model_cursor(pane)
            else:
                self.owner._side_sync_model_cursor(self.owner.last_python_pane)
            return
        if self.view == "three":
            self._three_prepare()
            state = self._three["states"]["code"]
            lines = self._three["lines"]
            line = min(max(0, int(state["line"])), max(0, len(lines) - 1))
            self.model.line = line
            self.model.column = min(
                max(0, int(state.get("column", 0))),
                len(lines[line]) if lines else 0,
            )
            self.model.top_line = int(state.get("top", 0))
            self.model.left_column = int(state.get("left", 0))
            self.model.clamp()
            self.model.update_cursor_context()

    def _active_python_projection_v40(self):
        """Return the active Python pane projection, or None outside CODE."""
        if self.menu_mode:
            return None
        if self.view == "four":
            self._ensure_four()
            pane = self.owner.side_panes[self._four_active]
            return pane if pane in ("readable", "executable") else None
        if self.view == "three":
            self._three_prepare()
            pane = self._three["panes"][self._three["active"]]
            return self.model.projection if pane == "code" else None
        return None

    def _export_active_python_v41(self):
        visible_projection = self._active_python_projection_v40()
        if visible_projection is None:
            self.status = "Ctrl-E PY.EXEC requires an active Python CODE pane; source is always EXEC"
            return False
        try:
            self._commit_code_cursor()
            result = self.model.export_execute_function_v41()
            self.status = self.model.status
            return result
        except Exception as exc:
            self.status = "Ctrl-E PY.EXEC failed: %s" % exc
            return False

    def _export_active_python_v40(self):
        return self._export_active_python_v41()

    def _active_is_asm_v34(self):
        if self.menu_mode:
            return False
        if self.view == "asm":
            return True
        if self.view == "three" and self._three is not None:
            return self._three["panes"][self._three["active"]] == "asm"
        if self.view == "four":
            return self.owner.side_panes[self._four_active] == "asm"
        return False

    def _maybe_show_large_loader_v35(self, target):
        loc = _model_loc_v35(self.model)
        key = (str(target).upper(), int(loc))
        if loc > LARGE_FUNCTION_LOC_THRESHOLD_V35 and key not in self._large_loader_seen_v35:
            _show_large_metadata_loader_v35(self.screen, loc, target)
            self._large_loader_seen_v35.add(key)
            return True
        return False

    @staticmethod
    def _history_state_copy_v24(state):
        state = dict(state or {})
        copied = {
            key: state.get(key)
            for key in ("line", "top", "left", "column", "focus", "action")
            if key in state
        }
        if state.get("_phi_cursor_v29"):
            copied["_phi_cursor_v29"] = dict(state["_phi_cursor_v29"])
        return copied

    def _asm_capture_history_cursor_v24(self):
        """Capture exact pane/model cursors for one linked ASM history frame."""
        snapshot = {
            "view": self.view,
            "projection": self.model.projection,
            "model": {
                "line": int(getattr(self.model, "line", 0) or 0),
                "column": int(getattr(self.model, "column", 0) or 0),
                "top": int(getattr(self.model, "top_line", 0) or 0),
                "left": int(getattr(self.model, "left_column", 0) or 0),
            },
        }
        if self.view == "three":
            self._three_prepare()
            snapshot.update({
                "active": int(self._three.get("active", 1) or 1),
                "states": {
                    pane: self._history_state_copy_v24(state)
                    for pane, state in dict(self._three.get("states", {}) or {}).items()
                },
                "selected_phi_sid": self._three.get("selected_phi_sid"),
            })
        elif self.view == "four":
            self._ensure_four()
            snapshot.update({
                "active": int(self._four_active),
                "last_python_pane": self.owner.last_python_pane,
                "states": {
                    pane: self._history_state_copy_v24(state)
                    for pane, state in dict(self.owner.side_state or {}).items()
                },
            })
        elif self.view == "asm":
            snapshot["states"] = {
                "asm": self._history_state_copy_v24(self.states.get("asm", {}))
            }
        return snapshot

    def _asm_commit_history_cursor_v24(self):
        if not self._asm_history_v34 or not (
            0 <= self._asm_history_index_v34 < len(self._asm_history_v34)
        ):
            return False
        self._asm_history_v34[self._asm_history_index_v34]["cursor_snapshot"] = (
            self._asm_capture_history_cursor_v24()
        )
        return True

    def _refresh_model_code_for_block_v24(
        self, focus, projection=None, preferred_line=None
    ):
        """Make a focused CFG target the root of the hidden/current code view."""
        focus = self.model._canonical_block_addr_v21(focus)
        if focus is None:
            return False
        candidates = []
        for value in (projection, self.model.projection, "readable", "executable"):
            if value in ("readable", "executable") and value not in candidates:
                candidates.append(value)
        for pane in candidates:
            try:
                blocks = list(self.model.projection_block_map_v21(
                    pane, allow_cursor_fallback=False
                ) or ())
                lines = list(self.model.oncs.render_lines(
                    pane, self.model.naming, self.model.operator_overlay
                ) or ())
            except Exception:
                continue
            matches = [index for index, block in enumerate(blocks) if block == focus]
            if not matches:
                continue
            line = matches[0]
            if preferred_line is not None:
                preferred = int(preferred_line)
                if 0 <= preferred < len(blocks) and blocks[preferred] == focus:
                    line = preferred
            self.model.projection = pane
            self.model.line = line
            self.model.column = min(
                max(0, int(getattr(self.model, "column", 0) or 0)),
                len(lines[line]) if 0 <= line < len(lines) else 0,
            )
            self.model.top_line = max(0, line - 2)
            self.model.clamp()
            self.model.update_cursor_context()
            return True
        return False

    def _asm_restore_history_cursor_v24(self, frame, focus):
        snapshot = dict(dict(frame or {}).get("cursor_snapshot") or {})
        if not snapshot or snapshot.get("view") != self.view:
            self._refresh_model_code_for_block_v24(
                focus, projection=dict(frame or {}).get("projection")
            )
            return False
        states = dict(snapshot.get("states", {}) or {})
        if self.view == "three":
            self._three_refresh_code()
            for pane, saved in states.items():
                if pane in self._three["states"]:
                    self._three["states"][pane].update(dict(saved or {}))
            self._three["active"] = int(snapshot.get("active", self._three["active"]))
            code_state = self._three["states"]["code"]
            preferred = int(code_state.get("line", 0) or 0)
            self._refresh_model_code_for_block_v24(
                focus, projection=snapshot.get("projection"),
                preferred_line=preferred,
            )
            self._three_refresh_code()
            code_state["line"] = int(self.model.line)
            code_state["top"] = int(self.model.top_line)
            code_state["column"] = int(self.model.column)
            code_state["left"] = int(self.model.left_column)
            self._asm_align_viewport_v27(
                self._three_rows("asm"), self._three["states"]["asm"]
            )
        elif self.view == "four":
            for pane, saved in states.items():
                if pane in self.owner.side_state:
                    self.owner.side_state[pane].update(dict(saved or {}))
            self._four_active = int(snapshot.get("active", self._four_active))
            self.owner.side_active = self._four_active
            anchor = str(snapshot.get("last_python_pane") or self.owner.last_python_pane)
            if anchor not in ("readable", "executable"):
                anchor = "readable"
            self.owner.last_python_pane = anchor
            self._refresh_model_code_for_block_v24(
                focus, projection=anchor,
                preferred_line=self.owner.side_state[anchor].get("line"),
            )
            self.owner.side_state[anchor].update({
                "line": int(self.model.line), "top": int(self.model.top_line),
                "column": int(self.model.column), "left": int(self.model.left_column),
            })
            self._asm_align_viewport_v27(
                self._four_asm_navigation_rows_v27(), self.owner.side_state["asm"]
            )
            self.owner._side_sync_python_pair(anchor)
        elif self.view == "asm":
            self.states["asm"].update(dict(states.get("asm", {}) or {}))
            self._asm_align_viewport_v27(
                self._one_rows("asm"), self.states["asm"]
            )
            model_state = dict(snapshot.get("model", {}) or {})
            self._refresh_model_code_for_block_v24(
                focus, projection=snapshot.get("projection"),
                preferred_line=model_state.get("line"),
            )
        return True

    def _asm_reset_history_v35(self, reason="ASM focus regained"):
        self._asm_history_v34 = []
        self._asm_history_index_v34 = -1
        self.status = "%s; ASM history cleared" % reason

    @staticmethod
    def _asm_history_step_for_key_v37(key):
        """Normalize angle-bracket history keys across curses/terminal variants.

        Some terminals report Shift-comma / Shift-period as the printable angle
        bracket, while others discard the Shift modifier and deliver the
        physical comma/period key.  Both forms are accepted.  Shifted-arrow
        keycodes and their common raw escape sequences are accepted as a final
        compatibility path, but the visible contract remains ``<`` / ``>``.
        """
        if isinstance(key, str):
            if key in ("<", ",", "\x1b[1;2D", "\x1b[1;2;3D"):
                return -1
            if key in (">", ".", "\x1b[1;2C", "\x1b[1;2;3C"):
                return 1
            return None
        if isinstance(key, int):
            if key in (
                ord("<"), ord(","),
                getattr(curses, "KEY_SLEFT", -10001),
            ):
                return -1
            if key in (
                ord(">"), ord("."),
                getattr(curses, "KEY_SRIGHT", -10002),
            ):
                return 1
            try:
                name = curses.keyname(key)
                if isinstance(name, bytes):
                    name = name.decode("ascii", "ignore")
                name = str(name or "").upper()
            except Exception:
                name = ""
            if name in ("<", ",", "KEY_SLEFT", "KLFT"):
                return -1
            if name in (">", ".", "KEY_SRIGHT", "KRIT"):
                return 1
        return None

    def _handle_asm_history_key_v37(self, key):
        """Consume angle-bracket history only when ASM owns keyboard focus."""
        step = self._asm_history_step_for_key_v37(key)
        if step is None or self.menu_mode:
            return False
        if self.view == "three":
            self._three_prepare()
            if self._three["panes"][self._three["active"]] != "asm":
                return False
        elif self.view == "four":
            self._ensure_four()
            if self.owner.side_panes[self._four_active] != "asm":
                return False
        elif self.view != "asm":
            return False
        self._asm_move_history_v34(step)
        return True

    def _phi_history_label_v46(self):
        if not self._phi_history_v46 or self._phi_history_index_v46 < 0:
            return "-"
        return "%d/%d" % (
            self._phi_history_index_v46 + 1,
            len(self._phi_history_v46),
        )

    @staticmethod
    def _phi_frame_rows_v46(rows):
        return tuple(dict(row or {}) for row in list(rows or ()))

    def _phi_capture_history_frame_v46(self):
        """Capture one exact STATIC DEBUG PHI viewport and linked surfaces.

        This is a visual frame snapshot, not a semantic rewrite.  Restoring it
        must reproduce the same PHI rows, cursor/highlight authority, linked ASM
        surface, and Python cursor without touching the independent ASM ledger.
        """
        if self.view != "three" or self._three is None:
            return None
        three = self._three
        model_state = {
            "projection": self.model.projection,
            "line": int(getattr(self.model, "line", 0) or 0),
            "column": int(getattr(self.model, "column", 0) or 0),
            "top": int(getattr(self.model, "top_line", 0) or 0),
            "left": int(getattr(self.model, "left_column", 0) or 0),
        }
        return {
            "kind": "pal_termui_phi_frame_v46",
            "model": model_state,
            "phi_rows": self._phi_frame_rows_v46(three.get("phi_rows")),
            "phi_list_rows": self._phi_frame_rows_v46(three.get("phi_list_rows")),
            "phi_detail_rows": self._phi_frame_rows_v46(three.get("phi_detail_rows")),
            "phi_state": self._history_state_copy_v24(three["states"]["phi"]),
            "asm_rows": self._phi_frame_rows_v46(three.get("asm_rows")),
            "asm_base_rows": self._phi_frame_rows_v46(three.get("asm_base_rows")),
            "asm_state": self._history_state_copy_v24(three["states"]["asm"]),
            "code_state": self._history_state_copy_v24(three["states"]["code"]),
            "selected_phi_sid": three.get("selected_phi_sid"),
            "selected_dropin_id": three.get("selected_dropin_id"),
            "phi_mode": three.get("phi_mode"),
            "phi_materialization_full_v48": bool(
                three.get("phi_materialization_full_v48")
            ),
            "phi_matches": self._phi_frame_rows_v46(three.get("phi_matches")),
            "phi_active_matches_v47": self._phi_frame_rows_v46(
                three.get("phi_active_matches_v47")
            ),
            "phi_passive_matches_v47": self._phi_frame_rows_v46(
                three.get("phi_passive_matches_v47")
            ),
            "block_activity_v47": dict(
                three.get("block_activity_v47") or {}
            ),
            "statement_context": dict(three.get("statement_context") or {}),
            "base_focus": three.get("base_focus"),
            "focus": three.get("focus"),
            "source": three.get("source"),
            "pointer_focus": three.get("pointer_focus"),
            "phi_stack_zoom": dict(three.get("phi_stack_zoom") or {}),
            "code_highlight_block": three.get("code_highlight_block"),
            "branch_focus_v35": dict(three.get("branch_focus_v35") or {}),
            "branch_role_by_block_v25": dict(three.get("branch_role_by_block_v25") or {}),
            "asm_hover_block_v25": three.get("asm_hover_block_v25"),
            "asm_hover_role_v25": three.get("asm_hover_role_v25"),
        }

    def _phi_commit_history_frame_v46(self):
        if not self._phi_history_v46 or not (
            0 <= self._phi_history_index_v46 < len(self._phi_history_v46)
        ):
            return False
        frame = self._phi_capture_history_frame_v46()
        if frame is None:
            return False
        self._phi_history_v46[self._phi_history_index_v46] = frame
        return True

    def _phi_prepare_enter_history_v46(self):
        """Freeze the pre-Enter PHI viewport as the origin/current frame."""
        if self.view != "three" or self._three is None:
            return False
        frame = self._phi_capture_history_frame_v46()
        if frame is None:
            return False
        if self._phi_history_v46 and (
            0 <= self._phi_history_index_v46 < len(self._phi_history_v46)
        ):
            self._phi_history_v46[self._phi_history_index_v46] = frame
        else:
            self._phi_history_v46 = [frame]
            self._phi_history_index_v46 = 0
        return True

    def _phi_record_after_enter_v46(self, reason="PHI Enter"):
        """Append the post-Enter PHI frame without touching ASM history."""
        frame = self._phi_capture_history_frame_v46()
        if frame is None:
            return False
        if self._phi_history_index_v46 < len(self._phi_history_v46) - 1:
            self._phi_history_v46 = self._phi_history_v46[
                :self._phi_history_index_v46 + 1
            ]
        current = (
            self._phi_history_v46[self._phi_history_index_v46]
            if self._phi_history_v46 and self._phi_history_index_v46 >= 0
            else None
        )
        if current == frame:
            self.status = "%s; PHI history %s" % (
                reason, self._phi_history_label_v46()
            )
            return False
        self._phi_history_v46.append(frame)
        self._phi_history_index_v46 = len(self._phi_history_v46) - 1
        self.status = "%s; PHI history %s" % (
            reason, self._phi_history_label_v46()
        )
        return True

    def _phi_apply_history_frame_v46(self, frame):
        """Restore an exact PHI frame while preserving all PHI highlighting."""
        if self.view != "three" or self._three is None:
            return False
        frame = dict(frame or {})
        if frame.get("kind") != "pal_termui_phi_frame_v46":
            return False
        three = self._three
        for key in ("phi_rows", "phi_list_rows", "phi_detail_rows", "asm_rows", "asm_base_rows"):
            three[key] = [dict(row or {}) for row in list(frame.get(key, ()) or ())]
        for key in (
            "selected_phi_sid", "selected_dropin_id", "phi_mode",
            "phi_materialization_full_v48",
            "base_focus", "focus", "source", "pointer_focus",
            "code_highlight_block", "asm_hover_block_v25", "asm_hover_role_v25",
        ):
            three[key] = frame.get(key)
        three["phi_matches"] = [
            dict(row or {}) for row in list(frame.get("phi_matches", ()) or ())
        ]
        three["phi_active_matches_v47"] = [
            dict(row or {}) for row in list(
                frame.get("phi_active_matches_v47", ()) or ()
            )
        ]
        three["phi_passive_matches_v47"] = [
            dict(row or {}) for row in list(
                frame.get("phi_passive_matches_v47", ()) or ()
            )
        ]
        three["block_activity_v47"] = dict(
            frame.get("block_activity_v47") or {}
        )
        three["statement_context"] = dict(frame.get("statement_context") or {})
        three["phi_stack_zoom"] = dict(frame.get("phi_stack_zoom") or {}) or None
        three["branch_focus_v35"] = dict(frame.get("branch_focus_v35") or {}) or None
        three["branch_role_by_block_v25"] = dict(
            frame.get("branch_role_by_block_v25") or {}
        )
        three["states"]["phi"].clear()
        three["states"]["phi"].update(dict(frame.get("phi_state") or {}))
        three["states"]["asm"].clear()
        three["states"]["asm"].update(dict(frame.get("asm_state") or {}))
        three["states"]["code"].clear()
        three["states"]["code"].update(dict(frame.get("code_state") or {}))
        three["active"] = three["panes"].index("phi")

        model_state = dict(frame.get("model") or {})
        projection = model_state.get("projection")
        try:
            if projection and self.model.document.projection(projection) is not None:
                self.model.projection = projection
        except Exception:
            pass
        self.model.line = int(model_state.get("line", self.model.line) or 0)
        self.model.column = int(model_state.get("column", self.model.column) or 0)
        self.model.top_line = int(model_state.get("top", self.model.top_line) or 0)
        self.model.left_column = int(model_state.get("left", self.model.left_column) or 0)
        try:
            self.model.clamp()
            self.model.update_cursor_context()
        except Exception:
            pass
        self.status = "PHI history %s restored | ASM history unchanged" % (
            self._phi_history_label_v46()
        )
        return True

    def _phi_move_history_v46(self, step):
        if not self._phi_history_v46:
            self.status = "PHI history is empty; Enter a PHI block/transition first"
            return False
        self._phi_commit_history_frame_v46()
        target = min(
            max(0, self._phi_history_index_v46 + int(step)),
            len(self._phi_history_v46) - 1,
        )
        if target == self._phi_history_index_v46:
            self.status = "PHI history boundary %s" % self._phi_history_label_v46()
            return False
        self._phi_history_index_v46 = target
        return self._phi_apply_history_frame_v46(
            self._phi_history_v46[target]
        )

    def _handle_history_key_v46(self, key):
        """Dispatch `<`/`>` to the history owned by the active pane."""
        step = self._asm_history_step_for_key_v37(key)
        if step is None or self.menu_mode:
            return False
        if self.view == "three":
            self._three_prepare()
            active = self._three["panes"][self._three["active"]]
            if active == "phi":
                self._phi_move_history_v46(step)
                return True
            if active == "asm":
                self._asm_move_history_v34(step)
                return True
            return False
        return self._handle_asm_history_key_v37(key)

    def _clear_active_history_v51(self):
        """Clear only the history ledger owned by the focused ASM/PHI pane."""
        if self.menu_mode:
            self.status = "0 requires an active ASM or PHI pane"
            return False
        if self.view == "three":
            self._three_prepare()
            pane = self._three["panes"][self._three["active"]]
            if pane == "phi":
                self._phi_history_v46 = []
                self._phi_history_index_v46 = -1
                self.status = "PHI history cleared; PHI cursor retained"
                return True
            if pane == "asm":
                self._asm_history_v34 = []
                self._asm_history_index_v34 = -1
                self.status = "ASM history cleared; ASM cursor retained"
                return True
            self.status = "0 is pane-local; CODE has no history ledger"
            return False
        if self.view == "phi":
            self._phi_history_v46 = []
            self._phi_history_index_v46 = -1
            self.status = "PHI history cleared; pane cursor retained"
            return True
        if self.view == "asm":
            self._asm_history_v34 = []
            self._asm_history_index_v34 = -1
            self.status = "ASM history cleared; pane cursor retained"
            return True
        if self.view == "four":
            self._ensure_four()
            if self.owner.side_panes[self._four_active] == "asm":
                self._asm_history_v34 = []
                self._asm_history_index_v34 = -1
                self.status = "ASM history cleared; pane cursor retained"
                return True
        self.status = "0 requires an active ASM or PHI pane"
        return False

    def _asm_history_label_v34(self):
        if not self._asm_history_v34 or self._asm_history_index_v34 < 0:
            return "-"
        return "%d/%d" % (
            self._asm_history_index_v34 + 1, len(self._asm_history_v34)
        )

    def _asm_focus_from_rows_v34(self, pane, rows, state):
        if self.view == "three" and self._three is not None:
            return self.model._canonical_block_addr_v21(
                self._three.get("pointer_focus") or self._three.get("base_focus")
            )
        if self.view == "four":
            return self.model._canonical_block_addr_v21(
                self._four_asm_focus_v34 or self.owner._side_asm_block_addr
            )
        if self.view == "asm":
            if self._asm_jump_focus:
                return self.model._canonical_block_addr_v21(self._asm_jump_focus)
            index = min(max(0, int(state.get("line", 0))), max(0, len(rows) - 1))
            for cursor in range(index, -1, -1):
                row = dict(rows[cursor] or {})
                if row.get("kind") == "block" and row.get("addr"):
                    return self.model._canonical_block_addr_v21(row.get("addr"))
        return None

    def _asm_record_jump_v34(self, pane, rows, state, row, target):
        target = self.model._canonical_block_addr_v21(target)
        if target is None:
            return
        row = dict(row or {})
        source = self.model._canonical_block_addr_v21(
            row.get("addr") or self._asm_focus_from_rows_v34(pane, rows, state)
        )
        semantic = self.model.asm_instruction_semantics_v33(row.get("text"))
        conditional = bool(row.get("conditional_jump") or semantic.get("conditional_jump"))
        self._asm_commit_history_cursor_v24()
        if self._asm_history_index_v34 < len(self._asm_history_v34) - 1:
            self._asm_history_v34 = self._asm_history_v34[:self._asm_history_index_v34 + 1]
        if not self._asm_history_v34 and source is not None:
            self._asm_history_v34.append({
                "focus": source, "source": "origin",
                "view": self.view, "projection": self.model.projection,
                "phi_sid": (self._three or {}).get("selected_phi_sid")
                if self.view == "three" else None,
                "conditional": False, "branch_source": None, "branch_target": None,
                "cursor_snapshot": self._asm_capture_history_cursor_v24(),
            })
        self._asm_history_v34.append({
            "focus": target,
            "source": str(row.get("text") or "jump"),
            "view": self.view, "projection": self.model.projection,
            "phi_sid": (self._three or {}).get("selected_phi_sid")
            if self.view == "three" else None,
            "conditional": conditional,
            "branch_source": source if conditional else None,
            "branch_target": target if conditional else None,
            "cursor_snapshot": None,
        })
        self._asm_history_index_v34 = len(self._asm_history_v34) - 1

    def _four_set_asm_focus_v34(self, target):
        canonical = self.model._canonical_block_addr_v21(target)
        if canonical is None:
            return False
        self._four_asm_focus_v34 = canonical
        self._four_asm_branch_rows_v35 = None
        self._four_asm_rows_v34 = list(
            self.model.asm_debug_focus_rows_v34(
                canonical, relation="ASM DEBUG WALKTHROUGH"
            ) or ()
        )
        self.owner._side_asm_block_addr = canonical
        asm_state = self.owner.side_state["asm"]
        headers = [
            index for index, row in enumerate(self._four_asm_rows_v34)
            if dict(row or {}).get("kind") == "block"
            and self.model._canonical_block_addr_v21(
                dict(row or {}).get("addr")
            ) == canonical
        ]
        asm_state.update({
            "line": headers[0] if headers else 0,
            "top": max(0, (headers[0] if headers else 0) - 1),
            "left": 0, "column": 0,
        })
        for pane in ("readable", "executable"):
            blocks = list(self.model.projection_block_map_v21(
                pane, allow_cursor_fallback=False
            ) or ())
            matches = [index for index, block in enumerate(blocks) if block == canonical]
            if matches:
                state = self.owner.side_state[pane]
                state["line"] = matches[0]
                state["top"] = max(0, matches[0] - 2)
                state["column"] = 0
        anchor = self.owner.last_python_pane
        if anchor not in ("readable", "executable"):
            anchor = "readable"
        self.owner._side_soft_sync_c(anchor)
        return True

    def _four_set_asm_branch_v35(self, source, target):
        source = self.model._canonical_block_addr_v21(source)
        target = self.model._canonical_block_addr_v21(target)
        if not source or not target:
            return False
        self._four_asm_focus_v34 = target
        self._four_asm_rows_v34 = None
        self._four_asm_branch_rows_v35 = list(
            self.model.asm_branch_forks_rows_v35(source, target) or ()
        )
        self.owner._side_asm_block_addr = target
        asm_state = self.owner.side_state["asm"]
        current = next((
            index for index, row in enumerate(self._four_asm_branch_rows_v35)
            if dict(row or {}).get("kind") == "block"
            and self.model._canonical_block_addr_v21(dict(row or {}).get("addr")) == target
        ), 0)
        asm_state.update({"line": current, "top": max(0, current - 2), "left": 0, "column": 0})
        self._four_active = self.owner.side_panes.index("asm")
        self.owner.side_active = self._four_active
        for pane in ("readable", "executable"):
            blocks = list(self.model.projection_block_map_v21(pane, allow_cursor_fallback=False) or ())
            matches = [index for index, block in enumerate(blocks) if block == target]
            if matches:
                state = self.owner.side_state[pane]
                state.update({"line": matches[0], "top": max(0, matches[0] - 2), "column": 0})
        anchor = self.owner.last_python_pane
        if anchor not in ("readable", "executable"):
            anchor = "readable"
        self.owner._side_soft_sync_c(anchor)
        return True

    def _asm_apply_history_frame_v34(self, frame):
        frame = dict(frame or {})
        focus = self.model._canonical_block_addr_v21(frame.get("focus"))
        if focus is None:
            return False
        conditional = bool(frame.get("conditional"))
        branch_source = self.model._canonical_block_addr_v21(frame.get("branch_source"))
        branch_target = self.model._canonical_block_addr_v21(frame.get("branch_target"))
        self._refresh_model_code_for_block_v24(
            focus, projection=frame.get("projection")
        )
        if self.view == "three":
            self._three_prepare()
            self._three_refresh_code()
            self._three_set_focus(
                focus, "asm",
                source_row={"addr": focus, "jump_target": focus},
                initialize=False,
            )
            if conditional and branch_source and branch_target:
                self._three["asm_rows"] = list(
                    self.model.asm_branch_forks_rows_v35(branch_source, branch_target) or ()
                )
                self._three["asm_base_rows"] = list(self._three["asm_rows"])
                self._three["branch_focus_v35"] = {"source": branch_source, "target": branch_target}
                self._three["active"] = self._three["panes"].index("asm")
            phi_sid = frame.get("phi_sid")
            if phi_sid:
                self._three["selected_phi_sid"] = str(phi_sid)
                self._three_rebuild_phi_rows(preferred_sid=str(phi_sid))
        elif self.view == "four":
            self._ensure_four()
            if conditional and branch_source and branch_target:
                self._four_set_asm_branch_v35(branch_source, branch_target)
            else:
                self._four_set_asm_focus_v34(focus)
        elif self.view == "asm":
            if conditional and branch_source and branch_target:
                self._asm_branch_focus_v35 = {"source": branch_source, "target": branch_target}
                self._asm_jump_focus = None
            else:
                self._asm_branch_focus_v35 = None
                self._asm_jump_focus = focus
            self.states["asm"].update({"line": 0, "top": 0, "left": 0, "focus": None})
            self._one_cache.pop("asm", None)
        else:
            return False
        self._asm_restore_history_cursor_v24(frame, focus)
        if self.view == "three" and conditional:
            self._three["branch_role_by_block_v25"] = self._asm_branch_role_map_v25(
                self._three.get("asm_rows", ())
            )
            self._three_link_from_asm_cursor_v25(
                rows=self._three.get("asm_rows", ()),
                state=self._three["states"]["asm"],
            )
        if conditional:
            if self.view == "three":
                self._three["active"] = self._three["panes"].index("asm")
            elif self.view == "four":
                self._four_active = self.owner.side_panes.index("asm")
                self.owner.side_active = self._four_active
        self.status = "ASM history %s -> %s | cursor restored | code relinked" % (
            self._asm_history_label_v34(), focus
        )
        return True

    def _asm_move_history_v34(self, step):
        if not self._asm_history_v34:
            self.status = "ASM history is empty; Enter a jump first"
            return False
        self._asm_commit_history_cursor_v24()
        target = min(
            max(0, self._asm_history_index_v34 + int(step)),
            len(self._asm_history_v34) - 1,
        )
        if target == self._asm_history_index_v34:
            self.status = "ASM history boundary %s" % self._asm_history_label_v34()
            return False
        self._asm_history_index_v34 = target
        return self._asm_apply_history_frame_v34(
            self._asm_history_v34[target]
        )

    def _active_variable_contract_v34(self):
        pane, rows, state = self._active_rows_state()
        index = min(max(0, int(state.get("line", 0))), max(0, len(rows) - 1))
        row = dict(rows[index] or {}) if rows else {}
        sid = None
        if self.view == "detail":
            sid = row.get("sid")
        elif self.view == "phi":
            sid = row.get("output_sid") or row.get("sid") or self._phi_menu_selected_sid
        elif self.view == "three":
            if pane == "phi":
                sid = row.get("output_sid") or row.get("sid") or self._three.get("selected_phi_sid")
            elif pane == "asm":
                sid = self._three.get("selected_phi_sid")
            else:
                self._commit_code_cursor()
                return self.model.current_contract(advanced=True)
        elif self.view == "four":
            if pane in ("readable", "executable"):
                self.owner._side_sync_model_cursor(pane)
            else:
                self.owner._side_sync_model_cursor(self.owner.last_python_pane)
            return self.model.current_contract(advanced=True)
        if sid:
            canonical = self.model.canonical_phi_sid_v33(sid)
            return self.model.oncs.contracts.get(canonical)
        return None

    def _rename_active_variable_v34(self):
        if self.view == "three" and self._three is not None:
            pane = self._three["panes"][self._three["active"]]
            if pane == "code":
                state = self._three["states"]["code"]
                changed = self.owner._rename_line_variable_v35(
                    projection=self.model.projection, line=int(state.get("line", 0))
                )
                self.status = self.model.status
                if changed:
                    self._three_refresh_code(); self._three_rebuild_phi_rows(preferred_sid=self._three.get("selected_phi_sid"))
                return changed
        if self.view == "four":
            pane = self.owner.side_panes[self._four_active]
            if pane in ("readable", "executable"):
                state = self.owner.side_state[pane]
                changed = self.owner._rename_line_variable_v35(
                    projection=pane, line=int(state.get("line", 0))
                )
                self.status = self.model.status
                return changed
        contract = dict(self._active_variable_contract_v34() or {})
        if not contract:
            self.status = "F4 rename requires a variable/PHI/code focus"
            return False
        if _contract_operator_rename_protected_v34(contract):
            self.status = "F4 rename blocked: protected ABI/system variable"
            return False
        sid = str(contract.get("canonical_ssa_name") or contract.get("sid") or "")
        shown = (
            contract.get("operator_alias")
            or _base_variable_name(contract, self.model.naming)
            or contract.get("pal_name") or sid
        )
        value = self.owner._prompt(
            "F4 sudo rename %s> " % shown,
            str(contract.get("operator_alias") or ""),
        )
        if value is None or not value.strip():
            return False
        try:
            saved = self.model.rename_variable_sid_v34(
                sid, value.strip(), author="operator-admin"
            )
        except Exception as exc:
            self.status = "F4 rename failed: %s" % exc
            return False
        self._one_cache.clear()
        self._digest = None
        if self._three is not None:
            self._three_refresh_code()
            self._three_rebuild_phi_rows(preferred_sid=sid)
        self.status = "F4 renamed %s -> %s" % (shown, saved)
        return True

    def _focus(self):
        pane, rows, state = self._active_rows_state()
        if not rows:
            return
        index = min(max(0, int(state["line"])), len(rows) - 1)
        row = dict(rows[index] or {})
        phi_enter_history_v46 = bool(
            self.view == "three" and pane == "phi"
        )
        if pane == "phi":
            self._phi_remember_cursor_v29(rows, state)
            if phi_enter_history_v46:
                self._phi_prepare_enter_history_v46()
        # mars v0.28: the cursor remains on the BLOCK header, but activation
        # inherits the block's terminal direct jump command when one exists.
        # This restores direct-jump and conditional topology actions without
        # reopening instruction-line navigation.
        if pane == "asm":
            action_row = self._asm_block_action_row_v28(rows, index)
            if action_row is not None:
                row = action_row
        if self.view == "four" and pane in ("readable", "executable"):
            # OVERVIEW focus is a whole Python line.  Do not invoke the legacy
            # variable/token hotspot resolver merely to commit cross-pane focus.
            self._sync_four_after_selection(pane)
            self.model.object_focus = None
            self.model.highlight_sid = None
            state["focus"] = None if state.get("focus") == index else index
            self.status = (
                "%s line %d committed; token metadata bypassed"
                % (pane.upper(), index + 1)
            )
        elif self.view == "four" and pane == "asm":
            semantic = self.model.asm_instruction_semantics_v33(row.get("text"))
            target = semantic.get("jump_target")
            if target:
                source = self.model._canonical_block_addr_v21(row.get("addr"))
                self._asm_record_jump_v34(pane, rows, state, row, target)
                if semantic.get("conditional_jump") and source:
                    self._four_set_asm_branch_v35(source, target)
                    self.status = "ASM branch topology %s -> %s | live READ/EXEC/C linkage | history %s" % (
                        source, target, self._asm_history_label_v34()
                    )
                else:
                    self._four_set_asm_focus_v34(target)
                    self.status = "ASM jump target %s | history %s" % (
                        target, self._asm_history_label_v34()
                    )
                self._asm_commit_history_cursor_v24()
            else:
                root = self.model._canonical_block_addr_v21(row.get("addr"))
                if root:
                    self._four_set_asm_focus_v34(root)
                    state["focus"] = index
                    self.status = "ASM focus root %s; code/C panes relinked" % root
                else:
                    state["focus"] = None if state.get("focus") == index else index
            return
        elif self.view == "three":
            if pane == "phi" and row.get("kind") == "dropin_summary":
                dropin_id = str(row.get("dropin_id") or "")
                self._three["selected_dropin_id"] = dropin_id or None
                destinations = tuple(
                    row.get("destination_sids", ()) or ()
                )
                self._three["selected_phi_sid"] = (
                    str(destinations[0])
                    if destinations else
                    str(row.get("output_sid") or "") or None
                )
                state["focus"] = index
                self._phi_remember_cursor_v29(rows, state)
                self.status = (
                    "selected focal drop-in block %s @ %s; ASM/PY focus retained"
                    % (
                        int(row.get("dropin_index") or 0),
                        self.model._canonical_block_addr_v21(
                            row.get("address") or row.get("addr")
                        ) or "-",
                    )
                )
                self._phi_record_after_enter_v46(
                    "selected focal drop-in block"
                )
                return
            if pane == "phi" and row.get("kind") == "phi_summary":
                sid = str(row.get("output_sid") or "")
                self._three["selected_phi_sid"] = sid
                self._three_rebuild_phi_rows(preferred_sid=sid)
                state = self._three["states"]["phi"]
                state["focus"] = int(state.get("line", 0))
                self._phi_remember_cursor_v29(self._three_rows("phi"), state)
                self.status = (
                    "selected PHI result %s; cursor retained" % sid
                )
                self._phi_record_after_enter_v46(
                    "selected PHI result %s" % sid
                )
                return
            if pane == "phi" and row.get("block_hotspot") and row.get("address"):
                prior_focus = state.get("focus")
                self._three_toggle_pointer_focus(row)
                state = self._three["states"]["phi"]
                current = int(state.get("line", 0))
                state["focus"] = None if prior_focus == current else current
                self._phi_remember_cursor_v29(self._three_rows("phi"), state)
                self._phi_record_after_enter_v46(
                    "PHI block pointer %s" % (
                        self.model._canonical_block_addr_v21(
                            row.get("address")
                        ) or "-"
                    )
                )
                return
            if pane == "asm":
                if self._three.get("branch_focus_v35") and not row.get("jump_target"):
                    self._three_link_from_asm_cursor_v25(rows=rows, state=state)
                    state["focus"] = index
                    return
                address = row.get("jump_target") or row.get("addr")
                if address:
                    semantic = self.model.asm_instruction_semantics_v33(row.get("text"))
                    source = self.model._canonical_block_addr_v21(row.get("addr"))
                    if row.get("jump_target"):
                        self._asm_record_jump_v34(pane, rows, state, row, address)
                    self._three_set_focus(address, "asm", source_row=row, source_index=index)
                    if row.get("jump_target") and semantic.get("conditional_jump") and source:
                        self._three["asm_rows"] = list(
                            self.model.asm_branch_forks_rows_v35(source, address) or ()
                        )
                        self._three["asm_base_rows"] = list(self._three["asm_rows"])
                        self._three["branch_focus_v35"] = {"source": source, "target": address}
                        self._three["branch_role_by_block_v25"] = self._asm_branch_role_map_v25(
                            self._three["asm_rows"]
                        )
                        asm_state = self._three["states"]["asm"]
                        target_row = next((
                            row_index for row_index, branch_row in enumerate(self._three["asm_rows"])
                            if dict(branch_row or {}).get("kind") == "block"
                            and self.model._canonical_block_addr_v21(
                                dict(branch_row or {}).get("addr")
                            ) == self.model._canonical_block_addr_v21(address)
                        ), 0)
                        asm_state.update({
                            "line": target_row,
                            "top": max(0, target_row - 2),
                            "focus": target_row,
                        })
                        self._three_link_from_asm_cursor_v25(
                            rows=self._three["asm_rows"], state=asm_state
                        )
                    state["focus"] = (
                        int(state.get("line", 0))
                        if row.get("jump_target") and semantic.get("conditional_jump")
                        else index
                    )
                    if row.get("jump_target"):
                        if semantic.get("conditional_jump"):
                            self._three["active"] = self._three["panes"].index("asm")
                            self.status = "ASM branch topology %s -> %s | live PHI/CODE linkage | history %s" % (
                                source, address, self._asm_history_label_v34()
                            )
                        else:
                            self.status = "ASM jump target %s | history %s" % (
                                address, self._asm_history_label_v34()
                            )
                        self._asm_commit_history_cursor_v24()
                return
            if pane == "code":
                block = row.get("block")
                if block:
                    self._three_set_focus(block, "code", source_row=row, source_index=index)
                    state["focus"] = index
                    self._commit_code_cursor()
                return
        elif self.view == "asm":
            target = row.get("jump_target")
            if target:
                canonical = self.model._canonical_block_addr_v21(target)
                source = self.model._canonical_block_addr_v21(row.get("addr"))
                semantic = self.model.asm_instruction_semantics_v33(row.get("text"))
                self._asm_record_jump_v34(pane, rows, state, row, canonical)
                if semantic.get("conditional_jump") and source:
                    self._asm_branch_focus_v35 = {"source": source, "target": canonical}
                    self._asm_jump_focus = None
                    self.status = "ASM branch topology %s -> %s | hidden CODE linkage | history %s" % (
                        source, canonical, self._asm_history_label_v34()
                    )
                else:
                    self._asm_branch_focus_v35 = None
                    self._asm_jump_focus = canonical
                    self.status = "ASM jump target %s | history %s" % (
                        canonical, self._asm_history_label_v34()
                    )
                state.update({"line": 0, "top": 0, "left": 0, "focus": None})
                self._one_cache.pop("asm", None)
                self._refresh_model_code_for_block_v24(
                    canonical, projection=self.model.projection
                )
                self._asm_commit_history_cursor_v24()
                return
            root = self.model._canonical_block_addr_v21(row.get("addr"))
            if root:
                self._asm_branch_focus_v35 = None
                self._asm_jump_focus = root
                state.update({"line": 0, "top": 0, "left": 0, "focus": None})
                self._one_cache.pop("asm", None)
                self._refresh_model_code_for_block_v24(
                    root, projection=self.model.projection
                )
                self.status = "ASM focus root %s; hidden code cursor relinked" % root
                return
            state["focus"] = None if state.get("focus") == index else index
        elif self.view == "detail":
            sid = str(row.get("sid") or "")
            if row.get("kind") != "var_row" or not sid:
                self.status = "select a variable row"
                return
            phi_index = self.model.phi_custody_index_for_sid_v16(sid)
            entries = list(self.model.phi_custody_inventory_v14() or ())
            if phi_index is None or not (0 <= int(phi_index) < len(entries)) or not entries[int(phi_index)].get("has_phi"):
                self.status = "%s has no frozen PHI custody node" % self.model.phi_display_name_v30(sid)
                return
            action = int(state.get("action", 0) or 0) % 2
            if action == 0:
                self._phi_menu_selected_sid = sid
                self.view_index = self.VIEWS.index("phi")
                phi_rows = self._phi_menu_rows_v31()
                target = next((
                    row_index for row_index, phi_row in enumerate(phi_rows)
                    if phi_row.get("kind") == "phi_summary"
                    and str(phi_row.get("output_sid") or "") == sid
                ), 0)
                self.states["phi"]["line"] = target
                self.states["phi"]["top"] = max(0, target - 2)
                self.status = "PHI Detail focus: %s" % self.model.phi_display_name_v30(sid)
            else:
                self._open_three_from_phi_v31(sid)
                self.status = "STATIC DEBUG focus: %s" % self.model.phi_display_name_v30(sid)
            return
        elif self.view == "phi":
            sid = str(row.get("output_sid") or row.get("sid") or "")
            if row.get("kind") == "phi_summary" and sid:
                self._phi_menu_selected_sid = sid
                self._open_three_from_phi_v31(sid)
                return
            if row.get("block_hotspot") and row.get("address"):
                self._open_three_from_phi_v31(sid, row.get("address"))
                return
        else:
            state["focus"] = None if state.get("focus") == index else index
        self.status = "focus %s row %d" % (pane.upper(), index + 1)

    def _full(self):
        """Toggle exact focused/filter state against a complete pane listing."""
        key = self._active_search_key()
        snapshot = self.full_snapshots.pop(key, None)
        if snapshot is not None:
            self.searches[key] = str(snapshot.get("query") or "")
            self.highlight_modes[key] = bool(snapshot.get("highlight"))
            if self.view == "three" and self._three is not None:
                pane = snapshot.get("pane")
                if pane == "phi" and snapshot.get("three_phi_rows") is not None:
                    self._three["phi_rows"] = list(snapshot.get("three_phi_rows") or ())
                    self._three["phi_list_rows"] = list(snapshot.get("three_phi_list_rows") or ())
                    self._three["phi_detail_rows"] = list(snapshot.get("three_phi_detail_rows") or ())
                    self._three["phi_materialization_full_v48"] = bool(
                        snapshot.get("three_phi_materialization_full_v48", False)
                    )
                    self._three["phi_mode"] = snapshot.get(
                        "three_phi_mode", self._three.get("phi_mode")
                    )
                    self._three["selected_phi_sid"] = snapshot.get(
                        "three_selected_phi_sid"
                    )
                if pane == "asm" and snapshot.get("three_asm_rows") is not None:
                    self._three["asm_rows"] = list(snapshot.get("three_asm_rows") or ())
                    self._three["asm_base_rows"] = list(snapshot.get("three_asm_base_rows") or ())
                    self._three["branch_focus_v35"] = snapshot.get("three_branch_focus")
                    data = dict(snapshot.get("three_pointer") or {})
                    self._three["pointer_focus"] = data.get("pointer_focus")
                    self._three["code_highlight_block"] = data.get("code_highlight_block")
                    self._three["phi_stack_zoom"] = data.get("phi_stack_zoom")
            if self.view == "asm":
                self._asm_jump_focus = snapshot.get("asm_jump_focus")
                self._asm_branch_focus_v35 = snapshot.get("asm_branch_focus")
            if self.view == "phi":
                self._phi_full_listing_v35 = bool(snapshot.get("phi_full_before", False))
            if self.view == "four" and snapshot.get("pane") == "asm":
                self._four_asm_focus_v34 = snapshot.get("four_asm_focus")
                self._four_asm_rows_v34 = list(snapshot.get("four_asm_rows") or ()) if snapshot.get("four_asm_rows") is not None else None
                self._four_asm_branch_rows_v35 = list(snapshot.get("four_branch_rows") or ()) if snapshot.get("four_branch_rows") is not None else None
            self.status = "FULL=OFF; focused %s state restored" % self._active_subpane_label()
            return

        pane = self._active_subpane_label().casefold()
        query = self.searches.get(key, "")
        data = {
            "query": query,
            "highlight": bool(self.highlight_modes.get(key, False)),
            "pane": None,
        }
        self.searches[key] = ""
        self.highlight_modes[key] = False

        if self.view == "three":
            self._three_prepare()
            active = self._three["panes"][self._three["active"]]
            data["pane"] = active
            if active == "phi":
                data.update({
                    "three_phi_rows": tuple(self._three.get("phi_rows", ()) or ()),
                    "three_phi_list_rows": tuple(self._three.get("phi_list_rows", ()) or ()),
                    "three_phi_detail_rows": tuple(self._three.get("phi_detail_rows", ()) or ()),
                    "three_phi_materialization_full_v48": bool(
                        self._three.get("phi_materialization_full_v48")
                    ),
                    "three_phi_mode": self._three.get("phi_mode"),
                    "three_selected_phi_sid": self._three.get("selected_phi_sid"),
                })
                self._three["phi_materialization_full_v48"] = True
                self._three_rebuild_phi_rows(
                    preferred_sid=self._three.get("selected_phi_sid")
                )
                self._three["states"]["phi"]["left"] = 0
            elif active == "asm":
                data.update({
                    "three_asm_rows": tuple(self._three.get("asm_rows", ()) or ()),
                    "three_asm_base_rows": tuple(self._three.get("asm_base_rows", ()) or ()),
                    "three_branch_focus": self._three.get("branch_focus_v35"),
                    "three_pointer": {
                        "pointer_focus": self._three.get("pointer_focus"),
                        "code_highlight_block": self._three.get("code_highlight_block"),
                        "phi_stack_zoom": dict(self._three.get("phi_stack_zoom") or {}),
                    },
                })
                full_rows = list(self._full_asm_rows_v35())
                self._three["asm_rows"] = full_rows
                self._three["asm_base_rows"] = full_rows
                self._three["branch_focus_v35"] = None
                self._three["states"]["asm"].update({"line": 0, "top": 0, "left": 0})
        elif self.view == "asm":
            data.update({
                "pane": "asm",
                "asm_jump_focus": self._asm_jump_focus,
                "asm_branch_focus": dict(self._asm_branch_focus_v35 or {}) or None,
            })
            self._asm_jump_focus = None
            self._asm_branch_focus_v35 = None
            self.states["asm"].update({"line": 0, "top": 0, "left": 0})
        elif self.view == "phi":
            data.update({"pane": "phi", "phi_full_before": self._phi_full_listing_v35})
            self._phi_full_listing_v35 = True
            self.states["phi"].update({"line": 0, "top": 0, "left": 0})
        elif self.view == "four" and self.owner.side_panes[self._four_active] == "asm":
            data.update({
                "pane": "asm",
                "four_asm_focus": self._four_asm_focus_v34,
                "four_asm_rows": tuple(self._four_asm_rows_v34) if self._four_asm_rows_v34 is not None else None,
                "four_branch_rows": tuple(self._four_asm_branch_rows_v35) if self._four_asm_branch_rows_v35 is not None else None,
            })
            self._four_asm_focus_v34 = None
            self._four_asm_branch_rows_v35 = None
            self._four_asm_rows_v34 = list(self._full_asm_rows_v35())
            self.owner.side_state["asm"].update({"line": 0, "top": 0, "left": 0, "column": 0})
        self.full_snapshots[key] = data
        if self.view == "three" and data.get("pane") == "phi":
            self.status = "FULL=ON; all materialized Φ unfolded by activity; F restores focal block"
        else:
            self.status = "FULL=ON; complete %s listing; F restores focus" % self._active_subpane_label()

    def _clear(self):
        """C clears only the focused pane's search and highlight lock."""
        key = self._active_search_key()
        previous = str(self.searches.get(key, "") or "")
        self.searches[key] = ""
        self.highlight_modes[key] = False
        self.status = (
            "cleared /%s and highlight lock for %s"
            % (previous, self._active_subpane_label())
            if previous else
            "search/highlight already clear for %s"
            % self._active_subpane_label()
        )
        return True


    def _command_prompt_v37(self, label="PAL CMD> ", initial=""):
        """Read a command directly beneath the graphic menu/key rows.

        The previous terminal-footer prompt detached command entry from the
        visible workbench controls.  NEPTUNE retains the
        lower header separator (row 4) so command entry remains inside the
        graphic control surface and never displaces the status footer.
        """
        height, width = self.screen.getmaxyx()
        row = min(max(0, 4), max(0, height - 1))
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
                self._add(
                    row, 0, " " * max(0, width - 1),
                    self._attr("status", bold=True), max(0, width - 1),
                )
                self._add(
                    row, 0, label,
                    self._attr("active_header", bold=True), len(label),
                )
                self._add(
                    row, len(label), text[left:left + available],
                    self._attr("default"), available,
                )
                try:
                    self.screen.move(row, min(width - 1, len(label) + cursor - left))
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
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass

    def _command(self):
        value = self._command_prompt_v37("PAL CMD> ", "")
        if value is None:
            return
        command, separator, argument = value.strip().partition(" ")
        command = command.casefold()
        argument = argument.strip()
        try:
            if command in ("rename", "name"):
                if not argument:
                    raise ValueError("usage: rename NEW_NAME")
                self._commit_code_cursor()
                saved = self.model.rename_current_variable(argument)
                self.status = "renamed to %s" % saved
            elif command in ("revert", "clearname"):
                self._commit_code_cursor()
                self.model.revert_current_variable()
                self.status = self.model.status
            elif command == "find":
                self._set_search(argument)
                self.status = "find /%s" % (argument or "-")
            elif command == "full":
                self._full()
            elif command == "clear":
                self._clear()
            elif command == "save":
                if callable(self.owner.save_handler):
                    self.owner.save_handler(self.model)
                else:
                    self.model.save()
                self.status = self.model.status
            elif command == "export":
                if not argument:
                    raise ValueError("usage: export PATH")
                self.model.export(argument)
                self.status = self.model.status
            elif command in ("pyexec", "exec-export", "execute-export"):
                if self._active_python_projection_v40() is None:
                    raise ValueError("activate a Python CODE pane first; source is always EXEC")
                self._commit_code_cursor()
                self.model.export_execute_function_v41()
                self.status = self.model.status
            elif command in ("view", "projection"):
                self._commit_code_cursor()
                self.model.switch_projection()
                self._one_cache.clear()
                self._digest = None
                self._three = None
                self.status = self.model.status
            elif command in ("names", "naming"):
                self.model.cycle_naming()
                self._one_cache.clear(); self._three = None
                self.status = self.model.status
            elif command in ("operator", "oper"):
                self.model.toggle_operator_overlay()
                self._one_cache.clear(); self._three = None
                self.status = self.model.status
            elif command in ("help", "?"):
                self.status = "commands: rename, revert, find, full, clear, save, export, pyexec, view, names, operator"
            elif command:
                raise ValueError("unknown command %s" % command)
        except Exception as exc:
            self.status = "command failed: %s" % exc

    def _display_control(self, key):
        active_key = self._active_search_key()
        full_active = active_key in self.full_snapshots
        projection_changed = False
        naming_changed = False
        if key == curses.KEY_F1:
            if not self.menu_mode:
                self._commit_code_cursor()
            self.model.switch_projection()
            projection_changed = True
        elif key == curses.KEY_F2:
            self.model.cycle_naming()
            naming_changed = True
        elif key == "\x0f":
            self.model.toggle_operator_overlay()
            naming_changed = True
        else:
            return False
        self._one_cache.clear()
        self._digest = None
        # SECAM: do not silently destroy a FULL snapshot.  F is the sole
        # restore switch; display controls repaint the active full listing.
        if not full_active:
            self.full_snapshots.clear()
        if projection_changed:
            if full_active:
                if self.view == "three" and self._three is not None:
                    self._three_refresh_code()
                elif self.view == "four":
                    source = (
                        self.model.projection
                        if self.model.projection in ("readable", "executable")
                        else "readable"
                    )
                    self.owner.last_python_pane = source
                    self.owner._side_sync_python_pair(source)
            else:
                self._four_asm_focus_v34 = None
                self._four_asm_rows_v34 = None
                self._four_asm_branch_rows_v35 = None
                self._three = None
                self._four_ready = False
        elif naming_changed and self._three is not None:
            selected = self._three.get("selected_phi_sid")
            self._three_refresh_code()
            self._three["all_paths"] = list(self.model.phi_path_focus_rows_v21() or ())
            self._three_rebuild_phi_rows(preferred_sid=selected)
            # Frozen PHI frames carry rendered names.  A naming-overlay change
            # starts a fresh PHI ledger so history can never resurrect stale
            # SSA/PAL/Humanized/operator spellings.
            self._phi_history_v46 = []
            self._phi_history_index_v46 = -1
        self.status = self.model.status
        return True

    def draw(self):
        body_top, body_height, width = self._draw_chrome()
        if self.menu_mode:
            self._draw_menu_view(body_top, body_height, width)
        elif self.view == "four":
            self._draw_four(body_top, body_height, width)
        elif self.view == "three":
            self._draw_three(body_top, body_height, width)
        else:
            self._draw_one(body_top, body_height, width)
        self._present()

    def run(self):
        # Every invocation begins at the retained graphic-menu selection.
        self.menu_mode = True
        self.status = "menu selection retained: %s" % self.LABELS[self.view]
        dirty = True
        while True:
            if dirty:
                self.draw()
                dirty = False
            try:
                key = self.screen.get_wch()
            except KeyboardInterrupt:
                if self.menu_mode:
                    break
                self._commit_code_cursor()
                self._commit_active_history_cursor_v51()
                self.menu_mode = True
                dirty = True
                continue

            if self.menu_mode:
                if key in ("\x1b", "q", "Q", "m", "M"):
                    break
                if self._display_control(key):
                    dirty = True
                    continue
                if key == "\x05":
                    self.status = "Ctrl-E PY.EXEC: activate a Python CODE pane; export source is always EXEC"
                    dirty = True
                    continue
                if key in (curses.KEY_DOWN, "j"):
                    self._switch_top(1); dirty = True; continue
                if key in (curses.KEY_UP, "k"):
                    self._switch_top(-1); dirty = True; continue
                if key in ("\n", "\r", curses.KEY_ENTER):
                    if self.view in ("three", "four"):
                        self._maybe_show_large_loader_v35(self.LABELS[self.view])
                    self.menu_mode = False
                    self.status = "opened %s | PHI history %s | ASM history %s" % (
                        self.LABELS[self.view],
                        self._phi_history_label_v46(),
                        self._asm_history_label_v34(),
                    )
                    dirty = True
                    continue
                if key in ("\t", KEY_CTRL_TAB, getattr(curses, "KEY_BTAB", -99999)):
                    self.status = "menu has no panes; Enter opens %s" % self.LABELS[self.view]
                    dirty = True
                    continue
                if key == curses.KEY_RESIZE:
                    dirty = True
                continue

            # Inside a view, M/Esc/Q returns exactly one node to MENU VIEW.
            if key in ("\x1b", "q", "Q", "m", "M"):
                self._commit_code_cursor()
                self._commit_active_history_cursor_v51()
                self.menu_mode = True
                self.status = "menu selection retained: %s | histories retained" % self.LABELS[self.view]
                dirty = True
                continue
            # v0.35a: angle-bracket history is pane-owned.  PHI replays PHI
            # visual frames; ASM replays ASM jump frames; neither ledger mutates
            # the other.
            if self._handle_history_key_v46(key):
                dirty = True
                continue
            if self._display_control(key):
                dirty = True
                continue
            if key == "\x05":
                self._export_active_python_v41()
                dirty = True
                continue
            if key == "\t":
                self._switch_pane(1); dirty = True; continue
            if key in (KEY_CTRL_TAB, getattr(curses, "KEY_BTAB", -99999)):
                self._switch_pane(-1); dirty = True; continue
            if key == "/":
                value = self.owner._prompt(
                    "/ find in %s: " % self._active_subpane_label(),
                    self._search(),
                )
                if value is not None:
                    self._set_search(value)
                    if str(value).strip():
                        self._move_match(1)
                    else:
                        self.status = "search and highlight mode cleared"
                dirty = True; continue
            if key == curses.KEY_F4:
                self._rename_active_variable_v34(); dirty = True; continue
            # mars v0.27 retained: arrows and j/k all browse ASM by machine block.
            # mars v0.29 retains semantic ASM block navigation and preserves
            # PHI cursor identity across Tab focus and Enter-triggered rebuilds.
            # mars v0.28: arrows and j/k browse by BLOCK; ENTER inherits that
            # block's terminal direct jump command when present. Angle
            # brackets replay the independent history of the active PHI or
            # ASM pane.
            if key in ("h", "H"):
                self._toggle_highlight_mode(); dirty = True; continue
            if key in ("f", "F"):
                self._full(); dirty = True; continue
            if key in ("c", "C"):
                self._clear(); dirty = True; continue
            if key == "0":
                self._clear_active_history_v51(); dirty = True; continue
            if key == "n":
                self._move_match(1); dirty = True; continue
            if key == "N":
                self._move_match(-1); dirty = True; continue
            if key in ("\n", "\r", curses.KEY_ENTER):
                self._focus(); dirty = True; continue
            if self._highlight_mode() and key in (
                curses.KEY_DOWN, curses.KEY_NPAGE, curses.KEY_END, "j", "G"
            ):
                self._move_match(1); dirty = True; continue
            if self._highlight_mode() and key in (
                curses.KEY_UP, curses.KEY_PPAGE, curses.KEY_HOME, "k", "g"
            ):
                self._move_match(-1); dirty = True; continue
            if key in (
                curses.KEY_DOWN, curses.KEY_UP, curses.KEY_NPAGE,
                curses.KEY_PPAGE, curses.KEY_HOME, curses.KEY_END,
                curses.KEY_LEFT, curses.KEY_RIGHT,
                "j", "k", "h", "l", "g", "G",
            ):
                self._move(key); dirty = True; continue
            if key == curses.KEY_RESIZE:
                dirty = True

        self.owner._last_layout = None
        self.owner._dirty = True
        self.model.status = "returned from PAL evidence menu"


# ============================================================================
# v0.23b EXPANDED ARTIFACT VIEWERS (READ-ONLY, THEMED)
# ============================================================================

VIEWER_FILE_PREVIEW_BYTES = 2 * 1024 * 1024
VIEWER_INVENTORY_LIMIT = 2000


def _viewer_json_lines(value):
    try:
        return tuple(json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            default=str,
        ).splitlines())
    except Exception as exc:
        return ("JSON rendering failed: %s: %s" % (type(exc).__name__, exc),)


def _viewer_artifact_declared_path(value):
    if isinstance(value, dict):
        return value.get("path") or value.get("filename") or value.get("file")
    if isinstance(value, str):
        return value
    return None


def _viewer_resolve_path(root, value):
    declared = _viewer_artifact_declared_path(value)
    if not declared:
        return None
    path = os.fspath(declared)
    if os.path.isabs(path):
        return os.path.abspath(path)
    return os.path.abspath(os.path.join(os.path.abspath(root), path))


def _viewer_read_text_lines(path, maximum_bytes=VIEWER_FILE_PREVIEW_BYTES):
    """Read a bounded text/JSON preview without mutating the artifact."""
    path = os.path.abspath(os.fspath(path))
    if not os.path.isfile(path):
        return ("Artifact is missing: %s" % path,)
    compressed = path.lower().endswith(".gz")
    opener = gzip.open if compressed else open
    truncated = False
    try:
        with opener(path, "rb") as handle:
            raw = handle.read(int(maximum_bytes) + 1)
        if len(raw) > int(maximum_bytes):
            raw = raw[:int(maximum_bytes)]
            truncated = True
        text = raw.decode("utf-8", errors="replace")
    except Exception as exc:
        return (
            "Unable to read %s" % path,
            "%s: %s" % (type(exc).__name__, exc),
        )

    # Pretty-print complete bounded JSON documents.  Truncated JSON remains a
    # literal preview so the viewer never fabricates a repaired structure.
    lines = None
    if not truncated and (
        path.lower().endswith(".json")
        or path.lower().endswith(".json.gz")
    ):
        try:
            lines = _viewer_json_lines(json.loads(text))
        except Exception:
            lines = None
    if lines is None:
        lines = tuple(text.splitlines())
    if truncated:
        lines = tuple(lines) + (
            "",
            "[preview truncated after %d bytes]" % int(maximum_bytes),
        )
    return tuple(lines) or ("[empty artifact]",)


def _viewer_file_summary_lines(path, declared=None):
    path = os.path.abspath(os.fspath(path)) if path else None
    exists = bool(path and os.path.isfile(path))
    lines = [
        "declared: %s" % (declared if declared is not None else "-"),
        "resolved: %s" % (path or "-"),
        "exists:   %s" % exists,
    ]
    if exists:
        try:
            lines.append("bytes:    %d" % os.path.getsize(path))
        except OSError:
            pass
    lines.extend(("", "Press R for the bounded raw artifact view."))
    return tuple(lines)


def _viewer_make_view(key, title, curated_lines, raw_lines=None, targets=None):
    return {
        "key": str(key),
        "title": str(title),
        "curated_lines": tuple(str(value) for value in list(curated_lines or [])),
        "raw_lines": tuple(
            str(value) for value in list(
                raw_lines if raw_lines is not None else curated_lines or []
            )
        ),
        "targets": dict(targets or {}),
    }


def _viewer_file_view(key, title, path, declared=None):
    path = os.path.abspath(os.fspath(path)) if path else None
    raw = _viewer_read_text_lines(path) if path else ("No artifact path is declared.",)
    return _viewer_make_view(
        key,
        title,
        _viewer_file_summary_lines(path, declared=declared),
        raw,
    )


def _viewer_project_inventory(project_root):
    project_root = os.path.abspath(os.fspath(project_root))
    rows = []
    targets = {}
    if not os.path.isdir(project_root):
        return ("Project directory is missing: %s" % project_root,), targets
    for current, directories, filenames in os.walk(project_root):
        directories[:] = sorted(
            name for name in directories
            if name not in ("__pycache__", ".git", ".pytest_cache")
        )
        for filename in sorted(filenames):
            path = os.path.abspath(os.path.join(current, filename))
            relative = os.path.relpath(path, project_root)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            line_index = len(rows)
            rows.append("%10s  %s" % (
                str(size) if size >= 0 else "?",
                relative,
            ))
            targets[line_index] = path
            if len(rows) >= VIEWER_INVENTORY_LIMIT:
                rows.append("[inventory limited to %d files]" % VIEWER_INVENTORY_LIMIT)
                return tuple(rows), targets
    return tuple(rows or ("Project directory contains no files.",)), targets


def _viewer_report_inventory(project_root):
    project_root = os.path.abspath(os.fspath(project_root))
    rows = []
    targets = {}
    report_suffixes = (".log", ".txt", ".md", ".report", ".trace")
    report_tokens = ("report", "pipeline", "release", "readme", "notes", "trace")
    if not os.path.isdir(project_root):
        return ("Project directory is missing: %s" % project_root,), targets
    for current, directories, filenames in os.walk(project_root):
        directories[:] = sorted(
            name for name in directories
            if name not in ("__pycache__", ".git", ".pytest_cache")
        )
        for filename in sorted(filenames):
            lower = filename.casefold()
            if not (
                lower.endswith(report_suffixes)
                or any(token in lower for token in report_tokens)
            ):
                continue
            path = os.path.abspath(os.path.join(current, filename))
            relative = os.path.relpath(path, project_root)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            line_index = len(rows)
            rows.append("%10s  %s" % (
                str(size) if size >= 0 else "?",
                relative,
            ))
            targets[line_index] = path
            if len(rows) >= VIEWER_INVENTORY_LIMIT:
                rows.append("[report inventory limited to %d files]" % VIEWER_INVENTORY_LIMIT)
                return tuple(rows), targets
    return tuple(rows or ("No report/log/note artifacts were discovered.",)), targets


def _viewer_manifest_summary(payload, path):
    payload = dict(payload or {})
    program = dict(payload.get("program", {}) or {})
    functions = list(payload.get("functions", []) or [])
    counts = dict(payload.get("counts", {}) or {})
    decompiled = counts.get("decompiled")
    if not isinstance(decompiled, int):
        decompiled = sum(
            dict(record or {}).get("status") == "decompiled"
            for record in functions
        )
    return (
        "path:       %s" % path,
        "format:     %s" % (payload.get("format") or "-"),
        "schema:     %s" % (payload.get("schema_version") or "-"),
        "status:     %s" % (payload.get("status") or "-"),
        "program:    %s" % (program.get("name") or "-"),
        "functions:  %d" % len(functions),
        "decompiled: %s" % decompiled,
        "",
        "Press R for the complete bounded JSON view.",
    )


def _viewer_jump_summary(payload, path):
    if isinstance(payload, dict):
        keys = list(payload)
        return tuple([
            "path:       %s" % path,
            "kind:       mapping",
            "entries:    %d" % len(payload),
            "top keys:   %s" % ", ".join(str(value) for value in keys[:12]),
            "",
            "Press R for the complete bounded JSON view.",
        ])
    if isinstance(payload, list):
        return (
            "path:       %s" % path,
            "kind:       sequence",
            "entries:    %d" % len(payload),
            "",
            "Press R for the complete bounded JSON view.",
        )
    return (
        "path:       %s" % path,
        "kind:       %s" % type(payload).__name__,
        "",
        "Press R for the complete bounded JSON view.",
    )


def _viewer_oncs_summary(payload, path, function_id=None):
    payload = dict(payload or {})
    functions = dict(payload.get("functions", {}) or {})
    singular_function = dict(payload.get("function", {}) or {})
    variables = dict(payload.get("variables", {}) or {})
    function_count = len(functions) if functions else int(bool(singular_function))
    lines = [
        "path:               %s" % path,
        "format:             %s" % (payload.get("format") or "-"),
        "schema:             %s" % (payload.get("schema_version") or "-"),
        "function records:   %d" % function_count,
        "variable sections:  %d" % len(variables),
    ]
    if function_id:
        lines.extend((
            "selected function:  %s" % function_id,
            "function present:   %s" % (
                (str(function_id) in functions) or bool(singular_function)
            ),
            "variables present:  %s" % (str(function_id) in variables),
        ))
    lines.extend(("", "Press R for the complete bounded JSON view."))
    return tuple(lines)


def _viewer_project_views(record):
    record = dict(record or {})
    root = os.path.abspath(os.fspath(record.get("project_path") or os.getcwd()))
    manifest_path = os.path.abspath(os.fspath(
        record.get("manifest_path") or os.path.join(root, PROJECT_MANIFEST)
    ))
    jump_path = os.path.join(root, PROJECT_JUMP_TABLE)
    dispatch_path = os.path.join(root, PROJECT_DISPATCH)
    oncs_path = os.path.join(root, PROJECT_NAME_REGISTRY)

    manifest_payload = _read_json_file(manifest_path, {}) or {}
    jump_payload = _read_json_file(jump_path, {}) or {}
    oncs_payload = _read_json_file(oncs_path, {}) or {}
    artifacts = dict(record.get("artifacts", {}) or {})

    overview = (
        "project:      %s" % (record.get("project_name") or "-"),
        "program:      %s" % (record.get("program_name") or "-"),
        "root:         %s" % root,
        "status:       %s" % (record.get("status") or "-"),
        "functions:    %s" % (record.get("functions") or 0),
        "decompiled:   %s" % (record.get("decompiled") or 0),
        "manifest:     %s" % bool(artifacts.get("manifest")),
        "jump table:   %s" % bool(artifacts.get("jump_table")),
        "dispatch:     %s" % bool(artifacts.get("dispatch")),
        "functions dir:%s" % bool(artifacts.get("functions")),
        "ONCS:         %s" % bool(artifacts.get("oncs")),
        "",
        "Project Metadata custody is read-only; PAL semantics and ONCS writes are untouched.",
    )
    inventory_lines, inventory_targets = _viewer_project_inventory(root)
    report_lines, report_targets = _viewer_report_inventory(root)

    return (
        _viewer_make_view("overview", "OVERVIEW", overview, _viewer_json_lines(record)),
        _viewer_make_view(
            "manifest", "MANIFEST",
            _viewer_manifest_summary(manifest_payload, manifest_path),
            _viewer_read_text_lines(manifest_path),
        ),
        _viewer_make_view(
            "jump", "JUMP TABLE",
            _viewer_jump_summary(jump_payload, jump_path),
            _viewer_read_text_lines(jump_path),
        ),
        _viewer_file_view("dispatch", "DISPATCH", dispatch_path, PROJECT_DISPATCH),
        _viewer_make_view(
            "oncs", "ONCS",
            _viewer_oncs_summary(oncs_payload, oncs_path),
            _viewer_read_text_lines(oncs_path),
        ),
        _viewer_make_view(
            "inventory", "INVENTORY", inventory_lines, inventory_lines,
            targets=inventory_targets,
        ),
        _viewer_make_view(
            "reports", "REPORTS / NOTES", report_lines, report_lines,
            targets=report_targets,
        ),
    )


def _viewer_function_artifact_records(root, record, source_path=None):
    record = dict(record or {})
    artifacts = dict(record.get("artifacts", {}) or {})
    resolved = []
    seen = set()
    for key, value in sorted(artifacts.items()):
        path = _viewer_resolve_path(root, value)
        declared_path = _viewer_artifact_declared_path(value)
        if path and not os.path.isfile(path) and declared_path and not os.path.isabs(os.fspath(declared_path)):
            candidates = (
                os.path.join(root, PROJECT_FUNCTIONS_DIRECTORY, os.fspath(declared_path)),
                os.path.join(root, PROJECT_FUNCTIONS_DIRECTORY, os.path.basename(os.fspath(declared_path))),
            )
            for candidate_path in candidates:
                candidate_path = os.path.abspath(candidate_path)
                if os.path.isfile(candidate_path):
                    path = candidate_path
                    break
        marker = os.path.abspath(path) if path else None
        if marker and marker in seen:
            continue
        if marker:
            seen.add(marker)
        resolved.append({
            "key": str(key),
            "declared": value,
            "path": path,
        })
    if source_path:
        marker = os.path.abspath(os.fspath(source_path))
        if marker not in seen:
            resolved.append({
                "key": "icecube",
                "declared": source_path,
                "path": marker,
            })
            seen.add(marker)

    # Legacy manifests may expose only Icecube.  Add existing siblings by the
    # frozen function basename, without assuming they are present.
    anchors = [item.get("path") for item in resolved if item.get("path")]
    for anchor in anchors:
        directory = os.path.dirname(anchor)
        base = os.path.basename(anchor)
        stem = re.sub(
            r"(?:\.icecube\.json(?:\.gz)?|\.json(?:\.gz)?)$", "", base,
            flags=re.IGNORECASE,
        )
        if not os.path.isdir(directory):
            continue
        try:
            siblings = sorted(os.listdir(directory))
        except OSError:
            siblings = []
        for filename in siblings:
            lower = filename.casefold()
            if not filename.startswith(stem):
                continue
            if not lower.endswith((
                ".read.py", ".readable.py", ".exec.py", ".executable.py",
                ".log", ".txt", ".report", ".json", ".json.gz",
            )):
                continue
            path = os.path.abspath(os.path.join(directory, filename))
            if path in seen:
                continue
            seen.add(path)
            resolved.append({
                "key": "sibling",
                "declared": filename,
                "path": path,
            })
    return resolved


def _viewer_pick_artifact(records, include_tokens, exclude_tokens=()):
    include_tokens = tuple(str(value).casefold() for value in include_tokens)
    exclude_tokens = tuple(str(value).casefold() for value in exclude_tokens)
    best = None
    for item in records:
        key = str(item.get("key") or "").casefold()
        path = str(item.get("path") or "").casefold()
        haystack = key + "\n" + path
        if any(token in haystack for token in exclude_tokens):
            continue
        score = sum(1 for token in include_tokens if token in haystack)
        if not score:
            continue
        candidate = (score, bool(item.get("path") and os.path.isfile(item["path"])))
        if best is None or candidate > best[0]:
            best = (candidate, item)
    return dict(best[1]) if best else {}


def _viewer_artifact_inventory_lines(records):
    rows = []
    targets = {}
    for item in records:
        path = item.get("path")
        exists = bool(path and os.path.isfile(path))
        try:
            size = os.path.getsize(path) if exists else -1
        except OSError:
            size = -1
        line_index = len(rows)
        rows.append("%-14s %1s %10s  %s" % (
            str(item.get("key") or "artifact")[:14],
            "Y" if exists else "N",
            str(size) if size >= 0 else "?",
            path or _viewer_artifact_declared_path(item.get("declared")) or "-",
        ))
        if exists:
            targets[line_index] = path
    return tuple(rows or ("No function artifacts are declared.",)), targets


def _viewer_function_views(root, record, source_path=None, oncs_payload=None):
    root = os.path.abspath(os.fspath(root))
    record = dict(record or {})
    manifest_record = dict(record.get("manifest_record", {}) or {})
    if manifest_record:
        merged = dict(manifest_record)
        merged.update({key: value for key, value in record.items() if key != "manifest_record"})
        record = merged
    function_id = str(record.get("function_id") or "")
    artifacts = _viewer_function_artifact_records(root, record, source_path=source_path)
    inventory_lines, inventory_targets = _viewer_artifact_inventory_lines(artifacts)
    icecube = _viewer_pick_artifact(artifacts, ("icecube",))
    readable = _viewer_pick_artifact(
        artifacts,
        (".read.py", "readable", "read"),
        ("thread", "readme", "pipeline", ".log", "report", "trace"),
    )
    executable = _viewer_pick_artifact(
        artifacts,
        (".exec.py", "executable", "exec"),
        ("icecube", "pipeline", ".log", "report", "trace"),
    )
    pipeline = _viewer_pick_artifact(
        artifacts, ("pipeline", ".log", "report", "trace")
    )
    oncs_payload = dict(oncs_payload or {})
    oncs_selected = {
        "function_id": function_id or None,
        "function": dict(oncs_payload.get("function", {}) or {}),
        "variables": dict(oncs_payload.get("variables", {}) or {}),
    }

    identity = (
        "name:       %s" % (record.get("name") or "-"),
        "qualified:  %s" % (record.get("qualified_name") or "-"),
        "entry:      %s" % (record.get("entry_hex") or record.get("entry") or "-"),
        "function id:%s" % (function_id or "-"),
        "status:     %s" % (record.get("status") or "-"),
        "external:   %s" % bool(record.get("external")),
        "thunk:      %s" % bool(record.get("thunk")),
        "project:    %s" % root,
        "",
        "Press R for the manifest record.",
    )

    def artifact_view(key, title, item):
        path = item.get("path") if item else None
        declared = item.get("declared") if item else None
        return _viewer_file_view(key, title, path, declared=declared)

    return (
        _viewer_make_view("record", "FUNCTION RECORD", identity, _viewer_json_lines(record)),
        _viewer_make_view(
            "artifacts", "ARTIFACT INVENTORY", inventory_lines, inventory_lines,
            targets=inventory_targets,
        ),
        artifact_view("icecube", "ICECUBE", icecube),
        artifact_view("read", "READ.PY", readable),
        artifact_view("exec", "EXEC.PY", executable),
        artifact_view("pipeline", "PIPELINE / REPORT", pipeline),
        _viewer_make_view(
            "oncs", "FUNCTION ONCS",
            _viewer_oncs_summary(oncs_selected, root, function_id=function_id),
            _viewer_json_lines(oncs_selected),
        ),
        _viewer_make_view(
            "raw", "RAW BUNDLE",
            ("Function record and resolved artifact map.", "", "Press R for JSON."),
            _viewer_json_lines({"record": record, "artifacts": artifacts}),
        ),
    )





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
        body_top = 5
        body_height = max(1, height - 7)
        if self.workspace.line < self.workspace.top_line:
            self.workspace.top_line = self.workspace.line
        if self.workspace.line >= self.workspace.top_line + body_height:
            self.workspace.top_line = self.workspace.line - body_height + 1
        separator = "=" * max(0, width - 1)
        self._safe_addstr(0, 0, separator, curses.A_BOLD, width - 1)
        title = " PAL // PROJECTS | %s | %d projects " % (
            self.workspace.projects_root, len(self.workspace.records)
        )
        self._safe_addstr(1, 0, title.ljust(width), curses.A_BOLD, width - 1)
        self._safe_addstr(2, 0, separator, curses.A_BOLD, width - 1)
        commands = " ENTER OPEN | arrows/j/k BROWSE | r REFRESH | q SYSTEM PROMPT "
        self._safe_addstr(3, 0, commands.ljust(width), curses.A_REVERSE | curses.A_BOLD, width - 1)
        self._safe_addstr(4, 0, separator, curses.A_BOLD, width - 1)
        for row in range(body_height):
            index = self.workspace.top_line + row
            if index >= len(self.workspace.records):
                break
            selected = index == self.workspace.line
            marker = ">" if selected else " "
            text = "%s %s" % (marker, self._row_text(self.workspace.records[index]))
            attr = curses.A_REVERSE | curses.A_BOLD if selected else 0
            self._safe_addstr(body_top + row, 0, text.ljust(width), attr, width - 1)
        self._safe_addstr(max(5, height - 2), 0, separator, curses.A_BOLD, width - 1)
        self._safe_addstr(height - 1, 0, str(self.workspace.status or "").ljust(width), 0, width - 1)
        try:
            self.screen.noutrefresh(); curses.doupdate()
        except Exception:
            self.screen.refresh()

    def _open(self):
        try:
            return self.workspace.open_selected()
        except Exception as exc:
            self.workspace.status = "open failed: %s" % exc
            return None

    def run(self):
        dirty = True
        while True:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            if dirty:
                self.draw()
                dirty = False
            key = self.screen.get_wch()
            height, unused_width = self.screen.getmaxyx()
            page = max(1, height - 4)
            before = (
                int(self.workspace.line),
                int(self.workspace.top_line),
                str(self.workspace.status or ""),
            )
            explicit = False
            if key in ("q", "Q"):
                return None
            if key in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
                catalog = self._open()
                if catalog is not None:
                    return catalog
                explicit = True
            elif key in ("r", "R"):
                self.workspace.refresh()
                explicit = True
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
                explicit = True
            else:
                continue
            self.workspace.clamp()
            after = (
                int(self.workspace.line),
                int(self.workspace.top_line),
                str(self.workspace.status or ""),
            )
            dirty = explicit or after != before


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
        body_top = 5
        body_height = max(1, height - 7)
        if self.catalog.line < self.catalog.top_line:
            self.catalog.top_line = self.catalog.line
        if self.catalog.line >= self.catalog.top_line + body_height:
            self.catalog.top_line = self.catalog.line - body_height + 1
        separator = "=" * max(0, width - 1)
        self._safe_addstr(0, 0, separator, curses.A_BOLD, width - 1)
        title = " PAL // FUNCTIONS | %s | %d/%d | ONCS:%s | FILTER:%s " % (
            self.catalog.program_name, len(records), len(self.catalog.records),
            self.catalog.function_naming_label(), self.catalog.function_filter or "-",
        )
        self._safe_addstr(1, 0, title.ljust(width), curses.A_BOLD, width - 1)
        self._safe_addstr(2, 0, separator, curses.A_BOLD, width - 1)
        commands = (
            " ENTER OPEN | / FILTER | ^X CLEAR | F2 NAMES | ^O OPER | "
            "F4 RENAME | F5 REVERT | arrows/j/k BROWSE | q PROJECT "
        )
        self._safe_addstr(3, 0, commands.ljust(width), curses.A_REVERSE | curses.A_BOLD, width - 1)
        self._safe_addstr(4, 0, separator, curses.A_BOLD, width - 1)
        for row in range(body_height):
            index = self.catalog.top_line + row
            if index >= len(records):
                break
            selected = index == self.catalog.line
            marker = ">" if selected else " "
            text = "%s %s" % (marker, self._row_text(records[index]))
            attr = curses.A_REVERSE | curses.A_BOLD if selected else 0
            self._safe_addstr(body_top + row, 0, text.ljust(width), attr, width - 1)
        self._safe_addstr(max(5, height - 2), 0, separator, curses.A_BOLD, width - 1)
        self._safe_addstr(height - 1, 0, str(self.catalog.status or "").ljust(width), 0, width - 1)
        try:
            self.screen.noutrefresh(); curses.doupdate()
        except Exception:
            self.screen.refresh()

    def _open(self):
        try:
            record = self.catalog.selected_record() or {}
            estimated_loc = _function_record_loc_v35(self.catalog, record)
            if estimated_loc > LARGE_FUNCTION_LOC_THRESHOLD_V35:
                _show_large_metadata_loader_v35(
                    self.screen, estimated_loc, "FUNCTION INITIALIZATION"
                )
            model = self.catalog.open_selected(
                verify=self.verify,
                projection=self.projection,
                naming=self.catalog.viewer_naming,
                operator_overlay=self.catalog.viewer_operator_overlay,
            )
            actual_loc = _model_loc_v35(model)
            if not estimated_loc and actual_loc > LARGE_FUNCTION_LOC_THRESHOLD_V35:
                model.status = (
                    "large function metadata loaded | LOC=%d" % actual_loc
                )
            return model
        except Exception as exc:
            self.catalog.status = "open failed: %s" % exc
            return None

    def run(self):
        dirty = True
        while True:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            if dirty:
                self.draw()
                dirty = False
            key = self.screen.get_wch()
            height, unused_width = self.screen.getmaxyx()
            page = max(1, height - 4)
            before = (
                int(self.catalog.line),
                int(self.catalog.top_line),
                str(self.catalog.function_filter or ""),
                str(self.catalog.function_naming),
                bool(self.catalog.function_operator_overlay),
                str(self.catalog.status or ""),
            )
            explicit = False
            if key in ("q", "Q"):
                return None
            if key == "/":
                value = self._prompt(
                    "filter function names> ", self.catalog.function_filter
                )
                if value is not None:
                    self.catalog.set_function_filter(value)
                dirty = True
                continue
            if key == "\x18":
                self.catalog.clear_function_filter()
                dirty = True
                continue
            if key in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
                model = self._open()
                if model is not None:
                    return model
                explicit = True
            elif key == curses.KEY_F2:
                self.catalog.cycle_function_naming()
                explicit = True
            elif key == "\x0f":
                self.catalog.toggle_function_operator_overlay()
                explicit = True
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
                explicit = True
            elif key == curses.KEY_F5:
                try:
                    self.catalog.clear_selected_function()
                except Exception as exc:
                    self.catalog.status = "function revert failed: %s" % exc
                explicit = True
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
                self.catalog.line = max(
                    0, len(self.catalog.visible_records()) - 1
                )
            elif key == curses.KEY_RESIZE:
                explicit = True
            else:
                continue
            self.catalog.clamp()
            after = (
                int(self.catalog.line),
                int(self.catalog.top_line),
                str(self.catalog.function_filter or ""),
                str(self.catalog.function_naming),
                bool(self.catalog.function_operator_overlay),
                str(self.catalog.status or ""),
            )
            dirty = explicit or after != before


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
            "Detached VT100/curses PAL browser, expanded artifact viewer and ONCS editor"
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
