# ============================================================
# PAL TRUTH DIGEST DAILY
# BUILD: truth_digest_v6_glitter_clean_source_metadata
# ============================================================

import json
import re


PANEL_ORDER = (
    "c_code",
    "function_definition",
    "called_functions",
    "abi_custody",
    "asm",
)

PANEL_KEYS = {
    "c_code": "F1",
    "function_definition": "F2",
    "called_functions": "F3",
    "abi_custody": "F4",
    "asm": "F5",
}

PANEL_TITLES = {
    "c_code": "C CODE",
    "function_definition": "FUNCTION & VARIABLE DEFINITIONS",
    "called_functions": "CALLED-BY-MODULE FUNCTION LIST",
    "abi_custody": "ABI CUSTODY INTERFACES",
    "asm": "BLOCK ASM",
}

_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_NAME_KEYS = (
    "pal_name", "display_name", "name", "original_name", "ssa_name",
    "canonical_ssa_name", "active_name", "generated_human_alias",
    "operator_alias", "python_symbol", "label", "symbol",
)


def percentage_document_position(line, line_count):
    """Return a stable 0.0..1.0 document position for soft cross-view sync."""
    try:
        count = max(0, int(line_count))
        index = max(0, int(line))
    except Exception:
        return 0.0
    if count <= 1:
        return 0.0
    return min(1.0, max(0.0, float(index) / float(count - 1)))


def line_from_document_position(position, line_count):
    """Map a document percentage into a clamped zero-based line index."""
    try:
        count = max(0, int(line_count))
        value = min(1.0, max(0.0, float(position)))
    except Exception:
        return 0
    if count <= 1:
        return 0
    return min(count - 1, max(0, int(round(value * float(count - 1)))))


def _statement_value(statement, name, default=None):
    if isinstance(statement, dict):
        return statement.get(name, default)
    return getattr(statement, name, default)


def _projection_lines(document, projection, view=None):
    if view is not None:
        lines = list(getattr(view, "lines", []) or [])
        if lines:
            return [str(value) for value in lines]
    for call in (
        lambda: document.export_lines(
            projection, naming="pal", include_edits=False
        ),
        lambda: document.project_alias_lines(projection, naming="pal"),
    ):
        try:
            lines = list(call() or [])
        except Exception:
            lines = []
        if lines:
            return [str(value) for value in lines]
    return []


def _statement_line(statement, ordinal):
    for key in (
        "line", "line_number", "line_index", "source_line", "start_line",
        "line_start", "rendered_line", "projection_line",
    ):
        value = _statement_value(statement, key)
        if isinstance(value, int):
            return max(0, int(value))
    span = _statement_value(statement, "source_span")
    if isinstance(span, dict):
        for key in ("line", "start_line", "line_start"):
            value = span.get(key)
            if isinstance(value, int):
                return max(0, int(value))
    # PALCodeDocument statements are emitted in projection order.
    return max(0, int(ordinal))


def _statement_column(statement, text):
    for key in (
        "column", "column_number", "column_index", "source_column",
        "start_column", "column_start", "rendered_column",
        "projection_column",
    ):
        value = _statement_value(statement, key)
        if isinstance(value, int):
            return max(0, min(int(value), len(text)))
    span = _statement_value(statement, "source_span")
    if isinstance(span, dict):
        for key in ("column", "start_column", "column_start"):
            value = span.get(key)
            if isinstance(value, int):
                return max(0, min(int(value), len(text)))
    return len(text) - len(text.lstrip())


def _metadata_resolve(document, reference):
    metadata = getattr(document, "metadata", None)
    resolver = getattr(metadata, "resolve", None)
    if not callable(resolver):
        return None
    try:
        return resolver(reference, None)
    except TypeError:
        try:
            return resolver(reference)
        except Exception:
            return None
    except Exception:
        return None


def _mapping(value):
    if isinstance(value, dict):
        return dict(value)
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        try:
            result = as_dict()
            return dict(result) if isinstance(result, dict) else {}
        except Exception:
            return {}
    data = getattr(value, "__dict__", None)
    return dict(data) if isinstance(data, dict) else {}


def _context_names(identity, record=None):
    names = set()
    record = _mapping(record)
    for key in _NAME_KEYS:
        value = record.get(key)
        if isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value):
            names.add(value)
    if isinstance(identity, str):
        tail = identity.split(":", 1)[-1]
        if _IDENTIFIER_RE.fullmatch(tail):
            names.add(tail)
    return sorted(names, key=lambda value: (-len(value), value))


def _identifier_spans(text, names):
    wanted = set(str(value) for value in names if value)
    if not wanted:
        return []
    return [
        (match.start(), match.end(), match.group(0))
        for match in _IDENTIFIER_RE.finditer(str(text))
        if match.group(0) in wanted
    ]


def _object_specs(document, statement):
    specs = []
    seen = set()

    def add(kind, identity, reference=None, record=None, role=None):
        if identity is None:
            return
        identity = str(identity)
        key = (str(kind or "object"), identity, str(role or ""))
        if key in seen:
            return
        seen.add(key)
        specs.append({
            "kind": str(kind or "object"),
            "identity": identity,
            "metadata_ref": reference,
            "role": role,
            "record": _mapping(record),
            "names": _context_names(identity, record),
        })

    for sid in list(_statement_value(statement, "definition_sids", []) or []):
        ref = "variable:%s" % sid
        add("variable", sid, ref, _metadata_resolve(document, ref), "definition")
    for sid in list(_statement_value(statement, "use_sids", []) or []):
        ref = "variable:%s" % sid
        add("variable", sid, ref, _metadata_resolve(document, ref), "use")

    for reference in list(_statement_value(statement, "metadata_refs", []) or []):
        reference = str(reference)
        record = _metadata_resolve(document, reference)
        mapped = _mapping(record)
        kind = (
            mapped.get("kind") or mapped.get("object_kind")
            or mapped.get("type") or reference.split(":", 1)[0]
        )
        identity = (
            mapped.get("sid") or mapped.get("object_id")
            or mapped.get("identity") or mapped.get("id") or reference
        )
        add(kind, identity, reference, mapped, "metadata")

    raw_contexts = (
        list(_statement_value(statement, "object_contexts", []) or [])
        + list(_statement_value(statement, "objects", []) or [])
        + list(_statement_value(statement, "tagged_objects", []) or [])
    )
    for item in raw_contexts:
        mapped = _mapping(item)
        identity = (
            mapped.get("identity") or mapped.get("object_id")
            or mapped.get("sid") or mapped.get("id")
        )
        kind = mapped.get("kind") or mapped.get("object_kind") or "object"
        add(kind, identity, mapped.get("metadata_ref"), mapped, "object_context")
    return specs


def projection_hotspots(document, projection):
    """Build ordered object-aware hotspots frozen in an Icecube projection.

    Newer Icecubes expose per-statement object context.  This routine anchors
    variable/function/metadata identities to their actual token columns instead
    of forcing every hotspot to column zero.  Statement-level and non-blank-line
    fallbacks remain for older Icecubes.
    """
    view = None
    try:
        view = document.projection(projection)
    except Exception:
        projections = getattr(document, "projections", {})
        if isinstance(projections, dict):
            view = projections.get(projection)

    lines = _projection_lines(document, projection, view=view)
    statements = list(getattr(view, "statements", []) or []) if view is not None else []
    hotspots = []
    seen = set()

    def append(item):
        key = (
            int(item.get("line", 0)), int(item.get("column", 0)),
            str(dict(item.get("object_context", {}) or {}).get("kind") or ""),
            str(dict(item.get("object_context", {}) or {}).get("identity") or ""),
            str(item.get("statement_id") or ""),
        )
        if key in seen:
            return
        seen.add(key)
        hotspots.append(item)

    for ordinal, statement in enumerate(statements):
        line = _statement_line(statement, ordinal)
        text = lines[line] if 0 <= line < len(lines) else ""
        statement_id = (
            _statement_value(statement, "statement_id")
            or _statement_value(statement, "id")
        )
        cfg_block = (
            _statement_value(statement, "cfg_block_addr")
            or _statement_value(statement, "block_addr")
        )
        op_keys = list(_statement_value(statement, "op_keys", []) or [])
        metadata_refs = list(_statement_value(statement, "metadata_refs", []) or [])
        definitions = list(_statement_value(statement, "definition_sids", []) or [])
        uses = list(_statement_value(statement, "use_sids", []) or [])
        common = {
            "line": line,
            "statement_id": statement_id,
            "cfg_block_addr": cfg_block,
            "op_keys": op_keys,
            "metadata_refs": metadata_refs,
            "definition_sids": definitions,
            "use_sids": uses,
        }

        anchored = False
        for context in _object_specs(document, statement):
            spans = _identifier_spans(text, context.get("names", []))
            for start, end, token_name in spans:
                item = dict(common)
                item.update({
                    "column": int(start),
                    "end_column": int(end),
                    "token": token_name,
                    "object_context": {
                        key: value for key, value in context.items()
                        if key != "record"
                    },
                })
                append(item)
                anchored = True

        evidence = bool(
            statement_id or cfg_block is not None or op_keys
            or metadata_refs or definitions or uses
        )
        if evidence and not anchored:
            column = _statement_column(statement, text)
            item = dict(common)
            item.update({
                "column": column,
                "end_column": min(len(text), column + 1),
                "statement_fallback": True,
            })
            append(item)

    if hotspots:
        hotspots.sort(key=lambda item: (
            int(item.get("line", 0)), int(item.get("column", 0)),
            str(dict(item.get("object_context", {}) or {}).get("identity") or ""),
            str(item.get("statement_id") or ""),
        ))
        return hotspots

    return [
        {
            "line": index,
            "column": len(str(text)) - len(str(text).lstrip()),
            "end_column": len(str(text)) - len(str(text).lstrip()) + 1,
            "fallback": True,
        }
        for index, text in enumerate(lines)
        if str(text).strip()
    ]


class TruthDigestDaily:
    """Bird's-eye metadata browser. R always exposes the unfiltered bundle."""

    def __init__(self, metadata_view, oncs_rows=None, cursor=None):
        self.metadata_view = metadata_view
        self.oncs_rows = list(oncs_rows or [])
        self.cursor = dict(cursor or {})
        self.bundle = metadata_view.digest_bundle(
            block_addr=self.cursor.get("cfg_block_addr")
        )
        self.panel = "function_definition"
        self.raw = False

    def select(self, panel):
        if panel not in PANEL_ORDER:
            raise ValueError("unknown Truth Digest panel %r" % panel)
        self.panel = panel
        self.raw = False
        return panel

    def toggle_raw(self):
        self.raw = not self.raw
        return self.raw

    def _header(self):
        function = dict(self.bundle.get("raw", {}).get("function_record", {}) or {})
        function_name = (
            function.get("active_name") or function.get("generated_name")
            or function.get("name") or "function"
        )
        return [
            "TRUTH DIGEST DAILY",
            "==================",
            "%s  |  function=%s  |  projection=%s  |  line=%s col=%s" % (
                PANEL_TITLES[self.panel],
                function_name,
                self.cursor.get("projection", "-"),
                int(self.cursor.get("line", 0)) + 1,
                int(self.cursor.get("column", 0)) + 1,
            ),
            "",
        ]

    def _oncs_section(self):
        if self.panel != "function_definition":
            return []
        lines = ["", "ONCS VARIABLE DEFINITIONS", "-------------------------"]
        if not self.oncs_rows:
            lines.append("  no variable contracts available")
            return lines
        for row in self.oncs_rows:
            marker = ">" if row.get("selected") else " "
            role = (
                "p_%s" % row.get("parameter_index")
                if isinstance(row.get("parameter_index"), int)
                else "var"
            )
            lock = "LOCK" if row.get("rename_locked") else row.get("source") or "PAL"
            lines.append(
                "%s %-5s SSA=%-13s PAL=%-17s HUMAN=%-15s OP=%-15s [%s]" % (
                    marker,
                    role,
                    row.get("ssa") or "-",
                    row.get("pal") or "-",
                    row.get("humanizer") or "-",
                    row.get("operator") or "-",
                    lock,
                )
            )
        return lines

    @staticmethod
    def _numbered_source(lines):
        lines = [str(value) for value in list(lines or [])]
        width = max(3, len(str(max(1, len(lines)))))
        return [
            "%*d | %s" % (width, ordinal + 1, value)
            for ordinal, value in enumerate(lines)
        ]

    def source_lines(self, panel=None):
        """Return only frozen C/ASM metadata lines, without report decoration.

        This is the clean export/display path used by the four-pane looking
        glass.  The interactive Truth Digest may still add its own navigational
        header and footer, but source-machine panes consume only these records.
        """
        panel_name = str(panel or self.panel)
        if panel_name not in ("c_code", "asm"):
            raise ValueError("source lines are available only for C and ASM")
        record = dict(self.bundle.get(panel_name, {}) or {})
        return [str(value) for value in list(record.get("lines", []) or [])]

    def _panel_lines(self, panel):
        lines = [str(value) for value in list(panel.get("lines", []) or [])]
        if self.panel == "c_code" and not panel.get("shim"):
            return self._numbered_source(lines)
        if self.panel == "asm" and not panel.get("shim"):
            summary = "blocks=%s instructions=%s" % (
                panel.get("blocks", "?"),
                panel.get("instruction_count", "?"),
            )
            return [summary, ""] + lines
        return lines

    def _source_machine_diagnostic(self):
        raw = dict(self.bundle.get("raw", {}) or {})
        metadata = dict(raw.get("metadata", {}) or {})
        index = dict(metadata.get("source_machine:index", {}) or {})
        source_path = self.cursor.get("source_path") or "<unknown icecube>"
        if not index:
            return [
                "",
                "SOURCE-MACHINE METADATA ABSENT",
                "--------------------------------",
                "loaded icecube: %s" % source_path,
                "This snapshot was not frozen by the C/ASM-enabled PALIcecube.py.",
                "Regenerate the icecube after PALBatchDecompiler imports PALIcecube directly.",
            ]
        return [
            "",
            "SOURCE-MACHINE INDEX",
            "--------------------",
            "loaded icecube: %s" % source_path,
            "C present=%s | ASM blocks=%s | ASM instructions=%s" % (
                index.get("c_code_present", False),
                index.get("asm_blocks", 0),
                index.get("asm_instructions", 0),
            ),
        ]

    def lines(self):
        if self.raw:
            return json.dumps(
                {
                    "bundle": self.bundle,
                    "oncs": self.oncs_rows,
                    "cursor": self.cursor,
                },
                indent=2,
                sort_keys=True,
                default=str,
            ).splitlines()

        panel = dict(self.bundle.get(self.panel, {}) or {})
        lines = self._header()
        source = panel.get("source") or "unknown"
        lines.append("source: %s%s" % (
            source,
            "  [SIM SHIM]" if panel.get("shim")
            else "  [FROZEN PALlibrary EVIDENCE]"
            if self.panel in ("c_code", "asm") else "",
        ))
        lines.append("-" * min(78, max(20, len(lines[-1]))))
        lines.extend(self._panel_lines(panel))
        if panel.get("shim") and self.panel in ("c_code", "asm"):
            lines.extend(self._source_machine_diagnostic())
        lines.extend(self._oncs_section())
        lines.extend([
            "",
            "F1 C code | F2 func/vars | F3 calls | F4 ABI | F5 ASM | R raw | Esc close",
        ])
        return lines


__all__ = [
    "TruthDigestDaily", "PANEL_ORDER", "PANEL_KEYS", "PANEL_TITLES",
    "percentage_document_position", "line_from_document_position",
    "projection_hotspots",
]
