# ============================================================
# PAL CODE DOCUMENT
# BUILD: im_d_v1_projection_alias_edit_sidecars
# Frozen, serialization-neutral provenance substrate for PAL projections
# ============================================================

import bisect
import gzip
import hashlib
import io
import json
import keyword
import math
import os
import re
import token
import tokenize
from dataclasses import dataclass, field


def _stable_text(value):
    """Return deterministic, display-safe identity text."""
    if value is None:
        return None
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, (tuple, list)):
        return "(" + ",".join(_stable_text(v) or "None" for v in value) + ")"
    return str(value)


def _unique(values):
    out = []
    seen = set()
    for value in list(values or []):
        if value is None:
            continue
        key = _stable_text(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _json_safe(value):
    """Detach bundle content from PyGhidra and other process-local objects."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        return {"kind": "bytes", "hex": value.hex()}
    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted((_json_safe(item) for item in value), key=str)
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return _json_safe(as_dict())
    return {
        "kind": "detached_object",
        "type": type(value).__name__,
        "text": str(value),
    }


def _canonical_json(value):
    return json.dumps(
        _json_safe(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


@dataclass
class ProvenanceSpan:
    """Half-open [start, end) provenance interval in frozen ASCII text."""

    span_id: str
    projection: str
    start_offset: int
    end_offset: int
    kind: str
    entity_id: str = None
    statement_id: str = None
    metadata_refs: list = field(default_factory=list)
    role: str = None
    token_text: str = None
    candidate_entity_ids: list = field(default_factory=list)
    confidence: str = None

    def as_dict(self):
        return {
            "span_id": self.span_id,
            "projection": self.projection,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "kind": self.kind,
            "entity_id": self.entity_id,
            "statement_id": self.statement_id,
            "metadata_refs": list(self.metadata_refs),
            "role": self.role,
            "token_text": self.token_text,
            "candidate_entity_ids": list(self.candidate_entity_ids),
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            span_id=str(data.get("span_id")),
            projection=str(data.get("projection")),
            start_offset=int(data.get("start_offset", 0)),
            end_offset=int(data.get("end_offset", 0)),
            kind=str(data.get("kind") or "statement_line"),
            entity_id=data.get("entity_id"),
            statement_id=data.get("statement_id"),
            metadata_refs=list(data.get("metadata_refs", []) or []),
            role=data.get("role"),
            token_text=data.get("token_text"),
            candidate_entity_ids=list(
                data.get("candidate_entity_ids", []) or []
            ),
            confidence=data.get("confidence"),
        )


@dataclass
class CursorContext:
    """Line-level cursor result that survives a frozen bundle round-trip."""

    projection: str
    offset: int = None
    line: int = None
    column: int = None
    statement_id: str = None
    exec_occurrence_id: str = None
    block_occurrence_id: str = None
    cfg_block_addr: object = None
    role: str = None
    op_keys: list = field(default_factory=list)
    definition_sids: list = field(default_factory=list)
    use_sids: list = field(default_factory=list)
    entity_ids: list = field(default_factory=list)
    metadata_refs: list = field(default_factory=list)
    span_ids: list = field(default_factory=list)
    state: str = None
    metadata_status: str = None
    primary_span_id: str = None
    primary_kind: str = None
    primary_entity_id: str = None
    primary_role: str = None
    token_text: str = None
    candidate_entity_ids: list = field(default_factory=list)

    def as_dict(self):
        return {
            "projection": self.projection,
            "offset": self.offset,
            "line": self.line,
            "column": self.column,
            "statement_id": self.statement_id,
            "exec_occurrence_id": self.exec_occurrence_id,
            "block_occurrence_id": self.block_occurrence_id,
            "cfg_block_addr": self.cfg_block_addr,
            "role": self.role,
            "op_keys": list(self.op_keys),
            "definition_sids": list(self.definition_sids),
            "use_sids": list(self.use_sids),
            "entity_ids": list(self.entity_ids),
            "metadata_refs": list(self.metadata_refs),
            "span_ids": list(self.span_ids),
            "state": self.state,
            "metadata_status": self.metadata_status,
            "primary_span_id": self.primary_span_id,
            "primary_kind": self.primary_kind,
            "primary_entity_id": self.primary_entity_id,
            "primary_role": self.primary_role,
            "token_text": self.token_text,
            "candidate_entity_ids": list(self.candidate_entity_ids),
        }


@dataclass
class ExecOccurrenceRecord:
    occurrence_id: str
    function_name: str
    exec_path: tuple
    node_kind: str
    cfg_block_addr: object = None
    projections: set = field(default_factory=set)
    metadata_refs: list = field(default_factory=list)

    def observe(self, projection, cfg_block_addr=None, metadata_refs=None):
        if projection:
            self.projections.add(str(projection))
        if self.cfg_block_addr is None and cfg_block_addr is not None:
            self.cfg_block_addr = cfg_block_addr
        self.metadata_refs = _unique(
            list(self.metadata_refs) + list(metadata_refs or [])
        )

    def as_dict(self):
        return {
            "occurrence_id": self.occurrence_id,
            "function_name": self.function_name,
            "exec_path": list(self.exec_path),
            "node_kind": self.node_kind,
            "cfg_block_addr": self.cfg_block_addr,
            "projections": sorted(self.projections),
            "metadata_refs": list(self.metadata_refs),
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            occurrence_id=str(data.get("occurrence_id")),
            function_name=str(data.get("function_name") or "func"),
            exec_path=tuple(data.get("exec_path", []) or []),
            node_kind=str(data.get("node_kind") or "node"),
            cfg_block_addr=data.get("cfg_block_addr"),
            projections=set(data.get("projections", []) or []),
            metadata_refs=list(data.get("metadata_refs", []) or []),
        )


# Public semantic alias retained because block-oriented UI consumers are the
# first inline-metadata client. The document separately indexes true CFG-backed block
# occurrences and all structural ExecTree occurrences.
BlockOccurrenceRecord = ExecOccurrenceRecord


@dataclass
class StatementRecord:
    statement_id: str
    projection: str
    line_number: int
    text: str
    role: str
    exec_occurrence_id: str = None
    block_occurrence_id: str = None
    cfg_block_addr: object = None
    op_keys: list = field(default_factory=list)
    definition_sids: list = field(default_factory=list)
    use_sids: list = field(default_factory=list)
    metadata_refs: list = field(default_factory=list)
    operation_fragments: list = field(default_factory=list)
    state: str = "original"
    metadata_status: str = "original"

    def as_dict(self):
        return {
            "statement_id": self.statement_id,
            "projection": self.projection,
            "line_number": self.line_number,
            "text": self.text,
            "role": self.role,
            "exec_occurrence_id": self.exec_occurrence_id,
            "block_occurrence_id": self.block_occurrence_id,
            "cfg_block_addr": self.cfg_block_addr,
            "op_keys": [_stable_text(v) for v in self.op_keys],
            "definition_sids": [_stable_text(v) for v in self.definition_sids],
            "use_sids": [_stable_text(v) for v in self.use_sids],
            "metadata_refs": list(self.metadata_refs),
            "operation_fragments": _json_safe(self.operation_fragments),
            "state": self.state,
            "metadata_status": self.metadata_status,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            statement_id=str(data.get("statement_id")),
            projection=str(data.get("projection")),
            line_number=int(data.get("line_number", 0)),
            text=str(data.get("text", "")),
            role=str(data.get("role") or "statement"),
            exec_occurrence_id=data.get("exec_occurrence_id"),
            block_occurrence_id=data.get("block_occurrence_id"),
            cfg_block_addr=data.get("cfg_block_addr"),
            op_keys=list(data.get("op_keys", []) or []),
            definition_sids=list(data.get("definition_sids", []) or []),
            use_sids=list(data.get("use_sids", []) or []),
            metadata_refs=list(data.get("metadata_refs", []) or []),
            operation_fragments=list(data.get("operation_fragments", []) or []),
            state=str(data.get("state") or "original"),
            metadata_status=str(data.get("metadata_status") or "original"),
        )


class MetadataRegistry:
    """Lightweight reference registry; large PAL records stay out of spans."""

    def __init__(self):
        self._records = {}

    def register(self, reference, value):
        if reference is None:
            return None
        key = str(reference)
        self._records[key] = value
        return key

    def resolve(self, reference, default=None):
        return self._records.get(str(reference), default)

    def clear(self):
        self._records.clear()

    def items(self):
        return list(self._records.items())

    def references(self):
        return sorted(self._records)

    def __len__(self):
        return len(self._records)

    def as_dict(self):
        return {
            key: _json_safe(value)
            for key, value in sorted(self._records.items())
        }

    @classmethod
    def from_dict(cls, data):
        registry = cls()
        registry._records = dict(data or {})
        return registry


class PALCodeProjection:
    """One frozen ASCII projection plus line-level source-map records."""

    def __init__(self, mode):
        self.mode = str(mode)
        self.lines = []
        self.text = ""
        self.line_offsets = []
        self.statements = []
        self.statement_by_id = {}
        self.statement_ids_by_line = {}
        self.spans = []
        self.spans_by_line = {}
        self.finalized = False

    def add_line(self, text, statement):
        if self.finalized:
            raise RuntimeError("cannot add a line to a finalized PAL projection")
        line_number = len(self.lines)
        text = str(text)
        if statement.line_number != line_number:
            raise ValueError("statement line number does not match projection")
        self.lines.append(text)
        self.statements.append(statement)
        self.statement_by_id.setdefault(statement.statement_id, []).append(statement)
        self.statement_ids_by_line.setdefault(line_number, []).append(
            statement.statement_id
        )

    def finalize(self):
        self.text = "\n".join(self.lines)
        self.line_offsets = []
        self.spans = []
        self.spans_by_line = {}
        offset = 0
        for line_number, line in enumerate(self.lines):
            self.line_offsets.append(offset)
            statement_ids = self.statement_ids_by_line.get(line_number, [])
            for span_ordinal, statement_id in enumerate(statement_ids):
                records = self.statement_by_id.get(statement_id, [])
                record = next(
                    (
                        item for item in records
                        if item.line_number == line_number
                    ),
                    None,
                )
                span = ProvenanceSpan(
                    span_id="span:%s:line:%d:%d" % (
                        self.mode, line_number, span_ordinal
                    ),
                    projection=self.mode,
                    start_offset=offset,
                    end_offset=offset + len(line),
                    kind="statement_line",
                    entity_id=statement_id,
                    statement_id=statement_id,
                    metadata_refs=list(
                        getattr(record, "metadata_refs", []) or []
                    ),
                    role="statement_owner",
                    confidence="authoritative",
                )
                self.spans.append(span)
                self.spans_by_line.setdefault(line_number, []).append(span)
            offset += len(line) + 1
        self.finalized = True
        return self

    def add_span(self, span, line_number=None):
        if not self.finalized:
            self.finalize()
        if span.projection != self.mode:
            raise ValueError("PAL inline span projection mismatch")
        if span.start_offset < 0 or span.end_offset < span.start_offset:
            raise ValueError("PAL inline span range is invalid")
        if span.end_offset > len(self.text):
            raise ValueError("PAL inline span exceeds projection text")
        self.spans.append(span)
        if line_number is None:
            line_number, _ = self.position_for_offset(
                span.start_offset, line_base=0, clamp=True
            )
        self.spans_by_line.setdefault(int(line_number), []).append(span)
        return span

    def replace_spans(self, spans):
        self.spans = []
        self.spans_by_line = {}
        for span in list(spans or []):
            self.add_span(span)
        self._sort_spans()

    def _sort_spans(self):
        priority = {
            "variable": 0,
            "constant": 0,
            "operation": 1,
            "helper": 2,
            "statement_line": 9,
        }
        key = lambda span: (
            span.start_offset,
            priority.get(span.kind, 5),
            max(0, span.end_offset - span.start_offset),
            span.span_id,
        )
        self.spans.sort(key=key)
        for values in self.spans_by_line.values():
            values.sort(key=key)

    def spans_at_offset(self, offset, line=None):
        if not self.finalized:
            self.finalize()
        offset = int(offset)
        if line is None:
            line, _ = self.position_for_offset(offset, line_base=0, clamp=True)
        candidates = self.spans_for_line(line, line_base=0)
        out = []
        for span in candidates:
            if span.start_offset <= offset < span.end_offset:
                out.append(span)
            elif span.start_offset == span.end_offset == offset:
                out.append(span)
            elif (
                offset == len(self.text)
                and span.end_offset == offset
                and span.start_offset < span.end_offset
            ):
                out.append(span)
        priority = {
            "variable": 0,
            "constant": 0,
            "operation": 1,
            "helper": 2,
            "statement_line": 9,
        }
        return sorted(
            out,
            key=lambda span: (
                priority.get(span.kind, 5),
                max(0, span.end_offset - span.start_offset),
                span.span_id,
            ),
        )

    def offset_for_position(self, line, column=0, line_base=0, clamp=False):
        if not self.finalized:
            self.finalize()
        line = int(line) - int(line_base)
        column = int(column)
        if not self.lines:
            raise IndexError("PAL projection contains no lines")
        if clamp:
            line = min(max(line, 0), len(self.lines) - 1)
            column = min(max(column, 0), len(self.lines[line]))
        elif line < 0 or line >= len(self.lines):
            raise IndexError("line outside PAL projection")
        elif column < 0 or column > len(self.lines[line]):
            raise IndexError("column outside PAL projection line")
        return self.line_offsets[line] + column

    def position_for_offset(self, offset, line_base=0, clamp=False):
        if not self.finalized:
            self.finalize()
        if not self.lines:
            raise IndexError("PAL projection contains no lines")
        offset = int(offset)
        maximum = len(self.text)
        if clamp:
            offset = min(max(offset, 0), maximum)
        elif offset < 0 or offset > maximum:
            raise IndexError("offset outside PAL projection")
        line = bisect.bisect_right(self.line_offsets, offset) - 1
        line = min(max(line, 0), len(self.lines) - 1)
        column = offset - self.line_offsets[line]
        column = min(max(column, 0), len(self.lines[line]))
        return line + int(line_base), column

    def statements_for_line(self, line, line_base=0):
        line = int(line) - int(line_base)
        if line < 0 or line >= len(self.lines):
            return []
        ids = list(self.statement_ids_by_line.get(line, []) or [])
        out = []
        for statement_id in ids:
            out.extend(
                record for record in self.statement_by_id.get(statement_id, [])
                if record.line_number == line
            )
        return out

    def spans_for_line(self, line, line_base=0):
        line = int(line) - int(line_base)
        if line < 0 or line >= len(self.lines):
            return []
        return list(self.spans_by_line.get(line, []) or [])

    def to_text(self, final_newline=False):
        text = self.text if self.finalized else "\n".join(self.lines)
        if final_newline and text and not text.endswith("\n"):
            return text + "\n"
        return text

    def as_dict(self, include_lines=False, include_statements=True):
        out = {
            "mode": self.mode,
            "line_count": len(self.lines),
            "statement_count": len(self.statements),
            "line_offsets": list(self.line_offsets),
            "span_count": len(self.spans),
            "finalized": bool(self.finalized),
        }
        if include_lines:
            out["lines"] = list(self.lines)
        if include_statements:
            out["statements"] = [record.as_dict() for record in self.statements]
        return out


    def to_bundle_dict(self):
        if not self.finalized:
            self.finalize()
        return {
            "mode": self.mode,
            "lines": list(self.lines),
            "text": self.text,
            "line_offsets": list(self.line_offsets),
            "statements": [record.as_dict() for record in self.statements],
            "spans": [span.as_dict() for span in self.spans],
            "finalized": True,
        }

    @classmethod
    def from_bundle_dict(cls, data):
        projection = cls(data.get("mode") or "unknown")
        records = [
            StatementRecord.from_dict(item)
            for item in list(data.get("statements", []) or [])
        ]
        lines = list(data.get("lines", []) or [])
        if len(records) != len(lines):
            raise ValueError("frozen PAL projection line/statement mismatch")
        for line_number, (line, record) in enumerate(zip(lines, records)):
            if record.line_number != line_number or record.text != str(line):
                raise ValueError("frozen PAL statement ownership mismatch")
            projection.add_line(str(line), record)
        projection.finalize()
        if data.get("text") is not None and str(data.get("text")) != projection.text:
            raise ValueError("frozen PAL projection text mismatch")
        supplied_offsets = list(data.get("line_offsets", []) or [])
        if supplied_offsets and supplied_offsets != projection.line_offsets:
            raise ValueError("frozen PAL projection line-offset mismatch")
        supplied_spans = [
            ProvenanceSpan.from_dict(item)
            for item in list(data.get("spans", []) or [])
        ]
        if supplied_spans:
            line_span_ids = {
                span.span_id for span in supplied_spans
                if span.kind == "statement_line"
            }
            required_line_span_ids = {
                span.span_id for span in projection.spans
                if span.kind == "statement_line"
            }
            if line_span_ids != required_line_span_ids:
                raise ValueError("frozen PAL projection line spans are incomplete")
            projection.replace_spans(supplied_spans)
        return projection


class PALCodeDocument:
    """
    Shared provenance identity for readable/executable PAL projections.

    IM-D keeps emitted ASCII immutable while adding synchronized projection
    lookup, deterministic/operator alias views, and revisioned edit sidecars.
    Frozen consumers need only this module; PyGhidra and PALemitter remain
    absent from the UI lookup/export path.
    """

    VERSION = "im_d_v1_projection_alias_edit_sidecars"
    BUNDLE_FORMAT = "pal_frozen_decompile_snapshot"
    BUNDLE_SCHEMA_VERSION = 3

    def __init__(self, function_name="func"):
        self.function_name = str(function_name or "func")
        self.projections = {}
        self.exec_occurrences = {}
        self.block_occurrences = {}
        self.metadata = MetadataRegistry()
        self.debug_events = []
        self.operator_aliases = {}
        self.alias_revisions = []
        self.edits = {}
        self.edit_revisions = []
        self._revision_counter = 0

    @staticmethod
    def occurrence_id(function_name, exec_path, node_kind, cfg_block_addr=None):
        path = "/".join(str(part) for part in tuple(exec_path or ("root",)))
        addr = _stable_text(cfg_block_addr) or "noaddr"
        return "occ:%s:%s:%s:%s" % (
            str(function_name or "func"), path, str(node_kind or "node"), addr
        )

    @staticmethod
    def statement_id(
        projection, occurrence_id, role, op_keys=None, ordinal=0
    ):
        op_text = "+".join(
            _stable_text(value) for value in list(op_keys or []) if value is not None
        ) or "no_op"
        owner = occurrence_id or "presentation:%s" % str(projection)
        return "stmt:%s:%s:%s:%d" % (
            owner, str(role or "statement"), op_text, int(ordinal)
        )

    def begin_projection(self, mode):
        projection = PALCodeProjection(mode)
        self.projections[str(mode)] = projection
        return projection

    def projection(self, mode):
        return self.projections.get(str(mode))

    def register_occurrence(
        self, occurrence_id, exec_path, node_kind,
        cfg_block_addr=None, projection=None, metadata_refs=None,
    ):
        record = self.exec_occurrences.get(occurrence_id)
        if record is None:
            record = ExecOccurrenceRecord(
                occurrence_id=occurrence_id,
                function_name=self.function_name,
                exec_path=tuple(exec_path or ()),
                node_kind=str(node_kind or "node"),
                cfg_block_addr=cfg_block_addr,
            )
            self.exec_occurrences[occurrence_id] = record
        record.observe(projection, cfg_block_addr, metadata_refs)
        if cfg_block_addr is not None or str(node_kind or "") == "block":
            self.block_occurrences[occurrence_id] = record
        return record

    def record_line(
        self, mode, text, statement_id, role,
        exec_occurrence_id=None, block_occurrence_id=None,
        cfg_block_addr=None, op_keys=None, definition_sids=None,
        use_sids=None, metadata_refs=None, operation_fragments=None,
    ):
        projection = self.projection(mode)
        if projection is None:
            projection = self.begin_projection(mode)
        record = StatementRecord(
            statement_id=str(statement_id),
            projection=str(mode),
            line_number=len(projection.lines),
            text=str(text),
            role=str(role or "statement"),
            exec_occurrence_id=exec_occurrence_id,
            block_occurrence_id=block_occurrence_id,
            cfg_block_addr=cfg_block_addr,
            op_keys=_unique(op_keys),
            definition_sids=_unique(definition_sids),
            use_sids=_unique(use_sids),
            metadata_refs=_unique(metadata_refs),
            operation_fragments=_json_safe(operation_fragments or []),
        )
        projection.add_line(text, record)
        return record

    def finalize_projection(self, mode, expected_lines=None):
        projection = self.projection(mode)
        if projection is None:
            raise KeyError("PAL projection %r does not exist" % mode)
        projection.finalize()
        if expected_lines is not None and list(expected_lines) != projection.lines:
            raise AssertionError(
                "PALCodeDocument changed emitted ASCII for projection %s" % mode
            )
        return projection

    @staticmethod
    def freeze_metadata_value(value):
        """Public detachment boundary used by the live PyGhidra producer."""
        return _json_safe(value)

    def reset_metadata(self):
        self.metadata.clear()

    def _variable_record(self, sid):
        return self.metadata.resolve("variable:%s" % str(sid), {}) or {}

    @staticmethod
    def _display_names_for_variable(record, sid=None):
        names = []
        if isinstance(record, dict):
            names.extend(list(record.get("display_names", []) or []))
            for key in ("display_name", "resolved_name", "original_name"):
                if record.get(key):
                    names.append(record.get(key))
        if sid is not None:
            names.append(str(sid))
        return [str(value) for value in _unique(names) if value is not None]

    @staticmethod
    def _tokenize_line(text):
        """Tokenize one rendered line without requiring valid whole-file Python."""
        out = []
        try:
            stream = io.StringIO(str(text) + "\n").readline
            for item in tokenize.generate_tokens(stream):
                if item.type in (token.NAME, token.NUMBER, token.OP):
                    out.append((item.string, item.start[1], item.end[1], item.type))
        except (IndentationError, SyntaxError, tokenize.TokenError):
            out = []
        if out:
            return out
        for match in re.finditer(
            r"[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|\d+|"
            r"==|!=|<=|>=|<<|>>|//|[%&|^~+\-*/<>]=?",
            str(text),
        ):
            value = match.group(0)
            kind = token.NAME if re.match(r"[A-Za-z_]", value) else token.OP
            if re.match(r"(?:0[xX][0-9A-Fa-f]+|\d+)\Z", value):
                kind = token.NUMBER
            out.append((value, match.start(), match.end(), kind))
        return out

    @staticmethod
    def _expression_columns(text):
        stripped = str(text).lstrip(" ")
        indent = len(str(text)) - len(stripped)
        if not stripped or stripped.startswith("#") or stripped.startswith("def "):
            return None
        if "=" in stripped and not stripped.startswith(("if ", "while ")):
            match = re.search(r"(?<![<>=!])=(?!=)", stripped)
            if match:
                start = indent + match.end()
                while start < len(text) and text[start] == " ":
                    start += 1
                return start, len(text)
        for prefix in ("if ", "while ", "return "):
            if stripped.startswith(prefix):
                start = indent + len(prefix)
                end = len(text) - (1 if stripped.endswith(":") else 0)
                return start, max(start, end)
        return indent, len(text)

    @staticmethod
    def _operation_symbols(opcode):
        return {
            "INT_ADD": ["+"], "INT_SUB": ["-"], "INT_MULT": ["*"],
            "INT_DIV": ["//"], "INT_SDIV": ["//"],
            "INT_REM": ["%"], "INT_SREM": ["%"],
            "INT_AND": ["&"], "INT_OR": ["|"], "INT_XOR": ["^"],
            "INT_LEFT": ["<<"], "INT_RIGHT": [">>"],
            "INT_SRIGHT": [">>"], "INT_EQUAL": ["=="],
            "INT_NOTEQUAL": ["!="], "INT_LESS": ["<"],
            "INT_SLESS": ["<"], "INT_LESSEQUAL": ["<="],
            "INT_SLESSEQUAL": ["<="], "INT_NEGATE": ["~"],
            "BOOL_NEGATE": ["not"],
        }.get(str(opcode or "").upper(), [])

    def _metadata_indexes(self):
        names = {}
        helpers = {}
        for reference, value in self.metadata.items():
            if reference.startswith("variable:") and isinstance(value, dict):
                sid = value.get("sid", reference.split(":", 1)[1])
                for name in self._display_names_for_variable(value, sid):
                    names.setdefault(name, []).append(reference)
            elif reference.startswith("operation:") and isinstance(value, dict):
                helper = value.get("runtime_helper")
                if helper:
                    helpers.setdefault(str(helper), []).append(reference)
        return (
            {key: sorted(set(values)) for key, values in names.items()},
            {key: sorted(set(values)) for key, values in helpers.items()},
        )

    def build_inline_spans(self, mode=None):
        """Build IM-C variable/operation spans after ASCII finalization."""
        modes = [str(mode)] if mode is not None else sorted(self.projections)
        name_index, helper_index = self._metadata_indexes()
        for current_mode in modes:
            projection = self.projection(current_mode)
            if projection is None:
                continue
            if not projection.finalized:
                projection.finalize()
            base_spans = [span for span in projection.spans if span.kind == "statement_line"]
            projection.replace_spans(base_spans)
            for record in projection.statements:
                line = projection.lines[record.line_number]
                base = projection.line_offsets[record.line_number]
                tokens = self._tokenize_line(line)
                eq_columns = [
                    start for value, start, _end, _kind in tokens if value == "="
                ]
                assignment_column = eq_columns[0] if eq_columns else None

                def_entities = ["variable:%s" % str(sid) for sid in record.definition_sids]
                use_entities = ["variable:%s" % str(sid) for sid in record.use_sids]
                for fragment in list(record.operation_fragments or []):
                    if not isinstance(fragment, dict) or fragment.get("op_key") is None:
                        continue
                    contract = self.metadata.resolve(
                        "operation:%s" % str(fragment.get("op_key")), {}
                    ) or {}
                    use_entities.extend(
                        "variable:%s" % str(sid)
                        for sid in list(contract.get("input_sids", []) or [])
                        if sid is not None
                    )
                use_entities = list(dict.fromkeys(use_entities))
                entity_names = {}
                for entity in def_entities + use_entities:
                    sid = entity.split(":", 1)[1]
                    variable = self.metadata.resolve(entity, {}) or {}
                    for name in self._display_names_for_variable(variable, sid):
                        entity_names.setdefault(name, []).append(entity)
                    for literal in list(variable.get("literal_candidates", []) or []):
                        entity_names.setdefault(str(literal), []).append(entity)

                for ordinal, (value, start, end, token_kind) in enumerate(tokens):
                    candidates = list(entity_names.get(value, []) or [])
                    source = "statement_contract"
                    if not candidates and token_kind == token.NAME:
                        candidates = list(name_index.get(value, []) or [])
                        source = "document_name_index"
                    if not candidates:
                        continue
                    candidates = sorted(set(candidates))
                    definition_candidates = [
                        item for item in candidates if item in def_entities
                    ]
                    use_candidates = [item for item in candidates if item in use_entities]
                    if (
                        definition_candidates
                        and assignment_column is not None
                        and start < assignment_column
                    ):
                        chosen = definition_candidates
                        role = "definition"
                    elif use_candidates:
                        chosen = use_candidates
                        role = "use"
                    else:
                        chosen = candidates
                        role = "reference"
                    entity_id = chosen[0] if len(chosen) == 1 else None
                    kind = "constant" if token_kind == token.NUMBER else "variable"
                    projection.add_span(ProvenanceSpan(
                        span_id="span:%s:line:%d:%s:%d" % (
                            current_mode, record.line_number, kind, ordinal
                        ),
                        projection=current_mode,
                        start_offset=base + start,
                        end_offset=base + end,
                        kind=kind,
                        entity_id=entity_id,
                        statement_id=record.statement_id,
                        metadata_refs=list(chosen),
                        role=role,
                        token_text=value,
                        candidate_entity_ids=chosen,
                        confidence=(
                            "authoritative" if len(chosen) == 1 and source == "statement_contract"
                            else "candidate"
                        ),
                    ), line_number=record.line_number)

                op_entities = ["operation:%s" % str(key) for key in record.op_keys]
                exact_operation_ranges = []
                fragment_cursor = 0
                for fragment_ordinal, fragment in enumerate(
                    list(record.operation_fragments or [])
                ):
                    if not isinstance(fragment, dict):
                        continue
                    op_key = fragment.get("op_key")
                    surface = fragment.get("surface_expr")
                    if op_key is None or not surface:
                        continue
                    surface = str(surface)
                    start = line.find(surface, fragment_cursor)
                    if start < 0:
                        start = line.find(surface)
                    if start < 0:
                        continue
                    end = start + len(surface)
                    fragment_cursor = end
                    entity = "operation:%s" % str(op_key)
                    exact_operation_ranges.append((start, end, entity))
                    projection.add_span(ProvenanceSpan(
                        span_id="span:%s:line:%d:operation:fragment:%d" % (
                            current_mode, record.line_number, fragment_ordinal
                        ),
                        projection=current_mode,
                        start_offset=base + start,
                        end_offset=base + end,
                        kind="operation",
                        entity_id=entity,
                        statement_id=record.statement_id,
                        metadata_refs=[entity],
                        role="rendered_contract_expression",
                        token_text=surface,
                        candidate_entity_ids=[entity],
                        confidence="authoritative",
                    ), line_number=record.line_number)
                    helper = fragment.get("helper")
                    if helper:
                        helper_start = line.find(str(helper), start, end)
                        if helper_start >= 0:
                            projection.add_span(ProvenanceSpan(
                                span_id="span:%s:line:%d:operation:helper:%d" % (
                                    current_mode, record.line_number,
                                    fragment_ordinal,
                                ),
                                projection=current_mode,
                                start_offset=base + helper_start,
                                end_offset=base + helper_start + len(str(helper)),
                                kind="operation",
                                entity_id=entity,
                                statement_id=record.statement_id,
                                metadata_refs=[entity],
                                role="helper_call",
                                token_text=str(helper),
                                candidate_entity_ids=[entity],
                                confidence="authoritative",
                            ), line_number=record.line_number)
                expr_columns = self._expression_columns(line)
                if op_entities and expr_columns is not None:
                    start, end = expr_columns
                    projection.add_span(ProvenanceSpan(
                        span_id="span:%s:line:%d:operation:expression" % (
                            current_mode, record.line_number
                        ),
                        projection=current_mode,
                        start_offset=base + start,
                        end_offset=base + end,
                        kind="operation",
                        entity_id=op_entities[0] if len(op_entities) == 1 else None,
                        statement_id=record.statement_id,
                        metadata_refs=op_entities,
                        role="expression",
                        token_text=line[start:end],
                        candidate_entity_ids=op_entities,
                        confidence="authoritative" if len(op_entities) == 1 else "candidate",
                    ), line_number=record.line_number)

                for ordinal, (value, start, end, token_kind) in enumerate(tokens):
                    operation_candidates = []
                    if token_kind == token.NAME and value.startswith("c_"):
                        exact_here = [
                            entity for range_start, range_end, entity
                            in exact_operation_ranges
                            if range_start <= start and end <= range_end
                        ]
                        if exact_here:
                            # An exact fragment already installed an authoritative
                            # helper span for this source contract.
                            continue
                        operation_candidates = list(helper_index.get(value, []) or [])
                        exact = [item for item in operation_candidates if item in op_entities]
                        if exact:
                            operation_candidates = exact
                    elif op_entities:
                        for entity in op_entities:
                            contract = self.metadata.resolve(entity, {}) or {}
                            if value in self._operation_symbols(contract.get("opcode")):
                                operation_candidates.append(entity)
                    operation_candidates = sorted(set(operation_candidates))
                    if not operation_candidates:
                        continue
                    projection.add_span(ProvenanceSpan(
                        span_id="span:%s:line:%d:operation:%d" % (
                            current_mode, record.line_number, ordinal
                        ),
                        projection=current_mode,
                        start_offset=base + start,
                        end_offset=base + end,
                        kind="operation",
                        entity_id=(
                            operation_candidates[0]
                            if len(operation_candidates) == 1 else None
                        ),
                        statement_id=record.statement_id,
                        metadata_refs=operation_candidates,
                        role="helper_call" if value.startswith("c_") else "operator",
                        token_text=value,
                        candidate_entity_ids=operation_candidates,
                        confidence=(
                            "authoritative" if len(operation_candidates) == 1
                            else "candidate"
                        ),
                    ), line_number=record.line_number)
            projection._sort_spans()
        return self.inline_span_summary()

    def inline_span_summary(self):
        counts = {}
        for projection in self.projections.values():
            for span in projection.spans:
                counts[span.kind] = counts.get(span.kind, 0) + 1
        return {
            "kind": "pal_inline_span_inventory_im_c",
            "version": self.VERSION,
            "span_kinds": dict(sorted(counts.items())),
            "spans": sum(counts.values()),
            "metadata_registry_records": len(self.metadata),
        }

    def lookup(
        self, mode, line=None, column=0, offset=None,
        line_base=0, clamp=True,
    ):
        """Resolve a cursor to its narrowest IM-C token/operation owner."""
        projection = self.projection(mode)
        if projection is None:
            raise KeyError("PAL projection %r does not exist" % mode)
        if not projection.finalized:
            projection.finalize()

        if offset is None:
            if line is None:
                raise ValueError("lookup requires line/column or offset")
            offset = projection.offset_for_position(
                line, column, line_base=line_base, clamp=clamp
            )
            resolved_line = int(line)
            resolved_column = int(column)
            if clamp:
                resolved_line, resolved_column = projection.position_for_offset(
                    offset, line_base=line_base, clamp=True
                )
        else:
            resolved_line, resolved_column = projection.position_for_offset(
                offset, line_base=line_base, clamp=clamp
            )

        records = projection.statements_for_line(
            resolved_line, line_base=line_base
        )
        line_zero = int(resolved_line) - int(line_base)
        spans = projection.spans_at_offset(
            offset, line=line_zero
        )
        primary = spans[0] if spans else None
        record = records[0] if records else None
        if record is None:
            return CursorContext(
                projection=str(mode),
                offset=int(offset),
                line=resolved_line,
                column=resolved_column,
                span_ids=[span.span_id for span in spans],
                primary_span_id=getattr(primary, "span_id", None),
                primary_kind=getattr(primary, "kind", None),
                primary_entity_id=getattr(primary, "entity_id", None),
                primary_role=getattr(primary, "role", None),
                token_text=getattr(primary, "token_text", None),
                candidate_entity_ids=list(
                    getattr(primary, "candidate_entity_ids", []) or []
                ),
            )

        entity_ids = [record.statement_id]
        for entity in (
            record.exec_occurrence_id,
            record.block_occurrence_id,
        ):
            if entity:
                entity_ids.append(entity)
        entity_ids.extend("operation:%s" % str(key) for key in record.op_keys)
        entity_ids.extend(
            "variable:%s" % str(sid)
            for sid in list(record.definition_sids) + list(record.use_sids)
        )
        metadata_refs = _unique(
            list(record.metadata_refs)
            + [ref for span in spans for ref in span.metadata_refs]
        )
        active_edit = self.edits.get(
            "%s:%s" % (str(mode), record.statement_id)
        )
        return CursorContext(
            projection=str(mode),
            offset=int(offset),
            line=resolved_line,
            column=resolved_column,
            statement_id=record.statement_id,
            exec_occurrence_id=record.exec_occurrence_id,
            block_occurrence_id=record.block_occurrence_id,
            cfg_block_addr=record.cfg_block_addr,
            role=record.role,
            op_keys=[_stable_text(value) for value in record.op_keys],
            definition_sids=[
                _stable_text(value) for value in record.definition_sids
            ],
            use_sids=[_stable_text(value) for value in record.use_sids],
            entity_ids=_unique(entity_ids),
            metadata_refs=metadata_refs,
            span_ids=[span.span_id for span in spans],
            state=(
                active_edit.get("state") if active_edit else record.state
            ),
            metadata_status=(
                active_edit.get("metadata_status")
                if active_edit else record.metadata_status
            ),
            primary_span_id=getattr(primary, "span_id", None),
            primary_kind=getattr(primary, "kind", None),
            primary_entity_id=getattr(primary, "entity_id", None),
            primary_role=getattr(primary, "role", None),
            token_text=getattr(primary, "token_text", None),
            candidate_entity_ids=list(
                getattr(primary, "candidate_entity_ids", []) or []
            ),
        )

    def lookup_offset(self, mode, offset, line_base=0, clamp=True):
        return self.lookup(
            mode, offset=offset, line_base=line_base, clamp=clamp
        )

    def describe_context(self, context):
        """Resolve an IM-C cursor context into a detached F3 metadata bundle."""
        if isinstance(context, dict):
            context_data = dict(context)
        else:
            context_data = context.as_dict()
        mode = context_data.get("projection")
        statement_id = context_data.get("statement_id")
        statement = None
        projection = self.projection(mode)
        if projection is not None and statement_id is not None:
            records = projection.statement_by_id.get(statement_id, []) or []
            line = context_data.get("line")
            for record in records:
                if line is None or record.line_number == int(line):
                    statement = record.as_dict()
                    break
            if statement is None and records:
                statement = records[0].as_dict()

        primary_id = context_data.get("primary_entity_id")
        candidates = list(context_data.get("candidate_entity_ids", []) or [])
        if primary_id and primary_id not in candidates:
            candidates.insert(0, primary_id)
        entity_ids = _unique(
            candidates
            + list(context_data.get("entity_ids", []) or [])
            + list(context_data.get("metadata_refs", []) or [])
        )
        resolved = []
        missing = []
        for entity_id in entity_ids:
            value = self.metadata.resolve(entity_id, None)
            if value is None:
                missing.append(str(entity_id))
            else:
                resolved.append({
                    "reference": str(entity_id),
                    "record": _json_safe(value),
                })

        occurrence = None
        occurrence_id = context_data.get("exec_occurrence_id")
        if occurrence_id in self.exec_occurrences:
            occurrence = self.exec_occurrences[occurrence_id].as_dict()
        block_occurrence = None
        block_id = context_data.get("block_occurrence_id")
        if block_id in self.block_occurrences:
            block_occurrence = self.block_occurrences[block_id].as_dict()

        alias_state = None
        if primary_id and str(primary_id).startswith("variable:"):
            sid = str(primary_id).split(":", 1)[1]
            alias_state = {
                "sid": sid,
                "contract": self._alias_contract(sid),
                "operator_alias": self.operator_aliases.get(sid),
                "names": {
                    naming: self.effective_variable_name(sid, naming)
                    for naming in ("pal", "ssa", "generated", "operator", "active")
                },
            }
        edit_key = "%s:%s" % (str(mode), statement_id)
        edit_state = self.edits.get(edit_key)

        return {
            "kind": "pal_f3_metadata_bundle_im_c",
            "version": self.VERSION,
            "context": _json_safe(context_data),
            "primary": (
                self.metadata.resolve(primary_id, None) if primary_id else None
            ),
            "candidate_records": resolved,
            "statement": statement,
            "exec_occurrence": occurrence,
            "block_occurrence": block_occurrence,
            "alias_state": _json_safe(alias_state),
            "edit_state": _json_safe(edit_state),
            "missing_references": sorted(set(missing)),
            "detached": True,
        }

    def describe_cursor(
        self, mode, line=None, column=0, offset=None,
        line_base=0, clamp=True,
    ):
        context = self.lookup(
            mode, line=line, column=column, offset=offset,
            line_base=line_base, clamp=clamp,
        )
        return self.describe_context(context)

    # =========================================================
    # IM-D F1 PROJECTION SYNCHRONIZATION
    # =========================================================

    @staticmethod
    def _span_entity_candidates(span):
        values = list(getattr(span, "candidate_entity_ids", []) or [])
        if getattr(span, "entity_id", None):
            values.insert(0, span.entity_id)
        return set(str(value) for value in values if value is not None)

    def sync_cursor(
        self, source_mode, target_mode, line=None, column=0, offset=None,
        line_base=0, clamp=True, source_naming="pal", target_naming="pal",
    ):
        """Map an F1 cursor to the same statement/entity in another projection."""
        source_view_column = None
        if offset is None and str(source_naming) not in ("pal", "original", "emitted"):
            source_view_column = int(column)
            column = self.view_column_to_base(
                source_mode, line, column, naming=source_naming,
                line_base=line_base,
            )
        source = self.lookup(
            source_mode, line=line, column=column, offset=offset,
            line_base=line_base, clamp=clamp,
        )
        target_projection = self.projection(target_mode)
        if target_projection is None:
            raise KeyError("PAL projection %r does not exist" % target_mode)
        records = list(
            target_projection.statement_by_id.get(source.statement_id, []) or []
        )
        if not records:
            return {
                "kind": "pal_projection_sync_im_d",
                "version": self.VERSION,
                "matched": False,
                "reason": "statement_not_present_in_target_projection",
                "source": source.as_dict(),
                "target": None,
            }
        target_record = records[0]
        source_projection = self.projection(source_mode)
        source_line_zero = int(source.line) - int(line_base)
        source_spans = source_projection.spans_at_offset(
            source.offset, line=source_line_zero
        )
        source_primary = source_spans[0] if source_spans else None
        wanted_entities = self._span_entity_candidates(source_primary)
        target_spans = target_projection.spans_for_line(
            target_record.line_number, line_base=0
        )
        matching = []
        for span in target_spans:
            if source_primary is not None and span.kind != source_primary.kind:
                continue
            if wanted_entities and not (
                wanted_entities & self._span_entity_candidates(span)
            ):
                continue
            if (
                source_primary is not None
                and source_primary.role
                and span.role != source_primary.role
            ):
                continue
            matching.append(span)

        chosen = None
        if matching:
            source_peer_spans = []
            if source_primary is not None:
                for span in source_projection.spans_for_line(
                    source_line_zero, line_base=0
                ):
                    if span.kind != source_primary.kind:
                        continue
                    if span.role != source_primary.role:
                        continue
                    if wanted_entities & self._span_entity_candidates(span):
                        source_peer_spans.append(span)
                source_peer_spans.sort(key=lambda item: item.start_offset)
                try:
                    ordinal = source_peer_spans.index(source_primary)
                except ValueError:
                    ordinal = 0
            else:
                ordinal = 0
            matching.sort(key=lambda item: item.start_offset)
            chosen = matching[min(ordinal, len(matching) - 1)]

        if chosen is not None:
            source_width = max(1, source_primary.end_offset - source_primary.start_offset)
            relative = max(0, source.offset - source_primary.start_offset)
            relative = min(relative, source_width - 1)
            target_width = max(1, chosen.end_offset - chosen.start_offset)
            target_offset = chosen.start_offset + min(relative, target_width - 1)
            reason = " "
        else:
            source_text = source_projection.lines[source_line_zero]
            target_text = target_projection.lines[target_record.line_number]
            ratio = (float(source.column) / max(1, len(source_text)))
            target_column = min(len(target_text), int(round(ratio * len(target_text))))
            target_offset = target_projection.offset_for_position(
                target_record.line_number, target_column, line_base=0, clamp=True
            )
            reason = " "

        target = self.lookup(
            target_mode, offset=target_offset, line_base=line_base, clamp=True
        )
        target_view_column = target.column
        if str(target_naming) not in ("pal", "original", "emitted"):
            target_view_column = self.base_column_to_view(
                target_mode, target.line, target.column,
                naming=target_naming, line_base=line_base,
            )
        return {
            "kind": "pal_projection_sync_im_d",
            "version": self.VERSION,
            "matched": True,
            "reason": reason,
            "source": source.as_dict(),
            "target": target.as_dict(),
            "source_view": {
                "naming": str(source_naming),
                "line": source.line,
                "column": (
                    source_view_column
                    if source_view_column is not None else source.column
                ),
            },
            "target_view": {
                "naming": str(target_naming),
                "line": target.line,
                "column": target_view_column,
            },
        }

    # =========================================================
    # IM-D F2 ALIAS PROJECTIONS
    # =========================================================

    @staticmethod
    def _validate_operator_alias(alias):
        alias = str(alias or "").strip()
        if (
            not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", alias)
            or keyword.iskeyword(alias)
        ):
            raise ValueError(
                "operator alias must be an ASCII non-keyword Python identifier"
            )
        if alias.startswith("c_"):
            raise ValueError("operator alias may not shadow PAL C-truth helpers")
        return alias

    def _alias_contract(self, sid):
        sid = str(sid)
        contract = self.metadata.resolve("alias:variable:%s" % sid, None)
        if isinstance(contract, dict):
            return dict(contract)
        variable = self._variable_record(sid)
        nested = variable.get("human_alias_contract") if isinstance(variable, dict) else None
        return dict(nested or {})

    def set_operator_alias(self, sid, alias, author="human"):
        sid = str(sid)
        alias = self._validate_operator_alias(alias)
        if self.metadata.resolve("variable:%s" % sid, None) is None:
            raise KeyError("unknown PAL variable SID %s" % sid)
        for reference, value in self.metadata.items():
            if not reference.startswith("variable:"):
                continue
            other_sid = reference.split(":", 1)[1]
            if other_sid == sid or not isinstance(value, dict):
                continue
            if value.get("is_constant"):
                continue
            if self.effective_variable_name(other_sid, "active") == alias:
                raise ValueError(
                    "operator alias %r already names variable %s"
                    % (alias, other_sid)
                )
        previous = self.operator_aliases.get(sid)
        if previous == alias:
            return previous
        self._revision_counter += 1
        self.operator_aliases[sid] = alias
        self.alias_revisions.append({
            "kind": "operator_alias_revision_im_d",
            "revision": self._revision_counter,
            "sid": sid,
            "previous": previous,
            "current": alias,
            "author": str(author or "human"),
            "state": "modified_at_source",
        })
        return alias

    def clear_operator_alias(self, sid, author="human"):
        sid = str(sid)
        previous = self.operator_aliases.pop(sid, None)
        if previous is not None:
            self._revision_counter += 1
            self.alias_revisions.append({
                "kind": "operator_alias_revision_im_d",
                "revision": self._revision_counter,
                "sid": sid,
                "previous": previous,
                "current": None,
                "author": str(author or "human"),
                "state": "reverted_to_original",
            })
        return previous

    def effective_variable_name(self, sid, naming="active"):
        sid = str(sid)
        variable = self._variable_record(sid)
        contract = self._alias_contract(sid)
        pal_name = variable.get("display_name") or contract.get("pal_name") or sid
        generated = contract.get("generated_human_alias")
        operator = self.operator_aliases.get(sid) or contract.get("operator_alias")
        naming = str(naming or "active").lower()
        if naming in ("pal", "original", "emitted"):
            return str(pal_name)
        if naming in ("ssa", "canonical"):
            return str(contract.get("canonical_ssa_name") or sid)
        if naming in ("generated", "human", "cognitive"):
            return str(generated or pal_name)
        if naming == "operator":
            return str(operator or pal_name)
        if naming == "active":
            return str(operator or generated or pal_name or sid)
        raise ValueError("unsupported PAL naming projection %r" % naming)

    def _line_alias_replacements(self, mode, line_number, naming):
        projection = self.projection(mode)
        if projection is None:
            raise KeyError("PAL projection %r does not exist" % mode)
        text = projection.lines[int(line_number)]
        line_start = projection.line_offsets[int(line_number)]
        candidates = []
        for span in projection.spans_for_line(int(line_number), line_base=0):
            if span.kind != "variable" or not span.entity_id:
                continue
            sid = str(span.entity_id).split(":", 1)[-1]
            variable = self._variable_record(sid)
            if variable.get("is_constant"):
                continue
            replacement = self.effective_variable_name(sid, naming=naming)
            start = span.start_offset - line_start
            end = span.end_offset - line_start
            if text[start:end] == replacement:
                continue
            candidates.append((start, end, replacement, sid))
        accepted = []
        occupied = set()
        for item in sorted(candidates, key=lambda value: (value[0], value[1])):
            start, end, replacement, sid = item
            interval = set(range(start, end))
            if occupied & interval:
                continue
            occupied.update(interval)
            accepted.append(item)
        return accepted

    def project_alias_lines(self, mode, naming="active"):
        """Return an F2 name view without mutating frozen projection text."""
        projection = self.projection(mode)
        if projection is None:
            raise KeyError("PAL projection %r does not exist" % mode)
        out = list(projection.lines)
        for line_number, text in enumerate(out):
            replacements = self._line_alias_replacements(mode, line_number, naming)
            for start, end, replacement, sid in sorted(
                replacements, key=lambda item: (item[0], item[1]), reverse=True
            ):
                text = text[:start] + replacement + text[end:]
            out[line_number] = text
        return out

    def view_column_to_base(
        self, mode, line, column, naming="active", line_base=0
    ):
        projection = self.projection(mode)
        line_zero = int(line) - int(line_base)
        base_text = projection.lines[line_zero]
        view_text = self.project_alias_lines(mode, naming=naming)[line_zero]
        column = min(max(int(column), 0), len(view_text))
        base_pos = view_pos = 0
        for start, end, replacement, sid in self._line_alias_replacements(
            mode, line_zero, naming
        ):
            unchanged = start - base_pos
            if column <= view_pos + unchanged:
                return min(len(base_text), base_pos + column - view_pos)
            view_pos += unchanged
            base_pos = start
            replacement_end = view_pos + len(replacement)
            if column <= replacement_end:
                relative = column - view_pos
                return start + min(relative, max(0, end - start - 1))
            view_pos = replacement_end
            base_pos = end
        return min(len(base_text), base_pos + column - view_pos)

    def base_column_to_view(
        self, mode, line, column, naming="active", line_base=0
    ):
        projection = self.projection(mode)
        line_zero = int(line) - int(line_base)
        base_text = projection.lines[line_zero]
        column = min(max(int(column), 0), len(base_text))
        base_pos = view_pos = 0
        for start, end, replacement, sid in self._line_alias_replacements(
            mode, line_zero, naming
        ):
            unchanged = start - base_pos
            if column <= start:
                return view_pos + column - base_pos
            view_pos += unchanged
            base_pos = start
            if column <= end:
                relative = column - start
                return view_pos + min(relative, max(0, len(replacement) - 1))
            view_pos += len(replacement)
            base_pos = end
        return view_pos + column - base_pos

    # =========================================================
    # IM-D REVISIONED EDIT SIDECARS
    # =========================================================

    def apply_line_edit(
        self, mode, line, new_text, line_base=0,
        naming="pal", author="human", expected_text=None,
    ):
        projection = self.projection(mode)
        if projection is None:
            raise KeyError("PAL projection %r does not exist" % mode)
        line_zero = int(line) - int(line_base)
        if line_zero < 0 or line_zero >= len(projection.lines):
            raise IndexError("line outside PAL projection")
        new_text = str(new_text)
        if "\n" in new_text or "\r" in new_text:
            raise ValueError("IM-D line edits may not contain line terminators")
        current_view = self.project_alias_lines(mode, naming=naming)[line_zero]
        if expected_text is not None and str(expected_text) != current_view:
            raise ValueError("PAL edit compare-and-swap text mismatch")
        records = projection.statements_for_line(line_zero, line_base=0)
        statement_id = records[0].statement_id if records else None
        key = "%s:%s" % (str(mode), statement_id or "line:%d" % line_zero)
        previous = self.edits.get(key)
        self._revision_counter += 1
        edit = {
            "kind": "pal_line_edit_im_d",
            "revision": self._revision_counter,
            "projection": str(mode),
            "line_number": line_zero,
            "statement_id": statement_id,
            "original_text": projection.lines[line_zero],
            "view_text_before_edit": current_view,
            "edited_text": new_text,
            "naming": str(naming),
            "author": str(author or "human"),
            "state": "modified_at_source",
            "metadata_status": "original_truth_preserved_in_snapshot",
            "previous_revision": previous.get("revision") if previous else None,
        }
        self.edits[key] = edit
        self.edit_revisions.append(dict(edit))
        return dict(edit)

    def revert_line_edit(self, mode, statement_id=None, line=None, line_base=0):
        if statement_id is None:
            projection = self.projection(mode)
            line_zero = int(line) - int(line_base)
            records = projection.statements_for_line(line_zero, line_base=0)
            statement_id = records[0].statement_id if records else "line:%d" % line_zero
        key = "%s:%s" % (str(mode), statement_id)
        previous = self.edits.pop(key, None)
        if previous is not None:
            self._revision_counter += 1
            self.edit_revisions.append({
                "kind": "pal_line_edit_revert_im_d",
                "revision": self._revision_counter,
                "projection": str(mode),
                "statement_id": statement_id,
                "reverted_revision": previous.get("revision"),
                "state": "reverted_to_original",
            })
        return previous

    def export_lines(self, mode, naming="pal", include_edits=True):
        lines = self.project_alias_lines(mode, naming=naming)
        if not include_edits:
            return lines
        for edit in sorted(
            self.edits.values(), key=lambda item: int(item.get("revision", 0))
        ):
            if edit.get("projection") != str(mode):
                continue
            if str(edit.get("naming")) != str(naming):
                raise ValueError(
                    "edited line was authored in naming projection %r, not %r"
                    % (edit.get("naming"), naming)
                )
            line_number = int(edit.get("line_number"))
            lines[line_number] = str(edit.get("edited_text"))
        return lines

    def export_text(
        self, mode, naming="pal", include_edits=True, final_newline=False
    ):
        text = "\n".join(self.export_lines(
            mode, naming=naming, include_edits=include_edits
        ))
        if final_newline and text and not text.endswith("\n"):
            text += "\n"
        return text

    def semantic_statement_ids(self, mode):
        projection = self.projection(mode)
        if projection is None:
            return set()
        return {
            record.statement_id
            for record in projection.statements
            if record.exec_occurrence_id is not None
        }

    def pairing_summary(self, readable="readable", executable="executable"):
        readable_ids = self.semantic_statement_ids(readable)
        executable_ids = self.semantic_statement_ids(executable)
        return {
            "readable_semantic_statements": len(readable_ids),
            "executable_semantic_statements": len(executable_ids),
            "paired_semantic_statements": len(readable_ids & executable_ids),
            "readable_only_statement_ids": sorted(readable_ids - executable_ids),
            "executable_only_statement_ids": sorted(executable_ids - readable_ids),
            "semantic_statement_ids_match": readable_ids == executable_ids,
        }

    def _document_payload(self):
        return {
            "document_version": self.VERSION,
            "function_name": self.function_name,
            "projections": {
                mode: projection.to_bundle_dict()
                for mode, projection in sorted(self.projections.items())
            },
            "exec_occurrences": [
                self.exec_occurrences[key].as_dict()
                for key in sorted(self.exec_occurrences)
            ],
            "block_occurrence_ids": sorted(self.block_occurrences),
            "metadata_registry": self.metadata.as_dict(),
            "debug_events": _json_safe(self.debug_events),
            "operator_aliases": _json_safe(self.operator_aliases),
            "alias_revisions": _json_safe(self.alias_revisions),
            "edits": _json_safe(self.edits),
            "edit_revisions": _json_safe(self.edit_revisions),
            "revision_counter": int(self._revision_counter),
            "text_policy": {
                "encoding": "ascii_compatible_utf8",
                "line_separator": "LF",
                "projection_text_has_final_lf": False,
            },
        }

    @classmethod
    def _bundle_unsigned_payload(cls, document_payload):
        return {
            "format": cls.BUNDLE_FORMAT,
            "schema_version": cls.BUNDLE_SCHEMA_VERSION,
            "document": document_payload,
        }

    @classmethod
    def _bundle_digest(cls, document_payload):
        unsigned = cls._bundle_unsigned_payload(document_payload)
        return hashlib.sha256(_canonical_json(unsigned)).hexdigest()

    def to_bundle(self):
        document_payload = _json_safe(self._document_payload())
        bundle = self._bundle_unsigned_payload(document_payload)
        bundle["integrity"] = {
            "algorithm": "sha256",
            "digest": self._bundle_digest(document_payload),
            "scope": "format+schema_version+document",
        }
        return bundle

    @classmethod
    def verify_bundle(cls, bundle):
        if not isinstance(bundle, dict):
            raise ValueError("PAL frozen snapshot must be a JSON object")
        if bundle.get("format") != cls.BUNDLE_FORMAT:
            raise ValueError("unsupported PAL frozen snapshot format")
        if int(bundle.get("schema_version", -1)) != cls.BUNDLE_SCHEMA_VERSION:
            raise ValueError("unsupported PAL frozen snapshot schema")
        integrity = dict(bundle.get("integrity", {}) or {})
        if integrity.get("algorithm") != "sha256":
            raise ValueError("PAL frozen snapshot has no SHA-256 integrity")
        document_payload = bundle.get("document")
        expected = cls._bundle_digest(document_payload)
        actual = str(integrity.get("digest") or "")
        if actual != expected:
            raise ValueError("PAL frozen snapshot integrity mismatch")
        return expected

    def save_bundle(self, path, indent=2, compress=None):
        """Atomically save a detached JSON or JSON.GZ decompile snapshot."""
        path = os.fspath(path)
        if compress is None:
            compress = path.lower().endswith(".gz")
        bundle = self.to_bundle()
        temp_path = "%s.tmp.%d" % (path, os.getpid())
        opener = gzip.open if compress else open
        try:
            with opener(
                temp_path, "wt", encoding="utf-8", newline="\n"
            ) as handle:
                json.dump(
                    bundle,
                    handle,
                    sort_keys=True,
                    indent=indent,
                    ensure_ascii=True,
                    allow_nan=False,
                )
                handle.write("\n")
            os.replace(temp_path, path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        return bundle["integrity"]["digest"]

    @classmethod
    def from_bundle(cls, bundle, verify=True):
        if verify:
            cls.verify_bundle(bundle)
        payload = dict(bundle.get("document", {}) or {})
        if payload.get("document_version") != cls.VERSION:
            raise ValueError("unsupported PAL code-document version")
        document = cls(payload.get("function_name") or "func")
        for item in list(payload.get("exec_occurrences", []) or []):
            record = ExecOccurrenceRecord.from_dict(item)
            document.exec_occurrences[record.occurrence_id] = record
        for occurrence_id in list(payload.get("block_occurrence_ids", []) or []):
            if occurrence_id not in document.exec_occurrences:
                raise ValueError("frozen block occurrence has no ExecTree owner")
            document.block_occurrences[occurrence_id] = (
                document.exec_occurrences[occurrence_id]
            )
        document.metadata = MetadataRegistry.from_dict(
            payload.get("metadata_registry", {})
        )
        document.debug_events = list(payload.get("debug_events", []) or [])
        document.operator_aliases = dict(payload.get("operator_aliases", {}) or {})
        document.alias_revisions = list(payload.get("alias_revisions", []) or [])
        document.edits = dict(payload.get("edits", {}) or {})
        document.edit_revisions = list(payload.get("edit_revisions", []) or [])
        document._revision_counter = int(payload.get("revision_counter", 0) or 0)
        for mode, projection_payload in sorted(
            dict(payload.get("projections", {}) or {}).items()
        ):
            projection = PALCodeProjection.from_bundle_dict(projection_payload)
            if projection.mode != str(mode):
                raise ValueError("frozen PAL projection mode mismatch")
            document.projections[str(mode)] = projection
        document.validate_frozen_snapshot()
        return document

    @classmethod
    def load_bundle(cls, path, verify=True, compress=None):
        path = os.fspath(path)
        if compress is None:
            compress = path.lower().endswith(".gz")
        opener = gzip.open if compress else open
        with opener(path, "rt", encoding="utf-8") as handle:
            bundle = json.load(handle)
        return cls.from_bundle(bundle, verify=verify)

    def validate_frozen_snapshot(self):
        for mode, projection in self.projections.items():
            if not projection.finalized:
                raise ValueError("frozen PAL projection is not finalized")
            if projection.text != "\n".join(projection.lines):
                raise ValueError("frozen PAL projection ASCII mismatch")
            for record in projection.statements:
                if record.line_number < 0 or record.line_number >= len(projection.lines):
                    raise ValueError("frozen PAL statement line is invalid")
                if projection.lines[record.line_number] != record.text:
                    raise ValueError("frozen PAL statement text is invalid")
                if (
                    record.exec_occurrence_id is not None
                    and record.exec_occurrence_id not in self.exec_occurrences
                ):
                    raise ValueError("frozen PAL statement ExecTree owner is missing")
                if (
                    record.block_occurrence_id is not None
                    and record.block_occurrence_id not in self.block_occurrences
                ):
                    raise ValueError("frozen PAL statement block owner is missing")
            span_ids = set()
            for span in projection.spans:
                if span.span_id in span_ids:
                    raise ValueError("frozen PAL inline span ID is duplicated")
                span_ids.add(span.span_id)
                if span.projection != mode:
                    raise ValueError("frozen PAL inline span projection is invalid")
                if (
                    span.start_offset < 0
                    or span.end_offset < span.start_offset
                    or span.end_offset > len(projection.text)
                ):
                    raise ValueError("frozen PAL inline span range is invalid")
                if (
                    span.statement_id is not None
                    and span.statement_id not in projection.statement_by_id
                ):
                    raise ValueError("frozen PAL inline span statement is missing")
        for sid, alias in self.operator_aliases.items():
            self._validate_operator_alias(alias)
            if self.metadata.resolve("variable:%s" % sid, None) is None:
                raise ValueError("frozen PAL operator alias variable is missing")
        for key, edit in self.edits.items():
            mode = edit.get("projection")
            projection = self.projection(mode)
            line_number = int(edit.get("line_number", -1))
            if projection is None or not (0 <= line_number < len(projection.lines)):
                raise ValueError("frozen PAL edit target is invalid")
            if "\n" in str(edit.get("edited_text", "")) or "\r" in str(
                edit.get("edited_text", "")
            ):
                raise ValueError("frozen PAL edit contains a line terminator")
        return True

    def summary(self):
        out = {
            "kind": "pal_code_document_inventory_im_d",
            "version": self.VERSION,
            "function_name": self.function_name,
            "projections": {
                mode: {
                    "lines": len(projection.lines),
                    "statements": len(projection.statements),
                    "spans": len(projection.spans),
                    "finalized": bool(projection.finalized),
                }
                for mode, projection in sorted(self.projections.items())
            },
            "exec_occurrences": len(self.exec_occurrences),
            "block_occurrences": len(self.block_occurrences),
            "metadata_registry_records": len(self.metadata),
            "ascii_mutation_guard": True,
            "line_cursor_lookup_ready": True,
            "inline_metadata_spans_ready": True,
            "f3_description_ready": True,
            "detached_resolution_ready": True,
            "projection_sync_ready": True,
            "alias_projection_ready": True,
            "operator_aliases": len(self.operator_aliases),
            "alias_revisions": len(self.alias_revisions),
            "active_edits": len(self.edits),
            "edit_revisions": len(self.edit_revisions),
            "frozen_bundle_ready": True,
            "bundle_schema_version": self.BUNDLE_SCHEMA_VERSION,
        }
        if "readable" in self.projections and "executable" in self.projections:
            out["projection_pairing"] = self.pairing_summary()
        return out
