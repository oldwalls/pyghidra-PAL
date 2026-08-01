# ============================================================
# PAL STATIC STRING COMPLETER
# BUILD: static_strings_v3_rebased_elf_address_truth
# ============================================================

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import struct
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


BUILD = "static_strings_v3_rebased_elf_address_truth"
OVERLAY_NAME = "PAL_stdio_strings.json"
REPORT_NAME = "PAL_static_string_completion.json"


class PALStaticStringCompletionError(RuntimeError):
    pass


def _read_json(path: Path) -> Dict[str, Any]:
    with Path(path).open("rt", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise PALStaticStringCompletionError(
            "expected JSON object: %s" % path
        )
    return value


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp.%d" % os.getpid())
    try:
        with temp.open("wt", encoding="utf-8", newline="\n") as handle:
            json.dump(
                value,
                handle,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _parse_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _manifest_image_base(
    manifest: Optional[Mapping[str, Any]],
) -> Optional[int]:
    if not isinstance(manifest, Mapping):
        return None
    program = dict(manifest.get("program") or {})
    for value in (
        program.get("image_base"),
        program.get("imageBase"),
        manifest.get("image_base"),
        manifest.get("imageBase"),
    ):
        parsed = _parse_int(value)
        if parsed is not None:
            return parsed
    return None


def _int_constant(node: ast.AST) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if isinstance(node, ast.UnaryOp):
        value = _int_constant(node.operand)
        if value is None:
            return None
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return value
    return None


class _ReferenceCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.constants: Dict[int, Set[str]] = {}

    def _add(self, value: Optional[int], reason: str) -> None:
        if value is None or value < 0:
            return
        self.constants.setdefault(int(value), set()).add(str(reason))

    def visit_Call(self, node: ast.Call) -> None:
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr

        # Narrow, architecture-level evidence:
        #
        #     c_ptrsub(0, CONSTANT, width)
        #
        # PALhelpers defines PTRSUB as base + byte offset. A zero base
        # therefore materializes an absolute program-data address. This is
        # exactly the static-literal representation that escaped the v1
        # Ghidra-defined-string publisher. Other integer constants are not
        # candidates and can never be promoted merely because their ELF bytes
        # happen to resemble text.
        if name == "c_ptrsub" and len(node.args) >= 2:
            base = _int_constant(node.args[0])
            offset = _int_constant(node.args[1])
            if base == 0 and offset is not None:
                self._add(offset, "c_ptrsub_zero_base")

        self.generic_visit(node)


def collect_referenced_constants(
    roots: Sequence[Path],
) -> Tuple[Dict[int, List[str]], List[str]]:
    found: Dict[int, Set[str]] = {}
    warnings: List[str] = []
    paths: List[Path] = []

    for root in roots:
        root = Path(root)
        if root.is_file() and root.suffix == ".py":
            paths.append(root)
        elif root.is_dir():
            paths.extend(sorted(root.rglob("*.py")))

    for path in paths:
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except Exception as exc:
            warnings.append("%s: %s" % (path, exc))
            continue
        collector = _ReferenceCollector()
        collector.visit(tree)
        for address, reasons in collector.constants.items():
            found.setdefault(address, set()).update(
                "%s:%s" % (path.name, reason)
                for reason in reasons
            )

    return (
        {
            address: sorted(reasons)
            for address, reasons in sorted(found.items())
        },
        warnings,
    )


class ELFLoadImage:
    PT_LOAD = 1
    PF_R = 4

    def __init__(self, path: Path) -> None:
        self.path = Path(path).resolve()
        self.data = self.path.read_bytes()
        self.bits = 0
        self.byte_order = ""
        self.segments: List[Dict[str, int]] = []
        self._parse()

    def _unpack(self, fmt: str, offset: int) -> Tuple[Any, ...]:
        size = struct.calcsize(fmt)
        end = int(offset) + size
        if offset < 0 or end > len(self.data):
            raise PALStaticStringCompletionError(
                "ELF structure exceeds file bounds: %s"
                % self.path
            )
        return struct.unpack(fmt, self.data[offset:end])

    def _parse(self) -> None:
        if len(self.data) < 16 or self.data[:4] != b"\x7fELF":
            raise PALStaticStringCompletionError(
                "not an ELF executable: %s" % self.path
            )

        elf_class = self.data[4]
        elf_data = self.data[5]
        if elf_class not in (1, 2):
            raise PALStaticStringCompletionError(
                "unsupported ELF class %r" % elf_class
            )
        if elf_data not in (1, 2):
            raise PALStaticStringCompletionError(
                "unsupported ELF byte order %r" % elf_data
            )

        endian = "<" if elf_data == 1 else ">"
        self.bits = 32 if elf_class == 1 else 64
        self.byte_order = "little" if elf_data == 1 else "big"

        if self.bits == 64:
            header = self._unpack(
                endian + "HHIQQQIHHHHHH", 16
            )
            e_phoff = int(header[4])
            e_phentsize = int(header[8])
            e_phnum = int(header[9])
            expected = struct.calcsize(endian + "IIQQQQQQ")
            if e_phentsize < expected:
                raise PALStaticStringCompletionError(
                    "ELF64 program header entry is too small"
                )
            for index in range(e_phnum):
                offset = e_phoff + index * e_phentsize
                values = self._unpack(
                    endian + "IIQQQQQQ", offset
                )
                (
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    _p_paddr,
                    p_filesz,
                    p_memsz,
                    _p_align,
                ) = values
                self._add_segment(
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    p_filesz,
                    p_memsz,
                )
        else:
            header = self._unpack(
                endian + "HHIIIIIHHHHHH", 16
            )
            e_phoff = int(header[4])
            e_phentsize = int(header[8])
            e_phnum = int(header[9])
            expected = struct.calcsize(endian + "IIIIIIII")
            if e_phentsize < expected:
                raise PALStaticStringCompletionError(
                    "ELF32 program header entry is too small"
                )
            for index in range(e_phnum):
                offset = e_phoff + index * e_phentsize
                values = self._unpack(
                    endian + "IIIIIIII", offset
                )
                (
                    p_type,
                    p_offset,
                    p_vaddr,
                    _p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    _p_align,
                ) = values
                self._add_segment(
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    p_filesz,
                    p_memsz,
                )

        if not self.segments:
            raise PALStaticStringCompletionError(
                "ELF contains no readable PT_LOAD segment: %s"
                % self.path
            )

    def _add_segment(
        self,
        p_type: int,
        p_flags: int,
        p_offset: int,
        p_vaddr: int,
        p_filesz: int,
        p_memsz: int,
    ) -> None:
        if int(p_type) != self.PT_LOAD:
            return
        if not (int(p_flags) & self.PF_R):
            return
        if int(p_offset) + int(p_filesz) > len(self.data):
            raise PALStaticStringCompletionError(
                "ELF PT_LOAD exceeds file bounds"
            )
        self.segments.append({
            "offset": int(p_offset),
            "vaddr": int(p_vaddr),
            "filesz": int(p_filesz),
            "memsz": int(p_memsz),
            "flags": int(p_flags),
        })

    @property
    def link_base(self) -> int:
        return min(
            int(segment["vaddr"])
            for segment in self.segments
        )

    def segment_for_file_address(
        self,
        address: int,
    ) -> Optional[Dict[str, int]]:
        address = int(address)
        for segment in self.segments:
            start = segment["vaddr"]
            end = start + segment["filesz"]
            if start <= address < end:
                return segment
        return None

    def read_c_string(
        self,
        address: int,
        *,
        maximum: int = 4096,
    ) -> Optional[Tuple[str, bytes, Dict[str, int]]]:
        segment = self.segment_for_file_address(address)
        if segment is None:
            return None

        relative = int(address) - segment["vaddr"]
        file_offset = segment["offset"] + relative
        available = segment["filesz"] - relative
        raw = self.data[
            file_offset:
            file_offset + min(int(maximum) + 1, available)
        ]
        terminator = raw.find(b"\0")
        if terminator <= 0:
            return None

        payload = raw[:terminator]
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None

        if not text:
            return None

        for character in text:
            if character in "\t\r\n":
                continue
            if not character.isprintable():
                return None

        return text, payload + b"\0", dict(segment)


def _normalize_overlay(
    payload: Mapping[str, Any],
) -> Dict[str, str]:
    values = payload.get("strings", payload)
    if not isinstance(values, dict):
        raise PALStaticStringCompletionError(
            "PAL string overlay lacks a strings object"
        )

    out: Dict[str, str] = {}
    for raw_address, text in values.items():
        address = int(str(raw_address), 0)
        out[hex(address)] = str(text)
    return out


def _resolve_executable(
    *,
    pal_root: Path,
    project_root: Path,
    manifest: Mapping[str, Any],
    explicit_path: Optional[Path] = None,
) -> Path:
    program = dict(manifest.get("program") or {})
    raw = str(program.get("executable_path") or "").strip()
    if not raw:
        raise PALStaticStringCompletionError(
            "manifest program.executable_path is missing"
        )

    requested = Path(raw).expanduser()
    candidates: List[Path] = []

    if explicit_path is not None:
        candidates.append(
            Path(explicit_path).expanduser()
        )

    environment_path = os.environ.get(
        "PAL_EXECUTABLE_PATH"
    )
    if environment_path:
        candidates.append(
            Path(environment_path).expanduser()
        )

    if requested.is_absolute():
        candidates.append(requested)

    candidates.extend([
        project_root / requested,
        project_root.parent / requested,
        project_root.parent.parent / requested,
        pal_root / requested,
        pal_root / requested.name,
        pal_root.parent / requested,
        pal_root.parent / requested.name,
        Path.cwd() / requested,
        Path.cwd() / requested.name,
    ])

    seen: Set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            resolved = candidate
        marker = str(resolved)
        if marker in seen:
            continue
        seen.add(marker)
        if resolved.is_file():
            return resolved

    raise PALStaticStringCompletionError(
        "original executable could not be resolved; tried: %s"
        % ", ".join(sorted(seen))
    )


def complete_overlay(
    *,
    overlay_path: Path,
    executable_path: Path,
    source_roots: Sequence[Path],
    manifest: Optional[Mapping[str, Any]] = None,
    report_path: Optional[Path] = None,
    write: bool = True,
) -> Dict[str, Any]:
    """Complete the PAL string overlay using direct or rebased ELF truth.

    Generated Python addresses remain the runtime/overlay authority.  ELF
    addresses are used only to locate original bytes.  A candidate is accepted
    when exactly one of these address modes resolves to a valid C string:

      direct:
          elf_address = generated_address

      rebased:
          elf_address = generated_address - (
              program_image_base - elf_link_base
          )

    When both distinct locations decode, the mapping is ambiguous and the
    operation fails closed.
    """
    overlay_path = Path(overlay_path).resolve()
    executable_path = Path(executable_path).resolve()

    payload = _read_json(overlay_path)
    original_strings = _normalize_overlay(payload)
    strings = dict(original_strings)

    references, parse_warnings = collect_referenced_constants(
        source_roots
    )
    image = ELFLoadImage(executable_path)

    program_image_base = _manifest_image_base(manifest)
    elf_link_base = int(image.link_base)
    load_bias = (
        int(program_image_base) - elf_link_base
        if program_image_base is not None
        else None
    )

    completed: List[Dict[str, Any]] = []
    existing: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    ambiguous: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    required_strings: Dict[str, str] = {}
    resolutions: List[Dict[str, Any]] = []

    direct_resolved = 0
    rebased_resolved = 0

    for generated_address, reasons in references.items():
        candidates: List[Dict[str, Any]] = []

        direct = image.read_c_string(generated_address)
        if direct is not None:
            text_value, raw, segment = direct
            candidates.append({
                "resolution_mode": "direct",
                "generated_address": int(generated_address),
                "elf_address": int(generated_address),
                "text": text_value,
                "raw": raw,
                "segment": segment,
            })

        if load_bias not in (None, 0):
            rebased_address = int(generated_address) - int(load_bias)
            if rebased_address >= 0:
                rebased = image.read_c_string(rebased_address)
                if rebased is not None:
                    text_value, raw, segment = rebased
                    candidates.append({
                        "resolution_mode": "rebased",
                        "generated_address": int(generated_address),
                        "elf_address": int(rebased_address),
                        "text": text_value,
                        "raw": raw,
                        "segment": segment,
                    })

        # De-duplicate the same physical ELF location. This occurs when the
        # computed load bias is zero or equivalent metadata paths converge.
        distinct: Dict[int, Dict[str, Any]] = {}
        for candidate in candidates:
            elf_address = int(candidate["elf_address"])
            previous = distinct.get(elf_address)
            if previous is None:
                distinct[elf_address] = candidate
                continue
            if (
                previous["text"] != candidate["text"]
                or previous["raw"] != candidate["raw"]
            ):
                raise PALStaticStringCompletionError(
                    "same ELF address produced conflicting string truth: "
                    "%s" % hex(elf_address)
                )

        candidates = list(distinct.values())
        key = hex(int(generated_address))

        if len(candidates) > 1:
            record = {
                "generated_address": key,
                "candidate_mappings": [
                    {
                        "resolution_mode": candidate["resolution_mode"],
                        "elf_address": hex(
                            int(candidate["elf_address"])
                        ),
                        "text": candidate["text"],
                    }
                    for candidate in sorted(
                        candidates,
                        key=lambda item: (
                            item["resolution_mode"],
                            item["elf_address"],
                        ),
                    )
                ],
                "program_image_base": (
                    hex(program_image_base)
                    if program_image_base is not None
                    else None
                ),
                "elf_link_base": hex(elf_link_base),
                "load_bias": (
                    hex(load_bias)
                    if load_bias is not None
                    else None
                ),
                "reasons": reasons,
            }
            ambiguous.append(record)
            continue

        if not candidates:
            unresolved.append({
                "address": key,
                "generated_address": key,
                "direct_elf_address": key,
                "rebased_elf_address": (
                    hex(int(generated_address) - int(load_bias))
                    if load_bias not in (None, 0)
                    and int(generated_address) - int(load_bias) >= 0
                    else None
                ),
                "program_image_base": (
                    hex(program_image_base)
                    if program_image_base is not None
                    else None
                ),
                "elf_link_base": hex(elf_link_base),
                "load_bias": (
                    hex(load_bias)
                    if load_bias is not None
                    else None
                ),
                "reasons": reasons,
                "action": (
                    "preserve_pointer_and_report_unresolved"
                ),
            })
            continue

        selected = candidates[0]
        resolution_mode = str(selected["resolution_mode"])
        elf_address = int(selected["elf_address"])
        text_value = str(selected["text"])
        raw = bytes(selected["raw"])
        segment = dict(selected["segment"])

        if resolution_mode == "direct":
            direct_resolved += 1
        else:
            rebased_resolved += 1

        required_strings[key] = text_value
        resolution_record = {
            "generated_address": key,
            "elf_address": hex(elf_address),
            "resolution_mode": resolution_mode,
            "text": text_value,
            "byte_length_with_nul": len(raw),
            "program_image_base": (
                hex(program_image_base)
                if program_image_base is not None
                else None
            ),
            "elf_link_base": hex(elf_link_base),
            "load_bias": (
                hex(load_bias)
                if load_bias is not None
                else None
            ),
            "reasons": reasons,
            "elf_segment": {
                "vaddr": hex(segment["vaddr"]),
                "filesz": segment["filesz"],
                "memsz": segment["memsz"],
                "flags": segment["flags"],
            },
        }
        resolutions.append(dict(resolution_record))

        if key in strings:
            if strings[key] != text_value:
                conflicts.append({
                    "address": key,
                    "generated_address": key,
                    "elf_address": hex(elf_address),
                    "resolution_mode": resolution_mode,
                    "overlay_text": strings[key],
                    "elf_text": text_value,
                    "reasons": reasons,
                })
            else:
                existing.append(dict(resolution_record))
            continue

        strings[key] = text_value
        completed.append(dict(resolution_record))

    if ambiguous:
        raise PALStaticStringCompletionError(
            "ambiguous direct/rebased ELF string mappings: %s"
            % ambiguous
        )

    if conflicts:
        raise PALStaticStringCompletionError(
            "ELF/overlay string conflicts: %s" % conflicts
        )

    translation = {
        "program_image_base": (
            hex(program_image_base)
            if program_image_base is not None
            else None
        ),
        "elf_link_base": hex(elf_link_base),
        "load_bias": (
            hex(load_bias)
            if load_bias is not None
            else None
        ),
        "direct_resolved_references": direct_resolved,
        "rebased_resolved_references": rebased_resolved,
        "ambiguous_references": len(ambiguous),
        "unresolved_references": len(unresolved),
        "resolution_rule": (
            "accept_exactly_one_valid_direct_or_rebased_readable_"
            "ELF_PT_LOAD_C_string_mapping"
        ),
    }

    output = dict(payload)
    output["format"] = "pal_stdio_string_overlay"
    output["schema_version"] = max(
        int(output.get("schema_version") or 1),
        3,
    )
    output["producer"] = "PALStaticStringPublisher"
    output["producer_build"] = BUILD
    output["source_policy"] = (
        "ghidra_defined_strings_plus_referenced_direct_or_"
        "rebased_readable_ELF_PT_LOAD_c_strings"
    )
    output["strings"] = {
        key: strings[key]
        for key in sorted(
            strings,
            key=lambda item: int(item, 0),
        )
    }
    output["completion"] = {
        "build": BUILD,
        "original_strings": len(original_strings),
        "completed_strings": len(completed),
        "final_strings": len(strings),
        "reference_constants": len(references),
        "required_runtime_strings": len(required_strings),
        "direct_resolved_references": direct_resolved,
        "rebased_resolved_references": rebased_resolved,
        "ambiguous_references": len(ambiguous),
        "unresolved_ptrsub_references": len(unresolved),
        "address_translation": translation,
        "executable": str(executable_path),
        "executable_sha256": _sha256(executable_path),
    }

    report = {
        "format": "pal_static_string_completion",
        "schema_version": 2,
        "build": BUILD,
        "overlay": str(overlay_path),
        "executable": str(executable_path),
        "executable_sha256": _sha256(executable_path),
        "source_roots": [
            str(Path(path)) for path in source_roots
        ],
        "reference_constants": {
            hex(address): reasons
            for address, reasons in references.items()
        },
        "address_translation": translation,
        "required_strings": required_strings,
        "resolutions": resolutions,
        "existing": existing,
        "completed": completed,
        "unresolved": unresolved,
        "ambiguous": ambiguous,
        "parse_warnings": parse_warnings,
        "conflicts": conflicts,
        "counts": {
            "original_strings": len(original_strings),
            "completed_strings": len(completed),
            "final_strings": len(strings),
            "required_runtime_strings": len(required_strings),
            "direct_resolved_references": direct_resolved,
            "rebased_resolved_references": rebased_resolved,
            "ambiguous_references": len(ambiguous),
            "unresolved_ptrsub_references": len(unresolved),
        },
    }

    if write:
        _write_json_atomic(overlay_path, output)
        if report_path is not None:
            _write_json_atomic(Path(report_path), report)

    return report


def _backup_once(path: Path, suffix: str) -> Optional[Path]:
    path = Path(path)
    if not path.is_file():
        return None
    backup = path.with_name(path.name + str(suffix))
    if not backup.exists():
        shutil.copy2(path, backup)
    return backup


def complete_project_static_strings(
    *,
    pal_root: Path,
    project_root: Path,
    stage_root: Path,
    manifest: Mapping[str, Any],
) -> Dict[str, Any]:
    pal_root = Path(pal_root).resolve()
    project_root = Path(project_root).resolve()
    stage_root = Path(stage_root).resolve()

    source_overlay = project_root / OVERLAY_NAME
    stage_overlay = stage_root / OVERLAY_NAME

    if not source_overlay.is_file() and not stage_overlay.is_file():
        return {
            "format": "pal_static_string_completion",
            "schema_version": 1,
            "build": BUILD,
            "active": False,
            "reason": "PAL_stdio_strings.json_not_present",
            "counts": {},
        }

    overlay = (
        stage_overlay
        if stage_overlay.is_file()
        else source_overlay
    )

    executable = _resolve_executable(
        pal_root=pal_root,
        project_root=project_root,
        manifest=manifest,
    )

    source_roots = [
        project_root / "functions",
        stage_root / "functions",
    ]
    report_path = stage_root / REPORT_NAME

    report = complete_overlay(
        overlay_path=overlay,
        executable_path=executable,
        source_roots=source_roots,
        manifest=manifest,
        report_path=report_path,
        write=True,
    )
    report["active"] = True

    loaded_overlay = _read_json(overlay)
    if overlay != source_overlay:
        _backup_once(
            source_overlay,
            ".before_static_string_v2",
        )
        _write_json_atomic(
            source_overlay,
            loaded_overlay,
        )
    if overlay != stage_overlay:
        _write_json_atomic(
            stage_overlay,
            loaded_overlay,
        )

    _write_json_atomic(
        project_root / REPORT_NAME,
        report,
    )
    _write_json_atomic(
        stage_root / REPORT_NAME,
        report,
    )
    return report
