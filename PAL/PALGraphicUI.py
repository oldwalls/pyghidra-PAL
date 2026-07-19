# ============================================================
# PAL GRAPHIC UI / FOUR-WAY TRUTH WORKSPACE
# BUILD: palgraphicui_v1_four_way_baby_moon_step
# ============================================================

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import messagebox
    from tkinter import ttk
except ImportError as exc:  # pragma: no cover - platform packaging issue
    raise SystemExit(
        "PALGraphicUI requires Python tkinter support: %s" % exc
    )


PAL_EXEC_ROOT = os.path.dirname(os.path.abspath(__file__))
if PAL_EXEC_ROOT not in sys.path:
    sys.path.insert(0, PAL_EXEC_ROOT)

# PALGraphicUI runs in a separate process. Importing PALTermUI here does not
# create a circular import because PALTermUI launches this module dynamically
# and never imports it at module load time.
from PALTermUI import (  # noqa: E402
    PALFunctionManifestModel,
    PALTerminalModel,
    PROJECT_MANIFEST,
)


BUILD = "palgraphicui_v1_four_way_baby_moon_step_fontscale"


def _initial_font_scale() -> float:
    """Return GUI font scale; defaults to 300% and accepts 100%-600%."""
    raw = os.environ.get("PAL_GUI_FONT_SCALE", "3.0")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = 3.0
    return max(1.0, min(6.0, value))


def _font_size(base: int, scale: float, minimum: int = 8) -> int:
    return max(int(minimum), int(round(abs(int(base)) * float(scale))))
PANE_ORDER = ("asm", "readable", "c_code", "executable")
PANE_TITLES = {
    "asm": "ASM / MACHINE TRUTH",
    "readable": "READ.PY / STRUCTURAL PROJECTION",
    "c_code": "GHIDRA C / DECOMPILER REFERENCE",
    "executable": "EXEC.PY / EXECUTABLE PROJECTION",
}


@dataclass
class LaunchContext:
    source_path: str
    manifest_path: Optional[str] = None
    naming: str = "augmented"
    projection: str = "readable"
    line: int = 0
    verify: bool = True


def _absolute(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.abspath(os.path.expanduser(os.fspath(path)))


def _candidate_manifest(source_path: str) -> Optional[str]:
    """Find the project manifest for ``project/<name>/functions/<icecube>``."""
    source_path = _absolute(source_path)
    if not source_path:
        return None
    function_dir = os.path.dirname(source_path)
    project_dir = os.path.dirname(function_dir)
    candidate = os.path.join(project_dir, PROJECT_MANIFEST)
    return candidate if os.path.isfile(candidate) else None


def _record_matches_source(catalog, record, source_path: str) -> bool:
    try:
        candidate = catalog.icecube_path(record)
    except Exception:
        candidate = None
    return bool(
        candidate
        and os.path.normcase(os.path.abspath(candidate))
        == os.path.normcase(os.path.abspath(source_path))
    )


def open_terminal_model(context: LaunchContext):
    """Open the function through its project manifest when possible.

    Project-mode opening retains the project-global PAL_ONCS store. Detached
    opening is the fallback for standalone icecubes.
    """
    source = _absolute(context.source_path)
    if not source or not os.path.isfile(source):
        raise FileNotFoundError("icecube does not exist: %s" % source)

    manifest = _absolute(context.manifest_path) or _candidate_manifest(source)
    if manifest and os.path.isfile(manifest):
        catalog = PALFunctionManifestModel.from_path(manifest)
        for index, record in enumerate(catalog.records):
            if not _record_matches_source(catalog, record, source):
                continue
            catalog.line = index
            model = catalog.open_selected(
                verify=context.verify,
                projection=context.projection,
                naming=context.naming,
            )
            model.line = max(0, int(context.line))
            model.clamp()
            return model, catalog

    model = PALTerminalModel.from_path(source, verify=context.verify)
    if model.document.projection(context.projection) is not None:
        model.projection = context.projection
    model.naming = context.naming
    model.line = max(0, int(context.line))
    model.clamp()
    return model, None


def _digest_lines(model, panel: str) -> List[str]:
    digest = model.truth_digest()
    digest.select(panel)
    return [str(value) for value in list(digest.lines() or [])]


def build_four_way_content(model) -> Dict[str, List[str]]:
    """Build the four immutable display projections without mutating cursors."""
    content: Dict[str, List[str]] = {}
    for projection in ("readable", "executable"):
        try:
            lines = model.oncs.render_lines(projection, model.naming)
        except Exception:
            try:
                lines = model.oncs.base_lines(projection)
            except Exception as exc:
                lines = [
                    "%s projection unavailable" % projection.upper(),
                    "%s: %s" % (type(exc).__name__, exc),
                ]
        content[projection] = [str(value) for value in list(lines or [])]

    for pane, panel in (("asm", "asm"), ("c_code", "c_code")):
        try:
            content[pane] = _digest_lines(model, panel)
        except Exception as exc:
            content[pane] = [
                "%s panel unavailable" % panel.upper(),
                "%s: %s" % (type(exc).__name__, exc),
            ]
    return content


class CodePane(ttk.Frame):
    """One independently scrollable, read-only truth projection."""

    def __init__(self, master, pane_id: str, title: str, activate_callback):
        super().__init__(master, style="PAL.Panel.TFrame")
        self.pane_id = pane_id
        self.activate_callback = activate_callback

        self.title_var = tk.StringVar(value=title)
        self.title = ttk.Label(
            self,
            textvariable=self.title_var,
            style="PAL.PaneTitle.TLabel",
            anchor="w",
            padding=(8, 4),
        )
        self.title.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.text = tk.Text(
            self,
            wrap="none",
            undo=False,
            autoseparators=False,
            background="#111318",
            foreground="#d8dee9",
            insertbackground="#8fbcbb",
            selectbackground="#244f66",
            selectforeground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=8,
            pady=6,
            highlightthickness=1,
            highlightbackground="#303641",
            highlightcolor="#5e81ac",
        )
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.hbar = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        self.text.configure(
            yscrollcommand=self.vbar.set,
            xscrollcommand=self.hbar.set,
        )

        self.text.grid(row=1, column=0, sticky="nsew")
        self.vbar.grid(row=1, column=1, sticky="ns")
        self.hbar.grid(row=2, column=0, sticky="ew")
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        for widget in (self, self.title, self.text):
            widget.bind("<Button-1>", self._activate, add="+")
            widget.bind("<FocusIn>", self._activate, add="+")

    def _activate(self, _event=None):
        self.activate_callback(self.pane_id)

    def set_active(self, active: bool):
        self.title.configure(
            style=(
                "PAL.ActivePaneTitle.TLabel"
                if active else "PAL.PaneTitle.TLabel"
            )
        )
        self.text.configure(
            highlightbackground="#bf616a" if active else "#303641",
            highlightcolor="#bf616a" if active else "#5e81ac",
        )

    def set_lines(self, lines: Iterable[str], preserve_scroll: bool = True):
        yview = self.text.yview()
        xview = self.text.xview()
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", "\n".join(str(line) for line in lines))
        self.text.configure(state="disabled")
        if preserve_scroll:
            if yview:
                self.text.yview_moveto(yview[0])
            if xview:
                self.text.xview_moveto(xview[0])

    def focus_line(self, line: int):
        line = max(0, int(line)) + 1
        self.text.configure(state="normal")
        self.text.mark_set("insert", "%d.0" % line)
        self.text.see("%d.0" % line)
        self.text.configure(state="disabled")


class PALGraphicFourWayApp:
    """First PAL graphical surface: the proven four-way truth workspace."""

    def __init__(self, root: tk.Tk, model, catalog=None, context=None):
        self.root = root
        self.model = model
        self.catalog = catalog
        self.context = context
        self.active_pane = (
            model.projection
            if model.projection in ("readable", "executable")
            else "readable"
        )
        self.panes: Dict[str, CodePane] = {}
        self.font_scale = _initial_font_scale()
        self.code_font = None

        self._configure_root()
        self._configure_styles()
        self._build_layout()
        self.refresh_content(preserve_scroll=False)
        self._activate_pane(self.active_pane)
        self.panes[self.active_pane].focus_line(model.line)

    def _configure_root(self):
        function_name = getattr(self.model.document, "function_name", "function")
        self.root.title("PAL Four-Way Truth — %s" % function_name)
        self.root.geometry("1500x940")
        self.root.minsize(900, 600)
        self.root.configure(background="#0b0d10")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.root.bind("<F10>", lambda _event: self.close())
        self.root.bind("<Escape>", lambda _event: self.close())
        self.root.bind("<F5>", lambda _event: self.refresh_content())
        self.root.bind("<F2>", lambda _event: self.cycle_naming())
        self.root.bind("<Control-Tab>", lambda _event: self.cycle_pane(1))
        self.root.bind("<Control-Shift-Tab>", lambda _event: self.cycle_pane(-1))
        self.root.bind("<Control-plus>", lambda _event: self.adjust_font_scale(+0.25))
        self.root.bind("<Control-equal>", lambda _event: self.adjust_font_scale(+0.25))
        self.root.bind("<Control-KP_Add>", lambda _event: self.adjust_font_scale(+0.25))
        self.root.bind("<Control-minus>", lambda _event: self.adjust_font_scale(-0.25))
        self.root.bind("<Control-KP_Subtract>", lambda _event: self.adjust_font_scale(-0.25))
        self.root.bind("<Control-Key-0>", lambda _event: self.reset_font_scale())

    def _configure_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("PAL.Root.TFrame", background="#0b0d10")
        style.configure("PAL.Panel.TFrame", background="#111318")
        self._style = style
        self._apply_scaled_style_fonts()

    def _build_layout(self):
        outer = ttk.Frame(self.root, style="PAL.Root.TFrame", padding=6)
        outer.pack(fill="both", expand=True)

        function_name = getattr(self.model.document, "function_name", "function")
        self.header_var = tk.StringVar()
        self.header = ttk.Label(
            outer,
            textvariable=self.header_var,
            style="PAL.Header.TLabel",
            anchor="w",
            padding=(10, 7),
        )
        self.header.pack(fill="x", pady=(0, 5))

        grid = ttk.Frame(outer, style="PAL.Root.TFrame")
        grid.pack(fill="both", expand=True)
        grid.rowconfigure(0, weight=1, uniform="truth_rows")
        grid.rowconfigure(1, weight=1, uniform="truth_rows")
        grid.columnconfigure(0, weight=1, uniform="truth_cols")
        grid.columnconfigure(1, weight=1, uniform="truth_cols")

        positions = {
            "asm": (0, 0),
            "readable": (0, 1),
            "c_code": (1, 0),
            "executable": (1, 1),
        }
        for pane_id in PANE_ORDER:
            pane = CodePane(
                grid,
                pane_id,
                PANE_TITLES[pane_id],
                self._activate_pane,
            )
            row, column = positions[pane_id]
            pane.grid(
                row=row,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 3, 3 if column == 0 else 0),
                pady=(0 if row == 0 else 3, 3 if row == 0 else 0),
            )
            self.panes[pane_id] = pane

        self.status_var = tk.StringVar()
        status = ttk.Label(
            outer,
            textvariable=self.status_var,
            style="PAL.Status.TLabel",
            anchor="w",
            padding=(8, 5),
        )
        status.pack(fill="x", pady=(5, 0))

        # Apply one shared scalable monospace font to every truth pane.
        self.code_font = tkfont.nametofont("TkFixedFont").copy()
        self._apply_code_font()

        self._update_header(function_name)

    def _apply_scaled_style_fonts(self):
        style = getattr(self, "_style", None)
        if style is None:
            return
        scale = self.font_scale
        style.configure(
            "PAL.Header.TLabel",
            background="#18202a",
            foreground="#a3be8c",
            font=("TkDefaultFont", _font_size(11, scale, 11), "bold"),
        )
        style.configure(
            "PAL.PaneTitle.TLabel",
            background="#1b2028",
            foreground="#88c0d0",
            font=("TkDefaultFont", _font_size(10, scale, 10), "bold"),
        )
        style.configure(
            "PAL.ActivePaneTitle.TLabel",
            background="#3b1f25",
            foreground="#ff8a80",
            font=("TkDefaultFont", _font_size(10, scale, 10), "bold"),
        )
        style.configure(
            "PAL.Status.TLabel",
            background="#18202a",
            foreground="#d8dee9",
            font=("TkDefaultFont", _font_size(9, scale, 9)),
        )

    def _apply_code_font(self):
        if self.code_font is None:
            return
        base = tkfont.nametofont("TkFixedFont")
        base_size = int(base.cget("size") or 10)
        self.code_font.configure(size=_font_size(base_size, self.font_scale, 10))
        for pane in self.panes.values():
            pane.text.configure(font=self.code_font)

    def adjust_font_scale(self, delta: float):
        self.font_scale = max(1.0, min(6.0, self.font_scale + float(delta)))
        self._apply_scaled_style_fonts()
        self._apply_code_font()
        self._update_header()
        return "break"

    def reset_font_scale(self):
        self.font_scale = 3.0
        self._apply_scaled_style_fonts()
        self._apply_code_font()
        self._update_header()
        return "break"

    def _update_header(self, function_name=None):
        function_name = function_name or getattr(
            self.model.document, "function_name", "function"
        )
        source = self.model.source_path or "detached document"
        self.header_var.set(
            " PAL FOUR-WAY TRUTH  |  %s  |  ONCS:%s  |  %s "
            % (function_name, self.model.naming, source)
        )
        self.status_var.set(
            "F2 naming  |  F5 refresh  |  Ctrl-Tab pane  |  "
            "Ctrl+/- font  Ctrl+0=300%%  |  F10/Esc close  |  "
            "scale=%d%%  |  active=%s"
            % (int(round(self.font_scale * 100)), PANE_TITLES[self.active_pane])
        )

    def _activate_pane(self, pane_id: str):
        if pane_id not in self.panes:
            return
        self.active_pane = pane_id
        for name, pane in self.panes.items():
            pane.set_active(name == pane_id)
        self.panes[pane_id].text.focus_set()
        self._update_header()

    def cycle_pane(self, step=1):
        index = PANE_ORDER.index(self.active_pane)
        self._activate_pane(PANE_ORDER[(index + int(step)) % len(PANE_ORDER)])
        return "break"

    def refresh_content(self, preserve_scroll=True):
        content = build_four_way_content(self.model)
        for pane_id, lines in content.items():
            self.panes[pane_id].set_lines(lines, preserve_scroll=preserve_scroll)
        self._update_header()
        return "break"

    def cycle_naming(self):
        self.model.cycle_naming()
        self.refresh_content(preserve_scroll=True)
        return "break"

    def close(self):
        self.root.destroy()
        return "break"


def run_graphic_ui(context: LaunchContext) -> int:
    model, catalog = open_terminal_model(context)
    root = tk.Tk()
    PALGraphicFourWayApp(root, model, catalog=catalog, context=context)
    root.mainloop()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="PAL native four-way truth workspace launched by PALTermUI F10"
    )
    parser.add_argument("source", help="current function .icecube.json[.gz]")
    parser.add_argument("--manifest", help="owning PAL_function_manifest.json")
    parser.add_argument(
        "--naming",
        default="augmented",
        choices=("ssa", "pal", "humanizer", "operator", "augmented"),
    )
    parser.add_argument(
        "--projection",
        default="readable",
        choices=("readable", "executable"),
    )
    parser.add_argument("--line", type=int, default=0)
    parser.add_argument("--no-verify", action="store_true")
    args = parser.parse_args(argv)

    context = LaunchContext(
        source_path=args.source,
        manifest_path=args.manifest,
        naming=args.naming,
        projection=args.projection,
        line=args.line,
        verify=not args.no_verify,
    )
    try:
        return run_graphic_ui(context)
    except Exception as exc:
        # Keep a terminal-visible diagnostic for launches from curses.
        try:
            messagebox.showerror(
                "PALGraphicUI launch failed",
                "%s: %s" % (type(exc).__name__, exc),
            )
        except Exception:
            pass
        sys.stderr.write(
            "PALGraphicUI launch failed: %s: %s\n"
            % (type(exc).__name__, exc)
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
