# ============================================================
# PAL SPLASH / MARS RISE + PAL ASCENT
# BUILD: palsplash_v4_mars_rise_pal_ufo_v2
# BASELINE: palsplash_v4_mars_rover_ghidra_chase_v1
# ============================================================

from __future__ import annotations

import math
import os
import random
import select
import shutil
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence, TextIO, Tuple


ESC = "\x1b"
CSI = ESC + "["
VT_CLEAR = CSI + "2J"
VT_HOME = CSI + "H"
VT_HIDE_CURSOR = CSI + "?25l"
VT_SHOW_CURSOR = CSI + "?25h"
VT_RESET = CSI + "0m"

DEFAULT_SUBTITLE = "PyGhidra / Python Abstract Layer / PALTermUI (mars)"
DEFAULT_FOOTER = (
    "PAL is an execution analysis oriented binary forensics reconstructive platform."
)
DEFAULT_PROMPT = "PRESS ANY KEY TO ENTER (mars)..."

Cell = Tuple[str, str]
Canvas = List[List[Cell]]

# ASCII-only PAL mask retained only for compatibility with callers that import it.
LOGO_LINES: Tuple[str, ...] = (
    "########   ########   ##       ",
    "##     ##  ##    ##   ##       ",
    "##     ##  ##    ##   ##       ",
    "########   ########   ##       ",
    "##         ##    ##   ##       ",
    "##         ##    ##   ##       ",
    "##         ##    ##   ######## ",
)

# A three-dimensional ship shell.  The large PAL panel is rendered separately
# so every letter cell receives its own bright phosphor color.
SHIP_SHELL: Tuple[str, ...] = (
    "                           .-^^^^-.",
    "                      _.-'  ____  `-._",
    "                 _.-'______/____\\______`-._",
    "             _.-'__________________________`-._",
    "         _.-'      ____________________      `-._",
    "      .-'_______.-'                    `-._______`-.",
    "    .'=========/                        \\========= `.",
    "   /__________/                          \\___________\\",
    "  <==========|                            |===========>",
    "   \\__________\\                          /___________/",
    "    `.=========\\________________________/=========.'",
    "      `-.___     `-.________________.-'     ___.-'",
    "           `--.___                  ___.--'",
    "                  `----------------'",
)

PAL_GLYPH: Tuple[str, ...] = (
    "####   ###   #    ",
    "#   # #   #  #    ",
    "####  #####  #    ",
    "#     #   #  #    ",
    "#     #   #  #####",
)

# 256-color foregrounds.  Roles are remapped to dimmer colors during fade.
ROLE_PALETTES: Dict[str, Tuple[int, int, int, int]] = {
    "sky": (16, 16, 16, 16),
    "star_dim": (238, 244, 250, 252),
    "star": (240, 248, 255, 231),
    "star_blue": (17, 25, 117, 159),
    "mars_shadow": (52, 88, 124, 160),
    "mars_dark": (52, 94, 130, 166),
    "mars_mid": (88, 130, 166, 202),
    "mars_light": (94, 166, 202, 208),
    "mars_hot": (130, 202, 208, 214),
    "crater": (52, 88, 94, 130),
    "ship_shadow": (236, 240, 244, 248),
    "ship_body": (240, 247, 250, 255),
    "ship_bright": (244, 250, 255, 231),
    "ship_glass": (17, 25, 45, 87),
    "pal_shadow": (22, 22, 28, 34),
    "pal": (22, 28, 46, 82),
    "engine": (52, 88, 196, 220),
    "title": (238, 244, 250, 252),
    "prompt": (22, 28, 46, 82),
}


# ---------------------------------------------------------------------------
# GENERIC HELPERS
# ---------------------------------------------------------------------------


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _smoothstep(value: float) -> float:
    value = max(0.0, min(1.0, float(value)))
    return value * value * (3.0 - 2.0 * value)


def _ease_out(value: float) -> float:
    value = max(0.0, min(1.0, float(value)))
    return 1.0 - (1.0 - value) ** 3


def _center_x(width: int, text_width: int) -> int:
    return max(0, (int(width) - int(text_width)) // 2)


def _clip_line(text: str, width: int) -> str:
    return str(text)[: max(0, int(width))]


def _new_canvas(width: int, height: int) -> Canvas:
    return [[(" ", "sky") for _ in range(max(1, width))] for _ in range(max(1, height))]


def _put_cell(canvas: Canvas, x: int, y: int, char: str, role: str) -> None:
    if not char:
        return
    if 0 <= y < len(canvas) and 0 <= x < len(canvas[y]):
        canvas[y][x] = (char[0], role)


def _put_text(
    canvas: Canvas,
    x: int,
    y: int,
    text: str,
    role: str,
    transparent_spaces: bool = True,
) -> None:
    for offset, char in enumerate(str(text)):
        if transparent_spaces and char == " ":
            continue
        _put_cell(canvas, x + offset, y, char, role)


def _sprite_dimensions(sprite: Sequence[str]) -> Tuple[int, int]:
    return max((len(line) for line in sprite), default=0), len(sprite)


def _deterministic_unit(*values: int) -> float:
    seed = 0x9E3779B9
    for value in values:
        seed ^= int(value) + 0x9E3779B9 + ((seed << 6) & 0xFFFFFFFF) + (seed >> 2)
        seed &= 0xFFFFFFFF
    seed ^= seed << 13
    seed ^= seed >> 17
    seed ^= seed << 5
    return float(seed & 0xFFFFFFFF) / float(0xFFFFFFFF)


# ---------------------------------------------------------------------------
# STARFIELD
# ---------------------------------------------------------------------------


def _star_catalog(width: int, height: int, seed: int) -> Tuple[Tuple[int, int, str, str, int], ...]:
    rng = random.Random((int(seed) << 12) ^ (width << 5) ^ height)
    count = max(18, int(width * height * 0.022))
    stars = []
    glyphs = (".", ".", ".", "+", "*", "·")
    roles = ("star_dim", "star_dim", "star", "star", "star_blue")
    for _ in range(count):
        x = rng.randrange(max(1, width))
        y = rng.randrange(max(1, max(1, height - 2)))
        glyph = rng.choice(glyphs)
        role = rng.choice(roles)
        twinkle = rng.randrange(11)
        stars.append((x, y, glyph, role, twinkle))
    return tuple(stars)


def _draw_stars(canvas: Canvas, stars, frame_index: int, alpha: float) -> None:
    if alpha <= 0.0:
        return
    for x, y, glyph, role, twinkle in stars:
        pulse = (int(frame_index) + int(twinkle)) % 17
        if pulse in (0, 1):
            glyph_now = "*" if glyph in (".", "·") else "+"
            role_now = "star" if role != "star_blue" else "star_blue"
        elif pulse == 8 and glyph in ("*", "+"):
            glyph_now = "."
            role_now = "star_dim"
        else:
            glyph_now = glyph
            role_now = role
        if _deterministic_unit(x, y, frame_index, 71) <= alpha:
            _put_cell(canvas, x, y, glyph_now, role_now)


# ---------------------------------------------------------------------------
# RISING MARS
# ---------------------------------------------------------------------------


def _mars_geometry(width: int, scene_height: int, motion: float) -> Tuple[float, float, float, float]:
    radius_x = max(22.0, min(width * 0.49, 74.0))
    radius_y = max(8.0, min(scene_height * 0.47, radius_x * 0.43))
    center_x = (width - 1) / 2.0
    start_center_y = scene_height + radius_y * 0.76
    end_center_y = scene_height - radius_y * 0.03
    center_y = start_center_y + (end_center_y - start_center_y) * _ease_out(motion)
    return center_x, center_y, radius_x, radius_y


def _mars_cell_role(nx: float, ny: float, x: int, y: int, frame_index: int) -> Tuple[str, str]:
    # Simulated lighting from upper left plus deterministic geology.
    normal_z = math.sqrt(max(0.0, 1.0 - nx * nx - ny * ny))
    light = max(0.0, 0.56 * (-nx) + 0.34 * (-ny) + 0.60 * normal_z)
    geology = (
        math.sin(nx * 9.3 + ny * 4.1)
        + 0.52 * math.sin(nx * 17.0 - ny * 8.0)
        + 0.28 * math.sin(nx * 31.0 + ny * 15.0)
    )
    grain = (_deterministic_unit(x, y, 991) - 0.5) * 0.36
    shade = light + geology * 0.11 + grain

    # Crater rings generated from a few fixed sphere-space centers.
    crater_hit = False
    for cx, cy, radius in ((-0.46, -0.20, 0.13), (0.31, -0.09, 0.10), (0.07, 0.25, 0.08), (-0.18, 0.08, 0.055)):
        distance = math.hypot(nx - cx, ny - cy)
        if abs(distance - radius) < 0.022 or distance < radius * 0.38:
            crater_hit = True
            break

    if crater_hit:
        role = "crater"
        glyph = "o" if _deterministic_unit(x, y, frame_index, 4) > 0.43 else "."
    elif shade < 0.28:
        role, glyph = "mars_shadow", "#"
    elif shade < 0.48:
        role, glyph = "mars_dark", "%"
    elif shade < 0.67:
        role, glyph = "mars_mid", "@"
    elif shade < 0.84:
        role, glyph = "mars_light", "&"
    else:
        role, glyph = "mars_hot", "*"
    return glyph, role


def _draw_mars(
    canvas: Canvas,
    width: int,
    scene_height: int,
    motion: float,
    frame_index: int,
    alpha: float,
) -> Tuple[float, float, float, float]:
    geometry = _mars_geometry(width, scene_height, motion)
    center_x, center_y, radius_x, radius_y = geometry
    if alpha <= 0.0:
        return geometry

    min_y = max(0, int(math.floor(center_y - radius_y - 1)))
    max_y = min(scene_height - 1, int(math.ceil(center_y + radius_y + 1)))
    min_x = max(0, int(math.floor(center_x - radius_x - 1)))
    max_x = min(width - 1, int(math.ceil(center_x + radius_x + 1)))

    for y in range(min_y, max_y + 1):
        ny = (y - center_y) / radius_y
        for x in range(min_x, max_x + 1):
            nx = (x - center_x) / radius_x
            distance = nx * nx + ny * ny
            if distance > 1.0:
                continue
            if _deterministic_unit(x, y, frame_index, 212) > alpha:
                continue
            glyph, role = _mars_cell_role(nx, ny, x, y, frame_index)
            # Bright rim at the upper curvature.
            if 0.92 <= distance <= 1.0 and ny < 0.0:
                glyph = "." if x % 2 else "'"
                role = "mars_hot" if nx < 0.20 else "mars_light"
            _put_cell(canvas, x, y, glyph, role)
    return geometry


# ---------------------------------------------------------------------------
# PAL SHIP
# ---------------------------------------------------------------------------


def _ship_role(line: str, column: int, char: str) -> str:
    if char in "^.'`":
        return "ship_bright"
    if char in "_=/\\<>[]|-":
        return "ship_body"
    return "ship_shadow"


def _draw_ship_shell(canvas: Canvas, x: int, y: int, alpha: float, frame_index: int) -> None:
    for row, line in enumerate(SHIP_SHELL):
        for column, char in enumerate(line):
            if char == " ":
                continue
            if _deterministic_unit(x + column, y + row, frame_index, 313) > alpha:
                continue
            _put_cell(canvas, x + column, y + row, char, _ship_role(line, column, char))

    # Blue cockpit glass, intentionally centered inside the upper hull.
    cockpit = ("        ________        ", "     .-'::::::::`-.     ", "    /::::::::::::::\\    ")
    cockpit_x = x + 22
    cockpit_y = y + 2
    for row, line in enumerate(cockpit):
        for column, char in enumerate(line):
            if char == " ":
                continue
            if _deterministic_unit(cockpit_x + column, cockpit_y + row, frame_index, 511) <= alpha:
                role = "ship_glass" if char == ":" else "ship_bright"
                _put_cell(canvas, cockpit_x + column, cockpit_y + row, char, role)


def _draw_pal_panel(canvas: Canvas, ship_x: int, ship_y: int, alpha: float, frame_index: int) -> None:
    glyph_width = max(len(line) for line in PAL_GLYPH)
    glyph_height = len(PAL_GLYPH)
    shell_width, _ = _sprite_dimensions(SHIP_SHELL)
    x = ship_x + max(0, (shell_width - glyph_width) // 2)
    y = ship_y + 6

    # Clear the front face so stars and Mars texture cannot punch through PAL.
    panel_left = x - 2
    panel_top = y - 1
    panel_width = glyph_width + 4
    panel_height = glyph_height + 2
    for py in range(panel_top, panel_top + panel_height):
        for px in range(panel_left, panel_left + panel_width):
            _put_cell(canvas, px, py, " ", "sky")
    _put_text(canvas, panel_left, panel_top, "+" + "-" * (panel_width - 2) + "+", "ship_body", False)
    _put_text(canvas, panel_left, panel_top + panel_height - 1, "+" + "-" * (panel_width - 2) + "+", "ship_body", False)
    for py in range(panel_top + 1, panel_top + panel_height - 1):
        _put_cell(canvas, panel_left, py, "|", "ship_body")
        _put_cell(canvas, panel_left + panel_width - 1, py, "|", "ship_body")

    # One-cell down/right extrusion gives the block lettering a 3-D face.
    for row, line in enumerate(PAL_GLYPH):
        for column, char in enumerate(line):
            if char == " ":
                continue
            if _deterministic_unit(x + column, y + row, frame_index, 701) <= alpha:
                _put_cell(canvas, x + column + 1, y + row + 1, "#", "pal_shadow")
    for row, line in enumerate(PAL_GLYPH):
        for column, char in enumerate(line):
            if char == " ":
                continue
            if _deterministic_unit(x + column, y + row, frame_index, 733) <= alpha:
                _put_cell(canvas, x + column, y + row, char, "pal")


def _draw_engine_plume(canvas: Canvas, ship_x: int, ship_y: int, alpha: float, frame_index: int) -> None:
    shell_width, shell_height = _sprite_dimensions(SHIP_SHELL)
    center = ship_x + shell_width // 2
    base_y = ship_y + shell_height
    plume_rows = (
        "   | |   ",
        "  :| |:  ",
        " .:|||:. ",
        "  .:*:.  ",
        "   ...   ",
    )
    jitter = (-1, 0, 1, 0)[frame_index % 4]
    for row, line in enumerate(plume_rows):
        px = center - len(line) // 2 + (jitter if row >= 2 else 0)
        py = base_y + row
        for column, char in enumerate(line):
            if char == " ":
                continue
            if _deterministic_unit(px + column, py, frame_index, 919) <= alpha:
                _put_cell(canvas, px + column, py, char, "engine")


def _ship_position(width: int, scene_height: int, motion: float) -> Tuple[int, int]:
    ship_width, ship_height = _sprite_dimensions(SHIP_SHELL)
    sway = int(round(math.sin(motion * math.pi * 2.0) * min(4.0, width * 0.025)))
    x = _center_x(width, ship_width) + sway
    start_y = scene_height + 2
    end_y = max(1, int(scene_height * 0.08))
    y = int(round(start_y + (end_y - start_y) * _ease_out(motion)))
    return x, y


def _draw_ship(
    canvas: Canvas,
    width: int,
    scene_height: int,
    motion: float,
    frame_index: int,
    alpha: float,
) -> Tuple[int, int]:
    ship_x, ship_y = _ship_position(width, scene_height, motion)
    _draw_engine_plume(canvas, ship_x, ship_y, alpha, frame_index)
    _draw_ship_shell(canvas, ship_x, ship_y, alpha, frame_index)
    _draw_pal_panel(canvas, ship_x, ship_y, alpha, frame_index)
    return ship_x, ship_y


# ---------------------------------------------------------------------------
# SCENE COMPOSITION
# ---------------------------------------------------------------------------


def _scene_phase(raw_phase: float) -> Tuple[float, float]:
    raw_phase = max(0.0, min(1.0, float(raw_phase)))
    if raw_phase <= 0.80:
        return _smoothstep(raw_phase / 0.80), 1.0
    fade = 1.0 - _smoothstep((raw_phase - 0.80) / 0.20)
    return 1.0, fade


def _compose_scene(
    terminal_width: int,
    terminal_height: int,
    raw_phase: float,
    frame_index: int,
    seed: int,
    subtitle: str,
    show_prompt: bool,
) -> Canvas:
    width = max(40, int(terminal_width))
    height = max(14, int(terminal_height))
    canvas = _new_canvas(width, height)
    scene_height = max(10, height - 2)
    motion, alpha = _scene_phase(raw_phase)
    stars = _star_catalog(width, scene_height, seed)
    _draw_stars(canvas, stars, frame_index, alpha)
    _draw_mars(canvas, width, scene_height, motion, frame_index, alpha)
    _draw_ship(canvas, width, scene_height, motion, frame_index, alpha)

    # The film itself is primary.  Only a compact footer remains.
    if alpha > 0.05:
        footer = _clip_line(subtitle, width)
        _put_text(canvas, _center_x(width, len(footer)), height - 2, footer, "title")
        if show_prompt:
            prompt = _clip_line(DEFAULT_PROMPT, width)
            _put_text(canvas, _center_x(width, len(prompt)), height - 1, prompt, "prompt")
    return canvas


def _role_color(role: str, alpha: float) -> int:
    palette = ROLE_PALETTES.get(role, ROLE_PALETTES["ship_body"])
    alpha = max(0.0, min(1.0, float(alpha)))
    index = min(3, max(0, int(round(alpha * 3.0))))
    return int(palette[index])


def _render_vt100_frame(
    terminal_width: int,
    terminal_height: int,
    raw_phase: float,
    frame_index: int,
    seed: int,
    subtitle: str,
    show_prompt: bool,
) -> str:
    canvas = _compose_scene(
        terminal_width,
        terminal_height,
        raw_phase,
        frame_index,
        seed,
        subtitle,
        show_prompt,
    )
    _, alpha = _scene_phase(raw_phase)
    out = [VT_HOME]
    for row in canvas:
        current_role: Optional[str] = None
        for char, role in row:
            if role != current_role:
                out.append(CSI + "38;5;%dm" % _role_color(role, alpha))
                current_role = role
            out.append(char)
        out.append(VT_RESET + "\n")
    return "".join(out)


# ---------------------------------------------------------------------------
# VT100 PLAYER
# ---------------------------------------------------------------------------


class _TerminalKeyReader:
    def __init__(self, stream: TextIO):
        self.stream = stream
        self.fd: Optional[int] = None
        self.previous = None

    def __enter__(self):
        if not _stream_is_tty(self.stream):
            return self
        try:
            import termios
            import tty

            self.fd = self.stream.fileno()
            self.previous = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        except Exception:
            self.fd = None
            self.previous = None
        return self

    def pressed(self) -> bool:
        if self.fd is None:
            return False
        try:
            readable, _, _ = select.select([self.fd], [], [], 0.0)
            if not readable:
                return False
            os.read(self.fd, 1)
            return True
        except Exception:
            return False

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None and self.previous is not None:
            try:
                import termios

                termios.tcsetattr(self.fd, termios.TCSADRAIN, self.previous)
            except Exception:
                pass
        return False


def animate_vt100(
    stream: Optional[TextIO] = None,
    subtitle: str = DEFAULT_SUBTITLE,
    footer: str = DEFAULT_FOOTER,
    duration: float = 4.80,
    fps: int = 24,
    wait_for_key: bool = False,
    seed: Optional[int] = None,
    comet_duration: float = 0.0,
) -> None:
    """Play the Mars-rise/PAL-ascent film.

    ``comet_duration`` remains accepted for API compatibility but is unused.
    With ``wait_for_key=True`` the film repeats until a key is pressed.
    """
    del footer, comet_duration
    stream = stream or sys.stdout
    seed = 260731 if seed is None else int(seed)

    if not _stream_is_tty(stream):
        logo_print(stream=stream, subtitle=subtitle, color=False)
        return

    size = shutil.get_terminal_size(fallback=(120, 36))
    terminal_width = max(40, int(size.columns))
    terminal_height = max(14, int(size.lines))
    fps = max(1, int(fps))
    frame_count = max(12, int(max(1.2, float(duration)) * fps))
    frame_delay = 1.0 / fps

    try:
        stream.write(VT_HIDE_CURSOR + VT_CLEAR + VT_HOME)
        stream.flush()
        with _TerminalKeyReader(sys.stdin) as key_reader:
            while True:
                interrupted = False
                for frame_index in range(frame_count):
                    raw_phase = frame_index / max(1, frame_count - 1)
                    stream.write(_render_vt100_frame(
                        terminal_width,
                        terminal_height,
                        raw_phase,
                        frame_index,
                        seed,
                        subtitle,
                        wait_for_key,
                    ))
                    stream.flush()
                    if key_reader.pressed():
                        interrupted = True
                        break
                    time.sleep(frame_delay)
                if interrupted or not wait_for_key:
                    break
    finally:
        stream.write(VT_RESET + VT_SHOW_CURSOR)
        stream.flush()


# ---------------------------------------------------------------------------
# CURSES PLAYER
# ---------------------------------------------------------------------------


def _curses_palette():
    try:
        import curses

        try:
            curses.start_color()
        except Exception:
            pass
        try:
            curses.use_default_colors()
            background = -1
        except Exception:
            background = curses.COLOR_BLACK

        role_attrs = {}
        next_pair = 1
        for role, palette in ROLE_PALETTES.items():
            foreground = palette[-1]
            if curses.COLORS < 256:
                foreground = {
                    "sky": curses.COLOR_BLACK,
                    "star_dim": curses.COLOR_WHITE,
                    "star": curses.COLOR_WHITE,
                    "star_blue": curses.COLOR_CYAN,
                    "mars_shadow": curses.COLOR_RED,
                    "mars_dark": curses.COLOR_RED,
                    "mars_mid": curses.COLOR_RED,
                    "mars_light": curses.COLOR_YELLOW,
                    "mars_hot": curses.COLOR_YELLOW,
                    "crater": curses.COLOR_RED,
                    "ship_shadow": curses.COLOR_WHITE,
                    "ship_body": curses.COLOR_WHITE,
                    "ship_bright": curses.COLOR_WHITE,
                    "ship_glass": curses.COLOR_CYAN,
                    "pal_shadow": curses.COLOR_GREEN,
                    "pal": curses.COLOR_GREEN,
                    "engine": curses.COLOR_YELLOW,
                    "title": curses.COLOR_WHITE,
                    "prompt": curses.COLOR_GREEN,
                }.get(role, curses.COLOR_WHITE)
            try:
                curses.init_pair(next_pair, int(foreground), background)
                attr = curses.color_pair(next_pair)
                if role in ("star", "mars_hot", "ship_bright", "pal", "engine", "prompt"):
                    attr |= curses.A_BOLD
                if role in ("star_dim", "mars_shadow", "ship_shadow"):
                    attr |= curses.A_DIM
                role_attrs[role] = attr
                next_pair += 1
            except Exception:
                role_attrs[role] = 0
        return role_attrs
    except Exception:
        return {role: 0 for role in ROLE_PALETTES}


def _safe_addnstr(screen, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    if y < 0 or x < 0 or width <= 0:
        return
    try:
        screen.addnstr(y, x, text, width, attr)
    except Exception:
        pass


def _draw_curses_frame(
    screen,
    raw_phase: float,
    frame_index: int,
    seed: int,
    subtitle: str,
    show_prompt: bool,
    role_attrs: Dict[str, int],
) -> None:
    height, width = screen.getmaxyx()
    width = max(1, width - 1)
    canvas = _compose_scene(width, height, raw_phase, frame_index, seed, subtitle, show_prompt)
    try:
        screen.erase()
    except Exception:
        pass
    for y, row in enumerate(canvas):
        if y >= height:
            break
        run_role: Optional[str] = None
        run_start = 0
        run_chars: List[str] = []
        for x, (char, role) in enumerate(row):
            if run_role is None:
                run_role = role
                run_start = x
            if role != run_role:
                _safe_addnstr(
                    screen,
                    y,
                    run_start,
                    "".join(run_chars),
                    max(0, width - run_start),
                    role_attrs.get(run_role, 0),
                )
                run_role = role
                run_start = x
                run_chars = []
            run_chars.append(char)
        if run_chars and run_role is not None:
            _safe_addnstr(
                screen,
                y,
                run_start,
                "".join(run_chars),
                max(0, width - run_start),
                role_attrs.get(run_role, 0),
            )
    try:
        screen.refresh()
    except Exception:
        pass


def draw_splash(
    screen,
    subtitle: str = DEFAULT_SUBTITLE,
    wait_for_key: bool = True,
    duration: float = 4.80,
    fps: int = 24,
    seed: Optional[int] = None,
    comet_duration: float = 0.0,
) -> None:
    """Curses-compatible Mars-rise/PAL-ascent splash.

    The legacy call signature remains intact.  The former fuzz reveal and comet
    phases are intentionally removed.
    """
    del comet_duration
    role_attrs = _curses_palette()
    seed = 260731 if seed is None else int(seed)
    fps = max(1, int(fps))
    frame_count = max(12, int(max(1.2, float(duration)) * fps))
    frame_delay = 1.0 / fps

    try:
        try:
            screen.nodelay(True)
            screen.keypad(True)
        except Exception:
            pass
        while True:
            interrupted = False
            for frame_index in range(frame_count):
                raw_phase = frame_index / max(1, frame_count - 1)
                _draw_curses_frame(
                    screen,
                    raw_phase,
                    frame_index,
                    seed,
                    subtitle,
                    wait_for_key,
                    role_attrs,
                )
                try:
                    if screen.getch() != -1:
                        interrupted = True
                        break
                except Exception:
                    pass
                time.sleep(frame_delay)
            if interrupted or not wait_for_key:
                break
    finally:
        try:
            screen.nodelay(False)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# STATIC FALLBACK
# ---------------------------------------------------------------------------


def _plain_scene(width: int = 120, height: int = 34) -> Tuple[str, ...]:
    canvas = _compose_scene(width, height, 0.70, 47, 260731, "", False)
    return tuple("".join(char for char, _role in row).rstrip() for row in canvas)


def logo_print(
    stream: Optional[TextIO] = None,
    subtitle: str = DEFAULT_SUBTITLE,
    footer: str = DEFAULT_FOOTER,
    color: Optional[bool] = None,
) -> None:
    """Print a static frame from the film for noninteractive callers."""
    del footer
    stream = stream or sys.stdout
    use_color = _stream_is_tty(stream) if color is None else bool(color)
    green = CSI + "1;38;5;82m" if use_color else ""
    reset = VT_RESET if use_color else ""
    stream.write("\n")
    for line in _plain_scene():
        stream.write(line + "\n")
    stream.write(green + subtitle + reset + "\n")
    stream.flush()


__all__ = [
    "LOGO_LINES",
    "animate_vt100",
    "logo_print",
    "draw_splash",
]


if __name__ == "__main__":
    animate_vt100(wait_for_key=True)
