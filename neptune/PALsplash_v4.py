# ============================================================
# PAL SPLASH / VT100 NOISE FADE + RED COMET ORBIT
# BUILD: palsplash_v3_looping_noise_green_pal_red_comet
# ============================================================

from __future__ import annotations

import math
import os
import random
import select
import shutil
import sys
import time
from typing import Dict, Optional, Sequence, TextIO, Tuple


ESC = "\x1b"
CSI = ESC + "["

VT_CLEAR = CSI + "2J"
VT_HOME = CSI + "H"
VT_HIDE_CURSOR = CSI + "?25l"
VT_SHOW_CURSOR = CSI + "?25h"
VT_RESET = CSI + "0m"
VT_DIM_GRAY = CSI + "2;37m"
VT_GREEN = CSI + "32m"
VT_BRIGHT_GREEN = CSI + "1;32m"
VT_RED = CSI + "31m"
VT_DIM_RED = CSI + "2;31m"
VT_BRIGHT_RED = CSI + "1;31m"

# ASCII-only block logo. Every non-space cell is part of the PAL mask.
LOGO_LINES: Tuple[str, ...] = (
    "########   ########   ##       ",
    "##     ##  ##    ##   ##       ",
    "##     ##  ##    ##   ##       ",
    "########   ########   ##       ",
    "##         ##    ##   ##       ",
    "##         ##    ##   ##       ",
    "##         ##    ##   ######## ",
)

NOISE_RAMP = " .:-=+*#%@"
LOGO_RAMP = " .:-=+*#%@"
COMET_TRAIL = "@*+=-:."
DEFAULT_SUBTITLE = "PyGhidra / Python Abstraction Layer / pre-Alpha PALTermUI (neptune) v0.23r (enhanced menus & views)"
DEFAULT_FOOTER = "PAL is an execution analysis oriented binary forensics reconstructive platform."
DEFAULT_PROMPT = "PRESS ANY KEY TO START..."


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _smoothstep(value: float) -> float:
    value = max(0.0, min(1.0, float(value)))
    return value * value * (3.0 - 2.0 * value)


def _center_x(width: int, text_width: int) -> int:
    return max(0, (int(width) - int(text_width)) // 2)


def _center_y(height: int, block_height: int) -> int:
    return max(0, (int(height) - int(block_height)) // 2)


def _clip_line(text: str, width: int) -> str:
    return str(text)[: max(0, int(width))]


def _logo_dimensions() -> Tuple[int, int]:
    return max(len(line) for line in LOGO_LINES), len(LOGO_LINES)


def _region_dimensions(terminal_width: int, terminal_height: int) -> Tuple[int, int]:
    logo_width, logo_height = _logo_dimensions()
    region_width = min(max(logo_width + 12, 50), max(1, terminal_width))
    region_height = min(max(logo_height + 8, 15), max(1, terminal_height - 4))
    return region_width, region_height


def _low_resolution_noise(
    width: int,
    height: int,
    density: float,
    rng: random.Random,
) -> Sequence[str]:
    """Return horizontally doubled, low-resolution ASCII noise."""
    width = max(1, int(width))
    height = max(1, int(height))
    density = max(0.0, min(1.0, float(density)))
    coarse_width = (width + 1) // 2
    rows = []

    for _ in range(height):
        coarse = []
        for _ in range(coarse_width):
            if rng.random() > density:
                char = " "
            else:
                ceiling = max(1, int((len(NOISE_RAMP) - 1) * density))
                char = NOISE_RAMP[rng.randint(1, ceiling)]
            coarse.append(char)
        rows.append("".join(char * 2 for char in coarse)[:width])

    return rows


def _logo_char(phase: float, rng: random.Random) -> str:
    """Map fade phase to an ASCII grayscale character with light jitter."""
    phase = max(0.0, min(1.0, float(phase)))
    jitter = rng.uniform(-0.10, 0.10) * (1.0 - phase)
    level = max(0.0, min(1.0, phase + jitter))
    index = int(round(level * (len(LOGO_RAMP) - 1)))
    return LOGO_RAMP[index]


def _compose_region(
    phase: float,
    width: int,
    height: int,
    rng: random.Random,
) -> Sequence[Sequence[Tuple[str, bool]]]:
    """Compose low-resolution noise with a fading PAL mask."""
    logo_width, logo_height = _logo_dimensions()
    region_width = max(width, logo_width + 8)
    region_height = max(height, logo_height + 4)
    noise_density = (1.0 - phase) ** 1.30
    noise = _low_resolution_noise(region_width, region_height, noise_density, rng)

    logo_x = _center_x(region_width, logo_width)
    logo_y = _center_y(region_height, logo_height)
    rows = [[(char, False) for char in line] for line in noise]

    for row_index, mask_line in enumerate(LOGO_LINES):
        target_y = logo_y + row_index
        if not 0 <= target_y < region_height:
            continue
        for column_index, mask_char in enumerate(mask_line):
            if mask_char == " ":
                continue
            target_x = logo_x + column_index
            if not 0 <= target_x < region_width:
                continue

            visible_probability = min(1.0, phase * 1.20)
            if phase < 0.98 and rng.random() > visible_probability:
                continue
            rows[target_y][target_x] = (_logo_char(phase, rng), True)

    return rows


def _comet_overlay(
    orbit_phase: float,
    region_width: int,
    region_height: int,
) -> Dict[Tuple[int, int], Tuple[str, str]]:
    """Return a red comet head and fading tail orbiting outside PAL.

    The orbit is elliptical because terminal cells are taller than they are
    wide.  The head travels clockwise and the tail follows the same path.
    """
    logo_width, logo_height = _logo_dimensions()
    logo_x = _center_x(region_width, logo_width)
    logo_y = _center_y(region_height, logo_height)

    center_x = logo_x + (logo_width - 1) / 2.0
    center_y = logo_y + (logo_height - 1) / 2.0
    radius_x = min(region_width / 2.0 - 1.0, logo_width / 2.0 + 4.0)
    radius_y = min(region_height / 2.0 - 1.0, logo_height / 2.0 + 2.5)

    overlay: Dict[Tuple[int, int], Tuple[str, str]] = {}
    phase = float(orbit_phase) % 1.0

    # Draw tail first, then head, so the head always wins on repeated cells.
    for tail_index in range(len(COMET_TRAIL) - 1, -1, -1):
        trail_phase = (phase - tail_index * 0.018) % 1.0
        angle = -math.pi / 2.0 + trail_phase * math.tau
        x = int(round(center_x + radius_x * math.cos(angle)))
        y = int(round(center_y + radius_y * math.sin(angle)))
        if not (0 <= x < region_width and 0 <= y < region_height):
            continue
        char = COMET_TRAIL[tail_index]
        role = (
            "comet_head" if tail_index == 0
            else "comet_tail" if tail_index < 4
            else "comet_dim"
        )
        overlay[(y, x)] = (char, role)

    return overlay


def _vt_style(role: str, logo_phase: float) -> str:
    if role == "logo":
        return VT_BRIGHT_GREEN if logo_phase >= 0.72 else VT_GREEN
    if role == "comet_head":
        return VT_BRIGHT_RED
    if role == "comet_tail":
        return VT_RED
    if role == "comet_dim":
        return VT_DIM_RED
    return VT_DIM_GRAY


def _render_vt100_frame(
    terminal_width: int,
    terminal_height: int,
    phase: float,
    subtitle: str,
    footer: str,
    rng: random.Random,
    show_prompt: bool,
    comet_phase: Optional[float] = None,
) -> str:
    region_width, region_height = _region_dimensions(
        terminal_width, terminal_height
    )
    region = _compose_region(phase, region_width, region_height, rng)
    comet = (
        _comet_overlay(comet_phase, region_width, region_height)
        if comet_phase is not None else {}
    )

    block_height = region_height + 4
    start_y = _center_y(terminal_height, block_height)
    start_x = _center_x(terminal_width, region_width)

    out = [VT_HOME]
    out.extend("\n" for _ in range(start_y))

    for row_index, row in enumerate(region):
        out.append(" " * start_x)
        current_role: Optional[str] = None
        for column_index, (char, is_logo) in enumerate(row):
            comet_cell = comet.get((row_index, column_index))
            if comet_cell is not None:
                char, role = comet_cell
            else:
                role = "logo" if is_logo else "noise"
            if role != current_role:
                out.append(_vt_style(role, phase))
                current_role = role
            out.append(char)
        out.append(VT_RESET + "\n")

    subtitle_text = _clip_line(subtitle, terminal_width)
    footer_text = _clip_line(footer, terminal_width)
    out.append(" " * _center_x(terminal_width, len(subtitle_text)))
    out.append(VT_GREEN if phase > 0.45 else VT_DIM_GRAY)
    out.append(subtitle_text + VT_RESET + "\n")

    out.append(" " * _center_x(terminal_width, len(footer_text)))
    out.append(VT_DIM_GRAY + footer_text + VT_RESET + "\n")

    if show_prompt:
        prompt = _clip_line(DEFAULT_PROMPT, terminal_width)
        out.append(" " * _center_x(terminal_width, len(prompt)))
        out.append(VT_BRIGHT_GREEN + prompt + VT_RESET)

    return "".join(out)


class _TerminalKeyReader:
    """POSIX cbreak/nonblocking key reader used during VT100 animation."""

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
        if self.fd is None or self.previous is None:
            return False
        try:
            import termios

            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.previous)
        except Exception:
            pass
        return False


def _play_vt_phase(
    stream: TextIO,
    key_reader: _TerminalKeyReader,
    terminal_width: int,
    terminal_height: int,
    rng: random.Random,
    subtitle: str,
    footer: str,
    frame_count: int,
    frame_delay: float,
    comet: bool,
    show_prompt: bool,
) -> bool:
    """Play one fade or comet phase. Return True when a key was pressed."""
    for frame_index in range(frame_count):
        raw_phase = frame_index / max(1, frame_count - 1)
        if comet:
            logo_phase = 1.0
            comet_phase = raw_phase
        else:
            logo_phase = _smoothstep(raw_phase)
            comet_phase = None

        stream.write(
            _render_vt100_frame(
                terminal_width=terminal_width,
                terminal_height=terminal_height,
                phase=logo_phase,
                subtitle=subtitle,
                footer=footer,
                rng=rng,
                show_prompt=show_prompt,
                comet_phase=comet_phase,
            )
        )
        stream.flush()
        if key_reader.pressed():
            return True
        time.sleep(frame_delay)
    return False


def animate_vt100(
    stream: Optional[TextIO] = None,
    subtitle: str = DEFAULT_SUBTITLE,
    footer: str = DEFAULT_FOOTER,
    duration: float = 1.35,
    fps: int = 24,
    wait_for_key: bool = False,
    seed: Optional[int] = None,
    comet_duration: float = 1.80,
) -> None:
    """Loop noise fade -> green PAL -> red comet orbit until key press.

    With ``wait_for_key=False`` exactly one fade/comet cycle is played.  With
    ``wait_for_key=True`` the two phases repeat until any key is pressed.
    Noninteractive streams receive the static logo without control sequences.
    """
    stream = stream or sys.stdout
    if not _stream_is_tty(stream):
        logo_print(stream=stream, subtitle=subtitle, footer=footer, color=False)
        return

    size = shutil.get_terminal_size(fallback=(80, 24))
    terminal_width = max(20, int(size.columns))
    terminal_height = max(10, int(size.lines))
    fps = max(1, int(fps))
    fade_frames = max(2, int(max(0.10, duration) * fps))
    comet_frames = max(2, int(max(0.10, comet_duration) * fps))
    frame_delay = 1.0 / fps
    rng = random.Random(seed)

    try:
        stream.write(VT_HIDE_CURSOR + VT_CLEAR + VT_HOME)
        stream.flush()

        with _TerminalKeyReader(sys.stdin) as key_reader:
            while True:
                if _play_vt_phase(
                    stream, key_reader,
                    terminal_width, terminal_height,
                    rng, subtitle, footer,
                    fade_frames, frame_delay,
                    comet=False,
                    show_prompt=wait_for_key,
                ):
                    break

                if _play_vt_phase(
                    stream, key_reader,
                    terminal_width, terminal_height,
                    rng, subtitle, footer,
                    comet_frames, frame_delay,
                    comet=True,
                    show_prompt=wait_for_key,
                ):
                    break

                if not wait_for_key:
                    break
    finally:
        stream.write(VT_RESET + VT_SHOW_CURSOR)
        stream.flush()


def logo_print(
    stream: Optional[TextIO] = None,
    subtitle: str = DEFAULT_SUBTITLE,
    footer: str = DEFAULT_FOOTER,
    color: Optional[bool] = None,
) -> None:
    """Print a static PAL logo; compatible with the earlier splash API."""
    stream = stream or sys.stdout
    use_color = _stream_is_tty(stream) if color is None else bool(color)
    green = VT_BRIGHT_GREEN if use_color else ""
    gray = VT_DIM_GRAY if use_color else ""
    reset = VT_RESET if use_color else ""

    stream.write("\n\n")
    for line in LOGO_LINES:
        stream.write(green + line.rstrip() + reset + "\n")
    stream.write("\n")
    stream.write(green + subtitle + reset + "\n")
    stream.write(gray + footer + reset + "\n\n")
    stream.flush()


def _curses_init_attributes():
    """Return noise, green, bright green, red, bright red attributes."""
    try:
        import curses

        noise_attr = curses.A_DIM
        green_attr = curses.A_NORMAL
        bright_green_attr = curses.A_BOLD
        red_attr = curses.A_NORMAL
        bright_red_attr = curses.A_BOLD

        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
                background = -1
            except Exception:
                background = curses.COLOR_BLACK
            try:
                curses.init_pair(1, curses.COLOR_WHITE, background)
                curses.init_pair(2, curses.COLOR_GREEN, background)
                curses.init_pair(3, curses.COLOR_RED, background)
                noise_attr = curses.color_pair(1) | curses.A_DIM
                green_attr = curses.color_pair(2)
                bright_green_attr = curses.color_pair(2) | curses.A_BOLD
                red_attr = curses.color_pair(3)
                bright_red_attr = curses.color_pair(3) | curses.A_BOLD
            except Exception:
                pass

        return (
            noise_attr,
            green_attr,
            bright_green_attr,
            red_attr,
            bright_red_attr,
        )
    except Exception:
        return 0, 0, 0, 0, 0


def _safe_addnstr(screen, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    if y < 0 or x < 0 or width <= 0:
        return
    try:
        screen.addnstr(y, x, text, width, attr)
    except Exception:
        pass


def _curses_role_attr(role: str, attributes, phase: float) -> int:
    noise_attr, green_attr, bright_green_attr, red_attr, bright_red_attr = attributes
    if role == "logo":
        return bright_green_attr if phase >= 0.72 else green_attr
    if role == "comet_head":
        return bright_red_attr
    if role == "comet_tail":
        return red_attr
    if role == "comet_dim":
        try:
            import curses
            return red_attr | curses.A_DIM
        except Exception:
            return red_attr
    return noise_attr


def _draw_curses_frame(
    screen,
    phase: float,
    subtitle: str,
    footer: str,
    rng: random.Random,
    show_prompt: bool,
    attributes,
    comet_phase: Optional[float] = None,
) -> None:
    height, width = screen.getmaxyx()
    region_width, region_height = _region_dimensions(
        max(1, width - 1), max(1, height)
    )
    region = _compose_region(phase, region_width, region_height, rng)
    comet = (
        _comet_overlay(comet_phase, region_width, region_height)
        if comet_phase is not None else {}
    )

    block_height = region_height + 4
    start_y = _center_y(height, block_height)
    start_x = _center_x(width, region_width)

    screen.erase()
    for row_index, row in enumerate(region):
        y = start_y + row_index
        if y >= height - 1:
            break

        run_chars = []
        run_role: Optional[str] = None
        run_start = 0

        for column_index, (char, is_logo) in enumerate(row):
            comet_cell = comet.get((row_index, column_index))
            if comet_cell is not None:
                char, role = comet_cell
            else:
                role = "logo" if is_logo else "noise"

            if run_role is None:
                run_role = role
                run_start = column_index
            if role != run_role:
                text = "".join(run_chars)
                _safe_addnstr(
                    screen,
                    y,
                    start_x + run_start,
                    text,
                    max(0, width - start_x - run_start - 1),
                    _curses_role_attr(run_role, attributes, phase),
                )
                run_chars = []
                run_role = role
                run_start = column_index
            run_chars.append(char)

        if run_chars and run_role is not None:
            text = "".join(run_chars)
            _safe_addnstr(
                screen,
                y,
                start_x + run_start,
                text,
                max(0, width - start_x - run_start - 1),
                _curses_role_attr(run_role, attributes, phase),
            )

    noise_attr, green_attr, bright_green_attr, _, _ = attributes
    subtitle_y = start_y + region_height
    footer_y = subtitle_y + 1
    prompt_y = footer_y + 2

    clipped_subtitle = _clip_line(subtitle, max(0, width - 1))
    clipped_footer = _clip_line(footer, max(0, width - 1))
    _safe_addnstr(
        screen,
        subtitle_y,
        _center_x(width, len(clipped_subtitle)),
        clipped_subtitle,
        max(0, width - 1),
        green_attr if phase > 0.45 else noise_attr,
    )
    _safe_addnstr(
        screen,
        footer_y,
        _center_x(width, len(clipped_footer)),
        clipped_footer,
        max(0, width - 1),
        noise_attr,
    )

    if show_prompt:
        prompt = _clip_line(DEFAULT_PROMPT, max(0, width - 1))
        _safe_addnstr(
            screen,
            prompt_y,
            _center_x(width, len(prompt)),
            prompt,
            max(0, width - 1),
            bright_green_attr,
        )

    try:
        screen.refresh()
    except Exception:
        pass


def _curses_key_pressed(screen) -> bool:
    try:
        return screen.getch() != -1
    except Exception:
        return False


def _play_curses_phase(
    screen,
    rng: random.Random,
    attributes,
    subtitle: str,
    frame_count: int,
    frame_delay: float,
    comet: bool,
    show_prompt: bool,
) -> bool:
    for frame_index in range(frame_count):
        raw_phase = frame_index / max(1, frame_count - 1)
        if comet:
            logo_phase = 1.0
            comet_phase = raw_phase
        else:
            logo_phase = _smoothstep(raw_phase)
            comet_phase = None

        _draw_curses_frame(
            screen=screen,
            phase=logo_phase,
            subtitle=DEFAULT_SUBTITLE,
            footer=subtitle,
            rng=rng,
            show_prompt=show_prompt,
            attributes=attributes,
            comet_phase=comet_phase,
        )
        if _curses_key_pressed(screen):
            return True
        time.sleep(frame_delay)
    return False


def draw_splash(
    screen,
    subtitle: str = DEFAULT_FOOTER,
    wait_for_key: bool = True,
    duration: float = 1.25,
    fps: int = 20,
    seed: Optional[int] = None,
    comet_duration: float = 1.80,
) -> None:
    """Loop noise fade and red comet orbit until any key is pressed.

    The original ``draw_splash(screen, subtitle, wait_for_key)`` calling
    convention remains intact.  ``wait_for_key=False`` plays one complete
    fade/comet cycle and returns.  ``wait_for_key=True`` loops indefinitely
    until a key is detected during either phase.
    """
    attributes = _curses_init_attributes()
    rng = random.Random(seed)
    fps = max(1, int(fps))
    fade_frames = max(2, int(max(0.10, duration) * fps))
    comet_frames = max(2, int(max(0.10, comet_duration) * fps))
    frame_delay = 1.0 / fps

    try:
        try:
            screen.nodelay(True)
            screen.keypad(True)
        except Exception:
            pass

        while True:
            if _play_curses_phase(
                screen, rng, attributes, subtitle,
                fade_frames, frame_delay,
                comet=False,
                show_prompt=wait_for_key,
            ):
                break

            if _play_curses_phase(
                screen, rng, attributes, subtitle,
                comet_frames, frame_delay,
                comet=True,
                show_prompt=wait_for_key,
            ):
                break

            if not wait_for_key:
                break
    finally:
        try:
            screen.nodelay(False)
        except Exception:
            pass


__all__ = [
    "LOGO_LINES",
    "animate_vt100",
    "logo_print",
    "draw_splash",
]


if __name__ == "__main__":
    animate_vt100(wait_for_key=True)
