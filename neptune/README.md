<img width="3840" height="1998" alt="image" src="https://github.com/user-attachments/assets/7824d91c-1a67-49ab-b5b5-38123e1b04f8" />



---

# PALTermUI neptune

### v0.23r · Pre-Alpha Preview · Static Python State-Machine Audit Workbench

`PALTermUI_neptune.py` is an opt-in interface for examining PAL-generated Python state machines alongside the machine-code, PHI, CFG, naming, call, ABI, and project evidence from which they were reconstructed. It does not replace the repository's default `PALTermUI.py`.

> Search the Python projection, lock onto the owning machine block, inspect the variable's PHI custody, and walk real static branch choices while every pane remains synchronized.

## What neptune adds

- **STATIC DEBUG** — synchronized PHI, ASM, and READ.PY/EXEC.PY inspection around one selected state pathway.
- **Static step-debug history** — follow ASM jumps with Enter, replay earlier or later frames with `<` and `>`, and branch into a new inspection path after stepping back.
- **Branch-fork truth** — inspect conditional source, taken path, fallthrough path, and nearest completion/join.
- **Python-to-machine navigation** — search any variable, constant, call, or ASCII sequence in Python and iterate its machine-owned hotspots.
- **PHI state custody** — trace incoming SSA values, merge points, drop-in origins, loop-carried cycles, and final projected variables.
- **OVERVIEW** — a four-way ASM / READ.PY / C / EXEC.PY evidence matrix.
- **Live naming overlays** — switch between SSA, PAL, and Humanized labels with optional operator aliases.
- **Fault localization** — expose reconstruction defects without executing the target, including missing predicates behind malformed structures such as an unbreakable `while True:` loop.

## Preview status

neptune has been exercised against the current PAL repository and newly generated function data with no known crash during human testing. It is already usable as a multifunction Python state-machine generation, provenance, and audit viewer, but remains pre-alpha while search/highlight behavior and semantic-lifting edge cases continue to mature.

The interface follows frozen addresses, CFG relationships, SSA/PHI custody, and PAL's projected structure. It is a **static semantic debugger**, not a runtime debugger.

## Quick start

From the repository root:

```bash
python neptune/PALTermUI_neptune.py
```

Or from inside the `neptune` directory:

```bash
python PALTermUI_neptune.py
```

An explicit PAL root, project directory, function manifest, or detached Icecube snapshot may also be supplied:

```bash
python PALTermUI_neptune.py /path/to/source
```

## Core investigation flow

```text
Python search hotspot
    -> owning ASM block
    -> implicated PHI authority
    -> selected branch or fallthrough
    -> synchronized Python and PHI context
    -> replayable static history
```

For the complete interface manual, key bindings, pane semantics, and audit recipes, see [`README(neptune).md`](./README(neptune).md).
