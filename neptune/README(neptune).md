# PALTermUI neptune v0.23r

`PALTermUI_neptune.py` is an opt-in pre-alpha interface for inspecting PAL-generated Python state machines against the machine-code, PHI, naming, ABI, call, and project evidence from which they were reconstructed. Its central instrument is **STATIC DEBUG**, a synchronized PHI–ASM–Python microscope that lets a human begin from a Python symbol or suspicious statement, identify the owning machine block, inspect the variable's PHI custody chain, and then follow real static branch choices through recorded ASM history.

neptune is not a runtime debugger. It is a static reconstruction, provenance, and fault-localization workbench: it follows frozen addresses, CFG relationships, SSA/PHI custody, and PAL's projected Python structure rather than executing the target program.

> The practical workflow is simple: find something suspicious in Python, lock onto its machine truth, inspect its state custody, and walk the possible execution path.

## Preview status

neptune is delivered as `PALTermUI_neptune.py` and does not replace the repository's default `PALTermUI.py`. It has been exercised against the existing PAL repository and against newly generated function data without a known crash during human testing. Search and highlight behavior is usable but still pre-alpha, and the interface may expose semantic-lifting defects that belong to PAL's decompiler pipeline rather than to the UI.

## Launch

Run neptune from a terminal with a sufficiently large VT100/curses window:

```bash
python PALTermUI_neptune.py
```

An optional source may be supplied:

```bash
python PALTermUI_neptune.py /path/to/PAL
python PALTermUI_neptune.py /path/to/project
python PALTermUI_neptune.py /path/to/PAL_function_manifest.json
python PALTermUI_neptune.py /path/to/function.icecube.json.gz
```

Accepted sources are a PAL root, a project directory, a function manifest, or a detached Icecube snapshot. With no source argument, neptune examines the directory containing the script.

Useful startup options:

```bash
python PALTermUI_neptune.py SOURCE --projection readable
python PALTermUI_neptune.py SOURCE --projection executable
python PALTermUI_neptune.py SOURCE --naming ssa
python PALTermUI_neptune.py SOURCE --naming pal
python PALTermUI_neptune.py SOURCE --naming humanizer
python PALTermUI_neptune.py SOURCE --no-verify
```

`--no-verify` skips SHA-256 verification and should only be used when the artifact set is trusted and verification is intentionally unnecessary.

## Human usage flow

### 1. Select a project and function

When launched against a PAL root containing multiple projects, select a project with Up/Down or `j/k`, then press Enter. The function browser supports:

```text
Enter       open function
/           filter function names
Ctrl-X      clear function filter
F2          cycle function naming
Ctrl-O      toggle function operator overlay
F4          rename selected function
F5          revert selected function rename
q           return to project list or exit
```

Functions larger than 175 processed lines may display a loader warning before initialization and before the first OVERVIEW or STATIC DEBUG build:

```text
LARGE FUNCTION METADATA - THIS MIGHT TAKE TIME | LOC=X
```

This is an informational warning, not an error.

### 2. Begin in Python

The root editor is the fastest place to scan READ.PY or EXEC.PY before opening the evidence workbench.

```text
F1 / Tab    switch READ.PY and EXEC.PY
F2          cycle SSA, PAL, and Humanized names
Ctrl-O      toggle operator aliases
/           search code
n / N       next / previous hit
F4          rename an editable variable on the current line
Enter       focus the object under the cursor
M           open the graphic evidence menu
q           return to the function list
```

READ.PY is the human-readable projection and may be explicitly marked non-executable. EXEC.PY is PAL's executable state-machine projection. Both remain linked to the same frozen function evidence.

A productive starting point is any suspicious Python construct, variable, constant, call, or ASCII sequence. Examples include:

```python
while True:
result = local_14 + loop_ctr
local_18 = feedback_result
```

Search for the text, iterate its hotspots, and open the evidence menu with `M`.

### 3. Open STATIC DEBUG

From the graphic menu, select **STATIC DEBUG** with Up/Down and press Enter. The view contains:

```text
PHI custody  |  ASM containment/path truth  |  READ.PY or EXEC.PY context
```

Use Tab and Shift-Tab to move between panes. Local arrow movement does not automatically rewrite the other panes; Enter commits the selected hotspot or branch focus and refreshes the synchronized view.

A common investigation starts in the Python pane:

1. Press `/` and enter a variable or code fragment.
2. Use `n/N` to iterate every occurrence.
3. Observe the PHI pane retarget to the implicated state authority.
4. Observe the ASM pane lock to the statement's owning machine block.
5. Press Tab to enter ASM when a branch or continuation needs inspection.
6. Press Enter on a jump to follow the chosen machine path.

This produces a static step-debug workflow:

```text
Python hotspot
    -> owning ASM block
    -> implicated PHI authority
    -> selected branch target
    -> refreshed Python and PHI context
```

## STATIC DEBUG panes

### PHI pane

The PHI pane describes how a projected variable acquires its value across alternative predecessors, joins, and loop-carried state.

A compact authority row follows this model:

```text
#5 result <= [v_1555 + v_1554 + v_1554]
```

The node number identifies the displayed PHI authority. The result name and all contributing names are rendered through the current naming state:

```text
SSA | PAL | Humanized  + optional Operator overlay
```

The selected custody blade may contain:

```text
<address>  value arrives
<address>  PHI merges source into result
<address>  PHI custody cycles back through result
----------> Final State: result
```

PHI nodes are SSA/CFG abstractions; they are not literal machine instructions. Their incoming records identify the predecessor-edge value transfers from which PAL may generate Python drop-ins such as:

```python
result = source_value
```

Statement-level focus prefers the selected Python assignment's destination authority. This prevents unrelated PHI nodes from appearing merely because they share a nearby block.

The pane is therefore useful for answering:

- Which SSA values can become this Python variable?
- Which block delivered each value?
- Where did a branch-exit or loop-carried drop-in originate?
- Is the same variable identity preserved across a cycle?
- Did a rename remain consistent through every custody label?

### ASM pane

The ASM pane presents frozen machine-code evidence around the current focus.

Color conventions include:

- orange: conditional and unconditional jumps;
- violet: `CMP`, `TEST`, and compare-family instructions;
- yellow: block headers;
- cyan: instruction addresses.

Press Enter on a resolved jump to follow it. Conditional branches display a bounded fork reconstruction containing the source, taken path, fallthrough path, and nearest completion/join when available:

```text
BRANCH SOURCE
FORK [TAKEN]
FORK [FALLTHROUGH]
FORK COMPLETION / JOIN
```

When a non-terminal block has no explicit outgoing jump, neptune may append the next-address block beneath it as:

```text
AUTO-SEQUENTIAL FALLTHROUGH -> BLOCK 0x...
```

This is UI continuation context only. It does not create or modify a frozen CFG edge. Explicit jumps and returns do not receive a false sequential continuation.

A one-operation block may also be shown with directly connected predecessor/current/successor context so that an otherwise isolated state operation remains intelligible.

### Python pane

The Python pane displays the READ.PY or EXEC.PY region linked to the selected block and PHI state. Search can begin here and drive the other two panes.

This is particularly effective for defect localization. A generated construct such as:

```python
while True:
    state += 1
```

may appear structurally unbreakable. STATIC DEBUG can reveal a nearby machine `TEST`/`JNZ` pair that PAL failed to lift as the loop predicate. The UI does not repair the decompilation; it identifies the exact machine and state evidence needed to correct the pipeline.

## Static ASM history

Every followed ASM jump records a human navigation frame. The status bar reports the current position:

```text
ASM-HIST=2/6
```

Controls:

```text
<           load the earlier frame
>           load the forward frame
Enter       follow the selected jump and append a frame
```

History replay refreshes the linked PHI, ASM, and Python context. When the user moves backward and selects a different jump, the obsolete forward branch is discarded and a new inspection path is recorded. This behaves like branchable browser history for static control flow.

History is intentionally cleared when ASM focus is regained, providing a fresh walkthrough slate for the new investigation.

## Search and highlight

Search belongs to the active pane.

```text
/           set or replace the search term
n / N       next / previous match
H           toggle visual search painting
blank /     clear search and highlight mode
```

`H=OFF` removes painted highlights immediately but preserves the stored query, so `n/N` can continue moving through its matches. `H=ON` restores painting. When highlight traversal is active, directional movement may advance through matches rather than ordinary rows; turn `H` off to browse the pane normally without losing the query.

A strong practical workflow is to search an ASCII sequence or variable in Python, iterate all hotspots, and let STATIC DEBUG continuously retarget the machine and PHI evidence.

## FULL and focused views

`F` is a reversible content switch for focused ASM and PHI surfaces:

```text
first F     show the complete unfiltered listing
second F    restore the exact previous focused state
```

FULL remains active while browsing, searching, changing projection, or changing naming. Only `F` restores the saved focus. The status bar reports `FULL=ON` or `FULL=OFF`.

`C` is broader: it clears filters, highlights, branch focus, and linked focus, then restores the captured initial view.

## Naming and renaming

neptune separates canonical identity from presentation:

```text
canonical SSA identity
    -> selected base naming: SSA / PAL / Humanized
    -> optional Operator alias overlay
    -> rendered UI label
```

Controls:

```text
F2          cycle SSA / PAL / Humanized base names
Ctrl-O      toggle Operator aliases
F4          rename an editable variable
```

In READ.PY or EXEC.PY, F4 discovers editable variables on the current line, excludes protected identities, presents a selectable variable list when necessary, and then opens the rename prompt.

Stack locals such as `local_14` are operator-renamable. Protected ABI, variadic, stack/frame-pointer, return-address, physical pointer-carrier, function target, and other system identities remain locked. F4 changes the ONCS presentation alias; it does not rewrite canonical SSA, ABI custody, or frozen provenance metadata.

Use `: save` in the workbench or Ctrl-S in the root editor to persist current naming changes through the catalog's save path.

## OVERVIEW

**OVERVIEW** provides the broad four-way evidence matrix:

```text
ASM | READ.PY | C | EXEC.PY
```

Use it when the investigation requires side-by-side comparison of original Ghidra C, both PAL Python projections, and assembly. Tab switches the active pane. Python movement refreshes linked ASM allegiance; the C pane remains frozen evidence and does not claim Python ownership.

STATIC DEBUG is narrower and state-centric. OVERVIEW is broader and artifact-centric.

## Other views

The graphic menu also exposes:

- **DETAIL** — one row per variable with SSA, PAL, Humanized, Operator, PHI Detail, and STATIC DEBUG destinations;
- **ASM** — standalone frozen assembly evidence and jump navigation;
- **C** — frozen Ghidra C evidence;
- **PHI** — all singular PHI custody records;
- **CALLS** — module/function call relationships;
- **ABI** — ABI custody interfaces and protected carriers;
- **PROJECT METADATA** — unified project and artifact digest.

Use `M` or Esc to return one level from a view to the graphic menu. The selected menu item is retained.

## Status bar

The footer is part of the operating instrument. Typical fields include:

```text
active=ASM
PY=READ or PY=EXEC
NAMES=SSA / PAL / HUMANIZED
OPER=ON/OFF
FIND=/term
H=ON/OFF
FULL=ON/OFF
ASM-HIST=current/total
focus/status message
```

Read the status bar before interpreting a pane. It tells whether the visible names include operator aliases, whether highlights are merely hidden, whether a complete listing is active, and where the current ASM walkthrough stands.

## PAL command line

Press `:` to open `PAL CMD>` directly beneath the graphic menu and key rows. Supported commands are:

```text
rename NEW_NAME
revert
find TEXT
full
clear
save
export PATH
view
names
operator
help
```

The command line is an alternate control path for operations already available through keys and for explicit save/export actions.

## Recommended audit recipes

### Find a missing loop condition

1. Search Python for `while True`.
2. Iterate occurrences with `n/N`.
3. Open STATIC DEBUG and inspect the owning block.
4. Look for violet `CMP`/`TEST` followed by an orange backward jump.
5. Follow the branch with Enter and inspect both forks.
6. Record the machine predicate, polarity, target, fallthrough, and implicated PHI state for the pipeline correction.

### Trace a suspicious assignment

1. Search for the destination variable or assignment text.
2. Confirm that the PHI pane selects the destination authority rather than neighboring block merges.
3. Inspect incoming-value and merge addresses.
4. Enter ASM and follow the relevant predecessor or branch.
5. Use `<`/`>` to compare earlier and later path frames.
6. Toggle F2 and Ctrl-O to verify naming consistency across all three panes.

### Audit a rename

1. Place the Python cursor on the line containing the variable.
2. Press F4 and choose the editable identity.
3. Apply an operator alias.
4. Move through Python hotspots, ASM history, and PHI records.
5. Confirm that no old `local_<n>` spelling leaks back after refresh.
6. Save the ONCS state.

## Interpretation boundaries

neptune displays a static family of possible paths, not one observed runtime trace. Conditional forks may be mutually exclusive, PHI cycles may represent different loop iterations, and auto-sequential fallthrough is explicitly a UI continuation when it is not frozen as a CFG edge.

The instrument should be read as:

> These machine blocks, state merges, and projected Python statements are linked by PAL's frozen reconstruction evidence.

It should not be read as:

> Every displayed block executed consecutively for one concrete input.

That distinction preserves machine truth while still giving the user a debugger-like way to inspect the genesis, generation, and audit trail of a Python state machine.
