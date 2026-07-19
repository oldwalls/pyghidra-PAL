# PAL User Manual — Pre-Alpha Workflow

PAL is an execution-oriented binary reconstruction and forensic comparison layer built on Ghidra/PyGhidra.

Current demonstrated path:

```text
ELF executable
→ Ghidra analysis
→ PAL batch reconstruction
→ Icecube function project
→ READ.PY / EXEC.PY
→ four-way forensic analysis
→ published Python state machine
→ native-result comparison
```

PAL has demonstrated executable-to-Python state-machine recovery across a limited eight-case regression corpus. This is a proof of concept, not general binary compatibility.

---

## 1. PAL repository layout

Default development root:

```text
~/gh/PAL/
```

Important entry points:

```text
crystal_batch.py       PyGhidra batch entry
PALTermUI.py           project/function analysis and ONCS naming
PALExecInterface.py    publish and run reconstructed state machines
```

Generated PAL projects live under:

```text
~/gh/PAL/project/<program-name>/
```

Typical project tree:

```text
project/<program-name>/
├── PAL_function_manifest.json
├── PAL_jump_table.json
├── PAL_dispatch.py
├── PAL_ONCS.json
└── functions/
    ├── f_<address>_<name>.icecube.json.gz
    ├── f_<address>_<name>.read.py
    └── f_<address>_<name>.exec.py
```

The Icecube is the frozen evidence object. It preserves the function projections and metadata required to correlate executable Python, readable Python, Ghidra C, assembly, variables, statements, blocks, calls and ABI state.

---

## 2. Ghidra and PyGhidra intake

### Prepare the binary

1. Create or open a Ghidra project.
2. Import the ELF executable.
3. Run Ghidra analysis.
4. Confirm the expected functions appear in the Symbol Tree and Decompiler.
5. Save the Ghidra project.

### Run PAL batch reconstruction

`crystal_batch.py` requires a live Ghidra `Program` supplied through PyGhidra. It is not a standalone raw-ELF parser.

From the PAL root, launch the analyzed project/program using the PyGhidra command established for the local installation:

```bash
cd ~/gh/PAL

<PYGHIDRA_PROJECT_COMMAND> crystal_batch.py
```

The batch process runs the PAL decompiler pipeline independently over discovered internal functions and writes the project under:

```text
~/gh/PAL/project/<program-name>/
```

Expected terminal summary includes discovered, decompiled and failed function counts.

### Confirm the export

```bash
ls ~/gh/PAL/project/<program-name>/
ls ~/gh/PAL/project/<program-name>/functions/
```

The minimum usable project contains:

```text
PAL_function_manifest.json
PAL_ONCS.json
functions/*.icecube.json.gz
functions/*.read.py
functions/*.exec.py
```

Do not manually edit an Icecube. It is the frozen evidence authority.

---

## 3. Open PALTermUI

From the PAL root:

```bash
cd ~/gh/PAL
python PALTermUI.py
```

PALTermUI may also open a specific project, manifest or detached Icecube:

```bash
python PALTermUI.py project/<program-name>
python PALTermUI.py project/<program-name>/PAL_function_manifest.json
python PALTermUI.py project/<program-name>/functions/<function>.icecube.json.gz
```

The status/footer shown by the running build is the final key authority.

---

## 4. Project and function selection

The first view lists PAL projects. Open a project to reach its function list.

Basic navigation:

```text
Up/Down or j/k     move selection
Enter              open selected project/function
/                  filter function names by keyword
Ctrl-X             clear the function filter
g / G              first / last entry
PageUp/PageDown    move by page
q                  return or quit
```

The function browser initially shows SSA-oriented function identity. Naming overlays do not mutate the physical function identity.

---

## 5. Single-function view

The single-function editor is the detailed READ/EXEC inspection and naming view.

Core controls:

```text
F1                 switch READ.PY / EXEC.PY projection
F2                 cycle base naming: SSA / PAL / Humanized
Ctrl-O             operator-name overlay on/off
F3                 truth/provenance digest
F4                 rename the object under the cursor
F5                 revert the selected edit
F6                 export current projection
Ctrl-S             save ONCS naming state
F9                 open four-pane analysis view
Enter              set or clear object-context highlighting
Arrow keys         move the code cursor
PageUp/PageDown    scroll vertically
Home/End           line boundaries
q                  return to the function list
```

### Naming model

PAL separates immutable machine identity from display names:

```text
SSA          native reconstructed identity
PAL          PAL structural/local naming
Humanized    generated cognitive naming
Operator     user-edited overlay
```

Operator names inherit the currently selected base mode and persist in:

```text
PAL_ONCS.json
```

Renaming changes the displayed projection; it does not rewrite the Icecube or machine identity.

---

## 6. Four-pane analysis view

Press `F9` from a function to open the linked truth view:

```text
┌──────────────────────────┬──────────────────────────┐
│ ASM / machine truth      │ READ.PY                  │
├──────────────────────────┼──────────────────────────┤
│ Ghidra C                 │ EXEC.PY                  │
└──────────────────────────┴──────────────────────────┘
```

Pane roles:

```text
ASM
    physical machine operations for the linked Icecube region

Ghidra C
    Ghidra's independent source-level reconstruction

READ.PY
    PAL's human-oriented semantic projection

EXEC.PY
    PAL's execution-oriented state-machine projection
```

Core controls:

```text
F8                 cycle active pane
F9 / Esc / q       return to the single-function view
Tab                next Icecube metadata hotspot
Ctrl-Tab           previous hotspot
Enter              set, replace or clear object-context highlighting
F4                 rename the active tagged object
Arrow keys         move cursor; READ/EXEC positions remain linked
j / k              horizontal pane scrolling
PageUp/PageDown    vertical pane scrolling
```

READ.PY and EXEC.PY are linked by shared Icecube statement/object metadata.

Ghidra C has no exact statement identity contract, so its position is soft-synchronized by approximate document percentage.

ASM remains anchored to the relevant Icecube machine-evidence region.

### Recommended analysis method

For a suspicious line:

1. Select the line in READ.PY or EXEC.PY.
2. Inspect the linked line in the other Python pane.
3. Inspect the corresponding assembly block.
4. Compare Ghidra C.
5. Use `Enter` to highlight the same tagged object across READ and EXEC.
6. Use `F3` or the single-function metadata view when deeper provenance is needed.

This identifies likely layer ownership:

```text
ASM vs EXEC.PY
    execution reconstruction, ABI, memory or emitter issue

EXEC.PY vs READ.PY
    semantic projection, identity or humanization issue

ASM vs Ghidra C
    decompiler interpretation issue

Both Python panes wrong
    likely upstream lifting, CFG, variable or PHI issue
```

---

## 7. Publish a project for execution

Run the execution interface from the PAL root:

```bash
cd ~/gh/PAL
python PALExecInterface.py
```

Choose a project, then:

```text
P    PUBLISH FOR EXEC
R    RUN PUBLISHED STATE MACHINE
B    PUBLISH AND RUN
C    choose another project
Q    quit
```

Publishing creates:

```text
project/<program-name>/execute/
├── state_machine.py
├── PAL_runner.py
├── PAL_project_runtime.py
├── PAL_abi_plans.json
├── config.exec.json
├── functions/
├── icecubes/
├── runtime/
└── shims/
```

Publication is detached from the analysis tree. Re-publish after changing:

```text
PALExecInterface.py
runtime support
ABI plans
*.exec.py
project execution metadata
```

---

## 8. Run a published state machine

The interface lists published functions and their execution mode:

```text
abi_context
legacy_direct
```

Select a function by number or name, then provide:

```text
fixed arguments
variadic arguments
```

Typical successful run:

```text
RUN: function:0x...
PAL EXEC BUILD: pal_exec_interface_v1f_dispatch_namespace_separation
PAL RESULT: <value>
PAL runner exit status: 0
```

`main()` functions with no parameters ignore supplied fixed arguments when their initial state is encoded internally.

To test state reshaping, edit the relevant published source input before re-publication, for example:

```text
project/<program-name>/functions/<main>.exec.py
```

Then publish again and run.

### Shim behavior

PAL currently models a limited external boundary.

Print-family calls are trapped into Python output:

```text
printf
fprintf
puts
fputs
putchar
checked print variants
```

Unknown external calls fail closed with:

```text
PALUnimplementedShim
```

A closed unresolved shim listed during publication is acceptable until execution reaches it.

Unresolved static C strings may print as:

```text
<cstr@0x...>
```

The argument values may still be correct even when the initialized data image has not been published.

---

## 9. Native convergence testing

For each specimen, record:

```text
native stdout
native return/result
PAL stdout
PAL result
PAL runner status
```

A passing proof case requires matching observable behavior for the exercised path.

PAL's present claim is limited:

> PAL has demonstrated executable-to-Python state-machine recovery with behavioral convergence across a controlled eight-case corpus.

It does not yet claim arbitrary executable support.

---

## 10. Codium and debugpy

### Create the debugger environment

```bash
conda create -n pal-debug python=3.12 pip -y
conda run -n pal-debug python -m pip install --upgrade debugpy
```

### Populate PAL Codium settings

From the PAL root, run the provided settings script:

```bash
chmod +x populate_pal_vscode_settings_pal_debug.sh
./populate_pal_vscode_settings_pal_debug.sh
```

It creates:

```text
project/<specimen>/execute/.vscode/settings.json
```

and exposes these import roots:

```text
execute/
execute/runtime/
execute/shims/
execute/functions/
```

### Open a published project

```bash
cd ~/gh/PAL/project/<program-name>/execute
codium .
```

Confirm the selected interpreter is:

```text
~/miniconda/envs/pal-debug/bin/python
```

In a new Codium terminal:

```bash
python -c "import sys; print(sys.executable)"
python -c "import PALABI, PALhelpers; print(PALABI.__file__); print(PALhelpers.__file__)"
```

The PAL imports should resolve from:

```text
execute/runtime/
```

### Minimal debug configuration

Create:

```text
execute/.vscode/launch.json
```

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "PAL: Debug published function",
            "type": "debugpy",
            "request": "launch",
            "python": "/home/rem/miniconda/envs/pal-debug/bin/python",
            "pythonArgs": [
                "-Xfrozen_modules=off"
            ],
            "program": "${workspaceFolder}/PAL_runner.py",
            "cwd": "${workspaceFolder}",
            "args": [
                "--function",
                "main"
            ],
            "env": {
                "PYTHONPATH": "${workspaceFolder}/runtime:${workspaceFolder}/shims:${workspaceFolder}/functions:${workspaceFolder}"
            },
            "console": "integratedTerminal",
            "justMyCode": false,
            "stopOnEntry": false
        }
    ]
}
```

Debug through:

```text
PAL_runner.py
```

Do not launch a generated function module directly. `PAL_runner.py` constructs shared memory, ABI context, call plans, internal dispatch and shims before entering recovered code.

Set breakpoints inside:

```text
functions/f_<address>_<name>.py
runtime/PALABI.py
runtime/PALhelpers.py
PAL_project_runtime.py
```

Press `F5` in Codium to begin.

---

## 11. Operational flow summary

```text
1. Import ELF into Ghidra
2. Analyze and save the Ghidra project
3. Run crystal_batch.py through PyGhidra
4. Confirm project/<program>/ manifest, ONCS and function artifacts
5. Open PALTermUI.py
6. Inspect functions in single view
7. Use F9 four-pane view for cross-truth analysis
8. Rename tagged objects through ONCS when useful
9. Run PALExecInterface.py
10. Publish the project for execution
11. Run selected functions and compare against native output
12. Open execute/ in Codium for standard Python debugging
```

---

## 12. Current boundaries

PAL is still pre-alpha.

Expect failures around:

```text
unmodeled external functions
initialized static-data publication
indirect calls and jumps
complex pointer ownership
threads and synchronization
exceptions and signals
system calls
unsupported ABI patterns
large optimized programs
```

Failures should be treated as evidence. Use the Icecube, four-pane view and published runtime to assign the defect to the responsible PAL layer before patching.
