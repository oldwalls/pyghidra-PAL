# PAL portable 9-specimen matrix scripts

These scripts contain no workstation-specific PAL root.

Both resolve PAL exclusively as:

```bash
SCRIPT_DIR/../PAL
```

This works when the scripts are placed:

- directly inside the PAL root; or
- in a sibling directory beside `PAL`.

For example:

```text
workspace/
├── PAL/
└── scripts/
    ├── PAL_regen_9_matrix_portable.sh
    └── PAL_publish_9_matrix_portable.sh
```

## Regenerate the matrix

The Ghidra project directory is now an explicit positional parameter:

```bash
./PAL_regen_9_matrix_portable.sh PATH_TO_GHIDRA_PROJECT
```

Optional second argument:

```bash
./PAL_regen_9_matrix_portable.sh     PATH_TO_GHIDRA_PROJECT     GHIDRA_PROJECT_NAME
```

Examples:

```bash
./PAL_regen_9_matrix_portable.sh ../scraps

./PAL_regen_9_matrix_portable.sh     ../scraps     PAL_RELEASE_MATRIX_022
```

The default Ghidra project name is:

```text
PAL_MATRIX_REGEN_<timestamp>
```

## Publish the matrix

```bash
./PAL_publish_9_matrix_portable.sh
```

The publisher derives all paths from `SCRIPT_DIR/../PAL` and calls:

```bash
python PALExecInterface.py   --root <derived-PAL-root>   --project <derived-project-path>   --publish
```

Both scripts log under:

```text
PAL/matrix_logs/
```
