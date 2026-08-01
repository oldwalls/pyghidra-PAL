<img width="786" height="856" alt="image" src="https://github.com/user-attachments/assets/9d7f57eb-da05-430e-b0aa-8aef3873c03a" />


# PAL Boundary Testing & Experimentation

PAL project suffixes are human-readable experiment classes, not different binary formats:

- **`<binary>.matrix`** — a controlled regression specimen expected to remain stable across releases.
- **`seq.frontier`** — a real or unfamiliar program used to push beyond the proven corpus and reveal the next missing capability.
- **`alpha_SGL_trap.test`** — a small synthetic specimen designed to isolate one structural, CFG, PHI, ABI, or emitter trap.
- **`<compiled-c>.ourtest`** — a contributor-owned boundary experiment. Compile the C program first, then give the resulting binary the `.ourtest` suffix, for example `branch_probe.ourtest`.

## Run an `.ourtest` target through PAL

Run the extension-driven autopipeline with the **`ourtest` filter parameter**.

The parameter acts as a filtered-import selector. The autopipeline scans the PAL specimen directory, selects only binaries ending in `.ourtest`, and leaves `.matrix`, `.frontier`, `.test`, and unrelated executables out of that run. Each selected target is then imported through PyGhidra, passed through the normal PAL decompile and publication pipeline, audited, and recorded in the run reports.

The published project appears beneath:

```text
project/<compiled-c>.ourtest/
```

The filter selects an experiment class; it is not a specimen-specific heuristic and does not alter PAL analysis behavior.

## Find the BUG MATRIX

Every filtered run receives an archived directory beneath:

```text
log_matrix/run_<timestamp>_<pid>/
```

Per-specimen failures are collected beneath:

```text
log_matrix/run_<timestamp>_<pid>/failed_reports/**/REPORT.md
```

The generated `Bug_Matrix_report_<timestamp>.md` is the convergence view. It reduces raw failures into unique binaries, exact occurrence clusters, runtime families, affected module/error keys, and likely patch owners.

## Teaching PAL a generalized heuristic

1. Reduce the failure to the smallest honest specimen.
2. Identify the invariant in CFG, p-code, storage, PHI, ABI, or occurrence evidence.
3. Patch the owning layer with explicit gates, receipts, and fail-closed diagnostics.
4. Never key behavior to a filename, function name, fixed address, or the `.ourtest` suffix.
5. Add the minimized trap to regression coverage, rerun the matrix, publish, audit, and execute.

A useful heuristic explains a class of binaries. A specimen-specific exception merely hides the next failure.

**Wishes of PASS.**
