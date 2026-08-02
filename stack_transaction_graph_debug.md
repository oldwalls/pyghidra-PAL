# PAL 3-Layer Transaction Graph (SGL → PHI → EMIT)

> Derived from Bug_Matrix_report 2026-07-28 (all families subsequently closed for mars alpha).  
> Focus: custody hand-off points that produced the dominant failure modes.

## Primary Transaction Graph

```mermaid
%%{init: {'themeVariables': { 'fontSize': '12px'}}}%%
flowchart TD
    %% ========== LAYERS ==========
    subgraph SGL["SGL Layer<br/>(PALSGLdecomp + EdgeTruth)"]
        SGL_IN["Machine / HighFunction<br/>edge evidence"]
        ET["EdgeTruth<br/>condition polarity<br/>+ target/fallthrough"]
        SGL_GATE["SGL:_gate_condition_custody_vNN"]
        SGL_DEC["SGL:_decision_condition_polarity_vNN"]
        SGL_IN --> ET --> SGL_GATE --> SGL_DEC
    end

    subgraph PHI["PHI Layer<br/>(PALPHIfolder)"]
        PHI_IN["Incoming structural<br/>+ EdgeTruth decisions"]
        PHI_LEDGER["Authorized Placement Ledger<br/>(transition_id + placement_id)"]
        PHI_GATE["PHI:_gate_occurrence_disposition_vNN"]
        PHI_DEC["PHI:_decision_edge_assignment_vNN<br/>or already_committed"]
        PHI_IN --> PHI_LEDGER --> PHI_GATE --> PHI_DEC
    end

    subgraph EMIT["EMIT Layer<br/>(PALemitter)"]
        EMIT_IN["PHI disposition receipts"]
        EMIT_COMMIT["Assignment Commit<br/>+ terminal receipt"]
        EMIT_GATE["EMIT:_gate_placement_commit_vNN"]
        EMIT_DEC["EMIT:_decision_rendered_line_vNN<br/>or reject_duplicate"]
        EMIT_IN --> EMIT_COMMIT --> EMIT_GATE --> EMIT_DEC
    end

    %% ========== CROSS-LAYER TRANSACTIONS ==========
    SGL_DEC -->|"B.SGL:_decision_condition_polarity_vNN"| PHI_IN
    PHI_DEC -->|"B.PHI:_decision_edge_assignment_vNN<br/>(authorized placement)"| EMIT_IN

    %% ========== FAILURE HOTSPOTS (from matrix) ==========
    SGL_GATE -.->|"FAM-SGL-CONDITION-CUSTODY<br/>priority 4"| SGL_FAIL["Missing / ambiguous<br/>condition polarity"]
    PHI_GATE -.->|"same_authorized_placement<br/>_committed_twice"| PHI_FAIL["Double disposition<br/>for same key"]
    EMIT_GATE -.->|"FAM-PALEMITTER-*<br/>(esp. 88841BC794 _init)"| EMIT_FAIL["Re-attempt of already<br/>terminal placement"]

    %% ========== STYLE ==========
    classDef layer fill:#1e293b,stroke:#64748b,color:#e2e8f0
    classDef gate fill:#7f1d1d,stroke:#f87171,color:#fecaca
    classDef decision fill:#14532d,stroke:#4ade80,color:#bbf7d0
    classDef fail fill:#450a0a,stroke:#f87171,color:#fecaca,stroke-dasharray: 5 5

    class SGL,PHI,EMIT layer
    class SGL_GATE,PHI_GATE,EMIT_GATE gate
    class SGL_DEC,PHI_DEC,EMIT_DEC decision
    class SGL_FAIL,PHI_FAIL,EMIT_FAIL fail
```

## Detailed Occurrence-Disposition Sub-Graph (PHI ↔ EMIT)

This is the most frequent failure pattern in the matrix (`same_authorized_placement_committed_twice`).

```mermaid
sequenceDiagram
    participant SGL as SGL / EdgeTruth
    participant PHI as PALPHIfolder
    participant LEDGER as Placement Ledger
    participant EMIT as PALemitter

    SGL->>PHI: decision_condition_polarity + CFG edge
    PHI->>LEDGER: authorize placement<br/>(transition_id, placement_id)
    LEDGER-->>PHI: authorized = true

    PHI->>EMIT: disposition receipt<br/>(edge_assignment_required)
    EMIT->>EMIT: render assignment line
    EMIT->>LEDGER: commit terminal receipt

    Note over PHI,EMIT: Second path / re-entrant occurrence<br/>reaches same placement key

    PHI->>EMIT: second disposition attempt<br/>(same terminal_disposition_key)
    EMIT--xLEDGER: REJECT<br/>same_authorized_placement_committed_twice
    EMIT-->>PHI: RuntimeError (FAM-PALEMITTER-*)
```

## Contract Normalization Points (patch targets)

| Layer | Gate | Expected Decision | Failure Mode in Matrix | Normalization Goal |
|-------|------|-------------------|------------------------|--------------------|
| **SGL** | `_gate_condition_custody` | `_decision_condition_polarity` | Missing / ambiguous polarity (FAM-SGL-CONDITION-CUSTODY) | Always emit explicit polarity or explicit unresolved |
| **PHI** | `_gate_occurrence_disposition` | `_decision_edge_assignment` **or** `already_committed` | Double commit of same key | Ledger is strictly once-per-key; second attempt returns `already_committed` |
| **EMIT** | `_gate_placement_commit` | `_decision_rendered_line` **or** `reject_duplicate` | Re-attempt after terminal receipt | Treat terminal PHI receipt as authoritative; never re-render same key |

## Recommended Execution Order (from matrix priority)

```mermaid
flowchart LR
    A["1. SGL<br/>EdgeTruth condition custody<br/>(priority 4)"] --> B["2. PHI<br/>occurrence-disposition ledger<br/>(once-per-key)"]
    B --> C["3. EMIT<br/>terminal-receipt authority<br/>(esp. _init cluster)"]
    C --> D["4. Re-run full matrix<br/>validate zero residual"]
```

---

*Graph generated from Bug_Matrix_report_2026-07-28 analysis.*  
*All families shown were closed prior to mars alpha; this diagram captures the historical transaction structure that produced them.*
