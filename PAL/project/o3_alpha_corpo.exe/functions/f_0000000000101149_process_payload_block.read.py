# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::process_payload_block
# Entry address: 0x101149

#======= PAL stack versioning ======
# PALStaticStringPublisher = static_strings_v1_defined_ghidra_data
# PALBatchDecompiler = batch_v2d_explicit_stdio_overlay_authority
# PALHumanizer = humanizer_v2_oncs_varnames_recovery
# PALDecompilerPipeline = unknown
# PALlibrary.PALLifter = unknown
# PALlibrary.FunctionCFG = unknown
# PALSymbolResolver = unknown
# PALRawAudit = unknown
# PALCompute = v23b_abi_thunk_compatibility_return_reconciliation
# PALSemanticGraphBuilder = unknown
# PALSGLdecomp = unknown
# PALPHIfolder = v23_abi_f_entry_state_convergence_custody
# PALemitter = v46p_immutable_abi_context_continuity
# PALCodeDocument = im_d_v1_projection_alias_edit_sidecars
#====================================

# PAL readable projection (non-executable)
# Static C-string call arguments projected from PAL_stdio_strings.json
# Width/sign contracts remain available in PAL provenance metadata

def process_payload_block(param_0, param_1, param_2):
    local_10 = 0
    if param_1 == 0:
        v_1554 = 0
    else:
        if param_2 >= 1:
            local_14 = param_0
            local_c = 0
            local_14 = param_0
            while local_c < param_2:
                v_416 = MEM8[(param_1 + local_c)]
                v_479 = ((v_416 ^ local_14) + 0x1f)
                local_14 = ((v_479 * 8) | (v_479 >> 0x1d))
                if v_416 & 1 != 0:
                    local_10 = (local_10 ^ 0x55)
                    local_c = (local_c + 1)
                else:
                    local_10 = (local_10 + 1)
                    local_c = (local_c + 1)
            if local_10 < 11:
                v_1554 = (local_14 + local_10)
            else:
                v_1554 = (local_14 ^ 0xa5a5a5a5)
        else:
            v_1554 = 0
    return v_1554
