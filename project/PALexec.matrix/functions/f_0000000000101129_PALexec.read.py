# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::PALexec
# Entry address: 0x101129

#======= PAL stack versioning ======
# PALStaticStringPublisher = static_strings_v1_defined_ghidra_data
# PALBatchDecompiler = batch_v2h_final_abi_authority_publication
# PALHumanizer = humanizer_v2_oncs_varnames_recovery
# PALDecompilerPipeline = unknown
# PALlibrary.PALLifter = PALlibrary_v23e_clothed_emperor_cfg_truth
# PALlibrary.FunctionCFG = PALlibrary_v23e_clothed_emperor_cfg_truth
# PALSymbolResolver = unknown
# PALRawAudit = unknown
# PALCompute = v23b_abi_thunk_compatibility_return_reconciliation
# PALSemanticGraphBuilder = PALSemanticGraphBuilder_v38_clothed_emperor_edgetruth_tristate_custody
# PALSGLdecomp = unknown
# PALPHIfolder = v23_abi_f_entry_state_convergence_custody
# PALemitter = v60u_mars_exact_inplace_state_write_terminator_v1
# PALCodeDocument = im_d_v1_projection_alias_edit_sidecars
#====================================

# PAL readable projection (non-executable)
# Static C-string call arguments projected from PAL_stdio_strings.json
# Width/sign contracts remain available in PAL provenance metadata

def PALexec(param_0, param_1, param_2):
    local_22 = param_0
    local_21 = param_1
    local_1e = param_0
    local_1c = 0x12345678
    local_18 = 0x80000000
    local_14 = 0
    local_20 = param_2
    while 2 >= local_14:
        if param_0 < param_1 and local_21 < local_22 or param_2 < 0:
            local_1c = (param_1 + (local_1c ^ 0x5f5f5f5f))
            v_4149 = local_18
        else:
            if local_18 == 0:
                v_4149 = param_0
            else:
                v_4149 = (local_18 / param_1)
        local_18 = v_4149
        local_10 = 0
        while True:
            local_10 = (local_10 + 1)
            if not (local_10 < 3):
                break
            local_21 = (local_21 >> 2)
            local_22 = (local_22 >> 2)
            local_20 = (local_20 << 5)
            if local_20 & 61440 == 0:
                continue
            local_1c = (local_1c | (local_21 ^ local_22))
        v_1443 = (local_1c & 3)
        if v_1443 == 2:
            local_18 = (local_18 % (local_1e | 1))
            local_14 = (local_14 + 1)
        else:
            if local_1c & 3 >= 3:
                local_1c = (~local_1c)
                local_14 = (local_14 + 1)
            else:
                if local_1c & 3 == 0:
                    local_1e = (param_2 + local_1e)
                    local_20 = (local_20 ^ 0xaaaa)
                    local_14 = (local_14 + 1)
                else:
                    if local_1c & 3 == 1:
                        local_20 = (local_20 ^ 0xaaaa)
                        local_14 = (local_14 + 1)
                    else:
                        local_1c = (~local_1c)
                        local_14 = (local_14 + 1)
    return ((local_20 | ((local_22 << 0x18) | (local_21 << 0x10))) + (local_18 ^ local_1c))
