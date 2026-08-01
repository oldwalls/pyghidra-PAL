# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::copy_token
# Entry address: 0x10159d

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

def copy_token(param_0, param_1, param_2, param_3):
    local_c = param_3
    if param_1 > param_3:
        pass
    else:
        local_c = (param_1 + 0xffffffff)
    local_10 = 0
    while local_10 < local_c:
        v_373 = MEM8[(param_2 + local_10)]
        MEM8[(param_0 + local_10)] <- v_373
        local_10 = (local_10 + 1)
        v_373 = MEM8[(param_2 + local_10)]
        MEM8[(param_0 + local_10)] <- v_373
        local_10 = (local_10 + 1)
    MEM8[(param_0 + local_c)] <- 0
    return 0
