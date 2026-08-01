# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::text_equal
# Entry address: 0x1014f7

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

def text_equal(param_0, param_1):
    local_c = 0
    while True:
        v_81 = MEM8[(param_0 + local_c)]
        if not (v_81 != 0):
            break
        v_160 = MEM8[(param_1 + local_c)]
        if v_160 == 0:
            break
        v_425 = MEM8[(param_0 + local_c)]
        v_478 = MEM8[(param_1 + local_c)]
        if v_425 != v_478:
            return 0
        local_c = (local_c + 1)
    v_241 = MEM8[(param_0 + local_c)]
    if v_241 != 0:
        v_842 = 0
    else:
        v_322 = MEM8[(param_1 + local_c)]
        if v_322 != 0:
            v_842 = 0
        else:
            v_842 = 1
    return v_842
