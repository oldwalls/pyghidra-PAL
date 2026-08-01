# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::parse_integer
# Entry address: 0x101611

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

def parse_integer(param_0, param_1):
    abi_context = ABI.current('function_entry:1054225')
    local_1c = 0
    local_18 = 1
    local_14 = 0
    local_10 = 0
    while True:
        v_131 = MEM8[(param_0 + local_1c)]
        v_2776 = is_space_char(v_131)
        if not (v_2776 != 0):
            break
        local_1c = (local_1c + 1)
    v_228 = MEM8[(param_0 + local_1c)]
    if v_228 != 45:
        v_1346 = MEM8[(param_0 + local_1c)]
        if v_1346 != 43:
            pass
        else:
            local_1c = (local_1c + 1)
    else:
        local_18 = 0xffffffff
        local_1c = (local_1c + 1)
    while True:
        v_370 = MEM8[(param_0 + local_1c)]
        if not (47 < v_370):
            break
        v_457 = MEM8[(param_0 + local_1c)]
        if v_457 >= 58:
            break
        v_882 = MEM8[(param_0 + local_1c)]
        if 1000000 < local_14:
            return 0
        local_14 = ((v_882 + 0xffffffd0) + (local_14 * 0xa))
        local_10 = (local_10 + 1)
        local_1c = (local_1c + 1)
    while True:
        v_545 = MEM8[(param_0 + local_1c)]
        v_2882 = is_space_char(v_545)
        if not (v_2882 != 0):
            break
        local_1c = (local_1c + 1)
    if local_10 == 0:
        v_2351 = 0
    else:
        v_678 = MEM8[(param_0 + local_1c)]
        if v_678 == 0:
            MEM32[param_1] <- (local_14 * local_18)
            v_2351 = 1
        else:
            v_2351 = 0
    return v_2351
