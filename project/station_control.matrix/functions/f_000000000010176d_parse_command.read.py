# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::parse_command
# Entry address: 0x10176d

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

def parse_command(param_0, param_1):
    abi_context = ABI.current('function_entry:1054573')
    local_14 = 0
    MEM8[param_1] <- 0
    v_81 = (param_1 + (0x10 * 1))
    MEM32[v_81] <- 0
    v_97 = (param_1 + (0x14 * 1))
    MEM32[v_97] <- 0
    while True:
        v_152 = MEM8[(param_0 + local_14)]
        v_2071 = is_space_char(v_152)
        if not (v_2071 != 0):
            break
        local_14 = (local_14 + 1)
    v_2550 = local_14
    while True:
        v_268 = MEM8[(param_0 + local_14)]
        if not (v_268 != 0):
            break
        v_347 = MEM8[(param_0 + local_14)]
        v_2098 = is_space_char(v_347)
        if v_2098 != 0:
            break
        local_14 = (local_14 + 1)
    v_424 = (local_14 - v_2550)
    if v_424 >= 1:
        copy_token(param_1, 0x10, (v_2550 + param_0), v_424)
        while True:
            v_627 = MEM8[(param_0 + local_14)]
            v_2139 = is_space_char(v_627)
            if not (v_2139 != 0):
                break
            local_14 = (local_14 + 1)
        v_724 = MEM8[(param_0 + local_14)]
        if v_724 == 0:
            v_1522 = 1
            return v_1522
        else:
            v_765 = (param_1 + (0x14 * 1))
            v_2155 = parse_integer((param_0 + local_14), v_765)
            if v_2155 != 0:
                v_867 = (param_1 + (0x10 * 1))
                MEM32[v_867] <- 1
                v_1522 = 1
            else:
                return 0xffffffff
    else:
        v_1522 = 0
    return v_1522
    return v_1522
