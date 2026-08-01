# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_route
# Entry address: 0x101d89

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

def command_route(param_0, param_1):
    abi_context = ABI.current('function_entry:1056137')
    v_60 = MEM32[param_0]
    if v_60 == 1:
        v_146 = MEM32[(param_1 + 0x10)]
        if v_146 != 0:
            v_215 = MEM32[(param_1 + 0x14)]
            if v_215 - 1 >= 4:
                record_fault(param_0, 'REJECTED: route must be 1, 2, 3 or 4.')
            else:
                v_296 = MEM32[(param_1 + 0x14)]
                v_311 = (param_0 + (3 * 4))
                MEM32[v_311] <- v_296
                refresh_checksum(param_0)
                v_345 = (param_0 + (3 * 4))
                v_348 = MEM32[v_345]
                printf('Routing channel %d selected.\n', v_348)
                v_381 = (param_0 + (4 * 4))
                v_384 = MEM32[v_381]
                printf('CHECKSUM: 0x%08X\n', v_384)
        else:
            record_fault(param_0, 'REJECTED: route requires an integer value.')
    else:
        record_fault(param_0, 'DENIED: route may be selected only in diagnostic mode.')
    return 0
