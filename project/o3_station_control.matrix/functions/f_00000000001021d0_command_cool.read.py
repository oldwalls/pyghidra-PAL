# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_cool
# Entry address: 0x1021d0

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

def command_cool(param_0):
    abi_context = ABI.current('function_entry:1057232')
    v_52 = MEM32[param_0]
    if v_52 == 2:
        v_135 = (param_0 + (2 * 4))
        v_138 = MEM32[v_135]
        v_161 = (param_0 + (3 * 4))
        v_164 = MEM32[v_161]
        v_215 = (param_0 + (7 * 4))
        v_218 = MEM32[v_215]
        v_437 = (param_0 + (2 * 4))
        v_440 = MEM32[v_437]
        v_499 = (param_0 + (2 * 4))
        MEM32[v_499] <- (v_440 - ((v_218 / 2) + ((v_164 + 6) * 4)))
        v_515 = (param_0 + (2 * 4))
        v_518 = MEM32[v_515]
        if v_518 >= 0:
            pass
        else:
            v_561 = (param_0 + (2 * 4))
            MEM32[v_561] <- 0
        refresh_checksum(param_0)
        puts('Coolant cycle started...')
        v_607 = (param_0 + (2 * 4))
        v_610 = MEM32[v_607]
        printf('Heat reduced from %d to %d.\n', v_138, v_610)
    else:
        record_fault(param_0, 'DENIED: coolant cycle requires an armed station.')
    return 0
