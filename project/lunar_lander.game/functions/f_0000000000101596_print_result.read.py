# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::print_result
# Entry address: 0x101596

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

def print_result(param_0):
    abi_context = ABI.current('function_entry:1054102')
    puts('========================================================')
    puts('                 PAL LUNAR LANDER RESULT')
    puts('========================================================')
    v_91 = MEM32[(param_0 + 0x18)]
    if v_91 == 0:
        v_187 = MEM32[(param_0 + 0x14)]
        if v_187 == 0:
            puts('*** CRASH LANDING ***')
            v_364 = MEM32[(param_0 + 4)]
            printf('Impact velocity: %d\n', v_364)
            puts('Try smaller thrust early and stronger thrust late.')
        else:
            puts('*** SOFT LANDING ***')
            v_243 = MEM32[(param_0 + 4)]
            printf('Velocity: %d\n', v_243)
            v_279 = MEM32[(param_0 + 8)]
            printf('Fuel:     %d\n', v_279)
            v_315 = MEM32[(param_0 + 0xc)]
            printf('Turns:    %d\n', v_315)
    else:
        puts('MISSION ABORTED')
        puts('The lander remains in orbit.')
    puts('Known soft-landing sequence: 0 0 0 0 7 2')
    return 0
