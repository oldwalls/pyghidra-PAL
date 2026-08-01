# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_boot
# Entry address: 0x101b3a

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

def command_boot(param_0):
    abi_context = ABI.current('function_entry:1055546')
    v_52 = MEM32[param_0]
    if v_52 == 0:
        puts('Boot sequence initiated...')
        puts('  control memory ........ OK')
        puts('  coolant circulation ... OK')
        puts('  routing matrix ........ OK')
        puts('  command interface ..... OK')
        MEM32[param_0] <- 1
        v_204 = (param_0 + (1 * 4))
        MEM32[v_204] <- 0
        v_220 = (param_0 + (2 * 4))
        MEM32[v_220] <- 0
        v_236 = (param_0 + (3 * 4))
        MEM32[v_236] <- 0
        v_252 = (param_0 + (7 * 4))
        MEM32[v_252] <- 0
        refresh_checksum(param_0)
        puts('Station entered DIAGNOSTIC mode.')
    else:
        record_fault(param_0, 'DENIED: boot is only valid while offline.')
    return 0
