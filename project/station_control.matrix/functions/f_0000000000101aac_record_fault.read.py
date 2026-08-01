# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::record_fault
# Entry address: 0x101aac

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

def record_fault(param_0, param_1):
    abi_context = ABI.current('function_entry:1055404')
    v_60 = (param_0 + (5 * 4))
    v_63 = MEM32[v_60]
    v_86 = (param_0 + (5 * 4))
    MEM32[v_86] <- (v_63 + 1)
    refresh_checksum(param_0)
    puts(param_1)
    v_138 = (param_0 + (5 * 4))
    v_141 = MEM32[v_138]
    printf('FAULTS: %d\n', v_141)
    v_174 = (param_0 + (5 * 4))
    v_177 = MEM32[v_174]
    if 2 >= v_177:
        pass
    else:
        MEM32[param_0] <- 4
        refresh_checksum(param_0)
        puts('STATION LOCKED: maximum fault count reached.')
    return 0
