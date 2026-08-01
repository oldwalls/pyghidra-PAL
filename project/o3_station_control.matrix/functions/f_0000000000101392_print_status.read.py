# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::print_status
# Entry address: 0x101392

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

def print_status(param_0):
    abi_context = ABI.current('function_entry:1053586')
    putchar(0xa)
    v_62 = MEM32[param_0]
    v_691 = mode_name(v_62)
    printf('MODE:      %s\n', v_691)
    v_105 = (param_0 + (1 * 4))
    v_108 = MEM32[v_105]
    printf('ENERGY:    %d\n', v_108)
    v_141 = (param_0 + (2 * 4))
    v_144 = MEM32[v_141]
    printf('HEAT:      %d\n', v_144)
    v_177 = (param_0 + (3 * 4))
    v_180 = MEM32[v_177]
    if v_180 != 0:
        v_405 = (param_0 + (3 * 4))
        v_408 = MEM32[v_405]
        printf('ROUTE:     %d\n', v_408)
    else:
        puts('ROUTE:     unset')
    v_236 = (param_0 + (4 * 4))
    v_239 = MEM32[v_236]
    printf('CHECKSUM:  0x%08X\n', v_239)
    v_272 = (param_0 + (5 * 4))
    v_275 = MEM32[v_272]
    printf('FAULTS:    %d\n', v_275)
    v_308 = (param_0 + (6 * 4))
    v_311 = MEM32[v_308]
    printf('ATTEMPTS:  %d\n', v_311)
    v_344 = (param_0 + (7 * 4))
    v_347 = MEM32[v_344]
    printf('PULSES:    %d\n', v_347)
    putchar(0xa)
    return 0
