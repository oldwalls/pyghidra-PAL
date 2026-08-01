# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::read_burn
# Entry address: 0x101437

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

def read_burn(param_0):
    abi_context = ABI.current('function_entry:1053751')
    abi_stack_pointer = abi_context.stack_pointer
    v_46 = (abi_stack_pointer - -0x28)
    v_237 = fgets(v_46, 0x10, stdin)
    if v_237 != 0:
        v_129 = (abi_stack_pointer - -0x28)
        v_700 = parse_burn(v_129, param_0)
        if v_700 >= 0:
            pass
        else:
            puts('INVALID THRUST: enter one digit from 0 through 9.')
            v_700 = local_c
    else:
        puts('INPUT CLOSED')
        v_700 = 0
    return v_700
