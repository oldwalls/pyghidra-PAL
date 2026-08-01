# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_start
# Entry address: 0x1010e0

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

def _start(param_0, param_1):
    abi_context = ABI.current('function_entry:1052896')
    abi_stack_pointer = abi_context.stack_pointer
    abi_overflow_arguments = abi_context.overflow_argument_area
    v_33 = (abi_stack_pointer - 8)
    v_66 = (abi_stack_pointer - -8)
    v_337 = (0 - 0x10271e)
    PTR___libc_start_main_00105fd8(v_337, param_1, v_33, 'GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0', 'GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0', param_0, v_66)
    while True:
        pass
