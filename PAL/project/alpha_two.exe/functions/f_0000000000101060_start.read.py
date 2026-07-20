# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_start
# Entry address: 0x101060

#======= PAL stack versioning ======
# PALStaticStringPublisher = static_strings_v1_defined_ghidra_data
# PALBatchDecompiler = batch_v2d_explicit_stdio_overlay_authority
# PALHumanizer = humanizer_v2_oncs_varnames_recovery
# PALDecompilerPipeline = unknown
# PALlibrary.PALLifter = unknown
# PALlibrary.FunctionCFG = unknown
# PALSymbolResolver = unknown
# PALRawAudit = unknown
# PALCompute = v23b_abi_thunk_compatibility_return_reconciliation
# PALSemanticGraphBuilder = unknown
# PALSGLdecomp = unknown
# PALPHIfolder = v23_abi_f_entry_state_convergence_custody
# PALemitter = v46p_immutable_abi_context_continuity
# PALCodeDocument = im_d_v1_projection_alias_edit_sidecars
#====================================

# PAL readable projection (non-executable)
# Static C-string call arguments projected from PAL_stdio_strings.json
# Width/sign contracts remain available in PAL provenance metadata

def _start(param_0, param_1):
    abi_context = ABI.current('function_entry:1052768')
    abi_stack_pointer = abi_context.stack_pointer
    abi_overflow_arguments = abi_context.overflow_argument_area
    v_33 = (abi_stack_pointer - 8)
    v_66 = (abi_stack_pointer - -8)
    v_337 = (0 - 0x10119d)
    PTR___libc_start_main_00103fd8(v_337, param_1, v_33, 'GNU C17 11.4.0 -mtune=generic -march=x86-64 -g -O0 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection', 'GNU C17 11.4.0 -mtune=generic -march=x86-64 -g -O0 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection', param_0, v_66)
    while True:
        pass
