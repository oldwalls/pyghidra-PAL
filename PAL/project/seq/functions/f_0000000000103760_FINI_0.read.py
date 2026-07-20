# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_FINI_0
# Entry address: 0x103760

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

def _FINI_0():
    abi_context = ABI.current('function_entry:1062752')
    if DAT_0010c0a0 != 0:
        return 0
    else:
        if PTR___cxa_finalize_0010bfe8 == 0:
            pass
        else:
            __cxa_finalize(PTR_LOOP_0010c008)
        FUN_001036f0()
        return 0
