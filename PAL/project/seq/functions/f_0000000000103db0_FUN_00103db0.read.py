# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103db0
# Entry address: 0x103db0

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

def FUN_00103db0():
    abi_context = ABI.current('function_entry:1064368')
    v_221 = dcgettext(0, 'memory exhausted', 5)
    error(DAT_0010c024, 0, 0x109176, v_221)
    abort()
