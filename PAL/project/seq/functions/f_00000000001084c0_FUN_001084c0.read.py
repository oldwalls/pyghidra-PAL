# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_001084c0
# Entry address: 0x1084c0

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

def FUN_001084c0():
    abi_context = ABI.current('function_entry:1082560')
    v_10 = MEM64[PTR_stdout_0010bfb0]
    v_693 = FUN_00104560(v_10)
    if v_693 == 0:
        v_184 = MEM64[PTR_stderr_0010bff0]
        v_728 = FUN_00104560(v_184)
        if v_728 != 0:
            _exit(DAT_0010c024)
        else:
            return 0
    else:
        v_352 = dcgettext(0, 'write error', 5)
        v_306 = __errno_location()
        v_127 = MEM32[v_306]
        error(0, v_127, 0x109176, v_352)
        _exit(DAT_0010c024)
