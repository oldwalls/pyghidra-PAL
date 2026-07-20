# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103ca0
# Entry address: 0x103ca0

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

def FUN_00103ca0():
    abi_context = ABI.current('function_entry:1064096')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    v_74 = (abi_stack_pointer - -0x128)
    local_20 = MEM64[(abi_tls_base + 0x28)]
    v_538 = setlocale(0, 0)
    if v_538 == 0:
        v_1382 = 0
    else:
        v_1382 = 0
        v_545 = strlen(v_538)
        if v_545 < 257:
            v_1398 = __memcpy_chk(v_74, v_538, (v_545 + 1), 0x101)
            if local_128 == 67:
                if local_127 == 0:
                    pass
                else:
                    v_558 = strcmp(v_1398, 'POSIX')
                    v_1382 = (v_558 != 0)
            else:
                v_558 = strcmp(v_1398, 'POSIX')
                v_1382 = (v_558 != 0)
    v_262 = MEM64[(abi_tls_base + 0x28)]
    if local_20 != v_262:
        __stack_chk_fail()
    else:
        return v_1382
