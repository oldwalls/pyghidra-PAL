# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103c60
# Entry address: 0x103c60

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

def FUN_00103c60():
    abi_context = ABI.current('function_entry:1064032')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    v_10 = MEM64[PTR_stdout_0010bfb0]
    clearerr_unlocked(v_10)
    v_905 = dcgettext(0, 'write error', 5)
    v_675 = __errno_location()
    v_75 = MEM32[v_675]
    error('.shstrtab', v_75, v_905)
    v_190 = (abi_stack_pointer - -0x130)
    lStack_28 = MEM64[(abi_tls_base + 0x28)]
    v_688 = setlocale(0, 0)
    if v_688 == 0:
        v_1961 = 0
    else:
        v_1961 = 0
        v_695 = strlen(v_688)
        if v_695 < 257:
            v_1982 = __memcpy_chk(v_190, v_688, (v_695 + 1), 0x101)
            if local_130 == 67:
                if local_12f == 0:
                    pass
                else:
                    v_708 = strcmp(v_1982, 'POSIX')
                    v_1961 = (v_708 != 0)
            else:
                v_708 = strcmp(v_1982, 'POSIX')
                v_1961 = (v_708 != 0)
    v_378 = MEM64[(abi_tls_base + 0x28)]
    if local_28 != v_378:
        __stack_chk_fail()
    else:
        return v_1961
