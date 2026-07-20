# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103df0
# Entry address: 0x103df0

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

def FUN_00103df0(param_0, param_1):
    abi_context = ABI.current('function_entry:1064432')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    local_30 = MEM64[(abi_tls_base + 0x28)]
    v_112 = (abi_stack_pointer - -0x40)
    strtold(param_0, v_112)
    v_151 = MEM8[local_40]
    v_3043 = local_40
    if v_151 != 0:
        v_1097 = __errno_location()
        v_472 = MEM32[v_1097]
        if DAT_0010c1c0 == 0:
            DAT_0010c1c0 = newlocale(0x1fbf, 0x1090d9, 0)
        if DAT_0010c1c0 == 0:
            v_3043 = param_0
            local_38 = param_0
            if local_40 < param_0:
                MEM32[v_1097] <- v_472
                v_3043 = local_40
            local_40 = v_3043
            if param_1 == 0:
                pass
            else:
                MEM64[param_1] <- local_40
            v_266 = MEM64[(abi_tls_base + 0x28)]
            if local_30 != v_266:
                __stack_chk_fail()
            else:
                return 0
        else:
            v_1113 = uselocale(DAT_0010c1c0)
            if v_1113 == 0:
                pass
            else:
                v_641 = (abi_stack_pointer - -0x38)
                strtold(param_0, v_641)
                v_656 = MEM32[v_1097]
                v_1128 = uselocale(v_1113)
                if v_1128 == 0:
                    abort()
                else:
                    MEM32[v_1097] <- v_656
                    v_3043 = local_38
                    if local_40 >= local_38:
                        pass
