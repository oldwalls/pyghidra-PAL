# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_001037b0
# Entry address: 0x1037b0

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

def FUN_001037b0(param_0, param_1, param_2, param_3):
    v_2038 = MEM8[(param_0 + 7)]
    if param_2 - 65 >= 26:
        pass
    else:
        v_2038 = (v_2038 & 0xdf)
    if v_2038 != param_2:
        return 0
    else:
        v_2076 = 1
        if param_2 != 0:
            v_2042 = MEM8[(param_0 + 8)]
            if param_3 - 65 >= 26:
                pass
            else:
                v_2042 = (v_2042 & 0xdf)
            if v_2042 != param_3:
                return 0
            else:
                v_2076 = 1
                if param_3 == 0:
                    pass
                else:
                    if param_0 == param_1:
                        pass
                    else:
                        v_1297 = 9
                        while True:
                            v_1962 = MEM8[(param_0 + v_1297)]
                            v_1989 = v_1962
                            if v_1962 - 65 >= 26:
                                pass
                            else:
                                v_1989 = (v_1962 + 0x20)
                                v_1962 = (v_1962 + 0x20)
                            v_1967 = MEM8[(param_1 + v_1297)]
                            v_2017 = v_1967
                            if v_1967 - 65 >= 26:
                                pass
                            else:
                                v_2017 = (v_1967 + 0x20)
                                v_1967 = (v_1967 + 0x20)
                            if v_1962 == 0:
                                break
                            v_1297 = (v_1297 + 1)
                            if v_1962 != v_1967:
                                break
                        v_2076 = (v_1989 == v_2017)
                return v_2076
        else:
            return v_2076
