# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00108560
# Entry address: 0x108560

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

def FUN_00108560(param_0, param_1):
    abi_context = ABI.current('function_entry:1082720')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    local_40 = MEM64[(abi_tls_base + 0x28)]
    v_122 = (abi_stack_pointer - -0x68)
    v_6864 = FUN_00103f60(param_1, v_122)
    if v_6864 == 0:
        v_3598 = FUN_00108540(param_1)
        v_3601 = dcgettext(0, 'invalid floating point argument: %s', 5)
        error(0, 0, v_3601, v_3598)
        FUN_001038a0('.shstrtab')
        __stack_chk_fail()
    else:
        v_9147 = ((uStack_60 << 64) | local_68)
        v_226 = float_nan(v_9147)
        if not v_226:
            v_9077 = (0 - 0x10c040)
            v_3583 = FUN_00108320('.shstrtab', param_1, v_9077)
            v_9080 = (0 - 0x10c040)
            v_3586 = FUN_00108320(0, 'not-a-number', v_9080)
            v_3589 = dcgettext(0, 'invalid %s argument: %s', 5)
            error(0, 0, v_3589, v_3586, v_3583)
            FUN_001038a0('.shstrtab')
            v_3598 = FUN_00108540(param_1)
            v_3601 = dcgettext(0, 'invalid floating point argument: %s', 5)
            error(0, 0, v_3601, v_3598)
            FUN_001038a0('.shstrtab')
            __stack_chk_fail()
        else:
            v_2514 = __ctype_b_loc()
            v_280 = MEM64[v_2514]
            v_3927 = param_1
            while True:
                v_286 = MEM8[v_3927]
                v_306 = MEM8[(v_280 + ((v_286 * 2) + 1))]
                v_3927 = (v_3927 + (1 * 1))
            local_58 = 0
            iStack_50 = 0x7fffffff
            v_9151 = strchr(v_3927, 0x2e)
            if v_9151 == 0:
                v_2530 = strchr(v_3927, 0x70)
                if v_2530 != 0:
                    pass
                else:
                    local_50 = 0
            v_2538 = strcspn(v_3927, 0x109179)
            v_434 = (v_3927 + (v_2538 * 1))
            v_437 = MEM8[v_434]
            if v_437 != 0:
                pass
            else:
                v_474 = int2float(0)
                v_515 = float_mult(v_9147, v_474)
                v_527 = float_equal(v_515, v_474)
                if v_527:
                    pass
                else:
                    v_9155 = strlen(v_3927)
                    local_58 = v_9155
                    if v_9151 == 0:
                        v_4437 = 0
                    else:
                        v_634 = (v_9151 + (1 * 1))
                        v_2553 = strcspn(v_634, 0x10917c)
                        if v_2553 < 2147483648:
                            local_50 = v_2553
                            if v_2553 != 0:
                                if v_3927 == v_9151:
                                    v_3625 = 1
                                else:
                                    v_712 = (v_9151 + (-1 * 1))
                                    v_715 = MEM8[v_712]
                                    v_3625 = (9 < (v_715 - 0x30))
                            else:
                                v_3625 = -1
                        v_795 = (v_9155 + (v_3625 * 1))
                        local_58 = v_795
                        v_4437 = v_2553
                    v_9159 = strchr(v_3927, 0x65)
                    v_4400 = v_9159
                    if v_4400 == 0:
                        v_9161 = strchr(v_3927, 0x45)
                        v_4400 = v_9161
                        if v_4400 == 0:
                            pass
                        else:
                            v_865 = (v_4400 + (1 * 1))
                            v_2578 = strtol(v_865, 0, 0xa)
                            v_7177 = v_2578
                            if v_7177 < 0:
                                v_2585 = strlen(v_3927)
                                v_9092 = (local_58 + (((-v_2585) - v_3927) * 1))
                                v_1653 = (v_4400 + (v_9092 * 1))
                                if v_9151 == 0:
                                    v_1806 = (v_1653 + (1 * 1))
                                    local_58 = v_1806
                                else:
                                    v_1705 = (v_9151 + (1 * 1))
                                    v_1725 = (v_1653 + (1 * 1))
                                    local_58 = v_1653
                                    if v_4400 == v_1705:
                                        pass
                                    else:
                                        local_58 = v_1725
                                v_3856 = (-v_2578)
                            else:
                                local_50 = iStack_50
                                v_6961 = local_50
                                if v_2578 < local_50:
                                    pass
                                else:
                                    v_6961 = v_7177
                                v_1067 = (iStack_50 - v_6961)
                                v_2592 = strlen(v_3927)
                                v_9093 = (local_58 + (((-v_2592) - v_3927) * 1))
                                local_58 = (v_4400 + (v_9093 * 1))
                                v_9050 = bool_and((v_4437 != 0), (v_9151 != 0))
                                if not (v_4437 != 0 and v_9151 != 0):
                                    pass
                                else:
                                    if local_50 - v_6961 != 0:
                                        pass
                                    else:
                                        local_58 = (local_58 + (-1 * 1))
                                v_4425 = v_4437
                                if v_2578 <= v_4437:
                                    pass
                                else:
                                    v_4425 = v_2578
                                v_3856 = (v_2578 - v_4425)
                            local_58 = (local_58 + (v_3856 * 1))
            v_7599 = ((local_5e << 16) | local_60)
            v_8002 = ((local_4c << 32) | local_50)
            MEM64[param_0] <- local_68
            v_7292 = (param_0 + (1 * 8))
            MEM64[v_7292] <- v_7599
            v_1428 = (param_0 + (2 * 8))
            MEM64[v_1428] <- local_58
            v_7302 = (param_0 + (3 * 8))
            MEM64[v_7302] <- v_8002
            v_1459 = MEM64[(abi_tls_base + 0x28)]
            if local_40 != v_1459:
                __stack_chk_fail()
            else:
                return param_0
