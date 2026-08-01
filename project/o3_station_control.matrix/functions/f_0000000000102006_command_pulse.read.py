# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_pulse
# Entry address: 0x102006

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

def command_pulse(param_0, param_1):
    abi_context = ABI.current('function_entry:1056774')
    v_60 = MEM32[param_0]
    if v_60 == 2:
        v_146 = MEM32[(param_1 + 0x10)]
        if v_146 != 0:
            v_215 = MEM32[(param_1 + 0x14)]
            if v_215 < 1:
                record_fault(param_0, 'REJECTED: pulse cycle count must be between 1 and 8.')
                return 0
            else:
                v_265 = MEM32[(param_1 + 0x14)]
                if 8 >= v_265:
                    local_14 = 1
                    while True:
                        v_351 = MEM32[(param_1 + 0x14)]
                        if not (local_14 <= v_351):
                            break
                        v_474 = (param_0 + (3 * 4))
                        v_477 = MEM32[v_474]
                        local_10 = (local_14 + ((v_477 + 3) * 2))
                        v_577 = (param_0 + (3 * 4))
                        v_580 = MEM32[v_577]
                        local_c = ((local_14 / 2) + (v_580 + 7))
                        v_817 = (param_0 + (4 * 4))
                        v_820 = MEM32[v_817]
                        if v_820 & 4 == 0:
                            local_c = (local_c + 1)
                        else:
                            local_10 = (local_10 + 2)
                        v_938 = (param_0 + (1 * 4))
                        v_941 = MEM32[v_938]
                        v_994 = (param_0 + (1 * 4))
                        MEM32[v_994] <- (v_941 + local_10)
                        v_1010 = (param_0 + (2 * 4))
                        v_1013 = MEM32[v_1010]
                        v_1066 = (param_0 + (2 * 4))
                        MEM32[v_1066] <- (v_1013 + local_c)
                        v_1082 = (param_0 + (7 * 4))
                        v_1085 = MEM32[v_1082]
                        v_1108 = (param_0 + (7 * 4))
                        MEM32[v_1108] <- (v_1085 + 1)
                        refresh_checksum(param_0)
                        v_1142 = (param_0 + (4 * 4))
                        v_1145 = MEM32[v_1142]
                        v_1160 = (param_0 + (2 * 4))
                        v_1163 = MEM32[v_1160]
                        v_1178 = (param_0 + (1 * 4))
                        v_1181 = MEM32[v_1178]
                        v_1199 = MEM32[(param_1 + 0x14)]
                        printf('Pulse cycle %d/%d: energy=%d heat=%d checksum=0x%08X\n', local_14, v_1199, v_1181, v_1163, v_1145)
                        v_1250 = (param_0 + (2 * 4))
                        v_1253 = MEM32[v_1250]
                        if 149 < v_1253:
                            MEM32[param_0] <- 4
                            refresh_checksum(param_0)
                            puts('THERMAL FAILURE: station entered FAILED mode.')
                            return 0
                        local_14 = (local_14 + 1)
                    v_408 = (param_0 + (2 * 4))
                    v_411 = MEM32[v_408]
                    if 80 >= v_411:
                        pass
                    else:
                        puts('WARNING: thermal level above commit threshold.')
                else:
                    record_fault(param_0, 'REJECTED: pulse cycle count must be between 1 and 8.')
        else:
            record_fault(param_0, 'REJECTED: pulse requires an integer cycle count.')
    else:
        record_fault(param_0, 'DENIED: pulse requires an armed station.')
    return 0
    return 0
    return 0
    return 0
    return 0
