# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_commit
# Entry address: 0x10229c

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

def command_commit(param_0):
    abi_context = ABI.current('function_entry:1057436')
    v_4172 = 1
    v_60 = MEM32[param_0]
    if v_60 == 2:
        v_133 = (param_0 + (4 * 4))
        v_136 = MEM32[v_133]
        v_151 = (param_0 + (1 * 4))
        v_154 = MEM32[v_151]
        v_255 = (param_0 + (3 * 4))
        v_258 = MEM32[v_255]
        puts('Final validation:')
        v_539 = (param_0 + (1 * 4))
        v_542 = MEM32[v_539]
        if v_542 < 350:
            v_643 = (param_0 + (1 * 4))
            v_646 = MEM32[v_643]
            printf('  energy ................ FAIL (%d)\n', v_646)
            v_4172 = 0
        else:
            v_591 = (param_0 + (1 * 4))
            v_594 = MEM32[v_591]
            if 520 >= v_594:
                v_1304 = (param_0 + (1 * 4))
                v_1307 = MEM32[v_1304]
                printf('  energy ................ OK (%d)\n', v_1307)
            else:
                v_643 = (param_0 + (1 * 4))
                v_646 = MEM32[v_643]
                printf('  energy ................ FAIL (%d)\n', v_646)
                v_4172 = 0
        v_688 = (param_0 + (2 * 4))
        v_691 = MEM32[v_688]
        if v_691 < 81:
            v_1268 = (param_0 + (2 * 4))
            v_1271 = MEM32[v_1268]
            printf('  heat .................. OK (%d)\n', v_1271)
        else:
            v_742 = (param_0 + (2 * 4))
            v_745 = MEM32[v_742]
            printf('  heat .................. FAIL (%d)\n', v_745)
            v_4172 = 0
        v_787 = (param_0 + (3 * 4))
        v_790 = MEM32[v_787]
        if v_790 != 0:
            v_1232 = (param_0 + (3 * 4))
            v_1235 = MEM32[v_1232]
            printf('  route ................. OK (%d)\n', v_1235)
        else:
            puts('  route ................. FAIL')
            v_4172 = 0
        v_854 = (param_0 + (3 * 4))
        v_857 = MEM32[v_854]
        if v_258 * 19 ^ v_136 ^ v_154 * 3 & 3 != v_857 + 1 & 3:
            puts('  checksum route ........ FAIL')
            v_4172 = 0
        else:
            puts('  checksum route ........ OK')
        v_977 = (param_0 + (5 * 4))
        v_980 = MEM32[v_977]
        if v_980 == 0:
            puts('  faults ................ CLEAR')
        else:
            v_1021 = (param_0 + (5 * 4))
            v_1024 = MEM32[v_1021]
            printf('  faults ................ FAIL (%d)\n', v_1024)
            v_4172 = 0
        if v_4172:
            MEM32[param_0] <- 3
            v_1130 = (param_0 + (8 * 4))
            MEM32[v_1130] <- 1
            refresh_checksum(param_0)
            puts('STATION CONTROL COMMITTED.')
            puts('DOCKING CORRIDOR OPEN.')
            puts('MISSION RESULT: SUCCESS')
        else:
            puts('COMMIT DENIED: validation incomplete.')
    else:
        puts('COMMIT DENIED: station is not armed.')
    return 0
