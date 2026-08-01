# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_arm
# Entry address: 0x101e64

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

def command_arm(param_0):
    abi_context = ABI.current('function_entry:1056356')
    v_2739 = 1
    v_60 = MEM32[param_0]
    if v_60 == 1:
        v_143 = (param_0 + (6 * 4))
        v_146 = MEM32[v_143]
        v_169 = (param_0 + (6 * 4))
        MEM32[v_169] <- (v_146 + 1)
        puts('Verifying station state...')
        v_197 = (param_0 + (1 * 4))
        v_200 = MEM32[v_197]
        if v_200 < 100:
            puts('  energy range .......... FAIL')
            v_2739 = 0
        else:
            v_251 = (param_0 + (1 * 4))
            v_254 = MEM32[v_251]
            if 500 >= v_254:
                puts('  energy range .......... OK')
            else:
                puts('  energy range .......... FAIL')
                v_2739 = 0
        v_324 = (param_0 + (3 * 4))
        v_327 = MEM32[v_324]
        if v_327 < 1:
            puts('  routing channel ....... FAIL')
            v_2739 = 0
        else:
            v_374 = (param_0 + (3 * 4))
            v_377 = MEM32[v_374]
            if 4 >= v_377:
                puts('  routing channel ....... OK')
            else:
                puts('  routing channel ....... FAIL')
                v_2739 = 0
        refresh_checksum(param_0)
        v_467 = (param_0 + (4 * 4))
        v_470 = MEM32[v_467]
        v_485 = (param_0 + (1 * 4))
        v_488 = MEM32[v_485]
        v_529 = (param_0 + (3 * 4))
        v_532 = MEM32[v_529]
        if v_532 + 1 ^ v_470 ^ v_488 & 1 == 0:
            puts('  checksum parity ....... OK')
        else:
            puts('  checksum parity ....... FAIL')
            v_2739 = 0
        v_674 = (param_0 + (5 * 4))
        v_677 = MEM32[v_674]
        if v_677 == 0:
            puts('  fault register ........ CLEAR')
        else:
            puts('  fault register ........ BLOCKED')
            v_2739 = 0
        if v_2739:
            MEM32[param_0] <- 2
            refresh_checksum(param_0)
            puts('Station ARMED.')
        else:
            puts('ARMING DENIED.')
    else:
        record_fault(param_0, 'DENIED: station must be in diagnostic mode before arming.')
    return 0
