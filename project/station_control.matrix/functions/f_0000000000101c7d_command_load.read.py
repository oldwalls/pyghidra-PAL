# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::command_load
# Entry address: 0x101c7d

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

def command_load(param_0, param_1):
    abi_context = ABI.current('function_entry:1055869')
    v_60 = MEM32[param_0]
    if v_60 == 1:
        v_146 = MEM32[(param_1 + 0x10)]
        if v_146 != 0:
            v_215 = MEM32[(param_1 + 0x14)]
            if v_215 < 100:
                record_fault(param_0, 'REJECTED: energy value must be between 100 and 500.')
            else:
                v_269 = MEM32[(param_1 + 0x14)]
                if 500 >= v_269:
                    v_344 = MEM32[(param_1 + 0x14)]
                    v_359 = (param_0 + (1 * 4))
                    MEM32[v_359] <- v_344
                    v_378 = MEM32[(param_1 + 0x14)]
                    v_743 = (param_0 + (2 * 4))
                    MEM32[v_743] <- (v_378 / 0x28)
                    refresh_checksum(param_0)
                    v_777 = (param_0 + (1 * 4))
                    v_780 = MEM32[v_777]
                    printf('Energy reserve set to %d units.\n', v_780)
                    v_813 = (param_0 + (4 * 4))
                    v_816 = MEM32[v_813]
                    printf('CHECKSUM: 0x%08X\n', v_816)
                else:
                    record_fault(param_0, 'REJECTED: energy value must be between 100 and 500.')
        else:
            record_fault(param_0, 'REJECTED: load requires an integer value.')
    else:
        record_fault(param_0, 'DENIED: energy may be loaded only in diagnostic mode.')
    return 0
