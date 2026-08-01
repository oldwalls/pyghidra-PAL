# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::apply_burn
# Entry address: 0x1014a6

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

def apply_burn(param_0, param_1):
    v_34 = (param_0 + (2 * 4))
    v_37 = MEM32[v_34]
    local_14 = param_1
    if v_37 >= param_1:
        pass
    else:
        v_94 = (param_0 + (2 * 4))
        local_14 = MEM32[v_94]
    v_120 = (param_0 + (2 * 4))
    v_123 = MEM32[v_120]
    v_182 = (param_0 + (2 * 4))
    MEM32[v_182] <- (v_123 - local_14)
    v_198 = (param_0 + (1 * 4))
    v_201 = MEM32[v_198]
    v_224 = (param_0 + (1 * 4))
    MEM32[v_224] <- (v_201 + 2)
    v_240 = (param_0 + (1 * 4))
    v_243 = MEM32[v_240]
    v_302 = (param_0 + (1 * 4))
    MEM32[v_302] <- (v_243 - local_14)
    v_318 = MEM32[param_0]
    v_333 = (param_0 + (1 * 4))
    v_336 = MEM32[v_333]
    MEM32[param_0] <- (v_318 - v_336)
    v_392 = (param_0 + (3 * 4))
    v_395 = MEM32[v_392]
    v_418 = (param_0 + (3 * 4))
    MEM32[v_418] <- (v_395 + 1)
    v_434 = MEM32[param_0]
    if 30 >= v_434:
        pass
    else:
        MEM32[param_0] <- 0x1e
        v_498 = (param_0 + (1 * 4))
        MEM32[v_498] <- 0
    v_514 = MEM32[param_0]
    if v_514 >= 1:
        pass
    else:
        MEM32[param_0] <- 0
        v_576 = (param_0 + (4 * 4))
        MEM32[v_576] <- 0
        v_592 = (param_0 + (1 * 4))
        v_595 = MEM32[v_592]
        if v_595 < 4294967294:
            v_733 = (param_0 + (5 * 4))
            MEM32[v_733] <- 0
        else:
            v_643 = (param_0 + (1 * 4))
            v_646 = MEM32[v_643]
            if 3 >= v_646:
                v_733 = (param_0 + (5 * 4))
                MEM32[v_733] <- 0
            else:
                v_699 = (param_0 + (5 * 4))
                MEM32[v_699] <- 1
    return 0
