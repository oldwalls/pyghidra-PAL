# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::compute_checksum
# Entry address: 0x101985

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

def compute_checksum(param_0):
    abi_context = ABI.current('function_entry:1055109')
    v_60 = (param_0 + (1 * 4))
    v_63 = MEM32[v_60]
    v_258 = (param_0 + (2 * 4))
    v_261 = MEM32[v_258]
    v_456 = (param_0 + (3 * 4))
    v_459 = MEM32[v_456]
    v_654 = (param_0 + (5 * 4))
    v_657 = MEM32[v_654]
    v_736 = (param_0 + (7 * 4))
    v_739 = MEM32[v_736]
    v_934 = MEM32[param_0]
    local_14 = (((((((v_63 * 0x21) ^ 0x13579bdf) ^ (v_261 * 0x11)) ^ (v_459 * 0x101)) ^ (v_657 * 0x1003)) ^ (v_739 * 0x1fff)) ^ (v_934 * 0x10001))
    v_1129 = (param_0 + (1 * 4))
    v_1132 = MEM32[v_1129]
    v_1147 = (param_0 + (2 * 4))
    v_1150 = MEM32[v_1147]
    v_1176 = (param_0 + (3 * 4))
    v_1179 = MEM32[v_1176]
    v_1360 = (param_0 + (6 * 4))
    v_1363 = MEM32[v_1360]
    local_10 = ((v_1363 * 0xb) + ((v_1132 + v_1150) + (v_1179 * 7)))
    local_c = 0
    while local_c < 4:
        v_3352 = rotate_left_5(local_14)
        local_14 = (v_3352 ^ (local_10 + (local_c * 0x1021)))
        local_10 = ((local_14 >> 3) ^ (local_10 * 0x1d))
        local_c = (local_c + 1)
        v_3352 = rotate_left_5(local_14)
        local_14 = (v_3352 ^ (local_10 + (local_c * 0x1021)))
        local_10 = ((local_14 >> 3) ^ (local_10 * 0x1d))
        local_c = (local_c + 1)
    return (local_14 ^ 0xa5a55a5a)
