# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::draw_lander
# Entry address: 0x101252

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

def draw_lander(param_0):
    abi_context = ABI.current('function_entry:1053266')
    v_52 = MEM32[param_0]
    v_1878 = craft_row_for_altitude(v_52)
    puts('========================================================')
    puts('              PAL ASCII LUNAR LANDER')
    puts('        integer physics / deterministic moon')
    puts('========================================================')
    v_135 = (param_0 + (2 * 4))
    v_138 = MEM32[v_135]
    v_153 = (param_0 + (1 * 4))
    v_156 = MEM32[v_153]
    v_171 = MEM32[param_0]
    v_186 = (param_0 + (3 * 4))
    v_189 = MEM32[v_186]
    printf('TURN: %-3d  ALTITUDE: %-3d  VELOCITY: %-3d  FUEL: %-3d\n', v_189, v_171, v_156, v_138)
    puts('--------------------------------------------------------')
    local_c = 0
    while local_c < 8:
        print_sky_row(local_c, v_1878)
        local_c = (local_c + 1)
        print_sky_row(local_c, v_1878)
        local_c = (local_c + 1)
    puts('________________________________________________________')
    puts('    .       *       .      MOON BASE PAL      .')
    puts('--------------------------------------------------------')
    v_325 = (param_0 + (1 * 4))
    v_328 = MEM32[v_325]
    if v_328 < 4:
        v_447 = (param_0 + (1 * 4))
        v_450 = MEM32[v_447]
        if v_450 >= 4294967294:
            puts('DESCENT RATE: SAFE BAND')
        else:
            puts('DESCENT RATE: ASCENDING')
    else:
        puts('DESCENT RATE: DANGER')
    printf('Enter thrust 0..9. Gravity adds %d each turn.\n', 2)
    puts('Q abandons the mission.')
    puts('THRUST>')
    return 0
