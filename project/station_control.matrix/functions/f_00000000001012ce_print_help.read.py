# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::print_help
# Entry address: 0x1012ce

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

def print_help():
    abi_context = ABI.current('function_entry:1053390')
    putchar(0xa)
    puts('COMMANDS')
    puts('  boot            enter diagnostic mode')
    puts('  status          display station state')
    puts('  load N          set energy reserve (100..500)')
    puts('  route N         select route (1..4)')
    puts('  arm             validate and arm the station')
    puts('  pulse N         execute 1..8 pulse cycles')
    puts('  cool            reduce thermal load')
    puts('  clear           clear recoverable faults')
    puts('  commit          validate and activate the corridor')
    puts('  quit            leave the console')
    putchar(0xa)
    return 0
