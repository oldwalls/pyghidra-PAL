# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::read_command
# Entry address: 0x1018bc

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

def read_command(param_0):
    abi_context = ABI.current('function_entry:1054908')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    local_10 = MEM64[(abi_tls_base + 0x28)]
    v_88 = (abi_stack_pointer - -0x78)
    v_394 = fgets(v_88, 0x60, stdin)
    if v_394 != 0:
        v_229 = (abi_stack_pointer - -0x78)
        v_899 = parse_command(v_229, param_0)
        if v_899 != 0:
            if v_899 >= 0:
                v_684 = abi_tls_base
                v_1149 = v_899
            else:
                puts('INVALID NUMERIC ARGUMENT')
                v_1149 = v_899
        else:
            puts('EMPTY COMMAND')
            v_1149 = v_899
    else:
        puts('\nINPUT CLOSED')
        v_1149 = 0
    v_171 = MEM64[(abi_tls_base + 0x28)]
    if local_10 == v_171:
        return v_1149
    else:
        __stack_chk_fail()
