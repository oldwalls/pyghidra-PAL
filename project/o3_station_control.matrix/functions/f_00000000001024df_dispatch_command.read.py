# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::dispatch_command
# Entry address: 0x1024df

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

def dispatch_command(param_0, param_1):
    abi_context = ABI.current('function_entry:1058015')
    v_2914 = (0 - 0x103b70)
    v_2210 = text_equal(param_1, v_2914)
    if v_2210 == 0:
        v_2221 = text_equal(param_1, 'status')
        if v_2221 == 0:
            v_2920 = (0 - 0x103b7c)
            v_2232 = text_equal(param_1, v_2920)
            if v_2232 == 0:
                v_2243 = text_equal(param_1, 'clear')
                if v_2243 == 0:
                    v_2926 = (0 - 0x103b87)
                    v_2254 = text_equal(param_1, v_2926)
                    if v_2254 == 0:
                        v_2265 = text_equal(param_1, 'route')
                        if v_2265 == 0:
                            v_2932 = (0 - 0x103b92)
                            v_2276 = text_equal(param_1, v_2932)
                            if v_2276 == 0:
                                v_2287 = text_equal(param_1, 'pulse')
                                if v_2287 == 0:
                                    v_2938 = (0 - 0x103b9c)
                                    v_2298 = text_equal(param_1, v_2938)
                                    if v_2298 == 0:
                                        v_2309 = text_equal(param_1, 'commit')
                                        if v_2309 == 0:
                                            v_2944 = (0 - 0x103ba8)
                                            v_2320 = text_equal(param_1, v_2944)
                                            if v_2320 == 0:
                                                record_fault(param_0, 'UNKNOWN COMMAND')
                                                return 1
                                            else:
                                                return 0
                                        else:
                                            command_commit(param_0)
                                            return 1
                                    else:
                                        command_cool(param_0)
                                        return 1
                                else:
                                    command_pulse(param_0, param_1)
                                    return 1
                            else:
                                command_arm(param_0)
                                return 1
                        else:
                            command_route(param_0, param_1)
                            return 1
                    else:
                        command_load(param_0, param_1)
                        return 1
                else:
                    command_clear(param_0)
                    return 1
            else:
                command_boot(param_0)
                return 1
        else:
            print_status(param_0)
            return 1
    else:
        print_help()
        return 1
