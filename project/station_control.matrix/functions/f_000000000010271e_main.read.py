# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::main
# Entry address: 0x10271e

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

def main():
    abi_context = ABI.current('function_entry:1058590')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    local_10 = MEM64[(abi_tls_base + 0x28)]
    local_60 = 1
    v_86 = (abi_stack_pointer - -0x58)
    initialize_station(v_86)
    print_banner()
    while True:
        if not (local_60 != 0):
            v_921 = abi_tls_base
            break
        v_682 = mode_name(UNNAMED)
        printf('\nstation[%s]> ', v_682)
        v_320 = (abi_stack_pointer - -0x28)
        v_1278 = read_command(v_320)
        if v_1278 == 0:
            v_921 = abi_tls_base
            break
        if 4294967295 < v_1278:
            pass
        else:
            v_917 = abi_tls_base
            continue
        v_418 = (abi_stack_pointer - -0x28)
        v_423 = (abi_stack_pointer - -0x58)
        local_60 = dispatch_command(v_423, v_418)
    puts('Station interface closed.')
    v_161 = (abi_stack_pointer - -0x58)
    v_1307 = station_exit_code(v_161)
    printf('Return code: %d\n', v_1307)
    v_194 = (abi_stack_pointer - -0x58)
    station_exit_code(v_194)
    v_232 = MEM64[(abi_tls_base + 0x28)]
    if local_10 == v_232:
        return 0
    else:
        __stack_chk_fail()
