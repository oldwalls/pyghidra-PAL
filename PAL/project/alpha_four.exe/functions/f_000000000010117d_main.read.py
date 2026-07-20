# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::main
# Entry address: 0x10117d

#======= PAL stack versioning ======
# PALStaticStringPublisher = static_strings_v1_defined_ghidra_data
# PALBatchDecompiler = batch_v2d_explicit_stdio_overlay_authority
# PALHumanizer = humanizer_v2_oncs_varnames_recovery
# PALDecompilerPipeline = unknown
# PALlibrary.PALLifter = unknown
# PALlibrary.FunctionCFG = unknown
# PALSymbolResolver = unknown
# PALRawAudit = unknown
# PALCompute = v23b_abi_thunk_compatibility_return_reconciliation
# PALSemanticGraphBuilder = unknown
# PALSGLdecomp = unknown
# PALPHIfolder = v23_abi_f_entry_state_convergence_custody
# PALemitter = v46p_immutable_abi_context_continuity
# PALCodeDocument = im_d_v1_projection_alias_edit_sidecars
#====================================

# PAL readable projection (non-executable)
# Static C-string call arguments projected from PAL_stdio_strings.json
# Width/sign contracts remain available in PAL provenance metadata

def main():
    abi_context = ABI.current('function_entry:1053053')
    local_2c = 0x10
    local_28 = 0
    local_24 = 0
    local_20 = 0
    while True:
        local_2c = mutate((local_20 + local_2c))
        local_1c = 0
        while not (9 < local_1c or local_28 < 1):
            v_4453 = feedback(local_2c, local_1c)
            if v_4453 ^ local_28 % 3 != 0:
                v_1257 = (v_4453 & 7)
                if v_1257 == 3:
                    local_18 = 0
                    local_24 = v_4453
                    while not (local_24 < 1 or 15 < local_18):
                        local_24 = mutate((local_24 >> 1))
                        local_18 = (local_18 + 1)
                        if local_24 == 15:
                            break
                else:
                    if v_4453 & 7 >= 4:
                        local_2c = (local_2c - local_28)
                    else:
                        if v_4453 & 7 >= 2:
                            if v_4453 & 7 == 2:
                                local_28 = (local_28 + 5)
                                local_24 = v_4453
                            else:
                                local_2c = (local_2c - local_28)
                        else:
                            local_2c = (local_2c ^ 0xaa)
                            local_28 = (local_28 + 5)
                            local_24 = v_4453
                if 4294967295 >= local_2c:
                    local_2c = 0
                    break
            else:
                local_28 = (local_28 - 2)
                local_24 = v_4453
                local_1c = (local_1c + 1)
                continue
            local_1c = (local_1c + 1)
        v_5265 = local_2c
        if local_20 & 1 == 0:
            pass
        else:
            local_2c = local_28
            local_28 = v_5265
        local_20 = (local_20 + 1)
        if 4 >= local_20:
            pass
        else:
            if 99 >= local_2c:
                break
        if 11 < local_20:
            pass
        else:
            break
    printf('Final after %d outer loops: %d, %d, %d\n', local_20, local_2c, local_28, local_24)
    return (local_28 + local_2c)
