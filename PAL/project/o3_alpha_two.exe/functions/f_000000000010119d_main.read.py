# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::main
# Entry address: 0x10119d

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
    abi_context = ABI.current('function_entry:1053085')
    local_2c = 0x64
    local_28 = 0
    local_24 = 0
    while 4 >= local_24:
        v_5684 = transform_a((local_2c + local_24))
        if v_5684 & 1 == 0 or (1 < local_24 and v_5684 < 500):
            local_20 = 0
            while local_20 < 3:
                v_5713 = transform_b((local_24 + local_20))
                v_1460 = (v_5713 % 4)
                if v_1460 == 2:
                    if local_2c < 201:
                        local_2c = (local_2c + 0x32)
                        local_20 = (local_20 + 1)
                    else:
                        local_2c = (local_2c - 0x14)
                        local_20 = (local_20 + 1)
                else:
                    if v_5713 % 4 >= 3:
                        local_2c = (local_2c << 1)
                        local_20 = (local_20 + 1)
                    else:
                        if v_5713 % 4 == 0:
                            local_2c = (local_2c + (v_5713 ^ 0x12))
                            local_20 = (local_20 + 1)
                        else:
                            if v_5713 % 4 == 1:
                                v_5760 = check_bit(local_2c, 3)
                                if v_5760 == 0:
                                    local_2c = transform_a(local_2c)
                                    local_20 = (local_20 + 1)
                                else:
                                    local_2c = (local_2c - 5)
                                    local_20 = (local_20 + 1)
                            else:
                                local_2c = (local_2c << 1)
                                local_20 = (local_20 + 1)
        else:
            if local_24 & 1 != 0:
                v_5822 = transform_a(local_24)
            else:
                v_5822 = transform_b(local_2c)
            local_1c = 0
            while local_1c < 2:
                if v_5822 >> (local_1c & 31) & 1 == 0:
                    local_2c = (local_2c + (v_5822 >> 2))
                    local_1c = (local_1c + 1)
                else:
                    local_2c = (local_2c ^ 0xff)
                    local_1c = (local_1c + 1)
        v_1041 = ((local_28 + local_2c) % 0xa)
        if v_1041 != 7:
            local_24 = (local_24 + 1)
            local_28 = ((local_28 + local_2c) % 0xa)
        else:
            local_2c = (local_2c - 0x64)
            local_24 = (local_24 + 1)
            local_28 = ((local_28 + local_2c) % 0xa)
    printf('Final State: %d, Acc: %d\n', local_28, local_2c)
    return local_2c
