# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103f60
# Entry address: 0x103f60

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00103f60(param_0, param_1):
    abi_context = ABI.current('function_entry:1064800')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    abi_st0 = abi_context.machine_state['ST0']
    v_34 = (abi_stack_pointer - -0x28)
    local_20 = MEM64[(abi_tls_base + 0x28)]
    v_504 = __errno_location()
    MEM32[v_504] <- 0
    FUN_00103df0(param_0, v_34)
    v_1171 = 0
    if param_0 == local_28:
        pass
    else:
        v_184 = MEM8[local_28]
        if v_184 == 0:
            v_369 = int2float(0)
            v_404 = float_notequal(in_ST0, v_369)
            v_1171 = 1
            if v_404:
                v_451 = MEM32[v_504]
                v_1171 = (v_451 != 0x22)
    MEM80[param_1] <- in_ST0
    v_267 = MEM64[(in_FS_OFFSET + 0x28)]
    if local_20 != v_267:
        __stack_chk_fail()
    else:
        return v_1171
