# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103ca0
# Entry address: 0x103ca0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00103ca0():
    abi_context = ABI.current('function_entry:1064096')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    v_74 = (abi_stack_pointer - -0x128)
    local_20 = MEM64[(abi_tls_base + 0x28)]
    v_538 = setlocale(0, 0)
    if v_538 == 0:
        v_1382 = 0
        abi_tls_base = in_FS_OFFSET
    else:
        v_1382 = 0
        v_545 = strlen(v_538)
        abi_tls_base = in_FS_OFFSET
        if v_545 < 257:
            v_1398 = __memcpy_chk(v_74, v_538, (v_545 + 1), 0x101)
            if local_128 == 67:
                if local_127 == 0:
                    pass
                else:
                    v_558 = strcmp(v_1398, 0x1090b7)
                    v_1382 = (v_558 != 0)
            else:
                v_558 = strcmp(v_1398, 0x1090b7)
                v_1382 = (v_558 != 0)
    v_262 = MEM64[(abi_tls_base + 0x28)]
    if local_20 != v_262:
        __stack_chk_fail()
    else:
        return v_1382
