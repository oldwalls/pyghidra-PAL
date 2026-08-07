# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00104100
# Entry address: 0x104100

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00104100(param_0, param_1):
    abi_context = ABI.current('function_entry:1065216')
    if param_1 != 0:
        v_236 = realloc(param_0, param_1)
        if v_236 != 0:
            return v_236
        else:
            if param_1 != 0:
                FUN_00103db0()
    else:
        if param_0 != 0:
            free(param_0)
            return 0
