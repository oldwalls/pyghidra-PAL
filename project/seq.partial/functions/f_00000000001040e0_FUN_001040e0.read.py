# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_001040e0
# Entry address: 0x1040e0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_001040e0(param_0):
    abi_context = ABI.current('function_entry:1065184')
    v_116 = malloc(param_0)
    if v_116 != 0:
        return 0
    else:
        if param_0 != 0:
            FUN_00103db0()
