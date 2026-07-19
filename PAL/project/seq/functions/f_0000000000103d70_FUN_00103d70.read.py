# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103d70
# Entry address: 0x103d70

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00103d70(param_0):
    abi_context = ABI.current('function_entry:1064304')
    v_0 = MEM8[param_0]
    if v_0 - 48 >= 10:
        return 0
    else:
        v_238 = strlen(param_0)
        v_246 = strspn(param_0, 0x1090bd)
        return (v_246 == v_238)
