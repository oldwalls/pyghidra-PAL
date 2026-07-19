# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_init
# Entry address: 0x101000

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def _init(param_0):
    abi_context = ABI.current('function_entry:1052672')
    v_212 = 0
    if PTR___gmon_start___00103fe8 == 0:
        pass
    else:
        v_212 = PTR___gmon_start___00103fe8()
    return v_212
