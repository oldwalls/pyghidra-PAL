# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::transform_b
# Entry address: 0x10115e

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def transform_b(param_0):
    abi_context = ABI.current('function_entry:1053022')
    return ((param_0 >> 1) + (param_0 * 7))
