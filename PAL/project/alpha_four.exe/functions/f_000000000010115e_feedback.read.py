# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::feedback
# Entry address: 0x10115e

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def feedback(param_0, param_1):
    abi_context = ABI.current('function_entry:1053022')
    return (param_0 + (param_1 * 0xfffffffd))
