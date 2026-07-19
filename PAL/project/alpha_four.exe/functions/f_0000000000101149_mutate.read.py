# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::mutate
# Entry address: 0x101149

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def mutate(param_0):
    abi_context = ABI.current('function_entry:1053001')
    return ((param_0 * 2) ^ 0x55)
