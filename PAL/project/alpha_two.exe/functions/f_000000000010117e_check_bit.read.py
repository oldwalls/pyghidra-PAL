# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::check_bit
# Entry address: 0x10117e

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def check_bit(param_1, param_0):
    abi_context = ABI.current('function_entry:1053054')
    return ((param_1 >> (param_0 & 0x1f)) & 1)
