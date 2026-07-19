# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::check_bit
# Entry address: 0x10117e

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def check_bit(param_0, param_1):
    return ((param_0 >> (param_1 & 0x1f)) & 1)
