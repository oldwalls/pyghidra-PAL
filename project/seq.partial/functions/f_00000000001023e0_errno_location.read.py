# PAL readable projection; this file is not execution authority.
# Ghidra function: <EXTERNAL>::__errno_location
# Entry address: 0x1023e0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def __errno_location():
    abi_context = ABI.current('function_entry:1057760')
    v_28 = PTR___errno_location_0010be00()
    return v_28
