# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::frame_dummy
# Entry address: 0x101120

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def frame_dummy():
    abi_context = ABI.current('function_entry:1052960')
    register_tm_clones()
    return 0
