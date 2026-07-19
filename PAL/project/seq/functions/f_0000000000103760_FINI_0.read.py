# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_FINI_0
# Entry address: 0x103760

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def _FINI_0():
    abi_context = ABI.current('function_entry:1062752')
    if DAT_0010c0a0 != 0:
        return 0
    else:
        if PTR___cxa_finalize_0010bfe8 == 0:
            pass
        else:
            __cxa_finalize(PTR_LOOP_0010c008)
        FUN_001036f0()
        return 0
