# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_DT_INIT
# Entry address: 0x102000

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def _DT_INIT():
    abi_context = ABI.current('function_entry:1056768')
    if PTR___gmon_start___0010bfc8 == 0:
        pass
    else:
        PTR___gmon_start___0010bfc8()
    return 0
