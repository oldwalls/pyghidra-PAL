# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_001084c0
# Entry address: 0x1084c0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_001084c0():
    abi_context = ABI.current('function_entry:1082560')
    v_10 = MEM64[PTR_stdout_0010bfb0]
    v_693 = FUN_00104560(v_10)
    if v_693 == 0:
        v_184 = MEM64[PTR_stderr_0010bff0]
        v_728 = FUN_00104560(v_184)
        if v_728 != 0:
            _exit(DAT_0010c024)
        else:
            return 0
    else:
        v_352 = dcgettext(0, 0x1090ab, 5)
        v_306 = __errno_location()
        v_127 = MEM32[v_306]
        error(0, v_127, 0x109176, v_352)
        _exit(DAT_0010c024)
