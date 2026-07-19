# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00104560
# Entry address: 0x104560

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00104560(param_0):
    abi_context = ABI.current('function_entry:1066336')
    v_1863 = __fpending()
    v_1107 = fileno(param_0)
    if v_1107 < 0 or (v_2946 != 0 and v_1128 == -1):
        v_3626 = fclose(param_0)
        if v_50 & 32 != 0:
            if v_3626 != 0:
                pass
            return 0xffffffff
        else:
            if v_3626 == 0:
                return 0
            else:
                if v_1863 != 0:
                    return 0xffffffff
                else:
                    v_1197 = __errno_location()
                    v_432 = MEM32[v_1197]
                    return (-(v_432 != 9))
    else:
        v_2952 = __freading(param_0)
        if v_2952 != 0:
            v_3643 = (param_0 - 0)
            v_645 = MEM32[v_3643]
            if v_645 & 256 == 0:
                pass
            else:
                if v_681 == v_673 or (v_764 == v_756 and v_802 == 0):
                    fseeko(param_0, 0, 1)
        v_1165 = fflush(param_0)
        if v_1165 == 0:
            v_3626 = fclose(param_0)
        else:
            v_1178 = __errno_location()
            v_243 = MEM32[v_1178]
            v_3626 = fclose(param_0)
            if v_243 == 0:
                pass
            else:
                MEM32[v_1178] <- v_243
                if v_50 & 32 == 0:
                    pass
                else:
                    return 0xffffffff
