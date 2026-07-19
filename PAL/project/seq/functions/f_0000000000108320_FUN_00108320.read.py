# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00108320
# Entry address: 0x108320

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00108320(param_0, param_1, param_2):
    abi_context = ABI.current('function_entry:1082144')
    v_1378 = __errno_location()
    v_102 = MEM32[v_1378]
    v_2088 = PTR_DAT_0010c090
    if DAT_0010c020 <= param_0:
        v_730 = MEM32[param_2]
        v_737 = (param_2 + (2 * 4))
        v_750 = (v_2088 + ((param_0 * 2) * 8))
        v_770 = (param_2 + (1 * 4))
        v_773 = MEM32[v_770]
        v_782 = MEM64[v_750]
        v_787 = (v_750 + (1 * 8))
        v_3996 = MEM64[v_787]
        v_2331 = v_3996
        v_795 = (param_2 + (0xc * 4))
        v_798 = MEM64[v_795]
        v_809 = (param_2 + (0xa * 4))
        v_812 = MEM64[v_809]
        v_1868 = FUN_00106e80(v_3996, v_782, param_1, v_730, (v_773 | 1), v_737, v_812, v_798)
        if v_782 > v_1868:
            MEM32[v_1378] <- v_102
            return v_2331
        else:
            v_934 = (v_1868 + 1)
            MEM64[v_750] <- v_934
            v_3946 = (0 - 0x10c0c0)
            if v_3996 == v_3946:
                pass
            else:
                free(v_3996)
            v_1420 = malloc(v_934)
            if v_1420 != 0:
                v_1086 = (v_750 + (1 * 8))
                MEM64[v_1086] <- v_1420
                v_1094 = MEM32[param_2]
                v_1105 = (param_2 + (0xc * 4))
                v_1108 = MEM64[v_1105]
                v_1125 = (param_2 + (0xa * 4))
                v_1128 = MEM64[v_1125]
                FUN_00106e80(v_1420, v_934, param_1, v_1094, (v_773 | 1), v_737, v_1128, v_1108)
                v_2331 = v_1420
                MEM32[v_1378] <- v_102
                return v_2331
            else:
                if v_1868 + 1 != 0:
                    FUN_00103db0()
                else:
                    v_1086 = (v_750 + (1 * 8))
                    MEM64[v_1086] <- v_1420
                    v_1094 = MEM32[param_2]
                    v_1105 = (param_2 + (0xc * 4))
                    v_1108 = MEM64[v_1105]
                    v_1125 = (param_2 + (0xa * 4))
                    v_1128 = MEM64[v_1125]
                    FUN_00106e80(v_1420, v_934, param_1, v_1094, (v_773 | 1), v_737, v_1128, v_1108)
                    v_2331 = v_1420
                    MEM32[v_1378] <- v_102
                    return v_2331
    else:
        v_153 = (param_0 + 1)
        v_167 = (v_153 << 4)
        v_3943 = (0 - 0x10c080)
        if PTR_DAT_0010c090 == v_3943:
            v_1385 = malloc(v_167)
            if v_1385 == 0:
                FUN_00103db0()
            else:
                MEM64[v_1385] <- DAT_0010c080
                v_3070 = (v_1385 + (1 * 8))
                MEM64[v_3070] <- PTR_DAT_0010c088
                v_3991 = PTR_DAT_0010c090
                v_2085 = v_1385
                v_611 = (v_2085 + ((DAT_0010c020 * 2) * 8))
                memset(v_611, 0, ((v_153 - DAT_0010c020) << 4))
                DAT_0010c020 = v_153
                v_2088 = v_2085
        else:
            v_2085 = realloc(PTR_DAT_0010c090, v_167)
            v_3991 = v_2085
            if v_2085 == 0:
                FUN_00103db0()
            else:
                v_611 = (v_2085 + ((DAT_0010c020 * 2) * 8))
                memset(v_611, 0, ((v_153 - DAT_0010c020) << 4))
                DAT_0010c020 = v_153
                v_2088 = v_2085
