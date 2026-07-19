# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00103ff0
# Entry address: 0x103ff0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00103ff0(param_0, param_1):
    abi_context = ABI.current('function_entry:1064944')
    v_2204 = nl_langinfo(0xe)
    if v_2204 == 0:
        v_1573 = (0 - 0x1090e2)
        if param_1 != 9:
            pass
        else:
            v_1573 = (0 - 0x109202)
        return v_1573
    else:
        v_86 = MEM8[v_2204]
        if v_86 == 0:
            pass
        else:
            v_1936 = (v_86 & 0xdf)
            if v_1936 != 85:
                if v_86 & 223 != 71:
                    pass
                else:
                    v_644 = (v_2204 + (1 * 1))
                    v_647 = MEM8[v_644]
                    if v_647 & 223 == 66:
                        v_708 = (v_2204 + (2 * 1))
                        v_711 = MEM8[v_708]
                        if v_711 != 49:
                            pass
                        else:
                            v_746 = (v_2204 + (3 * 1))
                            v_749 = MEM8[v_746]
                            if v_749 != 56:
                                pass
                            else:
                                v_784 = (v_2204 + (4 * 1))
                                v_787 = MEM8[v_784]
                                if v_787 != 48:
                                    pass
                                else:
                                    v_822 = (v_2204 + (5 * 1))
                                    v_825 = MEM8[v_822]
                                    if v_825 != 51:
                                        pass
                                    else:
                                        v_860 = (v_2204 + (6 * 1))
                                        v_863 = MEM8[v_860]
                                        if v_863 != 48:
                                            pass
                                        else:
                                            v_2055 = FUN_001037b0(v_2204, 0x1090ec, 0, 0)
                                            if v_2055 == 0:
                                                pass
                                            else:
                                                v_986 = MEM8[param_0]
                                                v_1551 = (0 - 0x1090e4)
                                                if v_986 != 96:
                                                    pass
                                                else:
                                                    v_1551 = (0 - 0x1090df)
                                                return v_1551
            else:
                v_175 = (v_2204 + (1 * 1))
                v_178 = MEM8[v_175]
                if v_178 & 223 != 84:
                    pass
                else:
                    v_241 = (v_2204 + (2 * 1))
                    v_244 = MEM8[v_241]
                    if v_244 & 223 != 70:
                        pass
                    else:
                        v_307 = (v_2204 + (3 * 1))
                        v_310 = MEM8[v_307]
                        if v_310 != 45:
                            pass
                        else:
                            v_345 = (v_2204 + (4 * 1))
                            v_348 = MEM8[v_345]
                            if v_348 != 56:
                                pass
                            else:
                                v_383 = (v_2204 + (5 * 1))
                                v_386 = MEM8[v_383]
                                if v_386 != 0:
                                    pass
                                else:
                                    v_421 = MEM8[param_0]
                                    v_1570 = (0 - 0x1090e8)
                                    if v_421 != 96:
                                        pass
                                    else:
                                        v_1570 = (0 - 0x1090db)
                                    return v_1570
