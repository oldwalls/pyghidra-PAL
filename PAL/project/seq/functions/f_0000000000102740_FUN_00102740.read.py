# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00102740
# Entry address: 0x102740

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00102740(param_0, param_1):
    abi_context = ABI.current('function_entry:1058624')
    abi_stack_pointer = abi_context.stack_pointer
    abi_st4 = abi_context.machine_state['ST4']
    abi_st3 = abi_context.machine_state['ST3']
    abi_st2 = abi_context.machine_state['ST2']
    abi_st1 = abi_context.machine_state['ST1']
    abi_st0 = abi_context.machine_state['ST0']
    abi_r14 = abi_context.machine_state['R14']
    abi_tls_base = abi_context.tls_base
    v_68260 = ((local_114 << 32) | local_118)
    v_10 = int2float(1)
    v_68261 = MEM64[param_1]
    local_40 = MEM64[(abi_tls_base + 0x28)]
    local_68 = v_10
    uStack_60 = (v_10 >> 0x40)
    local_58 = 1
    uStack_50 = (local_50 & -0x100000000)
    if v_68261 == 0:
        v_10958 = MEM64[PTR_stderr_0010bff0]
        fwrite(0x109a90, 1, 0x37, v_10958)
        abort()
    else:
        v_11243 = strrchr(v_68261, 0x2f)
        v_21649 = v_68261
        abi_st4 = in_ST4
        abi_st3 = in_ST3
        abi_st2 = in_ST2
        abi_st1 = in_ST1
        abi_st0 = in_ST0
        abi_tls_base = in_FS_OFFSET
        if v_11243 == 0:
            pass
        else:
            v_68266 = (v_11243 + (1 * 1))
            v_25128 = v_68266
            v_21649 = v_68261
            abi_st4 = in_ST4
            abi_st3 = in_ST3
            abi_st2 = in_ST2
            abi_st1 = in_ST1
            abi_st0 = in_ST0
            abi_tls_base = in_FS_OFFSET
            if 6 >= v_68266 - v_68261:
                pass
            else:
                v_322 = (v_11243 + (-6 * 1))
                v_11252 = strncmp(v_322, 0x109185, 7)
                v_21649 = v_68261
                abi_st4 = in_ST4
                abi_st3 = in_ST3
                abi_st2 = in_ST2
                abi_st1 = in_ST1
                abi_st0 = in_ST0
                abi_tls_base = in_FS_OFFSET
                if v_11252 != 0:
                    pass
                else:
                    v_11261 = strncmp(v_68266, 0x10918d, 3)
                    v_21649 = v_68266
                    if v_11261 == 0:
                        v_10939 = (v_11243 + (4 * 1))
                        MEM64[PTR_program_invocation_short_name_0010bfe0] <- v_10939
                        v_21649 = v_10939
        MEM64[PTR_program_invocation_name_0010bfd0] <- v_21649
        v_11269 = setlocale(6, 0x10914a)
        bindtextdomain(0x109082, 0x109191)
        v_21618 = 0
        textdomain(0x109082)
        v_67796 = (0 - 0x1084c0)
        FUN_001088b0(v_67796)
        v_532 = MEM32[PTR_optind_0010bfb8]
        v_25021 = v_11243
        if v_532 >= param_0:
            v_921 = MEM32[PTR_optind_0010bfb8]
            v_932 = (param_0 - v_921)
            if v_932 == 0:
                v_68302 = ((local_114 << 32) | local_118)
                v_20016 = dcgettext(0, 0x1091be, 5)
                error(0, 0, v_20016)
                v_67710 = v_68302
                FUN_001038a0(1)
            else:
                if 3 >= param_0 - v_921:
                    v_10661 = (param_1 + ((v_921 + 3) * 8))
                    v_10664 = MEM64[v_10661]
                    v_24886 = FUN_00108540(v_10664)
                    v_22270 = 0x1091ce
                    v_19974 = dcgettext(0, v_22270, 5)
                    error(0, 0, v_19974, v_24886)
                    v_67710 = v_67733
                    FUN_001038a0(1)
                else:
                    if v_21618 == 0:
                        v_21590 = v_21618
                        v_6415 = MEM32[PTR_optind_0010bfb8]
                        if param_0 - v_921 == 3:
                            v_39101 = FUN_00103d70()
                            if v_39101 == 0 or (v_39218 == 0 and v_39221):
                                v_67701 = 0
                            v_9811 = MEM32[PTR_optind_0010bfb8]
                            v_9819 = (param_1 + (v_9811 * 8))
                            v_9822 = MEM64[v_9819]
                            local_f8 = v_9822
                            local_f4 = (v_9822 >> 0x20)
                            v_39119 = FUN_00103d70(v_9822)
                            if v_39119 == 0:
                                v_68310 = (abi_stack_pointer - -0x88)
                                v_7008 = MEM32[PTR_optind_0010bfb8]
                                MEM32[PTR_optind_0010bfb8] <- (v_7008 + 1)
                                v_7029 = (param_1 + (v_7008 * 8))
                                v_7032 = MEM64[v_7029]
                                FUN_00108560(v_68310, v_7032)
                                local_70 = iStack_70
                                local_80 = uStack_80
                                v_7084 = MEM32[PTR_optind_0010bfb8]
                                local_d8 = local_88
                                local_d0 = uStack_80
                                if param_0 <= v_7084:
                                    local_108 = local_78
                                    MEM32[PTR_optind_0010bfb8] <- (v_7084 + 1)
                                    v_8462 = (param_1 + (v_7084 * 8))
                                    v_8465 = MEM64[v_8462]
                                    FUN_00108560(v_68310, v_8465)
                                    v_8522 = MEM32[PTR_optind_0010bfb8]
                                    local_e8 = local_88
                                    local_e7 = (local_88 >> 8)
                                    local_e0 = uStack_80
                                    v_24377 = local_78
                                    v_38889 = iStack_70
                                    if v_8522 < param_0:
                                        v_9091 = int2float(0)
                                        v_51306 = ((uStack_80 << 64) | local_88)
                                        uStack_50 = ((uStack_6c << 32) | iStack_70)
                                        local_68 = local_88
                                        uStack_60 = uStack_80
                                        local_58 = local_78
                                        v_9192 = float_equal(v_51306, v_9091)
                                        if v_9192:
                                            MEM32[PTR_optind_0010bfb8] <- (v_8522 + 1)
                                            v_9302 = (param_1 + (v_8522 * 8))
                                            v_9305 = MEM64[v_9302]
                                            FUN_00108560(v_68310, v_9305)
                                            local_e8 = local_88
                                            local_e7 = (local_88 >> 8)
                                            local_e0 = uStack_80
                                            v_24377 = local_78
                                            v_38889 = iStack_70
                                            v_40151 = bool_or((local_50 != 0), v_38869)
                                            v_8673 = bool_or(v_40151, (v_38889 != 0))
                                            v_20656 = v_20666
                                            if (local_50 != 0 or v_38869 != 0) or v_38889 != 0:
                                                if v_21590 == 0:
                                                    v_39322 = local_50
                                                    if local_50 <= v_38870:
                                                        pass
                                                    else:
                                                        v_39322 = v_38870
                                                    if v_39322 == 2147483647:
                                                        v_68331 = ((local_60 << 64) | local_68)
                                                        local_c8 = v_68331
                                                        v_20674 = v_20663
                                                    else:
                                                        if v_38891 == 2147483647:
                                                            v_68331 = ((local_60 << 64) | local_68)
                                                            local_c8 = v_68331
                                                            v_20674 = v_20663
                                                        else:
                                                            if DAT_0010c1ec == 0:
                                                                v_21596 = (0 - 0x10c1d0)
                                                                v_67920 = (0 - 0x10c1d0)
                                                                __sprintf_chk(v_67920, 1, 0x1c, 0x109233, v_67629)
                                                                v_68330 = ((uStack_60 << 64) | local_68)
                                                                local_c8 = v_68330
                                                                v_20674 = pcVar22
                                                            else:
                                                                v_2674 = (v_20660 + ((v_39935 - v_38871) * 1))
                                                                v_2734 = (v_24384 + ((v_39935 - v_38892) * 1))
                                                                if v_39935 != 0:
                                                                    if v_38892 != 0:
                                                                        pass
                                                                    else:
                                                                        v_2865 = (v_2734 + ((v_39935 != 0) * 1))
                                                                    if v_38871 != 0:
                                                                        pass
                                                                    else:
                                                                        v_20720 = (v_2674 + ((v_39935 != 0) * 1))
                                                                else:
                                                                    if v_38892 != 0:
                                                                        v_22336 = (v_2734 + (-1 * 1))
                                                                        v_20720 = (v_20660 + ((v_39935 - v_38871) * 1))
                                                                    else:
                                                                        v_2865 = (v_2734 + ((v_39935 != 0) * 1))
                                                                v_20710 = v_20720
                                                                if v_20720 < v_22336:
                                                                    pass
                                                                else:
                                                                    v_20710 = v_22336
                                                                v_20717 = v_20710
                                                                in_ST3 = abi_st3
                                                                in_ST2 = abi_st2
                                                                in_ST1 = abi_st1
                                                                in_ST0 = abi_st0
                                                                if v_20710 < 2147483648:
                                                                    v_21596 = (0 - 0x10c1d0)
                                                                    v_67923 = (0 - 0x10c1d0)
                                                                    __sprintf_chk(v_67923, 1, 0x1c, 0x109228, (v_20717 & 0xffffffff))
                                                                    v_68349 = ((uStack_60 << 64) | local_68)
                                                                    local_c8 = v_68349
                                                                    v_20674 = pcVar11
                                                                else:
                                                                    v_68331 = ((local_60 << 64) | local_68)
                                                                    local_c8 = v_68331
                                                                    v_20674 = v_20663
                                                else:
                                                    v_68327 = ((local_60 << 64) | local_68)
                                                    local_c8 = v_68327
                                                    v_20674 = v_20656
                                                    v_25090 = v_25043
                                                    v_24989 = v_24965
                                                    v_21596 = v_21590
                                                v_3131 = int2float(0)
                                                v_38907 = float_less(local_c8, v_3131)
                                                if v_38907:
                                                    v_53013 = ((local_d0 << 64) | local_d8)
                                                    v_51302 = ((local_e7 << 8) | local_e8)
                                                    v_51301 = ((local_e0 << 64) | v_51302)
                                                    v_39803 = float_less(v_53013, v_51301)
                                                else:
                                                    v_51282 = ((local_e7 << 8) | local_e8)
                                                    v_51281 = ((local_e0 << 64) | v_51282)
                                                    v_53004 = ((local_d0 << 64) | local_d8)
                                                    v_39803 = float_less(v_51281, v_53004)
                                                if v_39803:
                                                    v_5127 = MEM64[(abi_tls_base + 0x28)]
                                                    if local_40 != v_5127:
                                                        __stack_chk_fail()
                                                    else:
                                                        return 0
                                                else:
                                                    local_f0 = local_d0
                                                    local_108 = int2float(1)
                                                    v_67580 = 0
                                                    while not (4294967295 < v_39041 or v_67580):
                                                        v_39041 = __printf_chk(1, v_21596)
                                                        abi_st4 = in_ST4
                                                        abi_tls_base = in_FS_OFFSET
                                                        v_3668 = float_mult(local_108, local_c8)
                                                        v_53010 = ((local_d0 << 64) | local_d8)
                                                        v_3711 = float_add(v_53010, v_3668)
                                                        local_110 = (v_3711 >> 0x40)
                                                        v_3769 = int2float(0)
                                                        v_39046 = float_lessequal(v_3769, local_c8)
                                                        if v_39046:
                                                            v_51287 = ((local_e7 << 8) | local_e8)
                                                            v_51286 = ((local_e0 << 64) | v_51287)
                                                            v_38925 = float_less(v_51286, v_3711)
                                                            abi_st4 = in_ST4
                                                            abi_tls_base = in_FS_OFFSET
                                                            if v_38925:
                                                                v_4777 = MEM64[PTR_stdout_0010bfb0]
                                                                v_11664 = fputs_unlocked(DAT_0010c1f0, v_4777)
                                                                if v_11664 == 4294967295:
                                                                    break
                                                                else:
                                                                    v_4846 = int2float(1)
                                                                    local_108 = float_add(v_4846, local_108)
                                                                    local_f0 = local_110
                                                            else:
                                                                lVar27 = in_ST0
                                                                v_68231 = in_ST1
                                                                v_68234 = in_ST2
                                                                v_68237 = in_ST3
                                                                v_68240 = in_ST4
                                                                abi_tls_base = in_FS_OFFSET
                                                                if DAT_0010c1ed != 0:
                                                                    setlocale(1, 0x1090d9)
                                                                    lVar27 = in_ST0
                                                                    v_68231 = in_ST1
                                                                    v_68234 = in_ST2
                                                                    v_68237 = in_ST3
                                                                    v_68240 = in_ST4
                                                                    in_ST4 = lVar28
                                                                v_3992 = (abi_stack_pointer - -0x98)
                                                                v_38945 = FUN_00106d80(v_3992, v_21596)
                                                                abi_st4 = in_ST4
                                                                abi_tls_base = in_FS_OFFSET
                                                                if DAT_0010c1ed != 0:
                                                                    setlocale(1, 0x10914a)
                                                                if v_38945 < 0:
                                                                    break
                                                                else:
                                                                    v_4175 = (abi_stack_pointer - -0x90)
                                                                    v_4183 = (local_98 + ((v_38945 - v_25090) * 1))
                                                                    MEM8[v_4183] <- 0
                                                                    v_4194 = (local_98 + (v_24989 * 1))
                                                                    v_11607 = __errno_location()
                                                                    MEM32[v_11607] <- 0
                                                                    FUN_00103df0(v_4194, v_4175)
                                                        else:
                                                            v_51297 = ((local_e7 << 8) | local_e8)
                                                            v_51296 = ((local_e0 << 64) | v_51297)
                                                            v_39048 = float_less(v_3711, v_51296)
                                                            if v_39048:
                                                                pass
                                                    v_5061 = MEM64[PTR_stdout_0010bfb0]
                                                    v_11651 = fputs_unlocked(0x10a2ef, v_5061)
                                                    if v_11651 == 4294967295:
                                                        FUN_00103c60()
                                                        v_21596 = (0 - 0x10c1d0)
                                                        v_67923 = (0 - 0x10c1d0)
                                                        __sprintf_chk(v_67923, 1, 0x1c, 0x109228, (v_20717 & 0xffffffff))
                                                        v_68349 = ((uStack_60 << 64) | local_68)
                                                        local_c8 = v_68349
                                                        v_20674 = pcVar11
                                                    FUN_00103c60()
                                            else:
                                                v_8717 = float2float(0)
                                                v_53016 = ((local_80 << 64) | local_88)
                                                v_8763 = float_mult(v_53016, v_8717)
                                                v_8797 = float_equal(v_8763, v_8717)
                                                if v_8797:
                                                    if v_21590 == 0:
                                                        v_8897 = 0
                                                        if local_50 < v_8897:
                                                            pass
                                                        else:
                                                            v_39935 = v_8897
                                                        v_38892 = 0
                                                        v_24384 = v_24377
                                                        v_20660 = local_78
                                                        v_38871 = v_8897
                                                    else:
                                                        v_68331 = ((local_60 << 64) | local_68)
                                                        local_c8 = v_68331
                                                        v_20674 = v_20663
                                                else:
                                                    v_53022 = ((local_80 << 64) | local_88)
                                                    v_9019 = float_lessequal(v_8717, v_53022)
                                                    v_24390 = v_24377
                                                    v_20666 = local_78
                                                    if v_9019:
                                                        pass
                                                    else:
                                                        if v_7569 or (v_39371 and v_7760):
                                                            v_24380 = v_24390
                                                            v_20656 = local_78
                                        else:
                                            v_9406 = (param_1 + ((v_8522 + -1) * 8))
                                            v_9409 = MEM64[v_9406]
                                            v_24886 = FUN_00108540(v_9409)
                                            v_22270 = 0x109b60
                                            v_21641 = v_21590
                                            v_19974 = dcgettext(0, v_22270, 5)
                                            error(0, 0, v_19974, v_24886)
                                            v_67710 = v_67733
                                            FUN_001038a0(1)
                                else:
                                    local_e8 = local_88
                                    local_e7 = (local_88 >> 8)
                                    v_68012 = bool_and((iStack_70 == 0), (uStack_50 == 0))
                                    if v_38869 == 0 and local_50 == 0:
                                        v_20666 = 1
                                        local_e0 = uStack_80
                                        v_7468 = int2float(1)
                                        local_d8 = v_7468
                                        local_d0 = (v_7468 >> 0x40)
                                        abi_st4 = in_ST4
                                        abi_st3 = in_ST3
                                        abi_st2 = in_ST2
                                        abi_st1 = in_ST1
                                        abi_st0 = in_ST0
                                        abi_tls_base = in_FS_OFFSET
                                        v_24390 = local_78
                                    else:
                                        v_20656 = 1
                                        local_e0 = uStack_80
                                        v_7289 = int2float(1)
                                        local_d8 = v_7289
                                        local_d0 = (v_7289 >> 0x40)
                                        v_24380 = local_78
                                        v_38891 = iStack_70
                            else:
                                v_9921 = (param_1 + ((v_9811 + 1) * 8))
                                v_9924 = MEM64[v_9921]
                                v_39126 = FUN_00103d70(v_9924)
                                if v_39126 == 0:
                                    pass
                                else:
                                    if v_67701:
                                        pass
                                    else:
                                        v_10026 = (param_1 + ((v_9811 + 2) * 8))
                                        v_10029 = MEM64[v_10026]
                                        v_68082 = FUN_00103d70(v_10029)
                                        local_118 = MEM32[PTR_optind_0010bfb8]
                                        local_f8 = v_9822
                                        local_f4 = (v_9822 >> 0x20)
                                        local_80 = uStack_80
                                        local_70 = iStack_70
                                        local_6c = uStack_6c
                                        local_60 = uStack_60
                                        local_50 = uStack_50
                                        if v_68082 == 0:
                                            pass
                                        else:
                                            if DAT_0010c1ec == 1:
                                                pass
                                            else:
                                                if v_21590 != 0:
                                                    pass
                                                else:
                                                    v_11436 = strlen(DAT_0010c1f0)
                                                    if v_11436 != 1:
                                                        pass
                                                    else:
                                                        v_6680 = float2float(DAT_0010a2f8)
                                                        v_68309 = ((uStack_60 << 64) | local_68)
                                                        v_67562 = 0x10917f
                                                        v_67563 = 0
                                                        if param_0 - v_921 != 1:
                                                            pass
                                                        else:
                                                            v_67563 = local_f4
                                                            v_67562 = local_f8
                                                        if v_6771:
                                                            v_9563 = float_sub(v_68309, v_6680)
                                                            v_9635 = round(v_9563)
                                                            v_21236 = (v_9635 ^ -0x8000000000000000)
                                                        else:
                                                            v_6881 = round(v_68309)
                                                            v_21236 = v_6881
                                                        v_49570 = ((v_67563 << 32) | v_67562)
                                                        v_6950 = (param_1 + (((v_932 - 1) + local_118) * 8))
                                                        v_6953 = MEM64[v_6950]
                                                        v_38850 = FUN_00104140(v_49570, v_6953, v_21236)
                                                        if v_38850 != 0:
                                                            pass
                        else:
                            v_6458 = (param_1 + (v_6415 * 8))
                            v_6461 = MEM64[v_6458]
                            local_f8 = v_6461
                            local_f4 = (v_6461 >> 0x20)
                            v_38799 = FUN_00103d70(v_6461)
                            if v_38799 == 0:
                                pass
                            else:
                                if param_0 - v_921 != 1:
                                    v_9697 = (param_1 + ((v_6415 + 1) * 8))
                                    v_9700 = MEM64[v_9697]
                                    v_68082 = FUN_00103d70(v_9700)
                                    local_118 = MEM32[PTR_optind_0010bfb8]
                                    local_f8 = v_6461
                                    local_f4 = (v_6461 >> 0x20)
                                    local_80 = uStack_80
                                    local_70 = iStack_70
                                    local_6c = uStack_6c
                                    local_60 = uStack_60
                                    local_50 = uStack_50
                    else:
                        v_21293 = 1
                        v_20215 = 0
                        while True:
                            v_1053 = (v_21618 + (v_20215 * 1))
                            v_1056 = MEM8[v_1053]
                            v_68280 = (v_21293 + -1)
                            if v_1056 == 0:
                                v_68281 = FUN_00108540(v_21618)
                                v_19923 = dcgettext(0, 0x1091df, 5)
                                error(1, 0, v_19923, pcVar22)
                                break
                            else:
                                v_20681 = 1
                                v_25061 = v_68282
                        v_11333 = strspn(v_1108, 0x1091fd)
                        v_68285 = (v_68282 + v_11333)
                        v_1244 = (v_21618 + (v_68285 * 1))
                        v_11341 = strspn(v_1244, 0x1090bd)
                        v_21255 = (v_68285 + (v_11341 * 1))
                        v_1270 = (v_21618 + (v_21255 * 1))
                        v_1273 = MEM8[v_1270]
                        abi_st4 = in_ST4
                        abi_st3 = in_ST3
                        abi_st2 = in_ST2
                        abi_st1 = in_ST1
                        abi_st0 = in_ST0
                        abi_tls_base = in_FS_OFFSET
                        if v_1273 != 46:
                            pass
                        else:
                            v_1308 = (v_21255 + (1 * 1))
                            v_1316 = (v_21618 + (v_1308 * 1))
                            v_11349 = strspn(v_1316, 0x1090bd)
                            v_21255 = (v_1308 + (v_11349 * 1))
                        v_1366 = (v_21618 + (v_21255 * 1))
                        v_1369 = MEM8[v_1366]
                        v_68290 = (v_21255 + ((v_1369 == 0x4c) * 1))
                        v_25052 = v_68290
                        v_1413 = (v_21618 + (v_68290 * 1))
                        v_1426 = MEM8[v_1413]
                        if v_1426 == 0:
                            v_20007 = FUN_00108540(v_21618)
                            v_20010 = dcgettext(0, 0x109204, 5)
                            error(1, 0, v_20010, v_20007)
                            local_108 = (v_21618 + (v_68290 * 1))
                            v_68302 = ((local_114 << 32) | local_118)
                            v_20016 = dcgettext(0, 0x1091be, 5)
                            error(0, 0, v_20016)
                            v_67710 = v_68302
                            FUN_001038a0(1)
                        else:
                            local_118 = v_1426
                            v_11357 = strchr(0x109219, local_118)
                            v_22926 = (v_68290 + 1)
                            v_20123 = 1
                            abi_st4 = in_ST4
                            abi_st3 = in_ST3
                            abi_st2 = in_ST2
                            abi_st1 = in_ST1
                            abi_st0 = in_ST0
                            abi_tls_base = in_FS_OFFSET
                            if v_11357 != 0:
                                while True:
                                    v_5982 = (v_21618 + (v_22926 * 1))
                                    v_5985 = MEM8[v_5982]
                                    v_68295 = (v_20123 + -1)
                                    if v_5985 == 0:
                                        break
                                    else:
                                        v_20596 = 1
                                v_6278 = (v_22926 + (2 * 1))
                                v_68297 = FUN_001040e0(v_6278)
                                v_21590 = memcpy(v_68297, v_21618, v_21255)
                                local_118 = v_21590
                                local_114 = (v_21590 >> 0x20)
                                v_6349 = (v_21590 + (v_21255 * 1))
                                MEM8[v_6349] <- 0x4c
                                v_6357 = (v_21590 + (1 * 1))
                                v_6363 = (v_21255 + (v_6357 * 1))
                                strcpy(v_6363, v_1413)
                                abi_st4 = in_ST4
                                abi_st3 = in_ST3
                                abi_st2 = in_ST2
                                abi_st1 = in_ST1
                                abi_st0 = in_ST0
                                abi_tls_base = in_FS_OFFSET
                                if DAT_0010c1ec != 0:
                                    v_19932 = dcgettext(0, 0x109b18, 5)
                                    error(0, 0, v_19932)
                                    FUN_001038a0(1)
                                    v_19989 = FUN_00108540(v_21618)
                                    v_19992 = dcgettext(0, 0x109af0, 5)
                                    error(1, 0, v_19992, v_19989)
                                    v_25049 = v_68290
                                    v_19998 = FUN_00108540(v_21618)
                                    v_20001 = dcgettext(0, 0x109ac8, 5)
                                    error(1, 0, v_20001, v_19998, local_118)
                                    v_20007 = FUN_00108540(v_21618)
                                    v_20010 = dcgettext(0, 0x109204, 5)
                                    error(1, 0, v_20010, v_20007)
                                    local_108 = (v_21618 + (v_68290 * 1))
                                    v_68302 = ((local_114 << 32) | local_118)
                                    v_20016 = dcgettext(0, 0x1091be, 5)
                                    error(0, 0, v_20016)
                                    v_67710 = v_68302
                                    FUN_001038a0(1)
                                v_19989 = FUN_00108540(v_21618)
                                v_19992 = dcgettext(0, 0x109af0, 5)
                                error(1, 0, v_19992, v_19989)
                                v_25049 = v_68290
                                v_19998 = FUN_00108540(v_21618)
                                v_20001 = dcgettext(0, 0x109ac8, 5)
                                error(1, 0, v_20001, v_19998, local_118)
                                v_20007 = FUN_00108540(v_21618)
                                v_20010 = dcgettext(0, 0x109204, 5)
                                error(1, 0, v_20010, v_20007)
                                local_108 = (v_21618 + (v_68290 * 1))
                                v_68302 = ((local_114 << 32) | local_118)
                                v_20016 = dcgettext(0, 0x1091be, 5)
                                error(0, 0, v_20016)
                                v_67710 = v_68302
                                FUN_001038a0(1)
                                v_1912 = (abi_stack_pointer - -0xa8)
                                v_39549 = FUN_00106d80(v_1912, v_21603)
                                v_24314 = local_108
                                if v_39549 >= 0:
                                    v_2069 = MEM8[local_a0]
                                    if v_2069 == 45:
                                        free(local_a0)
                                        free(local_a8)
                                        v_38891 = 0
                                        v_38870 = 0
                                        v_24384 = v_24314
                                    else:
                                        v_2102 = MEM8[local_a8]
                                        if v_2102 == 45:
                                            free(local_a0)
                                            free(local_a8)
                                            v_38891 = 0
                                            v_38870 = 0
                                            v_24384 = v_24314
                                        else:
                                            v_2155 = float2float(DAT_0010a2f8)
                                            v_2196 = float_lessequal(v_2155, local_c8)
                                            if v_2196:
                                                v_5867 = float_sub(local_c8, v_2155)
                                                v_5926 = round(v_5867)
                                                v_21313 = (v_5926 ^ -0x8000000000000000)
                                            else:
                                                v_2295 = round(local_c8)
                                                v_21313 = v_2295
                                            v_39287 = FUN_00104140(local_a0, local_a8, v_21313)
                                            if v_39287 != 0:
                                                pass
                                            else:
                                                free(local_a0)
                                                free(local_a8)
                                                v_38891 = 0
                                                v_38870 = 0
                                                v_24384 = v_24314
                                else:
                                    FUN_00103db0()
                            else:
                                v_19998 = FUN_00108540(v_21618)
                                v_20001 = dcgettext(0, 0x109ac8, 5)
                                error(1, 0, v_20001, v_19998, local_118)
                                v_20007 = FUN_00108540(v_21618)
                                v_20010 = dcgettext(0, 0x109204, 5)
                                error(1, 0, v_20010, v_20007)
                                local_108 = (v_21618 + (v_68290 * 1))
                                v_68302 = ((local_114 << 32) | local_118)
                                v_20016 = dcgettext(0, 0x1091be, 5)
                                error(0, 0, v_20016)
                                v_67710 = v_68302
                                FUN_001038a0(1)
        else:
            v_573 = (0 - 0x10bb20)
            v_39736 = MEM32[PTR_optind_0010bfb8]
            while True:
                v_580 = (param_1 + (v_39736 * 8))
                v_68274 = MEM64[v_580]
                v_588 = MEM8[v_68274]
                v_67913 = (0 - 0x10bb20)
                v_38635 = getopt_long(param_0, param_1, 0x1091a3, v_67913, 0)
                abi_st4 = in_ST4
                abi_st3 = in_ST3
                abi_st2 = in_ST2
                abi_st1 = in_ST1
                abi_st0 = in_ST0
                abi_tls_base = in_FS_OFFSET
                v_21618 = v_21624
                if v_38635 == 4294967295:
                    break
                v_39736 = MEM32[PTR_optind_0010bfb8]
                v_21618 = v_21614
                if v_39736 < param_0:
                    pass
                else:
                    break
