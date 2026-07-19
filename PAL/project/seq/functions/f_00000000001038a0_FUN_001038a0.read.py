# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_001038a0
# Entry address: 0x1038a0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def FUN_001038a0(param_0):
    abi_context = ABI.current('function_entry:1063072')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    v_60 = (abi_stack_pointer - -0xb8)
    local_40 = MEM64[(abi_tls_base + 0x28)]
    if param_0 == 0:
        v_2536 = dcgettext(0, 0x109290, 5)
        __printf_chk(1, v_2536, DAT_0010c1f8, DAT_0010c1f8, DAT_0010c1f8)
        v_361 = MEM64[PTR_stdout_0010bfb0]
        v_9892 = dcgettext(0, 0x1092f8, 5)
        fputs_unlocked(v_9892, v_361)
        v_386 = MEM64[PTR_stdout_0010bfb0]
        v_9894 = dcgettext(0, 0x109338, 5)
        fputs_unlocked(v_9894, v_386)
        v_441 = MEM64[PTR_stdout_0010bfb0]
        v_9896 = dcgettext(0, 0x109388, 5)
        fputs_unlocked(v_9896, v_441)
        v_496 = MEM64[PTR_stdout_0010bfb0]
        v_9898 = dcgettext(0, 0x109460, 5)
        fputs_unlocked(v_9898, v_496)
        v_551 = MEM64[PTR_stdout_0010bfb0]
        v_9900 = dcgettext(0, 0x109490, 5)
        fputs_unlocked(v_9900, v_551)
        v_606 = MEM64[PTR_stdout_0010bfb0]
        v_9902 = dcgettext(0, 0x1094c8, 5)
        fputs_unlocked(v_9902, v_606)
        v_661 = MEM64[PTR_stdout_0010bfb0]
        v_9904 = dcgettext(0, 0x1096d0, 5)
        fputs_unlocked(v_9904, v_661)
        local_58 = 0
        local_b8 = (0 - 0x109008)
        local_b0 = 0x10900a
        local_a8 = 0x109082
        local_a0 = 0x10901a
        local_88 = 0x109049
        local_98 = 0x109030
        local_78 = 0x109053
        local_90 = 0x10903a
        local_80 = 0x10903a
        local_70 = 0x10903a
        local_68 = 0x10905d
        local_60 = 0x10903a
        local_50 = 0
        v_9889 = v_60
        while v_848 != 0:
            v_845 = (v_9889 + (0x10 * 1))
            v_848 = MEM64[v_845]
            v_859 = (v_9889 + (0x10 * 1))
            v_1883 = strcmp(0x109004, v_848)
            v_9889 = v_859
            if v_1883 != 0:
                pass
            else:
                break
        v_943 = (v_9889 + (0x18 * 1))
        v_946 = MEM64[v_943]
        if v_946 == 0:
            v_2587 = dcgettext(0, 0x109067, 5)
            __printf_chk(1, v_2587, 0x10907e, 0x1097a0)
            v_1901 = setlocale(5, 0)
            if v_1901 == 0:
                v_2596 = dcgettext(0, 0x109090, 5)
                v_1650 = (0 - 0x109004)
                v_9729 = (0 - 0x109004)
                __printf_chk(1, v_2596, 0x1097a0, v_9729)
            else:
                v_1910 = strncmp(v_1901, 0x10908c, 3)
                if v_1910 != 0:
                    v_1663 = (0 - 0x109004)
                    v_1366 = MEM64[PTR_stdout_0010bfb0]
                    v_9910 = dcgettext(0, 0x1097c8, 5)
                    fputs_unlocked(v_9910, v_1366)
                else:
                    v_2596 = dcgettext(0, 0x109090, 5)
                    v_1650 = (0 - 0x109004)
                    v_9729 = (0 - 0x109004)
                    __printf_chk(1, v_2596, 0x1097a0, v_9729)
        else:
            v_2602 = dcgettext(0, 0x109067, 5)
            __printf_chk(1, v_2602, 0x10907e, 0x1097a0)
            v_1938 = setlocale(5, 0)
            v_3764 = MEM64[v_943]
            if v_1938 == 0:
                pass
            else:
                v_1947 = strncmp(v_1938, 0x10908c, 3)
                v_3764 = MEM64[v_943]
                if v_1947 != 0:
                    v_1366 = MEM64[PTR_stdout_0010bfb0]
                    v_9910 = dcgettext(0, 0x1097c8, 5)
                    fputs_unlocked(v_9910, v_1366)
            v_2617 = dcgettext(0, 0x109090, 5)
            v_9723 = (0 - 0x109004)
            __printf_chk(1, v_2617, 0x1097a0, v_9723)
            v_9726 = (0 - 0x109004)
            if v_3764 != v_9726:
                pass
            else:
                pass
        v_2623 = dcgettext(0, 0x109810, 5)
        __printf_chk(1, v_2623, v_3757, v_3736)
    else:
        v_2629 = dcgettext(0, 0x109268, 5)
        v_194 = MEM64[PTR_stderr_0010bff0]
        __fprintf_chk(v_194, 1, v_2629, DAT_0010c1f8)
    exit(param_0)
