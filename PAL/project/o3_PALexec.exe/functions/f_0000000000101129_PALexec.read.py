# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::PALexec
# Entry address: 0x101129

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def PALexec(param_0, param_1, param_2):
    local_22 = param_0
    local_21 = param_1
    local_1e = param_0
    local_1c = 0x12345678
    local_18 = 0x80000000
    local_14 = 0
    local_20 = param_2
    while 2 >= local_14:
        if param_0 < param_1 and local_21 < local_22 or param_2 < 0:
            local_1c = (param_1 + (local_1c ^ 0x5f5f5f5f))
            v_4149 = local_18
        else:
            v_4149 = param_0
            if local_18 == 0:
                pass
            else:
                v_4149 = (local_18 / param_1)
        local_18 = v_4149
        local_10 = 0
        while local_10 + 1 < 3:
            local_10 = (local_10 + 1)
            local_21 = (local_21 >> 2)
            local_22 = (local_22 >> 2)
            local_20 = (local_20 << 5)
            if local_20 & 61440 == 0:
                pass
            else:
                local_1c = (local_1c | (local_21 ^ local_22))
        v_1443 = (local_1c & 3)
        if v_1443 == 2:
            local_18 = (local_18 % (local_1e | 1))
            local_14 = (local_14 + 1)
        else:
            if local_1c & 3 >= 3:
                local_1c = (~local_1c)
                local_14 = (local_14 + 1)
            else:
                if local_1c & 3 == 0:
                    local_1e = (param_2 + local_1e)
                    local_20 = (local_20 ^ 0xaaaa)
                    local_14 = (local_14 + 1)
                else:
                    if local_1c & 3 == 1:
                        local_20 = (local_20 ^ 0xaaaa)
                        local_14 = (local_14 + 1)
                    else:
                        local_1c = (~local_1c)
                        local_14 = (local_14 + 1)
    return ((local_20 | ((local_22 << 0x18) | (local_21 << 0x10))) + (local_18 ^ local_1c))
