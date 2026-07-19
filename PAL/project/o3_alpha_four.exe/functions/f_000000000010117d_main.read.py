# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::main
# Entry address: 0x10117d

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def main():
    abi_context = ABI.current('function_entry:1053053')
    local_20 = 0x10
    local_1c = 0x20
    local_18 = 0
    local_14 = 0
    while True:
        local_20 = mutate((local_14 + local_20))
        local_10 = 0
        while not (9 < local_10 or local_1c < 1):
            v_3988 = feedback(local_20, local_10)
            if v_3988 ^ local_1c % 3 != 0:
                v_1176 = (v_3988 & 7)
                local_18 = v_3988
                if v_3988 & 7 == 3:
                    local_18 = v_3988
                    while local_18 >= 1:
                        local_18 = mutate((local_18 >> 1))
                        if local_18 == 15:
                            break
                else:
                    if v_3988 & 7 >= 4:
                        local_20 = (local_20 - local_1c)
                        local_18 = v_3988
                    else:
                        if v_3988 & 7 >= 2:
                            if v_3988 & 7 == 2:
                                local_1c = (local_1c + 5)
                                local_18 = v_3988
                            else:
                                local_20 = (local_20 - local_1c)
                                local_18 = v_3988
                        else:
                            local_20 = (local_20 ^ 0xaa)
                            local_1c = (local_1c + 5)
                            local_18 = v_3988
                if 4294967295 >= local_20:
                    local_20 = 0
                    break
            else:
                local_1c = (local_1c - 2)
                local_18 = v_3988
                local_10 = (local_10 + 1)
                continue
            local_10 = (local_10 + 1)
        v_4653 = local_20
        if local_14 & 1 == 0:
            pass
        else:
            local_20 = local_1c
            local_1c = v_4653
        local_14 = (local_14 + 1)
        if 4 >= local_14:
            pass
        else:
            if 99 >= local_20:
                pass
            else:
                break
    printf(0x102004, local_20, local_1c, local_18)
    return (local_1c + local_20)
