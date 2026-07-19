# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::main
# Entry address: 0x1011e4

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def main():
    abi_context = ABI.current('function_entry:1053156')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    local_10 = MEM64[(abi_tls_base + 0x28)]
    local_18 = 0x78563412efbeadde
    v_96 = (abi_stack_pointer - -0x18)
    v_397 = process_payload_block(0x10203040, v_96, 8)
    v_168 = MEM64[(in_FS_OFFSET + 0x28)]
    if local_10 == v_168:
        return v_397
    else:
        __stack_chk_fail()
