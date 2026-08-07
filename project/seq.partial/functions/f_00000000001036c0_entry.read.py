# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::entry
# Entry address: 0x1036c0

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def entry(param_0, param_1):
    abi_context = ABI.current('function_entry:1062592')
    abi_stack_pointer = abi_context.stack_pointer
    abi_overflow_arguments = abi_context.overflow_argument_area
    v_33 = (abi_stack_pointer - 8)
    v_66 = (abi_stack_pointer - -8)
    v_337 = (0 - 0x102740)
    PTR___libc_start_main_0010bfa0(v_337, param_1, v_33, 0, 0, param_0, v_66)
    while True:
        pass
