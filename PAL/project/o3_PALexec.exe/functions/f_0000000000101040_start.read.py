# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::_start
# Entry address: 0x101040

# PAL readable projection (non-executable)
# Width/sign contracts remain available in PAL provenance metadata

def _start(param_0, param_1):
    abi_context = ABI.current('function_entry:1052736')
    abi_stack_pointer = abi_context.stack_pointer
    abi_overflow_arguments = abi_context.overflow_argument_area
    v_33 = (abi_stack_pointer - 8)
    v_66 = (abi_stack_pointer - -8)
    v_337 = (0 - 0x101273)
    PTR___libc_start_main_00103fd8(v_337, param_1, v_33, 0, 0, param_0, v_66)
    while True:
        pass
