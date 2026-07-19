from PALhelpers import c_add, c_and, c_eq, c_load, c_lshr, c_mul, c_or, c_return_bits, c_sext, c_slt, c_ult, c_xor, c_zext

def process_payload_block(param_0, param_1, param_2):
    parity_state = 0
    if c_eq(param_1, 0, 64):
        result = 0
    else:
        if not c_slt(param_2, 1, 32):
            checksum = param_0
            ptr_offset = 0
            while c_slt(ptr_offset, param_2, 32):
                current_byte = c_load(MEM, c_add(param_1, c_sext(ptr_offset, 32, 64), 64), 8)
                tmp_mix = c_add(c_xor(c_zext(current_byte, 8, 32), checksum, 32), 0x1f, 32)
                checksum = c_or(c_mul(tmp_mix, 8, 32), c_lshr(tmp_mix, 0x1d, 32), 32)
                if not c_eq(c_and(current_byte, 1, 8), 0, 8):
                    parity_state = c_xor(parity_state, 0x55, 32)
                    ptr_offset = c_add(ptr_offset, 1, 32)
                else:
                    parity_state = c_add(parity_state, 1, 32)
                    ptr_offset = c_add(ptr_offset, 1, 32)
            if c_ult(parity_state, 11, 32):
                result = c_add(checksum, parity_state, 32)
            else:
                result = c_xor(checksum, 0xa5a5a5a5, 32)
        else:
            result = 0
    return c_return_bits(result, 32)
