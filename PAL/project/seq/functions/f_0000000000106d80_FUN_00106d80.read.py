# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::FUN_00106d80
# Entry address: 0x106d80

#======= PAL stack versioning ======
# PALStaticStringPublisher = static_strings_v1_defined_ghidra_data
# PALBatchDecompiler = batch_v2d_explicit_stdio_overlay_authority
# PALHumanizer = humanizer_v2_oncs_varnames_recovery
# PALDecompilerPipeline = unknown
# PALlibrary.PALLifter = unknown
# PALlibrary.FunctionCFG = unknown
# PALSymbolResolver = unknown
# PALRawAudit = unknown
# PALCompute = v23b_abi_thunk_compatibility_return_reconciliation
# PALSemanticGraphBuilder = unknown
# PALSGLdecomp = unknown
# PALPHIfolder = v23_abi_f_entry_state_convergence_custody
# PALemitter = v46p_immutable_abi_context_continuity
# PALCodeDocument = im_d_v1_projection_alias_edit_sidecars
#====================================

# PAL readable projection (non-executable)
# Static C-string call arguments projected from PAL_stdio_strings.json
# Width/sign contracts remain available in PAL provenance metadata

def FUN_00106d80():
    abi_context = ABI.current('function_entry:1076608')
    abi_rdi = abi_context.registers['RDI']
    abi_rsi = abi_context.registers['RSI']
    abi_rdx = abi_context.registers['RDX']
    abi_rcx = abi_context.registers['RCX']
    abi_r8 = abi_context.registers['R8']
    abi_r9 = abi_context.registers['R9']
    abi_xmm0 = abi_context.registers['XMM0_QA']
    abi_xmm1 = abi_context.registers['XMM1_QA']
    abi_xmm2 = abi_context.registers['XMM2_QA']
    abi_xmm3 = abi_context.registers['XMM3_QA']
    abi_xmm4 = abi_context.registers['XMM4_QA']
    abi_xmm5 = abi_context.registers['XMM5_QA']
    abi_xmm6 = abi_context.registers['XMM6_QA']
    abi_xmm7 = abi_context.registers['XMM7_QA']
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    abi_xmm_count = abi_context.variadic_xmm_count
    abi_overflow_arguments = abi_context.overflow_argument_area
    if abi_xmm_count == 0:
        pass
    else:
        local_88 = abi_xmm0
        local_78 = abi_xmm1
        local_68 = abi_xmm2
        local_58 = abi_xmm3
        local_48 = abi_xmm4
        local_38 = abi_xmm5
        local_28 = abi_xmm6
        local_18 = abi_xmm7
    local_c0 = MEM64[(abi_tls_base + 0x28)]
    local_d0 = (abi_stack_pointer - 8)
    v_243 = (abi_stack_pointer - -0xd8)
    local_c8 = (abi_stack_pointer - -0xb8)
    v_253 = (abi_stack_pointer - -0xe0)
    local_d8 = 0x10
    local_d4 = 0x30
    v_1986 = FUN_00104c80(0, v_253, abi_rsi, v_243)
    if v_1986 == 0:
        v_628 = 0xffffffff
    else:
        if local_e0 >= 2147483648:
            free(v_1986)
            v_525 = __errno_location()
            MEM32[v_525] <- 0x4b
            v_628 = 0xffffffff
        else:
            MEM64[abi_rdi] <- v_1986
            v_628 = local_e0
    v_387 = MEM64[(abi_tls_base + 0x28)]
    if local_c0 != v_387:
        __stack_chk_fail()
    else:
        return v_628
