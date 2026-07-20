# PAL readable projection; this file is not execution authority.
# Ghidra function: Global::main
# Entry address: 0x10121c

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

def main():
    abi_context = ABI.current('function_entry:1053212')
    abi_stack_pointer = abi_context.stack_pointer
    abi_tls_base = abi_context.tls_base
    local_10 = MEM64[(abi_tls_base + 0x28)]
    local_5c = 0x64
    puts('==================================================')
    puts('        MATRIX_GLITCH_OS v0.99 (BETA) stdio test   ')
    puts('==================================================')
    puts('Neo wakes up. The sky is lime green. ')
    puts('Morpheus is wearing a cardboard box instead of a trench coat.')
    puts("Morpheus: 'Neo! The Architect ran out of budget! The simulation is falling apart!'")
    puts("Morpheus: 'Take this digital admin tool. Type [drop_axe] to sever glitch branches!'\n")
    puts('[SCENE 1] A flying killer lawnmower buzzes violently toward your face.')
    printf('Command options: [dodge] or [drop_axe]\n> ')
    v_198 = (abi_stack_pointer - -0x58)
    fgets(v_198, 0x40, stdin)
    v_215 = (abi_stack_pointer - -0x58)
    clean_input(v_215)
    v_230 = (abi_stack_pointer - -0x58)
    v_1201 = strcmp(v_230, 'drop_axe')
    if v_1201 != 0:
        puts('\n[GLITCH] You tried to dodge, but tripped over a stray virtual spoon.')
        puts('The lawnmower nips your leather jacket. Matrix Stability drops!\n')
        local_5c = 0x41
    else:
        puts('\n[SUCCESS] You drop the ax on the execution thread! ')
        puts('The lawnmower turns into a harmless rain of rubber ducks.\n')
    puts('[SCENE 2] Agent Smith steps out of a phone booth wearing a sparkling pink tutu.')
    puts("Smith: 'Mr. Anderson... do you like my pirouette?'")
    puts('He spins rapidly, generating a localized code tornado that blocks your exit.')
    printf('Command options: [applaud] or [drop_axe]\n> ')
    v_354 = (abi_stack_pointer - -0x58)
    fgets(v_354, 0x40, stdin)
    v_371 = (abi_stack_pointer - -0x58)
    clean_input(v_371)
    v_386 = (abi_stack_pointer - -0x58)
    v_1279 = strcmp(v_386, 'drop_axe')
    if v_1279 != 0:
        puts('\n[GLITCH] You applaud politely. Smith gets self-conscious, turns red,')
        puts('and slaps you with a copy of the Matrix sequels. Severe logic damage!\n')
        local_5c = (local_5c - 0x2d)
    else:
        puts("\n[SUCCESS] CRASH! The ax cuts the tutu's rendering logic.")
        puts('Smith turns neon blue, textures fail, and he falls through the floor geometry.\n')
    puts('[SCENE 3] The Architect appears on a massive CRT monitor, sipping a tiny juice box.')
    puts("Architect: 'Ergo, concordantly, vis-a-vis, your execution cycle is garbage collected.'")
    puts('The screen begins to freeze up. The core kernel is locking! Last chance!')
    printf('Command options: [panic] or [drop_axe]\n> ')
    v_510 = (abi_stack_pointer - -0x58)
    fgets(v_510, 0x40, stdin)
    v_527 = (abi_stack_pointer - -0x58)
    clean_input(v_527)
    v_542 = (abi_stack_pointer - -0x58)
    v_1357 = strcmp(v_542, 'drop_axe')
    if v_1357 != 0:
        puts('\n==================================================')
        puts('                  GAME OVER                       ')
        puts('==================================================')
        puts('You panicked. The Architect forces you to read his complete dictionary.')
        puts('Your brain melts instantly. The system completely crashes.')
    else:
        puts('\n==================================================')
        puts('                   VICTORY                        ')
        puts('==================================================')
        puts('BOOM! You drop the ultimate ax on the core kernel connection.')
        puts('The green simulation shatters completely!')
        puts('You wake up in the real world, safe on the Nebuchadnezzar, eating cold porridge.')
        printf('Remaining Matrix Stability Margin: %d%%\n', local_5c)
    v_715 = MEM64[(abi_tls_base + 0x28)]
    if local_10 == v_715:
        return 0
    else:
        __stack_chk_fail()
