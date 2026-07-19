#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

uint32_t PALexec(uint32_t alpha, int32_t beta, int16_t gamma) {
    // 1. Initial State & Width Casts
    uint8_t  u8_state  = (uint8_t)alpha;     // Explicit truncation (8-bit)
    int8_t   i8_state  = (int8_t)beta;       // Signed truncation (8-bit)
    uint16_t u16_state = (uint16_t)gamma;    // Mixed signedness casting (16-bit)
    int16_t  i16_state = (int16_t)alpha;     // Truncation to signed 16-bit
    uint32_t u32_accum = 0x12345678;
    int32_t  i32_accum = (int32_t)0x80000000; // Force INT32_MIN pattern

    // 2. Outer Loop: Structural & Control Flow Matrix
    for (int i = 0; i < 3; i++) {
        // Mixed Boolean Condition & Signed vs Unsigned Comparisons
        // Testing if the compiler uses signed (JL/JG) or unsigned (JB/JA) branches
        if (((uint32_t)beta > alpha) && (i8_state < (int8_t)u8_state) || !(gamma >= 0)) {
            u32_accum = (u32_accum ^ 0x5F5F5F5F) + (uint32_t)beta; // Unsigned wraparound
        } else {
            // Ternary-shaped branch logic
            i32_accum = (i32_accum == 0) ? (int32_t)alpha : (i32_accum / beta); // Negative C division
        }

        // 3. Inner Loop: Nested tracking, Breaks, and Continues
        int j = 0;
        while (true) {
            j++;
            if (j > 2) break;

            // Arithmetic vs Logical Shifts
            // Right-shifting a negative int8_t must preserve the sign bit (sign-extension)
            i8_state = i8_state >> 2;   // ASR (Arithmetic Shift Right)
            u8_state = u8_state >> 2;   // LSR (Logical Shift Right)

            // Left shift causing explicit unsigned wraparound/overflow
            u16_state = (uint16_t)(u16_state << 5); 

            if ((u16_state & 0xF000) == 0) {
                continue; // Trigger edge router latch mechanics
            }

            // Bitwise operations packing multiple widths
            u32_accum |= (uint32_t)(u8_state ^ i8_state);
        }

        // 4. Switch Fallthrough Emulation Matrix
        // Masking the lower bits to create a dense jump table or cascade
        switch (u32_accum & 0x3) {
            case 0:
                i16_state = (int16_t)(i16_state + gamma);
                // Intentional Fallthrough
            case 1:
                u16_state = (uint16_t)(u16_state ^ 0xAAAA);
                break;
            case 2:
                // Negative remainder test
                // C99 specifies remainder shares the sign of the dividend
                i32_accum = i32_accum % (int32_t)(i16_state | 1); 
                break;
            default:
                u32_accum = ~u32_accum;
                break;
        }
    }

    // 5. Final Deterministic Return Value Encoding Accumulated State
    // Forces complete resolution of mixed-width extensions right at the return edge
    uint32_t final_mask = ((uint32_t)u8_state  << 24) | 
                          ((uint32_t)i8_state  << 16) | 
                          ((uint32_t)u16_state << 0);
    
    return (u32_accum ^ (uint32_t)i32_accum) + final_mask;
}

// Forward declaration of the test gauntlet
//uint32_t PALexec(uint32_t alpha, int32_t beta, int16_t gamma);

int main(void) {
    // Test inputs selected to trigger the signed/unsigned and width boundary traps
    uint32_t alpha_input = 0xABCD1234; 
    int32_t  beta_input  = -500;         // Forces signed division and negative checks
    int16_t  gamma_input = 0x7FFF;       // Max positive signed 16-bit boundary

    // Single required function call
    uint32_t execution_result = PALexec(alpha_input, beta_input, gamma_input);

    // Standard return expression representing the final execution state token
    //return (int)execution_result;
	printf("Func retun: %d\n", execution_result);
}
