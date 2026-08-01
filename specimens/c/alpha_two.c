#include <stdio.h>

// Helper functions for the decompiler to link
int transform_a(int x) { return (x << 2) ^ 0xAF; }
int transform_b(int x) { return (x * 7) + (x >> 1); }
int check_bit(int x, int bit) { return (x >> bit) & 1; }

int main(void) {
    int acc = 100;
    int state = 0;
    int limit = 5;

    for (int i = 0; i < limit; i++) {
        int outer_val = transform_a(i + acc);
        
        // Complex nested conditional
        if (outer_val % 2 == 0 || (i > 1 && outer_val < 500)) {
            
            int j = 0;
            while (j < 3) {
                int inner_val = transform_b(j + i);
                
                // Switch statement test (Jump Table)
                switch (inner_val % 4) {
                    case 0:
                        acc += (inner_val ^ 0x12);
                        break;
                    case 1:
                        if (check_bit(acc, 3)) {
                            acc -= 5;
                        } else {
                            acc = transform_a(acc);
                        }
                        break;
                    case 2:
                        acc = (acc > 200) ? (acc - 20) : (acc + 50);
                        break;
                    default:
                        acc *= 2;
                        break;
                }
                j++;
            }
        } else {
            // Nested ternary and bitwise logic
            int alt = (i % 2 == 0) ? transform_b(acc) : transform_a(i);
            for (int k = 0; k < 2; k++) {
                if ((alt & (1 << k)) != 0) {
                    acc ^= 0xFF;
                } else {
                    acc = acc + (alt >> 2);
                }
            }
        }
        
        // Forced state update to check variable tracking
        state = (state + acc) % 10;
        if (state == 7) {
            acc -= 100;
        }
    }

    printf("Final State: %d, Acc: %d\n", state, acc);
    return acc;
}
