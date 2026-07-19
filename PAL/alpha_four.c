#include <stdio.h>

// Dummy functions to prevent aggressive compiler inlining/constant folding
int mutate(int v) { return (v << 1) ^ 0x55; }
int feedback(int x, int y) { return x - (y * 3); }

int main(void) {
    int alpha = 0x10;
    int beta = 0x20;
    int gamma = 0;
    int counter = 0;

    // TRAP 1: The Do-While Loop
    // Decompilers often incorrectly translate this into a 'while(true)' with a break at the end.
    do {
        alpha = mutate(alpha + counter);

        // TRAP 2: Dual-condition 'for' loop
        for (int i = 0; i < 10 && beta > 0; ++i) {
            gamma = feedback(alpha, i);

            // TRAP 3: The 'continue' statement
            // AST recovery often struggles to place 'continue' vs wrapping the rest in an 'else'
            if ((gamma ^ beta) % 3 == 0) {
                beta -= 2;
                continue; 
            }

            // TRAP 4: Switch Fallthrough
            switch (gamma & 0x07) {
                case 0:
                case 1:
                    alpha ^= 0xAA;
                    // Intentional fallthrough to case 2
                case 2:
                    beta += 5;
                    break;
                case 3:
                    // TRAP 5: Loop inside a switch case
                    // The 'break' here escapes the while, but NOT the switch!
                    while (gamma > 0) {
                        gamma = mutate(gamma >> 1);
                        if (gamma == 15) break; 
                    }
                    break;
                default:
                    alpha -= beta;
                    break;
            }

            // TRAP 6: Early loop exit
            if (alpha < 0) {
                alpha = 0;
                break;
            }
        }

        // State swap based on parity
        if (counter % 2 != 0) {
            int temp = alpha;
            alpha = beta;
            beta = temp;
        }

        counter++;
        
    // Complex tail condition
    } while (counter < 5 || alpha < 100);

    printf("Final: %d, %d, %d\n", alpha, beta, gamma);
    return alpha + beta;
}
