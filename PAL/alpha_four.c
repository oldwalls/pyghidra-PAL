#include <stdio.h>

// Dummy functions to prevent aggressive compiler inlining/constant folding
int mutate(int v) { return (v << 1) ^ 0x55; }
int feedback(int x, int y) { return x - (y * 3); }

int main(void) {
    int alpha = 0x10;
    int beta = 0x0;
    int gamma = 0;
    int counter = 0;

    // Hard safety limits: preserve the original control-flow traps while
    // guaranteeing that neither the nested loop nor the outer loop can run
    // indefinitely.
    const int max_outer_loops = 12;
    const int max_inner_loops = 16;

    // TRAP 1: The Do-While Loop
    do {
        alpha = mutate(alpha + counter);

        // TRAP 2: Dual-condition 'for' loop
        for (int i = 0; i < 10 && beta > 0; ++i) {
            gamma = feedback(alpha, i);

            // TRAP 3: The 'continue' statement
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

                case 3: {
                    // TRAP 5: Loop inside a switch case.
                    //
                    // The original specimen can enter the cycle:
                    //
                    //     75 -> 31 -> 75 -> 31 -> ...
                    //
                    // so this loop now has an independent hard iteration cap.
                    int inner_steps = 0;

                    while (gamma > 0 &&
                           inner_steps < max_inner_loops) {
                        gamma = mutate(gamma >> 1);
                        inner_steps++;

                        if (gamma == 15) {
                            break;
                        }
                    }
                    break;
                }

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

    // Preserve the original complex tail condition, but add a definitive
    // outer-loop ceiling.
    } while ((counter < 5 || alpha < 100) &&
             counter < max_outer_loops);

    printf(
        "Final after %d outer loops: %d, %d, %d\n",
        counter,
        alpha,
        beta,
        gamma
    );

    return alpha + beta;
}
