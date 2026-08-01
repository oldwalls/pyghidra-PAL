#include <stdio.h>

int main(int argc, char **argv) {
    int a = argc, b = 0;

    // 1. Initial unconditional jump skipping loop header setup (Irreducible Entry)
    __asm__ goto ("jmp %l[arm_b_mid]" :::: arm_b_mid);

loop_hdr:
    a += 1;
    if (a > 100) goto out;

    // 2. Diamond Split
    if (a & 1) {
    arm_a:
        b += 3;
        // Unconditional cross-jump into the middle of Arm B
        __asm__ goto ("jmp %l[arm_b_mid]" :::: arm_b_mid);
    } else {
        b += 7;
    arm_b_mid:
        b ^= a;
        // Irreducible back-edge directly into loop header
        if (b < 50) goto loop_hdr;
    }

    // 3. Post-dominator re-entry back into Arm A
    if (b & 2) {
        __asm__ goto ("jmp %l[arm_a]" :::: arm_a);
    }

out:
    return b;
}