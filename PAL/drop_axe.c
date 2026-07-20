#include <stdio.h>
#include <string.h>

// Helper to clean up newline characters from line inputs
void clean_input(char *str) {
    str[strcspn(str, "\n")] = 0;
}

int main(void) {
    char input[64];
    int system_stability = 100;

    printf("==================================================\n");
    printf("        MATRIX_GLITCH_OS v0.99 (BETA) stdio test   \n");
    printf("==================================================\n");
    printf("Neo wakes up. The sky is lime green. \n");
    printf("Morpheus is wearing a cardboard box instead of a trench coat.\n");
    printf("Morpheus: 'Neo! The Architect ran out of budget! The simulation is falling apart!'\n");
    printf("Morpheus: 'Take this digital admin tool. Type [drop_axe] to sever glitch branches!'\n\n");

    // --- ENCOUNTER 1: The Lawnmower Anomaly ---
    printf("[SCENE 1] A flying killer lawnmower buzzes violently toward your face.\n");
    printf("Command options: [dodge] or [drop_axe]\n> ");
    fgets(input, sizeof(input), stdin);
    clean_input(input);

    if (strcmp(input, "drop_axe") == 0) {
        printf("\n[SUCCESS] You drop the ax on the execution thread! \n");
        printf("The lawnmower turns into a harmless rain of rubber ducks.\n\n");
    } else {
        printf("\n[GLITCH] You tried to dodge, but tripped over a stray virtual spoon.\n");
        printf("The lawnmower nips your leather jacket. Matrix Stability drops!\n\n");
        system_stability -= 35;
    }

    // --- ENCOUNTER 2: Tutu Smith ---
    printf("[SCENE 2] Agent Smith steps out of a phone booth wearing a sparkling pink tutu.\n");
    printf("Smith: 'Mr. Anderson... do you like my pirouette?'\n");
    printf("He spins rapidly, generating a localized code tornado that blocks your exit.\n");
    printf("Command options: [applaud] or [drop_axe]\n> ");
    fgets(input, sizeof(input), stdin);
    clean_input(input);

    if (strcmp(input, "drop_axe") == 0) {
        printf("\n[SUCCESS] CRASH! The ax cuts the tutu's rendering logic.\n");
        printf("Smith turns neon blue, textures fail, and he falls through the floor geometry.\n\n");
    } else {
        printf("\n[GLITCH] You applaud politely. Smith gets self-conscious, turns red,\n");
        printf("and slaps you with a copy of the Matrix sequels. Severe logic damage!\n\n");
        system_stability -= 45;
    }

    // --- ENCOUNTER 3: The Architect's Juice Box ---
    printf("[SCENE 3] The Architect appears on a massive CRT monitor, sipping a tiny juice box.\n");
    printf("Architect: 'Ergo, concordantly, vis-a-vis, your execution cycle is garbage collected.'\n");
    printf("The screen begins to freeze up. The core kernel is locking! Last chance!\n");
    printf("Command options: [panic] or [drop_axe]\n> ");
    fgets(input, sizeof(input), stdin);
    clean_input(input);

    if (strcmp(input, "drop_axe") == 0) {
        printf("\n==================================================\n");
        printf("                   VICTORY                        \n");
        printf("==================================================\n");
        printf("BOOM! You drop the ultimate ax on the core kernel connection.\n");
        printf("The green simulation shatters completely!\n");
        printf("You wake up in the real world, safe on the Nebuchadnezzar, eating cold porridge.\n");
        printf("Remaining Matrix Stability Margin: %d%%\n", system_stability);
    } else {
        printf("\n==================================================\n");
        printf("                  GAME OVER                       \n");
        printf("==================================================\n");
        printf("You panicked. The Architect forces you to read his complete dictionary.\n");
        printf("Your brain melts instantly. The system completely crashes.\n");
    }

    return 0;
}
