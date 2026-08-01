/*
 * PAL ASCII LUNAR LANDER v6 - station read pattern
 *
 * Plain printable-ASCII edition.
 *
 * No VT100 escape bytes, no cursor control, no color sequences, and no
 * control-only static strings. Every displayed literal begins with a printable
 * ASCII byte.
 *
 * Library surface: <stdio.h> only.
 * External runtime calls: printf, fgets.
 *
 * Canonical PAL-style build:
 *   gcc -std=c11 -O0 -fPIE -pie -fno-stack-protector \
 *       lunar_lander.c -o lunar_lander.game
 */

#include <stdio.h>

#define INPUT_CAPACITY 16
#define START_ALTITUDE 24
#define START_FUEL 30
#define GRAVITY 2
#define SAFE_DOWN_SPEED 3
#define SAFE_UP_SPEED -2

typedef struct LanderState {
    int altitude;
    int velocity;
    int fuel;
    int turn;
    int active;
    int landed;
    int aborted;
} LanderState;

typedef struct BurnCommand {
    int value;
} BurnCommand;

static void initialize_lander(LanderState *lander);
static int craft_row_for_altitude(int altitude);
static void print_sky_row(int row, int craft_row);
static void draw_lander(const LanderState *lander);
static int parse_burn(const char *line, BurnCommand *command);
static int read_burn(BurnCommand *command);
static void apply_burn(LanderState *lander, int burn);
static void print_result(const LanderState *lander);
static int lander_exit_code(const LanderState *lander);

static void initialize_lander(LanderState *lander)
{
    lander->altitude = START_ALTITUDE;
    lander->velocity = 0;
    lander->fuel = START_FUEL;
    lander->turn = 0;
    lander->active = 1;
    lander->landed = 0;
    lander->aborted = 0;
}

static int craft_row_for_altitude(int altitude)
{
    if (altitude >= 27) {
        return 0;
    }

    if (altitude >= 23) {
        return 1;
    }

    if (altitude >= 19) {
        return 2;
    }

    if (altitude >= 15) {
        return 3;
    }

    if (altitude >= 11) {
        return 4;
    }

    if (altitude >= 7) {
        return 5;
    }

    if (altitude >= 3) {
        return 6;
    }

    return 7;
}

static void print_sky_row(int row, int craft_row)
{
    if (row == craft_row) {
        printf("                         /A\\\n");
    } else {
        printf("                            \n");
    }
}

static void draw_lander(const LanderState *lander)
{
    int row;
    int craft_row;

    craft_row = craft_row_for_altitude(lander->altitude);

    printf("========================================================\n");
    printf("              PAL ASCII LUNAR LANDER\n");
    printf("        integer physics / deterministic moon\n");
    printf("========================================================\n");
    printf("TURN: %-3d  ALTITUDE: %-3d  VELOCITY: %-3d  FUEL: %-3d\n",
           lander->turn,
           lander->altitude,
           lander->velocity,
           lander->fuel);
    printf("--------------------------------------------------------\n");

    for (row = 0; row < 8; row += 1) {
        print_sky_row(row, craft_row);
    }

    printf("________________________________________________________\n");
    printf("    .       *       .      MOON BASE PAL      .\n");
    printf("--------------------------------------------------------\n");

    if (lander->velocity > SAFE_DOWN_SPEED) {
        printf("DESCENT RATE: DANGER\n");
    } else if (lander->velocity < SAFE_UP_SPEED) {
        printf("DESCENT RATE: ASCENDING\n");
    } else {
        printf("DESCENT RATE: SAFE BAND\n");
    }

    printf("Enter thrust 0..9. Gravity adds %d each turn.\n", GRAVITY);
    printf("Q abandons the mission.\n");
    printf("THRUST>\n");
}

static int parse_burn(const char *line, BurnCommand *command)
{
    command->value = 0;

    if (line[0] == 'q') {
        return 0;
    }

    if (line[0] == 'Q') {
        return 0;
    }

    if (line[0] < '0') {
        return -1;
    }

    if (line[0] > '9') {
        return -1;
    }

    command->value = line[0] - '0';
    return 1;
}

static int read_burn(BurnCommand *command)
{
    char input[INPUT_CAPACITY];
    int parsed;

    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("INPUT CLOSED\n");
        return 0;
    }

    parsed = parse_burn(input, command);

    if (parsed < 0) {
        printf("INVALID THRUST: enter one digit from 0 through 9.\n");
    }

    return parsed;
}

static void apply_burn(LanderState *lander, int burn)
{
    if (burn > lander->fuel) {
        burn = lander->fuel;
    }

    lander->fuel -= burn;
    lander->velocity += GRAVITY;
    lander->velocity -= burn;
    lander->altitude -= lander->velocity;
    lander->turn += 1;

    if (lander->altitude > 30) {
        lander->altitude = 30;
        lander->velocity = 0;
    }

    if (lander->altitude <= 0) {
        lander->altitude = 0;
        lander->active = 0;

        if (lander->velocity >= SAFE_UP_SPEED &&
            lander->velocity <= SAFE_DOWN_SPEED) {
            lander->landed = 1;
        } else {
            lander->landed = 0;
        }
    }
}

static void print_result(const LanderState *lander)
{
    printf("========================================================\n");
    printf("                 PAL LUNAR LANDER RESULT\n");
    printf("========================================================\n");

    if (lander->aborted) {
        printf("MISSION ABORTED\n");
        printf("The lander remains in orbit.\n");
    } else if (lander->landed) {
        printf("*** SOFT LANDING ***\n");
        printf("Velocity: %d\n", lander->velocity);
        printf("Fuel:     %d\n", lander->fuel);
        printf("Turns:    %d\n", lander->turn);
    } else {
        printf("*** CRASH LANDING ***\n");
        printf("Impact velocity: %d\n", lander->velocity);
        printf("Try smaller thrust early and stronger thrust late.\n");
    }

    printf("Known soft-landing sequence: 0 0 0 0 7 2\n");
}

static int lander_exit_code(const LanderState *lander)
{
    if (lander->landed) {
        return 0;
    }

    if (lander->aborted) {
        return 2;
    }

    return 3;
}

int main(void)
{
    LanderState lander;
    BurnCommand command;
    int running;
    int parsed;

    initialize_lander(&lander);
    command.value = 0;
    running = 1;
    parsed = 1;

    while (running) {
        draw_lander(&lander);
        parsed = read_burn(&command);

        if (parsed == 0) {
            lander.aborted = 1;
            break;
        }

        if (parsed < 0) {
            continue;
        }

        apply_burn(&lander, command.value);
        running = lander.active;
    }

    print_result(&lander);
    return lander_exit_code(&lander);
}
