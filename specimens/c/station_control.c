/*
 * PAL Station Control
 *
 * Purpose-built console application specimen for PAL.
 *
 * Standard C11, one library dependency (<stdio.h>), deterministic input and
 * output, fixed-size storage, no heap, no filesystem, no randomness and no
 * platform-specific APIs.
 */

#include <stdio.h>

#define INPUT_CAPACITY 96
#define COMMAND_CAPACITY 16
#define ENERGY_MIN 100
#define ENERGY_MAX 500
#define COMMIT_ENERGY_MIN 350
#define COMMIT_ENERGY_MAX 520
#define COMMIT_HEAT_MAX 80
#define FAILURE_HEAT 150
#define MAX_FAULTS 3

typedef enum StationMode {
    MODE_OFFLINE = 0,
    MODE_DIAGNOSTIC = 1,
    MODE_ARMED = 2,
    MODE_ACTIVE = 3,
    MODE_FAILED = 4
} StationMode;

typedef struct StationState {
    StationMode mode;
    int energy;
    int heat;
    int route;
    unsigned int checksum;
    int faults;
    int attempts;
    int pulses;
    int committed;
} StationState;

typedef struct Command {
    char name[COMMAND_CAPACITY];
    int has_value;
    int value;
} Command;

static const char *mode_name(StationMode mode);
static void initialize_station(StationState *station);
static void print_banner(void);
static void print_help(void);
static void print_status(const StationState *station);
static int is_space_char(char value);
static int text_equal(const char *left, const char *right);
static void copy_token(char *destination, int capacity, const char *source, int length);
static int parse_integer(const char *text, int *value_out);
static int parse_command(const char *line, Command *command);
static int read_command(Command *command);
static unsigned int rotate_left_5(unsigned int value);
static unsigned int compute_checksum(const StationState *station);
static void refresh_checksum(StationState *station);
static void record_fault(StationState *station, const char *message);
static void command_boot(StationState *station);
static void command_clear(StationState *station);
static void command_load(StationState *station, const Command *command);
static void command_route(StationState *station, const Command *command);
static void command_arm(StationState *station);
static void command_pulse(StationState *station, const Command *command);
static void command_cool(StationState *station);
static void command_commit(StationState *station);
static int dispatch_command(StationState *station, const Command *command);
static int station_exit_code(const StationState *station);

static const char *mode_name(StationMode mode)
{
    switch (mode) {
        case MODE_OFFLINE:
            return "OFFLINE";
        case MODE_DIAGNOSTIC:
            return "DIAGNOSTIC";
        case MODE_ARMED:
            return "ARMED";
        case MODE_ACTIVE:
            return "ACTIVE";
        case MODE_FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}

static void initialize_station(StationState *station)
{
    station->mode = MODE_OFFLINE;
    station->energy = 0;
    station->heat = 0;
    station->route = 0;
    station->checksum = 0U;
    station->faults = 0;
    station->attempts = 0;
    station->pulses = 0;
    station->committed = 0;
}

static void print_banner(void)
{
    printf("PAL STATION CONTROL v1.0\n");
    printf("Type 'help' for available commands.\n");
}

static void print_help(void)
{
    printf("\n");
    printf("COMMANDS\n");
    printf("  boot            enter diagnostic mode\n");
    printf("  status          display station state\n");
    printf("  load N          set energy reserve (100..500)\n");
    printf("  route N         select route (1..4)\n");
    printf("  arm             validate and arm the station\n");
    printf("  pulse N         execute 1..8 pulse cycles\n");
    printf("  cool            reduce thermal load\n");
    printf("  clear           clear recoverable faults\n");
    printf("  commit          validate and activate the corridor\n");
    printf("  quit            leave the console\n");
    printf("\n");
}

static void print_status(const StationState *station)
{
    printf("\n");
    printf("MODE:      %s\n", mode_name(station->mode));
    printf("ENERGY:    %d\n", station->energy);
    printf("HEAT:      %d\n", station->heat);

    if (station->route == 0) {
        printf("ROUTE:     unset\n");
    } else {
        printf("ROUTE:     %d\n", station->route);
    }

    printf("CHECKSUM:  0x%08X\n", station->checksum);
    printf("FAULTS:    %d\n", station->faults);
    printf("ATTEMPTS:  %d\n", station->attempts);
    printf("PULSES:    %d\n", station->pulses);
    printf("\n");
}

static int is_space_char(char value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static int text_equal(const char *left, const char *right)
{
    int index = 0;

    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return 0;
        }
        index += 1;
    }

    return left[index] == '\0' && right[index] == '\0';
}

static void copy_token(
    char *destination,
    int capacity,
    const char *source,
    int length
)
{
    int index;
    int limit = length;

    if (limit >= capacity) {
        limit = capacity - 1;
    }

    for (index = 0; index < limit; index += 1) {
        destination[index] = source[index];
    }

    destination[limit] = '\0';
}

static int parse_integer(const char *text, int *value_out)
{
    int index = 0;
    int sign = 1;
    int value = 0;
    int digit_count = 0;

    while (is_space_char(text[index])) {
        index += 1;
    }

    if (text[index] == '-') {
        sign = -1;
        index += 1;
    } else if (text[index] == '+') {
        index += 1;
    }

    while (text[index] >= '0' && text[index] <= '9') {
        int digit = text[index] - '0';

        if (value > 1000000) {
            return 0;
        }

        value = (value * 10) + digit;
        digit_count += 1;
        index += 1;
    }

    while (is_space_char(text[index])) {
        index += 1;
    }

    if (digit_count == 0 || text[index] != '\0') {
        return 0;
    }

    *value_out = value * sign;
    return 1;
}

static int parse_command(const char *line, Command *command)
{
    int index = 0;
    int start;
    int length;

    command->name[0] = '\0';
    command->has_value = 0;
    command->value = 0;

    while (is_space_char(line[index])) {
        index += 1;
    }

    start = index;
    while (line[index] != '\0' && !is_space_char(line[index])) {
        index += 1;
    }

    length = index - start;
    if (length <= 0) {
        return 0;
    }

    copy_token(command->name, COMMAND_CAPACITY, line + start, length);

    while (is_space_char(line[index])) {
        index += 1;
    }

    if (line[index] != '\0') {
        if (!parse_integer(line + index, &command->value)) {
            return -1;
        }
        command->has_value = 1;
    }

    return 1;
}

static int read_command(Command *command)
{
    char input[INPUT_CAPACITY];
    int parsed;

    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("\nINPUT CLOSED\n");
        return 0;
    }

    parsed = parse_command(input, command);

    if (parsed == 0) {
        printf("EMPTY COMMAND\n");
    } else if (parsed < 0) {
        printf("INVALID NUMERIC ARGUMENT\n");
    }

    return parsed;
}

static unsigned int rotate_left_5(unsigned int value)
{
    return (value << 5) | (value >> 27);
}

static unsigned int compute_checksum(const StationState *station)
{
    unsigned int value;
    unsigned int mix;
    int round;

    value = 0x13579BDFU;
    value ^= (unsigned int)(station->energy * 33);
    value ^= (unsigned int)(station->heat * 17);
    value ^= (unsigned int)(station->route * 257);
    value ^= (unsigned int)(station->faults * 4099);
    value ^= (unsigned int)(station->pulses * 8191);
    value ^= (unsigned int)(station->mode * 65537);

    mix = (unsigned int)(
        station->energy
        + station->heat
        + (station->route * 7)
        + (station->attempts * 11)
    );

    for (round = 0; round < 4; round += 1) {
        value = rotate_left_5(value);
        value ^= mix + (unsigned int)(round * 0x1021);
        mix = (mix * 29U) ^ (value >> 3);
    }

    return value ^ 0xA5A55A5AU;
}

static void refresh_checksum(StationState *station)
{
    station->checksum = compute_checksum(station);
}

static void record_fault(StationState *station, const char *message)
{
    station->faults += 1;
    refresh_checksum(station);

    printf("%s\n", message);
    printf("FAULTS: %d\n", station->faults);

    if (station->faults >= MAX_FAULTS) {
        station->mode = MODE_FAILED;
        refresh_checksum(station);
        printf("STATION LOCKED: maximum fault count reached.\n");
    }
}

static void command_boot(StationState *station)
{
    if (station->mode != MODE_OFFLINE) {
        record_fault(station, "DENIED: boot is only valid while offline.");
        return;
    }

    printf("Boot sequence initiated...\n");
    printf("  control memory ........ OK\n");
    printf("  coolant circulation ... OK\n");
    printf("  routing matrix ........ OK\n");
    printf("  command interface ..... OK\n");

    station->mode = MODE_DIAGNOSTIC;
    station->energy = 0;
    station->heat = 0;
    station->route = 0;
    station->pulses = 0;
    refresh_checksum(station);

    printf("Station entered DIAGNOSTIC mode.\n");
}

static void command_clear(StationState *station)
{
    if (station->mode != MODE_DIAGNOSTIC) {
        printf("DENIED: faults may be cleared only in diagnostic mode.\n");
        return;
    }

    if (station->faults == 0) {
        printf("Fault register already clear.\n");
        return;
    }

    station->faults = 0;
    refresh_checksum(station);
    printf("Recoverable faults cleared.\n");
}

static void command_load(StationState *station, const Command *command)
{
    if (station->mode != MODE_DIAGNOSTIC) {
        record_fault(station, "DENIED: energy may be loaded only in diagnostic mode.");
        return;
    }

    if (!command->has_value) {
        record_fault(station, "REJECTED: load requires an integer value.");
        return;
    }

    if (command->value < ENERGY_MIN || command->value > ENERGY_MAX) {
        record_fault(station, "REJECTED: energy value must be between 100 and 500.");
        return;
    }

    station->energy = command->value;
    station->heat = command->value / 40;
    refresh_checksum(station);

    printf("Energy reserve set to %d units.\n", station->energy);
    printf("CHECKSUM: 0x%08X\n", station->checksum);
}

static void command_route(StationState *station, const Command *command)
{
    if (station->mode != MODE_DIAGNOSTIC) {
        record_fault(station, "DENIED: route may be selected only in diagnostic mode.");
        return;
    }

    if (!command->has_value) {
        record_fault(station, "REJECTED: route requires an integer value.");
        return;
    }

    switch (command->value) {
        case 1:
        case 2:
        case 3:
        case 4:
            station->route = command->value;
            refresh_checksum(station);
            printf("Routing channel %d selected.\n", station->route);
            printf("CHECKSUM: 0x%08X\n", station->checksum);
            break;
        default:
            record_fault(station, "REJECTED: route must be 1, 2, 3 or 4.");
            break;
    }
}

static void command_arm(StationState *station)
{
    int valid = 1;

    if (station->mode != MODE_DIAGNOSTIC) {
        record_fault(station, "DENIED: station must be in diagnostic mode before arming.");
        return;
    }

    station->attempts += 1;
    printf("Verifying station state...\n");

    if (station->energy < ENERGY_MIN || station->energy > ENERGY_MAX) {
        printf("  energy range .......... FAIL\n");
        valid = 0;
    } else {
        printf("  energy range .......... OK\n");
    }

    if (station->route < 1 || station->route > 4) {
        printf("  routing channel ....... FAIL\n");
        valid = 0;
    } else {
        printf("  routing channel ....... OK\n");
    }

    refresh_checksum(station);

    if (((station->checksum ^ (unsigned int)station->energy) & 1U) !=
        (unsigned int)((station->route + 1) & 1)) {
        printf("  checksum parity ....... FAIL\n");
        valid = 0;
    } else {
        printf("  checksum parity ....... OK\n");
    }

    if (station->faults != 0) {
        printf("  fault register ........ BLOCKED\n");
        valid = 0;
    } else {
        printf("  fault register ........ CLEAR\n");
    }

    if (!valid) {
        printf("ARMING DENIED.\n");
        return;
    }

    station->mode = MODE_ARMED;
    refresh_checksum(station);
    printf("Station ARMED.\n");
}

static void command_pulse(StationState *station, const Command *command)
{
    int cycle;

    if (station->mode != MODE_ARMED) {
        record_fault(station, "DENIED: pulse requires an armed station.");
        return;
    }

    if (!command->has_value) {
        record_fault(station, "REJECTED: pulse requires an integer cycle count.");
        return;
    }

    if (command->value < 1 || command->value > 8) {
        record_fault(station, "REJECTED: pulse cycle count must be between 1 and 8.");
        return;
    }

    for (cycle = 1; cycle <= command->value; cycle += 1) {
        int energy_gain;
        int heat_gain;

        energy_gain = 6 + (station->route * 2) + cycle;
        heat_gain = 7 + station->route + (cycle / 2);

        if ((station->checksum & 4U) != 0U) {
            energy_gain += 2;
        } else {
            heat_gain += 1;
        }

        station->energy += energy_gain;
        station->heat += heat_gain;
        station->pulses += 1;
        refresh_checksum(station);

        printf(
            "Pulse cycle %d/%d: energy=%d heat=%d checksum=0x%08X\n",
            cycle,
            command->value,
            station->energy,
            station->heat,
            station->checksum
        );

        if (station->heat >= FAILURE_HEAT) {
            station->mode = MODE_FAILED;
            refresh_checksum(station);
            printf("THERMAL FAILURE: station entered FAILED mode.\n");
            return;
        }
    }

    if (station->heat > COMMIT_HEAT_MAX) {
        printf("WARNING: thermal level above commit threshold.\n");
    }
}

static void command_cool(StationState *station)
{
    int before;
    int reduction;

    if (station->mode != MODE_ARMED) {
        record_fault(station, "DENIED: coolant cycle requires an armed station.");
        return;
    }

    before = station->heat;
    reduction = 24 + (station->route * 4) + (station->pulses / 2);

    station->heat -= reduction;
    if (station->heat < 0) {
        station->heat = 0;
    }

    refresh_checksum(station);

    printf("Coolant cycle started...\n");
    printf("Heat reduced from %d to %d.\n", before, station->heat);
}

static void command_commit(StationState *station)
{
    int valid = 1;
    unsigned int route_signature;

    if (station->mode != MODE_ARMED) {
        printf("COMMIT DENIED: station is not armed.\n");
        return;
    }

    route_signature = (
        station->checksum
        ^ (unsigned int)(station->energy * 3)
        ^ (unsigned int)(station->route * 19)
    ) & 3U;

    printf("Final validation:\n");

    if (station->energy < COMMIT_ENERGY_MIN ||
        station->energy > COMMIT_ENERGY_MAX) {
        printf("  energy ................ FAIL (%d)\n", station->energy);
        valid = 0;
    } else {
        printf("  energy ................ OK (%d)\n", station->energy);
    }

    if (station->heat > COMMIT_HEAT_MAX) {
        printf("  heat .................. FAIL (%d)\n", station->heat);
        valid = 0;
    } else {
        printf("  heat .................. OK (%d)\n", station->heat);
    }

    if (station->route == 0) {
        printf("  route ................. FAIL\n");
        valid = 0;
    } else {
        printf("  route ................. OK (%d)\n", station->route);
    }

    if (route_signature == (unsigned int)((station->route + 1) & 3)) {
        printf("  checksum route ........ OK\n");
    } else {
        printf("  checksum route ........ FAIL\n");
        valid = 0;
    }

    if (station->faults != 0) {
        printf("  faults ................ FAIL (%d)\n", station->faults);
        valid = 0;
    } else {
        printf("  faults ................ CLEAR\n");
    }

    if (!valid) {
        printf("COMMIT DENIED: validation incomplete.\n");
        return;
    }

    station->mode = MODE_ACTIVE;
    station->committed = 1;
    refresh_checksum(station);

    printf("STATION CONTROL COMMITTED.\n");
    printf("DOCKING CORRIDOR OPEN.\n");
    printf("MISSION RESULT: SUCCESS\n");
}

static int dispatch_command(StationState *station, const Command *command)
{
    if (text_equal(command->name, "help")) {
        print_help();
    } else if (text_equal(command->name, "status")) {
        print_status(station);
    } else if (text_equal(command->name, "boot")) {
        command_boot(station);
    } else if (text_equal(command->name, "clear")) {
        command_clear(station);
    } else if (text_equal(command->name, "load")) {
        command_load(station, command);
    } else if (text_equal(command->name, "route")) {
        command_route(station, command);
    } else if (text_equal(command->name, "arm")) {
        command_arm(station);
    } else if (text_equal(command->name, "pulse")) {
        command_pulse(station, command);
    } else if (text_equal(command->name, "cool")) {
        command_cool(station);
    } else if (text_equal(command->name, "commit")) {
        command_commit(station);
    } else if (text_equal(command->name, "quit")) {
        return 0;
    } else {
        record_fault(station, "UNKNOWN COMMAND");
    }

    return 1;
}

static int station_exit_code(const StationState *station)
{
    if (station->committed) {
        return 0;
    }

    if (station->mode == MODE_FAILED) {
        return 3;
    }

    return 2;
}

int main(void)
{
    StationState station;
    Command command;
    int running = 1;
    int parsed;

    initialize_station(&station);
    print_banner();

    while (running) {
        printf("\nstation[%s]> ", mode_name(station.mode));
        parsed = read_command(&command);

        if (parsed == 0) {
            break;
        }

        if (parsed < 0) {
            continue;
        }

        running = dispatch_command(&station, &command);
    }

    printf("Station interface closed.\n");
    printf("Return code: %d\n", station_exit_code(&station));

    return station_exit_code(&station);
}
