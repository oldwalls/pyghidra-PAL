#include <stdio.h>

// A standard utility function that a commercial team would write to 
// obfuscate/validate a block of telemetry or data packet payload.
unsigned int process_payload_block(unsigned int seed, unsigned char *data, int length) {
    unsigned int checksum = seed;
    unsigned int transform_flag = 0;

    // Standard guard clause seen in commercial code
    if (data == NULL || length <= 0) {
        return 0;
    }

    // Typical loop processing an array/buffer sequentially
    for (int i = 0; i < length; i++) {
        unsigned char current_byte = data[i];
        
        // Accumulate with bitwise mixing
        checksum = (checksum ^ current_byte) + 0x1f;
        checksum = (checksum << 3) | (checksum >> 29); // Simple bit rotation
        
        // Business logic state change based on data characteristics
        if (current_byte % 2 == 0) {
            transform_flag += 1;
        } else {
            transform_flag ^= 0x55;
        }
    }

    // A final conditional block simulating a status-check mutation
    if (transform_flag > 10) {
        checksum = checksum ^ 0xA5A5A5A5;
    } else {
        checksum = checksum + transform_flag;
    }

    return checksum;
}

int main() {
    // Simulated run-of-the-mill commercial payload data
    unsigned char payload[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78};
    unsigned int initial_seed = 0x10203040;
    
    // The single required function call
    unsigned int final_token = process_payload_block(initial_seed, payload, 8);
    
    // Return expression
    return (int)final_token;
}
