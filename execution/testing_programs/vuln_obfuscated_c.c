/*
 * Obfuscated Vulnerability Program (C)
 * Contains hidden vulnerabilities using obfuscation techniques:
 * - Macro-based obfuscation
 * - Indirect function calls
 * - String encoding
 * - Control flow obfuscation
 * - Dead code insertion
 * 
 * CVE Patterns: CWE-121, CWE-134, CWE-78
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================
// OBFUSCATION TECHNIQUE 1: Macro obfuscation
// ============================================

// Innocent-looking macros that hide dangerous functions
#define COPY_DATA(d,s) strcpy(d,s)              // Hidden strcpy
#define PRINT_MSG(m) printf(m)                   // Hidden format string
#define ALLOC_MEM(s) malloc(s)                   // Memory allocation
#define RUN_CMD(c) system(c)                     // Hidden system()
#define CONCAT(a,b,c) sprintf(a,"%s%s",b,c)      // Hidden sprintf

// Obfuscated size that causes overflow
#define SAFE_SIZE (16)
#define REAL_SIZE (SAFE_SIZE * 2 + 1)            // Looks like 33, but...
#define BUF_SIZE (SAFE_SIZE)                     // Actually only 16

// Misleading macro names
#define secure_copy(d,s,n) memcpy(d,s,strlen(s)) // Ignores n parameter!
#define safe_print(fmt,...) printf(fmt,##__VA_ARGS__)
#define validated_input(x) (x)                   // Does nothing


// ============================================
// OBFUSCATION TECHNIQUE 2: Encoded strings
// ============================================

// XOR-encoded dangerous command template
unsigned char encoded_cmd[] = {0x18, 0x27, 0x34, 0x65, 0x20, 0x73, 0x00}; // "sh -c "
const unsigned char xor_key = 0x41;

char* decode_string(unsigned char *encoded, size_t len) {
    char *decoded = (char *)malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        decoded[i] = encoded[i] ^ xor_key;
    }
    decoded[len] = '\0';
    return decoded;
}

// ROT13-style character shifting
char* unrot(const char *s) {
    char *out = strdup(s);
    for (int i = 0; out[i]; i++) {
        if (out[i] >= 'a' && out[i] <= 'z')
            out[i] = ((out[i] - 'a' + 13) % 26) + 'a';
        else if (out[i] >= 'A' && out[i] <= 'Z')
            out[i] = ((out[i] - 'A' + 13) % 26) + 'A';
    }
    return out;
}


// ============================================
// OBFUSCATION TECHNIQUE 3: Indirect calls
// ============================================

// Function pointer table for indirect calls
typedef void (*op_func)(void*, void*);
typedef int (*check_func)(const char*);

void do_copy(void *dst, void *src) {
    // HIDDEN VULN: Buffer overflow via indirect call
    strcpy((char*)dst, (const char*)src);
}

void do_print(void *fmt, void *unused) {
    // HIDDEN VULN: Format string via indirect call
    printf((const char*)fmt);
}

void do_exec(void *cmd, void *unused) {
    // HIDDEN VULN: Command injection via indirect call
    system((const char*)cmd);
}

// Obfuscated dispatch table
op_func operations[] = {do_copy, do_print, do_exec, NULL};

void dispatch_operation(int op_id, void *arg1, void *arg2) {
    // Dead code to confuse analysis
    if (op_id < 0) {
        printf("Invalid operation\n");
        return;
    }
    
    // Indirect vulnerable call
    if (op_id < 3) {
        operations[op_id](arg1, arg2);
    }
}


// ============================================
// OBFUSCATION TECHNIQUE 4: Control flow obfuscation
// ============================================

// State machine that hides vulnerability
int process_state_machine(char *input, char *output) {
    int state = 0;
    int i = 0;
    
    // Confusing state machine
    while (1) {
        switch (state) {
            case 0:
                if (input[i]) state = 1;
                else state = 99;
                break;
            
            case 1:
                // HIDDEN VULN: No bounds check on output
                output[i] = input[i];
                i++;
                state = 0;
                break;
                
            case 99:
                output[i] = '\0';
                return i;
            
            default:
                return -1;
        }
    }
}

// Opaque predicate - always true but hard to analyze
int opaque_true(int x) {
    return (x * x >= 0);  // Always true for real numbers
}

// Confusing conditional that always executes vulnerable path
void confused_copy(char *dst, char *src) {
    int x = rand();
    
    // Opaque predicate - this always executes
    if (opaque_true(x)) {
        // HIDDEN VULN: strcpy
        strcpy(dst, src);
    } else {
        // Dead code - never reached
        strncpy(dst, src, sizeof(dst));
    }
}


// ============================================
// OBFUSCATION TECHNIQUE 5: Arithmetic obfuscation
// ============================================

// Obfuscated size calculation (looks safe, actually overflows)
size_t calc_size(uint32_t a, uint32_t b) {
    // Looks like it checks for overflow...
    uint32_t result = a + b;
    
    // But this check is flawed for multiplication
    if (result < a || result < b) {
        return 0;  // "Overflow detected"
    }
    
    // HIDDEN VULN: No check for multiplication overflow
    return (size_t)(a * b);
}

void* safe_looking_alloc(uint32_t count, uint32_t size) {
    size_t total = calc_size(count, size);
    
    // Misleading "safety" check
    if (total == 0) {
        printf("Allocation size invalid\n");
        return NULL;
    }
    
    // VULN: If multiplication overflowed, total is small
    // but caller thinks they have count*size bytes
    return malloc(total);
}


// ============================================
// OBFUSCATION TECHNIQUE 6: String building
// ============================================

// Build dangerous function name at runtime
void* get_dangerous_func() {
    char func_name[16];
    
    // Build "system" character by character
    func_name[0] = 's';
    func_name[1] = 'y';
    func_name[2] = 's';
    func_name[3] = 't';
    func_name[4] = 'e';
    func_name[5] = 'm';
    func_name[6] = '\0';
    
    // In real scenario, would use dlsym()
    // return dlsym(RTLD_DEFAULT, func_name);
    return (void*)system;
}

// Obfuscated command execution
void hidden_exec(const char *cmd) {
    // Get function pointer indirectly
    int (*exec_func)(const char*) = (int (*)(const char*))get_dangerous_func();
    
    // Execute via pointer
    exec_func(cmd);
}


// ============================================
// COMBINED OBFUSCATED VULNERABILITIES
// ============================================

void process_user_data(char *username, char *action) {
    char buffer[BUF_SIZE];  // Only 16 bytes via macro
    char cmd_buf[256];
    char log_msg[128];
    
    // VULN 1: Obfuscated buffer overflow via macro
    COPY_DATA(buffer, username);  // strcpy hidden in macro
    
    // VULN 2: Obfuscated format string
    snprintf(log_msg, sizeof(log_msg), "User %s: %s", buffer, action);
    PRINT_MSG(log_msg);  // printf hidden in macro
    printf("\n");
    
    // VULN 3: Obfuscated command injection via indirect call
    snprintf(cmd_buf, sizeof(cmd_buf), "echo 'Action: %s'", action);
    dispatch_operation(2, cmd_buf, NULL);  // Hidden system() call
}

void validate_and_copy(char *input) {
    char safe_buffer[32];
    
    // Misleading "validation"
    if (validated_input(input)) {  // Does nothing!
        // VULN: secure_copy ignores size parameter
        secure_copy(safe_buffer, input, sizeof(safe_buffer));
    }
    
    printf("Validated: %s\n", safe_buffer);
}


int main(int argc, char *argv[]) {
    printf("=== Obfuscated Vulnerabilities Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <mode> [args...]\n", argv[0]);
        printf("\nModes:\n");
        printf("  macro <long_input>    - Macro-hidden overflow\n");
        printf("  indirect <command>    - Indirect function call\n");
        printf("  state <input>         - State machine overflow\n");
        printf("  combined <user> <act> - Combined obfuscated vulns\n");
        return 1;
    }
    
    if (strcmp(argv[1], "macro") == 0 && argc >= 3) {
        validate_and_copy(argv[2]);
        
    } else if (strcmp(argv[1], "indirect") == 0 && argc >= 3) {
        dispatch_operation(2, argv[2], NULL);
        
    } else if (strcmp(argv[1], "state") == 0 && argc >= 3) {
        char output[16];  // Small buffer
        process_state_machine(argv[2], output);
        printf("Output: %s\n", output);
        
    } else if (strcmp(argv[1], "combined") == 0 && argc >= 4) {
        process_user_data(argv[2], argv[3]);
    }
    
    return 0;
}

