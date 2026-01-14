/*
 * Obfuscated Buffer Overflow Program
 * Multiple overflow vulnerabilities hidden through:
 * - Macro obfuscation
 * - Indirect memory operations
 * - Computed buffer sizes
 * - Split operations
 * - Misleading variable names
 * 
 * CVE Patterns: CWE-121, CWE-122, CWE-787 (hidden)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================
// OBFUSCATION 1: Macro-based hiding
// ============================================

// Innocent-looking macros that perform dangerous operations
#define INIT_ARRAY(arr, val) memset(arr, val, sizeof(arr))
#define SAFE_COPY(d, s) do { for(int _i=0; s[_i]; _i++) d[_i]=s[_i]; d[strlen(s)]=0; } while(0)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define STR_DUP(dst, src) SAFE_COPY(dst, src)  // Actually unsafe!

// Hidden size manipulation
#define BUFFER_UNITS 8
#define UNIT_SIZE 4
#define CALC_SIZE(n) ((n) * UNIT_SIZE)  // Looks safe but...
#define REAL_BUF_SIZE CALC_SIZE(BUFFER_UNITS)  // = 32 bytes

// Deceptive "safety" wrappers
#define CHECKED_COPY(d, s, max) strcpy(d, s)  // Ignores max!
#define BOUNDS_CHECK(idx, max) (idx)          // Does nothing!
#define VALIDATED_PTR(p) (p)                   // Does nothing!

// ============================================
// OBFUSCATION 2: Computed/Dynamic sizes
// ============================================

// Returns size that looks computed but is actually wrong
static inline size_t compute_safe_size(size_t input_len) {
    // Appears to calculate safe size
    size_t base = 32;
    size_t aligned = (input_len + 7) & ~7;  // Align to 8
    
    // BUG: Returns base regardless of input
    (void)aligned;  // Unused
    return base;
}

// "Security" calculation that doesn't actually limit
size_t get_max_copy_len(const char *src, size_t dst_size) {
    size_t src_len = strlen(src);
    // Looks like it returns minimum, but...
    return src_len;  // Always returns source length!
}

// ============================================
// OBFUSCATION 3: Indirect operations
// ============================================

typedef void (*copy_func_t)(void*, const void*, size_t);
typedef void* (*mem_func_t)(void*, int, size_t);

// Function pointer table (hides actual functions used)
static struct {
    copy_func_t copy;
    mem_func_t set;
} mem_ops = {
    .copy = (copy_func_t)memcpy,
    .set = (mem_func_t)memset
};

// Indirect string copy (hides strcpy)
void string_transfer(char *dest, const char *src) {
    size_t len = strlen(src);
    // Uses indirect memcpy with +1 for null... but no dest check!
    mem_ops.copy(dest, src, len + 1);
}

// ============================================
// OBFUSCATION 4: Split operations
// ============================================

// Copies one character at a time (hides overflow)
void incremental_copy(char *dst, const char *src) {
    int idx = 0;
    // Loop has no bound check on dst
    while (src[idx]) {
        dst[idx] = src[idx];
        idx++;
    }
    dst[idx] = '\0';
}

// Copies in chunks (hides the actual overflow)
void chunked_copy(char *dst, const char *src, int chunk_size) {
    int offset = 0;
    int remaining = strlen(src);
    
    while (remaining > 0) {
        int to_copy = (remaining < chunk_size) ? remaining : chunk_size;
        // VULN: dst size never checked
        memcpy(dst + offset, src + offset, to_copy);
        offset += to_copy;
        remaining -= to_copy;
    }
    dst[offset] = '\0';
}

// ============================================
// OBFUSCATION 5: Misleading names
// ============================================

// Names suggest safety but are vulnerable
void secure_string_handler(char *safe_buffer, const char *untrusted_input) {
    // Name lies - this is not secure!
    strcpy(safe_buffer, untrusted_input);
}

void validated_copy(char *checked_dest, const char *verified_src, size_t verified_len) {
    // Parameter names lie - no validation happens
    memcpy(checked_dest, verified_src, verified_len);
}

void bounds_checked_operation(char *bounded_buf, size_t buf_capacity, const char *input) {
    // Despite the name, there's no bounds check
    (void)buf_capacity;  // Unused!
    strcpy(bounded_buf, input);
}

// ============================================
// OBFUSCATION 6: Complex control flow
// ============================================

// State machine that eventually overflows
void process_with_state_machine(char *output, const char *input) {
    int state = 0;
    int in_idx = 0;
    int out_idx = 0;
    
    // Confusing state transitions
    while (1) {
        switch (state) {
            case 0:  // Init
                if (input[in_idx]) {
                    state = 1;
                } else {
                    state = 3;
                }
                break;
                
            case 1:  // Process char
                // VULN: No check on out_idx bounds
                output[out_idx++] = input[in_idx++];
                state = 2;
                break;
                
            case 2:  // Check continue
                if (input[in_idx]) {
                    state = 1;
                } else {
                    state = 3;
                }
                break;
                
            case 3:  // Terminate
                output[out_idx] = '\0';
                return;
        }
    }
}

// Recursive copy (hides iteration count)
void recursive_copy(char *dst, const char *src, int idx) {
    if (src[idx] == '\0') {
        dst[idx] = '\0';
        return;
    }
    // VULN: No dst bounds check
    dst[idx] = src[idx];
    recursive_copy(dst, src, idx + 1);
}

// ============================================
// OBFUSCATION 7: Arithmetic hiding
// ============================================

// Size calculation that looks correct but isn't
struct sized_buffer {
    size_t declared_size;  // Claims to be the size
    char data[32];         // Actual size is 32
};

void use_sized_buffer(struct sized_buffer *buf, const char *input) {
    // Looks like it respects declared_size
    if (strlen(input) <= buf->declared_size) {
        // But strcpy ignores the check result!
        strcpy(buf->data, input);
    }
}

// Wraparound in size check
int safe_looking_check(size_t input_len, size_t buffer_size) {
    // Looks like overflow check but is flawed
    if (input_len + 1 > buffer_size) {  // +1 for null
        return 0;  // Unsafe
    }
    // BUG: If input_len is SIZE_MAX, input_len+1 wraps to 0!
    return 1;  // "Safe"
}

// ============================================
// COMBINED OBFUSCATED VULNERABILITIES
// ============================================

typedef struct {
    char tag[8];
    char safe_name[REAL_BUF_SIZE];  // 32 bytes via macro
    int validated;
    int privilege;
} obfuscated_record;

void process_obfuscated_record(obfuscated_record *rec, const char *input) {
    // Looks like validation
    rec->validated = 0;
    rec->privilege = 0;
    
    // Multiple obfuscated overflow points
    
    // 1. Macro-hidden strcpy
    STR_DUP(rec->safe_name, input);
    
    // 2. "Bounds checked" but not really
    bounds_checked_operation(rec->tag, sizeof(rec->tag), "TAG");
    
    // If overflow occurred, validated/privilege corrupted
    if (rec->validated || rec->privilege) {
        printf("[!] Record corruption detected!\n");
        printf("    validated: %d\n", rec->validated);
        printf("    privilege: %d\n", rec->privilege);
    }
}

void multi_layer_obfuscated(const char *user_input) {
    char layer1[16];
    char layer2[16];
    char layer3[16];
    int flag1 = 0;
    int flag2 = 0;
    int flag3 = 0;
    
    // Layer 1: Macro-hidden copy
    SAFE_COPY(layer1, user_input);
    
    // Layer 2: Indirect copy
    string_transfer(layer2, layer1);
    
    // Layer 3: State machine copy
    process_with_state_machine(layer3, layer2);
    
    printf("[*] Processing complete\n");
    printf("    flag1: %d, flag2: %d, flag3: %d\n", flag1, flag2, flag3);
    
    // Corruption check
    if (flag1 || flag2 || flag3) {
        printf("[!] Stack corruption via obfuscated overflow!\n");
    }
}

// ============================================
// "SAFE" API THAT ISN'T
// ============================================

// Looks like a safe string library
typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} safe_string;

safe_string* safe_string_create(size_t initial_capacity) {
    safe_string *s = malloc(sizeof(safe_string));
    s->data = malloc(initial_capacity);
    s->length = 0;
    s->capacity = initial_capacity;
    return s;
}

// Looks safe but has subtle bug
void safe_string_append(safe_string *s, const char *str) {
    size_t str_len = strlen(str);
    
    // "Safety" check
    if (s->length + str_len >= s->capacity) {
        // Should reallocate but doesn't!
        printf("[!] Would overflow, but continuing anyway...\n");
        // Falls through to vulnerable copy
    }
    
    // VULN: Copies regardless of capacity check
    strcpy(s->data + s->length, str);
    s->length += str_len;
}

int main(int argc, char *argv[]) {
    printf("=== Obfuscated Buffer Overflow Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo> [input]\n", argv[0]);
        printf("\nDemos:\n");
        printf("  macro <input>     - Macro-hidden overflow\n");
        printf("  indirect <input>  - Indirect function overflow\n");
        printf("  state <input>     - State machine overflow\n");
        printf("  recursive <input> - Recursive overflow\n");
        printf("  record <input>    - Record corruption\n");
        printf("  multi <input>     - Multi-layer obfuscated\n");
        printf("  safestr <input>   - 'Safe' string overflow\n");
        return 1;
    }
    
    if (strcmp(argv[1], "macro") == 0 && argc >= 3) {
        char buf[16];
        SAFE_COPY(buf, argv[2]);
        printf("Result: %s\n", buf);
        
    } else if (strcmp(argv[1], "indirect") == 0 && argc >= 3) {
        char buf[16];
        string_transfer(buf, argv[2]);
        printf("Result: %s\n", buf);
        
    } else if (strcmp(argv[1], "state") == 0 && argc >= 3) {
        char buf[16];
        process_with_state_machine(buf, argv[2]);
        printf("Result: %s\n", buf);
        
    } else if (strcmp(argv[1], "recursive") == 0 && argc >= 3) {
        char buf[16];
        recursive_copy(buf, argv[2], 0);
        printf("Result: %s\n", buf);
        
    } else if (strcmp(argv[1], "record") == 0 && argc >= 3) {
        obfuscated_record rec;
        process_obfuscated_record(&rec, argv[2]);
        printf("Record name: %s\n", rec.safe_name);
        
    } else if (strcmp(argv[1], "multi") == 0 && argc >= 3) {
        multi_layer_obfuscated(argv[2]);
        
    } else if (strcmp(argv[1], "safestr") == 0 && argc >= 3) {
        safe_string *s = safe_string_create(16);
        safe_string_append(s, argv[2]);
        printf("Safe string: %s (len=%zu, cap=%zu)\n", 
               s->data, s->length, s->capacity);
        free(s->data);
        free(s);
    }
    
    return 0;
}

