/*
 * Vulnerable Program: Heap Buffer Overflow
 * CVE Pattern: CWE-122 (Heap-based Buffer Overflow)
 * Similar to: CVE-2021-3156 (sudo Baron Samedit), CVE-2014-0160 (Heartbleed)
 * 
 * Vulnerability: Writing beyond allocated heap buffer boundaries,
 * potentially corrupting heap metadata or adjacent objects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Structure that might be adjacent in heap
typedef struct {
    char data[64];
    int is_admin;
    void (*auth_callback)(void);
} UserSession;

typedef struct {
    char buffer[32];
    char secret[32];
} DataBlock;

void grant_admin() {
    printf("[!] ADMIN ACCESS GRANTED!\n");
    printf("[!] This function should never be called by normal users!\n");
}

void normal_auth() {
    printf("[*] Normal user authenticated\n");
}

// VULNERABLE: Off-by-one heap overflow
char* copy_string_vulnerable(const char *input) {
    size_t len = strlen(input);
    
    // VULNERABLE: Allocates exact length, no room for null terminator
    char *buffer = (char *)malloc(len);  // Should be len + 1
    
    if (!buffer) return NULL;
    
    // VULNERABLE: strcpy writes null terminator beyond allocated space
    strcpy(buffer, input);
    
    return buffer;
}

// VULNERABLE: Heap overflow via memcpy
void process_data_vulnerable(const char *user_data, size_t claimed_len) {
    DataBlock *block = (DataBlock *)malloc(sizeof(DataBlock));
    
    if (!block) return;
    
    // Initialize with secret data
    strcpy(block->secret, "TOP_SECRET_DATA_12345");
    
    printf("[*] DataBlock allocated at: %p\n", (void*)block);
    printf("[*] block->buffer at: %p\n", (void*)block->buffer);
    printf("[*] block->secret at: %p\n", (void*)block->secret);
    
    // VULNERABLE: No bounds check - user controls claimed_len
    // If claimed_len > 32, overwrites into secret field
    printf("[*] Copying %zu bytes into 32-byte buffer...\n", claimed_len);
    memcpy(block->buffer, user_data, claimed_len);
    
    printf("[*] block->buffer: %.32s\n", block->buffer);
    printf("[*] block->secret: %s\n", block->secret);  // May be corrupted
    
    free(block);
}

// VULNERABLE: Heap spray / overflow to corrupt adjacent object
void heap_corruption_demo(const char *malicious_input) {
    // Allocate two adjacent structures
    UserSession *legit_session = (UserSession *)malloc(sizeof(UserSession));
    UserSession *attacker_target = (UserSession *)malloc(sizeof(UserSession));
    
    if (!legit_session || !attacker_target) return;
    
    // Initialize legitimate session
    strcpy(legit_session->data, "normal_user_data");
    legit_session->is_admin = 0;
    legit_session->auth_callback = normal_auth;
    
    // Initialize target (simulates another user's session)
    strcpy(attacker_target->data, "admin_session");
    attacker_target->is_admin = 0;
    attacker_target->auth_callback = normal_auth;
    
    printf("[*] Legitimate session at: %p\n", (void*)legit_session);
    printf("[*] Target session at: %p\n", (void*)attacker_target);
    printf("[*] Distance between allocations: %ld bytes\n", 
           (long)((char*)attacker_target - (char*)legit_session));
    
    printf("\n[*] Before overflow:\n");
    printf("    Target is_admin: %d\n", attacker_target->is_admin);
    
    // VULNERABLE: Overflow from legit_session into attacker_target
    // If input is larger than legit_session->data (64 bytes), 
    // it corrupts is_admin and auth_callback
    printf("\n[*] Copying potentially oversized input...\n");
    strcpy(legit_session->data, malicious_input);  // VULNERABLE: No bounds check
    
    printf("\n[*] After overflow:\n");
    printf("    Target is_admin: %d\n", attacker_target->is_admin);
    
    // Check if we became admin
    if (attacker_target->is_admin != 0) {
        printf("[!] Heap overflow successful - admin flag corrupted!\n");
    }
    
    free(legit_session);
    free(attacker_target);
}

// VULNERABLE: realloc without updating size tracking
char* append_data_vulnerable(char *buffer, size_t *current_size, 
                             const char *append, size_t append_len) {
    // VULNERABLE: Integer overflow in size calculation
    size_t new_size = *current_size + append_len;
    
    if (new_size < *current_size) {
        printf("[!] Integer overflow detected but ignored!\n");
        // Bug: Continues anyway
    }
    
    char *new_buffer = (char *)realloc(buffer, new_size);
    if (!new_buffer) {
        free(buffer);
        return NULL;
    }
    
    // VULNERABLE: If realloc failed to expand properly due to overflow
    memcpy(new_buffer + *current_size, append, append_len);
    *current_size = new_size;
    
    return new_buffer;
}

int main(int argc, char *argv[]) {
    printf("=== Heap Overflow Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo_type> [data]\n", argv[0]);
        printf("\nDemo types:\n");
        printf("  offbyone    - Off-by-one overflow\n");
        printf("  memcpy      - memcpy overflow\n");
        printf("  corrupt     - Heap metadata corruption\n");
        return 1;
    }
    
    if (strcmp(argv[1], "offbyone") == 0) {
        // Off-by-one demo
        char *result = copy_string_vulnerable("AAAAAAAAAAAAAAAA");  // 16 A's
        if (result) {
            printf("[*] Copied string: %s\n", result);
            free(result);
        }
        
    } else if (strcmp(argv[1], "memcpy") == 0) {
        // memcpy overflow demo
        char overflow_data[128];
        memset(overflow_data, 'X', 64);  // Fill 64 bytes with 'X'
        strcpy(overflow_data + 32, "OVERWRITTEN_SECRET!");
        
        // Claim 64 bytes but buffer is only 32
        process_data_vulnerable(overflow_data, 64);
        
    } else if (strcmp(argv[1], "corrupt") == 0) {
        // Heap corruption demo
        if (argc >= 3) {
            heap_corruption_demo(argv[2]);
        } else {
            // Create payload that overflows into is_admin
            char payload[128];
            memset(payload, 'A', 64);  // Fill data[64]
            *(int*)(payload + 64) = 1;  // Overwrite is_admin
            payload[68] = '\0';
            
            heap_corruption_demo(payload);
        }
    }
    
    return 0;
}

