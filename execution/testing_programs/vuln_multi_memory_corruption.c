/*
 * Multi-Vulnerability Program: Combined Memory Corruption
 * CVE Patterns: CWE-121 + CWE-134 + CWE-190 + CWE-416
 * 
 * Combines:
 * - Stack buffer overflow
 * - Format string vulnerability  
 * - Integer overflow
 * - Use-after-free
 * 
 * Multiple attack vectors in single program for testing detection tools.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    char username[32];
    int privilege_level;
    void (*handler)(char *);
} UserContext;

UserContext *global_ctx = NULL;

// Handler functions
void admin_handler(char *msg) {
    printf("[ADMIN] %s\n", msg);
    printf("[ADMIN] Executing privileged operation...\n");
}

void user_handler(char *msg) {
    printf("[USER] %s\n", msg);
}

// ===== VULNERABILITY 1: Buffer Overflow (CWE-121) =====
void process_username(char *input) {
    char local_buf[32];
    // VULN: strcpy without bounds check
    strcpy(local_buf, input);
    printf("Processing user: %s\n", local_buf);
}

// ===== VULNERABILITY 2: Format String (CWE-134) =====
void log_message(char *msg) {
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "[LOG] %s", msg);
    // VULN: Format string - msg can contain format specifiers
    printf(log_buf);
    printf("\n");
}

// ===== VULNERABILITY 3: Integer Overflow (CWE-190) =====
char* allocate_buffer(uint32_t count, uint32_t size) {
    // VULN: Multiplication overflow
    uint32_t total = count * size;
    printf("Allocating: %u * %u = %u bytes\n", count, size, total);
    
    char *buf = (char *)malloc(total);
    if (buf) {
        // If overflow occurred, this writes beyond allocation
        memset(buf, 'A', count * size);
    }
    return buf;
}

// ===== VULNERABILITY 4: Use-After-Free (CWE-416) =====
void create_context(const char *name, int priv) {
    global_ctx = (UserContext *)malloc(sizeof(UserContext));
    strncpy(global_ctx->username, name, 31);
    global_ctx->privilege_level = priv;
    global_ctx->handler = (priv > 0) ? admin_handler : user_handler;
}

void destroy_context() {
    if (global_ctx) {
        free(global_ctx);
        // VULN: Pointer not nullified - dangling pointer
    }
}

void use_context(char *action) {
    // VULN: Uses potentially freed memory
    if (global_ctx) {
        printf("User: %s, Privilege: %d\n", 
               global_ctx->username, 
               global_ctx->privilege_level);
        global_ctx->handler(action);
    }
}

// ===== COMBINED ATTACK CHAIN =====
void process_request(char *user, char *action, uint32_t data_count) {
    // Step 1: Buffer overflow via username
    process_username(user);
    
    // Step 2: Format string via action logging
    log_message(action);
    
    // Step 3: Integer overflow in allocation
    char *data = allocate_buffer(data_count, 64);
    
    // Step 4: Potential UAF if context was previously freed
    use_context(action);
    
    if (data) free(data);
}

// Vulnerable initialization sequence
void init_system(char *config) {
    char config_buf[64];
    
    // VULN 1: Buffer overflow
    sprintf(config_buf, "Config: %s", config);
    
    // VULN 2: Format string
    printf(config_buf);
    printf("\n");
    
    create_context("system", 1);
}

int main(int argc, char *argv[]) {
    printf("=== Multi-Vulnerability Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <mode> [args...]\n", argv[0]);
        printf("\nModes:\n");
        printf("  overflow <long_string>     - Buffer overflow\n");
        printf("  format <format_string>     - Format string\n");
        printf("  integer <count>            - Integer overflow\n");
        printf("  uaf                        - Use-after-free\n");
        printf("  chain <user> <action> <n>  - Combined attack\n");
        return 1;
    }
    
    if (strcmp(argv[1], "overflow") == 0 && argc >= 3) {
        process_username(argv[2]);
        
    } else if (strcmp(argv[1], "format") == 0 && argc >= 3) {
        log_message(argv[2]);
        
    } else if (strcmp(argv[1], "integer") == 0 && argc >= 3) {
        uint32_t count = (uint32_t)strtoul(argv[2], NULL, 10);
        char *buf = allocate_buffer(count, 64);
        if (buf) free(buf);
        
    } else if (strcmp(argv[1], "uaf") == 0) {
        create_context("victim", 0);
        destroy_context();
        // UAF: context still used after free
        use_context("test action");
        
    } else if (strcmp(argv[1], "chain") == 0 && argc >= 5) {
        init_system("default");
        process_request(argv[2], argv[3], (uint32_t)atoi(argv[4]));
        destroy_context();
    }
    
    return 0;
}

