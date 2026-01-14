/*
 * Combined Vulnerability: Buffer Overflow + Authentication Bypass
 * CVE Patterns: CWE-121 + CWE-287 + CWE-306 + CWE-863
 * Similar to: CVE-2021-3156 (sudo), CVE-2020-1938 (Tomcat Ghostcat)
 * 
 * Combines:
 * - Buffer overflow to bypass authentication
 * - Stack variable corruption for privilege escalation
 * - Return address overwrite for auth bypass
 * - Heap corruption to modify auth structures
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================
// Authentication structures
// ============================================

typedef struct {
    char username[32];
    char password_hash[64];
    int is_authenticated;
    int is_admin;
    int session_valid;
    void (*auth_callback)(void);
} AuthContext;

typedef struct {
    char token[32];
    int user_id;
    int permissions;
    time_t expiry;
} SessionToken;

// Global auth state
static int global_auth_status = 0;
static int global_admin_flag = 0;

// ============================================
// Callback functions
// ============================================

void admin_access_granted() {
    printf("[!!!] ADMIN ACCESS GRANTED!\n");
    printf("[!!!] You now have full system privileges!\n");
}

void user_access_granted() {
    printf("[*] Regular user access granted\n");
}

void access_denied() {
    printf("[-] Access denied\n");
}

// ============================================
// VULNERABILITY 1: Stack buffer overflow bypasses auth check
// ============================================

int authenticate_stack_vuln(const char *username, const char *password) {
    int authenticated = 0;  // Auth flag BEFORE buffer
    char user_buf[32];
    char pass_buf[32];
    int is_admin = 0;       // Admin flag AFTER buffer
    
    printf("[*] Stack layout:\n");
    printf("    &authenticated: %p\n", (void*)&authenticated);
    printf("    &user_buf:      %p\n", (void*)user_buf);
    printf("    &pass_buf:      %p\n", (void*)pass_buf);
    printf("    &is_admin:      %p\n", (void*)&is_admin);
    
    // VULN: Overflow pass_buf overwrites is_admin
    strcpy(user_buf, username);
    strcpy(pass_buf, password);  // OVERFLOW -> corrupts is_admin
    
    // Simulate password check
    if (strcmp(user_buf, "admin") == 0 && strcmp(pass_buf, "secretpassword") == 0) {
        authenticated = 1;
        is_admin = 1;
    }
    
    printf("[*] After input processing:\n");
    printf("    authenticated = %d\n", authenticated);
    printf("    is_admin = %d (0x%08x)\n", is_admin, is_admin);
    
    // Check if admin (can be corrupted by overflow!)
    if (is_admin) {
        printf("[!] Admin flag is set!\n");
        return 2;  // Admin access
    } else if (authenticated) {
        return 1;  // User access
    }
    
    return 0;  // Denied
}

// ============================================
// VULNERABILITY 2: Heap overflow corrupts auth structure
// ============================================

AuthContext* create_auth_context(const char *username) {
    AuthContext *ctx = (AuthContext *)malloc(sizeof(AuthContext));
    
    // Initialize to safe defaults
    ctx->is_authenticated = 0;
    ctx->is_admin = 0;
    ctx->session_valid = 0;
    ctx->auth_callback = access_denied;
    
    // VULN: Overflow in username corrupts other fields
    strcpy(ctx->username, username);  // No bounds check!
    
    printf("[*] AuthContext at %p:\n", (void*)ctx);
    printf("    username offset:      0\n");
    printf("    is_authenticated at:  +32\n");
    printf("    is_admin at:          +36\n");
    printf("    auth_callback at:     +48\n");
    
    return ctx;
}

int verify_auth_context(AuthContext *ctx) {
    printf("[*] Checking auth context:\n");
    printf("    is_authenticated: %d\n", ctx->is_authenticated);
    printf("    is_admin: %d\n", ctx->is_admin);
    printf("    auth_callback: %p\n", (void*)ctx->auth_callback);
    
    if (ctx->auth_callback) {
        printf("[*] Calling auth callback...\n");
        ctx->auth_callback();
    }
    
    // VULN: These can be corrupted by overflow
    if (ctx->is_admin) {
        return 2;
    } else if (ctx->is_authenticated) {
        return 1;
    }
    return 0;
}

// ============================================
// VULNERABILITY 3: Format string + auth bypass
// ============================================

int authenticate_format_vuln(const char *username) {
    char greeting[128];
    int access_level = 0;
    
    // Build greeting with potential format string
    snprintf(greeting, sizeof(greeting), "Welcome, %s!", username);
    
    // VULN: Format string can modify access_level
    printf(greeting);  // FORMAT STRING VULN!
    printf("\n");
    
    printf("[*] access_level address: %p\n", (void*)&access_level);
    printf("[*] access_level value: %d\n", access_level);
    
    // If access_level was modified by %n, auth bypassed
    if (access_level != 0) {
        printf("[!] Access level modified!\n");
        return access_level;
    }
    
    return 0;
}

// ============================================
// VULNERABILITY 4: Integer overflow in permission check
// ============================================

typedef struct {
    char name[32];
    uint32_t required_level;
    uint32_t user_level;
} PermissionCheck;

int check_permission_vuln(const char *resource, uint32_t user_level, uint32_t bonus) {
    PermissionCheck check;
    
    strcpy(check.name, resource);
    check.required_level = 100;  // Need level 100
    check.user_level = user_level;
    
    // VULN: Integer overflow bypass
    // If user_level + bonus overflows to small value, then >= wraps around
    uint32_t effective_level = user_level + bonus;  // Can overflow!
    
    printf("[*] Permission check:\n");
    printf("    Required: %u\n", check.required_level);
    printf("    User level: %u\n", user_level);
    printf("    Bonus: %u\n", bonus);
    printf("    Effective: %u (0x%08x)\n", effective_level, effective_level);
    
    // Another VULN: Subtraction underflow
    if (check.required_level - effective_level > 0x80000000) {
        // If effective > required, subtraction "underflows" to large positive
        printf("[!] Permission granted via underflow!\n");
        return 1;
    }
    
    if (effective_level >= check.required_level) {
        printf("[+] Permission granted\n");
        return 1;
    }
    
    printf("[-] Permission denied\n");
    return 0;
}

// ============================================
// VULNERABILITY 5: Session token overflow + type confusion
// ============================================

typedef struct {
    int type;  // 1 = user, 2 = admin
    char data[60];
} GenericToken;

typedef struct {
    int type;
    char user_token[28];
    int admin_flag;  // At offset 32
    char admin_token[28];
} MixedToken;

void process_token_vuln(const char *token_data, int token_type) {
    MixedToken token;
    
    token.type = token_type;
    token.admin_flag = 0;
    
    // VULN: Copy without checking which part of union
    if (token_type == 1) {
        // User token - should only fill user_token
        // But strcpy can overflow into admin_flag and admin_token
        strcpy(token.user_token, token_data);
    } else {
        strcpy(token.admin_token, token_data);
    }
    
    printf("[*] Token processed:\n");
    printf("    type: %d\n", token.type);
    printf("    admin_flag: %d (0x%08x)\n", token.admin_flag, token.admin_flag);
    
    // Check if admin (corrupted by overflow)
    if (token.admin_flag != 0) {
        printf("[!] Admin flag set via overflow!\n");
        admin_access_granted();
    }
}

// ============================================
// VULNERABILITY 6: Return-to-libc style auth bypass
// ============================================

// This function should never be called directly
void __attribute__((used)) secret_admin_backdoor() {
    printf("\n[!!!] SECRET BACKDOOR ACTIVATED!\n");
    printf("[!!!] Arbitrary code execution achieved!\n");
    global_admin_flag = 1;
    global_auth_status = 1;
}

void vulnerable_login(const char *input) {
    char buffer[64];
    void (*callback)(void) = access_denied;
    
    printf("[*] Buffer at: %p\n", (void*)buffer);
    printf("[*] Callback at: %p (value: %p)\n", (void*)&callback, (void*)callback);
    printf("[*] secret_admin_backdoor at: %p\n", (void*)secret_admin_backdoor);
    
    // VULN: Overflow buffer to overwrite callback pointer
    strcpy(buffer, input);
    
    printf("[*] After overflow, callback = %p\n", (void*)callback);
    
    // Call potentially corrupted pointer
    if (callback) {
        callback();
    }
}

// ============================================
// COMBINED ATTACK CHAIN
// ============================================

void multi_stage_attack(const char *stage1, const char *stage2, uint32_t stage3) {
    printf("\n=== Multi-Stage Auth Bypass Attack ===\n\n");
    
    // Stage 1: Heap overflow to set is_authenticated
    printf("[Stage 1] Heap overflow in username...\n");
    AuthContext *ctx = create_auth_context(stage1);
    
    // Stage 2: Stack overflow to set is_admin
    printf("\n[Stage 2] Stack overflow in password...\n");
    int result = authenticate_stack_vuln("user", stage2);
    
    // Stage 3: Integer overflow for permission
    printf("\n[Stage 3] Integer overflow in permission check...\n");
    check_permission_vuln("secret_resource", 1, stage3);
    
    // Final check
    printf("\n[Results]\n");
    printf("Stack auth result: %d\n", result);
    printf("Heap auth context is_admin: %d\n", ctx->is_admin);
    printf("Heap auth context is_authenticated: %d\n", ctx->is_authenticated);
    
    free(ctx);
}

int main(int argc, char *argv[]) {
    printf("=== Buffer Overflow + Auth Bypass Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo> [args...]\n", argv[0]);
        printf("\nDemos:\n");
        printf("  stack <user> <long_pass>     - Stack overflow auth bypass\n");
        printf("  heap <long_username>         - Heap overflow auth bypass\n");
        printf("  format <format_string>       - Format string auth bypass\n");
        printf("  intover <level> <bonus>      - Integer overflow permission bypass\n");
        printf("  token <long_token>           - Token overflow privilege escalation\n");
        printf("  callback <payload>           - Function pointer overwrite\n");
        printf("  chain <s1> <s2> <s3>         - Multi-stage combined attack\n");
        printf("\nExamples:\n");
        printf("  %s stack user $(python3 -c \"print('A'*32 + '\\x01\\x00\\x00\\x00')\")\n", argv[0]);
        printf("  %s heap $(python3 -c \"print('A'*32 + '\\x01' + 'B'*31 + '\\x01')\")\n", argv[0]);
        printf("  %s intover 1 4294967295\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "stack") == 0 && argc >= 4) {
        int result = authenticate_stack_vuln(argv[2], argv[3]);
        printf("\nFinal result: %s\n", 
               result == 2 ? "ADMIN" : result == 1 ? "USER" : "DENIED");
        
    } else if (strcmp(argv[1], "heap") == 0 && argc >= 3) {
        AuthContext *ctx = create_auth_context(argv[2]);
        int result = verify_auth_context(ctx);
        printf("\nFinal result: %s\n",
               result == 2 ? "ADMIN" : result == 1 ? "USER" : "DENIED");
        free(ctx);
        
    } else if (strcmp(argv[1], "format") == 0 && argc >= 3) {
        int result = authenticate_format_vuln(argv[2]);
        printf("\nFinal result: access_level = %d\n", result);
        
    } else if (strcmp(argv[1], "intover") == 0 && argc >= 4) {
        uint32_t level = (uint32_t)strtoul(argv[2], NULL, 10);
        uint32_t bonus = (uint32_t)strtoul(argv[3], NULL, 10);
        check_permission_vuln("admin_panel", level, bonus);
        
    } else if (strcmp(argv[1], "token") == 0 && argc >= 3) {
        process_token_vuln(argv[2], 1);
        
    } else if (strcmp(argv[1], "callback") == 0 && argc >= 3) {
        vulnerable_login(argv[2]);
        printf("\nGlobal auth status: %d, admin: %d\n", 
               global_auth_status, global_admin_flag);
        
    } else if (strcmp(argv[1], "chain") == 0 && argc >= 5) {
        multi_stage_attack(argv[2], argv[3], (uint32_t)strtoul(argv[4], NULL, 10));
    }
    
    return 0;
}

