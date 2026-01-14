/*
 * Vulnerable Program: Use-After-Free
 * CVE Pattern: CWE-416 (Use After Free)
 * Similar to: CVE-2021-22555 (Linux kernel), CVE-2022-0847 (Dirty Pipe)
 * 
 * Vulnerability: Memory accessed after being freed, leading to
 * potential code execution or information disclosure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Structure to simulate an object
typedef struct {
    char name[32];
    int id;
    void (*callback)(void);
} UserObject;

// Global pointer for demonstration
UserObject *global_user = NULL;

void admin_function() {
    printf("[!] ADMIN FUNCTION CALLED - This shouldn't happen!\n");
    printf("[!] Arbitrary code execution achieved!\n");
}

void normal_callback() {
    printf("[*] Normal callback executed\n");
}

// VULNERABLE: Use after free - dangling pointer
void create_user(const char *name, int id) {
    global_user = (UserObject *)malloc(sizeof(UserObject));
    if (!global_user) {
        printf("Allocation failed\n");
        return;
    }
    
    strncpy(global_user->name, name, 31);
    global_user->name[31] = '\0';
    global_user->id = id;
    global_user->callback = normal_callback;
    
    printf("[+] Created user: %s (ID: %d)\n", global_user->name, global_user->id);
}

// VULNERABLE: Frees memory but doesn't null the pointer
void delete_user() {
    if (global_user) {
        printf("[+] Deleting user: %s\n", global_user->name);
        free(global_user);
        // BUG: Pointer not set to NULL after free
        // global_user = NULL;  // This line is missing!
    }
}

// VULNERABLE: Uses freed memory
void print_user_info() {
    // VULNERABLE: No check if memory was freed
    // This accesses freed memory (dangling pointer)
    if (global_user) {  // This check passes even after free!
        printf("[*] User Info:\n");
        printf("    Name: %s\n", global_user->name);
        printf("    ID: %d\n", global_user->id);
    }
}

// VULNERABLE: Calls function pointer from freed memory
void execute_callback() {
    // VULNERABLE: Calls potentially corrupted function pointer
    if (global_user && global_user->callback) {
        printf("[*] Executing callback...\n");
        global_user->callback();
    }
}

// Attacker can allocate memory of same size to control freed region
void exploit_allocate(const char *data) {
    // This allocation might reuse the freed memory
    char *exploit_buffer = (char *)malloc(sizeof(UserObject));
    if (exploit_buffer) {
        memcpy(exploit_buffer, data, sizeof(UserObject));
        printf("[*] Allocated exploit buffer at: %p\n", (void*)exploit_buffer);
    }
}

// Double-free vulnerability
void double_free_vuln() {
    char *ptr = (char *)malloc(64);
    strcpy(ptr, "test data");
    
    printf("[*] Allocated: %p\n", (void*)ptr);
    free(ptr);
    printf("[*] First free done\n");
    
    // VULNERABLE: Double free
    free(ptr);
    printf("[*] Second free done (DOUBLE FREE!)\n");
}

int main(int argc, char *argv[]) {
    printf("=== Use-After-Free Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <action>\n", argv[0]);
        printf("\nActions:\n");
        printf("  demo     - Run UAF demonstration\n");
        printf("  double   - Run double-free demonstration\n");
        return 1;
    }
    
    if (strcmp(argv[1], "demo") == 0) {
        // Step 1: Create user
        create_user("Alice", 1001);
        printf("global_user pointer: %p\n\n", (void*)global_user);
        
        // Step 2: Delete user (but pointer remains!)
        delete_user();
        printf("global_user pointer after free: %p (should be NULL!)\n\n", (void*)global_user);
        
        // Step 3: Access freed memory (UAF!)
        printf("[!] Attempting to access freed memory...\n");
        print_user_info();  // UAF: reads freed memory
        
        // Step 4: Potentially call corrupted function pointer
        printf("\n[!] Attempting to call callback from freed object...\n");
        execute_callback();  // UAF: might call attacker-controlled function
        
    } else if (strcmp(argv[1], "double") == 0) {
        double_free_vuln();
    }
    
    return 0;
}

