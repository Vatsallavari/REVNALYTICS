/*
 * Vulnerable Program: Format String Attack
 * CVE Pattern: CWE-134 (Use of Externally-Controlled Format String)
 * Similar to: CVE-2012-0809 (sudo format string), CVE-2000-0573 (wu-ftpd)
 * 
 * Vulnerability: User input passed directly to printf() family functions
 * allows reading/writing arbitrary memory locations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulated sensitive data
static char secret_key[] = "SUPER_SECRET_API_KEY_12345";
static int admin_flag = 0;

// VULNERABLE: Direct user input to printf
void print_welcome(char *username) {
    char message[256];
    snprintf(message, sizeof(message), "Welcome, %s!", username);
    
    // VULNERABLE: format string attack possible
    // Attacker can use %x, %n, %s to read/write memory
    printf(message);
    printf("\n");
}

// VULNERABLE: User-controlled format string in fprintf
void log_user_action(char *action) {
    FILE *log = fopen("/tmp/app.log", "a");
    if (log) {
        // VULNERABLE: action is user-controlled format string
        fprintf(log, action);
        fprintf(log, "\n");
        fclose(log);
    }
}

// VULNERABLE: syslog-style format string issue
void debug_print(char *msg) {
    // VULNERABLE: Direct format string
    printf(msg);
}

// Demonstrate the vulnerability
void check_admin_status() {
    if (admin_flag) {
        printf("Admin access granted! Secret: %s\n", secret_key);
    } else {
        printf("Access denied. admin_flag = %d\n", admin_flag);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <username>\n", argv[0]);
        printf("Try: %s '%%x.%%x.%%x.%%x' to leak stack data\n", argv[0]);
        printf("This program demonstrates format string vulnerabilities\n");
        return 1;
    }
    
    printf("=== Format String Demo ===\n");
    printf("admin_flag address: %p\n", (void*)&admin_flag);
    
    print_welcome(argv[1]);
    check_admin_status();
    
    return 0;
}

