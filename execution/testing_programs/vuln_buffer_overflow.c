/*
 * Vulnerable Program: Stack Buffer Overflow
 * CVE Pattern: CWE-121 (Stack-based Buffer Overflow)
 * Similar to: CVE-2021-3156 (sudo heap overflow), CVE-2017-9798 (Apache Optionsbleed)
 * 
 * Vulnerability: Uses strcpy() without bounds checking, allowing
 * arbitrary code execution via stack smashing.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Vulnerable function - no bounds checking
void process_input(char *user_input) {
    char buffer[64];  // Fixed size buffer
    
    // VULNERABLE: strcpy does not check bounds
    // Attacker can overflow buffer and overwrite return address
    strcpy(buffer, user_input);
    
    printf("Processed: %s\n", buffer);
}

// Another vulnerable pattern - gets() is inherently unsafe
void read_username() {
    char username[32];
    
    printf("Enter username: ");
    // VULNERABLE: gets() is deprecated and dangerous
    // No way to limit input size
    gets(username);
    
    printf("Hello, %s!\n", username);
}

// Vulnerable sprintf without size limit
void log_action(char *action, char *details) {
    char log_entry[128];
    
    // VULNERABLE: sprintf can overflow log_entry
    sprintf(log_entry, "[ACTION] %s: %s", action, details);
    
    printf("%s\n", log_entry);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("This program demonstrates buffer overflow vulnerabilities\n");
        return 1;
    }
    
    printf("=== Buffer Overflow Demo ===\n");
    process_input(argv[1]);
    
    return 0;
}

