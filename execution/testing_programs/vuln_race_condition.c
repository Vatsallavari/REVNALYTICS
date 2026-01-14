/*
 * Vulnerable Program: Race Condition / TOCTOU
 * CVE Pattern: CWE-367 (Time-of-check Time-of-use Race Condition)
 * Similar to: CVE-2016-9566 (Nagios), CVE-2021-3560 (polkit)
 * 
 * Vulnerability: Time gap between checking a condition and using
 * the result allows an attacker to change state in between.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define TEMP_FILE "/tmp/race_condition_test"
#define SAFE_DIR "/tmp/safe_uploads"

// VULNERABLE: TOCTOU race in file access
int read_file_vulnerable(const char *filename) {
    struct stat st;
    
    // TIME OF CHECK: Verify file is a regular file and readable
    if (stat(filename, &st) != 0) {
        printf("[-] Cannot stat file: %s\n", strerror(errno));
        return -1;
    }
    
    // Check if it's a regular file (not symlink, directory, etc.)
    if (!S_ISREG(st.st_mode)) {
        printf("[-] Not a regular file!\n");
        return -1;
    }
    
    // Check if file is safe (not too large, owned by us, etc.)
    if (st.st_size > 1024 * 1024) {
        printf("[-] File too large!\n");
        return -1;
    }
    
    printf("[*] Security checks passed. File size: %ld bytes\n", st.st_size);
    
    // VULNERABLE WINDOW: Attacker can replace file with symlink here!
    // e.g., rm /tmp/file && ln -s /etc/shadow /tmp/file
    printf("[*] Sleeping to simulate processing delay...\n");
    sleep(2);  // Artificial delay to make race window obvious
    
    // TIME OF USE: Actually open and read the file
    // By now, the file might be different!
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("[-] Cannot open file: %s\n", strerror(errno));
        return -1;
    }
    
    char buffer[4096];
    size_t bytes = fread(buffer, 1, sizeof(buffer) - 1, f);
    buffer[bytes] = '\0';
    fclose(f);
    
    printf("[+] File contents (%zu bytes):\n%s\n", bytes, buffer);
    return 0;
}

// VULNERABLE: TOCTOU in file creation/write
int write_file_vulnerable(const char *filename, const char *data) {
    struct stat st;
    
    // TIME OF CHECK: Ensure file doesn't exist
    if (stat(filename, &st) == 0) {
        printf("[-] File already exists, won't overwrite\n");
        return -1;
    }
    
    // Check if errno is ENOENT (file not found - expected)
    if (errno != ENOENT) {
        printf("[-] Unexpected error: %s\n", strerror(errno));
        return -1;
    }
    
    printf("[*] File doesn't exist, safe to create\n");
    
    // VULNERABLE WINDOW: Attacker creates symlink here!
    // ln -s /etc/cron.d/backdoor /tmp/target_file
    printf("[*] Sleeping before creating file...\n");
    sleep(2);
    
    // TIME OF USE: Create and write to file
    // This might now write to attacker-controlled location via symlink!
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("[-] Cannot create file: %s\n", strerror(errno));
        return -1;
    }
    
    fprintf(f, "%s", data);
    fclose(f);
    
    printf("[+] Data written to %s\n", filename);
    return 0;
}

// VULNERABLE: TOCTOU in permission check
int execute_as_root_vulnerable(const char *script_path) {
    struct stat st;
    
    // TIME OF CHECK: Verify script is owned by root and not writable by others
    if (stat(script_path, &st) != 0) {
        printf("[-] Cannot stat script\n");
        return -1;
    }
    
    // Check ownership
    if (st.st_uid != 0) {
        printf("[-] Script must be owned by root\n");
        return -1;
    }
    
    // Check permissions - no world-writable
    if (st.st_mode & S_IWOTH) {
        printf("[-] Script is world-writable!\n");
        return -1;
    }
    
    printf("[*] Security checks passed\n");
    printf("[*] Owner: root, Permissions: %o\n", st.st_mode & 0777);
    
    // VULNERABLE WINDOW: Attacker modifies script content here
    printf("[*] Preparing to execute (sleeping)...\n");
    sleep(2);
    
    // TIME OF USE: Execute the script
    // Script content may have changed!
    printf("[+] Executing script: %s\n", script_path);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/bin/sh %s", script_path);
    return system(cmd);
}

// VULNERABLE: Race in temporary file creation
int process_with_tempfile_vulnerable(const char *data) {
    char tempname[256];
    snprintf(tempname, sizeof(tempname), "/tmp/process_%d", getpid());
    
    // VULNERABLE: Predictable temporary filename
    // Attacker can pre-create symlink: ln -s /etc/passwd /tmp/process_12345
    
    printf("[*] Using temp file: %s\n", tempname);
    
    // Check if temp file exists
    if (access(tempname, F_OK) == 0) {
        printf("[-] Temp file exists, removing...\n");
        unlink(tempname);
    }
    
    // VULNERABLE WINDOW: Attacker creates symlink after unlink
    sleep(1);
    
    // Create temp file (may follow symlink!)
    FILE *f = fopen(tempname, "w");
    if (!f) {
        printf("[-] Cannot create temp file\n");
        return -1;
    }
    
    fprintf(f, "%s", data);
    fclose(f);
    
    printf("[+] Data written to temp file\n");
    
    // Process and cleanup
    unlink(tempname);
    return 0;
}

// VULNERABLE: Race in directory check
int save_upload_vulnerable(const char *filename, const char *content) {
    char fullpath[512];
    struct stat st;
    
    // Build full path
    snprintf(fullpath, sizeof(fullpath), "%s/%s", SAFE_DIR, filename);
    
    // TIME OF CHECK: Verify path is within safe directory
    char *resolved = realpath(fullpath, NULL);
    if (resolved) {
        if (strncmp(resolved, SAFE_DIR, strlen(SAFE_DIR)) != 0) {
            printf("[-] Path traversal detected!\n");
            free(resolved);
            return -1;
        }
        free(resolved);
    }
    
    printf("[*] Path validation passed: %s\n", fullpath);
    
    // VULNERABLE WINDOW: Attacker creates symlink in SAFE_DIR
    sleep(2);
    
    // TIME OF USE: Write to file
    FILE *f = fopen(fullpath, "w");
    if (!f) {
        printf("[-] Cannot create file\n");
        return -1;
    }
    
    fprintf(f, "%s", content);
    fclose(f);
    
    printf("[+] File saved: %s\n", fullpath);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== Race Condition (TOCTOU) Demo ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <demo_type> [args...]\n", argv[0]);
        printf("\nDemo types:\n");
        printf("  read <file>         - TOCTOU file read\n");
        printf("  write <file> <data> - TOCTOU file write\n");
        printf("  temp <data>         - Predictable temp file\n");
        printf("  upload <name> <data> - Upload race\n");
        printf("\nTo exploit, run in parallel:\n");
        printf("  # Terminal 1: %s read /tmp/testfile\n", argv[0]);
        printf("  # Terminal 2: while true; do ln -sf /etc/passwd /tmp/testfile 2>/dev/null; done\n");
        return 1;
    }
    
    // Create safe directory for upload test
    mkdir(SAFE_DIR, 0755);
    
    if (strcmp(argv[1], "read") == 0 && argc >= 3) {
        read_file_vulnerable(argv[2]);
        
    } else if (strcmp(argv[1], "write") == 0 && argc >= 4) {
        write_file_vulnerable(argv[2], argv[3]);
        
    } else if (strcmp(argv[1], "temp") == 0 && argc >= 3) {
        process_with_tempfile_vulnerable(argv[2]);
        
    } else if (strcmp(argv[1], "upload") == 0 && argc >= 4) {
        save_upload_vulnerable(argv[2], argv[3]);
        
    } else {
        printf("Invalid arguments\n");
    }
    
    return 0;
}

