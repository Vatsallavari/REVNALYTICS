#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NOTE_SZ 64

/* ----------------- benign helpers ----------------- */

void banner() {
    puts("=== Internal Note Processor v1 ===");
}

void log_event(const char *msg) {
    printf("[log] %s\n", msg);
}

/* ----------------- hidden privileged function ----------------- */

void win() {
    puts("[+] privileged execution reached");
    system("/bin/sh");
}

/* ----------------- THE ONLY VULNERABLE FUNCTION ----------------- */
/*
 * This function is exploitable.
 * It is NEVER called directly by user input.
 */
void unsafe_copy(char *dst, const char *src) {
    char tmp[32];

    /* Vulnerability: stack buffer overflow */
    strcpy(tmp, src);     // <-- THE bug

    memcpy(dst, tmp, strlen(tmp));
}

/* ----------------- gatekeeper ----------------- */

void process_note() {
    char note[NOTE_SZ];
    char output[NOTE_SZ];

    puts("Enter note:");
    read(0, note, 128);          // user controls note

    log_event("processing note");

    /*
     * Looks innocent in Ghidra:
     * - No dangerous APIs here
     * - But it passes attacker data into unsafe_copy()
     */
    unsafe_copy(output, note);

    puts("Stored note:");
    puts(output);
}

/* ----------------- dead-end functions ----------------- */

void diagnostics() {
    char buf[32];
    puts("diagnostics:");
    fgets(buf, sizeof(buf), stdin);
    puts("ok");
}

void help() {
    puts("1. process note");
    puts("2. diagnostics");
    puts("3. exit");
}

/* ----------------- main ----------------- */

int main() {
    int choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    banner();

    while (1) {
        help();
        printf("> ");
        scanf("%d", &choice);
        getchar();

        switch (choice) {
            case 1:
                process_note();     // ONLY path to vuln
                break;
            case 2:
                diagnostics();      // red herring
                break;
            case 3:
                puts("bye");
                return 0;
            default:
                puts("invalid");
        }
    }
}
