#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define INPUT_SZ 64

// ---- intentionally not static ----
char secret[] = {0x21, 0x37, 0x13, 0x00};

/*
 * Hash-like mixing function
 * Looks crypto-ish but is weak on purpose
 */
unsigned long mix(const char *buf) {
    unsigned long h = 5381;
    int c;

    while ((c = *buf++))
        h = ((h << 5) + h) + c;   // djb2-ish

    for (int i = 0; secret[i]; i++)
        h ^= secret[i] << (i * 3);

    h ^= (time(NULL) / 30);
    return h;
}

/*
 * Verification routine
 */
int verify(const char *user) {
    unsigned long a = mix(user);
    unsigned long b = mix("operator");

    // weak comparison on purpose
    return (a & 0xfffff) == (b & 0xfffff);
}

/*
 * Debug helper (intentionally unsafe)
 */
void debug(char *msg) {
    printf(msg);     // FORMAT STRING VULN
    puts("");
}

/*
 * Hidden win function (not referenced directly)
 */
void win() {
    puts("[+] privileged path reached");
    system("/bin/sh");
}

int main() {
    char input[INPUT_SZ];
    char dbg[128];
    int choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("== session engine ==");
    puts("1. verify token");
    puts("2. debug message");
    puts("3. exit");

    while (1) {
        printf("> ");
        scanf("%d", &choice);
        getchar();

        if (choice == 1) {
            puts("token:");
            read(0, input, 128);        // STACK BUFFER OVERFLOW

            if (verify(input))
                puts("ACCESS GRANTED");
            else
                puts("ACCESS DENIED");
        }

        else if (choice == 2) {
            puts("debug:");
            scanf("%s", dbg);                  // STACK BUFFER OVERFLOW
            debug(dbg);
        }

        else if (choice == 3) {
            puts("bye");
            return 0;
        }
    }
}
