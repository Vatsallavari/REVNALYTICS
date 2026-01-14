#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USERNAME_LEN 16
#define PASSWORD_LEN 16

void banner() {
    puts("=================================");
    puts("   Internal Diagnostic Utility   ");
    puts("=================================");
}

void debug_log(char *msg) {
    // FORMAT STRING VULNERABILITY
    printf(msg);
    printf("\n");
}

int authenticate() {
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];

    puts("[*] Username:");
    scanf("%s", username);   // STACK BUFFER OVERFLOW

    puts("[*] Password:");
    scanf("%s", password);   // STACK BUFFER OVERFLOW

    if (strcmp(username, "admin") == 0 &&
        strcmp(password, "password123") == 0) {
        return 1;
    }
    return 0;
}

void read_file() {
    char filename[32];
    char buffer[128];
    FILE *fp;

    puts("[*] Enter filename:");
    scanf("%s", filename);   // STACK BUFFER OVERFLOW

    fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);

    puts("[*] File contents:");
    puts(buffer);            // INFO LEAK / NO NULL-TERM
}

void menu() {
    puts("\n1. Login");
    puts("2. Debug message");
    puts("3. Read file");
    puts("4. Exit");
}

int main() {
    int choice;
    short authenticated = 0;   // TRUNCATION TARGET

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    banner();

    while (1) {
        menu();
        puts("Choice:");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                authenticated = authenticate();
                puts(authenticated ? "[+] Logged in" : "[-] Failed");
                break;

            case 2: {
                char msg[128];
                puts("[*] Debug input:");
                scanf("%s", msg);     // STACK OVERFLOW
                debug_log(msg);       // FORMAT STRING
                break;
            }

            case 3:
                if (!authenticated) {
                    puts("[-] Access denied");
                    break;
                }
                read_file();
                break;

            case 4:
                exit(0);

            default:
                puts("Invalid option");
        }
    }
}
