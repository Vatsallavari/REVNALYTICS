#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char name[32];
    void (*action)();
} object;

object *obj = NULL;

void win() {
    puts("[+] You win!");
    system("/bin/sh");
}

void default_action() {
    puts("[-] Default action");
}

void create() {
    if (obj) {
        puts("[-] Object already exists");
        return;
    }

    obj = malloc(sizeof(object));
    obj->action = default_action;

    puts("[*] Enter name:");
    read(0, obj->name, 64);   // HEAP OVERFLOW (32-byte buffer)

    puts("[+] Object created");
}

void destroy() {
    if (!obj) {
        puts("[-] No object");
        return;
    }

    free(obj);               // FREE
    puts("[+] Object freed");
    // obj NOT cleared → UAF
}

void use() {
    if (!obj) {
        puts("[-] No object");
        return;
    }

    puts("[*] Triggering action...");
    obj->action();           // UAF / FUNC PTR HIJACK
}

void menu() {
    puts("\n1. Create object");
    puts("2. Destroy object");
    puts("3. Use object");
    puts("4. Exit");
}

int main() {
    int choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        menu();
        scanf("%d", &choice);
        getchar();

        switch (choice) {
            case 1:
                create();
                break;
            case 2:
                destroy();   // DOUBLE FREE POSSIBLE
                break;
            case 3:
                use();
                break;
            case 4:
                exit(0);
            default:
                puts("Invalid choice");
        }
    }
}
