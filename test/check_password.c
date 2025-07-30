#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "password123") == 0) {
        printf("Correct password\n");
    } else {
        printf("Password is wrong\n");
    }

    return 0;
}
