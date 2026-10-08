#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "argon2.h"

int main(int argc, char **argv) {
    if (argc != 7) return 2;
    argon2_type type;
    if (strcmp(argv[1], "argon2i") == 0) type = Argon2_i;
    else if (strcmp(argv[1], "argon2d") == 0) type = Argon2_d;
    else if (strcmp(argv[1], "argon2id") == 0) type = Argon2_id;
    else return 2;
    size_t length = (size_t)atoi(argv[5]);
    if (length < 4 || length > 1024) return 2;
    unsigned char output[1024];
    int result = argon2_hash((uint32_t)atoi(argv[2]), (uint32_t)atoi(argv[3]),
        (uint32_t)atoi(argv[4]), argv[6], strlen(argv[6]), "somesalt", 8,
        output, length, NULL, 0, type, ARGON2_VERSION_13);
    if (result != ARGON2_OK) return 1;
    for (size_t i = 0; i < length; i++) printf("%02x", output[i]);
    puts("");
    memset(output, 0, sizeof(output));
    return 0;
}
