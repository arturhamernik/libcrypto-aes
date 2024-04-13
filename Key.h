#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

unsigned char* generate_key(int bits) {
    if (bits % 8 != 0 || (bits != 128 && bits != 192 && bits != 256)) {
        fprintf(stderr, "Key length must be 128, 192, or 256 bits.\n");
        return NULL;
    }

    int bytes = bits / 8;
    unsigned char* key = (unsigned char*)malloc(bytes + 1);
    if (key == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    if (RAND_bytes(key, bytes) != 1) {
        fprintf(stderr, "Failed to generate random bytes.\n");
        free(key);
        return NULL;
    }
    key[bytes] = '\0';

    return key;
}