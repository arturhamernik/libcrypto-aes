#include "IV.h"
#include "Common.h"
#include "Key.h"
#include <string.h>
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char **ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char **plaintext);

int main(int argc, char *argv[]) {
    // Check if number of arguments is ok
    if (argc < 5) {
        fprintf(stderr, "Too few arguments provided to program\n");
        return -1;
    }

    // Define variables
    clock_t start, end;
    unsigned char *plainText;
    unsigned char *ciphertext = NULL;
    unsigned char *decryptedText = NULL;
    unsigned char *key;
    int desiredKeyLength;
    int ciphertext_len;
    int decryptedText_len;
    double time_taken;

    // Load plainText
    plainText = readFile(argv[2]);
    // Set up key
    desiredKeyLength = charToNumber(argv[1]);

    if(desiredKeyLength == 128 || desiredKeyLength == 192 || desiredKeyLength == 256) {
        printf("Chosen algorithm is AES-ECB-%d\n", desiredKeyLength);
    } else {
        fprintf(stderr, "Chosen key length is invalid!");
        return 0;
    }

    key = generate_key(desiredKeyLength);

    if(key == NULL) {
        fprintf(stderr, "Key generation failed\n");
        return 0;
    }

    // Encryption performance test
    for(int i = 0; i < 100; i++) {
        /* Recording the starting clock tick.*/
        start = clock();
        // Encryption
        ciphertext_len = encrypt(plainText, strlen((char *) plainText), key, &ciphertext);
        // Recording the end clock tick.
        end = clock();
        // Check if encrypted correctly
        if (ciphertext_len < 0) {
            // Handle encryption error
            free(plainText);
            return 1;
        }
        // Calculating total time taken by the program.
        time_taken = (double)(end - start) * 1000 / (double)(CLOCKS_PER_SEC);
        printf("%f\n", time_taken);
    }

    // Save Ciphertext to file
    BIO_dump_fp(fopen(argv[3], "wb"), (const char *)ciphertext, ciphertext_len);

    // Decryption
    decryptedText_len = decrypt(ciphertext, ciphertext_len, key, &decryptedText);
    // Check if decrypted correctly
    if (decryptedText_len < 0) {
        // Handle decryption error
        free(plainText);
        free(ciphertext);
        return 1;
    }

    // Null-terminate the decrypted text
    decryptedText[decryptedText_len] = '\0';

    // Save decrypted text to file
    saveToFile(argv[4], (const char *)decryptedText);

    // Free the allocated buffers
    free(plainText);
    free(ciphertext);
    free(decryptedText);
    free(key);

    return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int keyLength = strlen((const char *) key) * 8;
    int len;
    int ciphertext_len;
    int padding;

    if(keyLength == 128) {
        padding = EVP_CIPHER_block_size(EVP_aes_128_ecb()); // Padding can be up to one full block
    } else if(keyLength == 192) {
        padding = EVP_CIPHER_block_size(EVP_aes_192_ecb()); // Padding can be up to one full block
    } else {
        padding = EVP_CIPHER_block_size(EVP_aes_256_ecb()); // Padding can be up to one full block
    }

    *ciphertext = malloc(plaintext_len + padding); // Allocate memory
    if (*ciphertext == NULL) return -1; // Error handling

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 192 bits
     */

    int encryptInit;

    if(keyLength == 128) {
        encryptInit = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    } else if(keyLength == 192) {
        encryptInit = EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    } else {
        encryptInit = EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    }

    if(encryptInit != 1) {
        handleErrors();
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
        handleErrors();
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1) {
        handleErrors();
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char **plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int keyLength = strlen((const char *) key) * 8;
    int len;
    int plaintext_len;
    int padding;

    if(keyLength == 128) {
        padding = EVP_CIPHER_block_size(EVP_aes_128_ecb()); // Padding can be up to one full block
    } else if(keyLength == 192) {
        padding = EVP_CIPHER_block_size(EVP_aes_192_ecb()); // Padding can be up to one full block
    } else {
        padding = EVP_CIPHER_block_size(EVP_aes_256_ecb()); // Padding can be up to one full block
    }

    *plaintext = malloc(ciphertext_len + padding); // Allocate memory

    if (*plaintext == NULL) return -1; // Error handling


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 192 bits
     */
    int decryptInit;

    if(keyLength == 128) {
        decryptInit = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    } else if(keyLength == 192) {
        decryptInit = EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    } else {
        decryptInit = EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    }

    if(decryptInit != 1) {
        handleErrors();
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        handleErrors();
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1) {
        handleErrors();
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}