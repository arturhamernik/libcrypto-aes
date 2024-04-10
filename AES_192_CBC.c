#include <string.h>
#include "IV.h"
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char **ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char **plaintext);

int main(void) {
    clock_t start, end;

    // Set up the key and iv...
    //unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char iv[16]; // For AES, an IV size of 128 bits (16 bytes) is typical.
    generateSecureIV(iv, sizeof(iv));

    // Open the file containing the key
    FILE *key_file = NULL;
    errno_t key_err = fopen_s(&key_file, "H:/Praca_dyplomowa/Impl/LibcryptoAES/keys/192.txt", "r");

    if (key_file == NULL) {
        printf("Error! Could not open file\n");
        exit(-1); // must include stdlib.h
    }

    if (key_err != 0 || !key_file) handleErrors();

    // Seek to the end of the file to determine its size
    fseek(key_file, 0, SEEK_END);
    long keyFilesize = ftell(key_file);
    rewind(key_file); // Go back to the start of the file


    // Allocate memory for reading the key. Add 1 for null terminator.
    unsigned char *key = malloc(keyFilesize + 1);
    if (!key) handleErrors();

    // Read the file into memory and null-terminate the string
    size_t keyReadSize = fread(key, 1, keyFilesize, key_file);
    key[keyReadSize] = '\0'; // Null-terminate the key
    fclose(key_file); // Close the file

    // Open the file containing the plaintext
    FILE *file = NULL;
    errno_t err = fopen_s(&file, "H:/Praca_dyplomowa/Impl/LibcryptoAES/test/100mb.txt", "r");

    if (file == NULL) {
        printf("Error! Could not open file\n");
        exit(-1); // must include stdlib.h
    }

    if (err != 0 || !file) handleErrors();

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file); // Go back to the start of the file


    // Allocate memory for reading the plaintext. Add 1 for null terminator.
    unsigned char *plaintext = malloc(filesize + 1);
    if (!plaintext) handleErrors();

    // Read the file into memory and null-terminate the string
    size_t readSize = fread(plaintext, 1, filesize, file);
    plaintext[readSize] = '\0'; // Null-terminate the plaintext
    fclose(file); // Close the file

    // Encryption and decryption as before...
    // Dynamically allocate ciphertext buffer based on plaintext size
    unsigned char *ciphertext = NULL;
    unsigned char *decryptedtext = NULL;

    start = clock();
    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, &ciphertext);
    // Recording the end clock tick.
    end = clock();
    if (ciphertext_len < 0) {
        // Handle encryption error
        free(plaintext);
        return 1;
    }
/*
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);*/
    // Calculating total time taken by the program.
    double time_taken = (double)(end - start) / (double)(CLOCKS_PER_SEC);
    printf("%f", time_taken);

    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, &decryptedtext);
    if (decryptedtext_len < 0) {
        // Handle decryption error
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
/*    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);*/

    // Free the allocated buffers
    free(plaintext);
    free(ciphertext);
    free(decryptedtext);

    return 0;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    int padding = EVP_CIPHER_block_size(EVP_aes_192_cbc()); // Padding can be up to one full block
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
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char **plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int padding = EVP_CIPHER_block_size(EVP_aes_192_cbc()); // Padding can be up to one full block
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
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}