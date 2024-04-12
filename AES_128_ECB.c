#include <string.h>
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "Common.h"

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char **ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char **plaintext);

int main(int argc, char *argv[]) {
    /* clock_t clock(void) returns the number of clock ticks
   elapsed since the program was launched.To get the number
   of seconds used by the CPU, you will need to divide by
   CLOCKS_PER_SEC.where CLOCKS_PER_SEC is 1000000 on typical
   32 bit system.  */
    if (argc < 3) {
        fprintf(stderr, "Too few arguments provided to program\n");
        return -1;
    }

    clock_t start, end;
    //Set up key
    unsigned char* key = readFile(argv[1]);
    //Load plaintext
    unsigned char* plaintext = readFile(argv[2]);

    // Encryption and decryption as before...
    // Dynamically allocate ciphertext buffer based on plaintext size
    unsigned char *ciphertext = NULL;
    unsigned char *decryptedtext = NULL;
    int ciphertext_len;
    int decryptedtext_len;

    for(int i = 0; i < 100; i++) {
        /* Recording the starting clock tick.*/
        start = clock();
        ciphertext_len = encrypt(plaintext, strlen((char *) plaintext), key, &ciphertext);
        // Recording the end clock tick.
        end = clock();
        if (ciphertext_len < 0) {
            // Handle encryption error
            free(plaintext);
            return 1;
        }
        // Calculating total time taken by the program.
        double time_taken = (double)(end - start) / (double)(CLOCKS_PER_SEC);
        printf("%f\n", time_taken);
    }
/*

    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
*/

    printf("Decryption\n");
    for(int i = 0; i < 100; i++) {
        /* Recording the starting clock tick.*/
        start = clock();
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, &decryptedtext);
        end = clock();
        if (decryptedtext_len < 0) {
            // Handle decryption error
            free(plaintext);
            free(ciphertext);
            return 1;
        }
        // Calculating total time taken by the program.
        double time_taken = (double)(end - start) / (double)(CLOCKS_PER_SEC);
        printf("%f\n", time_taken);
    }

    /*decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);*/

    // Free the allocated buffers
    free(key);
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
            unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    int padding = EVP_CIPHER_block_size(EVP_aes_128_ecb()); // Padding can be up to one full block
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
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
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
            unsigned char **plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int padding = EVP_CIPHER_block_size(EVP_aes_128_ecb()); // Padding can be up to one full block
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
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
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
