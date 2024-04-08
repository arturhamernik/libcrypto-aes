#include <string.h>
#include <stdlib.h>
#include "AES.c"

int main(void) {
    // Open the file containing the key
    FILE *key_file = NULL;
    errno_t key_err = fopen_s(&key_file, "H:/Praca_dyplomowa/Impl/LibcryptoAES/keys/256.txt", "r");

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

    // Set up the key and iv...
    unsigned char *iv = (unsigned char *)"0123456789012345";

    // Open the file containing the plaintext
    FILE *file = NULL;
    errno_t err = fopen_s(&file, "H:/Praca_dyplomowa/Impl/LibcryptoAES/plaintext.txt", "r");

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

    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, &ciphertext);
    if (ciphertext_len < 0) {
        // Handle encryption error
        free(plaintext);
        return 1;
    }

    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, &decryptedtext);
    if (decryptedtext_len < 0) {
        // Handle decryption error
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    // Free the allocated buffers
    free(plaintext);
    free(ciphertext);
    free(decryptedtext);

    return 0;
}