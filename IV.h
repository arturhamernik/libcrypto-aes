#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

void generateSecureIV(unsigned char *iv, size_t length) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "Error acquiring cryptographic context\n");
        exit(1);
    }

    if (!CryptGenRandom(hProv, (DWORD)length, iv)) {
        fprintf(stderr, "Error generating random data\n");
        exit(1);
    }

    CryptReleaseContext(hProv, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Error opening /dev/urandom");
        exit(1);
    }

    ssize_t result = read(fd, iv, length);
    if (result < 0) {
        perror("Error reading from /dev/urandom");
        exit(1);
    }

    close(fd);
#endif
}