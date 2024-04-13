#include <string.h>
#include <stdlib.h>
#include <stdio.h>

unsigned char* readFile(const char* filePath) {
    unsigned char* content = NULL;
    long fileSize = 0;
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filePath, "rb"); // Open in binary mode

    if (err != 0 || !file) {
        printf("Error! Could not open file\n");
        exit(-1); // Exit if file opening fails
    }

    // Seek to the end to determine file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    rewind(file);

    // Allocate memory for file content. Add 1 for null terminator.
    content = (unsigned char*)malloc(fileSize + 1);
    if (!content) {
        printf("Memory allocation error\n");
        fclose(file);
        exit(-1);
    }

    // Read the file into memory and null-terminate the string
    size_t readSize = fread(content, 1, fileSize, file);
    content[readSize] = '\0'; // Null-terminate the array

    fclose(file); // Close the file
    return content;
}

long charToNumber(char* arg) {
    char *endptr;
    long number = strtol(arg, &endptr, 10); // Base 10 for decimal

    if (*endptr != '\0' || endptr == arg) {
        printf("Invalid integer format: '%s'\n", arg);
        return 1;
    }

    return number;
}