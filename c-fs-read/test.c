#include <stdio.h>
#include <stdlib.h>

#define FILE_SIZE 64 * 1024 * 1024  // 64 MiB

int main() {
    FILE *file;
    char *buffer;
    size_t result;

    file = fopen("/tmp/file", "rb");
    if (file == NULL) {
        fputs("Error opening file", stderr);
        return 1;
    }

    buffer = (char *)malloc(sizeof(char) * FILE_SIZE);
    if (buffer == NULL) {
        fputs("Memory error", stderr);
        fclose(file);
        return 2;
    }

    result = fread(buffer, 1, FILE_SIZE, file);
    if (result != FILE_SIZE) {
        fputs("Reading error", stderr);
        fclose(file);
        free(buffer);
        return 3;
    }

    fclose(file);
    free(buffer);

    return 0;
}
