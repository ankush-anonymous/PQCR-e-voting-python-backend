#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        return 1;
    }

    const char* file_path = argv[1];
    FILE *file = fopen(file_path, "r");
    if (!file) {
        fprintf(stderr, "Error: Unable to open file: %s\n", file_path);
        return 1;
    }

    // Move to the end of the file to get its size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Allocate memory for the file contents plus a null terminator
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Unable to allocate memory\n");
        fclose(file);
        return 1;
    }

    // Read the file into the buffer
    size_t read_size = fread(buffer, 1, file_size, file);
    if (read_size != file_size) {
        fprintf(stderr, "Error: Could not read the entire file\n");
        free(buffer);
        fclose(file);
        return 1;
    }
    buffer[file_size] = '\0'; // Null-terminate the buffer

    // Print the file contents
    printf("%s\n", buffer);

    free(buffer);
    fclose(file);
    return 0;
}
