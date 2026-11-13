#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int print_square(const char *text)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (end == text || errno || value < 0 || value > 100 ||
        (*end != '\0' && strcmp(end, "\n") != 0)) {
        return 2;
    }
    printf("%ld\n", value * value);
    return 0;
}

int main(int argc, char **argv)
{
    char line[64];
    int status = 2;
    if (argc == 2) {
        status = print_square(argv[1]);
    } else if (argc == 1 && fgets(line, sizeof line, stdin) != NULL) {
        status = print_square(line);
    } else if (argc == 3 && strcmp(argv[1], "--file") == 0) {
        FILE *input = fopen(argv[2], "rb");
        if (input != NULL) {
            if (fgets(line, sizeof line, input) != NULL) {
                status = print_square(line);
            }
            fclose(input);
        }
    }
    if (status != 0) {
        fputs("invalid number\n", stderr);
    }
    return status;
}
