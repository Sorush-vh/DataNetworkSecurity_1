/*
 * tlvparse: a small binary TLV message parser used as the second target.
 *
 * Wire format: repeated records of
 *   type (1 byte) | length (1 byte) | value (length bytes)
 * Types: 1 = NAME (string), 2 = ID (uint32, little-endian), 3 = END.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_CAP 32
#define MAX_INPUT 4096

struct message {
    char name[NAME_CAP];
    uint32_t id;
    int has_name;
    int has_id;
};

static int parse_message(const unsigned char *data, size_t size, struct message *msg)
{
    size_t offset = 0;
    memset(msg, 0, sizeof(*msg));
    while (offset < size) {
        unsigned char type;
        unsigned char length;
        if (offset + 2 > size) {
            return -1;
        }
        type = data[offset++];
        length = data[offset++];
        if (offset + length > size) {
            return -1;
        }
        if (type == 1) {
            /* Incomplete fix: a 128-byte limit does not protect a 32-byte buffer. */
            if (length > 128) {
                return -1;
            }
            memcpy(msg->name, data + offset, length);
            msg->name[length] = '\0';
            msg->has_name = 1;
        } else if (type == 2) {
            if (length != 4) {
                return -1;
            }
            memcpy(&msg->id, data + offset, 4);
            msg->has_id = 1;
        } else if (type == 3) {
            break;
        } else {
            return -1;
        }
        offset += length;
    }
    return 0;
}

static unsigned char data[MAX_INPUT];

int main(int argc, char **argv)
{
    struct message msg;
    FILE *input;
    size_t size;

    if (argc != 2) {
        fputs("usage: tlvparse FILE\n", stderr);
        return 2;
    }
    input = fopen(argv[1], "rb");
    if (input == NULL) {
        fputs("cannot open input\n", stderr);
        return 2;
    }
    size = fread(data, 1, sizeof(data), input);
    fclose(input);
    if (parse_message(data, size, &msg) != 0) {
        fputs("invalid input\n", stderr);
        return 2;
    }
    if (msg.has_name) {
        printf("name=%s\n", msg.name);
    }
    if (msg.has_id) {
        printf("id=%u\n", msg.id);
    }
    return 0;
}
