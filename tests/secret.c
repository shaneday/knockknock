#define SECRET_PATH "secret"
#define main knockknock_main
#include "../src/main.c"
#undef main

#include <assert.h>

static void check(const char *name, const void *contents, size_t size, int expected)
{
    FILE *file = fopen(SECRET_PATH, "wb");
    assert(file != NULL);
    assert(fwrite(contents, 1, size, file) == size);
    assert(fclose(file) == 0);

    char buffer[513];
    memset(buffer, 0x7f, sizeof(buffer));
    int length = load_secret(buffer, sizeof(buffer));
    if (length != expected)
        fprintf(stderr, "%s: expected %d, got %d\n", name, expected, length);
    assert(length == expected);
    if (expected < 0)
        return;

    size_t n = (size_t)length;
    assert(memcmp(buffer, contents, n) == 0);
    assert(buffer[n] == '\0');
    assert(secrets_match(contents, n, buffer, n));
    assert(!secrets_match(contents, n - 1, buffer, n));

    unsigned char payload[515];
    memcpy(payload, contents, n);
    payload[0] ^= 1;
    assert(!secrets_match(payload, n, buffer, n));
    payload[0] ^= 1;
    payload[n] = '\n';
    assert(!secrets_match(payload, n + 1, buffer, n));
    payload[n] = '\r';
    payload[n + 1] = '\n';
    assert(!secrets_match(payload, n + 2, buffer, n));
}

int main(void)
{
    const char *endings[] = { "", "\n", "\r\n" };
    for (size_t i = 0; i < sizeof(endings) / sizeof(endings[0]); i++) {
        char data[515];
        size_t ending_size = strlen(endings[i]);
        memcpy(data, "key", 3);
        memcpy(data + 3, endings[i], ending_size);
        check("short EOF/LF/CRLF", data, 3 + ending_size, 3);

        memset(data, 'x', 512);
        memcpy(data + 512, endings[i], ending_size);
        check("512 bytes EOF/LF/CRLF", data, 512 + ending_size, 512);

        memset(data, 'x', 513);
        memcpy(data + 513, endings[i], ending_size);
        check("513 bytes EOF/LF/CRLF", data, 513 + ending_size, -1);
    }

    char boundary[514];
    memset(boundary, 'x', sizeof(boundary));
    boundary[511] = '\n';
    check("512th byte LF, then more", boundary, sizeof(boundary), 511);
    boundary[511] = 'x';
    boundary[512] = '\r';
    check("512 bytes plus literal CR at EOF", boundary, 513, -1);
    boundary[513] = '\n';
    check("512 bytes plus CRLF", boundary, sizeof(boundary), 512);
    boundary[511] = '\r';
    check("511 bytes plus literal CR at EOF", boundary, 512, 512);

    check("literal CR at EOF", "key\r", 4, 4);
    check("only CR at EOF", "\r", 1, 1);
    check("empty file", "", 0, -1);
    check("empty LF first line", "\nnotes", 6, -1);
    check("empty CRLF first line", "\r\nnotes", 7, -1);

    char notes[4096];
    memset(notes, 'n', sizeof(notes));
    memcpy(notes, "key\n", 4);
    check("large following notes", notes, sizeof(notes), 3);
    memcpy(notes, "key\r\n", 5);
    check("large following notes after CRLF", notes, sizeof(notes), 3);

    const unsigned char binary[] = { 0x80, 0, 'x', '\r', 0xff, '\r', '\n' };
    check("binary EOF", binary, 5, 5);
    check("binary CRLF", binary, sizeof(binary), 5);
    check("NUL-only secret", "\0\n", 2, 1);

    assert(unlink(SECRET_PATH) == 0);
    char buffer[513];
    assert(load_secret(buffer, sizeof(buffer)) == -1);
    puts("secret tests passed");
    return 0;
}
