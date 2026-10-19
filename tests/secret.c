#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include <sys/stat.h>

static int test_fstat(int fd, struct stat *status);

#define SECRET_PATH "secret"
#define main knockknock_main
#define fstat test_fstat
#include "../src/main.c"
#undef fstat
#undef main

#include <assert.h>

static uid_t fake_owner = 0;
static bool fstat_error = false;

static int test_fstat(int fd, struct stat *status)
{
    if (fstat_error) {
        errno = EIO;
        return -1;
    }
    int result = fstat(fd, status);
    // Parser fixtures must work without running the tests as root.
    if (result == 0)
        status->st_uid = fake_owner;
    return result;
}

static void check_mode(const char *name, const void *contents, size_t size,
                       int expected, mode_t mode)
{
    FILE *file = fopen(SECRET_PATH, "wb");
    assert(file != NULL);
    assert(fchmod(fileno(file), 0600) == 0);
    assert(fwrite(contents, 1, size, file) == size);
    assert(fchmod(fileno(file), mode) == 0);
    assert(fclose(file) == 0);

    char buffer[513];
    memset(buffer, 0x7f, sizeof(buffer));
    int length = load_secret(buffer, sizeof(buffer));
    assert(chmod(SECRET_PATH, 0600) == 0);
    if (length != expected)
        fprintf(stderr, "%s: expected %d, got %d\n", name, expected, length);
    assert(length == expected);
    if (expected < 0) {
        for (size_t i = 0; i < sizeof(buffer); i++)
            assert(buffer[i] == 0x7f);
        return;
    }

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

static void check(const char *name, const void *contents, size_t size, int expected)
{
    check_mode(name, contents, size, expected, 0600);
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

    check_mode("owner read-only", "key", 3, 3, 0400);
    check_mode("owner read/write", "key", 3, 3, 0600);
    const mode_t rejected_modes[] = {
        0644, 0640, 0620, 0604, 0602, 0610, 0601
    };
    for (size_t i = 0; i < sizeof(rejected_modes) / sizeof(rejected_modes[0]); i++) {
        char name[64];
        snprintf(name, sizeof(name), "reject mode %04o", (unsigned int)rejected_modes[i]);
        check_mode(name, "key", 3, -1, rejected_modes[i]);
    }

    fake_owner = 1;
    check("reject non-root owner with mode 0600", "key", 3, -1);
    fake_owner = 0;
    fstat_error = true;
    check("reject fstat failure", "key", 3, -1);
    fstat_error = false;

    assert(unlink(SECRET_PATH) == 0);
    char buffer[513];
    assert(load_secret(buffer, sizeof(buffer)) == -1);
    puts("secret tests passed");
    return 0;
}
