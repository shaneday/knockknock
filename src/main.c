#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Let systemd queue UDP traffic between short-lived, one-packet invocations.
// Implement socket activation directly to keep the binary small and standalone.
enum { SD_LISTEN_FDS_START = 3, MAX_KNOCK_SIZE = 512, LOG_PAYLOAD_MAX = 64 };

// Path to the file holding the expected knock secret; override at compile time for tests.
#ifndef SECRET_PATH
#define SECRET_PATH "/etc/knockknock.secret"
#endif

// Parse a long >0, handling NULL, empty, and non-numeric strings as errors.
static int parse_positive_long(const char *text, long *value)
{
    char *end = NULL;
    long parsed;

    if (text == NULL || *text == '\0')
        return -1;

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed < 1)
        return -1;

    *value = parsed;
    return 0;
}

// Returns 1 if systemd passed exactly one socket, -1 otherwise.
static int activated_socket_count(void)
{
    const char *pid_text = getenv("LISTEN_PID");
    const char *fds_text = getenv("LISTEN_FDS");
    long listen_pid;
    long listen_fds;

    // LISTEN_PID prevents stale activation variables from making us consume an
    // unrelated inherited descriptor.
    if (parse_positive_long(pid_text, &listen_pid) < 0 ||
        parse_positive_long(fds_text, &listen_fds) < 0 ||
        listen_pid != (long)getpid() || listen_fds != 1) {
        fprintf(stderr, "knockknock: expected exactly one systemd socket\n");
        return -1;
    }

    return 1;
}

// Read the knock secret from SECRET_PATH into buf, stripping any trailing newline.
// Returns the secret length on success, -1 on failure.
static int load_secret(char *buf, size_t buf_size)
{
    FILE *f = fopen(SECRET_PATH, "r");
    if (f == NULL) {
        perror("knockknock: " SECRET_PATH);
        return -1;
    }
    size_t n = fread(buf, 1, buf_size - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err) {
        fprintf(stderr, "knockknock: error reading " SECRET_PATH "\n");
        return -1;
    }
    if (n > 0 && buf[n - 1] == '\n')
        n--;
    if (n == 0) {
        fprintf(stderr, "knockknock: " SECRET_PATH " is empty\n");
        return -1;
    }
    buf[n] = '\0';
    return (int)n;
}

// Return true if payload exactly matches the secret.
static bool secrets_match(const unsigned char *payload, size_t payload_len,
                           const char *secret, size_t secret_len)
{
    return payload_len == secret_len &&
           memcmp(payload, secret, payload_len) == 0;
}

// Returns true if the given fd is a datagram socket, false otherwise.
static bool is_datagram_socket(int fd)
{
    struct stat status;
    int type = 0;
    socklen_t length = sizeof(type);

    // Fail unless the inherited fd is exactly the kind of socket we expect.
    return fstat(fd, &status) == 0 && S_ISSOCK(status.st_mode) &&
           getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
           type == SOCK_DGRAM;
}

// Extract the numeric IP from a peer address into ip[INET6_ADDRSTRLEN].
// Returns the port number, or -1 on failure.
static int peer_to_ip(const struct sockaddr_storage *peer, char ip[INET6_ADDRSTRLEN])
{
    const void *address = NULL;
    int port = 0;

    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)peer;
        address = &ipv4->sin_addr;
        port = (int)ntohs(ipv4->sin_port);
    } else if (peer->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)peer;
        address = &ipv6->sin6_addr;
        port = (int)ntohs(ipv6->sin6_port);
    }

    if (address == NULL || inet_ntop(peer->ss_family, address, ip, INET6_ADDRSTRLEN) == NULL)
        return -1;

    return port;
}

// Try to run `ufw allow from <ip> to any port 22` using fork+exec to avoid shell.
// Failures are logged but do not abort the program.
static void allow_ssh_for_peer(const char *ip)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("knockknock: fork");
        return;
    }

    if (pid == 0) {
        // Child: absolute path and empty environment prevent PATH hijacking.
        char *const ufw_argv[] = { "ufw", "allow", "from", (char *)ip, "to", "any", "port", "22", "comment", "knockknock", NULL };
        char *const ufw_envp[] = { NULL };
        execve("/usr/sbin/ufw", ufw_argv, ufw_envp);
        perror("knockknock: execve ufw");
        _exit(127);
    }

    // Parent: wait for child and log the result.
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("knockknock: waitpid");
        return;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0)
            (void)fprintf(stderr, "knockknock: ufw allowed ssh from %s\n", ip);
        else
            (void)fprintf(stderr, "knockknock: ufw exited with code %d for %s\n", code, ip);
    } else if (WIFSIGNALED(status)) {
        (void)fprintf(stderr, "knockknock: ufw killed by signal %d\n", WTERMSIG(status));
    } else {
        (void)fprintf(stderr, "knockknock: ufw unknown child status for %s\n", ip);
    }
}

// Print the payload with escaping so binary bytes stay log-safe.
static void print_payload(const unsigned char *data, size_t length)
{
    // Escape payload bytes so logs stay readable and structurally safe.
    for (size_t index = 0; index < length; ++index) {
        unsigned char byte = data[index];
        if (byte == '\\')
            (void)fputs("\\\\", stdout);
        else if (byte >= 0x20 && byte <= 0x7e)
            (void)putchar((int)byte);
        else
            (void)printf("\\x%02x", (unsigned int)byte);
    }
}

// Receive one activated datagram, log it, and exit.
int main(int argc, char **argv)
{
    unsigned char packet[MAX_KNOCK_SIZE];
    char secret[MAX_KNOCK_SIZE + 1];
    struct sockaddr_storage peer;
    socklen_t peer_length = sizeof(peer);
    char peer_text[INET6_ADDRSTRLEN + 12]; /* ip + colon + 5-digit port + NUL */
    int secret_len;
    ssize_t received;

    // Reject unexpected command-line usage.
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: knockknock\n");
        return EXIT_FAILURE;
    }

    // Fail fast if the secret is missing or empty before touching the socket.
    secret_len = load_secret(secret, sizeof(secret));
    if (secret_len < 0)
        return EXIT_FAILURE;

    // Validate that systemd passed exactly one socket.
    if (activated_socket_count() < 0)
        return EXIT_FAILURE;

    // With Accept=no datagram activation the packet is already queued; a
    // blocking recvfrom on fd 3 is all that is needed — no poll required.
    if (!is_datagram_socket(SD_LISTEN_FDS_START)) {
        fprintf(stderr, "knockknock: activated fd %d is not a datagram socket\n",
                SD_LISTEN_FDS_START);
        return EXIT_FAILURE;
    }

    // Prevent the socket from leaking into the ufw child process.
    if (fcntl(SD_LISTEN_FDS_START, F_SETFD, FD_CLOEXEC) < 0) {
        perror("knockknock: fcntl FD_CLOEXEC");
        return EXIT_FAILURE;
    }

    // Read exactly one packet for this short-lived invocation.
    // MSG_TRUNC returns the true datagram length even when it exceeds the buffer,
    // so an oversized knock cannot pass a prefix-based payload check.
    do {
        received = recvfrom(SD_LISTEN_FDS_START, packet, sizeof(packet), MSG_TRUNC,
                            (struct sockaddr *)&peer, &peer_length);
    } while (received < 0 && errno == EINTR);

    if (received < 0) {
        perror("knockknock: recvfrom");
        return EXIT_FAILURE;
    }

    if (received > (ssize_t)sizeof(packet)) {
        fprintf(stderr, "knockknock: rejected oversized datagram (%zd bytes)\n", received);
        return EXIT_FAILURE;
    }

    // Log every knock attempt before validating so the audit trail is complete.
    char ip[INET6_ADDRSTRLEN];
    int port = peer_to_ip(&peer, ip);
    if (port < 0)
        (void)snprintf(peer_text, sizeof(peer_text), "unknown");
    else
        (void)snprintf(peer_text, sizeof(peer_text), "%s:%d", ip, port);
    size_t log_len = (size_t)received < LOG_PAYLOAD_MAX ? (size_t)received : LOG_PAYLOAD_MAX;
    (void)printf("received %zd bytes from %s: ", received, peer_text);
    print_payload(packet, log_len);
    if (log_len < (size_t)received)
        (void)fputs("[...]", stdout);
    (void)putchar('\n');
    (void)fflush(stdout);

    if (!secrets_match(packet, (size_t)received, secret, (size_t)secret_len)) {
        fprintf(stderr, "knockknock: rejected knock from %s\n", peer_text);
        return EXIT_SUCCESS;
    }

    if (port >= 0)
        allow_ssh_for_peer(ip);
    return ferror(stdout) ? EXIT_FAILURE : EXIT_SUCCESS;
}
