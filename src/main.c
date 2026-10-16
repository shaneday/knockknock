#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Let systemd queue UDP traffic between short-lived, one-packet invocations.
// Implement socket activation directly to keep the binary small and standalone.
enum { SD_LISTEN_FDS_START = 3, MAX_PACKET_SIZE = 65535 };

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

// Render a sockaddr_storage as host:port for logging.
static void format_peer(const struct sockaddr_storage *peer, socklen_t length,
                        char *output, size_t output_size)
{
    const void *address = NULL;
    uint16_t port = 0;

    // Extract the numeric address and port from the concrete socket type.
    (void)length;
    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)peer;
        address = &ipv4->sin_addr;
        port = ntohs(ipv4->sin_port);
    } else if (peer->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)peer;
        address = &ipv6->sin6_addr;
        port = ntohs(ipv6->sin6_port);
    }

    // Fall back cleanly if the address cannot be rendered.
    if (address == NULL || output_size > (size_t)UINT_MAX ||
        inet_ntop(peer->ss_family, address, output, (socklen_t)output_size) == NULL) {
        (void)snprintf(output, output_size, "unknown");
        return;
    }

    // Append the peer port after the textual IP address.
    size_t used = strlen(output);
    if (used < output_size)
        (void)snprintf(output + used, output_size - used, ":%u", (unsigned int)port);
}

// Try to run `ufw allow from <ip> to any port 22` using fork+exec to avoid shell.
// Failures are logged but do not abort the program.
static void allow_ssh_for_peer(const struct sockaddr_storage *peer, socklen_t length)
{
    const void *address = NULL;
    char ip[INET6_ADDRSTRLEN];

    (void)length;
    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)peer;
        address = &ipv4->sin_addr;
    } else if (peer->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)peer;
        address = &ipv6->sin6_addr;
    }

    if (address == NULL || inet_ntop(peer->ss_family, address, ip, sizeof(ip)) == NULL) {
        (void)fprintf(stderr, "knockknock: unable to extract peer ip for ufw\n");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("knockknock: fork");
        return;
    }

    if (pid == 0) {
        // Child: absolute path and empty environment prevent PATH hijacking.
        char *const ufw_argv[] = { "ufw", "allow", "from", ip, "to", "any", "port", "22", "comment", "knockknock", NULL };
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
        if (byte >= 0x20 && byte <= 0x7e && byte != '\\')
            (void)putchar((int)byte);
        else if (byte == '\\')
            (void)fputs("\\\\", stdout);
        else
            (void)printf("\\x%02x", (unsigned int)byte);
    }
}

// Receive one activated datagram, log it, and exit.
int main(int argc, char **argv)
{
    unsigned char packet[MAX_PACKET_SIZE];
    struct sockaddr_storage peer;
    socklen_t peer_length = sizeof(peer);
    char peer_text[INET6_ADDRSTRLEN + 8];
    ssize_t received;

    // Reject unexpected command-line usage.
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: knockknock\n");
        return EXIT_FAILURE;
    }

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

    // Read exactly one packet for this short-lived invocation.
    do {
        received = recvfrom(SD_LISTEN_FDS_START, packet, sizeof(packet), 0,
                            (struct sockaddr *)&peer, &peer_length);
    } while (received < 0 && errno == EINTR);

    if (received < 0) {
        perror("knockknock: recvfrom");
        return EXIT_FAILURE;
    }

    // Log the sender and escaped payload.
    format_peer(&peer, peer_length, peer_text, sizeof(peer_text));
    allow_ssh_for_peer(&peer, peer_length);
    (void)printf("received %zd bytes from %s: ", received, peer_text);
    print_payload(packet, (size_t)received);
    (void)putchar('\n');
    return ferror(stdout) ? EXIT_FAILURE : EXIT_SUCCESS;
}
