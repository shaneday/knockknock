#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

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
#include <time.h>
#include <unistd.h>

// Let systemd queue UDP traffic between short-lived invocations.
// Implement socket activation directly to keep the binary small and standalone.
enum { SD_LISTEN_FDS_START = 3, MAX_KNOCK_SIZE = 512 };

// Path to the file holding the expected knock secret; override at compile time for tests.
#ifndef SECRET_PATH
#define SECRET_PATH "/etc/knockknock.secret"
#endif

#ifndef SSH_PORT
#define SSH_PORT 22
#endif
#if SSH_PORT < 1 || SSH_PORT > 65535
#error "SSH_PORT must be between 1 and 65535"
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

// Returns 0 if systemd passed exactly one socket, -1 otherwise.
static int validate_socket_activation(void)
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

    return 0;
}

// Read the first line, excluding LF/CRLF, without truncating an oversized secret.
// Returns the secret length on success, -1 on failure.
static int load_secret(char *buf, size_t buf_size)
{
    FILE *f = fopen(SECRET_PATH, "r");
    if (f == NULL) {
        perror("knockknock: " SECRET_PATH);
        return -1;
    }
    struct stat status;
    if (fstat(fileno(f), &status) < 0) {
        perror("knockknock: fstat " SECRET_PATH);
        fclose(f);
        return -1;
    }
    if (status.st_uid != 0 || (status.st_mode & 077) != 0) {
        fprintf(stderr, "knockknock: " SECRET_PATH " must be owned by root with no group/other permissions\n");
        fclose(f);
        return -1;
    }
    char line[MAX_KNOCK_SIZE + 2];
    size_t n = 0;
    int byte = EOF;
    while (n < sizeof(line) && (byte = fgetc(f)) != EOF && byte != '\n')
        line[n++] = (char)byte;
    int err = ferror(f);
    fclose(f);
    if (err) {
        fprintf(stderr, "knockknock: error reading " SECRET_PATH "\n");
        return -1;
    }
    if (byte == '\n' && n > 0 && line[n - 1] == '\r')
        n--;
    if (n == 0 || n > MAX_KNOCK_SIZE || n >= buf_size) {
        fprintf(stderr, "knockknock: " SECRET_PATH " first line must contain 1-512 bytes\n");
        return -1;
    }
    memcpy(buf, line, n);
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

// Run a firewall command without a shell; missing optional backends stay quiet.
static int run_firewall(const char *path, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0)
            _exit(127);
        if (null_fd > STDERR_FILENO)
            (void)close(null_fd);
        char *const envp[] = { NULL };
        execve(path, argv, envp);
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Either UFW or the admin's FireHOL ipset may grant SSH access.
static void allow_ssh_for_peer(char *ip)
{
    char port[6];
    (void)snprintf(port, sizeof(port), "%u", (unsigned)SSH_PORT);
    char comment[sizeof("knockknock YYYYMMDD")];
    time_t now = time(NULL);
    struct tm utc;
    int ufw_status = -1;
    if (now != (time_t)-1 && gmtime_r(&now, &utc) != NULL &&
        strftime(comment, sizeof(comment), "knockknock %Y%m%d", &utc) != 0) {
        char *const argv[] = { "ufw", "allow", "from", ip, "to", "any", "port", port,
                               "proto", "tcp", "comment", comment, NULL };
        ufw_status = run_firewall("/usr/sbin/ufw", argv);
    }

    char *const ipset_argv[] = { "ipset", "-exist", "add", "knockknock_ssh", ip, NULL };
    int ipset_status = run_firewall("/usr/sbin/ipset", ipset_argv);
    if (ufw_status == 0)
        (void)fprintf(stderr, "knockknock: ufw allowed ssh from %s\n", ip);
    if (ipset_status == 0)
        (void)fprintf(stderr, "knockknock: ipset added ssh source %s\n", ip);
    if (ufw_status != 0 && ipset_status != 0)
        (void)fprintf(stderr, "knockknock: neither ufw nor ipset allowed ssh from %s (ufw %d, ipset %d)\n",
                      ip, ufw_status, ipset_status);
}


static void log_rejections(unsigned long rejected, unsigned long oversized)
{
    if (rejected != 0) {
        (void)printf("knockknock: rejected %lu knocks (%lu oversized)\n", rejected, oversized);
        (void)fflush(stdout);
    }
}

// Drain queued datagrams, authenticating each before any firewall action.
int main(int argc, char **argv)
{
    unsigned char packet[MAX_KNOCK_SIZE];
    char secret[MAX_KNOCK_SIZE + 1];
    struct sockaddr_storage peer;

    char peer_text[INET6_ADDRSTRLEN + 12]; /* ip + colon + 5-digit port + NUL */
    int secret_len = 0;
    ssize_t received;
    unsigned long rejected = 0, oversized = 0;
    time_t last_report = time(NULL);

    // Reject unexpected command-line usage.
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: knockknock\n");
        return EXIT_FAILURE;
    }


    // Validate that systemd passed exactly one socket.
    if (validate_socket_activation() < 0)
        return EXIT_FAILURE;


    if (!is_datagram_socket(SD_LISTEN_FDS_START)) {
        fprintf(stderr, "knockknock: activated fd %d is not a datagram socket\n",
                SD_LISTEN_FDS_START);
        return EXIT_FAILURE;
    }

    // Prevent the socket from leaking into firewall child processes.
    if (fcntl(SD_LISTEN_FDS_START, F_SETFD, FD_CLOEXEC) < 0) {
        perror("knockknock: fcntl FD_CLOEXEC");
        return EXIT_FAILURE;
    }

    for (;;) {
        socklen_t peer_length = sizeof(peer);

        // Drain without blocking; systemd reactivates us if more traffic arrives.
        // MSG_TRUNC prevents oversized packets from authenticating by prefix.
        do {
            received = recvfrom(SD_LISTEN_FDS_START, packet, sizeof(packet),
                                MSG_TRUNC | MSG_DONTWAIT,
                                (struct sockaddr *)&peer, &peer_length);
        } while (received < 0 && errno == EINTR);

        if (received < 0) {
            int receive_error = errno;
            log_rejections(rejected, oversized);
            if (receive_error == EAGAIN || receive_error == EWOULDBLOCK)
                return ferror(stdout) ? EXIT_FAILURE : EXIT_SUCCESS;
            errno = receive_error;
            perror("knockknock: recvfrom");
            return EXIT_FAILURE;
        }

        // Consume traffic even if configuration is broken, avoiding reactivation loops.
        if (secret_len == 0) {
            secret_len = load_secret(secret, sizeof(secret));
            if (secret_len < 0)
                fprintf(stderr, "knockknock: discarding queued datagrams: secret unavailable\n");
        }
        if (secret_len < 0)
            continue;

        bool too_large = received > (ssize_t)sizeof(packet);
        if (too_large || !secrets_match(packet, (size_t)received, secret, (size_t)secret_len)) {
            rejected++;
            if (too_large)
                oversized++;
            time_t now = time(NULL);
            if (now != last_report) {
                log_rejections(rejected, oversized);
                rejected = oversized = 0;
                last_report = now;
            }
            continue;
        }

        // Log metadata only: payloads can contain valid or mistyped secrets.
        char ip[INET6_ADDRSTRLEN];
        int port = peer_to_ip(&peer, ip);
        if (port < 0)
            (void)snprintf(peer_text, sizeof(peer_text), "unknown");
        else
            (void)snprintf(peer_text, sizeof(peer_text), "%s:%d", ip, port);
        (void)printf("knockknock: accepted knock from %s (%zd bytes)\n", peer_text, received);
        (void)fflush(stdout);

        if (port >= 0)
            allow_ssh_for_peer(ip);
        else
            fprintf(stderr, "knockknock: valid knock from unknown address, firewall not updated\n");
    }
}
