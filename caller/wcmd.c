#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MY_DYNAMIC_PATH_MAX (32768*3 + 32)
#define MNT_DRIVE_FS_PREFIX "/mnt/"

static void output_err(const char* s)
{
    ssize_t len = (ssize_t)strlen(s);
    ssize_t where = 0;
    while (len - where > 0) {
        ssize_t res = write(STDERR_FILENO, s + where, len - where);
        if (res < 0) {
            if (errno != EINTR)
                return;
        } else {
            where += res;
        }
    }
}

static void* xmalloc(size_t sz)
{
    void* result = malloc(sz);
    if (result == NULL) {
        output_err("malloc failed\n");
        abort();
    }
    return result;
}

static void* xrealloc(void *ptr, size_t sz)
{
    void* result = realloc(ptr, sz);
    if (result == NULL) {
        output_err("realloc failed\n");
        abort();
    }
    return result;
}

static char* agetcwd()
{
    size_t sz = 4096;
    char* buf = xmalloc(sz);
    while (getcwd(buf, sz) == NULL) {
        if (errno != ERANGE) {
            perror("getcwd");
            abort();
        }
        if (sz >= MY_DYNAMIC_PATH_MAX) {
            fprintf(stderr, "agetcwd: current directory stupidly way too large\n");
            abort();
        }
        sz *= 2; if (sz > MY_DYNAMIC_PATH_MAX) sz = MY_DYNAMIC_PATH_MAX;
        buf = xrealloc(buf, sz);
    }
    return buf;
}

static ssize_t send_all(const int sockfd, const void *buffer, const size_t length, const int flags)
{
    if ((ssize_t)length < 0) {
        errno = EINVAL;
        return -1;
    }
    const char *cbuf = (const char *)buffer;
    ssize_t rv;
    size_t where;
    bool first = true; // allow a single call to send() if length == 0
    for (where = 0; first || where < length; where += rv) {
        first = false;
        do {
            const int send_flags = flags | MSG_NOSIGNAL;
            int len = (length - where <= INT_MAX) ? (int)(length - where) : INT_MAX;
            rv = send(sockfd, cbuf + where, len, send_flags);
        } while (rv < 0 && errno == EINTR);
        if (rv < 0)
            return -1;
    }
    assert(where == length);
    return (ssize_t)where;
}

static char* convert_drive_fs_path_to_win32(const char* path)
{
    char* result = xmalloc(4 + strlen(path));
    result[0] = path[strlen(MNT_DRIVE_FS_PREFIX)];
    result[1] = ':';
    result[2] = '\\';
    strcpy(result + 3, path + strlen(MNT_DRIVE_FS_PREFIX) + 2);
    int i;
    for (i = 3; result[i]; i++)
        if (result[i] == '/')
            result[i] = '\\';
    return result;
}

struct string {
    size_t length;
    size_t capacity;
    char* str;
};

static struct string string_create(const char* init)
{
    struct string result;
    result.length = strlen(init);
    result.capacity = result.length;
    result.str = xmalloc(result.capacity + 1);
    memcpy(result.str, init, result.length + 1);
    return result;
}

static void string_reserve(struct string* s, size_t new_capacity)
{
    if (new_capacity > s->capacity) {
        s->capacity = new_capacity;
        s->str = xrealloc(s->str, s->capacity + 1);
    }
}

static void string_quad_grow(struct string* s, size_t append_length)
{
    if (s->length + append_length > s->capacity) {
        size_t new_capa = s->length + append_length;
        if (new_capa < s->capacity * 2 + 1)
            new_capa = s->capacity * 2 + 1;
        string_reserve(s, new_capa);
    }
}

static void string_append(struct string* restrict s, const char* restrict rhs)
{
    size_t rhs_len = strlen(rhs);
    string_quad_grow(s, rhs_len);
    memcpy(&s->str[s->length], rhs, rhs_len + 1);
    s->length += rhs_len;
}

static void string_destroy(struct string* s)
{
    free(s->str);
    s->str = NULL;
    s->capacity = 0;
    s->length = 0;
}

/*
static void string_append_consume(struct string* restrict s, struct string* restrict r)
{
    string_quad_grow(s, r->length);
    memcpy(&s->str[s->length], r->str, r->length + 1);
    s->length += r->length;
    string_destroy(r);
}*/

int main(int argc, char *argv[])
{
    char* cwd = agetcwd();
    if (!((strncmp(cwd, MNT_DRIVE_FS_PREFIX, strlen(MNT_DRIVE_FS_PREFIX)) == 0)
          && cwd[strlen(MNT_DRIVE_FS_PREFIX)] >= 'a'
          && cwd[strlen(MNT_DRIVE_FS_PREFIX)] <= 'z'
          && (cwd[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '/'
              || cwd[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '\0'))) {
        fprintf(stderr, "%s: can't translate a WSL VolFs path to a Win32 one\n", argv[0]);
        return EXIT_FAILURE;
    }
    char* cwd_win32 = convert_drive_fs_path_to_win32(cwd);
    free(cwd); cwd = NULL;
    char *outbash_port = getenv("OUTBASH_PORT");
    if (outbash_port == NULL) {
        fprintf(stderr, "%s: OUTBASH_PORT environment variable not set\n", argv[0]);
        abort();
    }
    int port = atoi(outbash_port);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "%s: OUTBASH_PORT environment variable does not contain a valid port number\n", argv[0]);
        abort();
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        abort();
    }

    struct string outbash_command = string_create("cd:");
    string_append(&outbash_command, cwd_win32); free(cwd_win32);

    string_append(&outbash_command, "\nrun:cmd /C");
    for (int i = 1; i < argc; i++) {
        string_append(&outbash_command, " ");
        string_append(&outbash_command, argv[i]);
    }
    string_append(&outbash_command, "\n\n");

    // printf("%s###\n", outbash_command.str);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(port);
    if (connect(sock, (const struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        abort();
    }

    if (send_all(sock, outbash_command.str, outbash_command.length, 0) < 0) {
        perror("send_all");
        abort();
    }
    shutdown(sock, SHUT_WR);
    string_destroy(&outbash_command);

    ssize_t res;
    do {
        char buf[128];
        res = recv(sock, buf, 128, 0);
    } while (res > 0 || (res < 0 && errno == EINTR));
    if (res != 0) {
        perror("recv");
        abort();
    }

    return 0;
}
