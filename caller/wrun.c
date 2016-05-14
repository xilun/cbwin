/*
 * Copyright(c) 2016  Guillaume Knispel <xilun0@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _XOPEN_SOURCE 700
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MY_DYNAMIC_PATH_MAX (32768*3 + 32)
#define MNT_DRIVE_FS_PREFIX "/mnt/"

enum tool_e
{
    TOOL_WRUN,
    TOOL_WCMD,
    TOOL_WSTART
};

const char* tool_name;

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

static void terminate_nocore() __attribute__ ((noreturn));
static void terminate_nocore()
{
    // we use SIGKILL because it's reliable, does not dump core, and Windows
    // does not have it, so if we ever get crazy enough to propagate
    // termination by signal, the caller will still be able to distinguish
    // between local and Win32 failures.
    kill(getpid(), SIGKILL);
    abort(); // fallback, should not happen
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

static int get_tool(const char* argv0)
{
    const char* s = strrchr(argv0, '/');
    tool_name = (s == NULL) ? argv0 : s + 1;
    if (!strcmp(tool_name, "wcmd")) {
        return TOOL_WCMD;
    } else if (!strcmp(tool_name, "wrun")) {
        return TOOL_WRUN;
    } else if (!strcmp(tool_name, "wstart")) {
        return TOOL_WSTART;
    } else {
        fprintf(stderr, "%s: unrecognized program name (should be wcmd, wrun, or wstart)\n", argv0);
        terminate_nocore();
    }
}

static void shift(int *pargc, char ***pargv)
{
    if (pargc) {
        (*pargc)--;
        (*pargv)++;
    } else {
        abort();
    }
}

static void check_argc(int argc)
{
    if (argc < 1) {
        fprintf(stderr, "%s: no command\n", tool_name);
        terminate_nocore();
    }
}

static int recv_line_before_drop(int sockfd, char *buf, size_t bufsz)
{
    ssize_t where, res;
    for (where = 0; where < (ssize_t)bufsz; where += res)
    {
        do {
            res = recv(sockfd, buf + where, bufsz - (size_t)where, 0);
        } while (res < 0 && errno == EINTR);
        if (res <= 0)
            return -1;
        char* nl = memchr(buf + where, '\n', res);
        if (nl) {
            *nl = 0;
            return 0;
        }
    }
    return -1;
}

static bool linux_fd_is_null_or_bad(int fd)
{
    struct stat buf;
    int res = fstat(fd, &buf);
    if (res < 0) {
        if (errno == EBADF)
            return true;
        abort();
    }
    // under Linux, the major and minor of /dev/null is fixed:
    if (S_ISCHR(buf.st_mode) && major(buf.st_rdev) == 1
                             && minor(buf.st_rdev) == 3) {
        return true;
    }
    return false;
}

// precondition: fd must not be bad
/*static bool fd_is_reg(int fd)
{
    struct stat buf;
    int res = fstat(fd, &buf);
    if (res < 0) {
        fprintf(stderr, "%s: fstat(%d) failed: %s\n", tool_name, fd, strerror(errno));
        abort();
    }
    return S_ISREG(buf.st_mode);
}*/

static void fd_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        fprintf(stderr, "%s: fcntl(%d, F_GETFL) failed: %s\n", tool_name, fd, strerror(errno));
        abort();
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "%s: fcntl(%d, F_SETFL, flags | O_NONBLOCK) failed: %s\n", tool_name, fd, strerror(errno));
        abort();
    }
}

static void ask_redirect(struct string* command, const char* field, int fd, int port)
{
    if (!isatty(fd)) {
        string_append(command, field);
        if (linux_fd_is_null_or_bad(fd)) {
            string_append(command, "nul");
        } else {
            char buf[32];
            (void)snprintf(buf, 32, "redirect=%d", port);
            string_append(command, buf);
        }
    }
}

static bool needs_socket_redirect(int fd)
{
    return !isatty(fd) && !linux_fd_is_null_or_bad(fd);
}

struct listening_socket {
    int sockfd;
    int port;
};

#define NO_LISTENING_SOCKET {-1, 0}

struct listening_socket socket_listen_one_loopback()
{
    struct listening_socket lsock = NO_LISTENING_SOCKET;
    lsock.sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsock.sockfd < 0) {
        fprintf(stderr, "%s: socket() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = 0;
    if (bind(lsock.sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        fprintf(stderr, "%s: bind() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }
    socklen_t namelen = sizeof(serv_addr);
    if (getsockname(lsock.sockfd, (struct sockaddr *)&serv_addr, &namelen) != 0) {
        fprintf(stderr, "%s: getsockname() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }

    lsock.port = ntohs(serv_addr.sin_port);

    if (listen(lsock.sockfd, 1) != 0) {
        fprintf(stderr, "%s: listen() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }

    return lsock;
}

int accept_and_close_listener(struct listening_socket *lsock)
{
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    int sock;
    do {
        socklen_t len = sizeof(client_addr);
        sock = accept(lsock->sockfd, (struct sockaddr *)&client_addr, &len);
    } while (sock < 0 && errno == EINTR);
    if (sock < 0) {
        fprintf(stderr, "%s: accept() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }
    // hopefully, like under Linux, WSL closes reliably:
    close(lsock->sockfd);
    lsock->sockfd = -1;

    fd_set_nonblock(sock);
    return sock;
}

static int get_return_code(int sock_ctrl)
{
    int rc = 255;
    char buf[16];
    if (recv_line_before_drop(sock_ctrl, buf, 16) >= 0) {
        long longrc = atol(buf);
        rc = (longrc >= 0 && longrc <= 255) ? longrc : 255;
    }
    ssize_t res;
    do {
        char buf[128];
        res = recv(sock_ctrl, buf, 128, 0);
    } while (res > 0 || (res < 0 && errno == EINTR));
    if (res != 0) {
        fprintf(stderr, "%s: recv() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }
    return rc;
}

#define FORWARD_BUFFER_SIZE 16384
struct forward_buffer
{
    int fill;
    char buffer[FORWARD_BUFFER_SIZE];
};

struct forward_state
{
    int fd_in;
    int fd_out;
    bool ready_in;
    bool ready_out;
    bool dead_in;
    bool dead_out;
    struct forward_buffer buf;
};

static void forward_state_init(struct forward_state *fs, int fd_in, int fd_out)
{
    fs->fd_in = fd_in;
    fs->fd_out = fd_out;
    fs->ready_in = false;
    fs->ready_out = false;
    fs->dead_in = false;
    fs->dead_out = false;
    fs->buf.fill = 0;
    // no need to init fs->buf.buffer
}

static void forward_state_down(struct forward_state *fs)
{
    fs->fd_in = -1;
    fs->fd_out = -1;
    fs->ready_in = false;
    fs->ready_out = false;
    fs->dead_in = true;
    fs->dead_out = true;
    fs->buf.fill = 0;
}

// If std fd are redirected to network sockets (on the WSL side, not just the
// TCP loopback redirection forwarding machinery), we might not want to abort
// on some connection/network errors. The following list has been pulled out
// of thin air, but seems reasonable.
static const int potential_connection_errors[] = {
    EPIPE,
    ECONNRESET,
    ETIMEDOUT,
    EHOSTUNREACH,
    ENETDOWN,
    ENETRESET,
    ENETUNREACH,
    ENONET,
    EPROTO
};

#define ARRAY_SIZE(arr)     ((sizeof(arr)) / (sizeof(arr[0])))

static bool err_is_connection_broken(int error)
{
    for (size_t i = 0; i < ARRAY_SIZE(potential_connection_errors); i++) {
        if (error == potential_connection_errors[i])
            return true;
    }
    return false;
}

static void forward_close_in(struct forward_state *fs)
{
    fs->ready_in = false;
    fs->dead_in = true;
    close(fs->fd_in);
    fs->fd_in = -1;
}

static void forward_close_out(struct forward_state *fs)
{
    fs->ready_out = false;
    fs->dead_out = true;
    close(fs->fd_out);
    fs->fd_out = -1;
}

static bool forwardable_stream(struct forward_state *fs)
{
    return (fs->ready_in || fs->buf.fill > 0) && fs->ready_out;
}

static void forward_stream(struct forward_state *fs, const char *stream_name)
{
    if (fs->ready_in && fs->buf.fill < FORWARD_BUFFER_SIZE) {
        ssize_t res;
        do {
            res = read(fs->fd_in, fs->buf.buffer + fs->buf.fill,
                                  FORWARD_BUFFER_SIZE - fs->buf.fill);
        } while (res < 0 && errno == EINTR);
        if (res < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fs->ready_in = false;
            } else if (err_is_connection_broken(errno)) {
                forward_close_in(fs);
            } else {
                fprintf(stderr, "%s: %s: read() error: %s\n", tool_name, stream_name, strerror(errno));
                abort();
            }
        } else if (res == 0) {
            forward_close_in(fs);
        } else { // res > 0
            fs->buf.fill += res;
        }
    }

    if (fs->ready_out && fs->buf.fill > 0) {
        ssize_t res;
        do {
            res = write(fs->fd_out, fs->buf.buffer, fs->buf.fill);
        } while (res < 0 && errno == EINTR);
        if (res < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fs->ready_out = false;
            } else if (err_is_connection_broken(errno)) {
                forward_close_out(fs);
            } else {
                fprintf(stderr, "%s: %s: write() error: %s\n", tool_name, stream_name, strerror(errno));
                abort();
            }
        } else {
            fs->buf.fill -= res;
            memmove(fs->buf.buffer, fs->buf.buffer + res, fs->buf.fill);
        }
    }

    if (fs->dead_in && fs->buf.fill <= 0 && !fs->dead_out)
        forward_close_out(fs);
    if (fs->dead_out && !fs->dead_in)
        forward_close_in(fs);
}

int main(int argc, char *argv[])
{
    if (argc < 1) {
        fprintf(stderr, "wcmd/wrun/wstart called without argument\n");
        terminate_nocore();
    }
    int tool = get_tool(argv[0]);
    char* cwd = agetcwd();
    if (!((strncmp(cwd, MNT_DRIVE_FS_PREFIX, strlen(MNT_DRIVE_FS_PREFIX)) == 0)
          && cwd[strlen(MNT_DRIVE_FS_PREFIX)] >= 'a'
          && cwd[strlen(MNT_DRIVE_FS_PREFIX)] <= 'z'
          && (cwd[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '/'
              || cwd[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '\0'))) {
        fprintf(stderr, "%s: can't translate a WSL VolFs path to a Win32 one\n", tool_name);
        terminate_nocore();
    }
    char* cwd_win32 = convert_drive_fs_path_to_win32(cwd);
    free(cwd); cwd = NULL;

    struct string outbash_command = string_create("cd:");
    string_append(&outbash_command, cwd_win32); free(cwd_win32);

    shift(&argc, &argv);
    while (argc && !strncmp(argv[0], "--", 2)) {
        if (!strcmp(argv[0], "--")) {
            shift(&argc, &argv);
            break;
        }
        if (!strcmp(argv[0], "--env")) {
            shift(&argc, &argv);
            while (argc && strncmp(argv[0], "--", 2) != 0
                        && *argv[0] != '\0' && strchr(argv[0] + 1, '=')) {
                string_append(&outbash_command, "\nenv:");
                string_append(&outbash_command, argv[0]);
                shift(&argc, &argv);
            }
        }
    }
    check_argc(argc);

    char *outbash_port = getenv("OUTBASH_PORT");
    if (outbash_port == NULL) {
        fprintf(stderr, "%s: OUTBASH_PORT environment variable not set\n", tool_name);
        terminate_nocore();
    }
    int port = atoi(outbash_port);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "%s: OUTBASH_PORT environment variable does not contain a valid port number\n", tool_name);
        terminate_nocore();
    }
    int sock_ctrl = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ctrl < 0) {
        fprintf(stderr, "%s: socket() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }

#define STDIN_NEEDS_SOCKET_REDIRECT     1
#define STDOUT_NEEDS_SOCKET_REDIRECT    2
#define STDERR_NEEDS_SOCKET_REDIRECT    4
    int redirects =   (needs_socket_redirect(STDIN_FILENO)  ? STDIN_NEEDS_SOCKET_REDIRECT  : 0)
                    | (needs_socket_redirect(STDOUT_FILENO) ? STDOUT_NEEDS_SOCKET_REDIRECT : 0);
//                  | (needs_socket_redirect(STDERR_FILENO) ? STDERR_NEEDS_SOCKET_REDIRECT : 0);
    struct listening_socket lsock_in = NO_LISTENING_SOCKET;
    struct listening_socket lsock_out = NO_LISTENING_SOCKET;
    if (redirects & STDIN_NEEDS_SOCKET_REDIRECT) lsock_in = socket_listen_one_loopback();
    if (redirects & STDOUT_NEEDS_SOCKET_REDIRECT) lsock_out = socket_listen_one_loopback();
    ask_redirect(&outbash_command, "\nstdin:", STDIN_FILENO, lsock_in.port);
    ask_redirect(&outbash_command, "\nstdout:", STDOUT_FILENO, lsock_out.port);
    //ask_redirect(&outbash_command, "\nstderr:", STDERR_FILENO);

    switch (tool) {
    case TOOL_WRUN:
        string_append(&outbash_command, "\nrun:");
        break;
    case TOOL_WCMD:
        string_append(&outbash_command, "\nrun:cmd /C ");
        break;
    case TOOL_WSTART:
        string_append(&outbash_command, "\nrun:cmd /C start ");
        break;
    }

    bool sep = false;
    for (int i = 0; i < argc; i++) {
        if (sep) string_append(&outbash_command, " ");
        string_append(&outbash_command, argv[i]);
        sep = true;
    }
    string_append(&outbash_command, "\n\n");
    //printf("%s", outbash_command.str);
    //return EXIT_FAILURE;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(port);
    if (connect(sock_ctrl, (const struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "%s: connect() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }

    if (send_all(sock_ctrl, outbash_command.str, outbash_command.length, 0) < 0) {
        fprintf(stderr, "%s: send_all() failed: %s\n", tool_name, strerror(errno));
        terminate_nocore();
    }
    shutdown(sock_ctrl, SHUT_WR);
    string_destroy(&outbash_command);

    if (redirects) {
        static struct forward_state fs[2];
        signal(SIGPIPE, SIG_IGN);
        if ((redirects & STDIN_NEEDS_SOCKET_REDIRECT) /* && !fd_is_reg(STDIN_FILENO) */ ) {
            fd_set_nonblock(STDIN_FILENO);
            int sock_in = accept_and_close_listener(&lsock_in);
            forward_state_init(&fs[STDIN_FILENO], STDIN_FILENO, sock_in);
        } else
            forward_state_down(&fs[STDIN_FILENO]);
        if ((redirects & STDOUT_NEEDS_SOCKET_REDIRECT) /* && !fd_is_reg(STDOUT_FILENO) */ ) {
            fd_set_nonblock(STDOUT_FILENO);
            int sock_out = accept_and_close_listener(&lsock_out);
            forward_state_init(&fs[STDOUT_FILENO], sock_out, STDOUT_FILENO);
        } else
            forward_state_down(&fs[STDOUT_FILENO]);
        // if ((redirects & STDERR_NEEDS_SOCKET_REDIRECT) /* && !fd_is_reg(STDERR_FILENO) */ )
        //     fd_set_nonblock(STDERR_FILENO); ...

#define MY_MAX(x, y) (((x) > (y)) ? (x) : (y))
        int nfds = 0;
        for (int i = 0; i < 2; i++) {
            nfds = MY_MAX(nfds, fs[i].fd_in);
            nfds = MY_MAX(nfds, fs[i].fd_out);
        }
        nfds++;

        while (1) {
            fd_set rfds;
            fd_set wfds;
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            int nblive = 0, nbpull = 0;
            for (int i = 0; i < 2; i++) {
                nblive += (fs[i].fd_in >= 0) + (fs[i].fd_out >= 0);
                if (fs[i].fd_in  >= 0 && !fs[i].ready_in)  { nbpull++; FD_SET(fs[i].fd_in,  &rfds); }
                if (fs[i].fd_out >= 0 && !fs[i].ready_out) { nbpull++; FD_SET(fs[i].fd_out, &wfds); }
            }
            if (!nblive)
                break;
            if (nbpull) {
                int res;
                do {
                    struct timeval immediate = { 0, 0 };
                    bool fwdable = forwardable_stream(&fs[0]) || forwardable_stream(&fs[1]);
                    res = select(nfds, &rfds, &wfds, NULL, fwdable ? &immediate : NULL);
                } while(res < 0 && errno == EINTR);
                if (res < 0)
                    abort();
                for (int i = 0; i < 2; i++) {
                    if (fs[i].fd_in  >= 0 && FD_ISSET(fs[i].fd_in,  &rfds)) fs[i].ready_in  = true;
                    if (fs[i].fd_out >= 0 && FD_ISSET(fs[i].fd_out, &wfds)) fs[i].ready_out = true;
                }
            }
            forward_stream(&fs[0], "stdin");
            forward_stream(&fs[1], "stdout");
        }
    }

    return get_return_code(sock_ctrl);
}
