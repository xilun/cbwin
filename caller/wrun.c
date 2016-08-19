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
#include <pthread.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pwd.h>

#define MY_DYNAMIC_PATH_MAX (32768*3 + 32)
#define MNT_DRIVE_FS_PREFIX "/mnt/"

enum tool_e
{
    TOOL_WRUN,
    TOOL_WCMD,
    TOOL_WSTART
};

static const char* tool_name;

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

#define STRERROR_BUFFER_SIZE    2048
static __thread char tls_strerror_buffer[STRERROR_BUFFER_SIZE];

static char *my_strerror(int errnum) // thread-safe
{
    int save_errno = errno;
    int res = strerror_r(errnum, tls_strerror_buffer, sizeof(tls_strerror_buffer));
    if (res != 0)
        snprintf(tls_strerror_buffer, sizeof(tls_strerror_buffer), "error %d", errnum);
    errno = save_errno;
    tls_strerror_buffer[sizeof(tls_strerror_buffer) - 1] = 0;
    return tls_strerror_buffer;
}

static char* agetcwd()
{
    size_t sz = 4096;
    char* buf = xmalloc(sz);
    while (getcwd(buf, sz) == NULL) {
        if (errno != ERANGE) {
            dprintf(STDERR_FILENO, "%s: getcwd() failed: %s\n", tool_name, my_strerror(errno));
            abort();
        }
        if (sz >= MY_DYNAMIC_PATH_MAX) {
            dprintf(STDERR_FILENO, "%s: agetcwd: current directory path stupidly way too long\n", tool_name);
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

static void string_exp_grow(struct string* s, size_t append_length)
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
    string_exp_grow(s, rhs_len);
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
        dprintf(STDERR_FILENO, "%s: unrecognized program name (should be wcmd, wrun, or wstart)\n", argv0);
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
        dprintf(STDERR_FILENO, "%s: no command\n", tool_name);
        dprintf(STDERR_FILENO, "type %s --help for more information.\n", tool_name);
        terminate_nocore();
    }
}

struct std_fd_info_struct {

    /* identity: */
    int fd;
    bool is_bad;
    bool is_dev_null;
    bool is_a_real_tty;
    bool is_socket;
    struct stat stbuf;

    /* policy: */
    bool redirect;
};

static struct std_fd_info_struct std_fd_info[3];

static void fill_std_fd_info_identity(int fd)
{
    assert(fd >= 0);
    assert(fd < 3);
    struct std_fd_info_struct *info = &std_fd_info[fd];

    info->fd = fd;

    int r = fstat(info->fd, &info->stbuf);
    if (r != 0) {
        if (errno == EBADF) {
            info->is_bad = true;
            return;
        } else {
            dprintf(STDERR_FILENO, "%s: fstat(%d, &st) failed: %s\n", tool_name, fd, my_strerror(errno));
            abort();
        }
    }

    // under Linux, the major and minor of /dev/null is fixed:
    if (S_ISCHR(info->stbuf.st_mode) && major(info->stbuf.st_rdev) == 1
                                     && minor(info->stbuf.st_rdev) == 3) {
        info->is_dev_null = true;
        return;
    }

    if (isatty(info->fd)) {
        if (strncmp(ttyname(fd), "/dev/tty", strlen("/dev/tty")) == 0)
            info->is_a_real_tty = true;
        return;
    }

    if (S_ISSOCK(info->stbuf.st_mode)) {
        info->is_socket = true;
        return;
    }
}

// precondition: fd_1 and fd_2 must not be bad
static bool are_stdfd_to_same_thing(int fd_1, int fd_2)
{
    assert(fd_1 >= 0);
    assert(fd_1 < 3);
    assert(fd_2 >= 0);
    assert(fd_2 < 3);

    if (std_fd_info[fd_1].is_bad || std_fd_info[fd_2].is_bad)
        return false;

    if ((std_fd_info[fd_1].stbuf.st_mode & S_IFMT) != (std_fd_info[fd_2].stbuf.st_mode & S_IFMT))
        return false;

    if (   S_ISCHR(std_fd_info[fd_1].stbuf.st_mode)
        || S_ISBLK(std_fd_info[fd_1].stbuf.st_mode))
        return std_fd_info[fd_1].stbuf.st_rdev == std_fd_info[fd_2].stbuf.st_rdev;
    else
        return (std_fd_info[fd_1].stbuf.st_dev == std_fd_info[fd_2].stbuf.st_dev)
            && (std_fd_info[fd_1].stbuf.st_ino == std_fd_info[fd_2].stbuf.st_ino);
}

static void decide_will_redirect(int stdfd, bool force)
{
    assert(stdfd >= 0);
    assert(stdfd < 3);
    std_fd_info[stdfd].redirect = force || !std_fd_info[stdfd].is_a_real_tty;
}

static bool needs_socket_redirect(int stdfd)
{
    assert(stdfd >= 0);
    assert(stdfd < 3);

    return  std_fd_info[stdfd].redirect
        && !std_fd_info[stdfd].is_bad
        && !std_fd_info[stdfd].is_dev_null;
}

static void ask_redirect(struct string* command, const char* field, int stdfd, int port)
{
    if (std_fd_info[stdfd].redirect) {
        string_append(command, field);
        if (std_fd_info[stdfd].is_bad || std_fd_info[stdfd].is_dev_null) {
            string_append(command, "nul");
        } else {
            char buf[32];
            (void)snprintf(buf, 32, "redirect=%d", port);
            string_append(command, buf);
        }
    }
}

struct listening_socket {
    int sockfd;
    int port;
};

#define NO_LISTENING_SOCKET {-1, 0}

static struct listening_socket socket_listen_one_loopback()
{
    struct listening_socket lsock = NO_LISTENING_SOCKET;
    lsock.sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsock.sockfd < 0) {
        dprintf(STDERR_FILENO, "%s: socket() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = 0;
    if (bind(lsock.sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        dprintf(STDERR_FILENO, "%s: bind() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }
    socklen_t namelen = sizeof(serv_addr);
    if (getsockname(lsock.sockfd, (struct sockaddr *)&serv_addr, &namelen) != 0) {
        dprintf(STDERR_FILENO, "%s: getsockname() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }

    lsock.port = ntohs(serv_addr.sin_port);

    if (listen(lsock.sockfd, 1) != 0) {
        dprintf(STDERR_FILENO, "%s: listen() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }

    return lsock;
}

static int accept_listener(struct listening_socket *lsock)
{
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    int sock;
    do {
        socklen_t len = sizeof(client_addr);
        sock = accept(lsock->sockfd, (struct sockaddr *)&client_addr, &len);
    } while (sock < 0 && errno == EINTR);
    if (sock < 0) {
        dprintf(STDERR_FILENO, "%s: accept() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }
    return sock;
}

static void close_listener(struct listening_socket *lsock)
{
    if (lsock->sockfd >= 0) {
        // hopefully, like under Linux, WSL closes reliably:
        close(lsock->sockfd);
        lsock->sockfd = -1;
    }
}

#define CTRL_IN_BUFFER_SIZE 128
struct ctrl_in_buffer {
    char buffer[CTRL_IN_BUFFER_SIZE];
    char line[CTRL_IN_BUFFER_SIZE];
    int fill;
};

static char *ctrl_readln(int sock_ctrl, int *nonblock_marker)
{
    static struct ctrl_in_buffer ctrl_buf;

    *nonblock_marker = 0;

    while (1) {
        char *nl = memchr(ctrl_buf.buffer, '\n', ctrl_buf.fill);
        if (nl) {
            int idxnl = nl - ctrl_buf.buffer;
            memcpy(ctrl_buf.line, ctrl_buf.buffer, idxnl);
            ctrl_buf.line[idxnl] = 0;
            ctrl_buf.fill -= idxnl + 1;
            assert(ctrl_buf.fill >= 0);
            memmove(ctrl_buf.buffer, ctrl_buf.buffer + idxnl + 1, ctrl_buf.fill);
            return ctrl_buf.line;
        }
        if (ctrl_buf.fill == CTRL_IN_BUFFER_SIZE) {
            dprintf(STDERR_FILENO, "%s: ctrl_readln: protocol violation: received line too long\n", tool_name);
            abort();
        }
        int r;
        do {
            r = recv(sock_ctrl, ctrl_buf.buffer + ctrl_buf.fill, CTRL_IN_BUFFER_SIZE - ctrl_buf.fill, MSG_DONTWAIT);
            if (r > 0)
                ctrl_buf.fill += r;
            if (r == 0)
                return NULL;
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                *nonblock_marker = 1;
                return NULL;
            }

            // XXX maybe not in all cases:
            dprintf(STDERR_FILENO, "%s: ctrl_readln: recv() failed: %s\n", tool_name, my_strerror(errno));
            terminate_nocore();
        }
    }
}

static int get_return_code(char *line)
{
    int rc = 255;

    if (line) {
        long longrc = atol(line);
        rc = (longrc >= 0 && longrc <= 255) ? longrc : 255;
    }

    return rc;
}

#define FORWARD_BUFFER_SIZE     16384
struct forward_buffer
{
    char buffer[FORWARD_BUFFER_SIZE];
    int fill;
} __attribute__((aligned(64)));

struct forward_state
{
    int fd_in;
    int fd_out;
    bool issock_in;
    bool issock_out;
    bool ready_in;
    bool ready_out;
    bool dead_in;
    bool dead_out;
    char ask_terminate;
    char finished;
    const char *stream_name;
    struct forward_buffer buf;
};

#define FORWARD_STATE_IN_IS_SOCKET  1
#define FORWARD_STATE_OUT_IS_SOCKET 2

static void forward_state_init(struct forward_state *fs, int fd_in, int fd_out, int flags, const char *stream_name)
{
    fs->fd_in = fd_in;
    fs->fd_out = fd_out;
    fs->issock_in = (flags & FORWARD_STATE_IN_IS_SOCKET);
    fs->issock_out = (flags & FORWARD_STATE_OUT_IS_SOCKET);
    fs->ready_in = false;
    fs->ready_out = false;
    fs->dead_in = false;
    fs->dead_out = false;
    fs->stream_name = stream_name;
    fs->ask_terminate = 0;
    fs->finished = 0;
    fs->buf.fill = 0;
    // no need to init fs->buf.buffer
}

static void forward_state_down(struct forward_state *fs)
{
    fs->fd_in = -1;
    fs->fd_out = -1;
    fs->issock_in = false;
    fs->issock_out = false;
    fs->ready_in = false;
    fs->ready_out = false;
    fs->dead_in = true;
    fs->dead_out = true;
    fs->stream_name = NULL;
    fs->ask_terminate = 0;
    fs->finished = 0;
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

static void forward_close_out(struct forward_state *fs, bool error)
{
    if (!fs->dead_out) {
        fs->ready_out = false;
        fs->dead_out = true;
        if (fs->issock_out && !error) {
            if (shutdown(fs->fd_out, SHUT_WR)) {
                dprintf(STDERR_FILENO, "%s: %s: will close(%d) because of shutdown(%d, SHUT_WR) error: %s\n",
                                       tool_name, fs->stream_name, fs->fd_out, fs->fd_out, my_strerror(errno));
                close(fs->fd_out);
                fs->fd_out = -1;
            }
        } else {
            close(fs->fd_out);
            fs->fd_out = -1;
        }
    }
}

static void noop_handler(int signum)
{
    (void)signum;
}

static void forward_stream(struct forward_state *fs)
{
    if (fs->ready_in && !__sync_fetch_and_add(&fs->ask_terminate, 0)
                     && fs->buf.fill == 0) {
        ssize_t res;
retry_read:
        res = read(fs->fd_in, fs->buf.buffer + fs->buf.fill,
                   FORWARD_BUFFER_SIZE - fs->buf.fill);
        if (res < 0) {
            if (errno == EINTR) {
                if (!__sync_fetch_and_add(&fs->ask_terminate, 0))
                    goto retry_read;
            } else if (err_is_connection_broken(errno)) {
                forward_close_in(fs);
            } else {
                dprintf(STDERR_FILENO, "%s: %s: read() error: %s\n", tool_name, fs->stream_name, my_strerror(errno));
                abort();
            }
        } else if (res == 0) {
            forward_close_in(fs);
        } else { // res > 0
            fs->buf.fill += res;
        }
    }

    while (fs->ready_out && !__sync_fetch_and_add(&fs->ask_terminate, 0)
                         && fs->buf.fill > 0) {
        ssize_t res = write(fs->fd_out, fs->buf.buffer, fs->buf.fill);
        if (res < 0) {
            if (errno == EINTR) {
                /* nothing to do */
            } else if (err_is_connection_broken(errno)) {
                forward_close_out(fs, true);
            } else {
                dprintf(STDERR_FILENO, "%s: %s: write() error: %s\n", tool_name, fs->stream_name, my_strerror(errno));
                abort();
            }
        } else {
            fs->buf.fill -= res;
            memmove(fs->buf.buffer, fs->buf.buffer + res, fs->buf.fill);
        }
    }

    if (((fs->dead_in && fs->buf.fill <= 0) || __sync_fetch_and_add(&fs->ask_terminate, 0)) && !fs->dead_out)
        forward_close_out(fs, false);
    if (fs->dead_out && !fs->dead_in)
        forward_close_in(fs);
}

static void fs_init_accept_as_needed(struct forward_state *fs, struct listening_socket *lsock,
                                     bool own_redir, int std_fileno, const char *stream_name)
{
    if (own_redir) {
        int sock = accept_listener(lsock);
        if (std_fileno == STDIN_FILENO) {
            // shutdown(sock, SHUT_RD);
            int flags = FORWARD_STATE_OUT_IS_SOCKET;
            if (std_fd_info[std_fileno].is_socket)
                flags |= FORWARD_STATE_IN_IS_SOCKET;
            forward_state_init(fs, std_fileno, sock, flags, stream_name);
        } else { // STDOUT_FILENO or STDERR_FILENO
            // shutdown(sock, SHUT_WR);
            int flags = FORWARD_STATE_IN_IS_SOCKET;
            if (std_fd_info[std_fileno].is_socket)
                flags |= FORWARD_STATE_OUT_IS_SOCKET;
            forward_state_init(fs, sock, std_fileno, flags, stream_name);
        }
    } else {
        forward_state_down(fs);
    }
}

static void *forward_one_stream(void *arg)
{
    struct forward_state *fs = arg;

    fs->ready_in = true;
    fs->ready_out = true;

    while ((!fs->dead_in) || (!fs->dead_out)) {
        forward_stream(fs);
    }

    __sync_fetch_and_add(&fs->finished, 1);

    return NULL;
}

volatile sig_atomic_t tstop_req;
static void tstop_handler(int n)
{
    (void)n;
    tstop_req = 1;
}

// States:
//
// RUNNING <-> SUSPEND_PENDING   # propagate suspend/resume
//  |    \     /     |
//  |     v   v      |
//  |     DYING      |  # ctrl socket failed while trying to suspend/resume
//  |       |        |
//  |       v        |
//  +-> TERMINATED <-+  # remote process terminated
//
// When we receive a SIGTSTP we just ask outbash to suspend the Windows process.
// Outbash acknowledges after it has suspended it. We then suspend ourselves;
// there is no need for a "SUSPENDED" state in this program because that's just
// when it is actually suspended by the OS...
// When we resume execution, we just send a resume command and go back to work,
// knowing that the Windows process will eventually get resumed. We delayed our
// suspension to avoid e.g. the Windows process sending text on the console for
// a few milliseconds after the WSL process is suspended and its suspension
// acted upon (by the shell, for example). There is no equivalent situation
// during the resume sequence, that's why no ack is needed for it.
// In case of problem while sending the suspend or resume commands, we go to
// the DYING state because the control socket is not supposed to fail.
// However, that's just a send failure, and hopefully the exit code can still
// get to us in the recv path. A transition occurs to TERMINATED when, from any
// state, the exit code is received.
// In the DYING and TERMINATED states, we still have to forward the remaining
// redirected data and flush all the buffers before actually exiting.
// In theory the stdout or stderr socket should not block anymore at this point,
// except if somebody forwarded the redirection in a "background" process on the
// Win32 side (however, note that Winsock seems to be unreliable in this case).
// Anyway, for now we just forward as usual when DYING/TERMINATED, without
// trying to do anything special, until all the work seems to be finished.
//
enum state_e { RUNNING, SUSPEND_PENDING, DYING, TERMINATED };

static char *get_homedir_dup(void)
{
    char *homedir = getenv("HOME");
    if (homedir)
        return strdup(homedir);
    struct passwd *p = getpwuid(getuid());
    if (!p)
        return NULL;
    return strdup(p->pw_dir);
}

static bool get_outbash_infos(int *port, bool *force_redirects)
{
    const char *origin = "OUTBASH_PORT environment variable";
    char *outbash_port = getenv("OUTBASH_PORT");

    char buffer[16] = { 0 };

    *port = 0;
    *force_redirects = false;

    if (outbash_port == NULL) {
        char *homedir = get_homedir_dup();
        if (!homedir) {
            dprintf(STDERR_FILENO, "%s: OUTBASH_PORT environment variable not set, and could not get home directory\n", tool_name);
            return false;
        }
#define CONF_SESSION_PORT_FILE "/.config/cbwin/outbash_port"
        char *conf_file_path = xmalloc(strlen(homedir) + strlen(CONF_SESSION_PORT_FILE) + 1);
        strcpy(conf_file_path, homedir);
        strcat(conf_file_path, CONF_SESSION_PORT_FILE);
        FILE *f = fopen(conf_file_path, "r");
        if (!f || !fread(buffer, 1, 15, f)) {
            dprintf(STDERR_FILENO, "%s: OUTBASH_PORT environment variable not set, and could not read %s\n", tool_name, conf_file_path);
            return false;
        }
        fclose(f);
        free(conf_file_path);
        free(homedir);

        outbash_port = buffer;
        *force_redirects = true;
        origin = "~" CONF_SESSION_PORT_FILE;
    }

    int p = atoi(outbash_port);
    if (p < 1 || p > 65535) {
        dprintf(STDERR_FILENO, "%s: %s does not contain a valid port number\n", tool_name, origin);
        return false;
    }

    *port = p;
    return true;
}

static void print_help(void)
{
    dprintf(STDERR_FILENO, "\nusage: %s [:] [OPTIONS] COMMAND_TO_RUN_ON_WINDOWS [PARAM_1 ... PARAM_N]\n\n", tool_name);

    dprintf(STDERR_FILENO,
    "Run native Windows executables outside of WSL. The output will be shown inside\n"
    "of WSL. For this to work, this must be called from outbash.exe\n"
    "\n"
    "There are three variations of this command: wcmd, wrun and wstart\n"
    "\n"
    "  * wcmd   runs a Windows command with cmd.exe and waits for its completion.\n"
    "           Example: 'wcmd dir'\n"
    "\n"
    "  * wrun   runs a Windows command using CreateProcess and waits for it to exit.\n"
    "           Example: 'wrun notepad'\n"
    "\n"
    "  * wstart runs a Windows command in background as using 'start' from cmd.exe.\n"
    "           Example: 'wstart http://microsoft.com/'\n"
    "\n"
    "A \":\" first parameter will make the tool disregard the current WSL working\n"
    "directory and launch the Windows command from %%USERPROFILE%%.\n"
    "Example:   user@BOX:/proc$ wcmd : echo %%cd%%\n"
    "           C:\\Users\\winuser\n"
    "\n"
    "Options:\n"
    "    --force-redirects\n"
    "        Redirect standard input, output, and/or error through the caller tool\n"
    "        even if they otherwise would be connected to the Win32 console.\n"
    "        Try that option if the output is not correct, for example if lines are\n"
    "        not aligned. This can also help if the typed characters are not all\n"
    "        interpreted correctly. However, the target program won't be able to use\n"
    "        the Win32 console API anymore, so this mode has drawbacks: for example\n"
    "        the output won't be colored.\n"
    "\n"
    "    --env [VAR_1=VALUE_1 ... VAR_N=VALUE_N]\n"
    "        Launch the Windows command with modified Windows environment variables.\n"
    "        outbash.exe uses its environment variables to launch commands, and this\n"
    "        option can be used to launch one with a modified environment.\n"
    "        Check with: 'wcmd --env VAR_1=VALUE_1 ... VAR_N=VALUE_N set'\n"
    "\n"
    "    --silent-breakaway\n"
    "        Child programs of the initial one won't be controlled by outbash.exe;\n"
    "        they won't be suspended when the caller tool is, and they won't be\n"
    "        killed when the caller tool or the initial program dies.\n"
    "        This option is automatically activated when using 'wstart'.\n"
    "        For 'wcmd' and 'wstart', the initial program is 'cmd.exe'.\n"
    "        For 'wrun', the initial program is COMMAND_TO_RUN_ON_WINDOWS.\n"
    "\n"
    "For more info, check https://github.com/xilun/cbwin\n\n"
    );
}

int main(int argc, char *argv[])
{
    if (argc < 1) {
        dprintf(STDERR_FILENO, "wcmd/wrun/wstart called without argument\n");
        terminate_nocore();
    }
    int tool = get_tool(argv[0]);

    fill_std_fd_info_identity(STDIN_FILENO);
    fill_std_fd_info_identity(STDOUT_FILENO);
    fill_std_fd_info_identity(STDERR_FILENO);

    bool force_redirects = false;
    bool silent_breakaway = (tool == TOOL_WSTART);

    int port;
    bool terminate = !get_outbash_infos(&port, &force_redirects);

    struct string outbash_command = string_create("cd:");

    shift(&argc, &argv);
    if (argc && argv[0][0] == ':' && argv[0][1] == '\0') {
        shift(&argc, &argv);
        string_append(&outbash_command, "~");
    } else {
        char* cwd = agetcwd();
        if (!((strncmp(cwd, MNT_DRIVE_FS_PREFIX, strlen(MNT_DRIVE_FS_PREFIX)) == 0)
              && cwd[strlen(MNT_DRIVE_FS_PREFIX)] >= 'a'
              && cwd[strlen(MNT_DRIVE_FS_PREFIX)] <= 'z'
              && (cwd[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '/'
                  || cwd[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '\0'))) {
            dprintf(STDERR_FILENO, "%s: can't translate a WSL VolFs path to a Win32 one\n", tool_name);
            terminate = true;
        } else {
            char* cwd_win32 = convert_drive_fs_path_to_win32(cwd);
            string_append(&outbash_command, cwd_win32);
            free(cwd_win32);
        }
        free(cwd);
    }

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
        } else if (!strcmp(argv[0], "--force-redirects")) {
            force_redirects = true;
            shift(&argc, &argv);
        } else if (!strcmp(argv[0], "--silent-breakaway")) {
            silent_breakaway = true;
            shift(&argc, &argv);
        } else if (!strcmp(argv[0], "--help")) {
            print_help();
            exit(1);
        } else {
            dprintf(STDERR_FILENO, "%s: unknown command line option: %s\n", tool_name, argv[0]);
            dprintf(STDERR_FILENO, "type %s --help for more information.\n", tool_name);
            terminate_nocore();
        }
    }
    if (terminate)
        terminate_nocore();
    check_argc(argc);

    decide_will_redirect(STDIN_FILENO,  force_redirects);
    decide_will_redirect(STDOUT_FILENO, force_redirects);
    decide_will_redirect(STDERR_FILENO, force_redirects);

    int sock_ctrl = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_ctrl < 0) {
        dprintf(STDERR_FILENO, "%s: socket() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }

#define STDIN_NEEDS_SOCKET_REDIRECT     1
#define STDOUT_NEEDS_SOCKET_REDIRECT    2
#define STDERR_NEEDS_SOCKET_REDIRECT    4
#define STDERR_SOCKREDIR_TO_STDOUT      8
    int redirects =   (needs_socket_redirect(STDIN_FILENO)  ? STDIN_NEEDS_SOCKET_REDIRECT  : 0)
                    | (needs_socket_redirect(STDOUT_FILENO) ? STDOUT_NEEDS_SOCKET_REDIRECT : 0);
    if (needs_socket_redirect(STDERR_FILENO)) {
        if ((redirects & STDOUT_NEEDS_SOCKET_REDIRECT) && are_stdfd_to_same_thing(STDOUT_FILENO, STDERR_FILENO))
            redirects |= STDERR_SOCKREDIR_TO_STDOUT;
        else
            redirects |= STDERR_NEEDS_SOCKET_REDIRECT;
    }

    struct listening_socket lsock_in = NO_LISTENING_SOCKET;
    struct listening_socket lsock_out = NO_LISTENING_SOCKET;
    struct listening_socket lsock_err = NO_LISTENING_SOCKET;
    if (redirects & STDIN_NEEDS_SOCKET_REDIRECT) lsock_in = socket_listen_one_loopback();
    if (redirects & STDOUT_NEEDS_SOCKET_REDIRECT) lsock_out = socket_listen_one_loopback();
    if (redirects & STDERR_NEEDS_SOCKET_REDIRECT) lsock_err = socket_listen_one_loopback();
    ask_redirect(&outbash_command, "\nstdin:", STDIN_FILENO, lsock_in.port);
    ask_redirect(&outbash_command, "\nstdout:", STDOUT_FILENO, lsock_out.port);
    ask_redirect(&outbash_command, "\nstderr:", STDERR_FILENO,
                 (redirects & STDERR_NEEDS_SOCKET_REDIRECT) ? lsock_err.port : lsock_out.port);

    if (silent_breakaway)
        string_append(&outbash_command, "\nsilent_breakaway:1");

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
        if (sep) string_append(&outbash_command, " \"");
        string_append(&outbash_command, argv[i]);
        if (sep) string_append(&outbash_command, "\"");
        sep = true;
    }
    string_append(&outbash_command, "\n\n");
    //dprintf(STDOUT_FILENO, "%s", outbash_command.str);
    //return EXIT_FAILURE;

    signal(SIGPIPE, SIG_IGN);

    sigset_t signal_set, orig_mask;

    //////////////////////////// unblock SIGUSR1
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL);

    //////////////////////////// block SIGTSTP
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGTSTP);
    pthread_sigmask(SIG_BLOCK, &signal_set, &orig_mask);

    //////////////////////////// install custom SIGTSTP handler if signal was not ignored
    struct sigaction sa;
    sigaction(SIGTSTP, NULL, &sa);
    const bool ignore_sigtstp = (sa.sa_handler == SIG_IGN);
    if (!ignore_sigtstp) {
        sa.sa_handler = tstop_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGTSTP, &sa, NULL);
    }

    //////////////////////////// install custom SIGUSR1 handler to wake-up blocked IO forwarding threads
    // NOTE: the handler itself do nothing, but any blocked syscall will return with EINTR error
    sa.sa_handler = noop_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(port);
    if (connect(sock_ctrl, (const struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        // NOTE: I'm not sure that WSL does what Linux does concerning
        // http://www.madore.org/~david/computers/connect-intr.html
        // for now we do not expect to recover after an interruption here.
        dprintf(STDERR_FILENO, "%s: connect() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }

    if (send_all(sock_ctrl, outbash_command.str, outbash_command.length, 0) < 0) {
        dprintf(STDERR_FILENO, "%s: send_all() failed: %s\n", tool_name, my_strerror(errno));
        terminate_nocore();
    }
    string_destroy(&outbash_command);

    static struct forward_state fs[3];
    fs_init_accept_as_needed(&fs[STDIN_FILENO],  &lsock_in,  redirects & STDIN_NEEDS_SOCKET_REDIRECT,  STDIN_FILENO,  "stdin");
    fs_init_accept_as_needed(&fs[STDOUT_FILENO], &lsock_out, redirects & STDOUT_NEEDS_SOCKET_REDIRECT, STDOUT_FILENO, "stdout");
    fs_init_accept_as_needed(&fs[STDERR_FILENO], &lsock_err, redirects & STDERR_NEEDS_SOCKET_REDIRECT, STDERR_FILENO, "stderr");

    close_listener(&lsock_in);
    close_listener(&lsock_out);
    close_listener(&lsock_err);

    enum state_e state = RUNNING;
    int program_return_code = 255;

    pthread_t   forward_threads[3];
    bool        active_threads[3] = {0};

    for (int i = 0; i < 3; i++) {
        if ((!fs[i].dead_in) || (!fs[i].dead_out)) {
            int err = pthread_create(&forward_threads[i], NULL, forward_one_stream, &fs[i]);
            if (err != 0) {
                dprintf(STDERR_FILENO, "%s: pthread_create() failed: %s\n", tool_name, my_strerror(err));
                terminate_nocore();
            }
            active_threads[i] = true;
        }
    }

    int nfds = sock_ctrl + 1;

    while (state != TERMINATED) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_ctrl, &rfds);

        int pselect_res = pselect(nfds, &rfds, NULL, NULL, NULL, &orig_mask); // tstop_handler can run here
        int pselect_errno = errno;

        if (tstop_req && state == RUNNING) {
            int r = send_all(sock_ctrl, "suspend\n", strlen("suspend\n"), 0);
            if (r < 0 && err_is_connection_broken(errno)) {
                // We will never be able to ask outbash to suspend the
                // Windows process, the expected reason is that it actually
                // has already terminated and we don't know yet about that,
                // so stop the suspend forwarding mechanism and suspend
                // ourselves immediately.
                shutdown(sock_ctrl, SHUT_WR); // also we can't send anything anymore // XXX to comment for WSL bug workaround? proba low here...
                signal(SIGTSTP, SIG_DFL);
                state = DYING;
                raise(SIGTSTP);
                pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
            } else if (r < 0) { // other errors
                dprintf(STDERR_FILENO, "%s: send_all(\"suspend\\n\") failed: %s\n", tool_name, my_strerror(errno));
                abort();
            } else { // OK
                // It's up to outbash now, just wait for its "suspend_ok"
                // answer after it has suspended the Windows process.
                state = SUSPEND_PENDING;
            }
        }

        if (pselect_res < 0 && pselect_errno == EINTR) {
            // "On error, -1 is returned, and errno is set appropriately;
            //  the sets and timeout become undefined, so do not rely on
            //  their contents after an error."
            continue;
        }

        if (pselect_res < 0) {
            dprintf(STDERR_FILENO, "%s: pselect() failed: %s\n", tool_name, my_strerror(pselect_errno));
            abort();
        }

        if (FD_ISSET(sock_ctrl, &rfds)) {
            while (1) {
                int nonblock_marker;
                char *line = ctrl_readln(sock_ctrl, &nonblock_marker);
                if (!line && nonblock_marker) break;
                if (line && !strcmp(line, "suspend_ok")) {
                    if (state == SUSPEND_PENDING) {
                        signal(SIGTSTP, SIG_DFL);
                        raise(SIGTSTP);
                        sigset_t previous_mask;
                        pthread_sigmask(SIG_SETMASK, &orig_mask, &previous_mask);
                            // >>> Process will Stop here, until SIGCONT <<<
                        pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
                        tstop_req = 0;
                        int r = send_all(sock_ctrl, "resume\n", strlen("resume\n"), 0);
                        if (r < 0 && err_is_connection_broken(errno)) {
                            // killed when suspended (if this is possible?)
                            // or maybe just before an attempt?
                            shutdown(sock_ctrl, SHUT_WR); // XXX to comment for WSL bug workaround? proba low here...
                            state = DYING;
                            pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
                        } else if (r < 0) {
                            dprintf(STDERR_FILENO, "%s: send_all(\"resume\\n\") failed: %s\n", tool_name, my_strerror(errno));
                            abort();
                        } else {
                            state = RUNNING;
                            sa.sa_handler = tstop_handler;
                            sigemptyset(&sa.sa_mask);
                            sa.sa_flags = 0;
                            sigaction(SIGTSTP, &sa, NULL);
                        }
                    } else {
                        dprintf(STDERR_FILENO, "%s: spurious \"suspend_ok\" received\n", tool_name);
                    }
                } else { // not "suspend_ok" => for now only other cases are exit conditions
                    program_return_code = get_return_code(line);
                    shutdown(sock_ctrl, SHUT_RDWR);
                    signal(SIGTSTP, ignore_sigtstp ? SIG_IGN : SIG_DFL);
                    if ((tstop_req && state == RUNNING) || state == SUSPEND_PENDING) {
                        // We expect to stop soon, but not without flushing the OS TCP
                        // buffers and our owns, and other WSL processes in a pipe might
                        // already be suspended, so we better honor suspend requests ASAP.
                        raise(SIGTSTP);
                    }
                    pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
                    tstop_req = 0;
                    state = TERMINATED;
                    break;
                }
            }
        }
    }

    // XXX: this is not ideal if the Win32 side managed to maintain the
    // redirection socket beyond the lifetime of the launched process,
    // however things seem to already be not reliable for Windows reasons
    // in this case
    if (active_threads[0]) {
        __sync_fetch_and_add(&fs[0].ask_terminate, 1);
        useconds_t usec_sleep = 20000;
        while (!__sync_fetch_and_add(&fs[0].finished, 0)) {
            pthread_kill(forward_threads[0], SIGUSR1);
            usleep(usec_sleep);
            usec_sleep *= 2;
            if (usec_sleep > 60000000)
                usec_sleep = 60000000;
        }
    }

    for (int i = 0; i < 3; i++)
        if (active_threads[i])
            pthread_join(forward_threads[i], NULL);

    return program_return_code;
}
