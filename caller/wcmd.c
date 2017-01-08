/*
 * Copyright(c) 2016-2017  Guillaume Knispel <xilun0@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "common.h"
#include "xalloc.h"
#include "err.h"
#include "nvec.h"

static const char* tool_name;
static char* wrun_path;

enum tool_e
{
    TOOL_WCMD,
    TOOL_WSTART
};

static int get_tool(const char* argv0)
{
    const char* s = strrchr(argv0, '/');
    if (s == NULL) {
        tool_name = argv0;
        wrun_path = "wrun";
    } else {
        size_t pos = s - argv0;
        tool_name = s + 1;
        wrun_path = xmalloc(pos + 1 + strlen("wrun") + 1);
        memcpy(wrun_path, argv0, pos + 1);
        memcpy(wrun_path + pos + 1, "wrun", strlen("wrun") + 1);
    }

    if (!strcmp(tool_name, "wcmd")) {
        return TOOL_WCMD;
    } else if (!strcmp(tool_name, "wstart")) {
        return TOOL_WSTART;
    } else {
        dprintf(STDERR_FILENO, "%s: unrecognized program name (should be wcmd or wstart)\n", argv0);
        terminate_nocore();
    }
}

typedef nvec_t(char*) nvec_charp;

static void push_sarg(nvec_charp *sa, const char* arg)
{
    nv_push(*sa, (char*)arg);
}

int main(int argc, char *argv[])
{
    if (argc < 1) {
        dprintf(STDERR_FILENO, "wcmd/wstart called without argument\n");
        terminate_nocore();
    }
    int tool = get_tool(argv[0]);

    nvec_charp sa;
    nv_init(sa);

    shift(&argc, &argv); // argv0
    push_sarg(&sa, wrun_path);

    push_sarg(&sa, "--tool_name");
    push_sarg(&sa, tool_name);

    if (argc && !strcmp(argv[0], ":"))
        push_sarg(&sa, shift(&argc, &argv));
    if (tool == TOOL_WSTART)
        push_sarg(&sa, "--silent-breakaway");
    while (argc && !strncmp(argv[0], "--", 2)) {
        if (!strcmp(argv[0], "--")) {
            push_sarg(&sa, shift(&argc, &argv));
            break;
        }
        if (!strcmp(argv[0], "--env")) {
            push_sarg(&sa, shift(&argc, &argv));
            while (argc && strncmp(argv[0], "--", 2) != 0
                        && *argv[0] != '\0' && strchr(argv[0] + 1, '=')) {
                push_sarg(&sa, shift(&argc, &argv));
            }
        } else {
            push_sarg(&sa, shift(&argc, &argv));
        }
    }
    switch (tool) {
    case TOOL_WCMD:
        push_sarg(&sa, "cmd");
        push_sarg(&sa, "/C");
        break;
    case TOOL_WSTART:
        push_sarg(&sa, "cmd");
        push_sarg(&sa, "/C start");
        break;
    }
    while (argc)
        push_sarg(&sa, shift(&argc, &argv));

    push_sarg(&sa, NULL);
    if (execvp(wrun_path, sa.a) < 0) {
        dprintf(STDERR_FILENO, "%s: failed to exec wrun: %s\n", tool_name, strerror(errno));
        return 1;
    }
}
