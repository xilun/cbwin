# cbwin

Launch Windows programs from "Bash on Ubuntu on Windows" (WSL)

main features:

* Win32 command line tools in the console, invoked from WSL
* Win32 command line tools with redirections to WSL (stdin/stdout/stderr to or from pipe/file)
* suspend/resume propagation (Ctrl-Z suspends the Win32 processes, `fg` resumes them)
* exit codes propagation
* launch "detached" GUI Windows programs (uses `start` of `cmd`)


# security warning

`outbash.exe` listens on 127.0.0.1, but validates that processes that establish a connection are
running as the same user as `outbash.exe`. However, for now if redirections are used (explicitely
or because the Windows console is not used directly) the redirected data uses extra unsecured
loopback sockets from outbash.exe to the WSL caller tool. Therefore, if used on multi-user
computers, there is a risk that another user manages to connect to a redirection port before
`outbash.exe` does, and send/receive arbitrary data.

Using cbwin breaks the WSL security model (access control within WSL using Linux accounts):
Windows programs are not subject to extra WSL security checks, so the capability to run a Windows
program is equivalent to being root in WSL. If you are only using separation between the WSL root
and user to avoid casual mistakes and not for strong security purposes this is not an issue.
(Note that being root under WSL does not give you any Windows administrator rights.)

WSL is currently vulnerable to a form of UAC bypass when running elevated WSL processes, see
[this issue](https://github.com/Microsoft/BashOnWindows/issues/626).
Elevated instances of `outbash.exe` do not allow non-elevated callers to launch processes, but
it is easy for non-elevated WSL processes to force elevated ones (present and future) to do
anything, including accessing protected Windows files and talking with `outbash.exe`. Therefore,
I do not recommend launching an elevated "Bash On Windows" (with or without `outbash.exe`) in an
hostile environment, in order not to reduce the effectiveness of UAC.


# installation

[Binary releases](https://github.com/xilun/cbwin/releases):

1. In the unpacked binary archive, launch `outbash.exe`
2. Do: `sudo ./install.sh`
3. In Windows, copy `outbash.exe` where you want, usually somewhere in your `%PATH%`
4. In WSL sessions launched by `outbash.exe`, you can now call Windows programs with the `wrun`, `wcmd`, and `wstart` commands.

Or from source:

1. Build `outbash.exe` with Visual C++ 2015 and use it instead of `bash.exe`
2. In `caller/`, build `wrun`, `wcmd`, and `wstart` (with `./build.sh`)
3. Install `wrun`, `wcmd`, and `wstart` in `/usr/local/bin` (with `sudo ./install.sh`)
4. In WSL sessions launched by `outbash.exe`, you can now call Windows programs with the `wrun`, `wcmd`, and `wstart` commands.


# examples

`wcmd` launches a command with `cmd`. `wrun` launches the command line directly with `CreateProcess`,
without using `cmd`. `wstart` launches a detached command (with `start` of `cmd`).

Windows processes and their children launched with `wcmd` or `wrun` are handled in a Windows Job, and
suspending the WSL caller process (`wcmd` or `wrun`) results in the suspension of all the Windows
processes in the corresponding Job. Also, when the launched process terminates, all its direct and
indirect children are killed. This means that trying to manually do e.g. `wcmd start notepad` won't yield
useful results, because notepad will be killed just after having been launched -- `wstart` must be used
in this case.

If in doubt use `wcmd` to launch Win32 command line tools, and `wstart` to launch graphical applications.

    xilun@WINWIN:/mnt/c/Users$ uname -a
    Linux WINWIN 3.4.0+ #1 PREEMPT Thu Aug 1 17:06:05 CST 2013 x86_64 x86_64 x86_64 GNU/Linux
    xilun@WINWIN:/mnt/c/Users$ wcmd dir
     Le volume dans le lecteur C n’a pas de nom.
     Le numéro de série du volume est CZTX-666H
    
     Répertoire de c:\Users
    
    22/04/2016  20:00    <DIR>          .
    22/04/2016  20:00    <DIR>          ..
    22/04/2016  20:20    <DIR>          Default.migrated
    22/04/2016  20:00    <DIR>          Public
    27/04/2016  01:15    <DIR>          xilun
                   0 fichier(s)                0 octets
                   5 Rép(s)  43 126 734 848 octets libres
    xilun@WINWIN:/mnt/c/Users$ wstart notepad
    xilun@WINWIN:/mnt/c/Users$ 

You can redirect input and output (avoid doing that with `wstart`, it would behave weirdly):

    xilun@WINWIN:/mnt/c/Users$ wcmd dir | grep xilun
    15/05/2016  05:09    <DIR>          xilun
    xilun@WINWIN:/mnt/c/Users$ wcmd dir > xilun/foobar
    xilun@WINWIN:/mnt/c/Users$ wc xilun/foobar
     12  50 457 xilun/foobar
    xilun@WINWIN:/mnt/c/Users$ echo dir | wrun cmd | grep 'c:\\Users'
    c:\Users>dir
     Répertoire de c:\Users
    c:\Users>
    xilun@WINWIN:/mnt/c/Users$ 

The environment block for launched processes is the one `outbash.exe` was started with, but it can be modified for
individual commands. The `--env` option allows to set environment variables for the command. Parameters after this
option are interpreted as environment variable definitions until one starts with "`--`" or a parameter does not contain
an "`=`" character. An empty value erases the variable. Remaining command line arguments are used to compose the
Windows command line. All the options interpreted by the launcher must be given at the start, before the Windows
command line.

    xilun@WINWIN:/mnt/c/Users$ wcmd --env TITI=TOTO TATA=TUTU set
    [...]
    SystemRoot=C:\WINDOWS
    TATA=TUTU
    TEMP=C:\Users\xilun\AppData\Local\Temp
    TITI=TOTO
    TMP=C:\Users\xilun\AppData\Local\Temp
    [...]
    xilun@WINWIN:/mnt/c/Users$ wcmd --env TEMP= set
    [...]
    SystemRoot=C:\WINDOWS
    TMP=C:\Users\xilun\AppData\Local\Temp
    [...]

Other example to launch `msbuild` to rebuild `outbash.exe`, which shows that return codes are propagated
(running from another copy of `outbash.exe`, its impossible to overwrite it when in use):

    xilun@WINWIN:/mnt/c/Users/xilun/Documents/Projects/cbwin/vs$ wcmd '"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64 && msbuild /t:Rebuild /p:Configuration=Release /m cbwin.sln'
    Microsoft (R) Build Engine, version 14.0.25123.0
    Copyright (C) Microsoft Corporation. Tous droits réservés.
    
    La génération a démarré 30/04/2016 15:46:15.
    
    [...]
    
        La génération a réussi.
        0 Avertissement(s)
        0 Erreur(s)

    Temps écoulé 00:00:04.61
    xilun@WINWIN:/mnt/c/Users/xilun/Documents/Projects/cbwin/vs$ echo $?
    0
    xilun@WINWIN:/mnt/c/Users/xilun/Documents/Projects/cbwin/vs$ wcmd '"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64 && msbuild /t:Rebuild /p:Configuration=Release /m does_not_exist.sln'
    Microsoft (R) Build Engine, version 14.0.25123.0
    Copyright (C) Microsoft Corporation. Tous droits réservés.
    
    MSBUILD : error MSB1009: Le fichier projet n'existe pas.
    Commutateur : does_not_exist.sln
    xilun@WINWIN:/mnt/c/Users/xilun/Documents/Projects/cbwin/vs$ echo $?
    1
    xilun@WINWIN:/mnt/c/Users/xilun/Documents/Projects/cbwin/vs$ 


# warnings

For now running *interactive* Win32 console tools in the same console as a WSL bash session (for example: `wrun cmd`
or `wcmd python`) does not work well. The main problems seem to be related to the console switching internal modes
(charset, but not only) between the Win32 and the WSL world. I don't know yet if something nice enough to use in that
regard can be achieved without some changes from MS about how their stuff works. (This might be somehow related to WSL
not working well, for now, with ConEmu or Bitvise SSH Server - but I'm not really sure about that)

It is an unfinished work in progress. There are various stuff not-implemented and maybe tons of bugs.
