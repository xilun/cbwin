# cbwin
Callback Win32 CreateProcess from WSL (or anything doing TCP on 127.0.0.1)

# installation
1. Build `outbash.exe` (for example with Visual C++ 2015) and use it instead of `bash.exe`
2. In `caller/`, build `wrun`, `wcmd`, and `wstart` (with `./build.sh`)
3. Install the binaries in `/usr/local/bin` (with `sudo ./install.sh`)
4. In WSL sessions launched by `outbash.exe`, you can now call Windows programs with the `wrun`, `wcmd`, and `wstart` commands.

# examples
`wcmd` launches a command with `cmd`, while `wstart` does likewise but also prefixes it with `start`.
`wrun` launches the command line directly with `CreateProcess`, without using `cmd`.
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

Other example to launch `msbuild` to rebuild `outbash.exe`:

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

Unfortunately Windows does not allow to replace open files, and that includes `.exe` that have been used to launch
a process that is still running (the above session was launched from an `outbash.exe` copied out of the `Release/`
directory, otherwise it would have failed). Win32 also has no equivalent of `exec()`, so we would not be able to
update a running `outbash.exe` anyway.

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

# warnings
Anybody with access to TCP 127.0.0.1 can launch anything with the privileges of the user who launched `outbash.exe`.
This might not be an issue if you are the only user of your computer. This might however break the WSL security model
(once it is properly implemented by MS), but if you are only using separation between the WSL root and user to avoid
casual mistakes and not for strong security purposes this is also not an issue.

It is an unfinished work in progress. There are various stuff not-implemented (CRT compatible escaping of the command
line args, trying to capture/restore the environment to easily do builds...)
