Control Ultimate-64.

This uses the UDP command interface and the FTP interface to start
programs, reset the machine, mount disk images or insert key presses.
Some features only work with a modified version of the Ultimate-64 firmware.
See https://github.com/p2mate/1541ultimate for the modified firmware.

```
u64-monitor 0.1
Peter De Schrijver
Ultimate64 remote control program

USAGE:
    u64-monitor [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -u, --ultimate64 <U64 address>    Ultimate64 hostname[:port]

SUBCOMMANDS:
    dumpmem     Dump U64 memory
    flash       Update U64 firmware
    fs          U64 fs manipulation
    help        Prints this message or the help of the given subcommand(s)
    keyb        Send keystrokes
    mount       Mount D64 image
    poweroff    Power off U64
    reset       Reset C64 or U64
    run         Run CRT, D64 or PRG file
    trace       Trace U64 execution
```
