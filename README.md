Static Mirai configuration dumper that works by parsing the assembly code in the binaries and extracting the sensible data from the proper references. Currently only x86 and arm32 architectures are supported. Binaries need to be unpacked.

## Installation

0. **Prerequisite**: This code relies in radare2 so it needs to be installed for it to work. Refer to [radare2's page](https://github.com/radareorg/radare2) for how to install it.
1. `pip install miraicfg` **or** clone this repo and run `pip install .` in the project's root.

## Usage

The script has a help menu showing possible runtime arguments:
```
$ miraicfg -h
usage: miraicfg [-h] [-v] [-q] [--no-stats] [-o OUTPUT] files [files ...]

positional arguments:
  files

optional arguments:
  -h, --help            show this help message and exit
  -v                    Enable verbosity
  -q, --quiet           Quiet mode
  --no-stats            Do not print configuration dumping stats at the end of the execution
  -o OUTPUT, --output OUTPUT
                        Output file (default: stdout)
```

Basic usage:
```
$ miraicfg 3cece358fecfc8fbe2e86a1b2c6ae3a0f34d9648cd2306cd734bc717216a728e 
{
    "3cece358fecfc8fbe2e86a1b2c6ae3a0f34d9648cd2306cd734bc717216a728e": {
        "cnc": "198.134.120.150",
        "key": 3739155375,
        "strings_table": [
            "\u00059",
            "\u0007\u00be",
            "DaddyL33T Infected Your Shit\u0000",
            "shell\u0000",
            "enable\u0000",
            "system\u0000",
            "sh\u0000",
            "/bin/busybox JOSHO\u0000",
            "JOSHO: applet not found\u0000",
            "ncorrect\u0000",
            "/bin/busybox ps\u0000",
            "/bin/busybox kill -9 \u0000",
            "/proc/\u0000",
            "/exe\u0000",
            "/fd\u0000",
            "/maps\u0000",
            "/proc/net/tcp\u0000",
            "/status\u0000",
            ".anime\u0000",
            "/proc/net/route\u0000",
            "assword\u0000",
            "TSource Engine Query\u0000",
            "/etc/resolv.conf\u0000",
            "nameserver \u0000",
            "/dev/watchdog\u0000",
            "/dev/misc/watchdog\u0000",
            "pbbf~cu\u0011",
            "ogin\u0000",
            "enter\u0000",
            "1gba4cdom53nhp12ei0kfj\u0000"
        ],
        "botnet": "JOSHO"
    }
}
[+] Execution statistics:
[+] Processed 1 files
	Config extracted: 1	Failed to extract: 0	Success ratio: 100.00%
```