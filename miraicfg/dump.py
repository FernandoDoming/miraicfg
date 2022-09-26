import re
from sys import base_prefix
import json
import r2pipe
import logging
import hashlib

from .utils.cmdline import green, red
from .archs.x86 import *
from .archs.arm32 import *

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("miraicfg.main")
log.setLevel(logging.INFO)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    parser.add_argument(
        "-v",
        help = "Enable verbosity",
        action = "store_true"
    )
    parser.add_argument(
        "-q", "--quiet",
        help = "Quiet mode",
        action = "store_true"
    )
    parser.add_argument(
        "--no-stats",
        help = "Do not print configuration dumping stats at the end of the execution",
        action = "store_true"
    )
    parser.add_argument(
        "-o", "--output",
        help = "Output file (default: stdout)",
        default = None
    )
    args = parser.parse_args()
    if args.v:
        log.setLevel(logging.DEBUG)
    elif args.quiet:
        log.setLevel(logging.WARNING)

    configs = {}
    for file in args.files:
        sha256 = None
        with open(file, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        cfg = dump_mirai(file)
        configs[sha256] = cfg

    if args.output:
        with open(args.output, "w") as f:
            f.write(json.dumps(configs, indent=4))
    else:
        print(json.dumps(configs, indent=4))

    if not args.no_stats:
        nsuccess, nerrors = 0, 0
        nfiles = len(args.files)
        for sha256, config in configs.items():
            if config and (
                config.get("cnc") or config.get("strings_table")
            ):
                nsuccess += 1
            else:
                nerrors += 1

        print(green("[+]") + " Execution statistics:")
        print(green("[+]") + f" Processed {nfiles} files")
        print(
            "\tConfig extracted: " +
            green(nsuccess) +
            "\tFailed to extract: " +
            red(nerrors) +
            f"\tSuccess ratio: {(nsuccess / float(nfiles) * 100):.2f}%"
        )

# ---------------------------------------------------
def identify_mirai_enc_fns(r2):
    candidate = None
    enc_fns = []

    fns = r2.cmdj("aflj")
    for fn in fns:
        if (
                not candidate and
                (fn["size"] > 50 and fn["size"] < 300) and
                # receives a single arg (index to be end / dec)
                fn["nargs"] == 1 and
                # does not call fns
                fn["outdegree"] == 0 and
                fn["nbbs"] > 1 and
                # gets called a lot
                fn["indegree"] >= 5 and
                (fn["is-pure"] == "false" or not fn["is-pure"]) and
                # the argument is an integer
                re.match(r"[\w\.]+ ?\(int[\w]+ \w+\);", fn["signature"])
            ):
            candidate = fn
            log.debug("Found first encryption candidate function: %s", fn["name"])
            continue

        if (
            candidate and
            # match a second fn with the same size as the 1st one
            candidate["size"] - 10 <= fn["size"] <= candidate["size"] + 10 and
            # the rest of features are the same as well
            fn["nargs"] == 1 and
            fn["outdegree"] == 0 and
            fn["nbbs"] > 1 and
            fn["indegree"] >= 5 and
            (fn["is-pure"] == "false" or not fn["is-pure"]) and
            re.match(r"[\w\.]+ \(int[\w]+ \w+\);", fn["signature"])
        ):
            enc_fns.append(candidate)
            enc_fns.append(fn)
            log.debug("Found duplicated encryption function: %s", fn["name"])
            break

    return enc_fns

def identify_mirai_table_init_fn(r2):
    fns = r2.cmdj("aflj")
    table_init = None
    for fn in fns:
        if (
            fn.get("type") == "fcn" and
            # no loops nor branches
            fn.get("nbbs") == 1 and
            fn.get("cc") <= 1 and
            # no params
            fn.get("nargs") == 0 and
            # more than 50 calls / jumps to another functions
            fn.get("outdegree", 0) >= 50 and
            # just a single call from outside (table_init is only called once)
            fn.get("indegree", 0) == 1
        ):
            table_init = fn
            break
    return table_init

# ---------------------------------------------------
def dump_mirai(fpath):
    cfg = {}
    r2 = r2pipe.open(fpath, flags=["-2"])
    r2.use_cache = True
    r2.cmd("aaaa")
    enc_fns = identify_mirai_enc_fns(r2)
    if not enc_fns or len(enc_fns) != 2:
        log.warning(
            "%s: Could not determine Mirai's encryption functions",
            fpath
        )
        return None

    log.debug(
        "%s: Mirai's encryption function found: %s, %s",
        fpath, enc_fns[0]['name'], enc_fns[1]['name']
    )
    table_init = identify_mirai_table_init_fn(r2)
    if not table_init:
        log.warning("%s: Could not find Mirai's table_init function", fpath)
        return None

    log.debug("%s: table_init found: %s", fpath, table_init['name'])

    bininfo = r2.cmdj("ij")
    arch = bininfo.get("bin", {}).get("arch")
    # Architecture-dependant data extraction
    # X86
    if arch == "x86":
        cfg["cnc"] = extract_cnc_x86(r2)
        table_base, key = extract_enc_values_x86(r2, enc_fns[0])
        cfg["key"] = key
        if key:
            cfg["strings_table"] = decrypt_table_x86(r2, table_init, key)

    # ARM32
    elif arch == "arm" and bininfo.get("bin", {}).get("bits") == 32:
        cfg["cnc"] = extract_cnc_arm32(r2)
        table_base, key = extract_enc_values_arm32(fpath, r2, enc_fns[0])
        cfg["key"] = key
        if key:
            cfg["strings_table"] = decrypt_table_arm32(r2, table_init, key)

    else:
        log.warning("%s: Architecture %s not supported", fpath, arch)

    r2.quit()
    if cfg:
        for _str in cfg.get("strings_table", []):
            pattern = re.compile(r"^\/bin\/busybox (\w+)\x00$")
            if m := pattern.match(_str):
                cfg["botnet"] = m.group(1)
                break

        log.debug("%s: Configuration dumped: %s", fpath, cfg)
    else:
        log.warning("%s: Configuration could not be dumped for refered file", fpath)

    return cfg
