import re
from sys import base_prefix
import json
import r2pipe
import logging
import hashlib
import struct
import traceback

from .utils.cmdline import green, red

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

# ---------------------------------------------------
def decode(key, enc_str):
    k1 = key & 0xFF
    k2 = (key>>8) & 0xFF
    k3 = (key>>16) & 0xFF
    k4 = (key>>24) & 0xFF
    output = ""
    for n in enc_str:
        c = chr(n)
        output += chr(ord(c)^k4^k3^k2^k1)
    return output

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
                # gets called a lot
                fn["indegree"] >= 5 and
                (fn["is-pure"] == "false" or not fn["is-pure"]) and
                # the argument is an integer
                re.match(r"[\w\.]+ \(int[\w]+ \w+\);", fn["signature"])
            ):
            candidate = fn
            continue

        if (
            candidate and
            # match a second fn with the same size as the 1st one
            candidate["size"] - 10 <= fn["size"] <= candidate["size"] + 10 and
            # the rest of features are the same as well
            fn["nargs"] == 1 and
            fn["outdegree"] == 0 and
            fn["indegree"] >= 5 and
            (fn["is-pure"] == "false" or not fn["is-pure"]) and
            re.match(r"[\w\.]+ \(int[\w]+ \w+\);", fn["signature"])
        ):
            enc_fns.append(candidate)
            enc_fns.append(fn)
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
    r2 = r2pipe.open(fpath)
    r2.use_cache = True
    r2.cmd("aaaa")
    enc_fns = identify_mirai_enc_fns(r2)
    if not enc_fns or len(enc_fns) != 2:
        log.warning(
            "%s: Could not determine Mirai's encryption functions",
            fpath
        )
        return None

    log.info(
        "%s: Mirai's encryption function found: %s, %s",
        fpath, enc_fns[0]['name'], enc_fns[1]['name']
    )
    table_init = identify_mirai_table_init_fn(r2)
    if not table_init:
        log.warning("%s: Could not find Mirai's table_init function", fpath)
        return None

    log.info("%s: table_init found: %s", fpath, table_init['name'])

    bininfo = r2.cmdj("ij")
    arch = bininfo.get("bin", {}).get("arch")
    # Architecture-dependant data extraction
    if arch == "x86":
        cfg["cnc"] = extract_cnc_x86(r2)
        table_base, key = extract_enc_values_x86(r2, enc_fns[0])
        cfg["key"] = key
        if key:
            cfg["strings_table"] = decrypt_table_x86(r2, table_init, key)

    elif arch == "arm" and bininfo.get("bin", {}).get("bits"):
        cfg["cnc"] = extract_cnc_arm32(r2)
        table_base, key = extract_enc_values_arm32(r2, enc_fns[0])
        cfg["key"] = key
        if key:
            cfg["strings_table"] = decrypt_table_arm32(r2, table_init, key)

    else:
        log.warning("%s: Architecture %s not supported", fpath, arch)

    r2.quit()
    if cfg:
        log.info("%s: Configuration dumped: %s", fpath, cfg)
    else:
        log.warning("%s: Configuration could not be dumped for refered file", fpath)

    return cfg

# ---------------------------------------------------
#                         X86                       |
# ---------------------------------------------------
def extract_enc_values_x86(r2, enc_fn):
    table_base = None
    key = None
    instrs = r2.cmdj(f"aoj {enc_fn['ninstrs']} @ {enc_fn['offset']}")
    for i in instrs:
        if (
            i["mnemonic"] == "lea" and
            len(i["opex"]["operands"]) == 2 and
            i["opex"]["operands"][1]["type"] == "mem" and
            i["opex"]["operands"][1]["disp"] != 0
        ):
            table_base = i["opex"]["operands"][1]["disp"]

        if (
            i["mnemonic"] == "mov" and
            len(i["opex"]["operands"]) == 2 and
            i["opex"]["operands"][1]["type"] == "mem" and
            ", dword [0x" in i["opcode"]
        ):
            key_addr = i["opex"]["operands"][1]["disp"]
            key = bytes(r2.cmdj(f"pxj 4 @ {key_addr}"))
            key = struct.unpack("<I", key)[0]
            break

    return table_base, key

def decrypt_table_x86(r2, tableinit_fn, key):
    strings = []
    instrs = r2.cmdj(f"aoj {tableinit_fn['ninstrs']} @ {tableinit_fn['offset']}")
    baddr = r2.cmdj("ij").get("bin", {}).get("baddr")

    last_instr = None
    for i in instrs:
        if (
            i["mnemonic"] == "push" and
            i["opex"]["operands"][0]["type"] == "imm" and
            i["opex"]["operands"][0]["value"] >= baddr
        ):
            str_addr = i["opex"]["operands"][0]["value"]
            str_len = last_instr["opex"]["operands"][0]["value"]
            enc_str = bytes(r2.cmdj(f"pxj {str_len} @ {str_addr}"))
            log.debug(
                "Got a encoded string. Str: %s, len: %d, addr: %x",
                enc_str, str_len, str_addr
            )
            dec_str = decode(key, enc_str)
            strings.append(dec_str)
            log.debug("Decrypted string: %s", dec_str)

        last_instr = i
    return strings

def extract_cnc_x86(r2):
    cnc = None
    baddr = r2.cmdj("ij").get("bin", {}).get("baddr")
    instrs = r2.cmdj("aoj 100 @ main")
    last_instr = None
    for i in instrs:
        if (
            i["mnemonic"] == "push" and
            i["opex"]["operands"][0]["type"] == "imm" and
            i["opex"]["operands"][0]["value"] == 5 and
            last_instr["mnemonic"] == "push" and
            last_instr["opex"]["operands"][0]["type"] == "imm" and
            last_instr["opex"]["operands"][0]["value"] >= baddr
        ):
            anti_gdb_entry = last_instr["opex"]["operands"][0]["value"]
            resolve_cnc_mov = r2.cmdj(f"aoj 1 @ {anti_gdb_entry}")[0]
            resolve_cnc_fn_addr = resolve_cnc_mov["opex"]["operands"][1]["value"]
            resolve_cnc_instrs = r2.cmdj(f"aoj 20 @ {resolve_cnc_fn_addr}")
            for _i in resolve_cnc_instrs:
                if (
                    _i["mnemonic"] == "mov" and
                    _i["opex"]["operands"][0]["type"] == "mem" and
                    _i["opex"]["operands"][1]["type"] == "imm" and
                    _i["opex"]["operands"][1]["value"] >= baddr
                ):
                    cnc_addr = _i["opex"]["operands"][1]["value"]
                    cnc = r2.cmd(f"ps @ {cnc_addr}")
                    break
        last_instr = i
    return cnc

# ---------------------------------------------------
#                         ARM32                     |
# ---------------------------------------------------
def extract_enc_values_arm32(r2, enc_fn):
    table_base = None
    key = None
    instrs = r2.cmdj(f"aoj {enc_fn['ninstrs']} @ {enc_fn['offset']}")
    for i in instrs:
        if (
            not table_base and
            i["mnemonic"] == "ldr" and
            len(i["opex"]["operands"]) == 2 and
            i["opex"]["operands"][1]["type"] == "mem" and
            i["opex"]["operands"][1]["disp"] != 0
        ):
            table_base = i["opex"]["operands"][1]["disp"]
            continue

        if (
            table_base and
            i["mnemonic"] == "ldr" and
            len(i["opex"]["operands"]) == 2 and
            i["opex"]["operands"][1]["type"] == "mem" and
            i["opex"]["operands"][1]["base"] == "pc"
        ):
            key_ptr_ptr = i["addr"] + 8 + i["opex"]["operands"][1]["disp"]
            key_ptr = bytes(r2.cmdj(f"pxj 4 @ {key_ptr_ptr}"))
            # Parse as little-endian 32 bit unsinged int
            key_ptr = struct.unpack("<I", key_ptr)[0]
            # I think the +4 in the line below is a r2 bug
            # however it may be, the addr read previously needs to be
            # offsetted by +4 to read the correct key in r2 (but not in IDA)
            key = bytes(r2.cmdj(f"pxj 4 @ {key_ptr + 4}"))
            key = struct.unpack("<I", key)[0]
            break

    return table_base, key

def decrypt_table_arm32(r2, tableinit_fn, key):
    strings = []
    instrs = r2.cmdj(f"aoj {tableinit_fn['ninstrs']} @ {tableinit_fn['offset']}")
    str_len = 0
    for i in instrs:
        if (
            i["mnemonic"] == "mov" and
            i["opex"]["operands"][1]["type"] == "imm"
        ):
            # The string length is always in the last mov rX,<imm value>
            # before loading the string. As such, we save the last mov observed
            # and use it when we identify a string
            str_len = i["opex"]["operands"][1]["value"]
            continue

        if (
            i["mnemonic"] == "ldr" and
            i["opex"]["operands"][0]["type"] == "reg" and
            (", aav." in i["disasm"] or ", str." in i["disasm"])
        ):
            # These instructions reference the strings
            try:
                str_addr = None
                if ", aav." in i["disasm"]:
                    str_addr = int(i["disasm"].split(", aav.")[1], 16)
                else:
                    str_addr = i["disasm"].split(", ")[1]
                log.debug("Got an encrypted_string - addr: %s, len: %d", str_addr, str_len)
                enc_str = bytes(r2.cmdj(f"pxj {str_len} @ {str_addr}"))
                dec_str = decode(key, enc_str)
                log.debug("Decoded string is %s", dec_str)
                strings.append(dec_str)

            except Exception as e:
                log.warning(
                    "Error obtaining str from instruction %s: %s",
                    i,
                    traceback.format_exception(
                        etype=type(e), value=e, tb=e.__traceback__
                    )
                )
    return strings

def extract_cnc_arm32(r2):
    cnc = None
    baddr = r2.cmdj("ij").get("bin", {}).get("baddr")
    instrs = r2.cmdj("aoj 100 @ main")
    last_instr = None
    for i in instrs:
        if (
            i["mnemonic"] == "push" and
            i["opex"]["operands"][0]["type"] == "imm" and
            i["opex"]["operands"][0]["value"] == 5 and
            last_instr["mnemonic"] == "push" and
            last_instr["opex"]["operands"][0]["type"] == "imm" and
            last_instr["opex"]["operands"][0]["value"] >= baddr
        ):
            anti_gdb_entry = last_instr["opex"]["operands"][0]["value"]
            resolve_cnc_mov = r2.cmdj(f"aoj 1 @ {anti_gdb_entry}")[0]
            resolve_cnc_fn_addr = resolve_cnc_mov["opex"]["operands"][1]["value"]
            resolve_cnc_instrs = r2.cmdj(f"aoj 20 @ {resolve_cnc_fn_addr}")
            for _i in resolve_cnc_instrs:
                if (
                    _i["mnemonic"] == "mov" and
                    _i["opex"]["operands"][0]["type"] == "mem" and
                    _i["opex"]["operands"][1]["type"] == "imm" and
                    _i["opex"]["operands"][1]["value"] >= baddr
                ):
                    cnc_addr = _i["opex"]["operands"][1]["value"]
                    cnc = r2.cmd(f"ps @ {cnc_addr}")
                    break
        last_instr = i
    return cnc