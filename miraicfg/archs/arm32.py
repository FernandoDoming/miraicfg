import struct
import logging
import traceback
from .common import decode

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("miraicfg.main")

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

# ---------------------------------------------------
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

# ---------------------------------------------------
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