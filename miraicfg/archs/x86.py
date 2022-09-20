import struct
import logging
from .common import decode

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("miraicfg.main")

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

# ---------------------------------------------------
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

# ---------------------------------------------------
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
                    cnc = r2.cmd(f"ps @ {cnc_addr}").strip()
                    break
        last_instr = i
    return cnc
