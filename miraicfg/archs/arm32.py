import struct
import logging
import traceback
import ipaddress
import re
from magic import Magic
from .common import decode

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("miraicfg.main")

# ---------------------------------------------------
#                         ARM32                     |
# ---------------------------------------------------
def extract_enc_values_arm32(fpath, r2, enc_fn):
    table_base, key = None, None

    try:
        instrs = r2.cmdj(f"aoj {enc_fn['ninstrs']} @ {enc_fn['offset']}")
        for i in instrs:
            if (
                not table_base and
                i["mnemonic"] == "ldr" and
                len(i["opex"]["operands"]) == 2 and
                i["opex"]["operands"][1]["type"] == "mem" and
                i["opex"]["operands"][1]["disp"] != 0
            ):
                table_base = i["addr"] + i["opex"]["operands"][1]["disp"] + 8
                log.debug("table base: %x", table_base)
                continue

            if (
                table_base and
                i["mnemonic"] == "ldr" and
                len(i["opex"]["operands"]) == 2 and
                i["opex"]["operands"][1]["type"] == "mem" and
                i["opex"]["operands"][1]["base"] == "pc"
            ):
                key_ptr_ptr = i["addr"] + 8 + i["opex"]["operands"][1]["disp"]
                log.debug("key_ptr_ptr: %x", key_ptr_ptr)
                key_ptr = bytes(r2.cmdj(f"pxj 4 @ {key_ptr_ptr}"))
                # Parse as little-endian 32 bit unsinged int
                key_ptr = struct.unpack("<I", key_ptr)[0]
                log.debug("key_ptr: %x", key_ptr)

                # It looks like ARM32 EABI4 is bugger in r2
                # and the data is offseted by 4 in certain sections
                # so we correct it in such case
                m = Magic()
                filetype = m.from_file(fpath)
                if "EABI4" in filetype:
                    key_ptr = key_ptr + 4

                key = bytes(r2.cmdj(f"pxj 4 @ {key_ptr}"))
                key = struct.unpack("<I", key)[0]
                log.debug("key: %x", key)
                break
    except:
        log.exception("Exception extracting key from %s", enc_fn["name"])

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
    resolve_cnc_addr = None

    try:
        instrs = r2.cmdj("aoj 100 @ main")
        # we will be looking for the asm sequence
        # ldr r1, aav.XXXXXX
        # mov r0, 5
        # bl signal
        # as the signal handler for signum 5 is the responsible 
        # of resolving the cnc addr
        for i in instrs:
            if (
                # find a ldr r1, aav.XXXXXXXX
                i["mnemonic"] == "ldr" and
                i["opex"]["operands"][0]["type"] == "reg" and
                i["opex"]["operands"][0]["value"] == "r1" and
                ", aav." in i["disasm"]
            ):
                # check that the next instruction is a mov r0, 5
                i2 = r2.cmdj(f"aoj 1 @ {i['addr'] + i['size']}")[0]
                if i2["disasm"] != "mov r0, 5":
                    continue

                # after that we must find a bl signal
                i3 = r2.cmdj(f"aoj 1 @ {i2['addr'] + i2['size']}")[0]
                if i3["mnemonic"] != "bl":
                    continue

                # we have found the sequence
                # the handler just sets a global var
                # to the correct function pointer
                handler_fn_addr = i["disasm"].split(", aav.")[1]
                log.debug("Found signum 5 handler: %s", handler_fn_addr)
                handler_fn = r2.cmdj(f"aoj 1 @ {handler_fn_addr}")[0]
                if handler_fn["mnemonic"] != "ldr" or ", aav." not in handler_fn["disasm"]:
                    continue

                resolve_cnc_addr = handler_fn["disasm"].split(", aav.")[1]
                log.debug("Found resolve_cnc_addr: %s", resolve_cnc_addr)
                break

        if resolve_cnc_addr:
            instrs = r2.cmdj(f"aoj 15 @ {resolve_cnc_addr}")
            skip = True
            for i in instrs:
                # if we find a ldr <reg>, <str> thats our CnC
                ldr_ip_pattern = re.compile(r"^ldr r\d+, str\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")
                if (
                    i["mnemonic"] == "ldr" and
                    ", str." in i["disasm"] and
                    (m := ldr_ip_pattern.match(i["disasm"]))
                ):
                    cnc = m.group(1)
                    log.debug("Found CnC info in instruction %s", i["disasm"])
                    break

                # else we may find a ldr of a referenced 4 byte value
                # which should be the encoded IP address of the CnC
                elif (
                    i["mnemonic"] == "ldr" and
                    ", [0x" in i["disasm"] and
                    i["opex"]["operands"][0]["type"] == "reg" and
                    i["opex"]["operands"][1]["type"] == "mem" and
                    i["opex"]["operands"][1]["base"] == "pc"
                ):
                    if skip:
                        # the second ldr reg,[0xXXXXXX] has the cnc data
                        skip = False
                        continue

                    cnc_addr = i["addr"] + i["opex"]["operands"][1]["disp"] + 8
                    cnc = bytes(r2.cmdj(f"pxj 4 @ {cnc_addr}"))
                    # int to readable ip
                    cnc = str(ipaddress.ip_address(cnc))
    except:
        log.exception("Exception extracting CnC from main")
    return cnc