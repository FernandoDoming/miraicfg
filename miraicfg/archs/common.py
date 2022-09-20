
# ---------------------------------------------------
def decode(key: int, enc_str: bytes):
    k1 = key & 0xFF
    k2 = (key>>8) & 0xFF
    k3 = (key>>16) & 0xFF
    k4 = (key>>24) & 0xFF
    output = ""
    for n in enc_str:
        c = chr(n)
        output += chr(ord(c)^k4^k3^k2^k1)
    return output