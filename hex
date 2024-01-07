# Hex conversion functions

bin2hex = {
    # Given a 4-char bitstring, return the corresponding 1-char hexstring
    "0000": "0", "1000": "1", "0100": "2", "1100": "3",
    "0010": "4", "1010": "5", "0110": "6", "1110": "7",
    "0001": "8", "1001": "9", "0101": "a", "1101": "b",
    "0011": "c", "1011": "d", "0111": "e", "1111": "f",
}

# Make the reverse lookup table too
hex2bin = {}
for (bin, hex) in bin2hex.items():
    hex2bin[hex] = bin

def bitstring2hexstring(b):
    """Take bitstring 'b' and return the corresponding hexstring."""

    result = ""
    l = len(b)
    if l % 4:
        b = b + "0" * (4 - (l % 4))
    for i in range(0, len(b), 4):
        result = result + bin2hex[b[i:i + 4]]
    return reverseString(result)


def hexstring2bitstring(h):
    """Take hexstring 'h' and return the corresponding bitstring."""

    result = ""
    for c in reverseString(h):
        result = result + hex2bin[c]
    return result


def reverseString(s):
    l = list(s)
    l.reverse()
    return "".join(l)
