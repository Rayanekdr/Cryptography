import re
import sys
import hex
import tables


def S(box, input):
    """Apply S-box number 'box' to 4-bit bitstring 'input' and return a
    4-bit bitstring as the result."""
    return SBoxBitstring[box % 8][input]


def SInverse(box, output):
    """Apply S-box number 'box' in reverse to 4-bit bitstring 'output' and
    return a 4-bit bitstring (the input) as the result."""
    return SBoxBitstringInverse[box % 8][output]


def SHat(box, input):
    """Apply a parallel array of 32 copies of S-box number 'box' to the
    128-bit bitstring 'input' and return a 128-bit bitstring as the
    result."""

    result = ""
    for i in range(32):
        result = result + S(box, input[4 * i:4 * (i + 1)])
    return result


def SHatInverse(box, output):
    """Apply, in reverse, a parallel array of 32 copies of S-box number
    'box' to the 128-bit bitstring 'output' and return a 128-bit bitstring
    (the input) as the result."""

    result = ""
    for i in range(32):
        result = result + SInverse(box, output[4 * i:4 * (i + 1)])
    return result


def LT(input):
    """Apply the table-based version of the linear transformation to the
    128-bit string 'input' and return a 128-bit string as the result."""

    if len(input) != 128:
        raise ValueError("input to LT is not 128 bit long")

    result = ""
    for i in range(len(tables.LTTable)):
        outputBit = "0"
        for j in tables.LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result


def LTInverse(output):
    """Apply the table-based version of the inverse of the linear
    transformation to the 128-bit string 'output' and return a 128-bit
    string (the input) as the result."""

    if len(output) != 128:
        raise ValueError("input to inverse LT is not 128 bit long")

    result = ""
    for i in range(len(tables.LTTableInverse)):
        inputBit = "0"
        for j in tables.LTTableInverse[i]:
            inputBit = xor(inputBit, output[j])
        result = result + inputBit
    return result


def IP(input):
    """Apply the Initial Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""
    return applyPermutation(tables.IPTable, input)


def FP(input):
    """Apply the Final Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""
    return applyPermutation(tables.FPTable, input)


def IPInverse(output):
    """Apply the Initial Permutation in reverse."""
    return FP(output)


def FPInverse(output):
    """Apply the Final Permutation in reverse."""
    return IP(output)


def applyPermutation(permutationTable, input):
    """Apply the permutation specified by the 128-element list
    'permutationTable' to the 128-bit bitstring 'input' and return a
    128-bit bitstring as the result."""

    if len(input) != len(permutationTable):
        raise ValueError("input size (%d) doesn't match perm table size (%d)"
                         % (len(input), len(permutationTable)))

    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result


def R(i, BHati, KHat):
    """Apply round 'i' to the 128-bit bitstring 'BHati', returning another
    128-bit bitstring (conceptually BHatiPlus1). Do this using the
    appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    xored = xor(BHati, KHat[i])

    SHati = SHat(i, xored)

    if 0 <= i <= r - 2:
        BHatiPlus1 = LT(SHati)
    elif i == r - 1:
        BHatiPlus1 = xor(SHati, KHat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r - 1))

    return BHatiPlus1


def RInverse(i, BHatiPlus1, KHat):
    """Apply round 'i' in reverse to the 128-bit bitstring 'BHatiPlus1',
    returning another 128-bit bitstring (conceptually BHati). Do this using
    the appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    if 0 <= i <= r - 2:
        SHati = LTInverse(BHatiPlus1)
    elif i == r - 1:
        SHati = xor(BHatiPlus1, KHat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r - 1))

    xored = SHatInverse(i, SHati)

    BHati = xor(xored, KHat[i])

    return BHati


def encrypt(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', and return a 128-bit ciphertext
    bitstring."""

    K, KHat = makeSubkeys(userKey)

    BHat = IP(plainText)  # BHat_0 at this stage
    for i in range(r):
        BHat = R(i, BHat, KHat)  # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e. _r
    C = FP(BHat)

    # O.show("cipherText", C, "cipherText")
    print("cipherText\n- ", hex.bitstring2hexstring(C), "\n")

    return C


def decrypt(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey' and return a 128-bit
    plaintext bitstring."""

    K, KHat = makeSubkeys(userKey)

    BHat = FPInverse(cipherText)  # BHat_r at this stage
    for i in range(r - 1, -1, -1):  # from r-1 down to 0 included
        BHat = RInverse(i, BHat, KHat)  # Produce BHat_i from BHat_i+1
    # BHat is now _0
    plainText = IPInverse(BHat)

    return hex.bitstring2hexstring(plainText)


def makeSubkeys(userKey):
    """Given the 256-bit bitstring 'userKey' (shown as K in the paper, but
    we can't use that name because of a collision with K[i] used later for
    something else), return two lists (conceptually K and KHat) of 33
    128-bit bitstrings each."""

    # Because in Python I can't index a list from anything other than 0,
    # I use a dictionary instead to legibly represent the w_i that are
    # indexed from -8.

    # We write the key as 8 32-bit words w-8 ... w-1
    # ENOTE: w-8 is the least significant word
    w = {}
    for i in range(-8, 0):
        w[i] = userKey[(i + 8) * 32:(i + 9) * 32]

    # We expand these to a prekey w0 ... w131 with the affine recurrence
    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1],
                bitstring(phi, 32), bitstring(i, 32)),
            11)

    # The round keys are now calculated from the prekeys using the S-boxes
    # in bitslice mode. Each k[i] is a 32-bit bitstring.
    k = {}
    for i in range(r + 1):
        whichS = (r + 3 - i) % r
        k[0 + 4 * i] = ""
        k[1 + 4 * i] = ""
        k[2 + 4 * i] = ""
        k[3 + 4 * i] = ""
        for j in range(32):  # for every bit in the k and w words
            # ENOTE: w0 and k0 are the least significant words, w99 and k99
            # the most.
            input = w[0 + 4 * i][j] + w[1 + 4 * i][j] + w[2 + 4 * i][j] + w[3 + 4 * i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l + 4 * i] = k[l + 4 * i] + output[l]

    # We then renumber the 32 bit values k_j as 128 bit subkeys K_i.
    K = []
    for i in range(33):
        # ENOTE: k4i is the least significant word, k4i+3 the most.
        K.append(k[4 * i] + k[4 * i + 1] + k[4 * i + 2] + k[4 * i + 3])

    # We now apply IP to the round key in order to place the key bits in
    # the correct column
    KHat = []
    for i in range(33):
        KHat.append(IP(K[i]))

    return K, KHat


def makeLongKey(k):
    """Take a key k in bitstring format. Return the long version of that
    key."""

    l = len(k)
    if l % 32 != 0 or l < 64 or l > 256:
        raise ValueError("Invalid key length (%d bits)" % l)

    if l == 256:
        return k
    else:
        return k + "1" + "0" * (256 - l - 1)


def bitstring(n, minlen=1):
    """Translate n from integer to bitstring, padding it with 0s as
    necessary to reach the minimum length 'minlen'. 'n' must be >= 0 since
    the bitstring format is undefined for negative integers.  Note that,
    while the bitstring format can represent arbitrarily large numbers,
    this is not so for Python's normal integer type: on a 32-bit machine,
    values of n >= 2^31 need to be expressed as python long integers or
    they will "look" negative and won't work. E.g. 0x80000000 needs to be
    passed in as 0x80000000L, or it will be taken as -2147483648 instead of
    +2147483648L.

    EXAMPLE: bitstring(10, 8) -> "01010000"
    """

    if minlen < 1:
        raise ValueError("a bitstring must have at least 1 char")
    if n < 0:
        raise ValueError("bitstring representation undefined for neg numbers")

    result = ""
    while n > 0:
        if n & 1:
            result = result + "1"
        else:
            result = result + "0"
        n = n >> 1
    if len(result) < minlen:
        result = result + "0" * (minlen - len(result))
    return result


def binaryXor(n1, n2):
    """Return the xor of two bitstrings of equal length as another
    bitstring of the same length.

    EXAMPLE: binaryXor("10010", "00011") -> "10001"
    """

    if len(n1) != len(n2):
        raise ValueError("can't xor bitstrings of different " + \
                         "lengths (%d and %d)" % (len(n1), len(n2)))
    # We assume that they are genuine bitstrings instead of just random
    # character strings.

    result = ""
    for i in range(len(n1)):
        if n1[i] == n2[i]:
            result = result + "0"
        else:
            result = result + "1"
    return result


def xor(*args):
    """Return the xor of an arbitrary number of bitstrings of the same
    length as another bitstring of the same length.

    EXAMPLE: xor("01", "11", "10") -> "00"
    """

    if args == []:
        raise ValueError("at least one argument needed")

    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result


def rotateLeft(input, places):
    """Take a bitstring 'input' of arbitrary length. Rotate it left by
    'places' places. Left means that the 'places' most significant bits are
    taken out and reinserted as the least significant bits. Note that,
    because the bitstring representation is little-endian, the visual
    effect is actually that of rotating the string to the right.

    EXAMPLE: rotateLeft("000111", 2) -> "110001"
    """

    p = places % len(input)
    return input[-p:] + input[:-p]


def rotateRight(input, places):
    return rotateLeft(input, -places)


def shiftLeft(input, p):
    if abs(p) >= len(input):
        # Everything gets shifted out anyway
        return "0" * len(input)
    if p < 0:
        # Shift right instead
        return input[-p:] + "0" * len(input[:-p])
    elif p == 0:
        return input
    else:  # p > 0, normal case
        return "0" * len(input[-p:]) + input[:-p]


def shiftRight(input, p):
    return shiftLeft(input, -p)


def keyLengthInBitsOf(k):
    return len(k) * 4


# --------------------------------------------------------------
# Format conversions

def quadSplit(b128):
    """Take a 128-bit bitstring and return it as a list of 4 32-bit
    bitstrings, least significant bitstring first."""

    if len(b128) != 128:
        raise ValueError("must be 128 bits long, not " + len(b128))

    result = []
    for i in range(4):
        result.append(b128[(i * 32):(i + 1) * 32])
    return result


def quadJoin(l4x32):
    """Take a list of 4 32-bit bitstrings and return it as a single 128-bit
    bitstring obtained by concatenating the internal ones."""

    if len(l4x32) != 4:
        raise ValueError("need a list of 4 bitstrings, not " + len(l4x32))

    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]


# --------------------------------------------------------------
# Constants
phi = 0x9e3779b9;
r = 32;
# --------------------------------------------------------------
# Data tables


# Each element of this list corresponds to one S-box. Each S-box in turn is
# a list of 16 integers in the range 0..15, without repetitions. Having the
# value v (say, 14) in position p (say, 0) means that if the input to that
# S-box is the pattern p (0, or 0x0) then the output will be the pattern v
# (14, or 0xe).
SBoxDecimalTable = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],  # S0
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],  # S1
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],  # S2
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],  # S3
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],  # S4
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],  # S5
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],  # S6
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],  # S7
]
# NB: in serpent-0, this was a list of 32 sublists (for the 32 different
# S-boxes derived from DES). In the final version of Serpent only 8 S-boxes
# are used, with each one being reused 4 times.


# Make another version of this table as a list of dictionaries: one
# dictionary per S-box, where the value of the entry indexed by i tells you
# the output configuration when the input is i, with both the index and the
# value being bitstrings.  Make also the inverse: another list of
# dictionaries, one per S-box, where each dictionary gets the output of the
# S-box as the key and gives you the input, with both values being 4-bit
# bitstrings.
SBoxBitstring = []
SBoxBitstringInverse = []
for line in SBoxDecimalTable:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = bitstring(i, 4)
        value = bitstring(line[i], 4)
        dict[index] = value
        inverseDict[value] = index
    SBoxBitstring.append(dict)
    SBoxBitstringInverse.append(inverseDict)


def helpExit(message=None):
    print(help)
    if message:
        print("ERROR:", message)
    sys.exit()


def convertToBitstring(input, numBits):
    """Take a string 'input', theoretically in std I/O format, but in
    practice liable to contain any sort of crap since it's user supplied,
    and return its bitstring representation, normalised to numBits
    bits. Raise the appropriate variant of ValueError (with explanatory
    message) if anything can't be done (this includes the case where the
    'input', while otherwise syntactically correct, can't be represented in
    'numBits' bits)."""

    if re.match("^[0-9a-f]+$", input):
        bitstring = hex.hexstring2bitstring(input)
    else:
        raise ValueError("%s is not a valid hexstring" % input)

    # assert: bitstring now contains the bitstring version of the input

    if len(bitstring) > numBits:
        # Last chance: maybe it's got some useless 0s...
        if re.match("^0+$", bitstring[numBits:]):
            bitstring = bitstring[:numBits]
        else:
            raise ValueError("input too large to fit in %d bits" % numBits)
    else:
        bitstring = bitstring + "0" * (numBits - len(bitstring))

    return bitstring
