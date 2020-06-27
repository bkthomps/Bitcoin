"""
ECE 458 Project 1
Skeleton solution file.

You need to assign values to variables, and implement two functions as part of your answers to this project
You are not allowed to call any DSA signature package.
You are allowed to define whatever subroutines you like to structure your code.
"""

import hashlib
import binascii
import Constants
from bitstring import BitArray

"""
sha3_224_hex() is design to take a hexadecimal string as the input and compute it's sha3_224 hash value. 
You may call sha3_224_hex() in your project for both DSA signature and sha3_224 hash computation
Don't directly call hashlib.sha3_224() which only takes a character string (then encode the string to utf-8 format) as the input.
No prefix for the input string, and len(hexstr) is even
e.g.  sha3_224_hex("4c")
"""


def sha3_224_hex(hexstr):
    if len(hexstr) % 2 != 0:
        raise ValueError("Error: Length of hex string should be even")
    m = hashlib.sha3_224()
    data = binascii.a2b_hex(str(hexstr))
    m.update(data)
    return m.hexdigest()


# --------------------------------------------------------------------------------

# Part 1:Copy and paste your parameters here
# p, q, g are DSA domain parameters,
# sk_i (secret keys), pk_i (public keys), k_i (random numbers) are used in each signature and verification
p = Constants.p
q = Constants.q
g = Constants.g

sk1 = Constants.sk1
sk2 = Constants.sk2
sk3 = Constants.sk3

# --------------------------------------------------------------------------------

# Part 2:Assign values that you compute to those parameters as part of your answers to (a) (b) and (c)
# (a) list all prime factors of p-1,
# list 3 public keys pk_i's corresponding to sk_i's, those numbers should be decimal integers
pfactor1 = 2
pfactor2 = q
pfactor3 = 599352188457547639693740171522680835865322184075286620256386716439921029334782998562008313995103840817116953210359643511447372101221464995653177706653918911634015555633001801773590292023083604552613918655194669929368962688659673544061885990566694774938089095597940505443430714573194211134223784784744939911387314440899638056016474270609853063142638329500429039904897328933858412897374253962878313102199163400319655392723027703101354927814377851954345336880097584669598515815463134218486896858352351187255794957262790967727451704317515673833695348341

pk1 = pow(g, sk1, p)
pk2 = pow(g, sk2, p)
pk3 = pow(g, sk3, p)

# (b) Sig_sk1 and Sig_sk2, k_i is the random number used in signature. 
# u, v, w is the intermediate results when verifying Sig_sk1(m1)
# All variables should be decimal integers
l1 = 2048 - pk1.bit_length()
l2 = 2048 - pk2.bit_length()
l3 = 2048 - pk3.bit_length()


# (b)(1)
def buildm1():
    amt1 = BitArray(hex='04')
    leading_zeroes_pk1 = ''.zfill(l1)
    leading_zeroes_pk2 = ''.zfill(l2)
    m1 = BitArray(bin=leading_zeroes_pk1) + BitArray(bin="{0:b}".format(pk1)) + BitArray(
        bin=leading_zeroes_pk2) + BitArray(bin="{0:b}".format(pk2)) + amt1
    print(len(m1))
    return m1.hex


m1 = buildm1()
k1 = int(sha3_224_hex('01'), 16)
r1 = pow(g, k1, p) % q
z1 = sha3_224_hex(m1)[0:int(min(q.bit_length(), 224) / 4)]
s1 = (int(z1, 16) + sk1 * r1) * pow(k1, -1, q)

# (b)(2)
w = pow(s1, -1, q)
u1 = int(z1, 16) * w % q
u2 = r1 * w % q
v = (pow(g, u1, p) * pow(pk1, u2, p) % p) % q


def signUser1():
    return Sign(p, q, g, k1, sk1, m1)


def verifyUser1(signed):
    return Verify(p, q, g, pk1, m1, signed[0], signed[1])


def signAndVerify():
    signed = signUser1()
    print(verifyUser1(signed))


# (b)(3)
def buildm2():
    amt2 = BitArray(hex='03')
    leading_zeroes_pk2 = ''.zfill(l2)
    leading_zeroes_pk3 = ''.zfill(l3)
    m2 = BitArray(bin=leading_zeroes_pk2) + BitArray(bin="{0:b}".format(pk2)) + BitArray(
        bin=leading_zeroes_pk3) + BitArray(bin="{0:b}".format(pk3)) + amt2
    print(len(m2))
    return m2.hex


m2 = buildm2()
k2 = int(sha3_224_hex('02'), 16)
r2 = pow(g, k2, p) % q
z2 = sha3_224_hex(m2)[0:int(min(q.bit_length(), 224) / 4)]
s2 = (int(z2, 16) + sk2 * r2) * pow(k2, -1, q)


# (c) PreImageOfPW1=h(amt0)||m1||nonce1, PreImageOfPW2=h(m1)||m2||nonce2,
# those two variables should be hex strings with on prefix of 0x
def findNonce():
    amt0 = BitArray(hex='05')
    h_amt0 = sha3_224_hex(amt0.hex)
    leading_zeroes = ''.zfill(32)
    i = 0
    while True:
        nonce = BitArray(int=i, length=128)
        input = BitArray(hex=h_amt0) + BitArray(hex=m1) + nonce
        pw1 = sha3_224_hex(input.hex)
        i += 1
        if pw1[0:32] == leading_zeroes:
            return nonce


findNonce()

PreImageOfPW1 = ""
PreImageOfPW2 = ""


# --------------------------------------------------------------------------------

# Part 3: DSA signature and verification
# DSA signature function, p, q, g, k, sk are integers, Message are hex strings of even length.
def Sign(p, q, g, k, sk, Message):
    r = pow(g, k, p) % q
    z = sha3_224_hex(Message)[0:int(min(q.bit_length(), 224) / 4)]
    s = (int(z, 16) + sk * r) * pow(k, -1, q)
    return r, s


# DSA verification function,  p, q, g, k, pk are integers, Message are hex strings of even length.
def Verify(p, q, g, pk, Message, r, s):
    w = pow(s, -1, q)
    z = sha3_224_hex(Message)[0:int(min(q.bit_length(), 224) / 4)]
    u1 = int(z, 16) * w % q
    u2 = r * w % q
    v = (pow(g, u1, p) * pow(pk, u2, p) % p) % q
    return v == r


signAndVerify()
