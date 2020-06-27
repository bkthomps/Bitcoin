"""
ECE 458 Project 1
Skeleton solution file.

You need to assign values to variables, and implement two functions as part of your answers to this project
You are not allowed to call any DSA signature package.
You are allowed to define whatever subroutines you like to structure your code.
"""

import hashlib
import binascii

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
# p,q,g are DSA domain parameters, sk_i (secret keys),pk_i (public keys),k_i (random numbers) are used in each signature and verification
p =
q =
g =

sk1 =
sk2 =
sk3 =

# --------------------------------------------------------------------------------

# Part 2:Assign values that you compute to those parameters as part of your answers to (a) (b) and (c)
# (a) list all prime factors of p-1, list 3 public keys pk_i's corresponding to sk_i's, those numbers should be decimal integers
pfactor1 =
pfacotr2 =
pfactor3 =

pk1 =
pk2 =
pk3 =

# (b) Sig_sk1 and Sig_sk2, k_i is the random number used in signature.
# u, v, w is the intermediate results when verifying Sig_sk1(m1)
# All variables should be decimal integers

# (b)(1)
k1 =
r1 =
s1 =

# (b)(2)
w =
u1 =
u2 =
v =

# (b)(3)
k2 =
r2 =
s2 =

# (c) PreImageOfPW1=h(amt0)||m1||nonce1, PreImageOfPW1=h(m1)||m2||nonce2, those two variables should be hex strings with on prefix of 0x
PreImageOfPW1 = ""
PreImageOfPW2 = ""


# --------------------------------------------------------------------------------

# Part 3: DSA signature and verification
# DSA signature function, p, q, g, k, sk are integers, Message are hex strings of even length.
def Sign(p, q, g, k, sk, Message):
    return r, s


# DSA verification function,  p, q, g, k, pk are integers, Message are hex strings of even length.
def Verify(p, q, g, pk, Message, r, s):
    if:
        return True
    else:
        return False
