"""
ECE 458 Project 1
Skeleton solution file.

You need to assign values to variables, and implement two functions as part of your answers to this project
You are not allowed to call any DSA signature package.
You are allowed to define whatever subroutines you like to structure your code.
"""

import hashlib
import binascii
from bitstring import BitArray
"""
sha3_224_hex() is design to take a hexadecimal string as the input and compute it's sha3_224 hash value. 
You may call sha3_224_hex() in your project for both DSA signature and sha3_224 hash computation
Don't directly call hashlib.sha3_224() which only takes a character string (then encode the string to utf-8 format) as the input.
No prefix for the input string, and len(hexstr) is even
e.g.  sha3_224_hex("4c")
"""

def sha3_224_hex( hexstr ):
	if len(hexstr)%2 != 0:
		raise ValueError("Error: Length of hex string should be even")
	m = hashlib.sha3_224()
	data = binascii.a2b_hex(str(hexstr))
	m.update(data)
	return m.hexdigest()
#--------------------------------------------------------------------------------

# Part 1:Copy and paste your parameters here
# p,q,g are DSA domain parameters, sk_i (secret keys),pk_i (public keys),k_i (random numbers) are used in each signature and verification
p=16158504202402426253991131950366800551482053399193655122805051657629706040252641329369229425927219006956473742476903978788728372679662561267749592756478584653187379668070077471640233053267867940899762269855538496229272646267260199331950754561826958115323964167572312112683234368745583189888499363692808195228055638616335542328241242316003188491076953028978519064222347878724668323621195651283341378845128401263313070932229612943555693076384094095923209888318983438374236756194589851339672873194326246553955090805398391550192769994438594243178242766618883803256121122147083299821412091095166213991439958926015606973543
q=13479974306915323548855049186344013292925286365246579443817723220231
g=9891663101749060596110525648800442312262047621700008710332290803354419734415239400374092972505760368555033978883727090878798786527869106102125568674515087767296064898813563305491697474743999164538645162593480340614583420272697669459439956057957775664653137969485217890077966731174553543597150973233536157598924038645446910353512441488171918287556367865699357854285249284142568915079933750257270947667792192723621634761458070065748588907955333315440434095504696037685941392628366404344728480845324408489345349308782555446303365930909965625721154544418491662738796491732039598162639642305389549083822675597763407558360

sk1=1638345978401353846116851778793259999694758574009723081524404059640
sk2=6855919804924557662940846677308739353667767373649805543974715032585
sk3=3981072895061189216378689145209367545855888478627878596112717817544


#--------------------------------------------------------------------------------

# Part 2:Assign values that you compute to those parameters as part of your answers to (a) (b) and (c)
# (a) list all prime factors of p-1, list 3 public keys pk_i's corresponding to sk_i's, those numbers should be decimal integers
pfactor1=2
pfactor2=q
pfactor3=599352188457547639693740171522680835865322184075286620256386716439921029334782998562008313995103840817116953210359643511447372101221464995653177706653918911634015555633001801773590292023083604552613918655194669929368962688659673544061885990566694774938089095597940505443430714573194211134223784784744939911387314440899638056016474270609853063142638329500429039904897328933858412897374253962878313102199163400319655392723027703101354927814377851954345336880097584669598515815463134218486896858352351187255794957262790967727451704317515673833695348341

pk1=pow(g, sk1, p)
pk2=pow(g, sk2, p)
pk3=pow(g, sk3, p)

# (b) Sig_sk1 and Sig_sk2, k_i is the random number used in signature. 
# u, v, w is the intermediate results when verifying Sig_sk1(m1)
# All variables should be decimal integers
l1 = 2048-pk1.bit_length()
l2 = 2048-pk2.bit_length()
# (b)(1)
def buildm1():
	amt1 = BitArray(hex='04')
	leadingZeroespk1 = ''.zfill(l1)
	leadingZeroespk2 = ''.zfill(l2)
	m1 = BitArray(bin=leadingZeroespk1) + BitArray(bin="{0:b}".format(pk1)) + BitArray(bin=leadingZeroespk2) + BitArray(bin="{0:b}".format(pk2)) + amt1
	print(len(m1))
	return m1.hex
m1 = buildm1()
k1 = int(sha3_224_hex('01'), 16)
r1 = pow(g, k1, p) % q

z = sha3_224_hex(m1)[0:(int)(min(q.bit_length(), 224)/4)]
	
s1 = (int(z, 16) + sk1*r1) * pow(k1, -1, 11)
 
# (b)(2)
# u=
# v=
# w=
#  
# # (b)(3)
# k2=
# r2=
# s2=


# (c) PreImageOfPW1=h(amt0)||m1||nonce1, PreImageOfPW1=h(m1)||m2||nonce2, those two variables should be hex strings with on prefix of 0x
PreImageOfPW1=""
PreImageOfPW2=""

#--------------------------------------------------------------------------------

#Part 3: DSA signature and verification
# DSA signature function, p, q, g, k, sk are integers, Message are hex strings of even length.
def Sign( p, q, g, k, sk, Message ):


	return r,s

# DSA verification function,  p, q, g, k, pk are integers, Message are hex strings of even length.
def Verify( p, q, g, pk, Message, r, s ):



	if ():
		return True
	else:   
		return False