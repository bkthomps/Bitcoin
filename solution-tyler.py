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
l3 = 2048-pk3.bit_length()
# (b)(1)
def buildm1():
	amt1 = BitArray(hex='04')
	leadingZeroespk1 = ''.zfill(l1)
	leadingZeroespk2 = ''.zfill(l2)
	m1 = BitArray(bin=leadingZeroespk1) + BitArray(bin="{0:b}".format(pk1)) + BitArray(bin=leadingZeroespk2) + BitArray(bin="{0:b}".format(pk2)) + amt1
	return m1.hex
m1 = buildm1()
k1 = int(sha3_224_hex('01'), 16)
r1 = pow(g, k1, p) % q
z1 = sha3_224_hex(m1)[0:(int)(min(q.bit_length(), 224)/4)]
s1 = (int(z1, 16) + sk1*r1) * pow(k1, -1, q)

# (b)(2)
w = pow(s1, -1, q)
u1 = int(z1, 16)*w % q
u2 = r1*w % q 
v = (pow(g, u1, p)*pow(pk1, u2, p) % p) % q 

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
	leadingZeroespk2 = ''.zfill(l2)
	leadingZeroespk3 = ''.zfill(l3)
	m2 = BitArray(bin=leadingZeroespk2) + BitArray(bin="{0:b}".format(pk2)) + BitArray(bin=leadingZeroespk3) + BitArray(bin="{0:b}".format(pk3)) + amt2
	return m2.hex
m2 = buildm2()
k2 = int(sha3_224_hex('02'), 16)
r2 = pow(g, k2, p) % q
z2 = sha3_224_hex(m2)[0:(int)(min(q.bit_length(), 224)/4)]
s2 = (int(z2, 16) + sk2*r2) * pow(k2, -1, q)


# (c) PreImageOfPW1=h(amt0)||m1||nonce1, PreImageOfPW1=h(m1)||m2||nonce2, those two variables should be hex strings with on prefix of 0x
def findFirstNonce():
	leadingZeroes = ''.zfill(32)
	amt0 = BitArray(hex='05')
	h_amt0 = sha3_224_hex(amt0.hex)
	print(h_amt0)
	i = 0
	while (True):
		nonce = BitArray(int = i, length = 128)
		input = BitArray(hex=h_amt0) + BitArray(hex=m1) + nonce
		pw1 = sha3_224_hex(input.hex)
		i += 1
		if (pw1[0:32] == leadingZeroes):
			return nonce

def findSecondNonce():
	leadingZeroes = ''.zfill(32)
	h_m1 = sha3_224_hex(m1)
	i = 0
	while (True): 
		nonce = BitArray(int = i, length = 128)
		input = BitArray(hex=h_m1) + BitArray(hex=m2) + nonce
		pw2 = sha3_224_hex(input.hex)
		i += 1
		if (pw2[0:32] == leadingZeroes):
			return nonce
		
#firstNonce = findFirstNonce()
#secondNonce = findSecondNonce()
PreImageOfPW1="8b6f5dc5b40559f78454716b208fa38a78974355adb22c6e34787d9c02c05e3f4f6c587b7d4a859f37a4f9a8ecddeb66c467d12497e501af41e094cb563be40fd1c3c98e6458e8d3e4699d1dd089a2b4c73723521cd2512dd19ece7ea936b2465aa672e77e5bdde5fa2955302243b296df6c7acd381ac80e0d26e64bbc50bbdc96c5ae622c9ec7ad4b15c1a44729e0dcaca5b6562e210539e1e9e139707f3ee7a8898d3ec610101155423d30c047f420907c1c24d020ede1c656e17ceb0c4a5d2c8e5543b486cf9deaaa785d1fe82815ff5443ffb4eafbb52f6ee9f21ba526ef15b53e0c4534fd59932d46bd50292f9ef88f5b51bee9464d734ef6c60029452600b155346dd0b404035c1741e29036f81f9fc4596490a68b6471c65e6c58b0b00ca2f1c3c81d5efc66c7aea5a6538f394a06f738e9c6906ea2feee3a5eadf04288925cc010ac4632a3b009e5d4a171865cbebdfa1289841f853c342f4aa337a7da6a784a067fcac337c8aac5cd572fd84578a8e1236905d941191384749621291f989561731f53507e78eac7c75649a0a490377886a4a4be8cd8832c608f0b3ab3df79249f9499ef78407a08733d1f2af2c8a92bfa182e408915dd1a40f9f3366f95724dac80b8d50549e1c677bf3103bf7ab520ea6d5c1780f21bc0b5003e850f2924ed5608197133ee8c8dec69ed02b016db9037486c9a084724ff697d2a8409064163e652be616100be320c32dd76261cbc0e2503a879fc26791704c000000000000000000000001abb4ea5"
PreImageOfPW2="efb8abd971c1aeabcac1c29cb3c6d7190ac1d7e1915d53b3601869a06c58b0b00ca2f1c3c81d5efc66c7aea5a6538f394a06f738e9c6906ea2feee3a5eadf04288925cc010ac4632a3b009e5d4a171865cbebdfa1289841f853c342f4aa337a7da6a784a067fcac337c8aac5cd572fd84578a8e1236905d941191384749621291f989561731f53507e78eac7c75649a0a490377886a4a4be8cd8832c608f0b3ab3df79249f9499ef78407a08733d1f2af2c8a92bfa182e408915dd1a40f9f3366f95724dac80b8d50549e1c677bf3103bf7ab520ea6d5c1780f21bc0b5003e850f2924ed5608197133ee8c8dec69ed02b016db9037486c9a084724ff697d2a8409064163e652be616100be320c32dd76261cbc0e2503a879fc267917639ffa7beb026c650c5f759cba310bcf300dab9b084b86a3fc871adb0d96a23c6fbdeea78639801da99667eda454730885b753fc5401d44c4e3ca489b0e252109a0fb4a4568dbd021f8136583a112bdc8e4c76a85a96541f5673e5c127aa9dcf3f86b0335eeda6bb9d2984200b1cdc94e4fd6cc94b0060ad93862f5d077cc00316e45df8fb4667dd4ca29c680159911b88e7d3dfa62dfc6a25545a8ac220e84e4784031c1e5c66894c816736f343a05a2a3f3ed8e7b1dc18d52ddf8e39120820c8ba229242cde54db91b001a6bbd1cf9bdf8fd4d4dd126703863ebaea9bddd0c0c9e225605b403306f18a11f9fae081078bf404b941df688dcdf5796baac160c03c0000000000000000000000002985515"
print(sha3_224_hex(PreImageOfPW1))
print(sha3_224_hex(PreImageOfPW2))

#--------------------------------------------------------------------------------

#Part 3: DSA signature and verification
# DSA signature function, p, q, g, k, sk are integers, Message are hex strings of even length.
def Sign( p, q, g, k, sk, Message ):
	r = pow(g, k, p) % q
	z = sha3_224_hex(Message)[0:(int)(min(q.bit_length(), 224)/4)]
	s = (int(z, 16) + sk*r) * pow(k, -1, q)
	return r,s

# DSA verification function,  p, q, g, k, pk are integers, Message are hex strings of even length.
def Verify( p, q, g, pk, Message, r, s ):
	w = pow(s, -1, q)
	z = sha3_224_hex(Message)[0:(int)(min(q.bit_length(), 224)/4)]
	u1 = int(z, 16)*w % q
	u2 = r*w % q 
	v = (pow(g, u1, p)*pow(pk, u2, p) % p) % q
	if (v == r):
		return True
	else:   
		return False
	
signAndVerify()
