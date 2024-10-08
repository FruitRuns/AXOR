import random

bit_level = 8
public_key = [random.randint(0, 2**bit_level+1) for i in range(bit_level)] # client & server have this
private_key = [random.randint(0, 2**bit_level+1) for i in range(bit_level)] # Only server has this
pub_priv_out = [0 for i in range(bit_level)] # client & server have this
for pub_k in range(0, len(public_key)):
    for priv_k in range(0, len(public_key)):
        pub_priv_out[pub_k] += ((public_key[pub_k]&private_key[priv_k]).bit_count()%2)*(2**priv_k)

print(public_key, private_key, pub_priv_out)

# Encrypt 5 for example :V
pub_key = 0
pub_priv_key = 0
mixer = 0
for i in range(4): # XOR'ing 4 random ones together really should be options^times>2^n so in this case times is 4 and options is 8
    mixer = random.randint(0, len(public_key)-1)
    pub_key = pub_key ^ public_key[mixer]
    pub_priv_key = pub_priv_key ^ pub_priv_out[mixer]
# Alright XORing 5 in
n = 5
pub_priv_key = pub_priv_key ^ n # Recommend 2^bit_level limit on n but it'll still work regardless because this mathematical function don't care

print(pub_key, pub_priv_key)

# Server generates actual out bits for key given to decode data XOR'd in
out = 0
for priv_k in range(0, len(public_key)):
    out += ((pub_key&private_key[priv_k]).bit_count()%2)*(2**priv_k)
print(out)

# Decrypting for the server is as simple as
print(pub_priv_key ^ out)

if (pub_priv_key ^ out) == n:
    print("Yep algorithm working!") # basic test to say it's working :w
# As seen in output whatever you XOR up to 2^(n) is secure but you always get a number out beyond (just not all bits are securely encrypted
# this algorithm provides 2^(n-1) security

"""
It basically works because across XOR operations the output is consistent with the key but XOR's are hard to follow.
So you can flip some bits and only the special algorithm to generate the original output will work
If you XOR 2 things there's a lot of stuff you could have XOR'd together to get that result
"""

