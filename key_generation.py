import random

def generate_keys():
    bit_level = 63
    public_key = [random.randint(0, 2**bit_level-1) for i in range(bit_level)] # client & server have this
    private_key = [random.randint(0, 2**bit_level-1) for i in range(bit_level)] # Only server has this
    pub_priv_out = [0 for i in range(bit_level)] # client & server have this
    for pub_k in range(0, len(public_key)):
        for priv_k in range(0, len(public_key)):
            pub_priv_out[pub_k] += ((public_key[pub_k]&private_key[priv_k]).bit_count()%2)*(2**priv_k)
    return pub_key, priv_key, out_key

def encrypt(n, public_key, out_key):
    # Encrypt 5 for example :V
    pub_key = 0
    pub_priv_key = 0
    mixer = 0
    for i in range(11): # XOR'ing 11 random ones together should be options^times>2^n so in this case times is 11 and options is 63
        mixer = random.randint(0, len(public_key)-1)
        pub_key = pub_key ^ public_key[mixer]
        pub_priv_key = pub_priv_key ^ out_key[mixer]
    # Alright XORing 5 in
    n = 5
    pub_priv_key = pub_priv_key ^ n # Recommend 2^bit_level limit on n but it'll still work regardless because this mathematical function don't care just won't encrypt beyond
    return pub_priv_key

def decrypt(public_key, private_key, n):
    # Server generates actual out bits for key given to decode data XOR'd in
    out = 0
    for priv_k in range(0, len(public_key)):
        out += ((pub_key&private_key[priv_k]).bit_count()%2)*(2**priv_k)
        
    # Decrypting for the server is as simple as
    return pub_priv_key ^ out
# As seen in output whatever you XOR up to 2^(n) is secure but you always get a number out beyond (just not all bits are encrypted)
# this algorithm provides 2^(n-1) security

"""
It basically works because across XOR operations the output is consistent with the key but XOR's are hard to follow.
So you can flip some bits and only the special algorithm to generate the original output will work
If you XOR 2 things there's a lot of stuff you could have XOR'd together to get that result
"""
if __name__ == "__main__":
    pub_key, priv_key, out_key = generate_keys()
    encrypted_data = encrypt(5, pub_key, out_key)
    output = decrypt(pub_key, out_key, encrypted_data)
    print(output) # Should be 5
