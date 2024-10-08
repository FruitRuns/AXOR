import random

def generate_keys(): # Generates the keys
    bit_level = 63
    public_key = [random.randint(0, 2**bit_level-1) for i in range(bit_level)] # client & server have this
    private_key = [random.randint(0, 2**bit_level-1) for i in range(bit_level)] # Only server has this
    pub_priv_out = [0 for i in range(bit_level)] # client & server have this
    for pub_k in range(0, len(public_key)):
        for priv_k in range(0, len(public_key)):
            pub_priv_out[pub_k] += ((public_key[pub_k]&private_key[priv_k]).bit_count()%2)*(2**priv_k)
    return public_key, private_key, pub_priv_out

def encrypt(n, public_key, out_key):
    # Encrypt 5 for example :V
    key_part = 0
    data_part = 0
    enc_mixer = 0
    for i in range(11): # XOR'ing 11 random ones together should be options^times>2^n so in this case times is 11 and options is 63
        enc_mixer = random.randint(0, len(public_key)-1)
        key_part = key_part ^ public_key[enc_mixer]
        data_part = data_part ^ out_key[enc_mixer]
    # Alright XORing 5 in
    n = 5
    data_part = data_part ^ n # Recommend 2^bit_level limit on n but it'll still work regardless because this mathematical function don't care just won't encrypt beyond
    return key_part, data_part

def decrypt(private_key, key, data): # Server generates actual out bits for key given to decode data XOR'd in
    out = 0
    for priv_k in range(0, len(private_key)):
        out += ((key&private_key[priv_k]).bit_count()%2)*(2**priv_k)
    return data ^ out # Decrypting for the server is as simple as
# As seen in output whatever you XOR up to 2^(n) is secure but you always get a number out beyond (just not all bits are encrypted)
# this algorithm provides 2^(n-1) security

"""
It basically works because across XOR operations the output is consistent with the key but XOR's are hard to follow.
So you can flip some bits and only the special algorithm to generate the original output will work
If you XOR 2 things there's a lot of stuff you could have XOR'd together to get that result
"""
if __name__ == "__main__":
    pub_key, priv_key, out_key = generate_keys()
    key_part, data_part = encrypt(5, pub_key, out_key)
    output = decrypt(priv_key, key_part, data_part)
    print(output) # Should be 5
