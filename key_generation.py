#!/usr/bin/env python3
"""
Issue 1
This version of the algorithm has been found vulnerable to RREF and can be
solved in polynomial time please do not use this version.
Please use the versions where an XOR layer is applied.
Can be solved in at least O(n^3)
"""

"""
A patch for Issue 1 has been found
This algorithm is at least O(2^N) to bruteforce where N is the bit_level
It has been found there is no possible way to accelerate an attack on this algorithm classically
For proof of this take A, B, C, and X where X is XOR.

(A & B) % 2        # Without XOR encrypt and decrypt
(A & B) % 2 X C    # With XOR encrypt and decrypt
As you can see there is no possible way to accelerate the encrypting or decrypting steps from the 2 options shown

Now looking at the user encrypting stage
with A, B, C, D as say the chosen rows and P is users data and E is the data part of the rows, F not data part

A X B X D X P         # User encrypted message 

As you can see there is no possible way to accelerate cracking this other than brute force and checking each outcome
until a match is found on the not data part from which you can find P as you found the rows of A B D which 
matches with F to give the original E to give P.

Now all parts of the process have be shown it should be trivial to conclude that there is no better method than brute
force to solve the encryption.

Unfortunately it is only possible to encrypt and decrypt messages via this algorithm
"""

import secrets
global bit_level
bit_level = 64

# Generates the keys
def generate_keys():
    # client & server have this
    public_key = [secrets.randbits(bit_level) for _ in range(bit_level)]

    # Only server has this
    private_key = [secrets.randbits(bit_level) for _ in range(bit_level)]

    # client & server have this
    pub_priv_out = [
        sum(
            (public_key[i] & private_key[j]).bit_count() % 2 * (2**j)
            for j in range(bit_level)
        )
        for i in range(bit_level)
    ]

    return public_key, private_key, pub_priv_out


def encrypt(n, public_key, out_key):
    key_part, data_part = 0, 0

    # 16 is pretty arbitrary choice
    for _ in range(16):
        enc_mixer = secrets.randbits(6) # 63 is 6 bits but 64 choices including 0
        key_part ^= public_key[enc_mixer]
        data_part ^= out_key[enc_mixer]

    data_part ^= n

    return key_part, data_part


def decrypt(private_key, key, data):
    # Server generates actual out bits for key given to decode data XOR'd in
    out = sum(
        ((key & private_key[i]).bit_count() % 2) * (2**i)
        for i in range(len(private_key))
    )

    # Decrypting for the server is as simple as
    return data ^ out

# Cry about it
def make_np_hard(out_key, xor_key):
    for i in range(len(out_key)):
        if secrets.randbits(1): # Either 0 or 1
            out_key[i] ^= xor_key
    return out_key

def main():
    pub_key, priv_key, out_key = generate_keys() # everyone has pub_key, run by server
    xor_key = secrets.randbits(bit_level) # Only server has this, run by server
    out_key = make_np_hard(out_key, xor_key) # Everyone has this outputted out_key, run by server
    key_part, data_part = encrypt(5, pub_key, out_key) # 5 is data inputted
    output = decrypt(priv_key, key_part, data_part)
    if output != 5:
        print(output^xor_key)  # Should be 5
    else:
        print(output)  # Should be 5



if __name__ == "__main__":
    main()
