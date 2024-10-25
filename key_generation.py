#!/usr/bin/env python3
"""
This version of the algorithm has been found vulnerable to RREF and can be
solved in polynomial time please do not use this version.
Please use the versions where a XOR layer is applied. 
"""

import random


# Generates the keys
def generate_keys():
    bit_level = 63

    # client & server have this
    public_key = [random.randint(0, 2**bit_level - 1) for _ in range(bit_level)]

    # Only server has this
    private_key = [random.randint(0, 2**bit_level - 1) for _ in range(bit_level)]

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

    # XOR'ing 11 random ones together should be options^times>2^n
    # so in this case times is 11 and options is 63
    for _ in range(11):
        enc_mixer = random.randint(0, len(public_key) - 1)
        key_part ^= public_key[enc_mixer]
        data_part ^= out_key[enc_mixer]

    # Recommend 2^bit_level limit on n, it'll still work regardless tho
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


def main():
    pub_key, priv_key, out_key = generate_keys()
    key_part, data_part = encrypt(5, pub_key, out_key)
    output = decrypt(priv_key, key_part, data_part)
    print(output)  # Should be 5


if __name__ == "__main__":
    main()
