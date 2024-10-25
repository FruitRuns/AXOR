#!/usr/bin/env python3
"""
By doing it this way you can basically take an identity matrix and have them XOR it without the consequence
of having to check 2^256 keys as the server, if it was done any other way it would be infeasible.
By applying my algorithm you can turn an identity matrix into noise which is linearly solvable and then apply seemingly
random XOR's ontop of it to make it unsolvable which is an epic prank, but it is still an identity matrix
just you can not actually see the matrix and, therefore, you can not solve it without lots of computations :D
The server can then easily figure out which rows were XOR together transmitting data.
"""

import random
import hashlib
from Crypto.Cipher import ChaCha20

global bit_level
bit_level = 63

def XOR_layer_gen():
    XOR_keys_pub = [random.randint(0, 2**bit_level-1) for _ in range(8)] # Kept secret by server
    # Create XOR layer combinations
    for key in XOR_keys_pub:
        for key2 in XOR_keys_pub:
            XOR_keys_pub.append(key^key2)
            XOR_keys_pub = list(set(XOR_keys_pub))
    return XOR_keys_pub

# Generates the keys
def generate_keys():
    # Only server has this
    public_key_overlay = [2**i for i in range(bit_level)]

    # client & server have this
    public_key = [random.randint(0, 2 ** bit_level - 1) for _ in range(bit_level)]

    # Only server has this
    private_key = [random.randint(0, 2 ** bit_level - 1) for _ in range(bit_level)]

    # client & server have this
    pub_priv_out = [
        sum(
            (public_key[i] & private_key[j]).bit_count() % 2 * (2 ** j)
            for j in range(bit_level)
        )
        for i in range(bit_level)
    ]

    # Potentially insecure because predictable true layer (probably safe - future me)
    for i in range(len(public_key)):
        pub_priv_out[i] = pub_priv_out[i] ^ public_key_overlay[i]

    return public_key, private_key, pub_priv_out

def encrypt(n, public_key, out_key):
    # Hardcoded in to give 5 this should not be done in real implementations
    public_key = public_key[n] ^ public_key[0]
    out_key = out_key[n] ^ out_key[0]
    return public_key, out_key

# Remove pub private layer of encryption
def decrypt(private_key, key, data):
    # Server generates actual out bits for key given to decode data XOR in
    out = sum(
        ((key & private_key[i]).bit_count() % 2) * (2 ** i)
        for i in range(len(private_key))
    )

    # Decrypting for the server is as simple as
    return data ^ out

# Only server runs this
def apply_layer(pub_key, out_key, XOR_keys_pub):
    for key_i in range(len(pub_key)):
        rand_num = random.randint(0, len(XOR_keys_pub)-1)
        pub_key[key_i] = pub_key[key_i] ^ XOR_keys_pub[rand_num]
        out_key[key_i] = out_key[key_i] ^ XOR_keys_pub[rand_num]
    return pub_key, out_key

# Only server runs this
def remove_layer(pub_key, out_key, try_me):
    pub_key = pub_key ^ try_me
    out_key = out_key ^ try_me
    return pub_key, out_key

def main():
    plaintext = b'Lorem ipsum dolor sit'
    h = hashlib.new('sha256')
    h.update(str(5).encode())
    secret = h.digest()
    cipher = ChaCha20.new(key=secret)
    msg = cipher.nonce + cipher.encrypt(plaintext)
    print(msg)
    pub_key, priv_key, out_key = generate_keys()
    XOR_keys_pub = XOR_layer_gen()
    # After random XOR layer applied key made public
    pub_key, out_key = apply_layer(pub_key, out_key, XOR_keys_pub)

    key_part, out_part = encrypt(2, pub_key, out_key)

    # Try each possible key known by server to get past random XOR layer
    for key in XOR_keys_pub:
        key_part2, out_part2 = remove_layer(key_part, out_part, key)
        output = decrypt(priv_key, key_part2, out_part2)
        print(output)
        print(bin(output))

        # Create a hash for output as password
        h = hashlib.new('sha256')
        h.update(str(output).encode())
        print(h.digest())
        msg_nonce = msg[:8]
        ciphertext = msg[8:]
        h = hashlib.new('sha256')
        h.update(str(output).encode())
        cipher = ChaCha20.new(key=h.digest(), nonce=msg_nonce)
        plaintext = cipher.decrypt(ciphertext)
        print(plaintext)
        if plaintext == b'Lorem ipsum dolor sit':
            print("Success key established")
            exit()

if __name__ == "__main__":
    main()
