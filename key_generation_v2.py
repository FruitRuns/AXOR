#!/usr/bin/env python3
"""
By doing it this way you can basically take an identity matrix and have them XOR it without the consequence
of having to check 2^256 keys as the server, if it was done any other way it would be infeasible.
By applying my algorithm you can turn an identity matrix into noise which is linearly solvable and then apply seemingly
random XOR's ontop of it to make it unsolvable which is an epic prank, but it is still an identity matrix
just you can not actually see the matrix and, therefore, you can not solve it without lots of computations :D
The server can then easily figure out which rows were XOR together transmitting data.

To help understand this program think of key_key as the public key and out_out as the public key
where key_key is the key and out_out is the value in a hashset
"""

import random
import hashlib
from Crypto.Cipher import ChaCha20

global bit_level
bit_level = 256

def xor_layer_gen() -> list[int]:
    """
    Under no circumstances use a range of 1 as this is vulnerable to XOR cross out attacks
    With 2 there is no way of knowing for sure if you have a cancelled out part and therefore no way of making a matrix
    which is solvable without the same amount of computations if not more as a brute force attack

    have fun guessing the xor number lol
    """
    xor_keys_private = [random.randint(0, 2 ** bit_level - 1) for _ in range(1)] # Kept secret by server
    # Create XOR layer combinations
    for key in xor_keys_private:
        for key2 in xor_keys_private:
            xor_keys_private.append(key^key2)
            # Remove duplicates
            xor_keys_private = list(set(xor_keys_private))
    return xor_keys_private

# Generates the keys
def generate_keys() -> tuple[list[int], list[int], list[int]]:
    # Only server has this
    identity_matrix = [2 ** i for i in range(bit_level)]

    # client & server have this
    key_key = [random.randint(0, 2 ** bit_level - 1) for _ in range(bit_level)]

    # Only server has this
    private_key = [random.randint(0, 2 ** bit_level - 1) for _ in range(bit_level)]

    # client & server have this
    out_key = [
        sum(
            (((key_key[i] & private_key[j]).bit_count()) % 2) * (2 ** j)
            for j in range(bit_level)
        )
        for i in range(bit_level)
    ]

    # Potentially insecure because predictable true layer (probably safe - future me)
    for i in range(len(key_key)):
        out_key[i] = out_key[i] ^ identity_matrix[i]

    return key_key, private_key, out_key

def encrypt(n, key_key, out_key) -> tuple[int, int]:
    # Encrypts n
    key_part, out_part = 0, 0
    n = list(bin(n).replace("0b", ""))
    n.reverse()
    for i in range(len(n)):
        if n[i] == "1":
            key_part = key_part ^ key_key[i]
            out_part = out_part ^ out_key[i]
    return key_part, out_part

# Remove pub private layer of encryption
def decrypt(private_key, key_part_2, out_part_2) -> int:
    # Server generates actual out bits for key given to decode data XOR in
    out = sum(
        (((key_part_2 & private_key[i]).bit_count()) % 2) * (2 ** i)
        for i in range(len(private_key))
    )

    # Decrypting for the server is as simple as
    return out_part_2 ^ out

# Only server runs this
def apply_layer(key_key, out_key, xor_keys_pub) -> tuple[int, int]:
    for key_i in range(len(key_key)):
        rand_num = random.randint(0, len(xor_keys_pub) - 1)
        key_key[key_i] = key_key[key_i] ^ xor_keys_pub[rand_num]
        out_key[key_i] = out_key[key_i] ^ xor_keys_pub[rand_num]
    return key_key, out_key

# Only server runs this
def remove_layer(key_part, out_part, key) -> tuple[int, int]:
    key_part = key_part ^ key
    out_part = out_part ^ key
    return key_part, out_part

# Both run this
def generate_sha256_hash_digest(password_number) -> bytes:
    h = hashlib.new('sha256')
    h.update(str(password_number).encode())
    secret = h.digest()
    return secret

# Strictly used to test the library
# Use as reference for building network server and client
def main():
    plaintext = b'Lorem ipsum dolor sit amet'
    # sha256 is used to generate 32 byte password for chacha
    password_number = random.randint(0, 2**bit_level-1)
    secret = generate_sha256_hash_digest(password_number)
    cipher = ChaCha20.new(key=secret)
    msg_encrypted = cipher.nonce + cipher.encrypt(plaintext)
    print(msg_encrypted)
    key_key, private_key, out_key = generate_keys()
    xor_keys_private = xor_layer_gen()
    # After random XOR layer applied key made public
    key_key, out_key = apply_layer(key_key, out_key, xor_keys_private)
    key_part, out_part = encrypt(password_number, key_key, out_key)

    # Try each possible key known by server to get past random XOR layer
    # The layer is applied to stop anyone other than the server reconstructing the original matrix (not identity matrix)
    for key in xor_keys_private:
        key_part_2, out_part_2 = remove_layer(key_part, out_part, key)
        output = decrypt(private_key, key_part_2, out_part_2)
        print(output)
        print(bin(output))

        # Create a hash for output as password
        msg_nonce = msg_encrypted[:8]
        ciphertext = msg_encrypted[8:]
        cipher = ChaCha20.new(key=generate_sha256_hash_digest(output), nonce=msg_nonce)
        plaintext = cipher.decrypt(ciphertext)
        print(plaintext)
        if plaintext == b'Lorem ipsum dolor sit amet':
            print("Success key established")
            exit()
    else:
        print("Failure key not established")

if __name__ == "__main__":
    main()
