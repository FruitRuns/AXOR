#!/usr/bin/env python3
from Crypto.Cipher import ChaCha20
import socketserver
import asymmetric
import threading
import random
import socket
import json

# https://docs.python.org/3/library/socketserver.html code used from here

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = str(self.request.recv(65536), 'ascii')
        # cur_thread = threading.current_thread()
        response = bytes(data, 'ascii')
        if response == b"AXOR_EXCHANGE":
            public_key, private_key, out_key = asymmetric.generate_keys()
            xor_keys_private = asymmetric.xor_layer_gen()
            public_key, out_key = asymmetric.apply_layer(public_key, out_key, xor_keys_private)
            self.request.sendall(json.dumps({"public_key": public_key, "out_key": out_key}).encode())
        else:
            return
        data = json.loads(str(self.request.recv(65536), 'ascii'))
        msg_encrypted = self.request.recv(65536)
        key_part = data["key_part"]
        out_part = data["out_part"]
        plaintext = data["plaintext"]

        for key in xor_keys_private:
            key_part_2, out_part_2 = asymmetric.remove_layer(key_part, out_part, key)
            output = asymmetric.decrypt(private_key, key_part_2, out_part_2)

            # Create a hash for output as password
            msg_nonce = msg_encrypted[:8]
            ciphertext = msg_encrypted[8:]
            cipher = ChaCha20.new(key=asymmetric.generate_sha256_hash_digest(output), nonce=msg_nonce)
            msg_decrypted = cipher.decrypt(ciphertext)

            # If anyone has a better way of doing this please put on git the hub thing
            if plaintext.replace("b'", "").replace("'", "").encode() == msg_decrypted:
                print("Symmetric key established")
                return
        else:
            print("Failure key not established")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    public_key = []
    private_key = []
    out_key = []
    xor_keys_private = []
    pass

def client(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        plaintext = b'Lorem ipsum dolor sit amet'
        sock.connect((ip, port))
        # Establish symmetric key connection code example
        sock.sendall(bytes("AXOR_EXCHANGE", 'ascii'))
        response = json.loads(str(sock.recv(65536), 'ascii'))
        key_key = response["public_key"]
        out_key = response["out_key"]

        password_number = random.randint(2 ** 255, 2 ** 256 - 1) # Generate 256-bit number
        secret = asymmetric.generate_sha256_hash_digest(password_number)
        cipher = ChaCha20.new(key=secret)
        msg = cipher.nonce + cipher.encrypt(plaintext)
        key_part, out_part = asymmetric.encrypt(password_number, key_key, out_key)
        sock.sendall(json.dumps({"key_part": key_part, "out_part": out_part,
                                 "plaintext": str(plaintext)}).encode())
        sock.sendall(msg)
        # Then you can go do all stuff in chacha20 with the symmetric key


if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "localhost", 0

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    with server:
        ip, port = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)

        client(ip, port)

        server.shutdown()
