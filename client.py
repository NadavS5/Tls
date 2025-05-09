__author__ = "Nadav Salem"

#Tls 1.2 client implementation

#This Client Uses cipher: ECDHE-RSA-AES128-GCM-SHA256

#elyptic curve diffie helman aes-gcm

#And Signature Algorithem: RSA_PSS_RSAE_SHA246



#client command: openssl s_client -connect www.google.com:443 -crlf -cipher 'ECDHE-RSA-AES128-GCM-SHA256' -sigalgs rsa_pss_rsae_sha256 -tls1_2
#openssl s_client -connect www.google.com:443 -crlf -tls1_2
#follwing this page: https://tls13.xargs.org/#client-hello/annotated

from socket import socket
from os import urandom
from Crypto.Cipher import AES
from Crypto.Protocol import DH
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA384
from handshakeuitls import build_extentions


from constants import ECDHE_RSA_AES256_GCM_SHA256

class tls_connection:


    client_random: bytes
    client_pre_master: bytes
    server_random: bytes


    def __init__(self, address: str, port:int, sock = None):
        self.address = address
        self.port = port
        self.sock = sock

        if not sock:
            self.sock = socket()

    def _send_client_hello(self):
        self.client_random = urandom(32)

        
        #version
        handshake_message = b"\x03\x03"

        #client random
        handshake_message += self.client_random

        #length 32 + session id
        handshake_message += b"\x20" + urandom(32)

        #length 2 + our cipher suit defined at top
        handshake_message += b"\x00\x02" + ECDHE_RSA_AES256_GCM_SHA256

        #length 1: compression type = null
        handshake_message += b"\x01" + b"\x00"

       
        extentions_full = build_extentions(self.address)
        handshake_message += len(extentions_full).to_bytes(2) + extentions_full
        
        #type: client hello
        handshake_header = b"\x01" + len(handshake_message).to_bytes(3)
        handshake_msg_full = handshake_header + handshake_message

    
        
        print(f"length: {len(handshake_msg_full)}")

        #Handshake, protocol version, handshake message length
        self.sock.send(b"\x16\x03\x03" + len(handshake_msg_full).to_bytes(2) + handshake_msg_full)

    def _recv_server_hello(self):
        with open("sh.bin", "wb") as f:
            f.write(self.sock.recv(1024))
    def _recv_server_certificate(self):
        with open("sh.bin", "wb") as f:
            f.write(self.sock.recv(4096 * 2))
    def connect(self):
        
        
        self.sock.connect((self.address, self.port))
        self._send_client_hello()
        self._recv_server_hello()
        self._recv_server_certificate()


    
if __name__ == "__main__" :
    conn = tls_connection("www.google.com", 443)
    conn.connect()