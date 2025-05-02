__author__ = "Nadav Salem"

#Tls 1.3 client implementation

#This Client Uses cipher: ECDHE-RSA-AES128-GCM-SHA256

#elyptic curve diffie helman aes-gcm

#And Signature Algorithem: RSA_PSS_RSAE_SHA246



#client command: openssl s_client -connect www.google.com:443 -crlf -cipher 'ECDHE-RSA-AES128-GCM-SHA256' --sigalgs -tls1_2
#openssl s_client -connect www.google.com:443 -crlf -tls1_2
#follwing this page: https://tls13.xargs.org/#client-hello/annotated

from socket import socket
from os import urandom
from Crypto.Cipher import AES
from Crypto.Protocol import DH
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA384


RSA_PSS_RSAE_SHA246 = b"\x08\x04"
ECDHE_RSA_AES256_GCM_SHA256 = b"\xC0\x30"
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

        #Handshake, protocol version, handshake message length
        
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

        extentions = b""

        #type: hostname, host_length, host

        server_name_list = b"\x00" + len(self.address).to_bytes(2) + self.address.encode()

        server_name_extention = len(server_name_list).to_bytes(2) + server_name_list
        #extention: server_name
        extentions += b"\x00\x00" + len(server_name_extention).to_bytes(2) + server_name_extention


        handshake_message += len(extentions).to_bytes(2) + extentions
        

        handshake_header = b"\x01" + len(handshake_message).to_bytes(3)
        handshake_msg_full = handshake_header + handshake_message

    
        
        print(f"length: {len(handshake_msg_full)}")
        #type: client hello
        self.sock.send(b"\x16\x03\x03" + len(handshake_msg_full).to_bytes(2) + handshake_msg_full)

    def connect(self):
        
        
        self.sock.connect((self.address, self.port))
        self._send_client_hello()
        
    


    
if __name__ == "__main__" :
    conn = tls_connection("www.google.com", 443)
    conn.connect()