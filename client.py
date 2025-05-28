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
from Crypto.Hash import SHA384, SHA256
from Crypto.Util.asn1 import DerBitString, DerSequence #for certs
from asn1crypto.x509 import Certificate
from pprint import  pprint

from handshakeutils import build_extensions, verify_signature
from constants import ECDHE_RSA_AES256_GCM_SHA256

class tls_connection:


    client_random: bytes
    client_pre_master: bytes
    server_random: bytes

    
    server_certs: list[Certificate]


    def __init__(self, address: str, port:int, sock = None):
        self.address = address
        self.port = port
        self.sock = sock

        if not sock:
            self.sock = socket()

    def _recv_by_size(self, size):
        buff = b""
        while(size > 0):
            recv = self.sock.recv(size)
            if recv == b"":
                return b""
            size-= len(recv)
            buff += recv
        return buff

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

       
        extensions_full = build_extensions(self.address)
        handshake_message += len(extensions_full).to_bytes(2) + extensions_full
        
        #type: client_hello
        handshake_header = b"\x01" + len(handshake_message).to_bytes(3)
        handshake_msg_full = handshake_header + handshake_message

    
        
        print(f"length: {len(handshake_msg_full)}")

        #Handshake, protocol version, handshake message length
        self.sock.send(b"\x16\x03\x03" + len(handshake_msg_full).to_bytes(2) + handshake_msg_full)


    def _recv_server_hello(self):
        data = self._recv_by_size(5)
        assert data[0] == 22, "received message isnt handshake"
        assert data[1:3] == b"\x03\x03", "received tls packet isnt TLS1.2"
        
        server_hello_length = int.from_bytes(data[3:5])
        server_hello = self._recv_by_size(server_hello_length)

    @staticmethod
    def __get_certs(data: bytes) ->list[bytes]:
        """this is a helper function for _recv_certs that returns the certs from Certification packet Certifications field"""
        #structred like this (length : 3 bytes, cert: length bytes)
        current = 0
        cnt = 0
        certs = []

        while True and cnt < 5:
            cnt +=1
            length = int.from_bytes(data[current : current + 3])
            current +=3
            certs.append(data[current : current + length])
            current += length
            print(current, len(data))
            if current == len(data):
                break

        return certs


    def _recv_certs(self):
        """
        this function receives and processes the Certificate packets
        """
        data = self._recv_by_size(6)
        assert data[0] == 22, "received message isnt handshake"
        assert data[1:3] == b"\x03\x03", "received tls packet isnt TLS1.2"
        tls_packet_length = int.from_bytes(data[3:5])
        print("tls packet length: ", tls_packet_length)
        handshake_type = data[5]
        assert handshake_type == 11, "received packet isnt a Certification handshake type "

        message_length = int.from_bytes(self._recv_by_size(3))
        print("message length: ", message_length)

        certs_length = int.from_bytes(self._recv_by_size(3))
        print("certs length: ",certs_length)

        certs_data = self._recv_by_size(certs_length)
        byte_certs = self.__get_certs(certs_data)
        certs = [Certificate.load(cert) for cert in byte_certs]

        self.server_certs = certs

        algorithm = certs[0].native['signature_algorithm']['algorithm']
        issuer = certs[0].native['tbs_certificate']['issuer']['common_name']
        signature = certs[0].native['signature_value']
        cert_hash = SHA256.new( certs[0]['tbs_certificate'].dump() )


        if not verify_signature(signature,cert_hash,issuer ):
            raise  Exception("certificate verification failed")

        pkey_ = certs[0].native['tbs_certificate']['subject_public_key_info']['public_key']
        pkey = RSA.construct((pkey_['modulus'], pkey_['public_exponent']))




    def _recv_key_exchange(self):
        data = self._recv_by_size(5)
        assert data[0] == 22, "received message isnt handshake"
        assert data[1:3] == b"\x03\x03", "received tls packet isnt TLS1.2"

        message_length = int.from_bytes(data[3:5])
        assert message_length > 4, "empty packet"
        message = self._recv_by_size(message_length)
        assert message[:4] == b"\x0c\x00\x01\x28", "packet isn't key exchange"
        assert message[4:7] == b"\x03\x00\x1d"
        print("using curve x25519")

        pkey_length = message[7]
        print("public key length:", message[7])
        pkey = message[8:8+pkey_length]

        sig_index = 8+ pkey_length
        print(message[sig_index: sig_index + 4])

        
    def connect(self):

        self.sock.connect((self.address, self.port))
        self._send_client_hello()
        self._recv_server_hello()
        self._recv_certs()
        self._recv_key_exchange()

    
if __name__ == "__main__" :
    conn = tls_connection("www.google.com", 443)
    conn.connect()