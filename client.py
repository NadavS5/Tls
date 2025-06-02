__author__ = "Nadav Salem"

#Tls 1.2 client implementation

#This Client Uses cipher: ECDHE-RSA-AES256-GCM-SHA384

#elyptic curve diffie helman aes-gcm

#And Signature Algorithem: RSA_PSS_RSAE_SHA246



#client command: openssl s_client -connect www.google.com:443 -crlf -cipher 'ECDHE-RSA-AES256-GCM-SHA384' -sigalgs rsa_pss_rsae_sha256 -tls1_2
#openssl s_client -connect www.google.com:443 -crlf -tls1_2
#follwing this page: https://tls13.xargs.org/#client-hello/annotated

from socket import socket
from os import urandom
from Crypto.Signature import pss 
from Crypto.Cipher import AES, _mode_gcm
from Crypto.Protocol import DH
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA384, SHA256
from Crypto.Util.asn1 import DerBitString, DerSequence #for certs
from asn1crypto.x509 import Certificate
from pprint import  pprint
import x25519
from Crypto.Protocol.KDF import PBKDF2
from handshakeutils import build_extensions, verify_signature, verify_key_exch_signature, calc_symetric_key, calc_verify_data
from constants import ECDHE_RSA_AES256_GCM_SHA384, RSA_PSS_RSAE_SHA256

class tls_connection:

    message_history: bytes

    client_random: bytes
    client_pre_master: bytes
    server_random: bytes
    server_certs: list[Certificate]
    server_pkey: RSA.RsaKey
    
    
    server_pkey: RSA.RsaKey
    server_ec_public: ECC.EccKey
    client_ec_private: ECC.EccKey
    client_ec_public: ECC.EccKey

    master_secret: bytes
    server_write_key: bytes
    client_write_key: bytes
    server_implicit_iv: bytes
    client_implicit_iv: bytes

    explicit_iv: bytes # counter, when sending bytes this will be converted into 8 bytes 

    client_seq: int
    server_seq: int

    def __init__(self, address: str, port:int, sock = None):
        self.address = address
        self.port = port
        self.sock = sock
        self.message_history = bytes()
        self.explicit_iv = bytes(8)
        self.client_seq = 0
        self.server_seq = 0
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
        # handshake_message += b"\x20" + urandom(32)
        handshake_message += b"\x00"

        #length 2 + our cipher suit defined at top
        handshake_message += b"\x00\x02" + ECDHE_RSA_AES256_GCM_SHA384

        #length 1: compression type = null
        handshake_message += b"\x01" + b"\x00"

       
        extensions_full = build_extensions(self.address)
        handshake_message += len(extensions_full).to_bytes(2) + extensions_full
        
        #type: client_hello
        handshake_header = b"\x01" + len(handshake_message).to_bytes(3)
        handshake_msg_full = handshake_header + handshake_message

    
        
        # print(f"length: {len(handshake_msg_full)}")

        #Handshake, protocol version, handshake message length
        self.sock.send(b"\x16\x03\x03" + len(handshake_msg_full).to_bytes(2) + handshake_msg_full)

        self.message_history += (handshake_msg_full)


    def _recv_server_hello(self):
        data = self._recv_by_size(5)
        assert data[0] == 22, "received message isnt handshake"
        assert data[1:3] == b"\x03\x03", "received tls packet isnt TLS1.2"
        
        server_hello_length = int.from_bytes(data[3:5])
        server_hello = self._recv_by_size(server_hello_length)

        assert server_hello[0] == 2, "this packet isn't server hello"

        server_random = server_hello[6: 6 + 32]
        self.server_random = server_random

        self.message_history += (server_hello)
        

    @staticmethod
    def __get_certs(data: bytes) ->list[bytes]:
        """this is a helper function for _recv_certs that returns the certs from Certification packet Certifications field"""
        #structred like this (length : 3 bytes, cert: length bytes)
        current = 0
        cnt = 0
        certs = []

        while current < len(data):
            cnt +=1
            length = int.from_bytes(data[current : current + 3])
            current +=3
            certs.append(data[current : current + length])
            current += length
            print(current, len(data))

        return certs


    def _recv_certs(self):
        """
        this function receives and processes the Certificate packets
        """
        data = self._recv_by_size(5)
        assert data[0] == 22, "received message isnt handshake"
        assert data[1:3] == b"\x03\x03", "received tls packet isnt TLS1.2"
        tls_packet_length = int.from_bytes(data[3:5])
        # print("tls packet length: ", tls_packet_length)

        message = self._recv_by_size(tls_packet_length)

        handshake_type = message[0]

        assert handshake_type == 11, "received packet isnt a Certification handshake type "

        message_length = int.from_bytes(message[2:5])
        # print("message length: ", message_length)

        certs_length = int.from_bytes(message[4:7])
        # print("certs length: ",certs_length)

        # certs_data = self._recv_by_size(certs_length)
        byte_certs = self.__get_certs(message[7:])
        certs = [Certificate.load(cert) for cert in byte_certs]

        self.server_certs = certs

        algorithm = certs[0].native['signature_algorithm']['algorithm']
        issuer = certs[0].native['tbs_certificate']['issuer']['common_name']
        signature = certs[0].native['signature_value']
        cert_hash = SHA256.new( certs[0]['tbs_certificate'].dump() )


        if not verify_signature(signature,cert_hash,issuer ):
            raise Exception("certificate verification failed")

        pkey_ = certs[0].native['tbs_certificate']['subject_public_key_info']['public_key']
        pkey = RSA.construct((pkey_['modulus'], pkey_['public_exponent']))
        self.server_pkey = pkey

        self.message_history += (message)


    def _recv_key_exchange(self):
        data = self._recv_by_size(5)
        assert data[0] == 22, "received message isnt handshake"
        assert data[1:3] == b"\x03\x03", "received tls packet isnt TLS1.2"

        message_length = int.from_bytes(data[3:5])
        assert message_length > 4, "empty packet"

        message = self._recv_by_size(message_length)
        assert message[:4] == b"\x0c\x00\x01\x28", "packet isn't key exchange"

        curve_info = message[4:7]
        assert curve_info == b"\x03\x00\x1d", "unsupported curve type"
        print("using curve x25519")

        pkey_length = message[7]
        print("public key length:", message[7])
        pkey = message[8:8+pkey_length]

        self.server_ec_public = DH.import_x25519_public_key(pkey)


        sig_index = 8+ pkey_length
        assert message[sig_index: sig_index + 2] == RSA_PSS_RSAE_SHA256, f"signature algorithm isnt {RSA_PSS_RSAE_SHA256}"
        
        sig_length = int.from_bytes(message[sig_index + 2: sig_index+4])
        
        signature = message[sig_index + 4: 4 + sig_index + sig_length]
        # print(len(signature))

        # https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3 for the hash input
        # https://www.rfc-editor.org/rfc/rfc4492.html#section-5.4 for the ECDHE_RSA extention in the hash input
        if not verify_key_exch_signature(self.server_pkey, signature, SHA256.new(self.client_random + self.server_random +curve_info+b"\x20"+ pkey)):
            raise Exception("key exchange verification failed")

        self.message_history += (message)

        #recieve server hello done
        data = self._recv_by_size(5)
        header = self._recv_by_size(int.from_bytes(data[3:5]))
        assert header == b"\x0e\x00\x00\x00"

        self.message_history += (header)
        
    

    def __generate_keys(self):
        # key = ECC.generate(curve = "curve25519")
        raw_key = bytearray(urandom(32))
        # raw_key = bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        # raw_key[0] &= 248
        # raw_key[31] &= 127
        # raw_key[31] |= 64
        key = DH.import_x25519_private_key(raw_key)
        self.client_ec_private = key
        self.client_ec_public = key.public_key()
    

    def _send_client_key_exchange(self):
        
        #0x20 -> 32 is the length of the curve
        pkey = b"\x20" + self.client_ec_public.export_key(format = "raw")
        
        #handshake message type: client key exchange
        hs_header = b"\x10"
        #length of key of client key exchange follows
        hs_header += len(pkey).to_bytes(3)

        #type: handshake
        record_header = b"\x16"

        #protocol version: TLS1.2
        record_header += b"\x03\x03"

        #length of the rest of the message
        record_header += (len(hs_header) + len(pkey)).to_bytes(2)
        
        self.sock.send(record_header + hs_header + pkey)

        self.message_history += (hs_header + pkey)
    
    def __calc_symmetric_key(self):
        # print(repr(self.client_ec_private))
        # print(repr(self.server_ec_public))
        def func(*args, **kwargs):
            self.client_pre_master = args[0]
            client_write,client_iv, server_write, server_iv, master_secret = calc_symetric_key(args[0], self.client_random, self.server_random)
            self.master_secret = master_secret
            self.server_write_key = server_write
            self.client_write_key = client_write
            self.client_implicit_iv = client_iv
            self.server_implicit_iv = server_iv
        # print(x25519.scalar_mult(self.client_ec_private, self.server_ec_public))
        DH.key_agreement(eph_priv= self.client_ec_private,eph_pub= self.server_ec_public, kdf=func)
        


    def _send_client_change_cipher(self):
        #ChangeCipherSpec record
        record = b"\x14"

        #version
        record += b"\x03\x03"

        #1 byte following
        record += b"\x00\x01"
        #payload of this message
        record += b"\x01"
        
        self.sock.send(record)


    def _send_client_handshake_finish(self):
    
        record = b"\x16\x03\x03"
        explicit_iv = self.explicit_iv

        verify_data = calc_verify_data(self.master_secret, self.message_history)
        to_encrypt = b"\x14"
        to_encrypt += len(verify_data).to_bytes(3, "big")
        to_encrypt += verify_data
        key = AES.new(key = self.client_write_key, mode= AES.MODE_GCM, nonce =(self.client_implicit_iv + self.explicit_iv) )
        key.update(self.client_seq.to_bytes(8) + record + len(to_encrypt).to_bytes(2))

        enc , tag = key.encrypt_and_digest(to_encrypt)

        record += (len(explicit_iv) + len(enc) + len(tag) ).to_bytes(2)
        full_message = record + explicit_iv + enc + tag
        self.sock.send(full_message)

        self.client_seq += 1

        print("master", self.master_secret.hex())
        print("cr", self.client_random.hex())
        print("sr", self.server_random.hex())

    
    def _recv_change_cipher(self):
        print(self.sock.recv(1024).hex())


    def _recv_handshake_finish(self):
        pass


    def connect(self):

        self.sock.connect((self.address, self.port))
        self._send_client_hello()
        self._recv_server_hello()
        self._recv_certs()
        self._recv_key_exchange()
        self.__generate_keys()
        self._send_client_key_exchange()
        self.__calc_symmetric_key()
        self._send_client_change_cipher()
        self._send_client_handshake_finish()
        self._recv_change_cipher()
        self._recv_handshake_finish()
    
if __name__ == "__main__" :
    conn = tls_connection("www.google.com", 443)
    conn.connect()