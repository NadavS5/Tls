from constants import RSA_PSS_RSAE_SHA256
from asn1crypto.x509 import  Certificate
from pprint import  pprint
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, pss
from Crypto.Hash import  SHA256, HMAC, SHA384
from Crypto.Cipher import AES, _mode_gcm

def build_extensions(address: str) -> bytes:
    'this doesnt returns the length field of the whole extensions (extensions Length)'
    # extensions = build_extensions(self.address)
    # extensions_full += b"\x00\x00" + len(extensions).to_bytes(2) + extensions

    extensions = b""


    #extension: server_name
    #type: hostname, host_length, host
    server_name_list = b"\x00" + len(address).to_bytes(2) + address.encode()
    server_name_extension = len(server_name_list).to_bytes(2) + server_name_list
    
    
    extensions += b"\x00\x00" + len(server_name_extension).to_bytes(2)
    extensions += server_name_extension
    
    #extension: ec_point_formats 
    #type: ec_points_formant0x0804
    extensions += b"\x00\x0b"
    extensions += b"\x00\x02"
    extensions += b"\x01"
    extensions += b"\x00"

    #extension: supported_groups 
    #type: supported_groups
    extensions += b"\x00\x0a"
    #length of the extension
    extensions += b"\x00\x04"
    #length of list
    extensions += b"\x00\x02"
    #supported grou0x0804p: x25519
    extensions += b"\x00\x1d"

    #extension: session ticket
    #type: session ticket
    # extensions += b"\x00\x23"
    # #length: 0 because we indicate that we have no session ticket
    # extensions += b"\x00\x00"

    #extension: encrypt than mac
    # #type: encrypt than mac (EtM)
    # extensions += b"\x00\x16"
    # #length 0: extension length is 0
    # extensions += b"\x00\x00"
    

    #extension: extended_master_secret
    #type: extended_master_secret
    extensions += b"\x00\x17"
    #length 0: 0 bytes of "Extended Master Secret" extension data
    extensions += b"\x00\x00"

    #extension: signature_algorithms
    #type: signature_algorithms
    extensions += b"\x00\x0d"
    #extension data length:4
    extensions += b"\x00\x04"
    #signature hash algorithms length
    extensions += b"\x00\x02"
    #our choosed signature alogrithem. look at constants,
    extensions += RSA_PSS_RSAE_SHA256

    #extension: supported versions

    
    return extensions

def verify_signature(signature: bytes,cert_hash, issuer: str)-> bool:
    """
    this function receives certificate fingerprint and verifies it by the ca that signed it
    cert_hash is pre digested SHA256 object that contains the tbs_certificate data

    Currently works only with WR2 signed certs, once finished I will add all
    """
    with open("wr2.crt", 'rb') as f :

        wr2_cert_ = f.read()
        wr2_cert = Certificate.load(wr2_cert_)
        # pprint(wr2_cert.native['tbs_certificate']['subject_public_key_info'])
        N = wr2_cert.native['tbs_certificate']['subject_public_key_info']['public_key']['modulus']
        E = wr2_cert.native['tbs_certificate']['subject_public_key_info']['public_key']['public_exponent']

        wr2_key = RSA.construct((N,E))
        cipher = PKCS1_v1_5.new(wr2_key)
        return cipher.verify(cert_hash,signature)

def verify_key_exch_signature(pkey: RSA.RsaKey, signature: bytes, hash)-> bool:
    """
    this function receives pre digested SHA256 object that contains:
    client_hello_random + server_hello_random + curve_info + public_key

    and verifies it against the server computed signature
    """

    our_sig = pss.new(pkey)
    try:
        our_sig.verify(hash,signature)
    except ValueError as e:
        return False
    else:
        return True


def prf(secret: bytes, label: bytes, seed: bytes, size: int) -> bytes:
    """
    TLS 1.2 Pseudo-Random Function using HMAC-SHA384\n
    see https://www.rfc-editor.org/rfc/rfc5246#section-5
    """
    def p_hash(secret: bytes, seed: bytes) -> bytes:
        result = b""
        A = seed
        while len(result) < size:
            A = HMAC.new(secret, A, SHA384).digest()
            result += HMAC.new(secret, A + seed, SHA384).digest()
        return result[:size]

    return p_hash(secret, label + seed)
def prfsha256(secret: bytes, label: bytes, seed: bytes, size: int) -> bytes:
    """
    TLS 1.2 Pseudo-Random Function using HMAC-SHA384\n
    see https://www.rfc-editor.org/rfc/rfc5246#section-5
    """
    def p_hash(secret: bytes, seed: bytes) -> bytes:
        result = b""
        A = seed
        while len(result) < size:
            A = HMAC.new(secret, A, SHA256).digest()
            result += HMAC.new(secret, A + seed, SHA256).digest()
        return result[:size]

    return p_hash(secret, label + seed)
def calc_symetric_key(pre_master_secret: bytes, client_random: bytes, server_random: bytes, all_hs_messages: bytes) -> tuple[bytes,bytes,bytes,bytes,bytes] :
    """
    this function receives the vars needed to generate the final aes key in the tls protocol

    it returns client_write_key, server_write_key
    """
    #EMS changes the way master_key is derived
    #https://www.ietf.org/rfc/rfc7627.html#section-4
    #-------master secret-------#
    master_secret = prf(
        pre_master_secret,
        b"extended master secret",
        SHA384.new(all_hs_messages).digest(),
        48
    )
    

    #-------key expansion-------#
    
    key_block_length = 32 + 32 + 4 + 4
    key_block = prf(
        master_secret,
        b"key expansion",
        server_random + client_random,
        key_block_length
    )

    client_write_key = key_block[0:32]
    server_write_key = key_block[32:64]
    client_iv = key_block[64:68]
    server_iv = key_block[68:72]

   
    return client_write_key, client_iv, server_write_key, server_iv, master_secret

def calc_verify_data(master_secret: bytes, all_hs_messages: bytes) -> bytes:
    """
    calculation of the verify data field in client-handshake finish\n
    see https://www.rfc-editor.org/rfc/rfc5246#section-7.4.9
    """
    
    return prf(
        master_secret,
        b"client finished",
        SHA384.new(all_hs_messages).digest(),
        12
    )
