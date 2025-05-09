from constants import RSA_PSS_RSAE_SHA256

def build_extentions(address: str) -> bytes:
    'this doesnt returns the length field of the whole extentions (Extentions Length)'
    # extentions = build_extentions(self.address)
    # extentions_full += b"\x00\x00" + len(extentions).to_bytes(2) + extentions

    extentions = b""


    #extention: server_name
    #type: hostname, host_length, host
    server_name_list = b"\x00" + len(address).to_bytes(2) + address.encode()
    server_name_extention = len(server_name_list).to_bytes(2) + server_name_list
    
    
    extentions += b"\x00\x00" + len(server_name_extention).to_bytes(2)
    extentions += server_name_extention
    
    #extention: ec_point_formats 
    #type: ec_points_formant0x0804


    #extention: supported_groups 
    #type: supported_groups
    extentions += b"\x00\x0a"
    #length of the extention
    extentions += b"\x00\x04"
    #length of list
    extentions += b"\x00\x02"
    #supported grou0x0804p: x25519
    extentions += b"\x00\x1d"

    #extention: session ticket
    #type: session ticket
    extentions += b"\x00\x23"
    #length: 0 because we indicate that we have no session ticket
    extentions += b"\x00\x00"

    #extention: encrypt than mac
    #type: encrypt than mac (EtM)
    extentions += b"\x00\x16"
    #length 0: extention length is 0
    extentions += b"\x00\x00"
    

    #extention: extended_master_secret
    #type: extended_master_secret
    extentions += b"\x00\x17"
    #length 0: 0 bytes of "Extended Master Secret" extension data
    extentions += b"\x00\x00"

    #extention: signature_algorithms
    #type: signature_algorithms
    extentions += b"\x00\x0d"
    #extention data length:4
    extentions += b"\x00\x04"
    #signature hash algorithms length
    extentions += b"\x00\x02"
    #our choosed signature alogrithem. look at constants,
    extentions += RSA_PSS_RSAE_SHA256

    #extention: supported versions

    
    return extentions