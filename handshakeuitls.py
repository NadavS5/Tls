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
    #type: ec_points_formant
    extentions += b"\x00\x0b"
    #length of the extention is 4
    extentions += b"\x00\x04"
    #ec points format length
    extentions += b"\x03"
    #ec points format: uncompressed, ansiX962 compressed prime, ansiX962 compressed char2
    extentions += b"\x00\x01\x02"


    #extention: supported_groups 
    #type: supported_groups
    extentions += b"\x00\x0a"
    #length of the extention
    extentions += b"\x00\x04"
    #supported groups list length 2 because we have 1 group
    extentions += b"\x00\x02"
    #supported group: x25519
    extentions += b"\x00\x1D"

    #extention: session ticket
    #extention: encrypt than mac
    #extention: extended_master_secret 
    #extention: signature_algorithms


    #extention: supported versions

    
    return extentions