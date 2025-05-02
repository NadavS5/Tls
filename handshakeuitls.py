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

    #extention: signature_algorithms 
    #extention: supported_groups 
    #extention: ec_point_formats 
    #extention: extended_master_secret 
    #extention: renegotiation_info

    
    return extentions