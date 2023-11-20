"""
    Name        : Zero2Auto_decode_str
    Author      : Charles Lomboni
    Description : Binary Ninja plugin to decode strings from zero2auto custom sample
"""

def get_ref_from_func():
    ref_lst = []
    fn_name = TextLineField("What is the func name? ")
    get_form_input(["Get Function Name", None, fn_name], "Decode Zero2Auto main_bin strings")
    
    fn_addr = bv.get_functions_by_name(fn_name.result)[0].start
    
    for x in bv.get_callers(fn_addr):
        ref_lst.append(x)
    
    return ref_lst

def get_encoded_strs(refs):
    encoded_strs = []
    for x in refs:
        encoded_strs.append(str(x.hlil).replace(')','').replace('"','').split('(')[1])
    
    return encoded_strs


def decode_str(encoded_str):
    base_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./="
    new_char = 0
    decoded_str = []

    for x in encoded_str:
        str_diff = (base_str.index(x) + 0xD)
        if str_diff < 66:
            decoded_str.append(base_str[str_diff])
        else:
            new_char = (base_str.index(x) - 66) + 0xD
            decoded_str.append(base_str[new_char])
        
    return ''.join(decoded_str)

refs = get_ref_from_func()
enc_strs = get_encoded_strs(refs)

# mw_resolve_api
for x in enc_strs:
    print(f"[+] {x} => {decode_str(x)}")