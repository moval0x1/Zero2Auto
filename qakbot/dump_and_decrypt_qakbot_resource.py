from arc4 import ARC4
from ctypes import *

import binascii
import pefile
import argparse
import struct


brieflz = cdll.LoadLibrary('libbrieflz.so')
DEFAULT_BLOCK_SIZE = 1024 * 1024

def save_to_file(file_name, hex_content):
    
    f = open(f"{file_name}.bin", "wb")
    f.write(hex_content)
    f.close()

def rc4_decrypt(key, data):
    cipher = ARC4(key)
    decrypted = cipher.decrypt(data)
    sha1_sum = decrypted[:20]
    
    return decrypted[20:]

def decompress_data(data, blocksize=DEFAULT_BLOCK_SIZE, level=1):
    """
        Reference: https://github.com/sysopfb/Malware_Scripts/blob/master/qakbot/blzpack.py#L74
    """

    decompressed_data = bytes() 
    max_packed_size = brieflz.blz_max_packed_size(blocksize);
	
    (magic,level,packedsize,crc,hdr_depackedsize,crc2) = struct.unpack_from('>IIIIII', data)
    data = data[24:]
    while magic == 0x626C7A1A and len(data) > 0:
        compressed_data = create_string_buffer(data[:packedsize])
        workdata = create_string_buffer(blocksize)
        depackedsize = brieflz.blz_depack(byref(compressed_data), byref(workdata), c_int(hdr_depackedsize))
        if depackedsize != hdr_depackedsize:
            print("Decompression error")
            print("DepackedSize: "+str(depackedsize) + "\nHdrVal: "+str(hdr_depackedsize))
            return None
        decompressed_data += workdata.raw[:depackedsize]
        data = data[packedsize:]
        if len(data) > 0:
            (magic,level,packedsize,crc,hdr_depackedsize,crc2) = struct.unpack_from('>IIIIII', data)
            data = data[24:]
        else:
            break
        return decompressed_data

def read_resource(pe_name, resource_name):
    
    pe = pefile.PE(pe_name)

    settings_resource = "" 
    offset = 0x0
    size = 0x0

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                if entry.name.__str__() == resource_name:
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size

    if offset != 0x0 and size != 0x0:
        print(f"[+] Reading the resource: {resource_name}")
        settings_resource = pe.get_memory_mapped_image()[offset:offset+size]
        return settings_resource
    else:
        print("[-] Error while trying to read the resource")

def get_args():

    parser = argparse.ArgumentParser(description='Remcos Config Extractor.')
    parser.add_argument("-f", "--file_path", type=str, help='File path of the Remcos binary')
    parser.add_argument("-r", "--res_name", type=str, help='Name of the resource file inside the Remcos binary')

    args = parser.parse_args()

    return args

def main():

    args = get_args()

    print(f"[+] Reading the file: {args.file_path}")
    settings_resource = read_resource(args.file_path, args.res_name)

    print("\t[>] Getting the key")
    key = settings_resource[:20]
    
    print("\t[>] Getting the data")
    data = settings_resource[20:]

    print("\t[>] Decrypting RC4")
    decrypted_resource = rc4_decrypt(key, data)

    print(f"[+] Decompressing data")
    # As it is a modified version, we need replace the magic
    replaced_data = binascii.hexlify(decrypted_resource).decode().replace("616cd31a", "626C7A1A")
    decompressed_qbot = decompress_data(bytes.fromhex(replaced_data))

    print(f"[+] Saving {args.res_name}.bin")
    if decompressed_qbot == b'':
        save_to_file(args.res_name, decrypted_resource)
    else:
        save_to_file(args.res_name, decompressed_qbot)

    print("[+] Done!")

if __name__ == '__main__':
    main()