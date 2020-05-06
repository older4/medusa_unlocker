from Crypto.Cipher import AES
import binascii
import struct
import sys
import os

from medusa_tools import get_aes_key, get_medusa_dump, byte_entropy
from tools import scan_crypted_file


def unlock(key, path):
    # define AES mode for medusa locker
    mode = AES.MODE_CBC
    iv_key = b"0000000000000000"

    cipher_key = binascii.unhexlify(key)

    with open(path, "rb") as f:
        cipherdata = f.read()

    path_tmp = path.split(".")
    decrypt_path = ".".join(path_tmp[:-1])
    print("decrypt: "+decrypt_path)

    datasize_b = cipherdata[-24:-16]
    data_size = struct.unpack("<Q", datasize_b)
    print("original file size: " + str(data_size[0])+"byte")

    dummy_byte = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    cipherdata = dummy_byte + cipherdata[0:-536]
    print("load file size: " + str(len(cipherdata)) + "byte")

    context = AES.new(cipher_key, mode, iv_key)
    cleardata = context.decrypt(cipherdata)[16:data_size[0]+16]

    with open(decrypt_path, "wb") as f:
        f.write(cleardata)

    return decrypt_path


def medusa_unlocker(mode=False, dump=None, input_file=None,key = None):
    # encrypted filename extension
    ext = "encrypted"

    # get memory dump
    if(mode=="test"):
        dump_path = dump
    elif(mode == "key"):
        dump_path = True
    else:
        dump_path = get_medusa_dump()

    if(bool(dump_path)):
        pass
    else:
        raise EnvironmentError("Failed to dump medusa process")

    # search AES key from memory dump
    if(mode == "key"):
        _256bitAESkeys = [key]
    else:
        _256bitAESkeys = get_aes_key(dump_path, 256)

    # check whether _256bitAESkeys is valid with file byte_base entropy
    is_key_valid = False
    for key in _256bitAESkeys:
        print("Candidate key: " + str(key))
        i = 0
        ent_sum = 0.0
        ave_ent = 0.0

        if(mode):
            print(input_file)
            with open(unlock(key, input_file), "rb") as f:
                sample = f.read()
            ave_ent = byte_entropy(sample)

        else:
            for file in scan_crypted_file(ext=ext):
                print(file)
                if(i > 5):
                    ave_ent = ent_sum / i
                    break
                with open(unlock(key, file), "rb") as f:
                    sample = f.read()
                ent_sum += byte_entropy(sample)
                i += 1

        print("average entropy: " + str(ave_ent))

        if(ave_ent < 0.95):
            is_key_valid = True
            break
        else:
            print(
                "Files entropy is big, so they aren't decrypted correctly with this key.")

    if(is_key_valid):
        print("found valid key: " + str(key))
    else:
        raise EnvironmentError("not found valid key from memory")

    # decrypt all files with found valid key
    if(mode):
        pass
    else:
        for file in scan_crypted_file(ext=ext):
            unlock(key, file)


if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print("usage: with no option: automatically scan aes key from memory and decrypt files.")
        print("medusa_unlocker.py test memory.dump encrypted_file_path : scan aes key from dump and decrypt file.")

    elif(sys.argv[1] == "run"):
        medusa_unlocker()

    elif(len(sys.argv) < 3):
        print("usage: with no option: automatically scan aes key from memory and decrypt files.")
        print("medusa_unlocker.py test memory.dump encrypted_file_path : scan aes key from dump and decrypt file.")

    elif(sys.argv[1] == "test" and sys.argv[2] and sys.argv[3]):
        print("test mode")
        medusa_unlocker(mode = "test",dump= os.path.abspath(
            sys.argv[2]),input_file= os.path.abspath(sys.argv[3]))

    elif(sys.argv[1] == "key" and sys.argv[2] and sys.argv[3]):
        print("key mode")
        medusa_unlocker(mode = "key", input_file = os.path.abspath(
            sys.argv[2]), key = sys.argv[3])

    else:
        pass
