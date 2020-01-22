from Crypto.Cipher import AES
import binascii
import struct
import sys

from medusa_tools import search_aes_key, get_medusa_dump, byte_entropy
from tools import scan_crypted_file


def unlock(key, path):
    # define AES mode for medusa locker
    mode = AES.MODE_CBC
    iv_key = b"0000000000000000"

    cipher_key = binascii.unhexlify(key)

    with open(path, "rb") as f:
        cipherdata = f.read()

    path_tmp = path.split(".")
    decrypt_path = path_tmp[0]+"."+path_tmp[1]
    print(decrypt_path)

    datasize_b = cipherdata[-24:-16]
    data_size = struct.unpack("<Q", datasize_b)
    print("original data size:" + str(data_size[0])+"byte")

    dummy_byte = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    cipherdata = dummy_byte + cipherdata[0:-536]
    print("decrypted file size:" + str(len(cipherdata)) + "byte")

    context = AES.new(cipher_key, mode, iv_key)
    cleardata = context.decrypt(cipherdata)[16:data_size[0]+16]

    with open(decrypt_path, "wb") as f:
        f.write(cleardata)

    return decrypt_path


def medusa_unlocker():
    ext = "encrypted"

    # get memory dump
    dump_path = get_medusa_dump()
    if(dump_path):
        pass
    else:
        raise EnvironmentError("Failed to dump medusa process")

    # search AES key from memory dump
    progress = 0
    _256bitAESkeys = []
    for output in search_aes_key(dump_path):
        if("progress" in output):
            progress += 1
            sys.stdout.write("\rProgress {:>3}%:".format(progress))
        else:
            sys.stdout.write("\r")
            if(len(output) == 32):
                print("128bit key: "+output)
            elif(len(output) == 64):
                print("256bit key: "+output)
                _256bitAESkeys.append(output)
            else:
                print(output)

            print(output)

        sys.stdout.flush()

# check whether _256bitAESkeys is valid with file byte_base entropy
    is_key_valid = False
    for key in _256bitAESkeys:
        i = 0
        ent_sum = 0.0
        ave_ent = 0.0
        for file in scan_crypted_file(ext=ext):
            print(file)
            if(i == 5):
                ave_ent = ent_sum / 5
                break
            with open(unlock(key, file), "rb") as f:
                sample = f.read()
            ent_sum += byte_entropy(sample)
            i += 1

        print("ave entropy: " + str(ave_ent))

        if(ave_ent < 0.95):
            is_key_valid = True
            break

    if(is_key_valid):
        print("found valid key: " + str(key))
    else:
        raise EnvironmentError("not found valid key")


if __name__ == "__main__":
    ext = "encrypted"
    _256bitAESkeys = ["2B4B6150645367566B5970337336763979244226452948404D6351655468576D",
                      "90e13711fb949a8f19716a07f09766de6b1b00361b4e64c12c687bb9e16b5d51"]
    # check whether _256bitAESkeys is valid with file byte_base entropy
    is_key_valid = False
    for key in _256bitAESkeys:
        i = 0
        ent_sum = 0.0
        ave_ent = 0.0
        for file in scan_crypted_file(ext=ext):
            print(file)
            if(i == 5):
                ave_ent = ent_sum / 5
                break
            with open(unlock(key, file), "rb") as f:
                sample = f.read()
            ent_sum += byte_entropy(sample)
            i += 1

        print("ave entropy: " + str(ave_ent))

        if(ave_ent < 0.95):
            is_key_valid = True
            break

    if(is_key_valid):
        print("found valid key: " + str(key))
    else:
        raise EnvironmentError("not found valid key")
