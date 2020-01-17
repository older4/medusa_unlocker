from Crypto.Cipher import AES
from Crypto.Util import Padding
import binascii
import struct

# path = input("path:")
path = "/home/ryo/.cuckoo/storage/analyses/28/encrypted_sample/BGinfo/openssh.ps1.encrypted"
# key = "3324f07ac6388f0b7c06dacce5b77289d6e9a8d95bcd97cd8e631b553591b221"
# key = "1ec3a52604a79561a7e483518a846d6ffc756658c1162b46aca6846516a86731"
key = "90e13711fb949a8f19716a07f09766de6b1b00361b4e64c12c687bb9e16b5d51"
mode = AES.MODE_CBC
iv_key = b"0000000000000000"

byte = b"\x0C\x1B\x00\x00\x00\x00\x00\x00\x0A\x00\x00\x00\x2C\x00\x00\x00"
cipher_key = binascii.unhexlify(key)

with open(path, "rb") as f:
    cipherdata = f.read()

name_tmp = path.split("/")[-1].split(".")
origin_filename = name_tmp[0]+"."+name_tmp[1]
print(origin_filename)

datasize_b = cipherdata[-24:-16]
print(datasize_b)
data_size = struct.unpack("<Q", datasize_b)
print("original data size:" + str(data_size[0])+"byte")

cipherdata = byte + cipherdata[:-536]

print("decrypted file size:" + str(len(cipherdata)) + "byte")

context = AES.new(cipher_key, mode, iv_key)
cleardata = context.decrypt(cipherdata)[:data_size[0]]

with open("/home/ryo/デスクトップ/decrypted/"+origin_filename, "wb") as f:
    f.write(cleardata)
