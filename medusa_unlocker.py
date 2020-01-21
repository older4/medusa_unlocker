from Crypto.Cipher import AES
from Crypto.Util import Padding
import binascii
import struct


path = input("path:")
key = input("key:")

mode = AES.MODE_CBC
iv_key = b"0000000000000000"

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

dummy_byte = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
cipherdata = dummy_byte + dummy_byte + cipherdata[0:-536]
print("decrypted file size:" + str(len(cipherdata)) + "byte")

context = AES.new(cipher_key, mode, iv_key)
cleardata = context.decrypt(cipherdata)[16:data_size[0]+16]

with open(origin_filename, "wb") as f:
    f.write(cleardata)
