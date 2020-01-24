import subprocess
import sys
import re
import os
import struct

from math import log

from minidump.utils import createminidump


def byte_entropy(binary):
    """
    calculate byte entropy
    https://stackoverflow.com/questions/990477/how-to-calculate-the-entropy-of-a-file
    """
    entropy = 0.0
    hex_binary = binary.hex()
    len_hex = len(hex_binary)
    byte_size = int(len_hex/2)
    byte_counts = [0]*256

    for dig in range(0, len_hex, 2):
        byte_counts[int(hex_binary[dig:dig+2], 16)] += 1

    for count in byte_counts:
        if(count == 0):
            pass
        else:
            p = 1.0*count/byte_size
            entropy -= p*log(p, 256)

    return entropy


def search_aes_key_wrapper(dump_path):
    cmd = "rsc/aeskeyfind_windows.exe {dump} -t 50".format(dump=dump_path)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    while True:
        line = proc.stdout.readline()
        if line:
            yield line.strip().decode("utf-8")

        if not line and proc.poll() is not None:
            break


def get_aes_key(dump_path, bit):
    progress = 0
    _128bitAESkeys = []
    _256bitAESkeys = []

    for output in search_aes_key_wrapper(dump_path):
        if("progress" in output):
            progress += 1
            sys.stdout.write("\rProgress {:>3}%:".format(progress))
        else:
            sys.stdout.write("\r")
            if(len(output) == 32):
                print("128bit key: "+output)
                _128bitAESkeys.append(output)
            elif(len(output) == 64):
                print("256bit key: "+output)
                _256bitAESkeys.append(output)
            else:
                print(output)

        sys.stdout.flush()

    if(bit == 128):
        return _128bitAESkeys

    elif(bit == 256):
        return _256bitAESkeys


def get_medusa_dump():
    user_path = os.path.expanduser("~")
    memory_dump = createminidump
    pid_to_name = memory_dump.enum_process_names()
    for pid in pid_to_name:
        # medusaのプロセス名を決め打ちする，あんまりよくない..
        if(re.match("dex|medusa", pid_to_name[pid])):
            print('found medusa process PID: {id} Name: {name}'.format(
                id=pid, name=pid_to_name[pid]))
            memory_dump.create_dump(pid, os.path.join(
                user_path, "Documents", "medusa.dump"), 0x00000002)
            break
        else:
            return 0
            pass
    return os.path.join(user_path, "Documents", "medusa.dump")


if __name__ == "__main__":
    pass
