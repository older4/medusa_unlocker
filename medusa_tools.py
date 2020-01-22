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


def search_aes_key(dump_path):
    cmd = "rsc/aeskeyfind_windows.exe {dump} -t 50".format(dump=dump_path)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    while True:
        line = proc.stdout.readline()
        if line:
            yield line.strip().decode("utf-8")

        if not line and proc.poll() is not None:
            break


def get_medusa_dump():
    user_path = os.path.expanduser("~")
    memory_dump = createminidump
    pid_to_name = createminidump.enum_process_names()
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
    original = r"D:\my_program\medusa_unlocker\sample\BGinfo_original\build.cfg"
    encrypted = r"D:\my_program\medusa_unlocker\sample\BGinfo_encrypted2\build.cfg.encrypted"

    with open(original, "rb") as f:
        original_data = f.read()

    with open(encrypted, "rb") as f:
        encrypted_data = f.read()

    print("original  entropy:{:<100}".format(byte_entropy(original_data)))
    print("encrypted entropy:{:<100}".format(byte_entropy(encrypted_data)))

    # dump_path = "memory.dmp"
    # progress = 0
    # gage = 0
    # for stdout in search_aes_key(dump_path):
    #     try:
    #         output_str = stdout.strip().decode("utf-8")
    #     except UnicodeDecodeError:
    #         output_str = stdout.strip()

    #     if("progress" in output_str):
    #         progress += 1
    #         sys.stdout.write("\rProgress {:>3}%:".format(progress))

    #         if(round(progress/2) != gage):
    #             gage = round(progress/2)

    #         for i in range(gage):
    #             sys.stdout.write("|")

    #     else:
    #         sys.stdout.write("\r")
    #         print(output_str)

    #     sys.stdout.flush()
