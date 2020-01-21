import subprocess
import time
import os
import sys

path = "D:\my_program\medusa_unlocker\memory.dmp"
cmd = "rsc/aeskeyfind_windows.exe {dump} -t 50".format(dump=path)
p = subprocess.Popen(cmd,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)
for line in iter(p.stdout.readline, b''):
    print(line.rstrip())
