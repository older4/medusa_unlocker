import re
import os

from minidump.utils import createminidump

user_path = os.path.expanduser("~")
medusa_ps_name = []
memory_dump = createminidump
pid_to_name = memory_dump.enum_process_names()
# print(pid_to_name)
for pid in pid_to_name:
    # print(pid_to_name[pid])
    # medusaのプロセス名を決め打ちする，あんまりよくない..
    print(pid_to_name[pid])
    if(re.match(".*(dex|medusa|firefox).*", pid_to_name[pid].lower())):
        print('found medusa process PID: {id} Name: {name}'.format(
            id=pid, name=pid_to_name[pid]))
        memory_dump.create_dump(pid, os.path.join(
            user_path, "Desktop", "medusa.dump"), 0x00000002)
        break
    else:
        pass
