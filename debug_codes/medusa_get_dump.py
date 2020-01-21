import re
import os

from minidump.utils import createminidump

user_path = os.path.expanduser("~")
medusa_ps_name = []
memory_dump = createminidump
pid_to_name = createminidump.enum_process_names()
for pid in pid_to_name:
    # medusaのプロセス名を決め打ちする，あんまりよくない..
    if(re.match("dex|medusa", pid_to_name[pid])):
        print('found medusa process PID: {id} Name: {name}'.format(
            id=pid, name=pid_to_name[pid]))
        memory_dump.create_dump(pid, os.path.join(
            user_path, "Desktop", "medusa.dump"), 0x00000002)
        break
    else:
        pass
