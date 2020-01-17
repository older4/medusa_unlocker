from minidump.utils import createminidump

memory_dump = createminidump
memory_dump.create_dump(14192, "nen.dump", 0x00000002, True)
