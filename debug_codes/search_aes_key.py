import subprocess
import sys


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


if __name__ == "__main__":
    dump_path = "memory.dmp"
    progress = 0
    gage = 0
    for stdout in search_aes_key(dump_path):
        try:
            output_str = stdout.strip().decode("utf-8")
        except UnicodeDecodeError:
            output_str = stdout.strip()

        if("progress" in output_str):
            progress += 1
            sys.stdout.write("\rProgress {:>3}%:".format(progress))

            if(round(progress/2) != gage):
                gage = round(progress/2)

            for i in range(gage):
                sys.stdout.write("|")

        else:
            sys.stdout.write("\r")
            print(output_str)

        sys.stdout.flush()
