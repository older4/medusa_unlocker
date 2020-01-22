import glob
import os
import win32.win32api as win32api


def get_logical_drives():
    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\000')[:-1]
    tmp_list = drives
    # 有効なディスクかチェック
    for count, drive_letter in enumerate(tmp_list):
        try:
            win32api.GetDiskFreeSpaceEx(drive_letter)
        except:
            del drives[count]

    return drives


def scan_crypted_file(skip_root_folders="defalt", ext=None):
    drives = get_logical_drives()
    if(skip_root_folders == "defalt"):
        skip_root_folders = ["Windows", "Program Files"]

    if(ext):
        ext = "/*." + ext
    else:
        ext = ""

    for drive in drives:
        for path in glob.iglob(drive+"*"):
            for skip in skip_root_folders:
                if(skip in path):
                    break

                if(skip == skip_root_folders[-1]):
                    for p in glob.iglob(path+"/**{}".format(ext), recursive=True):
                        if(os.path.isfile(p)):
                            yield p
