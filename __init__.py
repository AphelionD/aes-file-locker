import hashlib
from argon2 import hash_password
# https://pypi.org/project/argon2-cffi/
# pip install argon2-cffi
import random
import json
import os
import hashlib
from glob import glob
from shutil import rmtree, move
from tqdm import tqdm
from base64 import b64decode, b64encode
from tkinter import messagebox, ttk
CONFIG_DEFAULT = {
    'time_cost': 1,
    'memory_cost': 2097152,
    'parallelism': 5
}
configuration = {  # customize your own configuration heare
    'time_cost': 1,
    'memory_cost': 2097152,  # KiB
    'parallelism': 5
}
def all_files_can_be_moved_by_shutil(dir):
    '''检测一个目录下的文件是否都可以被移动，返回一个包含所有不可被移动的文件的list'''
    def get_all_files_list(dir):
        list = []
        if not os.path.isdir(dir):
            raise OSError(f'No such directory: {dir}')
        for i in os.walk(dir):
            for n in i[2]:
                list.append(os.path.join(i[0], n))
        return list
    list = []
    i = 0
    while os.path.isdir(os.path.join(dir, str(i))):
        i += 1
    target = os.path.join(dir, str(i))
    os.mkdir(target)
    del i
    for k in get_all_files_list(dir):
        try:
            move(k, os.path.join(target, os.path.basename(k)))
            move(os.path.join(target, os.path.basename(k)), k)
        except:
            list.append(k)
    rmtree(target)
    return list


def is_encrypted(dir):
    def get_all_files(dir):
        if not os.path.isdir(dir):
            raise OSError(f'No such directory: {dir}')
        for i in os.walk(dir):
            for n in i[2]:
                yield os.path.join(i[0], n)
    for f in get_all_files(dir):
        ext = os.path.splitext(f)[1]
        if ext != '.afd' and ext != '.dll' and ext != '.sti':
            return False
    return True


def get_relative_dir(a, b):
    '''获取a相对于b的路径.
    \n例如，返回：存志群里的音频资料\音标听力\光盘1\9. 巩固练习\巩固练习 01.mp3'''
    tinyword = ''
    for i in range(len(a)):
        tinyword = a[:i+1]
        if tinyword == b:
            del tinyword
            return a[i+2:]


def copy_dir(path):
    '''获取这个路径下的所有文件和文件夹，使用相对路径

    返回：[[dir1, dir2, ...], [file1, file2, ...]]'''
    files = []
    directories = []
    for i in os.walk(path):
        for x in i[2]:
            files.append(get_relative_dir(os.path.join(i[0], x), path))
        if i[0] == path:
            continue
        directories.append(get_relative_dir(i[0], path))
    return [directories, files]


def md5(fname,  is_file_dir=None, encoding='utf-8'):
    '''fname: 自动解释，可传入file directory, str, bytes\n
        is_file_dir: 强制指定是否为file directory，传入bool或None，None时自动判断\n
        注意：传入路径时未指定is_file_dir，则文件不存在不会报错，而是转而计算这个路径字符串str的哈希值。'''
    hash_md5 = hashlib.md5()
    if (os.path.isfile(fname) and is_file_dir != False) or is_file_dir == True:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    elif isinstance(fname, str):
        for i in (fname[i:i+2048] for i in range(0, len(fname), 2048)):
            hash_md5.update(i.encode(encoding))
        return hash_md5.hexdigest()
    elif isinstance(fname, bytes):
        for i in (fname[i:i+4096] for i in range(0, len(fname), 4096)):
            hash_md5.update(i)
        return hash_md5.hexdigest()
__all__ = ['random', 'json', 'os', 'glob', 'rmtree', 'move', 'tqdm',
           'messagebox', 'ttk', 'hash_password', 'b64decode', 'b64encode', 'hashlib','CONFIG_DEFAULT',
           'configuration','all_files_can_be_moved_by_shutil', 'is_encrypted', 'md5', 'copy_dir','get_relative_dir']