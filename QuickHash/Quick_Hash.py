import hashlib
import os
from time import time
from traceback import print_exc
import json
from collections import OrderedDict
from tqdm import tqdm
import functools

hash_method_table = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
    "sha512": hashlib.sha512,
    "sha384": hashlib.sha384,
}
HASH_METHOD = "sha256"
BLOCKS = 5  # how many blocks of bytes to hash in a file
BLOCK_SIZE = 102400  # 10KiB = 102400B


def calc_time(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        t0 = time()
        a = func(*args, **kwargs)
        print(f"{func.__name__}用时{round(time()-t0,2)}秒")
        return a

    return wrapper


def get_relative_dir(a, b):
    """获取a相对于b的路径.
    \n例如，返回：存志群里的音频资料\音标听力\光盘1\9. 巩固练习\巩固练习 01.mp3"""
    assert isinstance(a, str) and isinstance(b, str), "param 'a' and 'b' must be string"
    return a.replace(b, "").strip("\\")  # 这种方式也许在别的操作系统上面会出现问题


@calc_time
def QuickHash(
    path: str,
    progress_bar=True,
    blocks=BLOCKS,
    block_size=BLOCK_SIZE,
    hash_method=HASH_METHOD,
    ignore=["QuickHash.json", "Thumbs.db"],
):
    assert os.path.isdir(path)
    hash_method = hash_method_table[hash_method]
    result = {"headers": None, "dir": [], "file": OrderedDict()}
    try:
        total_dir_number = 0
        if progress_bar:
            total_file_number = 0
            for i, j, k in os.walk(path):
                total_file_number += len(k)
            tq = tqdm(
                total=total_file_number, mininterval=1.0, dynamic_ncols=True, delay=1.2
            )
        min_size = block_size * blocks
        steps = blocks - 1
        for i in os.walk(path):
            parent = get_relative_dir(i[0], path)
            if len(i[1]) == 0:  # 只保留最底层的目录
                result["dir"].append(os.path.join(parent))
            for file in sorted(i[2]):
                if file in ignore:
                    continue
                file_path = os.path.join(i[0], file)

                def _get_file_hash(file, file_size):
                    """内部函数，不允许在外部引用。由于前面已经计算过file_size，
                    为节约效率直接把前面的计算结果作为参数传入"""
                    hasher = hash_method()
                    step_size = (file_size - block_size) // steps
                    with open(file, "rb") as f:
                        if file_size <= min_size:
                            hasher.update(f.read())
                        else:
                            hasher.update(f.read(block_size))
                            for i in range(
                                step_size, (steps - 1) * step_size + 1, step_size
                            ):
                                f.seek(i, 0)
                                hasher.update(f.read(block_size))
                            f.seek(-block_size, 2)
                            hasher.update(f.read(block_size))
                    return hasher.hexdigest()

                file_size = os.path.getsize(file_path)
                result["file"][os.path.join(parent, file)] = {
                    "size": file_size,
                    "hash": _get_file_hash(file_path, file_size),
                }
                if progress_bar:
                    tq.update()
            total_dir_number += 1
        result["dir"] = list(sorted(result["dir"]))
        result["file"] = OrderedDict(sorted(result["file"].items(), key=lambda x: x[0]))
        headers = OrderedDict()
        headers["total_hash"] = ""
        headers["total_dir_number"] = total_dir_number - 1
        headers["total_file_number"] = len(result["file"])
        headers["BLOCKS"] = blocks
        headers["BLOCK_SIZE"] = block_size
        headers["HASH_METHOD"] = HASH_METHOD
        result["headers"] = headers
        result["headers"]["total_hash"] = hash_method(
            json.dumps(result, indent=4, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        result["headers"]["QuickHash_version"] = "1.0"
        return result
    except Exception as e:
        print_exc(e)
        os.system("pause")


if __name__ == "__main__":

    def compare_dicts(dict1, dict2):
        diff = {}

        # 检查 dict1 中的键是否存在于 dict2 中
        for key in dict1:
            if key not in dict2:
                diff[key] = (dict1[key], None)
            elif dict1[key] != dict2[key]:
                diff[key] = (dict1[key], dict2[key])

        # 检查 dict2 中的键是否存在于 dict1 中
        for key in dict2:
            if key not in dict1:
                diff[key] = (None, dict2[key])

        return diff

    def compare_quick_hash(path1, path2):
        dict1 = json.load(
            open(os.path.join(path1, "QuickHash.json"), "r", encoding="utf-8")
        )
        dict2 = json.load(
            open(os.path.join(path2, "QuickHash.json"), "r", encoding="utf-8")
        )
        if dict1["headers"] == dict2["headers"]:
            print("两个文件夹完全一致")
        else:
            for key, (val1, val2) in compare_dicts(dict1, dict2).items():
                print(
                    f"Key: {key},\n\tValue in dict1: {val1}, \n\tValue in dict2: {val2}"
                )

    print(f"HASH_METHOD = {HASH_METHOD}")
    print(f"BLOCKS = {BLOCKS}")
    print(f"BLOCK_SIZE = {BLOCK_SIZE}")
    path = r"C:\华为家庭存储\【CORE】核心文件\【10A】\学校网课录屏"
    print(f"path = {path}")
    # ========以下注释不可删除==========
    # generate QuickHash:
    json.dump(
        QuickHash(path, progress_bar=True),
        open(os.path.join(path, "QuickHash.json"), "w", encoding="utf-8"),
        ensure_ascii=False,
        indent=4,
    )

    # compare_quick_hash(r'G:\学习之过时或不常用文件\【初中文件】\【9B】','I:\备份&导出\学习核心文件备份\【9B】')

    # verify QuickHash:
    quick_hash_file = json.load(
        open(os.path.join(path, "QuickHash.json"), "r", encoding="utf-8")
    )
    latest_path = QuickHash(
        path,
        blocks=int(quick_hash_file["headers"]["BLOCKS"]),
        block_size=int(quick_hash_file["headers"]["BLOCK_SIZE"]),
        hash_method=quick_hash_file["headers"]["HASH_METHOD"],
    )
    if latest_path == quick_hash_file:
        print("校验成功！")
    else:
        for key, (val1, val2) in compare_dicts(quick_hash_file, latest_path).items():
            print(
                f"Key: {key},\n\tValue in QuickHash.json: {val1}, \n\tValue in path: {val2}"
            )
    os.system("pause")
