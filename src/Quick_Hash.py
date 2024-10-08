import hashlib
import os
from collections import OrderedDict
from tqdm import tqdm
import fnmatch
import ejson

HASH_METHOD_TABLE = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
    "sha512": hashlib.sha512,
    "sha384": hashlib.sha384,
}
HASH_METHOD = "sha256"
BLOCKS = 5  # how many blocks of bytes to hash in a file
BLOCK_SIZE = 102400  # 10KiB = 102400B



class VersionError(ValueError):
    pass
class QuickHashCmp():
    def __init__(self,left,right):
        '''left/right : a QuickHash object'''
        self.left_hasher = left
        self.right_hasher = right
        self.left_dir_only = []
        self.right_dir_only = []
        self.left_only = []
        self.right_only = []
        self.different = {}
        self.is_equal = None
        '''可以获取两个文件夹是否相等'''
        self.compare()
    def compare(self):
        if self.left_hasher.version != self.right_hasher.version:
            raise VersionError(f'left is of QuickHash version {self.left_hasher.version} while right is of QuickHash version {self.right_hasher.version},\
                               cannot compare two hashes with different versions')
        hashl = self.left_hasher.get_hash_content()
        hashr = self.right_hasher.get_hash_content()

        if self.left_hasher.digest() == self.right_hasher.digest():
            self.is_equal = True
            return self

        dictl = hashl['dir']
        dictr = hashr['dir']

        # 检查 dict1 中的键是否存在于 dict2 中
        for key in dictl:
            if key not in dictr:
                self.left_dir_only.append(key)

        # 检查 dict2 中的键是否存在于 dict1 中
        for key in dictr:
            if key not in dictl:
                self.right_dir_only.append(key)

        dictl = hashl['file']
        dictr = hashr['file']
        # 检查 dict1 中的键是否存在于 dict2 中
        for key in dictl:
            if key not in dictr:
                self.left_only.append(key)
            elif dictl[key] != dictr[key]:
                self.different[key] = (dictl[key], dictr[key])

        # 检查 dict2 中的键是否存在于 dict1 中
        for key in dictr:
            if key not in dictl:
                self.right_only.append(key)
        return self
    def report(self):
        if self.is_equal:
            print('The two directories are exactly the same!')
            return
        if self.left_only: # 如果列表不为空
            print('These files are only in the left hasher:')
            for i in self.left_only:
                print(i)
            print('-'*80)
        if self.right_only:
            print('These files are only in the right hasher:')
            for i in self.right_only:
                print(i)
            print('-'*80)
        if self.different:
            print('Different files:')
            print(self.different.items())
            print('-'*80)
        if self.left_dir_only:
            print('These directories are only in the left: ')
            for i in self.left_dir_only:
                print(i)
            print('-'*80)
        if self.right_dir_only:
            print('These directories are only in the right: ')
            for i in self.right_dir_only:
                print(i)
    def clear_cache(self):
        self.left_only = []
        self.right_only = []
        self.different = {}

class QuickHash():
    progress_bar=True
    '''class variable'''
    ignore=["QuickHash.json", "Thumbs.db"]
    '''class variable, a list of files or directories to be ignored. Uses Unix wildcard syntax.'''
    def __init__(
        self,
        blocks=BLOCKS,
        block_size=BLOCK_SIZE,
        hash_method=HASH_METHOD,
        mtime = False,
        ctime = False,
        content = True,
        version = '1.1'
    ):
        self.__hash_method = HASH_METHOD_TABLE[hash_method]
        self.blocks = blocks
        self.block_size = block_size
        self.__hash_content = ''
        self.version = version
        self.mtime = mtime
        self.ctime = ctime
        self.content = content

    @property
    def hash_method(self):
        reversed_hash_method_table = {
            "openssl_sha256": "sha256",
            "openssl_md5": "md5",
            "openssl_sha512": "sha512",
            "openssl_sha384": "sha384",
        }
        return reversed_hash_method_table[self.__hash_method.__name__]
    @hash_method.setter
    def hash_method(self,value):
        self.__hash_method =HASH_METHOD_TABLE[value]
        return value

    def _quick_hash_v1_0(self,path:str,return_new_instance=False):
        ''':param verify:如果True，那么不修改self.hash，否则修改
        样例：
        ```{
    "headers": {
        "total_hash": "fcaf9930f4f0b604c0db9860ef5ebe69089b3c1c051ab5e85ab7c80d46d804a2",
        "total_dir_number": 91,
        "total_file_number": 568,
        "BLOCKS": 5,
        "BLOCK_SIZE": 102400,
        "HASH_METHOD": "sha256",
        "QuickHash_version": "1.0"
    },
    "dir": [],
    "file": {
        "2023初三二模\\嘉定 5科全+跨学科+道法\\2023嘉定区初三二模化学及答案.pdf": {
            "size": 568981,
            "hash": "224fc4766fad5a6b45bf28dea94f1a6d131b39af9c7d7f812a1a58a19c2e12bd"
        },
        "2023初三二模\\嘉定 5科全+跨学科+道法\\2023嘉定区初三二模数学及答案.pdf": {
            "size": 371488,
            "hash": "319de5823d331241b9685e6cb69ed1c9e6a60d98feca964cf7a3753777c55aff"
        }```'''
        assert os.path.isdir(path)
        result = {"headers": None, "dir": [], "file": OrderedDict()}
        total_dir_number = 0
        if QuickHash.progress_bar:
            total_file_number = 0
            for i, j, k in os.walk(path):
                total_file_number += len(k)
            tq = tqdm(
                total=total_file_number, mininterval=1.0, dynamic_ncols=True, delay=1.2
            )
        min_size = self.block_size * self.blocks
        steps = self.blocks - 1
        for i in os.walk(path):
            parent = os.path.relpath(i[0], path)
            if len(i[1]) == 0:  # 只保留最底层的目录
                result["dir"].append(parent)
            for file in sorted(i[2]):
                if self.matches_ignore(QuickHash.ignore,file):
                    continue
                file_path = os.path.join(i[0], file)

                def _get_file_hash(file, file_size):
                    """内部函数，不允许在外部引用。由于前面已经计算过file_size，
                    为节约效率直接把前面的计算结果作为参数传入"""
                    hasher = self.__hash_method()
                    step_size = (file_size - self.block_size) // steps
                    with open(file, "rb") as f:
                        if file_size <= min_size:
                            hasher.update(f.read())
                        else:
                            hasher.update(f.read(self.block_size))
                            for i in range(
                                step_size, (steps - 1) * step_size + 1, step_size
                            ):
                                f.seek(i, 0)
                                hasher.update(f.read(self.block_size))
                            f.seek(-self.block_size, 2)
                            hasher.update(f.read(self.block_size))
                    return hasher.hexdigest()

                file_size = os.path.getsize(file_path)
                result["file"][os.path.join(parent, file)] = {
                    "size": file_size,
                    "hash": _get_file_hash(file_path, file_size),
                }
                if QuickHash.progress_bar:
                    tq.update()
            total_dir_number += 1
        result["dir"] = list(sorted(result["dir"]))
        result["file"] = OrderedDict(sorted(result["file"].items(), key=lambda x: x[0]))
        headers = OrderedDict()
        headers["total_hash"] = ""
        headers["total_dir_number"] = total_dir_number - 1
        headers["total_file_number"] = len(result["file"])
        headers["BLOCKS"] = self.blocks
        headers["BLOCK_SIZE"] = self.block_size
        headers["HASH_METHOD"] = HASH_METHOD
        result["headers"] = headers
        result["headers"]["total_hash"] = self.__hash_method(
            ejson.dumps(result, indent=4, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        result["headers"]["QuickHash_version"] = "1.0"
        if return_new_instance:
            new_qh = QuickHash()
            new_qh.__hash_content = result
            return new_qh
        else:
            self.__hash_content = result
            return self

    def _quick_hash_v1_1(self,path:str,return_new_instance=False):
        ''':param verify:如果True，那么不修改self.hash，否则修改
        版本更新：支持配置检查文件差异的办法：修改时间、创建时间、内容，可分别启用或弃用，不推荐使用创建时间

        样例：
        ```{
    "headers": {
        "total_hash": "9b3a2cb0d9c95333919e3377d903fbc825b40b503f6b2509c408bb094439e29c",
        "total_dir_number": 34,
        "total_file_number": 190,
        "BLOCKS": 5,
        "BLOCK_SIZE": 102400,
        "HASH_METHOD": "sha256",
        "content": true,
        "ctime": false,
        "mtime": true,
        "QuickHash_version": "1.1"
    },
    "dir": [
        "Bio",
        "Ch\\红楼梦_听书",
        "寒假课程\\团课\\Ce",
        "寒假课程\\团课\\En\\新建文件夹",
        "寒假课程\\团课\\En\\问卷星\\字母默写 A（A）【8】_files"
    ],
    "file": {
        "Bio\\寒假强化训练1.pdf": {
            "size": 682896,
            "mtime": 1705882345,
            "hash": "7783c2cfc6f1a4472b51419f3560161df77edaf55470b848f7730bf4784c4ee1"
        },
        "Bio\\寒假强化训练2.pdf": {
            "size": 640132,
            "mtime": 1705882344,
            "hash": "0e84032637af09fc2f952dc0d85b9ec19ddcf67d15b22c97923a5c3516e4ace0"
        },
        "Bio\\寒假强化训练3.pdf": {
            "size": 864627,
            "mtime": 1705882344,
            "hash": "bd230a00d2949eadb4803a50dd2ed25da66de351fe2fc5fdfa38b6876c5a7fa4"
        },
        "Ch\\红楼梦_听书\\红楼梦001a甄士隐梦幻识通灵 贾雨村风尘怀闺秀（感谢赞赏）.mp3": {
            "size": 8991408,
            "mtime": 1706109004,
            "hash": "9451bd5814a15b0edef1384abe93dfa1191a7c37fea20aa42f55659b7d3714b0"
        },
        "Ch\\红楼梦_听书\\红楼梦001b甄士隐梦幻识通灵 贾雨村风尘怀闺秀.mp3": {
            "size": 10097938,
            "mtime": 1706109022,
            "hash": "42d725133c77c7ae47b2235a976d0dc3f3f4eb2487e4cea7d7f05795580a15bb"
        }
        ```'''
        assert os.path.isdir(path)
        result = {"headers": None, "dir": [], "file": OrderedDict()}
        total_dir_number = 0
        if QuickHash.progress_bar:
            total_file_number = 0
            for i, j, k in os.walk(path):
                total_file_number += len(k)
            tq = tqdm(
                total=total_file_number, mininterval=1.0, dynamic_ncols=True, delay=1.2
            )
        min_size = self.block_size * self.blocks
        steps = self.blocks - 1
        for i in os.walk(path):
            parent = os.path.relpath(i[0], path) # 遍历到的路径相对于`path`变量的路径
            if len(i[1]) == 0 and not self.matches_ignore(QuickHash.ignore,parent):
                # 只保留最底层的目录，即保存在dir里面的目录下面都没有子目录了
                result["dir"].append(parent)
            for file in sorted(i[2]):
                if self.matches_ignore(QuickHash.ignore,file):
                    continue
                file_path = os.path.join(i[0], file)

                def _get_file_hash(file, file_size = None):
                    """内部函数，不允许在外部引用。由于前面已经计算过file_size，
                    为节约效率直接把前面的计算结果作为参数传入"""
                    hasher = self.__hash_method()
                    step_size = (file_size - self.block_size) // steps
                    with open(file, "rb") as f:
                        if file_size <= min_size:
                            hasher.update(f.read())
                        else:
                            hasher.update(f.read(self.block_size))
                            for i in range(
                                step_size, (steps - 1) * step_size + 1, step_size
                            ):
                                f.seek(i, 0)
                                hasher.update(f.read(self.block_size))
                            f.seek(-self.block_size, 2)
                            hasher.update(f.read(self.block_size))
                    return hasher.hexdigest()

                temp_dict = OrderedDict()
                file_size = os.path.getsize(file_path)
                temp_dict['size'] = file_size

                if self.ctime:
                    temp_dict['ctime'] = int(os.path.getctime(file_path))
                if self.mtime:
                    temp_dict['mtime'] = int(os.path.getmtime(file_path))
                if self.content:
                    temp_dict['hash'] = _get_file_hash(file_path, file_size)
                result["file"][os.path.join(parent, file)] = temp_dict
                if QuickHash.progress_bar:
                    tq.update()
            total_dir_number += 1
        result["dir"] = list(sorted(result["dir"]))
        result["file"] = OrderedDict(sorted(result["file"].items(), key=lambda x: x[0]))
        self.__hash_content = result
        return self.update_headers(return_new_instance)
    def update_headers(self, return_new_instance=False):
        headers = OrderedDict()
        headers["total_hash"] = ""
        headers["total_dir_number"] = len(self.__hash_content['dir']) - 1
        headers["total_file_number"] = len(self.__hash_content["file"])
        headers["BLOCKS"] = self.blocks
        headers["BLOCK_SIZE"] = self.block_size
        headers["HASH_METHOD"] = self.hash_method
        headers['content'] = self.content
        headers['ctime'] = self.ctime
        headers['mtime'] = self.mtime
        result = OrderedDict()
        result["headers"] = headers
        result["headers"]["total_hash"] = self.__hash_method(
            ejson.dumps(self.__hash_content, indent=4, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        result["headers"]["QuickHash_version"] = "1.1"
        result['dir'] = self.__hash_content['dir']
        result['file'] = self.__hash_content['file']
        if return_new_instance:
            new_qh = QuickHash()
            new_qh.__hash_content = result
            return new_qh
        else:
            self.__hash_content = result
            return self


    def hash(self,path:str,return_new_instance=False):
        '''Hashes a directory, returns a QuickHash object.'''
        # 用于版本控制的函数
        if self.version == "1.0":
            return self._quick_hash_v1_0(path,return_new_instance)
        elif self.version == "1.1":
            return self._quick_hash_v1_1(path, return_new_instance)
    def to_str(self):
        '''returns a json-serialized QuickHash'''
        return ejson.dumps(self.__hash_content, ensure_ascii=False, indent=4)

    @classmethod
    def from_str(cls,hash_content):
        '''classmethod, reads a json-serialized QuickHash
        :param hash_content: bytes or str'''
        hash_content = ejson.loads(hash_content)
        if hash_content['headers']['QuickHash_version'] == '1.0':
            blocks=int(hash_content["headers"]["BLOCKS"])
            block_size=int(hash_content["headers"]["BLOCK_SIZE"])
            hash_method=hash_content["headers"]["HASH_METHOD"]
            version = hash_content["headers"]["QuickHash_version"]
            new_instance = cls(blocks, block_size, hash_method, version)
            new_instance.__hash_content = hash_content
            return new_instance
        elif hash_content['headers']['QuickHash_version'] =='1.1':
            blocks=int(hash_content["headers"]["BLOCKS"])
            block_size=int(hash_content["headers"]["BLOCK_SIZE"])
            hash_method=hash_content["headers"]["HASH_METHOD"]
            version = hash_content["headers"]["QuickHash_version"]
            content = hash_content["headers"]["content"]
            mtime = hash_content["headers"]["mtime"]
            ctime = hash_content["headers"]["ctime"]
            new_instance = cls(blocks, block_size, hash_method, mtime, ctime, content, version)
            new_instance.__hash_content = hash_content
            return new_instance

    def verify(self, path:str):

        new_hash = self.hash(path,True)
        if new_hash.__hash_content['headers']['total_hash']== self.__hash_content['headers']['total_hash']:
            return True
        else:
            return False

    def compare_with(self, hasher):
        return QuickHashCmp(self,hasher)

    @staticmethod
    def matches_ignore(ignore: list[str], dir:str):
        ''':param ignore: Iterable, 里面的字符串是Unix shell 风格的通配pattern，例如：['*.py[cod]',r'*\desktop\*']
        :param dir: Directory'''
        for pattern in ignore:
            if fnmatch.fnmatch(dir, pattern):
                return True
        return False

    def pop_item(self, dir = [], file = []):
        for i in dir:
            self.__hash_content["dir"].remove(i)
        for i in file:
            self.__hash_content["file"].pop(i)
        self.update_headers()

    def digest(self):
        return self.__hash_content["headers"]["total_hash"]

    def get_hash_content(self):
        return self.__hash_content

if __name__ == "__main__":
    QuickHash.progress_bar = False
    qh1 = QuickHash(mtime=True,content=False) # initialization
    qh1.hash(r"C:\Users\jenso\Desktop\新建文件夹\T1")
    str1 = qh1.to_str()
    print(str1)
    qh2 = QuickHash.from_str(str1)
    print(qh2.verify(r"C:\Users\jenso\Desktop\新建文件夹\T1"))
    # qh2.hash(r"C:\Users\jenso\Desktop\新建文件夹\T2")
    # QuickHashCmp(qh1, qh2).report()