import hashlib
import os
import json
from collections import OrderedDict
from tqdm import tqdm
import fnmatch

hash_method_table = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
    "sha512": hashlib.sha512,
    "sha384": hashlib.sha384,
}
HASH_METHOD = "sha256"
BLOCKS = 5  # how many blocks of bytes to hash in a file
BLOCK_SIZE = 102400  # 10KiB = 102400B

def matches_ignore(ignore: list[str], dir:str):
    ''':param ignore: Iterable, 里面的字符串是Unix shell 风格的通配pattern，例如：['*.py[cod]',r'*\desktop\*']
    :param dir: Directory'''
    for pattern in ignore:
        if fnmatch.fnmatch(dir, pattern):
            return True
    return False
def get_relative_dir(a, b):
    """获取a相对于b的路径.
    \n例如，返回：存志群里的音频资料\音标听力\光盘1\9. 巩固练习\巩固练习 01.mp3"""
    assert isinstance(a, str) and isinstance(b, str), "param 'a' and 'b' must be string"
    return a.replace(b, "").strip("\\")  # 这种方式也许在别的操作系统上面会出现问题

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
        self.compare()
        '''可以获取两个文件夹是否相等'''
    def compare(self):
        if self.left_hasher.version != self.right_hasher.version:
            raise VersionError(f'left is of QuickHash version {self.left_hasher.version} while right is of QuickHash version {self.right_hasher.version},\
                               cannot compare two hashes with different versions')
        hashl = self.left_hasher.hash
        hashr = self.right_hasher.hash

        if hashl['headers']['total_hash'] == hashr['headers']['total_hash']:
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
        if len(self.left_only)!=0:
            print('These files are only in the left hasher:')
            for i in self.left_only:
                print(i)
            print('-'*80)
        if len(self.right_only)!=0:
            print('These files are only in the right hasher:')
            for i in self.right_only:
                print(i)
            print('-'*80)
        if len(self.different)!=0:
            print('Different files:')
            print(self.different.items())
            print('-'*80)
        if len(self.left_dir_only) != 0:
            print('These directories are only in the left: ')
            for i in self.left_dir_only:
                print(i)
            print('-'*80)
        if len(self.right_dir_only)!=0:
            print('These directories are only in the right: ')
            for i in self.right_dir_only:
                print(i)
    def clear_cache(self):
        self.left_only = []
        self.right_only = []
        self.different = {}

class QuickHash():
    def __init__(
        self,
        progress_bar=True,
        blocks=BLOCKS,
        block_size=BLOCK_SIZE,
        hash_method=HASH_METHOD,
        ignore=["QuickHash.json", "Thumbs.db"],
        mtime = False,
        ctime = False,
    ):
        self.progress_bar = progress_bar
        self.__hash_method = hash_method_table[hash_method]
        self.blocks = blocks
        self.block_size = block_size
        self.ignore = ignore
        self.hash_content = ''
        self.version = "1.1"
        self.mtime = mtime
        self.ctime = ctime

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
        self.__hash_method =hash_method_table[value]
        return value

    def quick_hash_v1_0(self,path:str,verify=False):
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
        if self.progress_bar:
            total_file_number = 0
            for i, j, k in os.walk(path):
                total_file_number += len(k)
            tq = tqdm(
                total=total_file_number, mininterval=1.0, dynamic_ncols=True, delay=1.2
            )
        min_size = self.block_size * self.blocks
        steps = self.blocks - 1
        for i in os.walk(path):
            parent = get_relative_dir(i[0], path)
            if len(i[1]) == 0:  # 只保留最底层的目录
                result["dir"].append(parent)
            for file in sorted(i[2]):
                if matches_ignore(self.ignore,file):
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
                if self.progress_bar:
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
            json.dumps(result, indent=4, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        result["headers"]["QuickHash_version"] = "1.0"
        if verify:
            new_qh = QuickHash()
            new_qh.hash_content = result
            return new_qh
        else:
            self.hash_content = result
            return self

    def quick_hash_v1_1(self,path:str,verify=False):
        ''':param verify:如果True，那么不修改self.hash，否则修改
        版本更新：支持配置是否使用ctime, mtime作为比较时的参考标准

        样例：
        ```{
    "headers": {
        "total_hash": "9b3a2cb0d9c95333919e3377d903fbc825b40b503f6b2509c408bb094439e29c",
        "total_dir_number": 34,
        "total_file_number": 190,
        "BLOCKS": 5,
        "BLOCK_SIZE": 102400,
        "HASH_METHOD": "sha256",
        "ctime": false,
        "mtime": true,
        "QuickHash_version": "1.1"
    },
    "dir": [
        "Bio",
        "Ch\\红楼梦_听书",
        "寒假课程\\团课\\Ce",
        "寒假课程\\团课\\En\\新建文件夹",
        "寒假课程\\团课\\En\\问卷星\\字母默写 A（A）【8】_files",
        "寒假课程\\团课\\En\\问卷星\\字母默写 A（B）【8】_files",
        "寒假课程\\团课\\En\\问卷星\\字母默写 A（C）【8】_files",
        "寒假课程\\团课\\En\\问卷星\\字母默写 B（A）【8】_files",
        "寒假课程\\团课\\Mt",
        "寒假课程\\团课\\Phy",
        "寒假课程\\团课\\录屏\\2024.01.14",
        "寒假课程\\团课\\录屏\\2024.01.19",
        "寒假课程\\团课\\录屏\\2024.01.20",
        "寒假课程\\团课\\录屏\\2024.01.22",
        "寒假课程\\团课\\录屏\\2024.01.23",
        "寒假课程\\团课\\录屏\\2024.01.24",
        "寒假课程\\团课\\录屏\\2024.01.25",
        "寒假课程\\团课\\录屏\\2024.01.26",
        "寒假课程\\团课\\录屏\\2024.01.27",
        "寒假课程\\团课\\录屏\\2024.01.28",
        "寒假课程\\团课\\录屏\\2024.01.29",
        "寒假课程\\团课\\录屏\\2024.01.30",
        "寒假课程\\团课\\录屏\\2024.01.31",
        "寒假课程\\团课\\录屏\\2024.02.01",
        "寒假课程\\学校网课\\录屏\\2024.01.26",
        "寒假课程\\学校网课\\录屏\\2024.01.27"
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
        },
        "Ch\\红楼梦_听书\\红楼梦002a贾夫人仙逝扬州城 冷子兴演说荣国府（感谢赞赏）.mp3": {
            "size": 6028270,
            "mtime": 1706109025,
            "hash": "2770e73993b8723cfa66b1d1b8a2efabc53178ec1f9d9f229ee335c75612c67b"
        },
        "Ch\\红楼梦_听书\\红楼梦002b贾夫人仙逝扬州城 冷子兴演说荣国府（感谢赞赏）.mp3": {
            "size": 7988707,
            "mtime": 1706109048,
            "hash": "cf6fd351a55597c6e258fe014a35906bcc85da79028eb4f19216b455725b74a9"
        },
        "Ch\\红楼梦_听书\\红楼梦003a托内兄如海荐西宾 接外孙贾母惜孤女（感谢赞赏）.mp3": {
            "size": 8876453,
            "mtime": 1706109049,
            "hash": "34e0bb5df8a151fc850cc543a6ed8c0f010c07e6315ab949fac84f864f2c222e"
        },
        "Ch\\红楼梦_听书\\红楼梦003b托内兄如海荐西宾 接外孙贾母惜孤女（感谢赞赏）.mp3": {
            "size": 10073697,
            "mtime": 1706161693,
            "hash": "18edef88c10e9fa05382cf03b90e6d95beb6830a55b3a13905ddce86025e7990"
        },
        "Ch\\红楼梦_听书\\红楼梦004a薄命女偏逢薄命郎 葫芦僧判断葫芦案（感谢赞赏）.mp3": {
            "size": 7530850,
            "mtime": 1706109067,
            "hash": "f069bc55e6614058f3ca02c4daf650f831602f2c70a4ad683c78b229768fd30d"
        },
        "Ch\\红楼梦_听书\\红楼梦004b薄命女偏逢薄命郎 葫芦僧判断葫芦案（感谢赞赏）.mp3": {
            "size": 4766050,
            "mtime": 1706109073,
            "hash": "fd619a5a3743efaa7554101ee7f840fccc509a83bbedd2d597aeca93c08b7496"
        },
        "Ch\\红楼梦_听书\\红楼梦005a贾宝玉神游太虚境 警幻仙曲演红楼梦（感谢赞赏）.mp3": {
            "size": 10560201,
            "mtime": 1706109079,
            "hash": "11695a13622939b8c6974305491b7bf5716573421cc2a7132567aefd6dee7eaa"
        },
        "Ch\\红楼梦_听书\\红楼梦005b贾宝玉神游太虚境 警幻仙曲演红楼梦（欢迎赞赏）.mp3": {
            "size": 11860907,
            "mtime": 1706109087,
            "hash": "6b5fdf86f28cb2c8a08e4dc9a66c6041620ace2075a4c82b5c12824742163495"
        },
        "Ch\\红楼梦_听书\\红楼梦006a 贾宝玉初试云雨情 刘姥姥一进荣国府（感谢赞赏）.mp3": {
            "size": 7923732,
            "mtime": 1706109096,
            "hash": "4edc8e2a8252febc1c8c19ff32bc35c259fa01a594ba272cb1bdc9415eb6e68d"
        },
        "Ch\\红楼梦_听书\\红楼梦006b 贾宝玉初试云雨情 刘姥姥一进荣国府（感谢赞赏）.mp3": {
            "size": 8000636,
            "mtime": 1706109207,
            "hash": "2f379ffb95a36fc63c2453eab449a092155987ddf341b40583d74ed7367dfbf2"
        },
        "Ch\\红楼梦_听书\\红楼梦007a送宫花贾琏戏熙凤 宴宁府宝玉会秦钟（感谢赞赏）.mp3": {
            "size": 8073152,
            "mtime": 1706109245,
            "hash": "472172ea884719d8464f5a113b142c75e852fc6eebcf7a7e261bca515d854b78"
        },
        "Ch\\红楼梦_听书\\红楼梦007b送宫花贾琏戏熙凤 宴宁府宝玉会秦钟.mp3": {
            "size": 7753831,
            "mtime": 1706109265,
            "hash": "441ae2b885a66de7a080104a97064fe1152cd860a125e2245fce90fce721c0a3"
        },
        "Ch\\红楼梦_听书\\红楼梦008a贾宝玉奇缘识金锁 薛宝钗巧合认通灵.mp3": {
            "size": 7424479,
            "mtime": 1706109284,
            "hash": "ee48921163d202795f383eb6398019775f2712eafa4aa09f57500e68a1121a03"
        },
        "Ch\\红楼梦_听书\\红楼梦008b贾宝玉奇缘识金锁 薛宝钗巧合认通灵.mp3": {
            "size": 7044973,
            "mtime": 1706109313,
            "hash": "3208699f7b0bf639fb0f9dc5f8c89a291674389c61598775b27731aca165c293"
        },
        "Ch\\红楼梦_听书\\红楼梦009a训劣子李贵承申饬 嗔顽童茗烟闹书房 (6).mp3": {
            "size": 5941769,
            "mtime": 1706111140,
            "hash": "5575297ca8c17ca0e33f7e4c306861527cc1ff638c00311aafe6277925b238e3"
        },
        "Ch\\红楼梦_听书\\红楼梦009b训劣子李贵承申饬 嗔顽童茗烟闹书房.mp3": {
            "size": 6105818,
            "mtime": 1706160977,
            "hash": "3263b69387ab76b93e012b0f363347795e8ea8f647fe58102e04c6a52fe40620"
        },
        "Ch\\红楼梦_听书\\红楼梦010a金寡妇贪利权受辱 张太医论病细穷源（感谢赞赏）.mp3": {
            "size": 6488234,
            "mtime": 1706111424,
            "hash": "4a56c1e32791e224a51320d30da17a6700f9247c13d8d0074e331114ac573de7"
        },
        "Ch\\红楼梦_听书\\红楼梦010b金寡妇贪利权受辱 张太医论病细穷源（感谢赞赏）.mp3": {
            "size": 4113181,
            "mtime": 1706111437,
            "hash": "28c9dd89405f203876ffc18f12f43910b90495ea89966e2bef7023195a2ff2ca"
        },
        "Ch\\红楼梦_听书\\红楼梦011a庆寿辰宁府排家宴 见熙凤贾瑞起淫心.mp3": {
            "size": 5550751,
            "mtime": 1706111558,
            "hash": "e29a040e76925b8e331ac5f91ff3da0e48160fd492202a22f11fb258d4d9c99d"
        },
        "Ch\\红楼梦_听书\\红楼梦011b庆寿辰宁府排家宴 见熙凤贾瑞起淫心.mp3": {
            "size": 7023640,
            "mtime": 1706111701,
            "hash": "178a3a73342fba1890b1ba257d1b7387b86cdf1fe022b8626f9cb5122397fdac"
        },
        "Ch\\红楼梦_听书\\红楼梦012a王熙凤毒设相思局 贾天祥正照风月鉴.mp3": {
            "size": 5246895,
            "mtime": 1706111588,
            "hash": "c0e7460d52a8bc8b0eb21d29caa24d4a044c4d630061ff829b1e1ad9c738075c"
        },
        "Ch\\红楼梦_听书\\红楼梦012b王熙凤毒设相思局 贾天祥正照风月鉴.mp3": {
            "size": 4742000,
            "mtime": 1706111602,
            "hash": "7d5c6991b2c58b872e60e081564df0868156e7ee48e234b34ce5c9d9ace733c5"
        },
        "Ch\\红楼梦_听书\\红楼梦013a秦可卿死封龙禁尉 王熙凤协理宁国府.mp3": {
            "size": 5969338,
            "mtime": 1706111617,
            "hash": "349664920aaffcdaa2feba28d209f5e09ae31ee96f92e3d95fae44740c3a9654"
        },
        "Ch\\红楼梦_听书\\红楼梦013b秦可卿死封龙禁尉 王熙凤协理宁国府.mp3": {
            "size": 6202350,
            "mtime": 1706111632,
            "hash": "593b19a2c2ce833e90ccb0f35fed89e0d533e03c04c9defb813212caa9c95250"
        },
        "Ch\\红楼梦_听书\\红楼梦014a林如海灵返苏州郡 贾宝玉路谒北静王 (1).mp3": {
            "size": 5930467,
            "mtime": 1706111661,
            "hash": "602cb05cc1c8e060a281e9e51141abb6884415370e8dc6335dc1c8f19d78c627"
        },
        "Ch\\红楼梦_听书\\红楼梦014b林如海灵返苏州郡 贾宝玉路谒北静王（感谢赞赏）.mp3": {
            "size": 6378311,
            "mtime": 1706161022,
            "hash": "b3b9bb4074c173c976265a79a8bea834358bc14b1d88590153a4f12394bb7fb3"
        },
        "Ch\\红楼梦_听书\\红楼梦015a王凤姐弄权铁槛寺 秦鲸卿得趣馒头庵.mp3": {
            "size": 5284302,
            "mtime": 1706161038,
            "hash": "e3cab4812f1574661ba68d8a85cfbbde7b61b8ef17f72b60bff5c170f34d0ad1"
        },
        "Ch\\红楼梦_听书\\红楼梦015b王凤姐弄权铁槛寺 秦鲸卿得趣馒头庵.mp3": {
            "size": 6059826,
            "mtime": 1706161053,
            "hash": "f0e0d6887bebfdcc7af3dba30a49f37e70a5ce59259b92c68a24246fcb63a38c"
        },
        "Ch\\红楼梦_听书\\红楼梦016a贾元春才选凤藻宫 秦鲸卿夭逝黄泉路.mp3": {
            "size": 8054954,
            "mtime": 1706161082,
            "hash": "b291f024c23ce87752e8181198473a86ddea641e57cf837c007ad7712e45a76f"
        },
        "Ch\\红楼梦_听书\\红楼梦016b贾元春才选凤藻宫 秦鲸卿夭逝黄泉路.mp3": {
            "size": 8629230,
            "mtime": 1706161083,
            "hash": "20efbeb3a17c9abc458c4e30347e1adade516a11a24f26a16a573ce7222bbe8a"
        },
        "Ch\\红楼梦_听书\\红楼梦017a大观园试才题对额 荣国府归省庆元宵.mp3": {
            "size": 8745840,
            "mtime": 1706161095,
            "hash": "850368ffa5a44b8f149feb85ff404e68b78c5c48d4cb5a847241cd7d7b1ac326"
        },
        "Ch\\红楼梦_听书\\红楼梦017b大观园试才题对额 荣国府归省庆元宵.mp3": {
            "size": 6967842,
            "mtime": 1706161104,
            "hash": "21d416b4ac03367b0305c23746381d3a82ef184e0c0a85f57b34bee5bd192c40"
        },
        "Ch\\红楼梦_听书\\红楼梦018a皇恩重元妃省父母 天伦乐宝玉呈才藻.mp3": {
            "size": 8161325,
            "mtime": 1706161115,
            "hash": "234c56e9b16b2ca6b1d814854a2f65ce233a77a8e80b6b50df90d04679831264"
        },
        "Ch\\红楼梦_听书\\红楼梦018b皇恩重元妃省父母 天伦乐宝玉呈才藻.mp3": {
            "size": 9486882,
            "mtime": 1706161127,
            "hash": "23b7b1782a9ce23e3de903cb42f3de58180334e4f592ba6395968af2b36dc931"
        },
        "Ch\\红楼梦_听书\\红楼梦019a情切切良宵花解语 意绵绵静日玉生香.mp3": {
            "size": 6535672,
            "mtime": 1706161139,
            "hash": "00c2c3313eef5915b0730651fbe5ad9d21590c93ac17e4fc97e9e629851df939"
        },
        "Ch\\红楼梦_听书\\红楼梦019b情切切良宵花解语 意绵绵静日玉生香.mp3": {
            "size": 8323911,
            "mtime": 1706161191,
            "hash": "f5ac470f0c862d2eb12e410b64fe64536160adb42b90fe79907d5a73f6f5f950"
        },
        "Ch\\红楼梦_听书\\红楼梦020a
        ```'''
        assert os.path.isdir(path)
        result = {"headers": None, "dir": [], "file": OrderedDict()}
        total_dir_number = 0
        if self.progress_bar:
            total_file_number = 0
            for i, j, k in os.walk(path):
                total_file_number += len(k)
            tq = tqdm(
                total=total_file_number, mininterval=1.0, dynamic_ncols=True, delay=1.2
            )
        min_size = self.block_size * self.blocks
        steps = self.blocks - 1
        for i in os.walk(path):
            parent = get_relative_dir(i[0], path) # 遍历到的路径相对于`path`变量的路径
            if len(i[1]) == 0:  # 只保留最底层的目录，即保存在dir里面的目录下面都没有子目录了
                result["dir"].append(parent)
            for file in sorted(i[2]):
                if matches_ignore(self.ignore,file):
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
                temp_dict['hash'] = _get_file_hash(file_path, file_size)
                result["file"][os.path.join(parent, file)] = temp_dict
                if self.progress_bar:
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
        headers["HASH_METHOD"] = self.hash_method
        headers['ctime'] = self.ctime
        headers['mtime'] = self.mtime
        result["headers"] = headers
        result["headers"]["total_hash"] = self.__hash_method(
            json.dumps(result, indent=4, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        result["headers"]["QuickHash_version"] = "1.1"
        if verify:
            new_qh = QuickHash()
            new_qh.hash_content = result
            return new_qh
        else:
            self.hash_content = result
            return self

    def quick_hash(self,path:str,verify=False):
        # 用于版本控制的函数
        if self.version == "1.0":
            return self.quick_hash_v1_0(path,verify)
        elif self.version == "1.1":
            return self.quick_hash_v1_1(path, verify)
    def to_str(self):
        '''returns a json-serialized QuickHash'''
        return json.dumps(self.hash_content, ensure_ascii=False, indent=4)
    def from_str(self,hash_content:str|bytes):
        '''reads a json-serialized QuickHash'''
        if self.version == '1.0':
            self.hash_content = json.loads(hash_content)
            self.blocks=int(self.hash_content["headers"]["BLOCKS"])
            self.block_size=int(self.hash_content["headers"]["BLOCK_SIZE"])
            self.hash_method=self.hash_content["headers"]["HASH_METHOD"]
            self.version = self.hash_content["headers"]["QuickHash_version"]
            return self
        elif self.version =='1.1':
            self.hash_content = json.loads(hash_content)
            self.blocks=int(self.hash_content["headers"]["BLOCKS"])
            self.block_size=int(self.hash_content["headers"]["BLOCK_SIZE"])
            self.hash_method=self.hash_content["headers"]["HASH_METHOD"]
            self.version = self.hash_content["headers"]["QuickHash_version"]
            self.mtime = self.hash_content["headers"]["mtime"]
            self.ctime = self.hash_content["headers"]["ctime"]
            return self

    def verify(self, path:str):

        new_hash = self.quick_hash(path,True)
        if new_hash.hash_content['headers']['total_hash']== self.hash_content['headers']['total_hash']:
            return True
        else:
            return False

    def compare_with(self, hasher):
        return QuickHashCmp(self,hasher)




if __name__ == "__main__":
    qh1 = QuickHash(mtime=True,progress_bar=False) # initialization
    qh1.quick_hash(r"C:\Users\jenso\Desktop\新建文件夹\T1")
    str1 = qh1.to_str()
    print(str1)
    qh2 = QuickHash()
    qh2.from_str(str1)
    qh2.quick_hash(r"C:\Users\jenso\Desktop\新建文件夹\T2")
    QuickHashCmp(qh1, qh2).report()
