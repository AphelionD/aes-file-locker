from AES import AES
from argon2 import PasswordHasher
# https://pypi.org/project/argon2-cffi/
# pip install argon2-cffi
import os
from glob import glob
from shutil import rmtree
from tqdm import tqdm
from base64 import b64decode
import sys
if sys.platform == "win32":
    # 在mac OS 系统下无法使用pywin32
    from win32file import CreateFile, SetFileTime, GetFileTime, CloseHandle
    from win32file import GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
    from pywintypes import Time
from Quick_Hash import QuickHash,QuickHashCmp
from ejson import dumps,loads
from uuid import uuid4
from rich import print
from PyQt5.QtCore import QThread, pyqtSignal
import unicodedata
CONFIG_DEFAULT = {
    'time_cost': 1,
    'memory_cost': 2097152,
    'parallelism': 5
}
configuration = {  # customize your own configuration here
    'time_cost': 1,
    'memory_cost': 2097152,  # KiB
    'parallelism': 5
}
ignores = [
    "*.afd",
    r"*.__sys*",
    "*config.json",
    "*.ini",
    "*Thumbs.db",
    "*WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt"
]
def modifyFileTime(filePath, createTime=None, modifyTime=None, accessTime=None):
    """
    用来修改任意文件的相关时间属性，传入unix时间戳
    :param filePath: 文件路径名
    :param createTime: 创建时间
    :param modifyTime: 修改时间
    :param accessTime: 访问时间
    """
    if sys.platform == "win32":
        fh = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, 0)
        createTimes, accessTimes, modifyTimes = GetFileTime(fh)
        if createTime != None:
            createTimes = Time(createTime)
        if accessTime != None:
            accessTimes = Time(accessTime)
        if modifyTime != None:
            modifyTimes = Time(modifyTime)
        SetFileTime(fh, createTimes, accessTimes, modifyTimes)
        CloseHandle(fh)
    else:
    # 在macOS下应改换成：（无法更改创建时间）
        os.utime(filePath, (accessTime, modifyTime))

def getFileTime(filename):
    '''返回：（创建时间，修改时间，访问时间）'''
    assert os.path.isfile(filename), "File %s not found" % filename
    return (os.path.getctime(filename), os.path.getmtime(filename), os.path.getatime(filename))

class Encrypt(QThread):
    # 自定义信号对象。
    pb_total_changed = pyqtSignal(int)
    pb_update = pyqtSignal(int)
    send_warning = pyqtSignal(str)
    work_thread_status_changed = pyqtSignal(str)
    task_completed = pyqtSignal()
    password_incorrect = pyqtSignal()
    clear_pb = pyqtSignal()

    def __init__(
        self,
        parent,
        vault_dir,
        file_dir,
        master_password,
        ignore_check=False,
        argon2_config=configuration,
    ):
        """:param ignore_check: whether check password when encrypting. This parameter won't be used when decrypting.
        :param argon2_config: a dictionary, like the `CONFIG_DEFAULT`. This parameter won't be used when decrypting.
        """
        super(Encrypt, self).__init__(parent)
        self.vault_dir = vault_dir
        self.file_dir = file_dir
        self.master_password = unicodedata.normalize('NFKD',master_password)
        self.ignore_check = ignore_check
        self.argon2_config = argon2_config

    def key_derivation(self, key, t, m, p, salt:bytes, msg = "正在验证密码"):
        '''使用argon2，传入配置参数'''
        self.pb_total_changed.emit(3)
        with tqdm(range(3), leave=False, smoothing=0.8) as tq: # 进度条
            tq.set_description('Verifying password')
            key = key.encode('utf-8')
            self.work_thread_status_changed.emit(msg)
            for i in tq:  # 使用argon2算法，迭代一个密码消耗3秒左右
                hasher = PasswordHasher(t,m,p,salt_len=128)
                key = hasher.hash(key, salt=salt).encode()
                self.pb_update.emit(i+1)
        self.clear_pb.emit()
        return key

    def run(self):
        afd_target_dir = os.path.join(self.vault_dir, '.__sys') # afd文件的目标路径
        QuickHash.progress_bar = False # 关闭QuickHash的进度条
        QuickHash.ignore = ignores # 设置忽略的文件
        qh = QuickHash(mtime=True)
        qh.hash(self.file_dir)
        hash_content = qh.get_hash_content()
        files = hash_content['file'].keys()
        if len(files) == 0:
            self.send_warning.emit(f'{self.file_dir}中没有文件。')
            return

        '''密码检验与密钥准备'''
        aes = AES(
            b"$L\xa7\xd1\xban!.:\x8b5\x08xI4*Xs\x19S\xf6F\xe7\x11v\xc9\x15\x10\t\x1e\xcfR\xdd\xaf\xf0\xb22\xd4\xa7\xea+\x06c\x12\x915\xad\xfb\xe7[\xe0B\xe9\x127\x0f\x84Y\x9fBg\x0f%7",
            "ECB",
        )  # 使用ECB模式初始化实例
        # 这是一个固定的密钥，用于读取config文件。加密的目的是隐藏起json的模样
        aes.b64 = False
        if not os.path.isfile(os.path.join(self.vault_dir, "config.json")) or self.ignore_check:
            # 如果是第一次加密，或者需要覆盖原本的密码，`self.ignore_check` 主要是为了防止因为输错密码而导致所有文件被加密无法找回
            self.ignore_check = True
            if os.path.exists(afd_target_dir):
                for i in glob(os.path.join(afd_target_dir, "*")):
                    os.remove(i)
            salt = os.urandom(128)
            stretched_key = self.key_derivation(
                self.master_password,
                self.argon2_config["time_cost"],
                self.argon2_config["memory_cost"],
                self.argon2_config["parallelism"],
                salt,
                "正在生成密钥"
            )
            rand_key = os.urandom(128) + b"===end==="
            updating = False # 是否使用文件动态更新
        else:
            # 验证密码
            with open(os.path.join(self.vault_dir, 'config.json'), 'rb') as f:
                read_config_json = aes.decrypt(f.read()).decode()
                read_config_json = loads(read_config_json)
            # config_json:{"argon2_configuration":"明文",
            # "password_header":[{"code":"密文","iv":b""},salt],
            # "interpreter":{"code":"密文","iv":b""},
            # "QuickHash":{"code":"密文","iv":b""},
            # "AFD_QuickHash":{"明文"}
            # }

            # 获得配置参数，新建一个read_config变量
            read_argon2_config = read_config_json['argon2_configuration']
            read_password_header = read_config_json['password_header'][0]
            read_salt = read_config_json['password_header'][1]
            read_solver = read_config_json['interpreter']
            read_quick_hash = read_config_json['QuickHash']
            stretched_key = self.key_derivation(
                self.master_password,
                read_argon2_config["time_cost"],
                read_argon2_config["memory_cost"],
                read_argon2_config["parallelism"],
                read_salt
            )
            # 使用读取的参数验证密码
            aes.key = stretched_key
            aes.mode = 'CBC'
            try:
                read_rand_key = aes.decrypt(read_password_header['code'],iv=read_password_header['iv'])
                if read_rand_key[-9:] != b'===end===':
                    raise Exception
            except Exception:
                print(f'[red]ERROR: Password incorrect for {self.vault_dir}!!![/red]')
                self.password_incorrect.emit()
                return


            salt = os.urandom(128)
            # if read_argon2_config != self.argon2_config:
            # 根据新的盐重新生成密钥
            stretched_key = self.key_derivation(
                self.master_password,
                self.argon2_config["time_cost"],
                self.argon2_config["memory_cost"],
                self.argon2_config["parallelism"],
                salt,
                "正在生成新的密钥"
            )

            updating = True
            aes.key = read_rand_key
            read_solver = aes.decrypt(read_solver['code'],iv=read_solver['iv']).decode()
            read_solver = loads(read_solver)
            read_quick_hash = aes.decrypt(read_quick_hash['code'],iv=read_quick_hash['iv']).decode()
            read_qh = QuickHash.from_str(read_quick_hash)
            rand_key = os.urandom(128) + b"===end==="

        '''验证afd文件的合法性'''
        problem_afds = []
        if not self.ignore_check:
            QuickHash.ignore = [x for x in ignores if x not in ["*.afd",r"*\.__sys*"]]
            if os.path.exists(os.path.join(self.vault_dir,'config.json')):
                read_qh_afd = QuickHash.from_str(read_config_json['AFD_QuickHash'])
                qh_afd = QuickHash().hash(afd_target_dir)
                cmp = QuickHashCmp(read_qh_afd,qh_afd)
                if not cmp.is_equal:
                    problem_afds = list(map(os.path.basename,cmp.left_only))+list(cmp.different.keys())
                    # 被改动或者删除的afd文件
                    for i in cmp.right_only+list(cmp.different.keys()):
                        os.remove(os.path.join(afd_target_dir,i))
        QuickHash.ignore = ignores

        # 到这里，需要准备好的变量：stretched_key, argon2_config（本次使用的config），rand_key, updating
        # 如果updating==True，那么要准备好read_solver, read_qh
        '''目录解释器编写与文件加密准备'''
        if not os.path.isdir(afd_target_dir):
            os.mkdir(afd_target_dir)  # 在A目录下创建文件夹
        if updating:
            problem_files = [k for k,v in read_solver.items() if v[0] in problem_afds]
            for i in problem_files:
                read_qh.pop_item(file=[i])
                del read_solver[i]
            cmp = QuickHashCmp(qh, read_qh)
            deleted_files = cmp.right_only + list(cmp.different.keys()) # 要删除的afd文件
            updated_files = cmp.left_only + list(cmp.different.keys())  # 要更新或添加的文件
            for i in deleted_files:
                if read_solver[i][0] not in problem_afds:
                    os.remove(os.path.join(afd_target_dir, read_solver[i][0])) # 删除afd 文件
                del read_solver[i] # 删除原解释器中的key
            solver = read_solver
            for i in updated_files:
                solver[i] = (str(uuid4())+'.afd',
                            os.urandom(16),
                            getFileTime(os.path.join(self.file_dir, i)),
                            os.urandom(128))
                # 把需要更新的文件添加到目录解释器
        else:
            solver = {}
            for i in files:
                solver[i] = (str(uuid4())+'.afd',
                            os.urandom(16),
                            getFileTime(os.path.join(self.file_dir, i)),
                            os.urandom(128))
        # 目录解释器结构：{相对路径文件名: (新的AFD文件名, iv向量，(创建时间，修改时间，访问时间)，每个文件的单独密钥)}

        '''文件加密'''
        aes.mode = 'CBC'
        # 设置AES CBC模式
        li = list(enumerate(solver.keys()))
        self.pb_total_changed.emit(len(li))
        with tqdm(li) as tq:
            self.work_thread_status_changed.emit("正在加密，请不要意外关闭程序")
            for index,i in tq:
                if os.path.exists(os.path.join(afd_target_dir, solver[i][0])):
                    # 如果这个文件已经存在，那么说明是之前就已经有过的一样的文件，无需再次加密
                    self.pb_update.emit(index+1)
                    continue
                # 加密文件
                with open(os.path.join(self.file_dir, i), 'rb') as f:
                    # 读取文件
                    aes.key = solver[i][3]
                    content = aes.encrypt(f.read(), iv=solver[i][1])
                with open(os.path.join(afd_target_dir, solver[i][0]), 'wb') as f:
                    # 写入文件
                    f.write(content)
                # os.remove(os.path.join(dir, i))
                self.pb_update.emit(index+1)
            self.work_thread_status_changed.emit('加密完成')

        '''打包config.json'''
        config_json = {"argon2_configuration":self.argon2_config}
        iv = os.urandom(16)
        aes.key = stretched_key
        assert aes.mode == 'CBC' # DEVELOPING
        config_json["password_header"] = [
            {"code": aes.encrypt(rand_key, iv=iv), "iv": iv},
            salt,
        ]
        iv = os.urandom(16)
        aes.key = rand_key
        config_json['interpreter'] = {
            "code":aes.encrypt(dumps(solver).encode(),iv=iv),
            "iv":iv
        }
        iv = os.urandom(16)
        aes.key = rand_key
        config_json['QuickHash'] = {
            "code":aes.encrypt(qh.to_str().encode(),iv=iv),
            "iv":iv
        }
        QuickHash.ignore = [x for x in ignores if x not in ["*.afd",r"*\.__sys*"]]
        config_json['AFD_QuickHash'] = QuickHash().hash(afd_target_dir).to_str()
        aes.key = b'$L\xa7\xd1\xban!.:\x8b5\x08xI4*Xs\x19S\xf6F\xe7\x11v\xc9\x15\x10\t\x1e\xcfR\xdd\xaf\xf0\xb22\xd4\xa7\xea+\x06c\x12\x915\xad\xfb\xe7[\xe0B\xe9\x127\x0f\x84Y\x9fBg\x0f%7'
        aes.mode = 'ECB'
        with open(os.path.join(self.vault_dir, 'config.json'), 'wb') as f:
            f.write(aes.encrypt(dumps(config_json)))
        for i in files:
            os.remove(os.path.join(self.file_dir,i))
        for i in glob(os.path.join(self.file_dir,'*')):
            if os.path.isdir(i) and not QuickHash.matches_ignore(ignores,i):
                rmtree(os.path.join(self.file_dir, i))
        if self.file_dir != self.vault_dir:
            rmtree(self.file_dir)
        self.task_completed.emit()
        return

class Decrypt(Encrypt):
    def __init__(self, parent, vault_dir,file_dir,master_password):
        super(Encrypt, self).__init__(parent)
        self.vault_dir = vault_dir
        self.file_dir = file_dir
        self.master_password = master_password

    def run(self):
        if not os.path.isdir(self.file_dir):
            os.mkdir(self.file_dir)
        if os.path.isfile(os.path.join(self.file_dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt')):
            # 在解密到一半的时候如果关闭程序或者解密失败之类，就会写入这个txt文件。
            # 如果存在“解密失败”文件，那么先把所有的个人文件删除，用AFD解密出来的文件来覆盖。
            for i in glob(os.path.join(self.file_dir, "*")):
                if QuickHash.matches_ignore(ignores,i):
                    continue
                if os.path.isdir(i):
                    rmtree(i)
                elif os.path.isfile(i):
                    os.remove(i)
        else:
            with open(os.path.join(self.file_dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt'), 'wb') as f:
                f.write(b64decode(b'V0FSTklORyEhIQpBbnkgY2hhbmdlcyB0byB5b3VyIGZpbGVzIGluIHRoaXMgZm9sZGVyIHdpbGwgbm90IGJlIHNhdmVkISEhCgrorablkYrvvIHvvIHvvIEK5a+56L+Z5Liq5paH5Lu25aS55LiL5L2g55qE5paH5Lu255qE5Lu75L2V5L+u5pS55bCG5LiN6KKr5L+d5a2Y77yB77yB77yBCgrorablkYrvvIHvvIHvvIEK5bCN6YCZ5YCL5paH5Lu25aS+5LiL5L2g55qE5paH5Lu255qE5Lu75L2V5L+u5pS55bCH5LiN6KKr5L+d5a2Y77yB77yB77yBCgrorablkYohISEK44GT44Gu44OV44Kp44Or44OA44Gu5LiL44Gr44GC44KL44OV44Kh44Kk44Or44KS5aSJ5pu044GX44Gm44KC5L+d5a2Y44GV44KM44G+44Gb44KTISEhCgrQktCd0JjQnNCQ0J3QmNCVISEhCtCb0Y7QsdGL0LUg0LjQt9C80LXQvdC10L3QuNGPINCy0LDRiNC40YUg0YTQsNC50LvQvtCyINCyINGN0YLQvtC5INC/0LDQv9C60LUg0L3QtSDQsdGD0LTRg9GCINGB0L7RhdGA0LDQvdC10L3RiyEhIQoKQVRURU5USU9OICEhIQpUb3V0ZSBtb2RpZmljYXRpb24gYXBwb3J0w6llIMOgIHZvcyBmaWNoaWVycyBkYW5zIGNlIGRvc3NpZXIgbmUgc2VyYSBwYXMgc2F1dmVnYXJkw6llICEhIQoKV0FSTlVORyEhIQpBbGxlIMOEbmRlcnVuZ2VuIGFuIElocmVuIERhdGVpZW4gaW4gZGllc2VtIE9yZG5lciB3ZXJkZW4gbmljaHQgZ2VzcGVpY2hlcnQhISEKCuqyveqzoCEhIQrsnbQg7Y+0642UIOyVhOuemOydmCDtjIzsnbzsl5Ag64yA7ZWcIOuzgOqyvSDsgqztla3snYAg7KCA7J6l65CY7KeAIOyViuyKteuLiOuLpCEhCgotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCuivt+WLv+WIoOmZpOatpOaWh+S7tuOAggpQbGVhc2UgZG8gbm90IGRlbGV0ZSB0aGlzIGZpbGUuIA=='))

        '''验证密码'''
        aes = AES(b'$L\xa7\xd1\xban!.:\x8b5\x08xI4*Xs\x19S\xf6F\xe7\x11v\xc9\x15\x10\t\x1e\xcfR\xdd\xaf\xf0\xb22\xd4\xa7\xea+\x06c\x12\x915\xad\xfb\xe7[\xe0B\xe9\x127\x0f\x84Y\x9fBg\x0f%7',
                'ECB') # 使用ECB模式初始化实例
        # 这是一个固定的密钥，用于读取config文件。加密的目的是隐藏起json的模样
        aes.b64 = False
        with open(os.path.join(self.vault_dir, 'config.json'), 'rb') as f:
            read_config_json = aes.decrypt(f.read()).decode()
            read_config_json = loads(read_config_json)
        # config_json:{"argon2_configuration":"明文",
        # "password_header":{"code":"密文","iv":b""},
        # "interpreter":{"code":"密文","iv":b""},
        # "QuickHash":{"code":"密文","iv":b""},
        # "AFD_QuickHash":{"明文"}
        # }
        # 获得配置参数，新建一个read_config变量
        read_argon2_config = read_config_json['argon2_configuration']
        read_password_header = read_config_json['password_header'][0]
        read_salt = read_config_json['password_header'][1]
        read_solver = read_config_json['interpreter']
        read_quick_hash = read_config_json['QuickHash']
        stretched_key = self.key_derivation(
            self.master_password,
            read_argon2_config["time_cost"],
            read_argon2_config["memory_cost"],
            read_argon2_config["parallelism"],
            read_salt
        )
        # 使用读取的参数验证密码
        aes.key = stretched_key
        aes.mode = 'CBC'
        # 验证密码
        try:
            read_rand_key = aes.decrypt(read_password_header['code'],iv=read_password_header['iv'])
            if read_rand_key[-9:] != b'===end===':
                raise Exception
        except Exception:
            os.remove(os.path.join(self.file_dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt'))
            if self.vault_dir!=self.file_dir:
                rmtree(self.file_dir)
            print(f'[red]ERROR: Password incorrect for {self.vault_dir}!!![/red]')
            self.password_incorrect.emit()
            return

        aes.key = read_rand_key
        read_solver = aes.decrypt(read_solver['code'],iv=read_solver['iv']).decode()
        read_solver = loads(read_solver)
        read_quick_hash = aes.decrypt(read_quick_hash['code'],iv=read_quick_hash['iv']).decode()
        read_qh = QuickHash.from_str(read_quick_hash)
        solver = {v[0]: (k, v[1], v[2],v[3]) for k, v in read_solver.items()}  # 将解释器反向
        # 结构：{AFD文件名: (相对路径文件名, iv向量，(创建时间，修改时间，访问时间), 每个文件的密钥)}

        '''验证afd文件的合法性'''
        msg = ""
        QuickHash.ignore = [x for x in ignores if x not in ["*.afd",r"*\.__sys*"]]
        if os.path.exists(os.path.join(self.vault_dir,'config.json')):
            read_qh_afd = QuickHash.from_str(read_config_json['AFD_QuickHash'])
            qh_afd = QuickHash().hash(os.path.join(self.vault_dir,'.__sys'))
            cmp = QuickHashCmp(read_qh_afd,qh_afd)
            if not cmp.is_equal:
                problems = cmp.left_only+cmp.right_only+list(cmp.different.keys())
                msg += "以下在.__sys文件中的afd文件已经损坏或丢失!!!请确保.__sys文件夹下的文件不被修改."
                print("[yellow]WARNING: These afd files in the .__sys folder are invalid!!!Make sure you don't modify the files under the .__sys folder.[/yellow]")
                for i in problems:
                    msg += f"\n{i}已经损坏或丢失，原文件{solver[os.path.basename(i)][0]}无法恢复"
                    print(f"[yellow]WARNING: {i} is invalid, the original file {solver[os.path.basename(i)][0]} will be affected.[/yellow]")
        QuickHash.ignore = ignores

        '''创建目录'''
        for i in read_qh.get_hash_content()['dir']:  # 创建目录
            if not os.path.isdir(os.path.join(self.file_dir, i)):
                os.makedirs(os.path.join(self.file_dir, i))

        aes.mode = 'CBC'
        li = list(enumerate(glob(os.path.join(self.vault_dir, '.__sys', '*.afd'))))
        self.pb_total_changed.emit(len(li))
        with tqdm(li) as tq:
            self.work_thread_status_changed.emit('正在解密')
            for index,i in tq:
                get = solver[os.path.basename(i)]
                with open(i, 'rb') as f:
                    try:
                        aes.key = get[3]
                        content = aes.decrypt(f.read(), iv=get[1])
                    except:
                        msg += f'WARNING: 在解密以下文件时发生错误：{i}， {get[0]}\n'
                        print(f'[yellow]WARNING: exception when decrypting: {i}, {get[0]}[/yellow]')
                        continue
                with open(os.path.join(self.file_dir, get[0]), 'wb') as f:
                    f.write(content)
                try:
                    if len(get)>=3:
                        modifyFileTime(os.path.join(self.file_dir, get[0]), *get[2])
                except Exception as e:
                    msg += f'WARNING: exception when modifying file time: {i}, {get[0]}\n'
                    print(f'[yellow]WARNING: exception when modifying file time: {i}, {get[0]}[/yellow]')
                    print(e)
                    continue
                self.pb_update.emit(index+1)
        if len(msg)!=0:
            self.send_warning.emit(msg)
        else:
            self.work_thread_status_changed.emit('解密完成')
            self.task_completed.emit()
        del content
        os.remove(os.path.join(self.file_dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt'))
        return