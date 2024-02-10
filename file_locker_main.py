'''AES_file_locker [version 1.6.0]
Powered by Python.
(c)2024 Illumination Studio, Yanteen Technology,.Ltd.'''
from AES import AES
from GUI import GUI
import hashlib
from argon2 import PasswordHasher
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
from tkinter import ttk
from win32file import CreateFile, SetFileTime, GetFileTime, CloseHandle
from win32file import GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
from pywintypes import Time  # 可以忽视这个 Time 报错（运行程序还是没问题的）
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
    if os.path.isfile(os.path.join(dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt')):
        return True
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

def copy_dir(path):
    '''获取这个路径下的所有文件和文件夹，使用相对路径

    返回：[[dir1, dir2, ...], [file1, file2, ...]]'''
    files = []
    directories = []
    for i in os.walk(path):
        for x in i[2]:
            files.append(os.path.relpath(os.path.join(i[0], x), path))
        if i[0] == path:
            continue
        directories.append(os.path.relpath(i[0], path))
    return [directories, files]


def md5(fname,  is_file_dir=None, encoding='utf-8'):
    ''':param fname: 自动解释，可传入file directory, str, bytes\n
        :param is_file_dir: 强制指定是否为file directory，传入bool或None，None时自动判断\n
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

def modifyFileTime(filePath, createTime=None, modifyTime=None, accessTime=None):
    """
    用来修改任意文件的相关时间属性，传入unix时间戳
    :param filePath: 文件路径名
    :param createTime: 创建时间
    :param modifyTime: 修改时间
    :param accessTime: 访问时间
    """
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

def getFileTime(filename):
    '''返回：（创建时间，修改时间，访问时间）'''
    assert os.path.isfile(filename), "File %s not found" % filename
    return (os.path.getctime(filename), os.path.getmtime(filename), os.path.getatime(filename))

def encrypt_dir(dir, master_password, ignore_check=False, config=configuration, instance = None):
    ''':param ignore_check: whether check password when encrypting
    :param config: a dictionary, like the `CONFIG_DEFAULT`
    :param instance: a GUI instance, for handling progressbar and other GUI interactions'''
    def key_derivation(key, t, m, p):
        '''使用argon2，传入配置参数'''
        with tqdm(range(3), leave=False, smoothing=0.8) as tq: # 进度条
            tq.set_description('Verifying password')
            key = key.encode('utf-8')
            if instance!=None: #对GUI实例进行进度条更新
                assert isinstance(instance,GUI), "param 'instance' must be a GUI instance"
                instance.info.set('Verifying password')
                instance.pb = ttk.Progressbar(instance.root, length=instance.root.winfo_width())
                instance.pb['maximum'] = 3
                instance.pb['value'] = 0
                instance.pb.grid(row=4, column=0, columnspan=3)
                instance.root.update()
            for i in tq:  # 使用argon2算法，迭代一个密码消耗3秒左右
                hasher = PasswordHasher(t,m,p)
                key = hasher.hash(key, salt=b'This is salt').encode()
                if instance != None:
                    instance.pb['value']=i+1
                    instance.root.update()
            if instance!=None:
                instance.pb.grid_forget()
        return key
    config_input = config
    target_dir = os.path.join(dir, '.__sys') # 目标路径
    dirs, files = copy_dir(dir) # 克隆文件结构
    files = list(filter(lambda x: x != '__Solver.dll' \
                            and x !='__Status.sti' \
                            and os.path.splitext(x)[1] != '.afd' \
                            and x != "WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt",
                        files)) # 筛选所有需要加密的文件和文件夹
    if len(files) == 0:
        print(f'WARNING: No files in {dir}!!!')
        return False
    dirs = list(filter(lambda x: x != os.path.relpath(target_dir, dir), dirs))
    aes = AES('所有侵犯隐私者将受到严惩。', 'ECB') # 创建AES实例
    aes.b64 = False
    if not os.path.isfile(os.path.join(dir, '__Status.sti')) or ignore_check:
        # 如果是第一次加密或者需要覆盖原本的密码，`ignore_check` 主要是为了防止因为输错密码而导致所有文件被加密无法找回
        stretched_key = key_derivation(
            master_password, config['time_cost'], config['memory_cost'], config['parallelism'])
        rand_key = os.urandom(random.randint(60, 90)) + b'===end==='
        config_bytes = aes.encrypt(json.dumps(config).encode('utf-8'))
        # 加密argon2配置参数，使其能隐藏在__satus.sti文件里面而不凸显出来
        config_bytes = config_bytes + int.to_bytes(len(config_bytes), 2, 'big')
        aes.key = stretched_key
        with open(os.path.join(dir, '__Status.sti'), 'wb') as f:
            f.write(aes.encrypt(rand_key)+config_bytes) # __Status.sti 结构：加密后的rand_key+加密后的config_bytes
    else:
        with open(os.path.join(dir, '__Status.sti'), 'rb') as f:  # 先验证密码
            content = f.read()
            config_len = int.from_bytes(content[-2:], 'big')
            config = json.loads(aes.decrypt(
                content[-2-config_len:-2]).decode('utf-8'))
            rand_key = content[:-2-config_len]
            stretched_key = key_derivation(
                master_password, config['time_cost'], config['memory_cost'], config['parallelism'])
            # 获得配置参数
            aes.key = stretched_key
            try: # 验证密码
                rand_key = aes.decrypt(rand_key)
                if rand_key[-9:] != b'===end===':
                    raise Exception
            except:
                print(f'ERROR: Password incorrect for {dir}!!!')
                return False
            aes.key = '所有侵犯隐私者将受到严惩。'
            if config != config_input: # 如果函数传入的配置参数和从__Status.sti文件中提取出来的参数不一致，则使用传入的参数
                stretched_key = key_derivation(
                    master_password, config_input['time_cost'], config_input['memory_cost'], config_input['parallelism'])
                config_bytes = aes.encrypt(
                    json.dumps(config_input).encode('utf-8'))
                config_bytes = config_bytes + \
                    int.to_bytes(len(config_bytes), 2, 'big')
            else:
                config_bytes = aes.encrypt(json.dumps(config).encode('utf-8'))
                config_bytes = config_bytes + \
                    int.to_bytes(len(config_bytes), 2, 'big')

            rand_key = os.urandom(random.randint(60, 90)) + b'===end==='
            aes.key = stretched_key
            with open(os.path.join(dir, '__Status.sti'), 'wb') as f:
                f.write(aes.encrypt(rand_key) + config_bytes)
    random.shuffle(files)
    if not os.path.isdir(target_dir):
        os.mkdir(target_dir)  # 在A目录下创建文件夹
    else:
        for i in glob(os.path.join(target_dir, '*')):
            os.remove(i)
    solver = {}  # 初始化目录解释器
    salt = os.urandom(10)
    for index, file in enumerate(files): # 进行目录解释，为每一个文件指定新的独一无二的文件名
        solver[file] = (md5(bytes(str(index), encoding='ascii') + salt)+'.afd', os.urandom(16), getFileTime(os.path.join(dir, file)))
    # 目录解释器结构：{相对路径文件名: (新的AFD文件名, iv向量，(创建时间，修改时间，访问时间))}
    aes.key = rand_key
    aes.mode = 'CBC'
    # 设置AES CBC模式
    with tqdm(enumerate(files)) as tq:
        if instance!=None: # 进度条
            assert isinstance(instance, GUI), "param 'instance' must be a GUI instance"
            instance.info.set('encrypting...')
            instance.pb = ttk.Progressbar(instance.root, length=instance.root.winfo_width())
            instance.pb['value'] = 0
            instance.pb['maximum'] = len(files)
            instance.pb.grid(row=4, column=0, columnspan=3)
            instance.pb
            instance.root.update()
        for index,i in tq:
            # 加密文件
            with open(os.path.join(dir, i), 'rb') as f:
                content = aes.encrypt(f.read(), iv=solver[i][1])
            with open(os.path.join(target_dir, solver[i][0]), 'wb') as f:
                f.write(content)
            if instance!=None:
                instance.pb['value']=index+1
                instance.root.update()
        if instance!=None:
            instance.pb.grid_forget()
            instance.info.set('completed')
    for i in solver.keys():
        # 由于json不支持传入bytes，因此把iv向量用base64转码（使用ascii）
        solver[i] = (solver[i][0], b64encode(solver[i][1]).decode('ascii'), solver[i][2])
    solver = json.dumps([solver, dirs], ensure_ascii=False,
                        indent=4)  # 序列化解释器（与dirs列表打包）
    aes.mode = 'ECB'
    with open(os.path.join(dir, '__Solver.dll'), 'wb') as f:
        f.write(aes.encrypt(solver))  # 加密解释器
    for i in files:
        with open(os.path.join(dir, i), 'wb') as f:
            f.write(b'')
        os.remove(os.path.join(dir, i))
    for i in dirs:
        if os.path.isdir(os.path.join(dir, i)):
            rmtree(os.path.join(dir, i))
    return True


def decrypt_dir(dir, master_password, instance=None):
    if os.path.isfile(os.path.join(dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt')):
        # 在解密到一半的时候如果关闭程序或者解密失败之类，就会写入这个txt文件。
        # 如果存在“解密失败”文件，那么先把所有的个人文件删除，用AFD解密出来的文件来覆盖。
        for i in glob(os.path.join(dir, "*")):
            if i== os.path.join(dir, ".__sys") \
                or i == os.path.join(dir, "__Solver.dll") \
                or i == os.path.join(dir, "__Status.sti") \
                or i == os.path.join(dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt'):
                continue
            if os.path.isdir(i):
                rmtree(i)
            elif os.path.isfile(i):
                os.remove(i)
    else:
        with open(os.path.join(dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt'), 'wb') as f:
            f.write(b64decode(b'V0FSTklORyEhIQpBbnkgY2hhbmdlcyB0byB5b3VyIGZpbGVzIGluIHRoaXMgZm9sZGVyIHdpbGwgbm90IGJlIHNhdmVkISEhCgrorablkYrvvIHvvIHvvIEK5a+56L+Z5Liq5paH5Lu25aS55LiL5L2g55qE5paH5Lu255qE5Lu75L2V5L+u5pS55bCG5LiN6KKr5L+d5a2Y77yB77yB77yBCgrorablkYrvvIHvvIHvvIEK5bCN6YCZ5YCL5paH5Lu25aS+5LiL5L2g55qE5paH5Lu255qE5Lu75L2V5L+u5pS55bCH5LiN6KKr5L+d5a2Y77yB77yB77yBCgrorablkYohISEK44GT44Gu44OV44Kp44Or44OA44Gu5LiL44Gr44GC44KL44OV44Kh44Kk44Or44KS5aSJ5pu044GX44Gm44KC5L+d5a2Y44GV44KM44G+44Gb44KTISEhCgrQktCd0JjQnNCQ0J3QmNCVISEhCtCb0Y7QsdGL0LUg0LjQt9C80LXQvdC10L3QuNGPINCy0LDRiNC40YUg0YTQsNC50LvQvtCyINCyINGN0YLQvtC5INC/0LDQv9C60LUg0L3QtSDQsdGD0LTRg9GCINGB0L7RhdGA0LDQvdC10L3RiyEhIQoKQVRURU5USU9OICEhIQpUb3V0ZSBtb2RpZmljYXRpb24gYXBwb3J0w6llIMOgIHZvcyBmaWNoaWVycyBkYW5zIGNlIGRvc3NpZXIgbmUgc2VyYSBwYXMgc2F1dmVnYXJkw6llICEhIQoKV0FSTlVORyEhIQpBbGxlIMOEbmRlcnVuZ2VuIGFuIElocmVuIERhdGVpZW4gaW4gZGllc2VtIE9yZG5lciB3ZXJkZW4gbmljaHQgZ2VzcGVpY2hlcnQhISEKCuqyveqzoCEhIQrsnbQg7Y+0642UIOyVhOuemOydmCDtjIzsnbzsl5Ag64yA7ZWcIOuzgOqyvSDsgqztla3snYAg7KCA7J6l65CY7KeAIOyViuyKteuLiOuLpCEhCgotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCuivt+WLv+WIoOmZpOatpOaWh+S7tuOAggpQbGVhc2UgZG8gbm90IGRlbGV0ZSB0aGlzIGZpbGUuIA=='))

    aes = AES('所有侵犯隐私者将受到严惩。', 'ECB')
    aes.b64 = False
    with open(os.path.join(dir, '__Status.sti'), 'rb') as f:  # 验证密码
        content = f.read()
        config_len = int.from_bytes(content[-2:], 'big')
        config = json.loads(aes.decrypt(
            content[-2-config_len:-2]).decode('utf-8'))
        rand_key = content[:-2-config_len]
        with tqdm(range(3), leave=False, smoothing=0.8) as tq:
            tq.set_description('Verifying password')
            master_password = master_password.encode('utf-8')
            if instance!=None:
                assert isinstance(instance,GUI), "param 'instance' must be a GUI instance"
                instance.info.set('Verifying password')
                instance.pb = ttk.Progressbar(instance.root, length=instance.root.winfo_width())
                instance.pb['maximum'] = 3
                instance.pb['value'] = 0
                instance.pb.grid(row=4, column=0, columnspan=3)
                instance.root.update()
            for i in tq:  # 使用argon2算法，迭代一个密码消耗3秒左右
                hasher = PasswordHasher(config['time_cost'], config['memory_cost'], config['parallelism'])
                master_password = hasher.hash(master_password, salt = b'This is salt').encode()
                # 如果不使用强制的salt，argon2会自动使用一个随机数作为salt，此时需要使用PasswordHasher().verify()的方法，即每次生成的stretched key都不尽相同，不适用于本程序
                if instance != None:
                    instance.pb['value']=i+1
                    instance.root.update()
            if instance != None:
                instance.pb.grid_forget()
                instance.root.update()
        try:
            aes.key = master_password
            rand_key = aes.decrypt(rand_key)
            if rand_key[-9:] != b'===end===':
                raise Exception
        except:
            print(f'ERROR: Password incorrect for {dir}!!!')
            return False
    aes.key = rand_key
    with open(os.path.join(dir, '__Solver.dll'), 'rb') as f:
        solver, dirs = json.loads(aes.decrypt(f.read()))  # 加载目录解释器
    for i in dirs:  # 创建目录
        if not os.path.isdir(os.path.join(dir, i)):
            os.makedirs(os.path.join(dir, i))
    solver = {v[0]: (k, b64decode(v[1].encode('ascii')), v[2])
              for k, v in solver.items()}  # 将解释器反向
    # 结构：{AFD文件名: (相对路径文件名, iv向量，(创建时间，修改时间，访问时间))}
    aes.mode = 'CBC'
    with tqdm(enumerate(len_files:=glob(os.path.join(dir, '.__sys', '*.afd')))) as tq:
        if instance!= None:
            instance.pb = ttk.Progressbar(instance.root, length=instance.root.winfo_width())
            instance.pb['maximum'] = len(len_files)
            del len_files
            instance.pb['value'] = 0
            instance.pb.grid(row=4, column=0, columnspan=3)
            instance.info.set('decrypting...')
            instance.root.update()
        warn_msg = ''
        for index,i in tq:
            get = solver[os.path.basename(i)]
            with open(i, 'rb') as f:
                try:
                    content = aes.decrypt(f.read(), iv=get[1])
                except:
                    warn_msg += f'WARNING: exception when decrypting: {i}, {get[0]}\n'
                    print(f'WARNING: exception when decrypting: {i}, {get[0]}')
                    continue
            with open(os.path.join(dir, get[0]), 'wb') as f:
                f.write(content)
            try:
                if len(get)>=3:
                    modifyFileTime(os.path.join(dir, get[0]), *get[2])
            except Exception as e:
                warn_msg += f'WARNING: exception when modifying file time: {i}, {get[0]}\n'
                print(f'WARNING: exception when modifying file time: {i}, {get[0]}')
                continue
            if instance!= None:
                instance.pb['value'] = index+1
                instance.root.update()
        if instance!= None:
            instance.pb.grid_forget()
            if len(warn_msg)!=0:
                instance.info.set(warn_msg)
            else:
                instance.info.set('completed')
            instance.root.update()
    del content
    os.remove(os.path.join(dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt'))
    return True


if __name__ == '__main__':
    if not os.path.isfile('directory settings.json'):
        f = open('directory settings.json', 'w', encoding='utf-8')
        json.dump(['Input directories here.'], f, ensure_ascii=False, indent=4)
        f.close()
        os.system('pause')
        exit()
    else:
        f = open('directory settings.json', 'r', encoding='utf-8')
        dirs = json.load(f)

    filtered = list(filter(lambda x: not os.path.isdir(x), dirs))
    if not len(filtered) == 0:
        print('These directories below are invalid: ')
        for i in filtered:
            print(i)
        os.system('pause')
        exit()

    for i in dirs:
        print(f'Current directory: {i}')
        check_move = all_files_can_be_moved_by_shutil(i)
        if len(check_move) != 0:
            for t in check_move:
                print(f'ERROR: file {t} can not be accessed')
            os.system('pause')
            continue
        if is_encrypted(i):  # 如果处于加密状态
            def excecute1():
                if not decrypt_dir(i, a.password, instance=a):
                    a.info.set('Password Incorrect')
                else:
                    a.message('Decryption successful')
                    a.destroy()
            a = GUI(None, title='Log in to decrypt %s' %
                    os.path.split(i)[1], command_OK=excecute1)
            a.info.set(i)
            a.loop()

        else:
            if not os.path.isfile(os.path.join(i, '__Status.sti')):  # 如果是第一次加密
                def execute2():
                    if a.user_name != a.password:
                        a.info.set(
                            'You inputed diffrent passwords. Failed to lock the folder. ')
                    else:
                        encrypt_dir(i,  a.password, instance=a)
                        a.message('Encryption successful')
                        a.destroy()
                a = GUI("Set password: ", 'Confirm your password: ',
                        title='Log in to encrypt %s' % os.path.split(i)[1], command_OK=execute2)
                a.info.set(i)
                a.loop()

            else:
                def execute4():
                    '''更换密码'''
                    global a, b
                    a.destroy()

                    def execute5():
                        '''更换密码时点击执行的函数'''
                        if b.user_name != b.password:
                            b.info.set(
                                'You inputed diffrent passwords. Failed to lock the folder. ')
                        else:
                            encrypt_dir(i,  b.password, ignore_check=True, instance=b)
                            b.message('Encryption successful')
                            b.destroy()
                    b = GUI("Set password: ", 'Confirm your password: ',
                            title='Log in to encrypt %s' % os.path.split(i)[1], command_OK=execute5)
                    b.info.set(i)
                    b.loop()

                def execute3():
                    '''加密时，若点OK运行的函数'''
                    if not encrypt_dir(i,  a.password, instance=a):
                        a.info.set(
                            'Password incorrect! Failed to lock the folder. ')
                    else:
                        a.message('Encryption successful')
                        a.destroy()
                a = GUI(None, title='log in to encrypt %s' %
                        os.path.split(i)[1], command_OK=execute3, change_pass=True, command_change=execute4)
                a.info.set(i)
                a.loop()
