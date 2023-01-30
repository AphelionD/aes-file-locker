'''AES_file_locker [version 1.4]
Powered by Python.
(c)2023 Illumination Studio, Yanteen Technology,.Ltd.'''
import json
import os
from AES import AES
import hashlib
from argon2 import hash_password
# https://pypi.org/project/argon2-cffi/
# pip install argon2-cffi
import random
from glob import glob
from shutil import rmtree, move
from tqdm import tqdm
from base64 import b64decode, b64encode
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


def encrypt_dir(dir, master_password, ignore_check=False, config=configuration):
    '''ignore_check: whether check password when encrypting
    config: a dictionary, like the `CONFIG_DEFAULT`'''
    def key_derivation(key, t, m, p):
        with tqdm(range(3), leave=False, smoothing=0.8) as tq:
            tq.set_description('Verifying password')
            key = key.encode('utf-8')
            for i in tq:  # 使用argon2算法，迭代一个密码消耗3秒左右
                key = hash_password(key, b'This is salt', t, m, p)
        return key
    config_input = config
    target_dir = os.path.join(dir, '.__sys')
    dirs, files = copy_dir(dir)
    files = list(filter(lambda x: x != '__Solver.dll' and x !=
                 '__Status.sti' and os.path.splitext(x)[1] != '.afd', files))
    dirs = list(filter(lambda x: x != get_relative_dir(target_dir, dir), dirs))
    aes = AES('所有侵犯隐私者将受到严惩。', 'ECB')
    aes.b64 = False
    if not os.path.isfile(os.path.join(dir, '__Status.sti')) or ignore_check:
        stretched_key = key_derivation(
            master_password, config['time_cost'], config['memory_cost'], config['parallelism'])
        rand_key = os.urandom(random.randint(60, 90)) + b'===end==='
        config_bytes = aes.encrypt(json.dumps(config).encode('utf-8'))
        config_bytes = config_bytes + int.to_bytes(len(config_bytes), 2, 'big')
        aes.key = stretched_key
        with open(os.path.join(dir, '__Status.sti'), 'wb') as f:
            f.write(aes.encrypt(rand_key)+config_bytes)
    else:
        with open(os.path.join(dir, '__Status.sti'), 'rb') as f:  # 先验证密码
            content = f.read()
            config_len = int.from_bytes(content[-2:], 'big')
            config = json.loads(aes.decrypt(
                content[-2-config_len:-2]).decode('utf-8'))
            rand_key = content[:-2-config_len]
            stretched_key = key_derivation(
                master_password, config['time_cost'], config['memory_cost'], config['parallelism'])
            aes.key = stretched_key
            try:
                rand_key = aes.decrypt(rand_key)
                if rand_key[-9:] != b'===end===':
                    raise Exception
            except:
                print(f'ERROR: Password incorrect for {dir}!!!')
                return False
            aes.key = '所有侵犯隐私者将受到严惩。'
            if config != config_input:
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
    if len(files) == 0:
        print(f'WARNING: No files in {dir}!!!')
        return False
    random.shuffle(files)
    if not os.path.isdir(target_dir):
        os.mkdir(target_dir)  # 在A目录下创建文件夹
    else:
        for i in glob(os.path.join(target_dir, '*')):
            os.remove(i)
    solver = {}  # 初始化目录解释器
    salt = os.urandom(10)
    for i in range(len(files)):  # 进行目录解释，为每一个文件指定新的独一无二的文件名
        solver[files[i]] = (
            md5(bytes(str(i), encoding='ascii') + salt)+'.afd', os.urandom(16))
    aes.key = rand_key
    aes.mode = 'CBC'
    with tqdm(files) as tq:
        for i in tq:
            with open(os.path.join(dir, i), 'rb') as f:
                content = aes.encrypt(f.read(), iv=solver[i][1])
            with open(os.path.join(target_dir, solver[i][0]), 'wb') as f:
                f.write(content)
    for i in solver.keys():
        solver[i] = (solver[i][0], b64encode(solver[i][1]).decode('ascii'))
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


def decrypt_dir(dir, master_password):
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
            for i in tq:  # 使用argon2算法，迭代一个密码消耗3秒左右
                master_password = hash_password(
                    master_password, b'This is salt', config['time_cost'], config['memory_cost'], config['parallelism'])
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
    solver = {v[0]: (k, b64decode(v[1].encode('ascii')))
              for k, v in solver.items()}  # 将解释器反向
    aes.mode = 'CBC'
    with tqdm(glob(os.path.join(os.path.join(dir, '.__sys'), '*.afd'))) as tq:
        for i in tq:
            with open(i, 'rb') as f:
                try:
                    content = aes.decrypt(
                        f.read(), iv=solver[os.path.basename(i)][1])
                except:
                    print(
                        f'WARNING: exception when encrypting: {i}, {solver[os.path.basename(i)][0]}')
                    continue
            with open(os.path.join(dir, solver[os.path.basename(i)][0]), 'wb') as f:
                f.write(content)
    del content
    # os.remove(os.path.join(dir,'__Status.sti'))
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

    from tkinter import *
    from tkinter import messagebox

    class GUI():
        def __init__(self, line1='Username', line2='Password', title='Log in', command_OK=None, change_pass=False, command_change=None):
            self.user_name = None
            self.password = None
            GUI.root = Tk()
            GUI.root.title(title)
            self.info = StringVar()
            if line1 != None:
                GUI.v1 = StringVar()
                GUI.l1_content = StringVar()
                GUI.l1_content.set(line1)
                GUI.l1 = Label(GUI.root, textvariable=GUI.l1_content)
                GUI.l1.grid(row=0, column=0)  # label：文本
            GUI.l2_content = StringVar()
            GUI.l2_content.set(line2)
            GUI.l2 = Label(GUI.root, textvariable=GUI.l2_content)  # grid：表格结构
            GUI.l2.grid(row=1, column=0)
            GUI.v2 = StringVar()
            if not line1 == None:
                GUI.e1 = Entry(GUI.root, textvariable=GUI.v1,show='*').grid(row=0, column=1, padx=10, pady=5)  # entry：输入框
            GUI.e2 = Entry(GUI.root, textvariable=GUI.v2, show='*').grid(row=1,column=1, padx=10, pady=5)  # 想显示什么就show=
            Label(GUI.root)

            def command():

                if hasattr(GUI, 'v1'):
                    if GUI.v1.get() != '' and GUI.v2.get() != '':
                        self.user_name = GUI.v1.get()
                        self.password = GUI.v2.get()
                        if callable(command_OK):
                            command_OK()
                    else:
                        messagebox.showinfo(
                            'WARNING', 'Please fill in all the blanks')
                else:
                    if GUI.v2.get() != '':
                        self.password = GUI.v2.get()
                        if callable(command_OK):
                            command_OK()
                    else:
                        messagebox.showinfo(
                            'WARNING', 'Please fill in all the blanks')

            GUI.b1 = Button(GUI.root, text='submit', width=10, command=command)
            GUI.b1.grid(row=4, column=0, sticky=W, padx=10, pady=10)
            GUI.b2 = Button(GUI.root, text='exit',width=10, command=GUI.root.quit)
            GUI.b2.grid(row=4, column=1, sticky=N, padx=10, pady=10)
            if change_pass:
                GUI.b3 = Button(GUI.root, text='change password', width=20, command=command_change)
                GUI.b3.grid(row=4, column=2, sticky=E, padx=20, pady=10)

            l3 = Label(GUI.root, textvariable=self.info)
            l3.grid(row=3, column=0, sticky=W)

        def set_l1(self, value):
            GUI.l1_content.set(value)

        def set_l2(self, value):
            GUI.l2_content.set(value)
        def message(self,message):
            messagebox.showinfo('info', message=message)
        def loop(self):
            GUI.root.mainloop()

        def destroy(self):
            '''All widgets will be removed!!'''
            GUI.root.destroy()

        def __call__(self):
            return self.status

    for i in dirs:
        print(f'Current directory: {i}')
        check_move = all_files_can_be_moved_by_shutil(i)
        if len(check_move) != 0:
            for t in check_move:
                print(f'ERROR: file {t} can not be accessed')
            continue
        if is_encrypted(i):
            def excecute1():
                if not decrypt_dir(i, a.password):
                    a.info.set('Password Incorrect')
                else:
                    a.message('Decryption successful')
                    a.destroy()
            a = GUI(None, title='Log in to decrypt %s' %
                    i, command_OK=excecute1)
            a.loop()

        else:
            if not os.path.isfile(os.path.join(i, '__Status.sti')):
                def execute2():
                    if a.user_name != a.password:
                        a.info.set(
                            'You inputed diffrent passwords. Failed to lock the folder. ')
                    else:
                        encrypt_dir(i,  a.password)
                        a.message('Encryption successful')
                        a.destroy()
                a = GUI("Set password: ", 'Confirm your password: ',
                        title='Log in to encrypt %s' % i, command_OK=execute2)
                a.loop()

            else:
                def execute4():
                    global a, b
                    a.destroy()

                    def execute5():
                        if b.user_name != b.password:
                            b.info.set(
                                'You inputed diffrent passwords. Failed to lock the folder. ')
                        else:
                            encrypt_dir(i,  b.password, ignore_check=True)
                            b.message('Encryption successful')
                            b.destroy()
                    b = GUI("Set password: ", 'Confirm your password: ',
                            title='Log in to encrypt %s' % i, command_OK=execute5)
                    b.loop()

                def execute3():
                    if not encrypt_dir(i,  a.password):
                        a.info.set(
                            'Password incorrect! Failed to lock the folder. ')
                    else:
                        a.message('Encryption successful')
                        a.destroy()
                a = GUI(None, title='log in to encrypt %s' %
                        i, command_OK=execute3, change_pass=True, command_change=execute4)
                a.loop()
