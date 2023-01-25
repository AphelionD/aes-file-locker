'''AES_file_locker [version 1.3]
Powered by Python.
(c)2023 Illumination Studio, Yanteen Technology,.Ltd.'''
import json
import os
from AES import *
import hashlib
from argon2 import hash_password
import random
from glob import glob
from shutil import rmtree, move
from tqdm import tqdm
from base64 import b64decode, b64encode
CONFIG_DEFAULT = {
    'time_cost' : 1,
    'memory_cost' : 2097152,
    'parallelism' : 5
}
configuration = { # customize your own configuration heare
    'time_cost' : 1,
    'memory_cost' : 2097152, #KiB
    'parallelism' : 5
}
def all_files_can_be_moved_by_shutil(dir):
    '''检测一个目录下的文件是否都可以被移动，返回一个包含所有不可被移动的文件的list'''
    def get_all_files_list(dir):
        list = []
        if not os.path.isdir(dir):
            raise OSError(f'No such directory: {dir}')
        for i in os.walk(dir):
            for n in i[2]:
                list.append(os.path.join(i[0],n))
        return list
    list =[]
    i = 0
    while os.path.isdir(os.path.join(dir, str(i))):
        i+=1
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
                yield os.path.join(i[0],n)
    for f in get_all_files(dir):
        ext = os.path.splitext(f)[1]
        if ext!='.afd' and ext!='.dll' and ext!='.sti':
            return False
    return True
def get_relative_dir(a,b):
    '''获取a相对于b的路径.
    \n例如，返回：存志群里的音频资料\音标听力\光盘1\9. 巩固练习\巩固练习 01.mp3'''
    tinyword=''
    for i in range(len(a)):
        tinyword=a[:i+1]
        if tinyword==b:
            del tinyword
            return a[i+2:]

def copy_dir(path):
    '''获取这个路径下的所有文件和文件夹，使用相对路径

    返回：[[dir1, dir2, ...], [file1, file2, ...]]'''
    files = []
    directories = []
    for i in os.walk(path):
        for x in i[2]:
            files.append(get_relative_dir(os.path.join(i[0],x),path))
        if i[0]==path:
            continue
        directories.append(get_relative_dir(i[0],path))
    return [directories, files]

def md5(fname,  is_file_dir=None, encoding = 'utf-8'):
    '''fname: 自动解释，可传入file directory, str, bytes\n
        is_file_dir: 强制指定是否为file directory，传入bool或None，None时自动判断\n
        注意：传入路径时未指定is_file_dir，则文件不存在不会报错，而是转而计算这个路径字符串str的哈希值。'''
    hash_md5 = hashlib.md5()
    if (os.path.isfile(fname) and is_file_dir!=False) or is_file_dir==True:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    elif isinstance(fname, str):
        for i in (fname[i:i+2048] for i in range(0,len(fname),2048)):
            hash_md5.update(i.encode(encoding))
        return hash_md5.hexdigest()
    elif isinstance(fname, bytes):
        for i in (fname[i:i+4096] for i in range(0,len(fname),4096)):
            hash_md5.update(i)
        return hash_md5.hexdigest()

def encrypt_dir(dir, master_password, ignore_check = False, config = configuration):
    '''ignore_check: whether check password when encrypting
    config: a dictionary, like the `CONFIG_DEFAULT`'''
    def key_derivation(key,t,m,p):
        with tqdm(range(3), leave=False,smoothing=0.8) as tq:
            tq.set_description('Verifying password')
            key = key.encode('utf-8')
            for i in tq: #使用argon2算法，迭代一个密码消耗3秒左右
                key = hash_password(key,b'This is salt',t,m,p)
        return key
    config_input = config
    target_dir = os.path.join(dir, '.__sys')
    dirs, files = copy_dir(dir)
    files = list(filter(lambda x: x!='__Solver.dll' and x!= '__Status.sti' and os.path.splitext(x)[1]!='.afd', files))
    dirs = list(filter(lambda x: x!=get_relative_dir(target_dir, dir), dirs))
    if not os.path.isfile(os.path.join(dir,'__Status.sti')) or ignore_check:
        stretched_key = key_derivation(master_password,config['time_cost'],config['memory_cost'],config['parallelism'])
        rand_key = os.urandom(random.randint(60,90)) + b'===end==='
        config_bytes = encrypt('所有侵犯隐私者将受到严惩。', json.dumps(config).encode('utf-8'), b64=False)
        config_bytes = config_bytes + int.to_bytes(len(config_bytes), 2, 'big')
        with open(os.path.join(dir,'__Status.sti'), 'wb') as f:
            f.write(encrypt(stretched_key, rand_key, b64=False)+config_bytes)
    else:
        with open(os.path.join(dir,'__Status.sti'), 'rb') as f: #先验证密码
            content = f.read()
            config_len = int.from_bytes(content[-2:], 'big')
            config = json.loads(decrypt('所有侵犯隐私者将受到严惩。', content[-2-config_len:-2], b64=False).decode('utf-8'))
            rand_key = content[:-2-config_len]
            stretched_key = key_derivation(master_password,config['time_cost'],config['memory_cost'],config['parallelism'])
            try:
                rand_key = decrypt(stretched_key, rand_key, b64=False)
                if rand_key[-9:]!=b'===end===':
                    raise Exception
            except:
                print(f'ERROR: Password incorrect for {dir}!!!')
                return False
            if config != config_input:
                stretched_key = key_derivation(master_password, config_input['time_cost'], config_input['memory_cost'],config_input['parallelism'])
                config_bytes = encrypt('所有侵犯隐私者将受到严惩。', json.dumps(config_input).encode('utf-8'), b64=False)
                config_bytes = config_bytes + int.to_bytes(len(config_bytes), 2, 'big')
            else:
                config_bytes=encrypt('所有侵犯隐私者将受到严惩。', json.dumps(config).encode('utf-8'), b64=False)
                config_bytes = config_bytes + int.to_bytes(len(config_bytes), 2, 'big')

            rand_key = os.urandom(random.randint(60,90)) + b'===end==='
            with open(os.path.join(dir,'__Status.sti'), 'wb') as f:
                f.write(encrypt(stretched_key, rand_key, b64=False)+config_bytes)
    if len(files)==0:
        print(f'WARNING: No files in {dir}!!!')
        return False
    random.shuffle(files)
    if not os.path.isdir(target_dir):
        os.mkdir(target_dir) # 在A目录下创建文件夹
    else:
        for i in glob(os.path.join(target_dir,'*')):
            os.remove(i)
    solver = {} # 初始化目录解释器
    salt = os.urandom(10)
    for i in range(len(files)): # 进行目录解释，为每一个文件指定新的独一无二的文件名
        solver[files[i]]= (md5(bytes(str(i), encoding='ascii') + salt)+'.afd', os.urandom(16))
    with tqdm(files) as tq:
        for i in tq:
            with open(os.path.join(dir, i), 'rb') as f:
                content = encrypt(rand_key, f.read(), b64=False, mode='CBC', iv=solver[i][1])
            with open(os.path.join(target_dir, solver[i][0]), 'wb') as f:
                f.write(content)
    for i in solver.keys():
        solver[i]=(solver[i][0],b64encode(solver[i][1]).decode('ascii'))
    solver = json.dumps([solver,dirs], ensure_ascii=False, indent=4) # 序列化解释器（与dirs列表打包）
    with open(os.path.join(dir, '__Solver.dll'), 'wb') as f:
        f.write(encrypt(rand_key, solver, b64=False)) # 加密解释器
    for i in files:
        with open(os.path.join(dir, i), 'wb') as f:
            f.write(b'')
        os.remove(os.path.join(dir, i))
    for i in dirs:
        if os.path.isdir(os.path.join(dir, i)):
            rmtree(os.path.join(dir, i))
    return True

def decrypt_dir(dir, master_password):
    # if not os.path.isfile(os.path.join(dir,'__Status.sti')): # 不存在状态指示器时，判定为加密。
    #     encrypt_dir(dir, os.path.join(dir, '.__sys'), password)
    # else:
        with open(os.path.join(dir,'__Status.sti'), 'rb') as f: #验证密码
            content = f.read()
            config_len = int.from_bytes(content[-2:], 'big')
            config = json.loads(decrypt('所有侵犯隐私者将受到严惩。', content[-2-config_len:-2], b64=False).decode('utf-8'))
            rand_key = content[:-2-config_len]
            with tqdm(range(3), leave=False,smoothing=0.8) as tq:
                tq.set_description('Verifying password')
                master_password = master_password.encode('utf-8')
                for i in tq: #使用argon2算法，迭代一个密码消耗3秒左右
                    master_password = hash_password(master_password,b'This is salt',config['time_cost'],config['memory_cost'],config['parallelism'])
            try:
                rand_key = decrypt(master_password, rand_key, b64=False)
                if rand_key[-9:]!=b'===end===':
                    raise Exception
            except:
                print(f'ERROR: Password incorrect for {dir}!!!')
                return False
        with open(os.path.join(dir,'__Solver.dll'),'rb') as f:
            solver, dirs = json.loads(decrypt(rand_key, f.read(), b64=False)) # 加载目录解释器
        for i in dirs: # 创建目录
            if not os.path.isdir(os.path.join(dir, i)):
                os.makedirs(os.path.join(dir, i))
        solver = {v[0]: (k,b64decode(v[1].encode('ascii'))) for k, v in solver.items()} # 将解释器反向
        with tqdm(glob(os.path.join(os.path.join(dir,'.__sys'), '*.afd'))) as tq:
            for i in tq:
                with open(i, 'rb') as f:
                    try:
                        content = decrypt(rand_key, f.read(), b64=False, mode='CBC', iv=solver[os.path.basename(i)][1])
                    except:
                        print(f'WARNING: exception when encrypting: {i}, {solver[os.path.basename(i)][0]}')
                        continue
                with open(os.path.join(dir, solver[os.path.basename(i)][0]), 'wb') as f:
                    f.write(content)
        del content
        # os.remove(os.path.join(dir,'__Status.sti'))
        return True

if __name__=='__main__':
    from tkinter import *
    # from tkinter import messagebox
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
    if not len(filtered)==0:
        print('These directories below are invalid: ')
        for i in filtered:
            print(i)
        os.system('pause')
        exit()

    for i in dirs:
        print(f'Current directory: {i}')
        check_move = all_files_can_be_moved_by_shutil(i)
        if len(check_move)!=0:
            for t in check_move:
                print(f'ERROR: file {t} can not be accessed')
            continue
        def check_pass_loop():
            global password, i
            password = input('Input password: ')
            if password=='Change' and not is_encrypted(i):
                password = input('Input new password: ')
                check = input('Confirm your password: ')
                if check!=password:
                    print('You inputed diffrent passwords. Failed to lock the folder. ')
                    os.system("pause")
                    exit()
                return
            try:
                with open(os.path.join(i,'__Status.sti'), 'r', encoding='utf-8') as f:
                    if not decrypt(password, f.read().rstrip('\n'))=='This info is to check whether the password is correct.':
                        print('WARNING: Password incorrect!!!')
                        check_pass_loop()
            except:
                print('WARNING: Password incorrect!!!')
                check_pass_loop()

        # if os.path.isfile(os.path.join(i,'__Status.sti')):
        #     check_pass_loop()
        # else:
        #     password = input("Set password: ")
        #     check = input('Confirm your password: ')
        #     if check!=password:
        #         print('You inputed diffrent passwords. Failed to lock the folder. ')
        #         os.system("pause")
        #         exit()
        # print('\n'*2000)
        # ==============不可删去，等待有两个以上目录时启用===================
        # def execute():
        #     window.destroy()
        #     if choice.get()==1:
        #         if is_encrypted(i):
        #             decrypt_dir(i, password)
        #         else:
        #             encrypt_dir(i,  password)
        # window = Tk()
        # window.title('Choose an action for %s' % i)
        # window.geometry('400x300')
        # choice = IntVar(window, 0)
        # btn_1 = Radiobutton(window, text='Unock' if is_encrypted(i) else 'Lock', variable=choice, value=1)
        # btn_2 = Radiobutton(window, text='Skip', variable=choice, value=2)
        # btn_1.grid(column=0, row=0, sticky=W)
        # btn_2.grid(column=0, row=1, sticky=W)
        # ok_btn = Button(window, text='OK', command=execute)
        # ok_btn.grid(column=0, row=2, sticky=W)
        # window.mainloop()
        # ================================================================
        if is_encrypted(i):
            password = input("Input password: ")
            print('\n'*2000)
            while not decrypt_dir(i, password):
                password = input("Input password: ")
                print('\n'*2000)
        else:
            if not os.path.isfile(os.path.join(i,'__Status.sti')):
                password = input("Set password: ")
                check = input('Confirm your password: ')
                if check!=password:
                    print('You inputed diffrent passwords. Failed to lock the folder. ')
                    os.system("pause")
                    exit()
                print('\n'*2000)
                encrypt_dir(i,  password)
            else:
                password = input("Input password: ")
                print('\n'*2000)
                if password =='Change':
                    password = input("Set password: ")
                    check = input('Confirm your password: ')
                    print('\n'*2000)
                    if check!=password:
                        print('You inputed diffrent passwords. Failed to lock the folder. ')
                        os.system("pause")
                        exit()
                    encrypt_dir(i,  password, True)
                    print('Successfully %sed. ' %('Lock' if is_encrypted(i) else 'Unlock'))
                    continue
                while not encrypt_dir(i,  password):
                    password = input("Input password: ")
                    if password =='Change':
                        password = input("Set password: ")
                        check = input('Confirm your password: ')
                        print('\n'*2000)
                        if check!=password:
                            print('You inputed diffrent passwords. Failed to lock the folder. ')
                            os.system("pause")
                            exit()
                        encrypt_dir(i,  password, True)
                        break
                    print('\n'*2000)
        print('Successfully %sed. ' %('Lock' if is_encrypted(i) else 'Unlock'))
os.system('pause')