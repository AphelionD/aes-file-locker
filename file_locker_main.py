'''AES_file_locker [version 1.4.6]
Powered by Python.
(c)2023 Illumination Studio, Yanteen Technology,.Ltd.'''
from AES import AES
from File_locker import *
from GUI import GUI


def encrypt_dir(dir, master_password, ignore_check=False, config=configuration, instance = None):
    '''ignore_check: whether check password when encrypting
    config: a dictionary, like the `CONFIG_DEFAULT`'''
    def key_derivation(key, t, m, p):
        with tqdm(range(3), leave=False, smoothing=0.8) as tq:
            tq.set_description('Verifying password')
            key = key.encode('utf-8')
            if instance!=None:
                assert isinstance(instance,GUI), "param 'instance' must be a GUI instance"
                instance.info.set('Verifying password')
                instance.pb = ttk.Progressbar(instance.root, length=instance.root.winfo_width())
                instance.pb['maximum'] = 3
                instance.pb['value'] = 0
                instance.pb.grid(row=4, column=0, columnspan=3)
                instance.root.update()
            for i in tq:  # 使用argon2算法，迭代一个密码消耗3秒左右
                key = hash_password(key, b'This is salt', t, m, p)
                if instance != None:
                    instance.pb['value']=i+1
                    instance.root.update()
            if instance!=None:
                instance.pb.grid_forget()
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
    with tqdm(enumerate(files)) as tq:
        if instance!=None:
            assert isinstance(instance, GUI), "param 'instance' must be a GUI instance"
            instance.info.set('encrypting...')
            instance.pb = ttk.Progressbar(instance.root, length=instance.root.winfo_width())
            instance.pb['value'] = 0
            instance.pb['maximum'] = len(files)
            instance.pb.grid(row=4, column=0, columnspan=3)
            instance.pb
            instance.root.update()
        for index,i in tq:
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


def decrypt_dir(dir, master_password, instance=None):
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
                master_password = hash_password(
                    master_password, b'This is salt', config['time_cost'], config['memory_cost'], config['parallelism'])
                if instance != None:
                    instance.pb['value']=i+1
                    instance.root.update()
            if instance!=None:
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
    solver = {v[0]: (k, b64decode(v[1].encode('ascii')))
              for k, v in solver.items()}  # 将解释器反向
    aes.mode = 'CBC'
    with tqdm(enumerate(len_files:=glob(os.path.join(os.path.join(dir, '.__sys'), '*.afd')))) as tq:
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
            with open(i, 'rb') as f:
                try:
                    content = aes.decrypt(f.read(), iv=solver[os.path.basename(i)][1])
                except:
                    warn_msg += f'WARNING: exception when encrypting: {i}, {solver[os.path.basename(i)][0]}\n'
                    print(f'WARNING: exception when encrypting: {i}, {solver[os.path.basename(i)][0]}')
                    continue
            with open(os.path.join(dir, solver[os.path.basename(i)][0]), 'wb') as f:
                f.write(content)
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
