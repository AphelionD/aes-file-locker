'''
AES-256算法，面向对象。ECB或CBC，PKCS5/7 Padding或Zero Padding，sha256密钥处理
'''
from base64 import b64decode, b64encode
from Crypto.Cipher import AES as AES_py
from hashlib import sha256

class AES():
    '''可选绑定参数：b64；salt；result_type
    可更改参数：key，mode'''
    def Zero_Padding(data):
        data += b'\x00'
        while len(data) % 16 != 0:
            data += b'\x00'
        return data
    def PKCS_Padding(data):
        return data + int.to_bytes(16-(len(data)%16), byteorder='little')*(16-(len(data)%16))

    def __init__(self, key, mode = 'ECB', packing_mode = 'PKCS', encoding = 'utf-8') -> None:
        self.__encoding = encoding
        if isinstance(key, str):
            self.__key = key.encode(self.__encoding)
        elif isinstance(key, bytes):
            self.__key = key
        else:
            raise ValueError('Key must be string or bytes')
        if mode=='ECB':
            self.__mode = AES_py.MODE_ECB
        elif mode == 'CBC':
            self.__mode = AES_py.MODE_CBC
        else:
            raise ValueError('AES mode can only be ECB or CBC')
        if packing_mode == 'PKCS':
            self.__packing_mode = AES.PKCS_Padding
        elif packing_mode == 'Zero':
            self.__packing_mode = AES.ZeroPadding
        else:
            raise ValueError('Packing mode must be "PKCS" or "Zero"')
    @property
    def key(self):
        return self.__key
    @key.setter
    def key(self, value):
        if isinstance(value, str):
            self.__key = value.encode(self.__encoding)
        elif isinstance(value, bytes):
            self.__key = value
        else:
            raise ValueError('Key must be string or bytes')
    @property
    def mode(self):
        if self.__mode == AES_py.MODE_ECB:
            return 'ECB'
        elif self.__mode == AES_py.MODE_CBC:
            return 'CBC'
    @mode.setter
    def mode(self, value):
        if value=='ECB':
            self.__mode = AES_py.MODE_ECB
        elif value == 'CBC':
            self.__mode = AES_py.MODE_CBC
        else:
            raise ValueError('AES mode can only be ECB or CBC')


    def encrypt(self, text: bytes | str, salt='This is salt', b64 = True, result_type = str, iv = None):
        '''text: 自动判断是bytes还是str

        如果b64为True，返回base64调制后的结果，可选择返回str或bytes（result_type）。若b64为False，返回bytes'''
        if hasattr(self, 'b64'):
            b64 = self.b64
        if hasattr(self, 'salt'):
            salt = self.salt
        if hasattr(self, 'result_type'):
            result_type = self.result_type
        if isinstance(text, str):
            text = text.encode(self.__encoding)
        key = sha256(self.__key + salt.encode(self.__encoding)).digest()
        if iv==None:
            aes = AES_py.new(key, self.__mode)  # 初始化加密器
        else:
            aes = AES_py.new(key, self.__mode, iv)
        encrypt_aes = aes.encrypt(self.__packing_mode(text))  # 先进行aes加密
        if b64:
            if result_type==str:
                return str(b64encode(encrypt_aes), encoding=self.__encoding)
            elif result_type==bytes:
                return b64encode(encrypt_aes)
        else:
            return encrypt_aes

    def StripZeroPadding(data):
        data = data[:-1]
        while len(data) % 16 != 0:
            data = data.rstrip(b'\x00')
            if data[-1] != b"\x00":
                break
        return data
    def Strip_PKCS_Padding(data):
        return data[:-data[-1]]
    def decrypt(self, text: bytes | str, salt='This is salt', b64 = True, result_type = str, iv = None):
        '''key: 自动判断是bytes还是str

        如果b64为True，自动判断text是bytes还是str。若b64为False，请传入bytes，且返回bytes。'''
        if hasattr(self, 'b64'):
            if not isinstance(self.b64, bool):
                raise ValueError('property "b64" must be a bool')
            b64 = self.b64
        if hasattr(self, 'salt'):
            assert isinstance(self.salt, str)
            salt = self.salt
        if hasattr(self, 'result_type'):
            result_type = self.result_type
        key = sha256(self.__key + salt.encode(self.__encoding)).digest()
        if iv==None:
            aes = AES_py.new(key, self.__mode)  # 初始化加密器
        else:
            aes = AES_py.new(key, self.__mode, iv)
        if self.__packing_mode.__name__=='Zero_Padding':
            unpadding = AES.StripZeroPadding
        elif self.__packing_mode.__name__=='PKCS_Padding':
            unpadding = AES.Strip_PKCS_Padding
        else:
            raise ValueError('Unknown padding, function name probably changed')
        if b64:
            if isinstance(text,str):
                base64_decrypted = b64decode(text.encode(encoding=self.__encoding))  # 优先逆向解密base64成bytes
            elif isinstance(text, bytes):
                base64_decrypted = b64decode(text)
            if result_type==str:
                return str(unpadding(aes.decrypt(base64_decrypted)), encoding=self.__encoding)  # 执行解密密并转码返回str
            elif result_type==bytes:
                return unpadding(aes.decrypt(base64_decrypted))
        else:
            return unpadding(aes.decrypt(text))

if __name__=='__main__':
    a = '''    梁山附近有个当保正的晁盖，得知奸臣蔡京的女婿梁中书派杨志押送“生辰纲”上京，便由吴用定计，约集了其他七名好汉劫了生辰纲，投奔梁山。杨志丢了“生辰纲”，不能回去交差，就与鲁智深会合，占了二龙山。
    郓城有个好汉叫宋江，他的老婆与人私通。在探知宋江与梁山强盗有来往后，她百般要挟。宋江一怒之下，杀了阎婆惜，逃奔小旋风柴进庄上，结识了武松。武松与宋江分手后，在景阳冈上打死猛虎，成了英雄，之后去阳谷县当了一名武官，碰巧遇见失散多年的胞兄武大。可是他的嫂子潘金莲却不守妇道，趁武松外出，私通西门庆，毒死武大。武松归后察知其情，杀了二人，给兄长报了仇。事后他被发配孟州，结识施恩，醉打蒋门神，怒杀张都监全家，也转去投二龙山安身。'''
    aes = AES('password')
    aes.b64 = False
    b = aes.encrypt(a)
    print(b)
    c = aes.decrypt(b).decode('utf-8')
    print(c)
    assert a == c