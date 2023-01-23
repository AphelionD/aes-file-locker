'''
AES-256算法，ECB，PKCS5/7 Padding，md5密钥处理，加盐可配置，究极版本
'''
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from hashlib import md5




def encrypt(key: bytes | str, text: bytes | str, salt='This is salt', b64 = True, result_type = str, encoding='utf-8'):
    '''key: 自动判断是bytes还是str

    text: 自动判断是bytes还是str

    如果b64为True，返回base64调制后的结果，可选择返回str或bytes（result_type）。若b64为False，返回bytes'''
    def ZeroPadding(data):
        data += b'\x00'
        while len(data) % 16 != 0:
            data += b'\x00'
        return data
    def PKCS_Padding(data):
        return data + int.to_bytes(16-(len(data)%16), byteorder='little')*(16-(len(data)%16))

    if isinstance(text, str):
        text = text.encode(encoding)
    if isinstance(key, str):
        key = md5((key + salt).encode(encoding)).hexdigest()
    elif isinstance(key, bytes):
        key = md5(key + salt.encode(encoding)).hexdigest()
    aes = AES.new(key.encode('ascii'), AES.MODE_ECB)  # 初始化加密器
    encrypt_aes = aes.encrypt(PKCS_Padding(text))  # 先进行aes加密
    if b64:
        if result_type==str:
            return str(b64encode(encrypt_aes), encoding=encoding)
        elif result_type==bytes:
            return b64encode(encrypt_aes)
    else:
        return encrypt_aes

def decrypt(key:str, text: bytes | str, salt='This is salt', b64 = True, result_type = str, encoding='utf-8'):
    '''key: 自动判断是bytes还是str

    如果b64为True，自动判断text是bytes还是str。若b64为False，请传入bytes，且返回bytes。'''
    def StripZeroPadding(data):
        data = data[:-1]
        while len(data) % 16 != 0:
            data = data.rstrip(b'\x00')
            if data[-1] != b"\x00":
                break
        return data
    def Strip_PKCS_Padding(data):
        return data[:-data[-1]]
    if isinstance(key, str):
        key = md5((key + salt).encode(encoding)).hexdigest()
    elif isinstance(key, bytes):
        key = md5(key + salt.encode(encoding)).hexdigest()
    aes = AES.new(key.encode('ascii'), AES.MODE_ECB)  # 初始化加密器
    if b64:
        if isinstance(text,str):
            base64_decrypted = b64decode(text.encode(encoding=encoding))  # 优先逆向解密base64成bytes
        elif isinstance(text, bytes):
            base64_decrypted = b64decode(text)
        if result_type==str:
            return str(Strip_PKCS_Padding(aes.decrypt(base64_decrypted)), encoding=encoding)  # 执行解密密并转码返回str
        elif result_type==bytes:
            return Strip_PKCS_Padding(aes.decrypt(base64_decrypted))
    else:
        return Strip_PKCS_Padding(aes.decrypt(text))

if __name__=='__main__':
    # with open(r"C:\Users\jenso\Desktop\73+74~75+79~81 (0).mp4", 'rb') as f:
    #     content = decrypt('password', f.read(), result_type=bytes, b64=False)
    # with open(r"C:\Users\jenso\Desktop\73+74~75+79~81 (1).mp4", 'wb') as f:
    #     f.write(content)
    pass
    a = '''hello
    梁山附近有个当保正的晁盖，得知奸臣蔡京的女婿梁中书派杨志押送“生辰纲”上京，便由吴用定计，约集了其他七名好汉劫了生辰纲，投奔梁山。杨志丢了“生辰纲”，不能回去交差，就与鲁智深会合，占了二龙山。
    郓城有个好汉叫宋江，他的老婆与人私通。在探知宋江与梁山强盗有来往后，她百般要挟。宋江一怒之下，杀了阎婆惜，逃奔小旋风柴进庄上，结识了武松。武松与宋江分手后，在景阳冈上打死猛虎，成了英雄，之后去阳谷县当了一名武官，碰巧遇见失散多年的胞兄武大。可是他的嫂子潘金莲却不守妇道，趁武松外出，私通西门庆，毒死武大。武松归后察知其情，杀了二人，给兄长报了仇。事后他被发配孟州，结识施恩，醉打蒋门神，怒杀张都监全家，也转去投二龙山安身。'''
    b = encrypt('password', a)
    print(decrypt('password', b))
# import base64
# from Crypto.Cipher import AES
# from hashlib import sha1, md5
# import random

# '''
# AES对称加密算法
# '''
# 需要补位，str不是16的倍数那就补足为16的倍数
# def add_to_16_bytes(value):
#     while len(value) % 16 != 0:
#         value += b'\x00'
#     return value  # 返回bytes
# def add_to_16_str(value):
#     while len(value) % 16 != 0:
#         value += '\0'
#     return str.encode(value)  # 返回bytes

# 加密方法
# def encrypt(key:str, text: bytes, salt='This is salt', codec='utf-8'):
#     key = md5((key + salt).encode(codec)).hexdigest()
#     aes = AES.new(key.encode('ascii'), AES.MODE_ECB)  # 初始化加密器
#     return aes.encrypt(ZeroPadding(text))  # 先进行aes加密
# # 解密方法
# def decrypt(key:str, text: bytes, salt='This is salt', codec='utf-8'):
#     key = md5((key + salt).encode(codec)).hexdigest()
#     aes = AES.new(key.encode('ascii'), AES.MODE_ECB)  # 初始化加密器
#     return StripZeroPadding(aes.decrypt(text))
# def generate_akc(file, length=4096):
#     def random_utf8_seq():
#         def byte_range(first, last):
#             return list(range(first, last+1))

#         first_values = byte_range(0x00, 0x7F) + byte_range(0xC2, 0xF4)
#         trailing_values = byte_range(0x80, 0xBF)
#         first = random.choice(first_values)
#         if first <= 0x7F:
#             return bytes([first])
#         elif first <= 0xDF:
#             return bytes([first, random.choice(trailing_values)])
#         elif first == 0xE0:
#             return bytes([first, random.choice(byte_range(0xA0, 0xBF)), random.choice(trailing_values)])
#         elif first == 0xED:
#             return bytes([first, random.choice(byte_range(0x80, 0x9F)), random.choice(trailing_values)])
#         elif first <= 0xEF:
#             return bytes([first, random.choice(trailing_values), random.choice(trailing_values)])
#         elif first == 0xF0:
#             return bytes([first, random.choice(byte_range(0x90, 0xBF)), random.choice(trailing_values), random.choice(trailing_values)])
#         elif first <= 0xF3:
#             return bytes([first, random.choice(trailing_values), random.choice(trailing_values), random.choice(trailing_values)])
#         elif first == 0xF4:
#             return bytes([first, random.choice(byte_range(0x80, 0x8F)), random.choice(trailing_values), random.choice(trailing_values)])
#     with open(file, 'wb') as f:
#         f.write(random.randbytes(length))
# if __name__=='__main__':
#     with open(r"C:\Users\jenso\Desktop\73+74~75+79~81 (0).mp4", 'rb') as f:
#         content = decrypt('password', f.read())
#     with open(r"C:\Users\jenso\Desktop\73+74~75+79~81 (2).mp4", 'wb') as f:
#         f.write(content)