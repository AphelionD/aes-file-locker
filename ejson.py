'''extended json, supports serializing custom objects and bytes'''
import importlib
import json
import types
from functools import partial
from base64 import b64encode,b64decode

def default(obj):
    '''自定义json序列化，支持bytes以及自定义类，强烈建议自定义类的参数中不要出现函数'''
    if isinstance(obj, bytes):
        return {'__class__': 'bytes', '__value__': b64encode(obj).decode()}
    elif hasattr(obj, '__dict__'):
        d = {}
        d['__class__'] = obj.__class__.__name__
        d['__module__'] = obj.__class__.__module__
        for key, val in obj.__dict__.items():
            d[key] = default(val)
        return d
    elif isinstance(obj, (types.BuiltinFunctionType,types.BuiltinMethodType)):
        # 检查对象是否为内置函数类型，强烈建议不要把一个函数序列化
        return {'__class__': 'builtin_function_or_method', '__value__': f'{obj.__module__}.{obj.__name__}'}
    return obj
def object_hook(json_obj):
    if hasattr(json_obj, '__contains__'):
        if '__class__' in json_obj: # bytes没有__module__的属性，所以要单独讨论
            if json_obj['__class__'] == 'bytes':
                return b64decode(json_obj['__value__'].encode())
            if json_obj['__class__'] == 'function':
                code, name, defaults = json_obj['__value__']
                return types.FunctionType(code, globals(), name, defaults)
            elif json_obj['__class__'] == 'builtin_function_or_method':
                module_name, func_name = json_obj['__value__'].split('.')
                module = __import__(module_name, fromlist=[func_name])
                return getattr(module, func_name)
        # elif isinstance(json_obj, dict):
        #     ordered_dict = OrderedDict()
        #     for key, value in json_obj.items():
        #         ordered_dict[key] = object_hook(value)  # 递归地对值进行处理
        #     return ordered_dict
        if '__class__' in json_obj and '__module__' in json_obj:
            class_name = json_obj['__class__']
            module_name = json_obj['__module__']
            if module_name != 'builtins':
                module = importlib.import_module(module_name)
                class_ = getattr(module, class_name)
                if hasattr(class_, '__init__'):  # 检查是否存在构造函数
                    obj = class_.__new__(class_)  # 绕过__init__来创建对象实例
                    for key, value in json_obj.items():
                        if key == '__class__' or key == '__module__':
                            continue
                        setattr(obj, key, object_hook(value))  # 绑定对象属性
                    return obj
    return json_obj

dumps = partial(json.dumps,default=default,indent=4,ensure_ascii=False)
dump = partial(json.dump,default=default,indent=4,ensure_ascii=False)
loads = partial(json.loads,object_hook=object_hook)
load = partial(json.load,object_hook=object_hook)

if __name__ == '__main__':
    from QuickHash.Quick_Hash import QuickHash
    # class QuickHash(QuickHash_imported):
    #     pass # 序列化的自定义对象一定要来自本文件,否则会出错
    def f(n):return n**2
    QuickHash.progress_bar = False
    qh1 = QuickHash(mtime=True) # initialization
    qh1.quick_hash(r"C:\Users\jenso\Desktop\新建文件夹\T1")
    a = json.dumps(['123',12.1565,'你好'.encode(),['hello;',123,{'def':'en'}],qh1],default=default,ensure_ascii=False)
    print(a)
    b = json.loads(a.encode(),object_hook=object_hook)
    print(b[-1].hash_content)