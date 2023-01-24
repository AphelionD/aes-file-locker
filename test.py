'''Use this file to test which parameters you should use for argon2, while running this'''
import time
from argon2 import hash_password
import random
password = random.randbytes(10)
salt = random.randbytes(10)
t0 = time.time()
for i in range(8):
    password = hash_password(password,salt,1,2097152,4)
print(time.time()-t0)
print(password)