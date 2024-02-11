import time
from argon2 import PasswordHasher
import random
password = random.randbytes(10)
salt = random.randbytes(10)
ph = PasswordHasher(1,2097152,5)
t0 = time.time()
for i in range(3):
    password = ph.hash(password).encode()
print(time.time()-t0)
print(password)