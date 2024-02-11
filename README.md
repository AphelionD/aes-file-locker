# Introduction

AES File Locker（AFL）is a file encryption program based on `argon2` hashing function and `AES-256` algorithm.

# Security Features

- It has a `tkinter` GUI interface.
- All filenames and directory structures can be encrypted.
- It can effectively prevent force attacks, as long as the password is strong enough.
- Even if the encrypted file is moved, as long as the correct path is provided to the program, decryption can still be performed.
- There is a password input confirmation feature to prevent accidentally entering a different password during encryption, which could result in data loss.
- Passwords support special characters such as Chinese, and the password can be changed.
- It can automatically determine whether to encrypt or decrypt.
- Files support dynamic updates, with only the newly modified files being encrypted each time.
Each file has its own unique key.

# Encryption Process

![AFL explained](AFL%20explained.png)

# requirements

```
pip install argon2-cffi
pip install pycryptodome
pip install rich
pip install tqdm
pip install pywin32
```

# Compatibility

Compatible with windows and macOS. Linux is not tested.