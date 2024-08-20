# Introduction

AES File Locker（AFL）is a file encryption program based on `argon2` hashing function and `AES-256` algorithm.

# Features

- It has a `tkinter` GUI interface.
- All filenames and directory structures can be encrypted.
- It can effectively prevent force attacks, as long as the password is strong enough.
- Even if the encrypted file is moved, as long as the correct path is provided to the program, decryption can still be performed.
- There is a password input confirmation feature to prevent accidentally entering a different password during encryption, which could result in data loss.
- Passwords support special characters such as Chinese, and the password can be changed.
- It can automatically determine whether to encrypt or decrypt.
- Files support dynamic updates, with only the newly modified files being encrypted each time.
- Each file has its own unique key.
- Decrypted and encrypted files can be separated. This is especially useful if you only want to sync encrypted files to a cloud service.
- The size of your files will NOT be encrypted.

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
# Usage

When you run `file_locker_main.py` the first time, a `directory_settings.json` file will be generated.

If the encryption path and the decryption path are the same, put their path in a one-item array. If they are different, the first item of the array should be the vault path(the path of encrypted files), and the second item should be the file path(the path of decrypted files).

```json
[
    ["vault_path", "file_path"],
    ["vault_path|file_path"]
]
```


# Compatibility

Compatible with windows and macOS. Linux is not tested.