# Introduction

<img src="src/assets/AFL_icon.ico" alt="Description of image" width="100" height="auto">

AES File Locker（AFL）is a file encryption program based on [`argon2`](https://github.com/p-h-c/phc-winner-argon2) hashing function and `AES-256` algorithm.

# Features

- All filenames and directory structures can be encrypted.
- Decrypted and encrypted files can be separated (optional). This is especially useful if you only want to sync encrypted files to a cloud service.
- Each file has its own unique key.
- Files support dynamic updates, with only the newly modified files being encrypted each time.
- It has a `pyqt` GUI interface. You can manages your vaults easily.
- Thanks to [`argon2`](https://github.com/p-h-c/phc-winner-argon2), it can effectively prevent force attacks, as long as the password is strong enough.
- Decrypted and encrypted files can be separated (optional). This is especially useful if you only want to sync encrypted files to a cloud service.
- Each file has its own unique key.
- Files support dynamic updates, with only the newly modified files being encrypted each time.
- It has a `pyqt` GUI interface. You can manages your vaults easily.
- Thanks to [`argon2`](https://github.com/p-h-c/phc-winner-argon2), it can effectively prevent force attacks, as long as the password is strong enough.
- Even if the encrypted file is moved, as long as the correct path is provided to the program, decryption can still be performed.
- There is a password input confirmation feature to prevent accidentally entering a different password during encryption, which could result in data loss.
- Passwords are NFKD normalized.
- Passwords strength is measured by `zxcvbn` and weak passwords wont't be allowed by the program.
- It supports necessary features such as:
  - show/hide password inputs
  - change passwords
  - automatically decide whether to encrypt or decrypt.
  - use multithread so that the GUI interface won't get stuck while encrypting and decrypting.
  - warn users when the password contains non-ASCII characters or spaces.
- Passwords are NFKD normalized.
- Passwords strength is measured by `zxcvbn` and weak passwords wont't be allowed by the program.
- It supports necessary features such as:
  - show/hide password inputs
  - change passwords
  - automatically decide whether to encrypt or decrypt.
  - use multithread so that the GUI interface won't get stuck while encrypting and decrypting.
  - warn users when the password contains non-ASCII characters or spaces.
- The size of your files will NOT be encrypted.

# Encryption Process

![AFL explained](AFL%20explained.png)

# requirements

```
python >= 3.7, python <3.10
python >= 3.7, python <3.10
pip install argon2-cffi
pip install pycryptodome
pip install rich
pip install tqdm
pip install pywin32
pip install zxcvbn
pip install pyqt5
pip install pyqt5-tools
pip install zxcvbn
pip install pyqt5
pip install pyqt5-tools
```
# Usage

Simply run `GUI_main_window.py` to get started.
Simply run `GUI_main_window.py` to get started.

# Compatibility

Compatible with windows. MacOS and Linux are not tested yet.
Compatible with windows. MacOS and Linux are not tested yet.