import sys
from PyQt5.QtGui import QKeyEvent, QIcon, QPixmap
from PyQt5.QtWidgets import QMainWindow,QApplication,QLineEdit,QMessageBox, QFileDialog, QDialog
from Ui_main_window import Ui_MainWindow
from Ui_vaut_config_dialog import Ui_Dialog
from PyQt5.QtCore import pyqtSignal,Qt
import file_locker_main
from ejson import dump,load
from Quick_Hash import QuickHash
import win32file
import os
from zxcvbn import zxcvbn
import re

app_config = None

def app_path():
    """Returns the base application path."""
    if hasattr(sys, 'frozen'):
        # Handles PyInstaller
        return os.path.dirname(sys.executable)  #使用pyinstaller打包后的exe目录
    return os.path.dirname(__file__)                 #没打包前的py目录

def is_encrypted(dir):
    if os.path.isfile(os.path.join(dir,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt')):
        return True
    def get_all_files(dir):
        if not os.path.isdir(dir):
            raise OSError(f'No such directory: {dir}')
        for i in os.walk(dir):
            for n in i[2]:
                yield os.path.join(i[0], n)
    for f in get_all_files(dir):
        if not QuickHash.matches_ignore(file_locker_main.ignores,f):
            return False
    return True
def is_used(file):
    try:
        vHandle = win32file.CreateFile(file, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, None)
        return int(vHandle) == win32file.INVALID_HANDLE_VALUE
    except:
        return True
    finally:
        try:
            win32file.CloseHandle(vHandle)
        except:
            pass
def all_files_can_be_moved(dir):
    '''检测一个目录下的文件是否都可以被移动，返回一个包含所有不可被移动的文件的list'''
    def get_all_files_list(dir):
        li = []
        if not os.path.isdir(dir):
            raise OSError(f'No such directory: {dir}')
        for i in os.walk(dir):
            for n in i[2]:
                li.append(os.path.join(i[0], n))
        return li
    li = []
    for i in get_all_files_list(dir):
        if not os.access(i,os.W_OK) or not os.access(i,os.R_OK) or is_used(i):
            li.append(i)
    return li

class MainWindowVaultConfig(QDialog, Ui_Dialog):
    path_updated = pyqtSignal(str,str,str,bool) # 信号，用于通知主窗口更新密码库信息。参数：vault_name,vault_path,file_path,editting
    def __init__(self, parent=None, vault_name="", vault_path="", file_path="", editting=False):
        """
        初始化MainWindowVaultConfig类的构造函数。

        参数:
        - parent: 父窗口，默认为None。
        - vault_name: 保险库名称，默认为空字符串。
        - vault_path: 保险库路径，默认为空字符串。
        - file_path: 文件路径，默认为空字符串。
        - editting: 是否为编辑密码库，决定是否替换在app_config中的设置，默认为True。

        该构造函数用于初始化保险库配置窗口的基本设置和界面布局。
        """
        super(MainWindowVaultConfig, self).__init__(parent)  # 调用父类构造函数
        self.setupUi(self)  # 初始化界面设置
        self.resize(550, 450)  # 调整窗口大小

        # 保存传入的参数
        self.original_vault_name = vault_name
        self.vault_path = vault_path
        self.file_path = file_path
        self.editting = editting
        if not self.editting:
            # 如果是新建密码库，所有项都是空的，而程序第一次运行不会执行合法性检查，所以默认应该设置为不可用
            self.OKButton.setEnabled(False)

        # 根据保险库路径和文件路径的比较结果来决定是否显示链接标签
        if vault_path != file_path:
            self.linkLabel.hide()

        # 设置各个编辑框的初始值
        self.VaultNameEdit.setText(vault_name)
        self.vaultPathEdit.setText(vault_path)
        self.filePathEdit.setText(file_path)

        # 隐藏提醒标签，根据后续逻辑需要决定是否显示
        self.vaultNameReminder.hide()
        self.vaultPathReminder.hide()
        self.filePathReminder.hide()

        self.raise_()
        self.activateWindow()

    def checkVaultSettingsValidity(self):
        """
        更新路径检查提示，更新link图标

        此函数用于检查密码库设置的有效性。它通过一系列的条件判断来确保
        密码库名称不为空、密码库名称唯一、指定的路径存在等条件，从而保证
        用户输入的设置信息有效。有效性检查通过后，允许启用确定按钮。
        """
        flag = True  # flag必须通过全部检查点才可以变成True
        # 检查密码库名称是否为空
        if self.VaultNameEdit.text() == "":
            self.vaultNameReminder.show()  # 显示提示信息
            self.vaultNameReminder.setText("密码库名称不能为空！")
            flag = False
        # 检查密码库名称是否唯一
        elif self.VaultNameEdit.text() in app_config and self.VaultNameEdit.text() != self.original_vault_name:
            self.vaultNameReminder.show()  # 显示提示信息
            self.vaultNameReminder.setText("密码库名称已存在！")
            flag = False
        else:
            self.vaultNameReminder.hide()  # 隐藏提示信息
        # 更新密码库路径
        self.vault_path = self.vaultPathEdit.text()
        # 更新文件路径
        self.file_path = self.filePathEdit.text()
        # 检查密码库路径是否有效
        if os.path.isdir(self.vault_path):
            self.vaultPathReminder.hide()  # 隐藏无效路径提示
        else:
            self.vaultPathReminder.show()  # 显示无效路径提示
        # 检查文件路径的目录是否有效
        if os.path.isdir(os.path.split(self.file_path)[0]):
            self.filePathReminder.hide()  # 隐藏无效路径提示
        else:
            self.filePathReminder.show()  # 显示无效路径提示
        # 根据路径有效性更新link图标
        if os.path.isdir(self.vault_path) and os.path.isdir(os.path.split(self.file_path)[0]):
            if self.vault_path == self.file_path:
                self.linkLabel.show()  # 显示link图标
            else:
                self.linkLabel.hide()  # 隐藏link图标
        else:
            flag = False  # 如果路径无效，设置flag为False
        self.OKButton.setEnabled(flag)  # 根据flag的值启用或禁用确定按钮

    def vaultConfigExecute(self):
        """vault_config完成，OK按钮被点击，保存相应的设置"""
        global app_config
        if self.VaultNameEdit.text() != self.original_vault_name:
            if self.editting:
                del app_config[self.original_vault_name]
            app_config[self.VaultNameEdit.text()] = {
                "vault_path": self.vault_path,
                "file_path": self.file_path
            }
        else:
            app_config[self.VaultNameEdit.text()] = {
                "vault_path": self.vault_path,
                "file_path": self.file_path
            }
        dump(app_config,open(os.path.join(app_path(),'app_config.json'),'w',encoding='utf8'))
        self.path_updated.emit(self.VaultNameEdit.text(),self.vault_path,self.file_path, self.editting)
        self.close()

    def keyPressEvent(self, a0: QKeyEvent) -> None:
        if (a0.key() == Qt.Key.Key_Enter or a0.key() == Qt.Key.Key_Return) and self.OKButton.isEnabled():
            self.vaultConfigExecute()

    def chooseFilePath(self):
        self.file_path = QFileDialog.getExistingDirectory(self, "选择解密文件夹路径", "./")
        self.filePathEdit.setText(self.file_path)

    def chooseVaultPath(self):
        self.vault_path = QFileDialog.getExistingDirectory(self, "选择加密文件夹路径", "./")
        self.vaultPathEdit.setText(self.vault_path)
        if self.file_path == "":
            # 如果用户没有设置file path，那么缺省是将file path和vault path设成相同
            self.file_path = self.vault_path
            self.filePathEdit.setText(self.file_path)

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        global app_config
        super(MainWindow,self).__init__()
        self.setupUi(self)
        # 图标
        filename = self.resource_path(os.path.join("assets","AFL_icon.ico"))
        icon = QIcon()
        icon.addPixmap(QPixmap(filename), QIcon.Normal, QIcon.Off)
        self.setWindowIcon(icon)

        app_config = load(open(os.path.join(app_path(),'app_config.json'),'r',encoding='utf8'))
        # self.current_working_on = "" # 防止正在进行加解密操作时进行其他文件夹的加解密
        self.status = ''
        for i in app_config:
            self.vaultList.addItem(i)
        # 隐藏警告信息
        self.progressBar.hide()
        self.progressBar.reset()
        self.progressBar.setRange(0,3)
        self.vaultPathReminderLabel.hide()
        self.progressReminder.hide()
        self.passwordTwiceEdit.hide()
        self.passwordTwiceLabel.hide()
        self.vaultConfigWidget.hide()
        self.refreshButton.hide()
        self.lock.hide()
        self.cancelButton.hide()

    def update_status(self, only_check_if_dir_exist = False):
        """判断密码库状态：待加密、待解密、创建新密码"""
        if not os.path.isdir(self.vault_path):
            self.status = "invalid_vault_path"
        # 库文分离的情况
        elif self.status == 'encrypting' or self.status == 'decrypting':
            pass
        elif os.path.isfile(
                os.path.join(
                    self.file_path,
                    "WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt",
                )
            ):
            if not hasattr(self, "message_shown"):
                QMessageBox.warning(
                    self,
                    "意外退出",
                    f"上次解密{self.vault_name}时意外退出，解密文件处于暴露状态！现在输入密码将使用密码库中的文件解密",
                    QMessageBox.Yes,
                )
                self.message_shown = True  # 防止重复弹出
            self.status = "encrypted"
        elif self.vault_path != self.file_path:
            # 如果file存在
            if os.path.isdir(self.file_path) and not only_check_if_dir_exist:
                # 如果密码库已配置，判定为已解密
                if os.path.isfile(os.path.join(self.vault_path,'config.json')):
                    self.status = "decrypted"
                else: # 如果密码库未配置，要新建密码
                    self.status = "new_password"
            elif self.status == 'change_password':
                # 注意一定要保证self.status的存在
                # 修改密码的过程中如果用户删除了解密文件夹，应该报错（谁会这么无聊）
                self.status == "invalid_file_path"
            elif only_check_if_dir_exist:
                pass
            elif os.path.isfile(os.path.join(self.vault_path,'config.json')): # 如果密码库已配置，判定为已加密
                self.status =  "encrypted"
            else:
                # 没有待加密文件夹
                self.status =  "invalid_file_path"
        # 库文相同
        elif os.path.isfile(os.path.join(self.vault_path,'config.json')):# 不存在配置文件时，新建密码
            if is_encrypted(self.vault_path):
                self.status =  "encrypted"
            else:
                self.status = "decrypted"
        else:
            self.status =  "new_password"
        return self.status

    def updateVaultInfo(self, clear_password_input = True, only_check_if_dir_exist = False):

        if clear_password_input:
            # 清空密码输入字段
            self.passwordEdit.clear()
            self.progressBar.hide()
            self.passwordTwiceEdit.clear()
            self.progressReminder.hide()
        self.update_password_echo_mode(False)
        self.refreshButton.hide()
        self.passwordTwiceEdit.hide()
        self.passwordTwiceLabel.hide()
        self.vaultConfigWidget.show()
        self.changePassword.setEnabled(False)
        self.vaultPathReminderLabel.hide()
        self.OKButton.setEnabled(False)
        self.passwordInputWidget.setEnabled(True)
        self.lock.hide()

        # 检查是否有密码库被选中
        if not self.vaultList.selectedItems():
            # 如果没有密码库选中
            self.file_path = ""
            self.filePathLabel.setText("解密文件夹路径：")
            self.vaultPathLabel.setText("密码库路径：")
            self.vaultPathReminderLabel.hide()
            self.vaultConfigWidget.setEnabled(False)
            self.vaultInfoWidget.setEnabled(False)
            return

        # 获取当前选中的密码库名称并显示
        self.vault_name = self.vaultList.currentItem().text()
        self.vaultNameLabel.setText("密码库：%s" % self.vault_name)
        self.file_path = app_config[self.vault_name]['file_path']
        self.vault_path = app_config[self.vault_name]['vault_path']
        self.vaultPathLabel.setText(f"密码库路径：{self.vault_path}")
        self.filePathLabel.setText(f"解密文件夹路径：{self.file_path}")
        self.vaultInfoWidget.setEnabled(True)

        self.update_status(only_check_if_dir_exist)
        # 如果有密码库被选中，开启密码库设置相关按钮
        if self.status == 'encrypting' or self.status == 'decrypting':
                # 正在加密或解密，显示进度条
                self.progressBar.show()
                self.vaultConfigWidget.setEnabled(False)
                self.passwordInputWidget.setEnabled(True)
                self.vaultConfigWidget.setEnabled(False)
        else:
            self.progressBar.hide()
            self.vaultConfigWidget.setEnabled(True)

        if self.status == "invalid_vault_path":
            # 如果加密目录不存在，显示警告
            self.vaultPathReminderLabel.show()
            self.vaultPathReminderLabel.setText("密码库路径不存在！")
            self.passwordInputWidget.setEnabled(False)
            self.refreshButton.show()
            return "invalid"
        elif self.status == "invalid_file_path":
            self.vaultPathReminderLabel.show()
            self.vaultPathReminderLabel.setText("找不到待加密的文件夹，请先创建这个文件夹")
            self.refreshButton.show()
            self.passwordInputWidget.setEnabled(False)
            return "invalid"
        elif self.status == "new_password":
            self.lock.show()
            self.lock.setStyleSheet('border-image:url(:/link/assets/解锁.svg)')
            self.newPassword()
        elif self.status == "encrypted":
            self.lock.show()
            self.lock.setStyleSheet('border-image:url(:/link/assets/锁定.svg)')
            if os.path.isfile(os.path.join(self.file_path,'WARNING-警告！对这个文件夹下你的文件的任何修改将不被保存.txt')):
                self.vaultNameLabel.setText(f"密码库：{self.vault_name}（解密时意外退出！）")
                self.OKButton.setText("从加密文件恢复")
            else:
                self.vaultNameLabel.setText("密码库：%s（已加密）" % (self.vault_name))
                self.OKButton.setText("解密")
        elif self.status == "decrypted":
            self.lock.show()
            self.lock.setStyleSheet('border-image:url(:/link/assets/解锁.svg)')
            self.vaultNameLabel.setText("密码库：%s（已解密）" % self.vault_name)
            self.OKButton.setText("加密")
            self.changePassword.setEnabled(True)

    def newPassword(self):
        """如果点击了修改密码，或者需要创建新密码时，就使用这个"""
        self.passwordInputWidget.setEnabled(True)
        self.vaultNameLabel.setText("密码库：%s（待加密）" % self.vault_name)
        self.passwordTwiceEdit.show()
        self.passwordTwiceLabel.show()
        self.OKButton.setEnabled(False)
        self.progressReminder.hide()
        if self.status == "new_password":
            self.OKButton.setText("创建新密码")
        elif self.status == "decrypted" or self.status == "change_password":
            # "change_password"作为条件是为了防止用户重复点击修改密码
            self.cancelButton.show()
            self.status = 'change_password'
            self.OKButton.setText("修改密码")
        else:
            raise Exception("密码库状态错误，程序漏洞")

    def OK(self):
        """点击OK的槽函数
        """
        original_status = self.status
        self.updateVaultInfo(clear_password_input = False, only_check_if_dir_exist = True)
        if 'invalid' in self.status or self.status != original_status:
            # 防止用户突然删除与解密相关的文件
            self.passwordEdit.clear()
            self.passwordTwiceEdit.clear()
            return
        inaccessible_files = all_files_can_be_moved(self.vault_path)
        if inaccessible_files:
            QMessageBox.warning(self, '警告', '程序没有得到对密码库以下文件的读写权限！\n'+"\n".join(inaccessible_files))
            self.updateVaultInfo()
            return
        if os.path.isdir(self.file_path):
            inaccessible_files = all_files_can_be_moved(self.file_path)
            if inaccessible_files:
                QMessageBox.warning(self, '警告', '程序没有得到对解密文件夹路径中以下文件的读写权限！\n' + "\n".join(inaccessible_files))
                self.updateVaultInfo()
                return
        if self.status == 'encrypted':
            self.work = file_locker_main.Decrypt(self,self.vault_path,self.file_path,self.passwordEdit.text())
            self.status = 'decrypting'
        elif self.status == 'decrypted':
            self.work = file_locker_main.Encrypt(self,self.vault_path,self.file_path,self.passwordEdit.text())
            self.status = 'encrypting'
        elif self.status == 'change_password' or self.status == 'new_password':
            self.work = file_locker_main.Encrypt(self,self.vault_path,self.file_path,self.passwordEdit.text(),True)
            self.status = 'encrypting'
        else:
            raise Exception('程序漏洞')
        self.progressReminder.clear()
        self.progressReminder.show()
        self.vaultList.setEnabled(False)
        self.addVaultButton.setEnabled(False)
        self.vaultConfigWidget.setEnabled(False)
        self.progressBar.show()
        self.progressBar.setValue(0)
        self.progressBar.setEnabled(True)
        self.work.start()
        self.work.pb_update.connect(self.updateProgressBar)
        self.work.pb_total_changed.connect(self.updatePbTotal)
        self.work.work_thread_status_changed.connect(self.updateProgressReminder)
        self.work.send_warning.connect(self.sendWarning)
        self.work.task_completed.connect(self.taskCompleted)
        self.work.password_incorrect.connect(self.catch_encryption_error)
        self.work.clear_pb.connect(self.clearPb)

    def keyPressEvent(self, a0: QKeyEvent) -> None:
        if (a0.key() == Qt.Key.Key_Enter or a0.key() == Qt.Key.Key_Return) and self.OKButton.isEnabled():
            self.OK()

    def catch_encryption_error(self):
        self.vaultList.setEnabled(True)
        self.addVaultButton.setEnabled(True)
        self.progressReminder.setStyleSheet("color: rgb(184,5,5)")
        self.progressReminder.setText('密码错误')
        self.progressBar.hide()
        if self.status == 'encrypting':
            self.status = 'decrypted'
        elif self.status == 'decrypting':
            self.status = 'encrypted'
        else:
            raise Exception('程序漏洞')
        self.updateVaultInfo(False)

    def updateProgressBar(self, num):
        self.progressBar.setValue(num)

    def clearPb(self):
        self.progressBar.setValue(0)

    def updatePbTotal(self,num):
        self.progressBar.setMaximum(num)

    def updateProgressReminder(self,msg):
        self.progressReminder.setStyleSheet('')
        self.progressReminder.setText(msg)

    def sendWarning(self,msg):
        QMessageBox.warning(self, '警告', msg, QMessageBox.Yes)
        if self.status == 'decrypting':
            self.status = 'decrypted'
        else:
            self.status = 'encrypted'
        self.updateVaultInfo()

    def taskCompleted(self):
        if self.status == 'decrypting':
            msg = '解密成功'
            self.status = 'decrypted'
        else:
            msg = '加密成功'
            self.status = 'encrypted'
        self.vaultList.setEnabled(True)
        self.addVaultButton.setEnabled(True)
        QMessageBox.information(self, msg, msg, QMessageBox.Yes)
        self.updateVaultInfo()

    def measurePasswordStrength(self):
        # 初始化
        pw1 = self.passwordEdit.text()
        pw2 = self.passwordTwiceEdit.text()
        self.progressReminder.show()
        self.progressReminder.setStyleSheet("color: rgb(184,5,5)")
        self.OKButton.setEnabled(False)
        # 如果不是新建密码状态
        if pw1 == "":
            self.progressReminder.setText('密码不能为空！')
        elif self.status != 'new_password' and self.status != 'change_password':
            self.progressReminder.hide()
            self.OKButton.setEnabled(True)
        elif pw1 != pw2:
            self.progressReminder.setText('两次输入的密码不一致！')
        else:
            score = zxcvbn(pw1)['score']
            if score == 0:
                self.progressReminder.setText('密码强度：极弱')
            elif score == 1:
                self.progressReminder.setStyleSheet("color: rgb(255, 106, 27)")
                self.progressReminder.setText('密码强度：弱')
            elif score == 2:
                self.progressReminder.setStyleSheet("color: rgb(150, 133, 45)")
                self.progressReminder.setText('密码强度：中等')
                self.OKButton.setEnabled(True)
            elif score == 3:
                self.progressReminder.setText('密码强度：较强')
                self.progressReminder.setStyleSheet("color: rgb(99, 140, 42)")
                self.OKButton.setEnabled(True)
            elif score == 4:
                self.progressReminder.setStyleSheet("color: rgb(16, 119, 15)")
                self.progressReminder.setText('密码强度：强')
                self.OKButton.setEnabled(True)
            if any(ord(char) > 127 for char in pw1):
                self.progressReminder.setText(self.progressReminder.text() +'（密码中包含非ascii字符！）')
            if re.match(r'.*\s.*',pw1):
                self.progressReminder.setText(self.progressReminder.text() +'（密码中包含空格或换行！）')

    def cancelPasswordChange(self):
        self.passwordTwiceEdit.hide()
        self.passwordTwiceLabel.hide()
        self.progressReminder.hide()
        self.cancelButton.hide()
        self.updateVaultInfo()

    def update_password_echo_mode(self, bool):
        """showPassword - toggled(bool)的槽函数"""
        if bool:
            self.passwordEdit.setEchoMode(QLineEdit.Normal)
            self.passwordTwiceEdit.setEchoMode(QLineEdit.Normal)
        else:
            self.passwordEdit.setEchoMode(QLineEdit.Password)
            self.passwordTwiceEdit.setEchoMode(QLineEdit.Password)

    def update_path(self, name, vault_path,file_path, editting):
        """接收到子窗口传来的信号后，更新文件路径与密码库名称"""
        if not editting:
            # 如果是新建的密码库
            self.vaultList.addItem(name)
            item = self.vaultList.item(self.vaultList.count() - 1)
            self.vaultList.setCurrentItem(item)
        elif len(self.vaultList.selectedItems())>0:
            # 如果有选中的密码库
            if name != self.vaultList.currentItem().text():
                self.vaultList.currentItem().setText(name) # 修改了列表里面的密码库名称，就不用修改info界面的密码库名称了，因为updateVaultInfo方法会自动按照vaultList里面的名称修改
        self.vault_path = vault_path
        self.file_path = file_path
        self.updateVaultInfo()

    def showWarning(self,msg):
        return QMessageBox.warning(self, '删除密码库', msg, QMessageBox.Yes|QMessageBox.Cancel,QMessageBox.Cancel)
        # 待优化：改成中文

    def editVaultSettings(self):
        """槽函数：运行子窗口"""
        global app_config
        vault_name = self.vaultList.currentItem().text()
        self.dialog = MainWindowVaultConfig(self,vault_name, app_config[vault_name]['vault_path'],app_config[vault_name]['file_path'], True)
        self.dialog.path_updated.connect(self.update_path)
        self.dialog.setModal(True)
        # myVaultWin一定要加self
        self.dialog.show()

    def addVault(self):
        """槽函数：新建密码库"""
        global app_config
        self.dialog = MainWindowVaultConfig(self)
        self.dialog.path_updated.connect(self.update_path)
        self.dialog.setModal(True)
        self.dialog.show()

    def deleteVault(self):
        """槽函数：删除密码库"""
        reply = self.showWarning("确认删除密码库吗？程序不会删除你的文件。")
        if reply == QMessageBox.Yes:
            del app_config[self.vault_name]
            dump(app_config,open(os.path.join(app_path(),'app_config.json'),'w',encoding='utf8'))
            self.vaultList.takeItem(self.vaultList.currentRow())
            self.updateVaultInfo()
    def resource_path(self, relative_path):
        """
        根据给定的相对路径获取资源的绝对路径。

        这个方法是为了处理PyInstaller打包后的可执行文件资源访问问题。
        在打包模式下，sys.frozen会被设置为True，从而使用sys._MEIPASS作为基路径；
        在非打包模式下，则使用当前目录作为基路径。

        参数:
        relative_path (str): 资源的相对路径。

        返回:
        str: 资源的绝对路径。
        """
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)


if __name__ == "__main__":
    if not os.path.isfile(os.path.join(app_path(),'app_config.json')):
        dump({},open(os.path.join(app_path(),'app_config.json'),'w',encoding='utf-8'))
    app = QApplication(sys.argv)
    myWin = MainWindow()
    myWin.show()
    sys.exit(app.exec_())