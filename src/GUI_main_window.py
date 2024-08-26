import sys
from PyQt5.QtWidgets import QMainWindow,QApplication,QLineEdit,QMessageBox, QFileDialog, QDialog
from Ui_main_window import Ui_MainWindow
from Ui_vaut_config_dialog import Ui_Dialog
from PyQt5.QtCore import QThread, pyqtSignal
import file_locker_main
import time
import random
from ejson import dump,load
import os
from zxcvbn import zxcvbn

app_config = None
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
            self.link_label.hide()

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
        """更新路径检查提示，更新link图标"""
        flag = True # flag必须通过全部检查点才可以变成True
        if self.VaultNameEdit.text() == "":
            self.vaultNameReminder.show()
            self.vaultNameReminder.setText("密码库名称不能为空！")
            flag = False
        elif self.VaultNameEdit.text() in app_config and self.VaultNameEdit.text() != self.original_vault_name:
            self.vaultNameReminder.show()
            self.vaultNameReminder.setText("密码库名称已存在！")
            flag = False
        else:
            self.vaultNameReminder.hide()
        self.vault_path = self.vaultPathEdit.text()
        self.file_path = self.filePathEdit.text()
        if os.path.isdir(self.vault_path):
            self.vaultPathReminder.hide()
        else:
            self.vaultPathReminder.show()
        if os.path.isdir(os.path.split(self.file_path)[0]):
            self.filePathReminder.hide()
        else:
            self.filePathReminder.show()
        if os.path.isdir(self.vault_path) and os.path.isdir(os.path.split(self.file_path)[0]):
            if self.vault_path == self.file_path:
                self.link_label.show()
            else:
                self.link_label.hide()
        else:
            flag = False
        self.OKButton.setEnabled(flag)
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
        dump(app_config,open("app_config.json",'w',encoding='utf8'))
        self.path_updated.emit(self.VaultNameEdit.text(),self.vault_path,self.file_path, self.editting)
        self.close()

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
        self.work = WorkThread()
        app_config = load(open("app_config.json",'r',encoding='utf8'))
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

    def get_status(self):
        """判断密码库状态：待加密、待解密、创建新密码"""
        if not os.path.isdir(self.vault_path):
            self.status = "invalid_vault_path"
        # 库文分离的情况
        elif self.vault_path != self.file_path:
            # 如果file存在
            if not hasattr(self,'status'):
                self.status = ''
            if os.path.isdir(self.file_path):
                # 如果密码库已配置，判定为已解密
                if os.path.isfile(os.path.join(self.vault_path,'config.json')):
                    self.status = "decrypted"
                else: # 如果密码库未配置，要新建密码
                    self.status = "new_password"
            elif self.status == 'change_password':
                # 注意一定要保证self.status的存在
                # 修改密码的过程中如果用户删除了解密文件夹，应该报错（谁会这么无聊）
                self.status == "invalid_file_path"
            elif os.path.isfile(os.path.join(self.vault_path,'config.json')): # 如果密码库已配置，判定为已加密
                self.status =  "encrypted"
            else:
                # 没有待加密文件夹
                self.status =  "invalid_file_path"
        # 库文相同
        elif os.path.isfile(os.path.join(self.vault_path,'config.json')):# 不存在配置文件时，新建密码
            if file_locker_main.is_encrypted(self.vault_path):
                self.status =  "encrypted"
            else:
                self.status = "decrypted"
        else:
            self.status =  "new_password"
        return self.status

    def updateVaultInfo(self):
        # 清空密码输入字段
        self.passwordEdit.clear()
        self.passwordTwiceEdit.clear()
        self.refreshButton.hide()
        self.progressReminder.hide()
        self.passwordTwiceEdit.hide()
        self.passwordTwiceLabel.hide()
        self.vaultConfigWidget.show()
        self.changePassword.setEnabled(False)
        self.vaultPathReminderLabel.hide()
        self.OKButton.setEnabled(False)

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

        # 如果有密码库被选中，开启密码库设置相关按钮
        self.vaultConfigWidget.setEnabled(True)
        self.vaultInfoWidget.setEnabled(True)

        # 获取当前选中的密码库名称并显示
        self.vault_name = self.vaultList.currentItem().text()
        self.vaultNameLabel.setText("密码库：%s" % self.vault_name)
        self.file_path = app_config[self.vault_name]['file_path']
        self.vault_path = app_config[self.vault_name]['vault_path']
        self.vaultPathLabel.setText(f"密码库路径：{self.vault_path}")
        self.filePathLabel.setText(f"解密文件夹路径：{self.file_path}")


        self.get_status()

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
            self.newPassword()
        elif self.status == "encrypted":
            self.vaultNameLabel.setText("密码库：%s（已加密）" % (self.vault_name))
            self.OKButton.setText("解密")
        elif self.status == "decrypted":
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
            self.status = 'change_password'
            self.OKButton.setText("修改密码")
        else:
            raise Exception("密码库状态错误，程序漏洞")

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
            dump(app_config,open("app_config.json",'w',encoding='utf8'))
            self.vaultList.takeItem(self.vaultList.currentRow())
            self.updateVaultInfo()

class WorkThread(QThread):
    # 自定义信号对象。参数str就代表这个信号可以传一个字符串
    trigger = pyqtSignal(int)

    def __int__(self):
        # 初始化函数
        super(WorkThread, self).__init__()

    def run(self):
        #重写线程执行的run函数
        #触发自定义信号
        for i in range(3):
            time.sleep(1+random.random())
            # 通过自定义信号把待显示的字符串传递给槽函数
            self.trigger.emit(i+1)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWin = MainWindow()
    myWin.show()
    sys.exit(app.exec_())