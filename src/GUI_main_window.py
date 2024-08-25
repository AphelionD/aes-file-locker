import sys
from PyQt5.QtWidgets import QMainWindow,QApplication,QLineEdit,QMessageBox, QFileDialog
from Ui_main_window import Ui_MainWindow
from Ui_vault_config_window import Ui_MainWindowVaultConfig
from PyQt5.QtCore import QThread, pyqtSignal
import file_locker_main
import time
import random
from ejson import dump,dumps,load,loads
import os

app_config = None
class MainWindowVaultConfig(QMainWindow, Ui_MainWindowVaultConfig):
    path_updated = pyqtSignal(str,str,str)
    def __init__(self, parent = None, vault_name = "", vault_path = "", file_path = ""):
        super(MainWindowVaultConfig,self).__init__(parent)
        self.setupUi(self)
        self.resize(550,450)
        self.original_vault_name = vault_name
        self.vault_path = vault_path
        self.file_path = file_path
        if vault_path != file_path:
            self.link_label.hide()
        self.VaultNameEdit.setText(vault_name)
        self.vaultPathEdit.setText(vault_path)
        self.filePathEdit.setText(file_path)
        self.vaultNameReminder.hide()
        self.vaultPathReminder.hide()
        self.filePathReminder.hide()

    def checkVaultNameValidity(self):
        if self.VaultNameEdit.text() == "":
            self.vaultNameReminder.show()
            self.vaultNameReminder.setText("密码库名称不能为空！")
            self.OKButton.setEnabled(False)
        elif self.VaultNameEdit.text() in app_config and self.VaultNameEdit.text() != self.original_vault_name:
            self.vaultNameReminder.show()
            self.vaultNameReminder.setText("密码库名称已存在！")
            self.OKButton.setEnabled(False)

        else:
            self.vaultNameReminder.hide()
            self.OKButton.setEnabled(True)
    def updateLinkIcon(self):
        self.vault_path = self.vaultPathEdit.text()
        self.file_path = self.filePathEdit.text()
        if os.path.isdir(self.vault_path):
            self.vaultPathReminder.hide()
        else:
            self.vaultPathReminder.show()
        if os.path.isdir(self.file_path):
            self.filePathReminder.hide()
        else:
            self.filePathReminder.show()
        if os.path.isdir(self.vault_path) and os.path.isdir(self.file_path):
            if self.vault_path == self.file_path:
                self.link_label.show()
            else:
                self.link_label.hide()
            self.OKButton.setEnabled(True)
        else:
            self.OKButton.setEnabled(False)
    def vaultConfigExecute(self):
        global app_config
        if self.VaultNameEdit.text() != self.original_vault_name:
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
        self.path_updated.emit(self.VaultNameEdit.text(),self.vault_path,self.file_path)
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
    def showWarningMsg(self,msg):
        QMessageBox.warning(self, 'Warning', msg, QMessageBox.Yes)

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
        self.filePathReminderLabel.hide()

    def updateVaultInfo(self):
        self.vaultConfigWidget.setEnabled(True)
        self.vaultInfoWidget.setEnabled(True)
        self.vault_name = self.vaultList.currentItem().text()
        self.vaultNameLabel.setText("密码库：%s" % self.vault_name)
        self.vault_path = app_config[self.vault_name]['vault_path']
        if not os.path.isdir(self.vault_path):
            # 如果加密目录不存在，显示警告
            self.vaultPathReminderLabel.show()
            self.passwordInputWidget.setEnabled(False)
        else:
            self.file_path = app_config[self.vault_name]['file_path']
            self.vaultPathLabel.setText(f"密码库路径：{self.vault_path}")
            self.filePathLabel.setText(f"解密文件夹路径：{self.file_path}")
            self.vaultPathReminderLabel.hide()
            self.filePathReminderLabel.hide()
            self.passwordInputWidget.setEnabled(True)
            if self.vault_path != self.file_path:
                # 库文分离
                is_encrypted = not os.path.isdir(self.file_path)
            else:
                is_encrypted = file_locker_main.is_encrypted(self.vault_path)
            self.vaultNameLabel.setText("密码库：%s（已%s）" % (self.vault_name, "加密" if is_encrypted else "解密"))

    def update_password_echo_mode(self, bool):
        """showPassword - toggled(bool)的槽函数"""
        if bool:
            self.passwordEdit.setEchoMode(QLineEdit.Normal)
            self.passwordTwiceEdit.setEchoMode(QLineEdit.Normal)
        else:
            self.passwordEdit.setEchoMode(QLineEdit.Password)
            self.passwordTwiceEdit.setEchoMode(QLineEdit.Password)

    def update_path(self,name, vault_path,file_path):
        """接收到子窗口传来的信号后，更新文件路径与密码库名称"""
        if name != self.vaultList.currentItem().text():
            self.vaultList.currentItem().setText(name)
        self.vault_path = vault_path
        self.file_path = file_path
        self.updateVaultInfo()
    def launchVaultWin(self):
        global app_config
        vault_name = self.vaultList.currentItem().text()
        self.myVaultWin = MainWindowVaultConfig(self,vault_name, app_config[vault_name]['vault_path'],app_config[vault_name]['file_path'])
        self.myVaultWin.path_updated.connect(self.update_path)
        # myVaultWin一定要加self
        self.myVaultWin.show()
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