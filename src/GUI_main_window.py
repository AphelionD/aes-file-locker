import sys
from PyQt5.QtWidgets import QMainWindow,QApplication,QLineEdit,QMessageBox, QFileDialog, QDialog
from Ui_main_window import Ui_MainWindow
from Ui_vaut_config_dialog import Ui_Dialog
from PyQt5.QtCore import QThread, pyqtSignal
import file_locker_main
import time
import random
from ejson import dump,dumps,load,loads
import os

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

    def updateVaultInfo(self):
        if not self.vaultList.selectedItems():
            # 如果没有密码库选中
            self.file_path = ""
            self.filePathLabel.setText("解密文件夹路径：")
            self.vaultPathLabel.setText("密码库路径：")
            self.vaultPathReminderLabel.hide()
            self.vaultConfigWidget.setEnabled(False)
            self.vaultInfoWidget.setEnabled(False)
            return
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