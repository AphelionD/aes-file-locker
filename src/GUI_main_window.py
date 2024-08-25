import sys
from PyQt5.QtWidgets import QMainWindow,QApplication,QLineEdit,QMessageBox
from Ui_main_window_2 import Ui_MainWindow
from PyQt5.QtCore import QThread, pyqtSignal
import time
import random

class MyMainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MyMainWindow,self).__init__()
        self.setupUi(self)
        self.work = WorkThread()

        self.progressBar.hide()
        self.progressBar.reset()
        self.progressBar.setRange(0,3)
    def update_password_echo_mode(self, bool):
        """showPassword - toggled(bool)的槽函数"""
        if bool:
            self.passwordEdit.setEchoMode(QLineEdit.Normal)
            self.passwordTwiceEdit.setEchoMode(QLineEdit.Normal)
        else:
            self.passwordEdit.setEchoMode(QLineEdit.Password)
            self.passwordTwiceEdit.setEchoMode(QLineEdit.Password)

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
    myWin = MyMainWindow()
    myWin.show()
    sys.exit(app.exec_())