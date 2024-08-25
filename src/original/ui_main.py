import sys
from PyQt5.QtWidgets import QMainWindow,QApplication,QLineEdit,QMessageBox
from Ui_main_window import Ui_Dialog
from PyQt5.QtCore import QThread, pyqtSignal
import time
import random

class MyMainWindow(QMainWindow, Ui_Dialog):
    def __init__(self):
        super(MyMainWindow,self).__init__()
        self.setupUi(self)
        self.work = WorkThread()
        self.password_hidden = True
        self.checkBox.stateChanged.connect(self.changeText)
        self.Button_OK.clicked.connect(self.check_password)
        self.progressBar.hide()
        self.progressBar.reset()
        self.progressBar.setRange(0,3)
        self.progressBar.valueChanged.connect(self.show_msg)
    def changeText(self):
        if self.password_hidden:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_hidden = False
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_hidden = True
    def check_password(self):
        self.progressBar.setVisible(True)
        self.work.start()
        self.work.trigger.connect(self.displayBar)
    def show_msg(self):
        if self.progressBar.value()==3:
            print(self.password_input.text())
            msg = QMessageBox(self)
            msg.setText('Password Correct')
            msg.exec()
            self.close()
    def displayBar(self,num):
        self.progressBar.setValue(num)

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