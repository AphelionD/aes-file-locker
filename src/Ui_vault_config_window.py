# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'c:\华为家庭存储\多媒体、计算机文件\编程\aes-file-locker\src\vault_config_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindowVaultConfig(object):
    def setupUi(self, MainWindowVaultConfig):
        MainWindowVaultConfig.setObjectName("MainWindowVaultConfig")
        MainWindowVaultConfig.resize(447, 378)
        MainWindowVaultConfig.setBaseSize(QtCore.QSize(800, 400))
        self.centralwidget = QtWidgets.QWidget(MainWindowVaultConfig)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setContentsMargins(40, 30, 40, 30)
        self.gridLayout.setVerticalSpacing(5)
        self.gridLayout.setObjectName("gridLayout")
        self.vaultNameLabel = QtWidgets.QLabel(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.vaultNameLabel.setFont(font)
        self.vaultNameLabel.setObjectName("vaultNameLabel")
        self.gridLayout.addWidget(self.vaultNameLabel, 0, 0, 1, 1)
        self.VaultNameEdit = QtWidgets.QLineEdit(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.VaultNameEdit.setFont(font)
        self.VaultNameEdit.setObjectName("VaultNameEdit")
        self.gridLayout.addWidget(self.VaultNameEdit, 0, 1, 1, 1)
        self.vaultNameReminder = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.vaultNameReminder.sizePolicy().hasHeightForWidth())
        self.vaultNameReminder.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setBold(True)
        font.setWeight(75)
        self.vaultNameReminder.setFont(font)
        self.vaultNameReminder.setStyleSheet("color:rgb(170, 0, 0)")
        self.vaultNameReminder.setObjectName("vaultNameReminder")
        self.gridLayout.addWidget(self.vaultNameReminder, 1, 0, 1, 1)
        self.vaultPathLabel = QtWidgets.QLabel(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.vaultPathLabel.setFont(font)
        self.vaultPathLabel.setObjectName("vaultPathLabel")
        self.gridLayout.addWidget(self.vaultPathLabel, 2, 0, 1, 1)
        self.vaultPathEdit = QtWidgets.QLineEdit(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.vaultPathEdit.setFont(font)
        self.vaultPathEdit.setObjectName("vaultPathEdit")
        self.gridLayout.addWidget(self.vaultPathEdit, 2, 1, 1, 1)
        self.vaultPathToolButton = QtWidgets.QToolButton(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.vaultPathToolButton.setFont(font)
        self.vaultPathToolButton.setObjectName("vaultPathToolButton")
        self.gridLayout.addWidget(self.vaultPathToolButton, 2, 2, 1, 1)
        self.vaultPathReminder = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.vaultPathReminder.sizePolicy().hasHeightForWidth())
        self.vaultPathReminder.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setBold(True)
        font.setWeight(75)
        self.vaultPathReminder.setFont(font)
        self.vaultPathReminder.setStyleSheet("color:rgb(170, 0, 0)")
        self.vaultPathReminder.setObjectName("vaultPathReminder")
        self.gridLayout.addWidget(self.vaultPathReminder, 3, 0, 1, 1)
        self.link_label = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.link_label.sizePolicy().hasHeightForWidth())
        self.link_label.setSizePolicy(sizePolicy)
        self.link_label.setMinimumSize(QtCore.QSize(30, 30))
        self.link_label.setMaximumSize(QtCore.QSize(30, 30))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.link_label.setFont(font)
        self.link_label.setStyleSheet("border-image:url(:/link/link.svg)")
        self.link_label.setText("")
        self.link_label.setAlignment(QtCore.Qt.AlignCenter)
        self.link_label.setObjectName("link_label")
        self.gridLayout.addWidget(self.link_label, 3, 1, 1, 1, QtCore.Qt.AlignHCenter)
        self.filePathLabel = QtWidgets.QLabel(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.filePathLabel.setFont(font)
        self.filePathLabel.setObjectName("filePathLabel")
        self.gridLayout.addWidget(self.filePathLabel, 4, 0, 1, 1)
        self.filePathEdit = QtWidgets.QLineEdit(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.filePathEdit.setFont(font)
        self.filePathEdit.setObjectName("filePathEdit")
        self.gridLayout.addWidget(self.filePathEdit, 4, 1, 1, 1)
        self.filePathToolButton = QtWidgets.QToolButton(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.filePathToolButton.setFont(font)
        self.filePathToolButton.setObjectName("filePathToolButton")
        self.gridLayout.addWidget(self.filePathToolButton, 4, 2, 1, 1)
        self.filePathReminder = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.filePathReminder.sizePolicy().hasHeightForWidth())
        self.filePathReminder.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setBold(True)
        font.setWeight(75)
        self.filePathReminder.setFont(font)
        self.filePathReminder.setStyleSheet("color:rgb(170, 0, 0)")
        self.filePathReminder.setObjectName("filePathReminder")
        self.gridLayout.addWidget(self.filePathReminder, 5, 0, 1, 2)
        self.OKButton = QtWidgets.QPushButton(self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.OKButton.setFont(font)
        self.OKButton.setObjectName("OKButton")
        self.gridLayout.addWidget(self.OKButton, 6, 0, 1, 1)
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setMaximumSize(QtCore.QSize(120, 16777215))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 6, 1, 1, 1, QtCore.Qt.AlignRight)
        MainWindowVaultConfig.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindowVaultConfig)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 447, 23))
        self.menubar.setObjectName("menubar")
        MainWindowVaultConfig.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindowVaultConfig)
        self.statusbar.setObjectName("statusbar")
        MainWindowVaultConfig.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindowVaultConfig)
        self.vaultPathEdit.textChanged['QString'].connect(MainWindowVaultConfig.updateLinkIcon) # type: ignore
        self.filePathEdit.textChanged['QString'].connect(MainWindowVaultConfig.updateLinkIcon) # type: ignore
        self.vaultPathToolButton.clicked.connect(MainWindowVaultConfig.chooseVaultPath) # type: ignore
        self.filePathToolButton.clicked.connect(MainWindowVaultConfig.chooseVaultPath) # type: ignore
        self.VaultNameEdit.textChanged['QString'].connect(MainWindowVaultConfig.checkVaultNameValidity) # type: ignore
        self.pushButton.clicked.connect(MainWindowVaultConfig.close) # type: ignore
        self.OKButton.clicked.connect(MainWindowVaultConfig.vaultConfigExecute) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(MainWindowVaultConfig)

    def retranslateUi(self, MainWindowVaultConfig):
        _translate = QtCore.QCoreApplication.translate
        MainWindowVaultConfig.setWindowTitle(_translate("MainWindowVaultConfig", "MainWindow"))
        self.vaultNameLabel.setWhatsThis(_translate("MainWindowVaultConfig", "<html><head/><body><p>为你的密码库取一个名称，便于记忆</p></body></html>"))
        self.vaultNameLabel.setText(_translate("MainWindowVaultConfig", "密码库名称"))
        self.vaultNameReminder.setText(_translate("MainWindowVaultConfig", "密码库名称已存在！"))
        self.vaultPathLabel.setToolTip(_translate("MainWindowVaultConfig", "<html><head/><body><p>加密后的文件会放在这里</p></body></html>"))
        self.vaultPathLabel.setText(_translate("MainWindowVaultConfig", "密码库路径"))
        self.vaultPathToolButton.setText(_translate("MainWindowVaultConfig", "..."))
        self.vaultPathReminder.setText(_translate("MainWindowVaultConfig", "密码库路径不存在！"))
        self.link_label.setToolTip(_translate("MainWindowVaultConfig", "<html><head/><body><p><br/></p></body></html>"))
        self.link_label.setWhatsThis(_translate("MainWindowVaultConfig", "<html><head/><body><p><br/></p></body></html>"))
        self.filePathLabel.setToolTip(_translate("MainWindowVaultConfig", "<html><head/><body><p><br/></p></body></html>"))
        self.filePathLabel.setWhatsThis(_translate("MainWindowVaultConfig", "<html><head/><body><p>解密后的文件会放在这里</p></body></html>"))
        self.filePathLabel.setText(_translate("MainWindowVaultConfig", "解密文件夹路径"))
        self.filePathToolButton.setText(_translate("MainWindowVaultConfig", "..."))
        self.filePathReminder.setText(_translate("MainWindowVaultConfig", "解密文件夹路径不存在！"))
        self.OKButton.setText(_translate("MainWindowVaultConfig", "确定"))
        self.pushButton.setText(_translate("MainWindowVaultConfig", "关闭"))
import pictures_rc
