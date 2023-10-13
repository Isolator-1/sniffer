from logging import exception
import sys
import MainWindow,SelectionWindow, filter
from PyQt6.QtWidgets import QApplication, QWidget
from PyQt6 import QtCore, QtGui, QtWidgets


from winpcapy import WinPcapDevices,WinPcapUtils
import winpcapy
'''
import winpcapy报错:
ImportError: cannot import name 'Callable' from 'collections'

在winpcapy.py中
将from Callable import Callable
改为from typing import Callable

Python版本的问题
'''

#pyqt6-tools designer
#pyuic6  test.ui -o test.py

interfaces = None
globalFilter = None


def onSelectionButtonClicked(UI,Window,mainWindow):
    global interfaces
    text = UI.comboBox.currentText()
    if text == "请选择网卡":
        msg = QtWidgets.QMessageBox()
        msg.setText("请选择网卡")
        msg.exec()
    else:
        interfaces = text
        print(interfaces)
        Window.close()
        mainWindow.show()



def onStartButtonClicked(mainWindowUI):
    global interfaces
    global globalFilter
    #启动一个线程开始写入文本文件
    deviceName = interfaces.split(" ")[0]
    #print(deviceName)
    with winpcapy.WinPcap("WLAN") as pcap:
        pcap.run()

def onFilterButtonClicked(mainWindowUI):
    global interfaces
    global globalFilter
    if interfaces == None:
        raise exception("interfaces not set")
    globalFilter = filter.RuleFilter(mainWindowUI.textEdit.toPlainText()) # return a list filled with packages
    



def main():
    app = QtWidgets.QApplication(sys.argv)
    selectionWindow = QtWidgets.QWidget()
    selectionWindowUI = SelectionWindow.Ui_Form()
    selectionWindowUI.setupUi(selectionWindow)
    selectionWindowUI.setupUi(selectionWindow)

    selectionWindowUI.comboBox.addItem("请选择网卡")
    with WinPcapDevices() as devices:
        for device in devices:
            selectionWindowUI.comboBox.addItem(str(device.name)[2:-1] + " " +  str(device.description)[2:-1])

    selectionWindowUI.pushButton.clicked.connect(lambda:onSelectionButtonClicked(selectionWindowUI,selectionWindow,mainWindow))
    selectionWindow.show()



    
    mainWindow = QtWidgets.QMainWindow()
    mainWindowUI = MainWindow.Ui_MainWindow()
    mainWindowUI.setupUi(mainWindow)
    mainWindowUI.filterButton.clicked.connect(lambda:onFilterButtonClicked(mainWindowUI))
    mainWindowUI.startButton.clicked.connect(lambda:onStartButtonClicked(mainWindowUI))
    sys.exit(app.exec())

    


if __name__ == '__main__':
    main()
