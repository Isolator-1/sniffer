import sys,ctypes,os,time,shutil
from datetime import datetime

import MainWindow,SelectionWindow
from packetAnalyzer import getSummary, getTreeInfo
from filter import checkPackages
from utils import stdoutCapture

from PyQt6.QtWidgets import QApplication, QWidget,QTableWidgetItem
from PyQt6 import QtCore, QtGui, QtWidgets

import libpcap as pcap
from winpcapy import WinPcapDevices,WinPcapUtils
import winpcapy
from scapy.all import *
from threading import Thread

from io import BytesIO

'''
import winpcapy报错:
ImportError: cannot import name 'Callable' from 'collections'

在winpcapy.py中
将from Callable import Callable
改为from typing import Callable

Python版本的问题
'''
 
#pyqt6-tools designer (windows)  linux的在~/.local/bin里
#pyuic6  test.ui -o test.py

interfaces = None
globalFilter = None
threadCapture = None
threadCaptureControl = True
threadAnalyze = None
threadAnalyzeControl = True
FilterList = []
PackagesList = []
RuleChangedSignal = False
CurrentRule = ""

Capturelock = threading.Lock()
Analyzelock = threading.Lock()

def threadForCapture():
    with Capturelock:
        print("----------Capture Start------------")
        global interfaces
        global threadCaptureControl
        device = bytes(interfaces.split(" ")[0],encoding="utf-8")
        print("Sniffer on the :" , device)
        errbuf = ctypes.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        handle = pcap.open_live(device,4096,1,1000,errbuf)
        if errbuf.value:
            print("hanle error :",errbuf.value) 
        fname = b"cash.cap"
        fPcap = pcap.dump_open(handle,fname)
        while threadCaptureControl:
            pheader = pcap.pkthdr()
            fPcapUbyte = ctypes.cast(fPcap,ctypes.POINTER(ctypes.c_ubyte))
            packet = pcap.next(handle,pheader)
            pcap.dump(fPcapUbyte,pheader,packet)

        print("----------Capture Terminate--------")

def threadForAnalyze(mainWindowUI):
    with Analyzelock:
        global threadAnalyzeControl
        global FilterList
        global PackagesList
        global CurrentRule
        while threadAnalyzeControl:
            # 按规则更新新的数据包
            if os.path.exists("./cash.cap"):
                try:
                    packets = rdpcap('cash.cap')
                except :
                    # cash.cap is empty
                    time.sleep(0.1)
                    continue
                newPackets = [x for x  in packets if x not in PackagesList]
                for packet in newPackets:
                    if checkPackages(packet, CurrentRule) == True: # 保证filterList中的元素一一对应tableWidget的元素
                        FilterList.append(packet)
                        Source,Destination,Protocol,Length,Info = getSummary(packet)
                        rowPosition = mainWindowUI.tableWidget.rowCount()
                        mainWindowUI.tableWidget.insertRow(rowPosition)
                        mainWindowUI.tableWidget.setItem(rowPosition, 0, QTableWidgetItem(str(Source)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 1, QTableWidgetItem(str(Destination)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 2, QTableWidgetItem(str(Protocol)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 3, QTableWidgetItem(str(Length)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 4, QTableWidgetItem(str(Info)))
                PackagesList.extend(newPackets)
                time.sleep(0.1)
            else:
                time.sleep(0.1)


def onSelectionButtonClicked(UI,Window,mainWindow):
    global interfaces
    text = UI.comboBox.currentText()
    if text == "请选择网卡":
        msg = QtWidgets.QMessageBox()
        msg.setText("请选择网卡")
        msg.exec()
    else:
        interfaces = text
        #print(interfaces)
        Window.close()
        mainWindow.show()

def onStartButtonClicked(mainWindowUI):
    global threadCapture
    global threadCaptureControl
    global threadAnalyze
    global threadAnalyzeControl
    global FilterList
    if mainWindowUI.startButton.text() == "开始":
        threadCapture = Thread(target=threadForCapture)
        threadCaptureControl = True
        threadCapture.start()
        threadAnalyze = Thread(target=threadForAnalyze,args=[mainWindowUI])
        threadAnalyzeControl = True
        threadAnalyze.start()
        mainWindowUI.startButton.setText("停止")
    elif mainWindowUI.startButton.text() == "停止":
        threadCaptureControl = False
        threadCapture.join()
        threadAnalyzeControl = False
        threadAnalyze.join()
        mainWindowUI.startButton.setText("开始")
        # 保存cap文件
        shutil.copyfile("./cash.cap", "./Save/" + datetime.strftime(datetime.now(),'%Y-%m%d-%H-%M-%S') + ".cap")


def onFilterButtonClicked(mainWindowUI):
    global CurrentRule
    global PackagesList
    newRule = mainWindowUI.textEdit.toPlainText()
    if CurrentRule != newRule:
        with Analyzelock: # 加锁是因为两个线程同时占用FilterList，CurrentRule
            #检查 filter 是否更改
            newRule = mainWindowUI.textEdit.toPlainText()
            CurrentRule = newRule
            print("CurrentRule is \"{}\"".format(CurrentRule))
            # 更新旧有的数据包
            mainWindowUI.tableWidget.setRowCount(0)
            for packet in PackagesList:
                    if checkPackages(packet, CurrentRule) == True: # 保证filterList中的元素一一对应tableWidget的元素
                        FilterList.append(packet)
                        Source,Destination,Protocol,Length,Info = getSummary(packet)
                        rowPosition = mainWindowUI.tableWidget.rowCount()
                        mainWindowUI.tableWidget.insertRow(rowPosition)
                        mainWindowUI.tableWidget.setItem(rowPosition, 0, QTableWidgetItem(str(Source)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 1, QTableWidgetItem(str(Destination)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 2, QTableWidgetItem(str(Protocol)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 3, QTableWidgetItem(str(Length)))
                        mainWindowUI.tableWidget.setItem(rowPosition, 4, QTableWidgetItem(str(Info)))
    else:
        msg = QtWidgets.QMessageBox()
        msg.setText("规则未改变")
        msg.exec()

def updateInformation(item,mainWindowUI):
    global FilterList
    row = item.row()
    hexd = stdoutCapture(hexdump,FilterList[row],Capturelock,Analyzelock)
    mainWindowUI.textBrowser.setText(hexd)
    tree = getTreeInfo(FilterList[row])
    mainWindowUI.textBrowser_2.setText(tree)



def main():
    app = QtWidgets.QApplication(sys.argv)
    selectionWindow = QtWidgets.QWidget()
    selectionWindowUI = SelectionWindow.Ui_Form()
    selectionWindowUI.setupUi(selectionWindow)
    selectionWindowUI.setupUi(selectionWindow)

    selectionWindowUI.comboBox.addItem("请选择网卡")

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
    mainWindowUI.tableWidget.itemClicked.connect(lambda item: updateInformation(item, mainWindowUI))

    sys.exit(app.exec())

    


if __name__ == '__main__':
    main()
