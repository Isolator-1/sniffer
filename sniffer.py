import sys
import MainWindow
from PyQt6.QtWidgets import QApplication, QWidget
from PyQt6 import QtCore, QtGui, QtWidgets

import winpcapy
'''
import winpcapy报错:
ImportError: cannot import name 'Callable' from 'collections'

将from Callable import Callable
改为from typing import Callable

Python版本的问题
'''

#pyqt6-tools designer
#pyuic6  test.ui -o test.py


def main():

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    ui = MainWindow.Ui_MainWindow()
    ui.setupUi(mw)
    mw.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
