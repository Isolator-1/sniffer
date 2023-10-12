import sys
import MainWindow
from PyQt6.QtWidgets import QApplication, QWidget
from PyQt6 import QtCore, QtGui, QtWidgets

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