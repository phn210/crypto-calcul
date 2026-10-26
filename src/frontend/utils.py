import os
from PyQt5.QtWidgets import QMessageBox

WIREFRAME_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wireframes')

def show_error_dialog(message: str):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("Error")
    msg.setInformativeText(message)
    msg.setWindowTitle("Error")
    msg.exec_()