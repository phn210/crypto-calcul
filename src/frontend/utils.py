import os, platform, sys
from PyQt5.QtWidgets import QMessageBox

WIREFRAME_PATH = 'src/frontend/wireframes'

def add_build_to_path(name='build'):
    path_sep = '/'
    if platform.system() == 'Windows':
        path_sep = '\\'
    index = os.getcwd().split(path_sep).index('crypto-calcul')
    path = path_sep.join(os.getcwd().split(path_sep)[:index+1] + [name])
    sys.path.append(path)

def show_error_dialog(message: str):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("Error")
    msg.setInformativeText(message)
    msg.setWindowTitle("Error")
    msg.exec_()