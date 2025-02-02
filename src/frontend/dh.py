from utils import add_build_to_path
add_build_to_path()

import base64
from wrappers.dh import DiffieHellman
from wrappers.enums import SecurityLevel

from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from error_handling import show_error_dialog

WIREFRAME_PATH = "src/frontend/wireframes"

class DHUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(DHUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_dh.ui", self)
        self.selectedHash = None
        self.secLevel = None
        self.initButtons()
        
    def initButtons(self):
        self.btnSecretGen.clicked.connect(self.generateSecret)
        self.btnKeyEx.clicked.connect(self.keyExchange)
        
    def generateSecret(self):
        try:
            selectedLevel = self.selSecLevel.checkedButton().text()
            if '0' in selectedLevel.lower():
                secLevel = SecurityLevel.L0
            else:
                secLevel = SecurityLevel.L1
            self.dh = DiffieHellman(secLevel)
            self.sA = self.dh.gen_secret()
            self.sB = self.dh.gen_secret()
            self.outputSecretA.setText(str(base64.b64encode(self.sA))[2:-1])
            self.outputSecretB.setText(str(base64.b64encode(self.sB))[2:-1])
        except Exception as e:
            show_error_dialog(str(e))
    
    def keyExchange(self):
        try:
            pA = self.dh.gen_public(self.sA)
            pB = self.dh.gen_public(self.sB)
            sharedSecretA = self.dh.compute_shared_secret(self.sA, pB)
            sharedSecretB = self.dh.compute_shared_secret(self.sB, pA)
            
            self.outputText.clear()
            self.outputText.append("Shared Secret A:")
            self.outputText.append(str(base64.b64encode(sharedSecretA))[2:-1])
            self.outputText.append("Shared Secret B:")
            self.outputText.append(str(base64.b64encode(sharedSecretB))[2:-1])
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = DHUI()
    widget.show()
    sys.exit(app.exec_())