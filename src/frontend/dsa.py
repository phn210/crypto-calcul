
from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.dsa import DSA
from wrappers.enums import HashFunction, SecurityLevel

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi

class DsaUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(DsaUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_dsa.ui", self)
        self.selectedHash = None
        self.secLevel = None
        self.initButtons()

    def initButtons(self):
        for btn in self.selSecLevel.buttons():
            btn.clicked.connect(self.toggleSecurityLevel)
        for btn in self.selHashAlgo.buttons():
            btn.clicked.connect(self.toggleHashAlgo)
        self.btnKeyGen.clicked.connect(self.keygen)
        self.btnSign.clicked.connect(self.sign)
        self.btnVerify.clicked.connect(self.verify)

    def toggleSecurityLevel(self):
        try:
            selectedLevel = self.selSecLevel.checkedButton().text()
            if '0' in selectedLevel.lower():
                self.secLevel = SecurityLevel.L0
            else:
                self.secLevel = SecurityLevel.L1
        except Exception as e:
            show_error_dialog(str(e))
            
    def toggleHashAlgo(self):
        try:
            selectedHash = self.selHashAlgo.checkedButton().text()
            if 'md5' in selectedHash.lower():
                self.selectedHash = HashFunction.MD5
            elif 'sha1' in selectedHash.lower():
                self.selectedHash = HashFunction.SHA1
            elif 'sha2' in selectedHash.lower():
                self.selectedHash = HashFunction.SHA2
            else:
                self.selectedHash = HashFunction.SHA3
        except Exception as e:
            show_error_dialog(str(e))

    def keygen(self):
        try:
            if self.secLevel is None:
                raise Exception("Please select a security level")
            self.dsa = DSA(self.secLevel, self.selectedHash)
            self.dsa.keygen()
            pubKey = self.dsa.pubKey
            prvKey = self.dsa.prvKey
            self.outputPubKey.setText(f"e: {pubKey.y}")
            self.outputPrivKey.setText(f"d: {prvKey.x}")
                
        except Exception as e:
            show_error_dialog(str(e))

    def sign(self):
        try:
            input = bytes(self.inputText.toPlainText(), 'utf-8')
            signed = self.dsa.sign(input)
            signed = [str(base64.b64encode(e))[2:-1] for e in signed]
            self.outputText.setText(str(signed))
        except Exception as e:
            show_error_dialog(str(e))

    def verify(self):
        try:
            input = bytes(self.inputText.toPlainText(), 'utf-8')
            sig = [base64.b64decode(e) for e in self.inputSig.toPlainText()[1:-1].replace(' ', '').split(',')]
            verified = self.dsa.verify(input, sig[0], sig[1])
            self.outputText.setText(str(verified))
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = DsaUI()
    widget.show()
    sys.exit(app.exec_())