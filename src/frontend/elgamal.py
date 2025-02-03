from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.elgamal import ElGamal
from wrappers.enums import SecurityLevel

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi

class ElGamalUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(ElGamalUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_elgamal.ui", self)
        self.selectedAlgo = None
        self.selectedVariant = None
        self.secLevel = None
        self.initTabs()
        self.initButtons()
        
    def initTabs(self):
        self.tabWidget.setCurrentIndex(0)
        self.selectedTab = self.tabWidget.currentIndex()
    
    def initButtons(self):
        self.btnKeyGenEnc.clicked.connect(self.keygen)
        self.btnKeyGenSig.clicked.connect(self.keygen)
        for btn in self.selSecLevEnc.buttons() + self.selSecLevSig.buttons():
            btn.clicked.connect(self.toggleSecurityLevel)
        self.tabWidget.currentChanged.connect(self.toggleTab)
        self.btnEncrypt.clicked.connect(self.encrypt)
        self.btnDecrypt.clicked.connect(self.decrypt)
        self.btnSign.clicked.connect(self.sign)
        self.btnVerify.clicked.connect(self.verify)
            
    def toggleSecurityLevel(self):
        try:
            selectedLevel = self.selSecLevEnc.checkedButton().text() if self.selectedTab == 0 else self.selSecLevSig.checkedButton().text()
            if '0' in selectedLevel.lower():
                self.secLevel = SecurityLevel.L0
            else:
                self.secLevel = SecurityLevel.L1
        except Exception as e:
            show_error_dialog(str(e))

    def toggleTab(self):
        try:
            self.selectedTab = self.tabWidget.currentIndex()
            self.elgamal = None
        except Exception as e:
            show_error_dialog(str(e))

    def keygen(self):
        try:
            if self.secLevel is None:
                raise Exception("Please select a security level")
            self.elgamal = ElGamal(self.secLevel)
            self.elgamal.keygen()
            pubKey = self.elgamal.pubKey
            prvKey = self.elgamal.prvKey
            if self.selectedTab == 0:
                self.outputPubKeyEnc.setText(f"e: {pubKey.y}")
                self.outputPrivKeyEnc.setText(f"d: {prvKey.x}")
            else:
                self.outputPubKeySig.setText(f"e: {pubKey.y}")
                self.outputPrivKeySig.setText(f"d: {prvKey.x}")
                
        except Exception as e:
            show_error_dialog(str(e))

    def encrypt(self):
        try:
            input = bytes(self.inputTextEnc.toPlainText(), 'utf-8')
            encrypted = self.elgamal.encrypt(input)
            encrypted = [str(base64.b64encode(e))[2:-1] for e in encrypted]
            self.outputTextEnc.setText(str(encrypted))
        except Exception as e:
            show_error_dialog(str(e))

    def decrypt(self):
        try:
            input = base64.b64decode(self.inputTextEnc.toPlainText())
            input = [base64.b64decode(e) for e in self.inputTextEnc.toPlainText()[1:-1].replace(' ', '').split(',')]
            decrypted = self.elgamal.decrypt(input[0], input[1])
            self.outputTextEnc.setText(decrypted.decode('utf-8'))
        except Exception as e:
            show_error_dialog(str(e))

    def sign(self):
        try:
            input = bytes(self.inputTextSig.toPlainText(), 'utf-8')
            signed = self.elgamal.sign(input)
            signed = [str(base64.b64encode(e))[2:-1] for e in signed]
            self.outputTextSig.setText(str(signed))
        except Exception as e:
            show_error_dialog(str(e))

    def verify(self):
        try:
            input = bytes(self.inputTextSig.toPlainText(), 'utf-8')
            sig = [base64.b64decode(e) for e in self.inputSig.toPlainText()[1:-1].replace(' ', '').split(',')]
            verified = self.elgamal.verify(input, sig[0], sig[1])
            self.outputTextSig.setText(str(verified))
        except Exception as e:
            show_error_dialog(str(e))    

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = ElGamalUI()
    widget.show()
    sys.exit(app.exec_())