from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.rsa import RSA, RSAAlgo, RSAVariant
from wrappers.enums import HashFunction, SecurityLevel

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from utils import WIREFRAME_PATH, show_error_dialog

class RsaUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(RsaUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_rsa.ui", self)
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
        for btn in self.selAlgoEnc.buttons() + self.selAlgoSig.buttons():
            btn.clicked.connect(self.toggleRsaAlgo)
        for btn in self.selVarEnc.buttons() + self.selVarSig.buttons():
            btn.clicked.connect(self.toggleRsaVariant)
        for btn in self.selSecLevEnc.buttons() + self.selSecLevSig.buttons():
            btn.clicked.connect(self.toggleSecurityLevel)
        self.tabWidget.currentChanged.connect(self.toggleTab)
        self.btnEncrypt.clicked.connect(self.encrypt)
        self.btnDecrypt.clicked.connect(self.decrypt)
        self.btnSign.clicked.connect(self.sign)
        self.btnVerify.clicked.connect(self.verify)

    def toggleRsaAlgo(self):
        try:
            selectedAlgo = self.selAlgoEnc.checkedButton().text() if self.selectedTab == 0 else self.selAlgoSig.checkedButton().text()
            if 'crt' in selectedAlgo.lower():
                self.selectedAlgo = RSAAlgo.CRT
            else:
                self.selectedAlgo = RSAAlgo.STANDARD
        except Exception as e:
            show_error_dialog(str(e))

    def toggleRsaVariant(self):
        try:
            selectedVariant = self.selVarEnc.checkedButton().text() if self.selectedTab == 0 else self.selVarSig.checkedButton().text()
            if 'textbook' in selectedVariant.lower():
                self.selectedVariant = RSAVariant.TEXTBOOK
            elif 'pkcs' in selectedVariant.lower():
                self.selectedVariant = RSAVariant.PKCS1
            else:
                self.selectedVariant = RSAVariant.SECURE
        except Exception as e:
            show_error_dialog(str(e))
            
    def toggleSecurityLevel(self):
        try:
            selectedLevel = self.selSecLevEnc.checkedButton().text() if self.selectedTab == 0 else self.selSecLevSig.checkedButton().text()
            if '0' in selectedLevel.lower():
                self.secLevel = SecurityLevel.L0
            elif '1' in selectedLevel.lower():
                self.secLevel = SecurityLevel.L1
            elif '2' in selectedLevel.lower():
                self.secLevel = SecurityLevel.L2
            else:
                self.secLevel = SecurityLevel.L3
        except Exception as e:
            show_error_dialog(str(e))

    def toggleTab(self):
        try:
            self.selectedTab = self.tabWidget.currentIndex()
            self.rsa = None
        except Exception as e:
            show_error_dialog(str(e))

    def keygen(self):
        try:
            if self.selectedAlgo is None or self.selectedVariant is None or self.secLevel is None:
                raise ValueError("Please select all options")
            self.rsa = RSA(self.secLevel, self.selectedVariant)
            self.rsa.keygen()
            pubKey = self.rsa.pubKey
            prvKey = self.rsa.prvKey
            if self.selectedTab == 0:
                self.outputPubKeyEnc.setText(f"e: {pubKey.e}")
                self.outputPrivKeyEnc.setText(f"d: {prvKey.d}")
            else:
                self.outputPubKeySig.setText(f"e: {pubKey.e}")
                self.outputPrivKeySig.setText(f"d: {prvKey.d}")
                
        except Exception as e:
            show_error_dialog(str(e))

    def encrypt(self):
        try:
            input = bytes(self.inputTextEnc.toPlainText(), 'utf-8')
            encrypted = self.rsa.encrypt(input)
            self.outputTextEnc.setText(str(base64.b64encode(encrypted))[2:-1])
        except Exception as e:
            show_error_dialog(str(e))

    def decrypt(self):
        try:
            input = base64.b64decode(self.inputTextEnc.toPlainText())
            decrypted = self.rsa.decrypt(input, self.selectedAlgo)
            self.outputTextEnc.setText(decrypted.decode('utf-8'))
        except Exception as e:
            show_error_dialog(str(e))

    def sign(self):
        try:
            input = bytes(self.inputTextSig.toPlainText(), 'utf-8')
            signed = self.rsa.sign(input, self.selectedAlgo)
            self.outputTextSig.setText(str(base64.b64encode(signed))[2:-1])
        except Exception as e:
            show_error_dialog(str(e))

    def verify(self):
        try:
            input = bytes(self.inputTextSig.toPlainText(), 'utf-8')
            sig = base64.b64decode(self.inputSig.toPlainText())
            verified = self.rsa.verify(input, sig)
            self.outputTextSig.setText(str(verified))
        except Exception as e:
            show_error_dialog(str(e))    

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = RsaUI()
    widget.show()
    sys.exit(app.exec_())