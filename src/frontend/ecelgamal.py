from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.ec import EC, ECType, WeierstrassCurve, MontgomeryCurve, EdwardsCurve
from wrappers.ecelgamal import ECElGamal
from wrappers.enums import HashFunction

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi

class ECElGamalUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(ECElGamalUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_ec_elgamal.ui", self)
        self.curveType = None
        self.initTabs()
        self.initButtons()

    def initTabs(self):
        self.tabWidget.setCurrentIndex(0)
        self.selectedTab = self.tabWidget.currentIndex()

    def initButtons(self):
        self.btnKeyGenEnc.clicked.connect(self.keygen)
        self.btnKeyGenSig.clicked.connect(self.keygen)
        for btn in self.selCurveEnc.buttons() + self.selCurveSig.buttons():
            btn.clicked.connect(self.toggleCurveType)
        self.tabWidget.currentChanged.connect(self.toggleTab)
        self.btnEncrypt.clicked.connect(self.encrypt)
        self.btnDecrypt.clicked.connect(self.decrypt)
        self.btnSign.clicked.connect(self.sign)
        self.btnVerify.clicked.connect(self.verify)

    def toggleTab(self):
        try:
            self.selectedTab = self.tabWidget.currentIndex()
            self.elgamal = None
        except Exception as e:
            show_error_dialog(str(e))

    def toggleCurveType(self):
        try:
            selectedCurve = self.selCurveEnc.checkedButton().text() if self.selectedTab == 0 else self.selCurveSig.checkedButton().text()
            if 'weierstrass' in selectedCurve.lower():
                self.curveType = ECType.WEIERSTRASS
            elif 'montgomery' in selectedCurve.lower():
                self.curveType = ECType.MONTGOMERY
            else:
                self.curveType = ECType.EDWARDS
        except Exception as e:
            show_error_dialog(str(e))

    def keygen(self):
        try:
            if self.curveType is None:
                raise ValueError("Please select a curve type.")
            if self.curveType == ECType.WEIERSTRASS:
                self.curveId = WeierstrassCurve(self.selWeierEnc.currentIndex() if self.selectedTab == 0 else self.selWeierSig.currentIndex())
            elif self.curveType == ECType.MONTGOMERY:
                self.curveId = MontgomeryCurve(self.selMontEnc.currentIndex() if self.selectedTab == 0 else self.selMontSig.currentIndex())
            else:
                self.curveId = EdwardsCurve(self.selEdwEnc.currentIndex() if self.selectedTab == 0 else self.selEdwSig.currentIndex())
            ec = EC(self.curveType, self.curveId)
            self.elgamal = ECElGamal(ec)
            self.elgamal.keygen()
            pubKey = self.elgamal.pubKey
            prvKey = self.elgamal.prvKey
            if self.selectedTab == 0:
                self.outputPubKeyEnc.setText(f"y: {pubKey.y}")
                self.outputPrivKeyEnc.setText(f"x: {prvKey.x}")
            else:
                self.outputPubKeySig.setText(f"y: {pubKey.y}")
                self.outputPrivKeySig.setText(f"x: {prvKey.x}")
        except Exception as e:
            show_error_dialog(str(e))

    def encrypt(self):
        try:
            input = bytes(self.inputTextEnc.toPlainText(), 'utf-8')
            encrypted = self.elgamal.encrypt(input, HashFunction.SHA2)
            encrypted = [str(base64.b64encode(e))[2:-1] for e in encrypted]
            self.outputTextEnc.setText(str(encrypted))
        except Exception as e:
            show_error_dialog(str(e))

    def decrypt(self):
        try:
            input = base64.b64decode(self.inputTextEnc.toPlainText())
            input = [base64.b64decode(e) for e in self.inputTextEnc.toPlainText()[1:-1].replace(' ', '').split(',')]
            decrypted = self.elgamal.decrypt(input[0], input[1], HashFunction.SHA2)
            self.outputTextEnc.setText(decrypted.decode('utf-8'))
        except Exception as e:
            show_error_dialog(str(e))

    def sign(self):
        try:
            input = bytes(self.inputTextSig.toPlainText(), 'utf-8')
            signed = self.elgamal.sign(input, HashFunction.SHA2)
            signed = [str(base64.b64encode(e))[2:-1] for e in signed]
            self.outputTextSig.setText(str(signed))
        except Exception as e:
            show_error_dialog(str(e))

    def verify(self):
        try:
            input = bytes(self.inputTextSig.toPlainText(), 'utf-8')
            sig = [base64.b64decode(e) for e in self.inputSig.toPlainText()[1:-1].replace(' ', '').split(',')]
            verified = self.elgamal.verify(input, sig[0], sig[1], HashFunction.SHA2)
            self.outputTextSig.setText(str(verified))
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = ECElGamalUI()
    widget.show()
    sys.exit(app.exec_())