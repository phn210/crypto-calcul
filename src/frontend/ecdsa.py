from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.ec import EC, ECType, WeierstrassCurve, MontgomeryCurve, EdwardsCurve
from wrappers.ecelgamal import ECElGamal
from wrappers.enums import HashFunction

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi

class ECDSAUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(ECDSAUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_ecdsa.ui", self)
        self.curveType = None
        self.initButtons()

    def initButtons(self):
        self.btnKeyGen.clicked.connect(self.keygen)
        for btn in self.selCurve.buttons():
            btn.clicked.connect(self.toggleCurveType)
        self.btnSign.clicked.connect(self.sign)
        self.btnVerify.clicked.connect(self.verify)

    def toggleCurveType(self):
        try:
            selectedCurve = self.selCurve.checkedButton().text()
            if 'weierstrass' in selectedCurve.lower():
                self.curveType = ECType.WEIERSTRASS
            else:
                self.curveType = ECType.EDWARDS
        except Exception as e:
            show_error_dialog(str(e))

    def keygen(self):
        try:
            if self.curveType is None:
                raise ValueError("Please select a curve type.")
            if self.curveType == ECType.WEIERSTRASS:
                self.curveId = WeierstrassCurve(self.selWeier.currentIndex())
            else:
                self.curveId = EdwardsCurve(self.selEdw.currentIndex())
            ec = EC(self.curveType, self.curveId)
            self.elgamal = ECElGamal(ec)
            self.elgamal.keygen()
            pubKey = self.elgamal.pubKey
            prvKey = self.elgamal.prvKey
            self.outputPubKey.setText(f"q: {pubKey.y}")
            self.outputPrivKey.setText(f"d: {prvKey.x}")
        except Exception as e:
            show_error_dialog(str(e))

    def sign(self):
        try:
            input = bytes(self.inputText.toPlainText(), 'utf-8')
            signed = self.elgamal.sign(input, HashFunction.SHA2)
            signed = [str(base64.b64encode(e))[2:-1] for e in signed]
            self.outputText.setText(str(signed))
        except Exception as e:
            show_error_dialog(str(e))

    def verify(self):
        try:
            input = bytes(self.inputText.toPlainText(), 'utf-8')
            sig = [base64.b64decode(e) for e in self.inputSig.toPlainText()[1:-1].replace(' ', '').split(',')]
            verified = self.elgamal.verify(input, sig[0], sig[1], HashFunction.SHA2)
            self.outputText.setText(str(verified))
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = ECDSAUI()
    widget.show()
    sys.exit(app.exec_())