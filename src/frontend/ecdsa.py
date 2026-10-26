from utils import WIREFRAME_PATH, show_error_dialog
from cryptocalc import ECDSA, EC, ECType, EdwardsCurve, HashFunction, WeierstrassCurve

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
            self.ecdsa = ECDSA(ec, HashFunction.SHA2)
            self.ecdsa.keygen()
            pubKey = self.ecdsa.pubKey
            prvKey = self.ecdsa.prvKey
            self.outputPubKey.setText(f"q: {pubKey.q}")
            self.outputPrivKey.setText(f"d: {prvKey.d}")
        except Exception as e:
            show_error_dialog(str(e))

    def sign(self):
        try:
            input = bytes(self.inputText.toPlainText(), 'utf-8')
            signed = self.ecdsa.sign(input)
            signed = [str(base64.b64encode(e))[2:-1] for e in signed]
            self.outputText.setText(str(signed))
        except Exception as e:
            show_error_dialog(str(e))

    def verify(self):
        try:
            input = bytes(self.inputText.toPlainText(), 'utf-8')
            sig = [base64.b64decode(e) for e in self.inputSig.toPlainText()[1:-1].replace(' ', '').split(',')]
            verified = self.ecdsa.verify(input, sig[0], sig[1])
            self.outputText.setText(str(verified))
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    import theme
    app = QtWidgets.QApplication(sys.argv)
    theme.apply(app, theme.saved())
    widget = ECDSAUI()
    theme.polish(widget)
    widget.setContentsMargins(32, 32, 32, 32)
    widget.show()
    sys.exit(app.exec_())