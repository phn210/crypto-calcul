from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.ec import EC, ECType, WeierstrassCurve, MontgomeryCurve, EdwardsCurve
from wrappers.ecdh import ECDH

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi

class ECDHUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(ECDHUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_ecdh.ui", self)
        self.curveType = None
        self.initButtons()

    def initButtons(self):
        for btn in self.selCurve.buttons():
            btn.clicked.connect(self.toggleCurveType)
        self.btnSecretGen.clicked.connect(self.generateSecret)
        self.btnKeyEx.clicked.connect(self.keyExchange)

    def toggleCurveType(self):
        try:
            selectedCurve = self.selCurve.checkedButton().text()
            if 'weierstrass' in selectedCurve.lower():
                self.curveType = ECType.WEIERSTRASS
            elif 'montgomery' in selectedCurve.lower():
                self.curveType = ECType.MONTGOMERY
            else:
                self.curveType = ECType.EDWARDS
        except Exception as e:
            show_error_dialog(str(e))
            
    def generateSecret(self):
        try:
            if self.curveType is None:
                raise ValueError("Please select a curve type.")
            if self.curveType == ECType.WEIERSTRASS:
                self.curveId = WeierstrassCurve(self.selWeier.currentIndex())
            else:
                self.curveId = EdwardsCurve(self.selEdw.currentIndex())
            ec = EC(self.curveType, self.curveId)
            self.dh = ECDH(ec)
            self.sA = self.dh.gen_secret()
            self.sB = self.dh.gen_secret()
            self.outputSecretA.setText(str(base64.b64encode(self.sA))[2:-1])
            self.outputSecretB.setText(str(base64.b64encode(self.sB))[2:-1])
            pass
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
            pass
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = ECDHUI()
    widget.show()
    sys.exit(app.exec_())