from utils import add_build_to_path
add_build_to_path()

from wrappers.md5 import MD5
from wrappers.sha1 import SHA1
from wrappers.sha2 import SHA224, SHA256, SHA384, SHA512
from wrappers.sha3 import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256

from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtCore, QtGui
from error_handling import show_error_dialog

WIREFRAME_PATH = "src/frontend/wireframes"

class HashUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(HashUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_hash.ui", self)
        self.initAlgorithms()
        self.initButtons()
        
    def initAlgorithms(self):
        self.md5 = MD5()
        self.sha1 = SHA1()
        self.sha224 = SHA224()
        self.sha256 = SHA256()
        self.sha384 = SHA384()
        self.sha512 = SHA512()
        self.sha3_224 = SHA3_224()
        self.sha3_256 = SHA3_256()
        self.sha3_384 = SHA3_384()
        self.sha3_512 = SHA3_512()
        self.shake128 = SHAKE128()
        self.shake256 = SHAKE256()

    def initButtons(self):
        try:
            self.btnGenHash.clicked.connect(self.generateHash)
            self.btnGenShake.clicked.connect(self.generateHashShake)
        except Exception as e:
            show_error_dialog(str(e))
        
    def generateHash(self):
        try:
            input = bytes(self.inputHash.toPlainText(), "utf-8")
            if self.md5RadioButton.isChecked():
                digest = self.md5.hash(input)
            elif self.sha1RadioButton.isChecked():
                digest = self.sha1.hash(input)
            elif self.sha2RadioButton.isChecked():
                if self.securityLevelL0.isChecked():
                    digest = self.sha224.hash(input)
                elif self.securityLevelL1.isChecked():
                    digest = self.sha256.hash(input)
                elif self.securityLevelL2.isChecked():
                    digest = self.sha384.hash(input)
                elif self.securityLevelL3.isChecked():
                    digest = self.sha512.hash(input)
                else:
                    raise Exception("Please select a security level")
            elif self.sha3RadioButton.isChecked():
                if self.securityLevelL0.isChecked():
                    digest = self.sha3_224.hash(input)
                elif self.securityLevelL1.isChecked():
                    digest = self.sha3_256.hash(input)
                elif self.securityLevelL2.isChecked():
                    digest = self.sha3_384.hash(input)
                elif self.securityLevelL3.isChecked():
                    digest = self.sha3_512.hash(input)
                else:
                    raise Exception("Please select a security level")
            else:
                raise Exception("Please select a hashing algorithm")
            self.outputHash.clear()
            self.outputHash.setPlainText(digest.hex().upper())
        except Exception as e:
            show_error_dialog(str(e))

    def generateHashShake(self):
        try:
            input = bytes(self.inputShake.toPlainText(), "utf-8")
            if self.securityLevelL1Shake.isChecked():
                self.shake128.update(input)
                self.shake128.xof()
                digest = self.shake128.squeeze(32)
            elif self.securityLevelL3Shake.isChecked():
                digest = self.shake256.update(input)
                self.shake256.xof()
                digest = self.shake256.squeeze(64)
            else:
                raise Exception("Please select a shake algorithm")
            self.outputShake.clear()
            self.outputShake.setPlainText(digest.hex().upper())
        except Exception as e:
            show_error_dialog(str(e))

    def clearShakeCtx(self):
        self.shake128 = SHAKE128()
        self.shake256 = SHAKE256()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = HashUI()
    widget.show()
    sys.exit(app.exec_())