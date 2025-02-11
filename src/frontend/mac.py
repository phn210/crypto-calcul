from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.mac import CBCMAC, HMAC
from wrappers.enums import HashFunction, SecurityLevel

from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from utils import WIREFRAME_PATH, show_error_dialog

class MacUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(MacUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_secret_mac.ui", self)
        self.selectedFile = None
        self.initButtons()
    
    def initButtons(self):
        try:
            self.btnChooseFile.clicked.connect(self.chooseFile)
            self.btnGenTag.clicked.connect(self.generateTag)
            self.cbcMacRadioButton.clicked.connect(self.toggleMacAlgo)
            self.hmacRadioButton.clicked.connect(self.toggleMacAlgo)
            for btn in self.selHashAlgo.buttons():
                btn.clicked.connect(self.toggleHashAlgo)
        except Exception as e:
            show_error_dialog(str(e))
    
    def chooseFile(self):
        try:
            fileDialog = QtWidgets.QFileDialog()
            fileDialog.open()
            fileDialog.setFileMode(QtWidgets.QFileDialog.FileMode.ExistingFile)
            fileDialog.setViewMode(QtWidgets.QFileDialog.ViewMode.Detail)

            if fileDialog.exec():
                self.selectedFile = fileDialog.selectedFiles()[0]
                if 'encrypted' in self.selectedFile.lower():
                    self.inputText.setPlainText(f"Selected file: {self.selectedFile}")
                    with open(self.selectedFile, "r", encoding="latin-1") as f:
                        self.inputText.append(f.read())
                else:
                    self.inputText.setPlainText(f"Selected file: {self.selectedFile}")
                    with open(self.selectedFile, "r", encoding="utf-8") as f:
                        self.inputText.append(f.read())
        except Exception as e:
            show_error_dialog(str(e))
    
    def toggleMacAlgo(self):
        try:
            selectedAlgo = self.selMacAlgo.checkedButton().text()
            if 'cbc' in selectedAlgo.lower():
                for btn in self.selSecLevel.buttons():
                    btn.setEnabled(True)
                for btn in [self.level0RadioButton] + self.selHashAlgo.buttons():
                    btn.setEnabled(False)
            else:
                for btn in self.selSecLevel.buttons() + self.selHashAlgo.buttons():
                    btn.setEnabled(True)
        except Exception as e:
            show_error_dialog(str(e))
    
    def toggleHashAlgo(self):
        try:
            selectedAlgo = self.selHashAlgo.checkedButton().text()
            if 'md5' in selectedAlgo.lower() or '1' in selectedAlgo.lower():
                for btn in self.selSecLevel.buttons():
                    btn.setEnabled(False)
            else:
                for btn in self.selSecLevel.buttons():
                    btn.setEnabled(True)
        except Exception as e:
            show_error_dialog(str(e))

    def generateTag(self):
        try:
            self.outputText.clear()
            key = bytes(self.inputKey.text(), "utf-8")
            isFile = False
            if self.textInputRadioButton.isChecked():
                input = bytes(self.inputText.toPlainText(), "utf-8")
            elif self.fileInputRadioButton.isChecked():
                isFile = True
                if self.selectedFile is None:
                    raise ValueError("No file selected")
                input = self.selectedFile
            else:
                raise ValueError("No input type selected")
            if self.level0RadioButton.isChecked():
                if self.cbcMacRadioButton.isChecked():
                    raise ValueError("CBC-MAC does not support security level 0")
                secLevel = SecurityLevel.L0
            elif self.level1RadioButton.isChecked():
                secLevel = SecurityLevel.L1
            elif self.level2RadioButton.isChecked():
                secLevel = SecurityLevel.L2
            elif self.level3RadioButton.isChecked():
                secLevel = SecurityLevel.L3
            else:
                raise ValueError("No security level selected")
            
            if self.cbcMacRadioButton.isChecked():
                mac = CBCMAC(secLevel)
                self.outputText.setPlainText(f"CBC-MAC-{secLevel.value}:")
                tag = mac.mac_file(input, key) if isFile else mac.mac(input, key)
            else:
                if self.md5RadioButton.isChecked():
                    hashFunc = HashFunction.MD5
                    self.outputText.setPlainText(f"HMAC-MD5:")
                elif self.sha1RadioButton.isChecked():
                    hashFunc = HashFunction.SHA1
                    self.outputText.setPlainText(f"HMAC-SHA1:")
                elif self.sha2RadioButton.isChecked():
                    hashFunc = HashFunction.SHA2
                    self.outputText.setPlainText(f"HMAC-SHA{secLevel.value*2}:")
                elif self.sha3RadioButton.isChecked():
                    hashFunc = HashFunction.SHA3
                    self.outputText.setPlainText(f"HMAC-SHA3-{secLevel.value*2}:")
                else:
                    raise ValueError("No hash function selected")
                mac = HMAC(secLevel, hashFunc)
                tag = mac.mac_file(input, key) if isFile else mac.mac(input, key)
                
            self.outputText.append(tag.hex().upper())
        except Exception as e:
            show_error_dialog(str(e))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = MacUI()
    widget.show()
    sys.exit(app.exec_())