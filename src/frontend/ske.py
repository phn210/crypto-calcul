from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.aes import AES, AESMode
from wrappers.des import DES
from wrappers.enums import SecurityLevel

import base64
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi

class SKEncUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(SKEncUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_secret_enc.ui", self)
        self.selectedFile = None
        self.initButtons()
    
    def initButtons(self):
        self.btnChooseFile.clicked.connect(self.chooseFile)
        self.btnEncrypt.clicked.connect(self.encrypt)
        self.btnDecrypt.clicked.connect(self.decrypt)
        self.aesRadioButton.clicked.connect(self.toggleEncryptionAlgo)
        self.desRadioButton.clicked.connect(self.toggleEncryptionAlgo)
    
    def chooseFile(self):
        try:
            fileDialog = QtWidgets.QFileDialog()
            fileDialog.open()
            fileDialog.setFileMode(QtWidgets.QFileDialog.FileMode.ExistingFile)
            fileDialog.setViewMode(QtWidgets.QFileDialog.ViewMode.Detail)

            if fileDialog.exec():
                self.selectedFile = fileDialog.selectedFiles()[0]
                print(self.selectedFile)
                if 'encrypted' in self.selectedFile.lower():
                    self.inputText.setPlainText(f"Selected file: {self.selectedFile}")
                    with open(self.selectedFile, "rb") as f:
                        self.inputText.append(str(base64.b64encode(f.read()))[2:-1])
                else:
                    self.inputText.setPlainText(f"Selected file: {self.selectedFile}")
                    with open(self.selectedFile, "r", encoding="utf-8") as f:
                        self.inputText.append(f.read())
        except Exception as e:
            show_error_dialog(str(e))
    
    def toggleEncryptionAlgo(self):
        selectedAlgo = self.selEncAlgo.checkedButton().text()
        if 'des' in selectedAlgo.lower():
            for btn in self.selSecLevel.buttons() + self.selAesMode.buttons():
                btn.setEnabled(False)
            self.inputIV.setEnabled(False)
            self.inputNonce.setEnabled(False)
        else:
            for btn in self.selSecLevel.buttons() + self.selAesMode.buttons():
                btn.setEnabled(True)
            self.inputIV.setEnabled(True)
            self.inputNonce.setEnabled(True)

    def encrypt(self):
        try:
            self.outputText.clear()
            key = bytes(self.inputSecretKey.text(), "utf-8")
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

            if self.aesRadioButton.isChecked():
                if self.securityL1RadioButton.isChecked():
                    secLevel = SecurityLevel.L1
                elif self.securityL2RadioButton.isChecked():
                    secLevel = SecurityLevel.L2
                elif self.securityL3RadioButton.isChecked():
                    secLevel = SecurityLevel.L3
                else:
                    raise ValueError("No security level selected")
                if self.ecbRadioButton.isChecked():
                    mode = AESMode.ECB
                elif self.cbcRadioButton.isChecked():
                    mode = AESMode.CBC
                elif self.ofbRadioButton.isChecked():
                    mode = AESMode.OFB
                elif self.cfbRadioButton.isChecked():
                    mode = AESMode.CFB
                elif self.ctrRadioButton.isChecked():
                    mode = AESMode.CTR
                else:
                    raise ValueError("No AES mode selected")
                aes = AES(secLevel, mode)
                iv = bytes(self.inputIV.text(), "utf-8")
                nonce = bytes(self.inputNonce.text(), "utf-8")
                if isFile:
                    fileDialog = QtWidgets.QFileDialog()
                    fileDialog.open()
                    fileDialog.setFileMode(QtWidgets.QFileDialog.FileMode.DirectoryOnly)
                    fileDialog.setViewMode(QtWidgets.QFileDialog.ViewMode.Detail)
                    
                    if fileDialog.exec():
                        folder = fileDialog.selectedFiles()[0]
                        aes.encrypt_file(input, f"{folder}/aes_output_encrypted.txt", key, iv if mode != AESMode.CTR else nonce)
                        with open(f"{folder}/aes_output_encrypted.txt", "rb") as f:
                            encrypted = f.read()
                        self.outputText.append(f"Encrypted file saved to {folder}/aes_output_encrypted.txt")
                else:
                    encrypted = aes.encrypt(input, key, iv, nonce)
                self.outputText.setPlainText(f"AES-{secLevel.value}-{str(mode).split('.')[-1]}:")
            elif self.desRadioButton.isChecked():
                des = DES()
                self.outputText.setPlainText(f"DES:")
                if isFile:
                    fileDialog = QtWidgets.QFileDialog()
                    fileDialog.open()
                    fileDialog.setFileMode(QtWidgets.QFileDialog.FileMode.DirectoryOnly)
                    fileDialog.setViewMode(QtWidgets.QFileDialog.ViewMode.Detail)
                    
                    if fileDialog.exec():
                        folder = fileDialog.selectedFiles()[0]
                        des.encrypt_file(input, f"{folder}/des_output_encrypted.txt", key)
                        with open(f"{folder}/des_output_encrypted.txt", "rb") as f:
                            encrypted = f.read()
                        self.outputText.append(f"Encrypted file saved to {folder}/des_output_encrypted.txt")
                else:
                    encrypted = des.encrypt(input, key)
            else:
                raise ValueError("No encryption algorithm selected")
            self.outputText.append(str(base64.b64encode(encrypted))[2:-1])
        except Exception as e:
            show_error_dialog(str(e))

    def decrypt(self):
        try:
            self.outputText.clear()
            key = bytes(self.inputSecretKey.text(), "utf-8")
            isFile = False
            if self.textInputRadioButton.isChecked():
                input = base64.b64decode(self.inputText.toPlainText())
            elif self.fileInputRadioButton.isChecked():
                isFile = True
                if self.selectedFile is None:
                    raise ValueError("No file selected")
                input = self.selectedFile
            else:
                raise ValueError("No input type selected")
        
            if self.aesRadioButton.isChecked():
                if self.securityL1RadioButton.isChecked():
                    secLevel = SecurityLevel.L1
                elif self.securityL2RadioButton.isChecked():
                    secLevel = SecurityLevel.L2
                elif self.securityL3RadioButton.isChecked():
                    secLevel = SecurityLevel.L3
                else:
                    raise ValueError("No security level selected")
                if self.ecbRadioButton.isChecked():
                    mode = AESMode.ECB
                elif self.cbcRadioButton.isChecked():
                    mode = AESMode.CBC
                elif self.ofbRadioButton.isChecked():
                    mode = AESMode.OFB
                elif self.cfbRadioButton.isChecked():
                    mode = AESMode.CFB
                elif self.ctrRadioButton.isChecked():
                    mode = AESMode.CTR
                else:
                    raise ValueError("No AES mode selected")
                aes = AES(secLevel, mode)
                iv = bytes(self.inputIV.text(), "utf-8")
                nonce = bytes(self.inputNonce.text(), "utf-8")
                if isFile:
                    fileDialog = QtWidgets.QFileDialog()
                    fileDialog.open()
                    fileDialog.setFileMode(QtWidgets.QFileDialog.FileMode.DirectoryOnly)
                    fileDialog.setViewMode(QtWidgets.QFileDialog.ViewMode.Detail)
                    
                    if fileDialog.exec():
                        folder = fileDialog.selectedFiles()[0]
                        aes.decrypt_file(input, f"{folder}/aes_output_decrypted.txt", key, iv if mode != AESMode.CTR else nonce)
                        with open(f"{folder}/aes_output_decrypted.txt", "rb") as f:
                            decrypted = f.read()
                        self.outputText.append(f"Decrypted file saved to {folder}/aes_output_decrypted.txt")
                else:
                    decrypted = aes.decrypt(input, key, iv, nonce)
                self.outputText.setPlainText(f"AES-{secLevel.value}-{str(mode).split('.')[-1]}:")
            elif self.desRadioButton.isChecked():
                des = DES()
                self.outputText.setPlainText(f"DES:")
                if isFile:
                    fileDialog = QtWidgets.QFileDialog()
                    fileDialog.open()
                    fileDialog.setFileMode(QtWidgets.QFileDialog.FileMode.DirectoryOnly)
                    fileDialog.setViewMode(QtWidgets.QFileDialog.ViewMode.Detail)
                    
                    if fileDialog.exec():
                        folder = fileDialog.selectedFiles()[0]
                        des.decrypt_file(input, f"{folder}/des_output_decrypted.txt", key)
                        with open(f"{folder}/des_output_decrypted.txt", "rb") as f:
                            decrypted = f.read()
                        self.outputText.append(f"Decrypted file saved to {folder}/des_output_encrypted.txt")
                else:
                    decrypted = des.decrypt(input, key)
            else:
                raise ValueError("No encryption algorithm selected")
            self.outputText.append(decrypted.decode("utf-8"))

        except Exception as e:
            show_error_dialog(str(e))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = SKEncUI()
    widget.show()
    sys.exit(app.exec_())