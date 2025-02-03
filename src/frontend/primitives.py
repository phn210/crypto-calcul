from utils import WIREFRAME_PATH, add_build_to_path, show_error_dialog
add_build_to_path()
from wrappers.gmp import GMPInteger
from wrappers.rng import RNG
from wrappers.prime import Prime, PrimalityTest

from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from utils import WIREFRAME_PATH, show_error_dialog

NB_SPRIMES = 5
NB_TESTS = 25

class PrimitivesUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(PrimitivesUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_primitives.ui", self)
        self.selectedFunction = None
        self.initAlgorithms()
        self.initButtons()
        
    def initAlgorithms(self):
        self.rng = RNG()
        self.prime = Prime()

    def initButtons(self):
        try:
            self.btnRng.clicked.connect(self.generateRandom)
            self.btnPrimeTest.clicked.connect(self.testPrime)
            self.btnPrimeGen.clicked.connect(self.generatePrime)
            self.enableSeed.stateChanged.connect(self.toggleEnableSeed)
            self.btnBitRng.clicked.connect(self.toggleRngMode)
            self.btnModRng.clicked.connect(self.toggleRngMode)
            self.btnBitPrimeGen.clicked.connect(self.togglePrimeGenMode)
            self.btnModPrimeGen.clicked.connect(self.togglePrimeGenMode)
        except Exception as e:
            show_error_dialog(str(e))
            
    def generateRandom(self):
        try:
            seed = None
            if (self.inputSeed.isEnabled()):
                seed = int(self.inputSeed.text())
            rng = RNG(seed)
            base = 2 if self.base2.isChecked() else 10 if self.base10.isChecked() else 16 if self.base16.isChecked() else 0
            if base == 0:
                raise ValueError("No base selected")
            if self.inputBitRng.isEnabled():
                bits = int(self.inputBitRng.text())
                rand = rng.rand_int_b(bits, base)
            elif self.inputModRng.isEnabled():
                modulo = GMPInteger()
                modulo.set_value(self.inputModRng.text(), base)
                rand = rng.rand_int_m(modulo, base)
            else:
                raise ValueError("No RNG mode selected")
            self.outputRng.clear()
            self.outputRng.setText(rand)
        except Exception as e:
            show_error_dialog(str(e))

    def generatePrime(self):
        try:
            prime = Prime()
            rng = RNG()
            if self.inputBitPrimeGen.isEnabled():
                bits = int(self.inputBitPrimeGen.text())
                p = prime.gen_prime_b(rng.state, bits, NB_SPRIMES, NB_TESTS, PrimalityTest.GMP)
            elif self.inputModPrimeGen.isEnabled():
                modulo = GMPInteger()
                modulo.set_value(str(int(self.inputModPrimeGen.text())), 10)
                p = self.prime.gen_prime_m(self.rng.state, modulo, NB_SPRIMES, NB_TESTS, PrimalityTest.GMP)
            else:
                raise ValueError("No prime generation mode selected")
            self.outputPrimeGen.clear()
            self.outputPrimeGen.setText(p)
        except (Exception, SystemExit) as e:
            show_error_dialog(str(e))

    def testPrime(self):
        try:
            input = int(self.inputPrimeTest.text())
            candidate = GMPInteger()
            candidate.set_value(str(input), 10)
            if self.gmpTestRadio.isChecked():
                test = PrimalityTest.GMP
            elif self.fermatTestRadio.isChecked():
                test = PrimalityTest.FERMAT
            elif self.millerRabinTestRadio.isChecked():
                test = PrimalityTest.MILLER_RABIN
            else:
                raise ValueError("No prime test selected")
            res = self.prime.test(candidate, self.rng.state, NB_TESTS, test)
            self.outputPrimeTest.clear()
            self.outputPrimeTest.setText(str(res))
        except Exception as e:
            show_error_dialog(str(e))

    def toggleEnableSeed(self):
        try:
            if self.enableSeed.checkState() == 0:
                self.inputSeed.setEnabled(False)
            else:
                self.inputSeed.setEnabled(True)
        except Exception as e:
            show_error_dialog(str(e))

    def toggleRngMode(self):
        if self.btnBitRng.isChecked():
            self.inputModRng.setEnabled(False)
            self.inputBitRng.setEnabled(True)
        else:
            self.inputBitRng.setEnabled(False)
            self.inputModRng.setEnabled(True)
    
    def togglePrimeGenMode(self):
        if self.btnBitPrimeGen.isChecked():
            self.inputModPrimeGen.setEnabled(False)
            self.inputBitPrimeGen.setEnabled(True)
        else:
            self.inputBitPrimeGen.setEnabled(False)
            self.inputModPrimeGen.setEnabled(True)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = PrimitivesUI()
    widget.show()
    sys.exit(app.exec_())