from PyQt5 import QtWidgets
from navbar import NavBarUI
from primitives import PrimitivesUI
from hash import HashUI
from ske import SKEncUI
from mac import MacUI
from rsa import RsaUI
from elgamal import ElGamalUI
from dsa import DsaUI
from dh import DHUI
from ecelgamal import ECElGamalUI
from ecdsa import ECDSAUI
from ecdh import ECDHUI

NAVBAR_WIDTH=350
CONTENT_WIDTH=1000
WINDOW_HEIGHT=935

class MainWindow(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle("DLC: Group 14A")
        self.setMinimumSize(CONTENT_WIDTH + NAVBAR_WIDTH, WINDOW_HEIGHT)
        self.initNavBar()
        self.initStackedWidget()
        self.initMainLayout()
        self.initNavBarBtns()

    def initMainLayout(self):
        self.mainLayout = QtWidgets.QGridLayout()
        self.mainLayout.setSizeConstraint(QtWidgets.QLayout.SetNoConstraint)
        self.mainLayout.setContentsMargins(0,0,0,0)
        self.mainLayout.setSpacing(0)
        self.mainLayout.setObjectName("mainLayout")
        self.setLayout(self.mainLayout)
        self.mainLayout.addWidget(self.navbar, 0, 0, 1, 2)
        self.mainLayout.addWidget(self.stackedWidget, 0, 1, 1, 2)

    def initNavBar(self):
        self.navbar = NavBarUI()
        self.navbar.setFixedWidth(NAVBAR_WIDTH)

    def initNavBarBtns(self):
        for i, btn in enumerate(self.navbar.findChildren(QtWidgets.QPushButton)):
            text = btn.objectName().lower()
            if btn.isEnabled():
                if text == "primitives":
                    id = 0
                elif text == "hash":
                    id = 1
                elif text == "enc":
                    id = 2
                elif text == "mac":
                    id = 3
                elif text == "rsa":
                    id = 4
                elif text == "elgamal":
                    id = 5
                elif text == "dsa":
                    id = 6
                elif text == "dh":
                    id = 7
                elif text == "ecelgamal":
                    id = 8
                elif text == "ecdsa":
                    id = 9
                elif text == "ecdh":
                    id = 10
                else:
                    raise ValueError("Invalid button name")
                btn.clicked.connect(lambda t, i=id: self.loadPage(i))

    def loadPage(self, pageIndex):
        self.stackedWidget.setCurrentIndex(pageIndex)

    def initStackedWidget(self):
        self.stackedWidget = QtWidgets.QStackedWidget(self)
        self.stackedWidget.setObjectName("stackedWidget")

        self.initPrimitives()
        self.stackedWidget.addWidget(self.primitives)
        
        self.initHash()
        self.stackedWidget.addWidget(self.hash)

        self.initSKEnc()
        self.stackedWidget.addWidget(self.ske)

        self.initMac()
        self.stackedWidget.addWidget(self.mac)

        self.initRsa()
        self.stackedWidget.addWidget(self.rsa)

        self.initElGamal()
        self.stackedWidget.addWidget(self.elgamal)

        self.initDsa()
        self.stackedWidget.addWidget(self.dsa)

        self.initDH()
        self.stackedWidget.addWidget(self.dh)

        self.initECElGamal()
        self.stackedWidget.addWidget(self.ecelgamal)

        self.initECDSA()
        self.stackedWidget.addWidget(self.ecdsa)

        self.initECDH()
        self.stackedWidget.addWidget(self.ecdh)
    
    def initPrimitives(self):
        self.primitives = PrimitivesUI()
    
    def initHash(self):
        self.hash = HashUI()
    
    def initSKEnc(self):
        self.ske = SKEncUI()    

    def initMac(self):
        self.mac = MacUI()
    
    def initRsa(self):
        self.rsa = RsaUI()

    def initElGamal(self):
        self.elgamal = ElGamalUI()
    
    def initDsa(self):
        self.dsa = DsaUI()

    def initDH(self):
        self.dh = DHUI()
    
    def initECElGamal(self):
        self.ecelgamal = ECElGamalUI()

    def initECDSA(self):
        self.ecdsa = ECDSAUI()
    
    def initECDH(self):
        self.ecdh = ECDHUI()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())