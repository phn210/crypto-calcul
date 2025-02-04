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
        self.setWindowTitle("DLC: Cryptographic Calculator - Group 14A")
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
        self.navbar.setObjectName("NavBar")
        self.navbar.setStyleSheet("QWidget#NavBar { background-color: #303657; }")


    def initNavBarBtns(self):
        for _, btn in enumerate(self.navbar.findChildren(QtWidgets.QPushButton)):
            text = btn.objectName().lower()
            if btn.isEnabled():
                id = self.pages.index(text)
                btn.clicked.connect(lambda _, i=id: self.loadPage(i))

    def loadPage(self, pageIndex):
        self.stackedWidget.setCurrentIndex(pageIndex)

    def initStackedWidget(self):
        self.stackedWidget = QtWidgets.QStackedWidget(self)
        self.stackedWidget.setObjectName("stackedWidget")
        self.pages = ['primitives', 'hash', 'enc', 'mac', 'rsa', 'elgamal', 'dsa', 'dh', 'ecelgamal', 'ecdsa', 'ecdh']
        self.widgets = [PrimitivesUI(), HashUI(), SKEncUI(), MacUI(), RsaUI(), ElGamalUI(), DsaUI(), DHUI(), ECElGamalUI(), ECDSAUI(), ECDHUI()]
        for widget in self.widgets:
            self.stackedWidget.addWidget(widget)

    #     self.initPrimitives()
    #     self.stackedWidget.addWidget(self.primitives)
        
    #     self.initHash()
    #     self.stackedWidget.addWidget(self.hash)

    #     self.initSKEnc()
    #     self.stackedWidget.addWidget(self.ske)

    #     self.initMac()
    #     self.stackedWidget.addWidget(self.mac)

    #     self.initRsa()
    #     self.stackedWidget.addWidget(self.rsa)

    #     self.initElGamal()
    #     self.stackedWidget.addWidget(self.elgamal)

    #     self.initDsa()
    #     self.stackedWidget.addWidget(self.dsa)

    #     self.initDH()
    #     self.stackedWidget.addWidget(self.dh)

    #     self.initECElGamal()
    #     self.stackedWidget.addWidget(self.ecelgamal)

    #     self.initECDSA()
    #     self.stackedWidget.addWidget(self.ecdsa)

    #     self.initECDH()
    #     self.stackedWidget.addWidget(self.ecdh)
        
    # def initPrimitives(self):
    #     self.primitives = PrimitivesUI()
    
    # def initHash(self):
    #     self.hash = HashUI()
    
    # def initSKEnc(self):
    #     self.ske = SKEncUI()    

    # def initMac(self):
    #     self.mac = MacUI()
    
    # def initRsa(self):
    #     self.rsa = RsaUI()

    # def initElGamal(self):
    #     self.elgamal = ElGamalUI()
    
    # def initDsa(self):
    #     self.dsa = DsaUI()

    # def initDH(self):
    #     self.dh = DHUI()
    
    # def initECElGamal(self):
    #     self.ecelgamal = ECElGamalUI()

    # def initECDSA(self):
    #     self.ecdsa = ECDSAUI()
    
    # def initECDH(self):
    #     self.ecdh = ECDHUI()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MainWindow()
    # mainWindow.setStyleSheet("background-color: #303657;")
    mainWindow.show()
    sys.exit(app.exec_())