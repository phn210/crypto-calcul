from PyQt5 import QtCore, QtWidgets

import theme
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

NAVBAR_WIDTH = 248
CONTENT_MAX_WIDTH = 1040

# Page key: (title, subtitle)
PAGE_INFO = {
    "primitives": ("Random numbers & primes", "Random integers, primality tests and prime generation"),
    "hash": ("Hash functions", "MD5, SHA-1, SHA-2 and SHA-3 digests, and SHAKE extendable output"),
    "enc": ("Symmetric encryption", "AES and DES with PKCS#7 padding, for text or files"),
    "mac": ("Message authentication", "HMAC and AES-CBC-MAC tags for text or files"),
    "rsa": ("RSA", "Textbook, PKCS#1 v1.5 and OAEP/PSS encryption and signatures"),
    "elgamal": ("ElGamal", "ElGamal encryption and signatures over RFC 3526 groups"),
    "dsa": ("DSA", "Digital Signature Algorithm with SHA-2 or SHA-3"),
    "dh": ("Diffie-Hellman", "Key exchange over finite-field groups"),
    "ecelgamal": ("EC-ElGamal", "Elliptic-curve ElGamal encryption and signatures"),
    "ecdsa": ("ECDSA", "Elliptic Curve Digital Signature Algorithm"),
    "ecdh": ("ECDH", "Elliptic-curve Diffie-Hellman key exchange"),
}


class MainWindow(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setObjectName("root")
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        self.setWindowTitle("Cryptographic Calculator")
        self.setMinimumSize(1100, 760)
        self.resize(1320, 880)
        self.themeName = theme.saved()
        self.initNavBar()
        self.initStackedWidget()
        self.initMainLayout()
        self.loadPage(0)

    def initNavBar(self):
        self.navbar = NavBarUI()
        self.navbar.setFixedWidth(NAVBAR_WIDTH)
        self.navbar.pageSelected.connect(lambda key: self.loadPage(self.pages.index(key)))
        self.navbar.themeToggled.connect(self.toggleTheme)
        self.navbar.setTheme(self.themeName)

    def initStackedWidget(self):
        self.stackedWidget = QtWidgets.QStackedWidget(self)
        self.stackedWidget.setObjectName("stackedWidget")
        self.pages = ['primitives', 'hash', 'enc', 'mac', 'rsa', 'elgamal', 'dsa', 'dh', 'ecelgamal', 'ecdsa', 'ecdh']
        self.widgets = [PrimitivesUI(), HashUI(), SKEncUI(), MacUI(), RsaUI(), ElGamalUI(), DsaUI(), DHUI(), ECElGamalUI(), ECDSAUI(), ECDHUI()]
        for widget in self.widgets:
            theme.polish(widget)
            self.stackedWidget.addWidget(widget)

    def initMainLayout(self):
        self.pageTitle = QtWidgets.QLabel()
        self.pageTitle.setObjectName("pageTitle")
        self.pageSubtitle = QtWidgets.QLabel()
        self.pageSubtitle.setObjectName("pageSubtitle")

        # Header and page in a column of bounded width, scrolled when the window is small
        column = QtWidgets.QWidget()
        column.setMaximumWidth(CONTENT_MAX_WIDTH)
        columnLayout = QtWidgets.QVBoxLayout(column)
        columnLayout.setContentsMargins(40, 32, 40, 32)
        columnLayout.setSpacing(4)
        columnLayout.addWidget(self.pageTitle)
        columnLayout.addWidget(self.pageSubtitle)
        columnLayout.addSpacing(20)
        columnLayout.addWidget(self.stackedWidget, 1)

        content = QtWidgets.QWidget()
        content.setObjectName("content")
        content.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        contentLayout = QtWidgets.QHBoxLayout(content)
        contentLayout.setContentsMargins(0, 0, 0, 0)
        contentLayout.addWidget(column, 1)
        contentLayout.addStretch(0)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll.setWidget(content)

        self.mainLayout = QtWidgets.QHBoxLayout(self)
        self.mainLayout.setContentsMargins(0, 0, 0, 0)
        self.mainLayout.setSpacing(0)
        self.mainLayout.addWidget(self.navbar)
        self.mainLayout.addWidget(scroll, 1)

    def loadPage(self, pageIndex):
        key = self.pages[pageIndex]
        self.stackedWidget.setCurrentIndex(pageIndex)
        title, subtitle = PAGE_INFO[key]
        self.pageTitle.setText(title)
        self.pageSubtitle.setText(subtitle)
        self.navbar.select(key)

    def toggleTheme(self):
        self.themeName = "dark" if self.themeName == "light" else "light"
        theme.save(self.themeName)
        theme.apply(QtWidgets.QApplication.instance(), self.themeName)
        self.navbar.setTheme(self.themeName)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    theme.apply(app, theme.saved())
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
