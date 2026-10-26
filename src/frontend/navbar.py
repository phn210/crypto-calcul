from PyQt5 import QtCore, QtGui, QtWidgets

# (section, [(page key, label)]) in display order
SECTIONS = [
    ("Fundamentals", [("primitives", "Random && primes"), ("hash", "Hash functions")]),
    ("Symmetric", [("enc", "Encryption"), ("mac", "Message authentication")]),
    ("Public key", [("rsa", "RSA"), ("elgamal", "ElGamal"), ("dsa", "DSA"), ("dh", "Diffie-Hellman")]),
    ("Elliptic curves", [("ecelgamal", "EC-ElGamal"), ("ecdsa", "ECDSA"), ("ecdh", "ECDH")]),
]


class NavBarUI(QtWidgets.QWidget):
    """Sidebar: app name, page navigation by section, and the light/dark switch."""

    pageSelected = QtCore.pyqtSignal(str)
    themeToggled = QtCore.pyqtSignal()

    def __init__(self, *args, **kwargs):
        super(NavBarUI, self).__init__(*args, **kwargs)
        self.setObjectName("sidebar")
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        self.buttons = {}

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 24, 16, 16)
        layout.setSpacing(2)

        brand = QtWidgets.QLabel("Crypto Calculator")
        brand.setObjectName("brand")
        tagline = QtWidgets.QLabel("Cryptography workbench")
        tagline.setObjectName("brandTagline")
        for label in (brand, tagline):
            label.setContentsMargins(12, 0, 12, 0)
            layout.addWidget(label)

        group = QtWidgets.QButtonGroup(self)
        group.setExclusive(True)
        for section, items in SECTIONS:
            layout.addSpacing(18)
            heading = QtWidgets.QLabel(section.upper())
            heading.setObjectName("navSection")
            font = heading.font()
            font.setLetterSpacing(QtGui.QFont.AbsoluteSpacing, 0.8)
            heading.setFont(font)
            layout.addWidget(heading)
            layout.addSpacing(4)
            for key, text in items:
                button = QtWidgets.QPushButton(text)
                button.setObjectName("navItem")
                button.setCheckable(True)
                button.setCursor(QtCore.Qt.PointingHandCursor)
                button.clicked.connect(lambda _, k=key: self.pageSelected.emit(k))
                group.addButton(button)
                layout.addWidget(button)
                self.buttons[key] = button

        layout.addStretch(1)
        self.themeButton = QtWidgets.QPushButton()
        self.themeButton.setObjectName("themeToggle")
        self.themeButton.setCursor(QtCore.Qt.PointingHandCursor)
        self.themeButton.clicked.connect(self.themeToggled.emit)
        layout.addWidget(self.themeButton)

    def select(self, key: str) -> None:
        self.buttons[key].setChecked(True)

    def setTheme(self, name: str) -> None:
        self.themeButton.setText("Switch to dark mode" if name == "light" else "Switch to light mode")
