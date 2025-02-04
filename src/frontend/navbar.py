from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from utils import WIREFRAME_PATH

class NavBarUI(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(NavBarUI, self).__init__(*args, **kwargs)
        loadUi(f"{WIREFRAME_PATH}/ui_navbar.ui", self)
        self.setButtonsHover()

    def setButtonsHover(self):
        for button in self.findChildren(QtWidgets.QPushButton):
            if button.isEnabled():
                button.setStyleSheet("""QPushButton
{
  	border-style: none;
	color: white;
	font-size: 20px;
	font-weight: bold;
	background-color: #3f4773;
	border-radius: 10;
	text-align: left;
	padding-left: 10;
}
QPushButton:hover
{
  	background-color:#485187;
}""")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    widget = NavBarUI()
    widget.setStyleSheet("background-color: #303657;")
    widget.show()
    sys.exit(app.exec_())