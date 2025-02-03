from utils import add_build_to_path
add_build_to_path()

from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from error_handling import show_error_dialog

class NavBar(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(NavBar, self).__init__(*args, **kwargs)
        loadUi("wireframes/ui_navbar.ui", self)
        # self.setWindowTitle("Navbar")
        self.setButtonsHover()

    def setButtonsHover(self):
        for button in self.findChildren(QtWidgets.QPushButton):
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
    widget = NavBar()
    widget.show()
    sys.exit(app.exec_())