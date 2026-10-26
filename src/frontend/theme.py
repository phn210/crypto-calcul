"""Application theme: light and dark color tokens, the Qt stylesheet built from them, and a
polish pass that gives the Designer forms roles (cards, field labels, button kinds) to style."""
import os
import re

from PyQt5 import QtCore, QtGui, QtWidgets

LIGHT = {
    "bg": "#f5f6f8",
    "surface": "#ffffff",
    "sidebar": "#fbfbfc",
    "text": "#111827",
    "muted": "#6b7280",
    "border": "#e4e6eb",
    "hover": "#f0f1f4",
    "input": "#ffffff",
    "readonly": "#f8f9fb",
    "accent": "#4f46e5",
    "accent_hover": "#4338ca",
    "on_accent": "#ffffff",
    "soft": "#eef0ff",
    "on_soft": "#3730a3",
}

DARK = {
    "bg": "#0f1116",
    "surface": "#171a21",
    "sidebar": "#13161c",
    "text": "#e6e8ec",
    "muted": "#9aa1ad",
    "border": "#2a2e38",
    "hover": "#1f232c",
    "input": "#11141a",
    "readonly": "#141720",
    "accent": "#6366f1",
    "accent_hover": "#7c7ff5",
    "on_accent": "#ffffff",
    "soft": "#23264a",
    "on_soft": "#c7cbff",
}

THEMES = {"light": LIGHT, "dark": DARK}

ICONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons").replace(os.sep, "/")

MONO = '"JetBrains Mono", "SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono", monospace'

STYLESHEET = """
QWidget {{ color: {text}; font-size: 14px; }}
#root, #content, #page {{ background: {bg}; }}
QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
QToolTip {{ background: {surface}; color: {text}; border: 1px solid {border}; padding: 6px; }}

/* Sidebar */
#sidebar {{ background: {sidebar}; border-right: 1px solid {border}; }}
#brand {{ font-size: 17px; font-weight: 700; }}
#brandTagline {{ color: {muted}; font-size: 12px; }}
#navSection {{ color: {muted}; font-size: 11px; font-weight: 700; padding: 0 12px; }}
#navItem {{
    background: transparent; border: none; border-radius: 8px;
    padding: 8px 12px; text-align: left; font-weight: 500;
}}
#navItem:hover {{ background: {hover}; }}
#navItem:checked {{ background: {soft}; color: {on_soft}; font-weight: 600; }}
#themeToggle {{ background: transparent; border: 1px solid {border}; border-radius: 8px; padding: 7px 12px; color: {muted}; }}
#themeToggle:hover {{ background: {hover}; color: {text}; }}

/* Page header */
#pageTitle {{ font-size: 26px; font-weight: 700; }}
#pageSubtitle {{ color: {muted}; font-size: 14px; }}

/* Cards */
QGroupBox, QFrame[card="true"] {{
    background: {surface}; border: 1px solid {border}; border-radius: 12px;
}}
QLabel[role="section"] {{ font-size: 16px; font-weight: 600; }}
QLabel[role="field"] {{ color: {muted}; font-weight: 500; }}

/* Tabs */
QTabWidget::pane {{ border: none; top: -1px; }}
QTabBar {{ qproperty-drawBase: 0; font-weight: 600; }}
QTabBar::tab {{
    background: transparent; color: {muted}; padding: 8px 14px; margin-right: 4px;
    border: none; border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ color: {text}; }}
QTabBar::tab:selected {{ color: {accent}; border-bottom: 2px solid {accent}; }}

/* Inputs */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{
    background: {input}; border: 1px solid {border}; border-radius: 8px;
    padding: 7px 10px; selection-background-color: {accent}; selection-color: {on_accent};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border: 1px solid {accent}; }}
QLineEdit:disabled, QComboBox:disabled {{ color: {muted}; background: {readonly}; }}
QLineEdit[readOnly="true"], QTextEdit[result="true"] {{ background: {readonly}; }}
QLineEdit[result="true"], QTextEdit[result="true"] {{ font-family: {mono}; font-size: 13px; }}
QComboBox::drop-down {{ subcontrol-origin: padding; subcontrol-position: center right; width: 28px; border: none; }}
QComboBox::down-arrow {{ image: url({icons}/chevron-{name}.svg); width: 12px; height: 12px; }}
QComboBox QAbstractItemView {{
    background: {surface}; border: 1px solid {border}; selection-background-color: {soft}; selection-color: {on_soft};
}}

/* Buttons */
QPushButton {{
    background: {surface}; border: 1px solid {border}; border-radius: 8px;
    padding: 8px 18px; font-weight: 600; min-height: 20px;
}}
QPushButton:hover {{ background: {hover}; }}
QPushButton:pressed {{ background: {border}; }}
QPushButton:disabled {{ color: {muted}; }}
QPushButton[kind="primary"] {{ background: {accent}; border: 1px solid {accent}; color: {on_accent}; }}
QPushButton[kind="primary"]:hover {{ background: {accent_hover}; border-color: {accent_hover}; }}
QPushButton[kind="tonal"] {{ background: {soft}; border: 1px solid {soft}; color: {on_soft}; }}
QPushButton[kind="tonal"]:hover {{ border-color: {accent}; }}

/* Choices: radio buttons are drawn as segmented chips */
QRadioButton {{
    background: {surface}; border: 1px solid {border}; border-radius: 8px;
    padding: 6px 12px; spacing: 0px; min-height: 20px;
}}
QRadioButton::indicator {{ width: 0px; height: 0px; margin: 0px; border: none; background: transparent; image: none; }}
QRadioButton:hover {{ background: {hover}; }}
QRadioButton:checked {{ background: {soft}; border-color: {accent}; color: {on_soft}; font-weight: 600; }}
QRadioButton:focus, QPushButton:focus, QCheckBox:focus {{ outline: none; }}
QRadioButton:focus, QPushButton:focus {{ border-color: {accent}; }}
QRadioButton:disabled {{ color: {muted}; background: transparent; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border: 1px solid {border}; border-radius: 4px; background: {input};
}}
QCheckBox::indicator:checked {{ background: {accent}; border-color: {accent}; image: url({icons}/check.svg); }}

/* Scroll bars */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle {{ background: {border}; border-radius: 3px; min-height: 30px; min-width: 30px; }}
QScrollBar::handle:hover {{ background: {muted}; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; }}

QMessageBox {{ background: {surface}; }}
"""


def stylesheet(name: str) -> str:
    return STYLESHEET.format(mono=MONO, icons=ICONS, name=name, **THEMES[name])


def palette(name: str) -> QtGui.QPalette:
    """Fusion palette matching the theme, for widgets and dialogs the stylesheet does not cover."""
    t = THEMES[name]
    color = QtGui.QColor
    p = QtGui.QPalette()
    p.setColor(QtGui.QPalette.Window, color(t["bg"]))
    p.setColor(QtGui.QPalette.WindowText, color(t["text"]))
    p.setColor(QtGui.QPalette.Base, color(t["input"]))
    p.setColor(QtGui.QPalette.AlternateBase, color(t["readonly"]))
    p.setColor(QtGui.QPalette.Text, color(t["text"]))
    p.setColor(QtGui.QPalette.Button, color(t["surface"]))
    p.setColor(QtGui.QPalette.ButtonText, color(t["text"]))
    p.setColor(QtGui.QPalette.Highlight, color(t["accent"]))
    p.setColor(QtGui.QPalette.HighlightedText, color(t["on_accent"]))
    p.setColor(QtGui.QPalette.ToolTipBase, color(t["surface"]))
    p.setColor(QtGui.QPalette.ToolTipText, color(t["text"]))
    p.setColor(QtGui.QPalette.PlaceholderText, color(t["muted"]))
    for role in (QtGui.QPalette.WindowText, QtGui.QPalette.Text, QtGui.QPalette.ButtonText):
        p.setColor(QtGui.QPalette.Disabled, role, color(t["muted"]))
    return p


def saved() -> str:
    """Theme chosen last time (light by default)."""
    name = QtCore.QSettings("cryptocalc", "gui").value("theme", "light")
    return name if name in THEMES else "light"


def save(name: str) -> None:
    QtCore.QSettings("cryptocalc", "gui").setValue("theme", name)


def apply(app: QtWidgets.QApplication, name: str) -> None:
    app.setStyle("Fusion")
    app.setPalette(palette(name))
    app.setStyleSheet(stylesheet(name))


# ---------------------------------------------------------------------------
# Polishing the Designer forms
# ---------------------------------------------------------------------------

TITLE_LABELS = ("mainTitle", "titleLabel")
PRIMARY = re.compile(r"^btn(Encrypt|Sign|Rng|PrimeTest|PrimeGen|GenHash|GenShake|GenTag|KeyEx)$")
TONAL = re.compile(r"^btn(KeyGen\w*|SecretGen)$")
FIELD_LABEL_WIDTH = 130
QWIDGETSIZE_MAX = (1 << 24) - 1


def _layouts(layout):
    yield layout
    for i in range(layout.count()):
        child = layout.itemAt(i).layout()
        if child is not None:
            yield from _layouts(child)


def _widgets(layout):
    return [layout.itemAt(i).widget() for i in range(layout.count()) if layout.itemAt(i).widget() is not None]


def _wrap_in_card(page: QtWidgets.QWidget) -> None:
    layout = page.layout()
    card = QtWidgets.QFrame(page)
    card.setProperty("card", True)
    card_layout = QtWidgets.QVBoxLayout(card)
    card_layout.setContentsMargins(20, 20, 20, 20)
    card_layout.setSpacing(14)
    while layout.count():
        item = layout.takeAt(0)
        if item.widget() is not None:
            card_layout.addWidget(item.widget())
        elif item.layout() is not None:
            # Adding the layout to the card reparents its widgets to the card
            sub = item.layout()
            sub.setParent(None)
            card_layout.addLayout(sub)
        else:
            card_layout.addItem(item)
    layout.addWidget(card)


def polish(page: QtWidgets.QWidget) -> str:
    """Prepares a loaded form for the theme and returns its title, which the window header shows."""
    title = ""
    for name in TITLE_LABELS:
        label = page.findChild(QtWidgets.QLabel, name)
        if label is not None:
            title = label.text()
            label.hide()

    page.setObjectName("page")
    if page.layout() is not None:
        page.layout().setContentsMargins(0, 0, 0, 0)
        page.layout().setSpacing(16)

    # Cards: group boxes and plain frames
    for frame in page.findChildren(QtWidgets.QFrame):
        if type(frame) is QtWidgets.QFrame:
            frame.setProperty("card", True)
    for card in page.findChildren(QtWidgets.QGroupBox) + [f for f in page.findChildren(QtWidgets.QFrame) if f.property("card")]:
        if card.layout() is not None:
            card.layout().setContentsMargins(20, 20, 20, 20)
            card.layout().setSpacing(14)

    # Tab pages: some forms place their card at a fixed size; a layout lets it follow the window.
    # The margins leave room under the tab underline and for the card border.
    for tabs in page.findChildren(QtWidgets.QTabWidget):
        for i in range(tabs.count()):
            tab = tabs.widget(i)
            if tab.layout() is None:
                layout = QtWidgets.QVBoxLayout(tab)
                for child in tab.findChildren(QtWidgets.QWidget, options=QtCore.Qt.FindDirectChildrenOnly):
                    layout.addWidget(child)
            tab.layout().setContentsMargins(1, 16, 1, 1)

    # Forms without any card get one around their whole content
    if not page.findChildren(QtWidgets.QGroupBox) and not page.findChildren(QtWidgets.QTabWidget) \
            and not any(f.property("card") for f in page.findChildren(QtWidgets.QFrame)):
        _wrap_in_card(page)

    # Labels: section headings and field labels
    for label in page.findChildren(QtWidgets.QLabel):
        if label.objectName() in TITLE_LABELS:
            continue
        if label.text().strip().endswith(":"):
            label.setText(label.text().strip())
            label.setProperty("role", "field")
            label.setMinimumWidth(FIELD_LABEL_WIDTH)
        else:
            label.setProperty("role", "section")

    # Rows of choices and buttons are packed to the left instead of spread over the width
    expanding = (QtWidgets.QLineEdit, QtWidgets.QTextEdit, QtWidgets.QPlainTextEdit, QtWidgets.QComboBox)
    for root in page.findChildren(QtWidgets.QLayout):
        for layout in _layouts(root):
            if not isinstance(layout, QtWidgets.QHBoxLayout):
                continue
            layout.setSpacing(8)
            widgets = _widgets(layout)
            if widgets and not any(isinstance(w, expanding) for w in widgets):
                layout.addStretch(1)
            # A label beside a multi-line input lines up with its first line
            if any(isinstance(w, (QtWidgets.QTextEdit, QtWidgets.QPlainTextEdit)) for w in widgets):
                for label in (w for w in widgets if isinstance(w, QtWidgets.QLabel)):
                    layout.setAlignment(label, QtCore.Qt.AlignTop)
                    label.setContentsMargins(0, 9, 0, 0)

    # Buttons: the forms cap them at 150x30, which clips longer labels with the theme's padding
    for button in page.findChildren(QtWidgets.QPushButton):
        button.setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX)
        name = button.objectName()
        button.setText(button.text().strip())
        button.setProperty("kind", "primary" if PRIMARY.match(name) else "tonal" if TONAL.match(name) else "secondary")
        button.setCursor(QtCore.Qt.PointingHandCursor)

    # Chips keep their natural width, also in grids
    for choice in page.findChildren(QtWidgets.QRadioButton):
        choice.setText(choice.text().strip().rstrip(":"))
        choice.setCursor(QtCore.Qt.PointingHandCursor)
        choice.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        choice.setMinimumWidth(0)

    # Results: read-only and monospace
    for widget in page.findChildren(QtWidgets.QLineEdit) + page.findChildren(QtWidgets.QTextEdit):
        if widget.objectName().startswith("output"):
            widget.setReadOnly(True)
            widget.setProperty("result", True)
        if isinstance(widget, QtWidgets.QTextEdit):
            widget.setMinimumHeight(90)

    return title
