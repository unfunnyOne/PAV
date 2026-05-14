import sys

from PyQt6.QtWidgets import (
    QMainWindow, QWidget,
    QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel,
    QFrame, QStackedWidget,
    QApplication, QSpacerItem,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QIcon

from gui.scan_page import ScanPage


NAV_ITEMS = [
    ("🏠", "Home"),
    ("🔍", "Scan"),
    ("📋", "History"),
    ("🔒", "Quarantine"),
]

SIDEBAR_STYLE = "background-color: #0f0f0f; border-right: 1px solid #1f1f1f;"

BTN_BASE = """
    QPushButton {{
        background-color: {bg};
        color: {fg};
        text-align: left;
        padding: 10px 14px;
        border-radius: 10px;
        font-size: 14px;
        border: none;
    }}
    QPushButton:hover {{
        background-color: {hover};
        color: white;
    }}
"""

BTN_NORMAL = BTN_BASE.format(bg="transparent", fg="#888888", hover="#1e1e1e")
BTN_ACTIVE = BTN_BASE.format(bg="#1e3a8a", fg="white", hover="#1d4ed8")


class SidebarButton(QPushButton):
    def __init__(self, icon: str, label: str):
        super().__init__(f"  {icon}  {label}")
        self.setFixedHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setActive(False)

    def setActive(self, active: bool):
        self.setStyleSheet(BTN_ACTIVE if active else BTN_NORMAL)


class PlaceholderPage(QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.setStyleSheet("background-color: #181818;")
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(layout)

        icon = QLabel({"Home": "🏠", "History": "📋", "Quarantine": "🔒"}.get(title, "📄"))
        icon.setStyleSheet("font-size: 48px;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel(title)
        lbl.setStyleSheet("color: #555; font-size: 22px; font-weight: bold;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        sub = QLabel("This section is under construction")
        sub.setStyleSheet("color: #333; font-size: 13px;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(icon)
        layout.addSpacing(8)
        layout.addWidget(lbl)
        layout.addWidget(sub)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PAV")
        self.resize(1200, 720)
        self.setMinimumSize(900, 600)
        self.setStyleSheet("background-color: #181818;")

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        central.setLayout(main_layout)

        # ─────────── SIDEBAR ───────────
        sidebar = QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet(SIDEBAR_STYLE)

        side_layout = QVBoxLayout()
        side_layout.setContentsMargins(16, 24, 16, 24)
        side_layout.setSpacing(6)
        sidebar.setLayout(side_layout)

        # Logo
        logo_row = QHBoxLayout()
        logo_icon = QLabel("🛡️")
        logo_icon.setStyleSheet("font-size: 22px;")
        logo_text = QLabel("PAV")
        logo_text.setStyleSheet(
            "color: white; font-size: 18px; font-weight: bold; letter-spacing: 0.5px;"
        )
        logo_row.addWidget(logo_icon)
        logo_row.addWidget(logo_text)
        logo_row.addStretch()

        side_layout.addLayout(logo_row)
        side_layout.addSpacing(20)

        # Divider label
        nav_label = QLabel("NAVIGATION")
        nav_label.setStyleSheet("color: #333; font-size: 10px; letter-spacing: 1.5px;")
        side_layout.addWidget(nav_label)
        side_layout.addSpacing(4)

        # ─────────── STACK ───────────
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: #181818;")

        self.home_page     = PlaceholderPage("Home")
        self.scan_page     = ScanPage()
        self.history_page  = PlaceholderPage("History")
        self.quarantine_page = PlaceholderPage("Quarantine")

        pages = [
            self.home_page,
            self.scan_page,
            self.history_page,
            self.quarantine_page,
        ]
        for p in pages:
            self.stack.addWidget(p)

        # ─────────── NAV BUTTONS ───────────
        self._nav_buttons: list[SidebarButton] = []

        for idx, (icon, label) in enumerate(NAV_ITEMS):
            btn = SidebarButton(icon, label)
            page = pages[idx]
            btn.clicked.connect(lambda checked, b=btn, p=page: self._navigate(b, p))
            self._nav_buttons.append(btn)
            side_layout.addWidget(btn)

        # Activate "Home" by default
        self._navigate(self._nav_buttons[0], self.home_page)

        side_layout.addStretch()

        # Because I can
        author = QLabel("unfunny0ne, 2026")
        author.setStyleSheet("color: #2a2a2a; font-size: 11px;")
        author.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(author)

        # ─────────── ASSEMBLE ───────────
        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.stack, 1)

    # ─────────── NAVIGATION ───────────
    def _navigate(self, active_btn: SidebarButton, page: QWidget):
        for btn in self._nav_buttons:
            btn.setActive(btn is active_btn)
        self.stack.setCurrentWidget(page)


def run():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())