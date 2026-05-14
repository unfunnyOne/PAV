from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog,
    QProgressBar, QComboBox,
    QPlainTextEdit, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from pathlib import Path

from core import engine


# ─────────────────────────────────────────────
#  Worker
# ─────────────────────────────────────────────
class ScanWorker(QThread):
    # (filepath, files_done, total, is_infected, matched_rules)
    file_scanned = pyqtSignal(str, int, int, bool, list)
    error        = pyqtSignal(str)
    finished     = pyqtSignal(int, int)   # (total_scanned, threats_found)

    def __init__(self, paths: list):
        super().__init__()
        self.paths = paths
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        total_scanned = 0
        threats_found = 0

        for scan_path in self.paths:
            if self._cancelled:
                break
            try:
                for result, done, total in engine.scanPath(scan_path, returnnegatives=True):
                    if self._cancelled:
                        break
                    total_scanned += 1
                    if result.infected:
                        threats_found += 1
                    self.file_scanned.emit(
                        str(result.filepath),
                        done,
                        total,
                        result.infected,
                        result.matches,
                    )
            except RuntimeError as e:
                self.error.emit(str(e))
                return

        self.finished.emit(total_scanned, threats_found)


# ─────────────────────────────────────────────
#  Styles
# ─────────────────────────────────────────────
COMBO_STYLE = """
    QComboBox {
        background-color: #1e1e1e;
        color: white;
        border: 1px solid #2e2e2e;
        padding: 8px 12px;
        border-radius: 10px;
        font-size: 13px;
    }
    QComboBox::drop-down { border: none; width: 24px; }
    QComboBox QAbstractItemView {
        background-color: #1e1e1e;
        color: white;
        selection-background-color: #2563eb;
        border: 1px solid #333;
    }
"""
BTN_SECONDARY = """
    QPushButton {
        background-color: #1e1e1e;
        color: #cccccc;
        border: 1px solid #2e2e2e;
        padding: 9px 14px;
        border-radius: 10px;
        font-size: 13px;
        text-align: left;
    }
    QPushButton:hover { background-color: #2a2a2a; color: white; }
    QPushButton:disabled { color: #444; border-color: #222; }
"""
BTN_PRIMARY = """
    QPushButton {
        background-color: #2563eb;
        color: white;
        font-size: 15px;
        font-weight: bold;
        padding: 12px;
        border-radius: 12px;
        border: none;
    }
    QPushButton:hover { background-color: #1d4ed8; }
    QPushButton:disabled { background-color: #1a3a7a; color: #668; }
"""
BTN_DANGER = """
    QPushButton {
        background-color: #7f1d1d;
        color: #fca5a5;
        font-size: 15px;
        font-weight: bold;
        padding: 12px;
        border-radius: 12px;
        border: none;
    }
    QPushButton:hover { background-color: #991b1b; }
"""
BTN_SMALL = """
    QPushButton {
        background-color: transparent;
        color: #555;
        border: 1px solid #2a2a2a;
        padding: 5px 10px;
        border-radius: 8px;
        font-size: 11px;
    }
    QPushButton:hover { color: #aaa; border-color: #444; }
"""
PROGRESS_STYLE = """
    QProgressBar {
        background-color: #1e1e1e;
        border: 1px solid #2a2a2a;
        border-radius: 8px;
        height: 14px;
        color: transparent;
    }
    QProgressBar::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #2563eb, stop:1 #60a5fa);
        border-radius: 8px;
    }
"""
LOG_STYLE = """
    QPlainTextEdit {
        background-color: #0f0f0f;
        color: #a0a0a0;
        border: 1px solid #1f1f1f;
        border-radius: 10px;
        padding: 10px;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12px;
        selection-background-color: #2563eb;
    }
"""


# ─────────────────────────────────────────────
#  Page
# ─────────────────────────────────────────────
class ScanPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("QWidget { background-color: #181818; color: white; }")

        self.selected_paths: list = []
        self._worker: ScanWorker | None = None

        root = QVBoxLayout()
        root.setContentsMargins(40, 36, 40, 36)
        root.setSpacing(0)
        self.setLayout(root)

        # ── Title ──
        title = QLabel("Scan Center")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: white;")
        subtitle = QLabel("Choose a scan mode and target, then press Start.")
        subtitle.setStyleSheet("color: #555; font-size: 13px; margin-bottom: 4px;")
        root.addWidget(title)
        root.addWidget(subtitle)
        root.addSpacing(24)

        # ── Mode ──
        mode_label = QLabel("SCAN MODE")
        mode_label.setStyleSheet("color: #444; font-size: 10px; letter-spacing: 1.5px;")
        root.addWidget(mode_label)
        root.addSpacing(4)

        self.mode = QComboBox()
        self.mode.addItems(["Quick Scan", "Full Scan", "Custom Scan"])
        self.mode.setStyleSheet(COMBO_STYLE)
        self.mode.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode.currentTextChanged.connect(self._on_mode_change)
        root.addWidget(self.mode)
        root.addSpacing(12)

        # ── Target row ──
        target_row = QHBoxLayout()
        target_row.setSpacing(8)

        self.folder_btn = QPushButton("📁  Folder")
        self.folder_btn.setStyleSheet(BTN_SECONDARY)
        self.folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.folder_btn.clicked.connect(self._pick_folder)

        self.files_btn = QPushButton("📄  Files")
        self.files_btn.setStyleSheet(BTN_SECONDARY)
        self.files_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.files_btn.clicked.connect(self._pick_files)

        self.target_label = QLabel("No target selected")
        self.target_label.setStyleSheet("color: #444; font-size: 12px;")
        self.target_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        target_row.addWidget(self.folder_btn)
        target_row.addWidget(self.files_btn)
        target_row.addWidget(self.target_label, 1)
        root.addLayout(target_row)
        root.addSpacing(16)

        # ── Start / Cancel button ──
        self.start_btn = QPushButton("▶   Start Scan")
        self.start_btn.setStyleSheet(BTN_PRIMARY)
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.clicked.connect(self._on_start_cancel)
        root.addWidget(self.start_btn)
        root.addSpacing(14)

        # ── Progress ──
        prog_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(14)
        self.progress.setStyleSheet(PROGRESS_STYLE)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #444; font-size: 11px;")
        self.progress_label.setVisible(False)

        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.progress_label)
        root.addLayout(prog_row)
        root.addSpacing(14)

        # ── Log header ──
        log_header = QHBoxLayout()
        log_lbl = QLabel("SCAN LOG")
        log_lbl.setStyleSheet("color: #444; font-size: 10px; letter-spacing: 1.5px;")
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet(BTN_SMALL)
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        log_header.addWidget(log_lbl)
        log_header.addStretch()
        log_header.addWidget(self.clear_btn)
        root.addLayout(log_header)
        root.addSpacing(4)

        # ── Log ──
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet(LOG_STYLE)
        root.addWidget(self.log, 1)

        self.clear_btn.clicked.connect(self.log.clear)

        self._on_mode_change(self.mode.currentText())

    # ─────────── Mode ───────────
    def _on_mode_change(self, mode: str):
        self._reset_target()
        is_custom = mode == "Custom Scan"
        self.folder_btn.setEnabled(is_custom)
        self.files_btn.setEnabled(is_custom)
        self._log("INFO", f"Mode: {mode}")

    # ─────────── Target ───────────
    def _pick_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if not path:
            return
        self.selected_paths = [Path(path)]
        self.target_label.setText(f"📁  {path}")
        self.target_label.setStyleSheet("color: #60a5fa; font-size: 12px;")
        self._log("TARGET", path)

    def _pick_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Scan")
        if not paths:
            return
        self.selected_paths = [Path(p) for p in paths]
        self.target_label.setText(f"📄  {len(paths)} file(s) selected")
        self.target_label.setStyleSheet("color: #60a5fa; font-size: 12px;")
        for p in paths:
            self._log("FILE", p)

    def _reset_target(self):
        self.selected_paths = []
        self.target_label.setText("No target selected")
        self.target_label.setStyleSheet("color: #444; font-size: 12px;")

    # ─────────── Start / Cancel ───────────
    def _on_start_cancel(self):
        if self._worker and self._worker.isRunning():
            self._cancel_scan()
        else:
            self._start_scan()

    def _start_scan(self):
        mode = self.mode.currentText()

        if mode == "Custom Scan" and not self.selected_paths:
            self._log("ERROR", "No target selected.")
            return

        if mode == "Quick Scan":
            scan_paths = [Path.home() / "Downloads", Path.home() / "Desktop"]
        elif mode == "Full Scan":
            scan_paths = [Path.home()]
        else:
            scan_paths = self.selected_paths

        engine.compileRules()

        if engine.rules is None:
            self._log("ERROR", "YARA rules are not loaded. Call engine.compileRules() first.")
            return

        self._log("SCAN", f"Starting {mode} → {[str(p) for p in scan_paths]}")
        self._set_ui_scanning(True)

        self._worker = ScanWorker(scan_paths)
        self._worker.file_scanned.connect(self._on_file_scanned)
        self._worker.error.connect(self._on_scan_error)
        self._worker.finished.connect(self._on_scan_done)
        self._worker.start()

    def _cancel_scan(self):
        if self._worker:
            self._worker.cancel()
            self._log("SCAN", "Cancelling…")

    # ─────────── Worker signals ───────────
    def _on_file_scanned(self, filepath: str, done: int, total: int,
                         infected: bool, matches: list):
        pct = int(done / total * 100) if total else 100
        self.progress.setValue(pct)
        self.progress_label.setText(f"{done} / {total}")

        if infected:
            self._log("THREAT", f"{filepath}  →  {', '.join(matches)}")
        elif done % 50 == 0:
            # Log clean files only every 50 to keep the output readable
            self._log("OK", filepath)

    def _on_scan_error(self, msg: str):
        self._log("ERROR", msg)
        self._set_ui_scanning(False)

    def _on_scan_done(self, total_scanned: int, threats_found: int):
        if threats_found:
            self._log("DONE", f"⚠  {threats_found} threat(s) found in {total_scanned} file(s).")
        else:
            self._log("DONE", f"✓  Clean — {total_scanned} file(s) scanned, no threats found.")
        self._set_ui_scanning(False)

    # ─────────── UI state ───────────
    def _set_ui_scanning(self, scanning: bool):
        is_custom = self.mode.currentText() == "Custom Scan"
        self.mode.setEnabled(not scanning)
        self.folder_btn.setEnabled(not scanning and is_custom)
        self.files_btn.setEnabled(not scanning and is_custom)
        self.progress.setVisible(scanning)
        self.progress_label.setVisible(scanning)
        self.progress.setValue(0)
        self.progress_label.setText("")

        if scanning:
            self.start_btn.setText("⏹   Cancel")
            self.start_btn.setStyleSheet(BTN_DANGER)
        else:
            self.start_btn.setText("▶   Start Scan")
            self.start_btn.setStyleSheet(BTN_PRIMARY)

    # ─────────── Logging ───────────
    def _log(self, tag: str, msg: str):
        self.log.appendPlainText(f"[{tag}] {msg}")
        self.log.verticalScrollBar().setValue(
            self.log.verticalScrollBar().maximum()
        )