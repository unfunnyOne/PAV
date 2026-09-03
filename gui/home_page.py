from pathlib import Path
from core import engine
from core import updater

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QPlainTextEdit, QFileDialog
)

class PathSelection(QWidget):
    def __init__(self):
        super().__init__()

        self.pathbox = QLineEdit()
        self.pathbox.setReadOnly(True)

        self.selectbutton = QPushButton("Browse")

        self.selectbutton.clicked.connect(self.selectPath)

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.pathbox)
        self.layout.addWidget(self.selectbutton)
        self.setLayout(self.layout)

    def getPath(self):
        return self.pathbox.text()

    def selectPath(self):
        path = QFileDialog.getExistingDirectory(self, "Select a directory")
        if not path: return
        self.pathbox.setText(path)

class ScanWorker(QObject):
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, path, shownegatives):
        super().__init__()
        self.path = path
        self.shownegatives = shownegatives

    def run(self):
        self.log.emit("Loading the configuration...")
        success, message = engine.loadConfig()
        self.log.emit(f"{message}\n")
        self.log.emit("Updating the rules...\n")
        success, message = updater.updateRules()
        self.log.emit(f"{message}\n")
        self.log.emit("Compiling the rules...\n")

        success, message = engine.compileRules()
        self.log.emit(f"{message}\n")

        if not success:
            self.finished.emit()
            return

        for result, idx, total in engine.scanPath(self.path, True):
            if result.infected:
                self.log.emit(f"({idx}/{total}) {result.filepath}: {result.infected}. Matches:")

                for match in result.matches:
                    self.log.emit(f"{match}")

                self.log.emit(f"Total risk score: {result.riskscore}\n")

            elif self.shownegatives:
                self.log.emit(f"({idx}/{total}) {result.filepath}: {result.infected}\nTotal risk score: {result.riskscore}\n")

        self.finished.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None

        self.setWindowTitle("PAV Testing")

        self.pathselectionframe = PathSelection()
        self.startbutton = QPushButton("Start")
        self.outputfield = QPlainTextEdit()

        self.outputfield.setReadOnly(True)
        self.startbutton.clicked.connect(lambda: self.startScan(True))

        layout = QVBoxLayout()
        layout.addWidget(self.pathselectionframe)
        layout.addWidget(self.startbutton)
        layout.addWidget(self.outputfield)

        mainFrame = QWidget()
        mainFrame.setLayout(layout)
        self.setCentralWidget(mainFrame)

    def appendLog(self, text):
        self.outputfield.appendPlainText(text)

    def startScan(self, shownegatives: bool = False):
        if self.thread and self.thread.isRunning():
            return

        path = Path(self.pathselectionframe.getPath())

        self.thread = QThread()
        self.worker = ScanWorker(path, shownegatives)

        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.log.connect(self.appendLog)
        self.worker.finished.connect(self.thread.quit)

        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()