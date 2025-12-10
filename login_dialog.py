from PyQt5 import QtWidgets

from ..core.auth import AuthService
from ..core.models import User


class LoginDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setModal(True)
        self.resize(360, 180)
        self._auth = AuthService()
        self._authenticated_user: User | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)

        form = QtWidgets.QFormLayout()
        self.username = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)

        form.addRow("Username", self.username)
        form.addRow("Password", self.password)

        self.error_label = QtWidgets.QLabel("")
        self.error_label.setStyleSheet("color: red;")

        btns = QtWidgets.QDialogButtonBox()
        btns.setStandardButtons(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_login)
        btns.rejected.connect(self.reject)

        layout.addLayout(form)
        layout.addWidget(self.error_label)
        layout.addWidget(btns)

    def _on_login(self) -> None:
        username = self.username.text().strip()
        password = self.password.text()
        user = self._auth.authenticate(username, password)
        if user is None:
            self.error_label.setText("Invalid credentials")
            return
        self._authenticated_user = user
        self.accept()

    def get_authenticated_user(self) -> User:
        assert self._authenticated_user is not None
        return self._authenticated_user


