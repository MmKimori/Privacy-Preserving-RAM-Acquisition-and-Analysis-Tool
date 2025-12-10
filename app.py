import sys
from PyQt5 import QtWidgets

from .ui.main_window import MainWindow
from .ui.login_dialog import LoginDialog


def _ensure_admin_privileges() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        if shell32.IsUserAnAdmin():
            return
        params = "-m ram_acq.app"
        result = shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if result <= 32:
            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                None,
                "Administrator privileges are required to capture physical memory.\n"
                "Please rerun the application as an administrator.",
                "RAM Acquisition Tool",
                0,
            )
            sys.exit(1)
        sys.exit(0)
    except Exception:
        # If elevation fails unexpectedly, continue without exiting so the user can see the error.
        pass


def main() -> None:
    _ensure_admin_privileges()
    app = QtWidgets.QApplication(sys.argv)

    login_dialog = LoginDialog()
    if login_dialog.exec_() != QtWidgets.QDialog.Accepted:
        sys.exit(0)

    user = login_dialog.get_authenticated_user()
    window = MainWindow(current_user=user)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()


