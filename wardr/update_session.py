"""Serialize Wardr package changes and serve desktop update state."""

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import threading

from . import updater
from .state import BusyError


@contextmanager
def installation_lock():
    """Use one OS-released lock for all Wardr processes in this environment."""
    if problem := updater.installation_problem():
        raise updater.UpdaterError(problem)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(Path(sys.prefix) / ".wardr-update.lock", flags, 0o600)
    except OSError as exc:
        raise updater.UpdaterError("Wardr could not lock its installation for an update.") from exc
    try:
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise updater.UpdaterError("Another Wardr process is updating this installation.") from exc
        yield
    finally:
        os.close(fd)


class UpdateSession:
    """Keep a running dashboard's version separate from installed wheel metadata."""

    def __init__(self, offline: bool, blocker: str | None = None):
        self.current = updater.current_version()
        self.blocker = "Updates are disabled in offline mode." if offline else updater.installation_problem() or blocker
        self.state = "unavailable" if self.blocker else "idle"
        self.message = self.blocker or "Check getwardr.com for a signed Wardr release."
        self.available = None
        self.installed = None
        self.restart_requested = False
        self._lock = threading.Lock()

    def status(self) -> dict:
        with self._lock:
            return {
                "state": self.state,
                "current_version": self.current,
                "available_version": self.available.version if self.available else None,
                "installed_version": self.installed,
                "message": self.message,
                "can_check": not self.blocker and self.state in ("idle", "current", "available", "error"),
                "can_update": self.state == "available",
                "can_restart": self.state == "installed",
            }

    def start_check(self) -> None:
        with self._lock:
            if self.blocker:
                raise updater.UpdaterError(self.blocker)
            if self.state not in ("idle", "current", "available", "error"):
                raise BusyError("An update action is already in progress or ready to restart.")
            self.available = None
            self.state = "checking"
            self.message = "Checking for a signed Wardr release."
        threading.Thread(target=self._check, name="wardr-update-check", daemon=True).start()

    def _check(self) -> None:
        try:
            with installation_lock():
                installed = updater.current_version()
                if installed != self.current:
                    self._record_installed(installed)
                    return
                available = updater.check_for_update()
        except updater.UpdaterError as exc:
            self._error(str(exc))
            return
        except OSError:
            self._error("Wardr could not check the official release. Try again.")
            return
        with self._lock:
            self.available = available
            self.state = "available" if available else "current"
            self.message = (
                f"Wardr {available.version} is available from the signed release channel."
                if available else "Your Wardr installation is up to date."
            )

    def start_install(self, version: str) -> None:
        with self._lock:
            if self.blocker:
                raise updater.UpdaterError(self.blocker)
            if self.state in ("checking", "installing", "restarting"):
                raise BusyError("An update action is already in progress.")
            available = self.available
            if self.state != "available" or available is None or available.version != version:
                raise ValueError("Check for updates before installing the requested version.")
            self.state = "installing"
            self.message = f"Downloading, verifying, and installing Wardr {available.version}."
        threading.Thread(target=self._install, args=(available,), name="wardr-update-install").start()

    def _install(self, available) -> None:
        try:
            with installation_lock():
                installed = updater.current_version()
                if installed == self.current:
                    installed = updater.install_update(available)
                elif installed != available.version:
                    raise updater.UpdaterError("The installed version changed. Restart Wardr and check again.")
            self._record_installed(installed)
        except updater.UpdaterError as exc:
            self._error(str(exc))
        except OSError:
            self._error("Wardr could not complete the update. Check the installation before trying again.")

    def _record_installed(self, version: str) -> None:
        with self._lock:
            self.available = None
            self.installed = version
            self.state = "installed"
            self.message = f"Wardr {version} is ready. Restart Wardr to use it."

    def _error(self, message: str) -> None:
        with self._lock:
            self.available = None
            self.state = "error"
            self.message = message

    def request_restart(self) -> None:
        with self._lock:
            if self.state != "installed":
                raise ValueError("Install an update before restarting Wardr here.")
            self.restart_requested = True
            self.state = "restarting"
            self.message = "Wardr is restarting. Open the new dashboard link."
