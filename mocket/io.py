from __future__ import annotations

import io
import os

from devtools import debug


class MocketSocketIO(io.BytesIO):
    def __init__(self, address) -> None:
        super().__init__()
        self._address = address
        self._fd_pair: tuple[int, int] | None = None

    def get_fd_pair(self) -> tuple[int, int]:
        if self._fd_pair is None:
            self._fd_pair = os.pipe()
        return self._fd_pair

    def write(self, content):
        debug("writing IO", self._address)
        super().write(content)

        # _, w_fd = Mocket.get_pair(self._address)
        # self._r_fd, self._w_fd = Mocket.get_pair(self._address)
        if self._fd_pair is not None:
            _, w_fd = self._fd_pair
            debug("writing FD", self._address, w_fd)
            os.write(w_fd, content)
