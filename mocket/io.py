import io
import os

from devtools import debug

from mocket.mocket import Mocket


class MocketSocketIO(io.BytesIO):
    def __init__(self, address) -> None:
        self._address = address
        super().__init__()

    def write(self, content):
        debug("writing IO", self._address)
        super().write(content)

        _, w_fd = Mocket.get_pair(self._address)
        if w_fd:
            debug("writing FD", self._address, w_fd)
            os.write(w_fd, content)
