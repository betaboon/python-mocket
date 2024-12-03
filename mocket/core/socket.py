from __future__ import annotations

import _socket
import contextlib
import errno
import os
import select
import socket
from types import TracebackType
from typing import Any, Type

from typing_extensions import Self

from mocket.core.entry import MocketBaseEntry
from mocket.core.io import MocketSocketIO
from mocket.core.mocket import Mocket
from mocket.core.mode import MocketMode
from mocket.core.types import (
    Address,
    WriteableBuffer,
    _Address,
    _RetAddress,
)

true_gethostbyname = socket.gethostbyname
true_socket = socket.socket

DEFAULT_ADDRESS = ("0.0.0.0", 0)


def mock_create_connection(
    address: Address,
    timeout: float | None = None,
    source_address: _Address | None = None,
) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    if timeout:
        s.settimeout(timeout)
    s.connect(address)
    return s


def mock_getaddrinfo(
    host: str,
    port: int,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    return [(2, 1, 6, "", (host, port))]


def mock_gethostbyname(hostname: str) -> str:
    return "127.0.0.1"


def mock_gethostname() -> str:
    return "localhost"


def mock_inet_pton(address_family: int, ip_string: str) -> bytes:
    return bytes("\x7f\x00\x00\x01", "utf-8")


def mock_socketpair(*args: Any, **kwargs: Any) -> tuple[_socket.socket, _socket.socket]:
    """Returns a real socketpair() used by asyncio loop for supporting calls made by fastapi and similar services."""

    return _socket.socketpair(*args, **kwargs)


class MocketSocket:
    def __init__(
        self,
        family: socket.AddressFamily | int = socket.AF_INET,
        type: socket.SocketKind | int = socket.SOCK_STREAM,
        proto: int = 0,
        fileno: int | None = None,
        **kwargs: Any,
    ) -> None:
        self._family = family
        self._type = type
        self._proto = proto

        self._kwargs = kwargs
        self._true_socket = true_socket(family, type, proto)

        self._buflen = 65536
        self._timeout: float | None = None

        self._address: Address = DEFAULT_ADDRESS

        self._io: MocketSocketIO | None = None
        self._entry: MocketBaseEntry | None = None

    def __str__(self) -> str:
        return f"({self.__class__.__name__})(family={self.family} type={self.type} protocol={self.proto})"

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        type_: Type[BaseException] | None,  # noqa: UP006
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def family(self) -> int:
        return self._family

    @property
    def type(self) -> int:
        return self._type

    @property
    def proto(self) -> int:
        return self._proto

    @property
    def io(self) -> MocketSocketIO:
        if self._io is None:
            self._io = MocketSocketIO(self._address)
        return self._io

    def fileno(self) -> int:
        r_fd, _ = Mocket.get_pair(self._address)
        if not r_fd:
            r_fd, w_fd = os.pipe()
            Mocket.set_pair(self._address, (r_fd, w_fd))
        return r_fd

    def gettimeout(self) -> float | None:
        return self._timeout

    # FIXME the arguments here seem wrong. they should be `level: int, optname: int, value: int | ReadableBuffer | None`
    def setsockopt(self, family: int, type: int, proto: int) -> None:
        self._family = family
        self._type = type
        self._proto = proto

        if self._true_socket:
            self._true_socket.setsockopt(family, type, proto)

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout

    @staticmethod
    def getsockopt(level: int, optname: int, buflen: int | None = None) -> int:
        return socket.SOCK_STREAM

    def getpeername(self) -> _RetAddress:
        return self._address

    def setblocking(self, block: bool) -> None:
        self.settimeout(None) if block else self.settimeout(0.0)

    def getblocking(self) -> bool:
        return self.gettimeout() is None

    def getsockname(self) -> _RetAddress:
        host, port = self._address
        return true_gethostbyname(host), port

    def connect(self, address: Address) -> None:
        self._address = address
        Mocket._address = address

    def makefile(self, mode: str = "r", bufsize: int = -1) -> MocketSocketIO:
        return self.io

    def get_entry(self, data: bytes) -> MocketBaseEntry | None:
        host, port = self._address
        return Mocket.get_entry(host, port, data)

    def sendall(
        self,
        data: bytes,
        entry: MocketBaseEntry | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if entry is None:
            entry = self.get_entry(data)

        if entry:
            consume_response = entry.collect(data)
            response = entry.get_response() if consume_response is not False else None
        else:
            response = self.true_sendall(data, *args, **kwargs)

        if response is not None:
            self.io.seek(0)
            self.io.write(response)
            self.io.truncate()
            self.io.seek(0)

    def recv_into(
        self,
        buffer: WriteableBuffer,
        buffersize: int | None = None,
        flags: int | None = None,
    ) -> int:
        if hasattr(buffer, "write"):
            return buffer.write(self.recv(buffersize))  # type: ignore

        # buffer is a memoryview
        if buffersize is None:
            buffersize = len(buffer)  # type: ignore

        data = self.recv(buffersize)
        if data:
            buffer[: len(data)] = data  # type: ignore
        return len(data)

    def recv(self, buffersize: int, flags: int | None = None) -> bytes:
        r_fd, _ = Mocket.get_pair(self._address)
        if r_fd:
            return os.read(r_fd, buffersize)
        data = self.io.read(buffersize)
        if data:
            return data
        # used by Redis mock
        exc = BlockingIOError()
        exc.errno = errno.EWOULDBLOCK
        exc.args = (0,)
        raise exc

    def true_sendall(self, data: bytes, *args: Any, **kwargs: Any) -> bytes:
        if not MocketMode().is_allowed(self._address):
            MocketMode.raise_not_allowed()

        # try to get the response from recordings
        if Mocket._record_storage:
            record = Mocket._record_storage.get_record(
                address=self._address,
                request=data,
            )
            if record is not None:
                return record.response

        host, port = self._address
        host = true_gethostbyname(host)

        with contextlib.suppress(OSError, ValueError):
            # already connected
            self._true_socket.connect((host, port))

        self._true_socket.sendall(data, *args, **kwargs)
        response = b""
        # https://github.com/kennethreitz/requests/blob/master/tests/testserver/server.py#L12
        while True:
            more_to_read = select.select([self._true_socket], [], [], 0.1)[0]
            if not more_to_read and response:
                break
            new_content = self._true_socket.recv(self._buflen)
            if not new_content:
                break
            response += new_content

        # store request+response in recordings
        if Mocket._record_storage:
            Mocket._record_storage.put_record(
                address=self._address,
                request=data,
                response=response,
            )

        return response

    def send(
        self,
        data: bytes,
        *args: Any,
        **kwargs: Any,
    ) -> int:  # pragma: no cover
        entry = self.get_entry(data)
        if not entry or (entry and self._entry != entry):
            kwargs["entry"] = entry
            self.sendall(data, *args, **kwargs)
        else:
            req = Mocket.last_request()
            if req and hasattr(req, "_add_data"):
                req._add_data(data)
        self._entry = entry
        return len(data)

    def close(self) -> None:
        if self._true_socket and self._true_socket.fileno():
            self._true_socket.close()

    def __getattr__(self, name: str) -> Any:
        """Do nothing catchall function, for methods like shutdown()"""

        def do_nothing(*args: Any, **kwargs: Any) -> Any:
            pass

        return do_nothing
