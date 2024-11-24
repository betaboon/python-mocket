from asyncio.sslproto import SSLProtocol
from typing import Any

from devtools import debug

from mocket.ssl.context import MocketSSLContext


class MocketSSLProtocol(SSLProtocol):
    # def __init__(self, *args: Any, **kwargs: Any) -> None:
    #     debug("SSLPROTOCOL INIT", args, kwargs)
    #     super().__init__(*args, **kwargs)
    #     # debug(self.__dict__)
    #     # sslcontext: MocketSSLContext = self._sslcontext
    #     # debug(sslcontext._sslprotocol_sockets)
    #     # sslcontext._sslprotocol_sockets[id(self)] = None
    #     # sslobj = self._sslobj
    #     # debug(sslobj)
    #     # app_transport = self._app_transport

    #     # debug(app_transport.__dict__)

    def connection_made(self, transport):
        debug("CONNECTION MADE")
        if isinstance(self._sslcontext, MocketSSLContext):
            sock = transport._sock
            sslcontext = self._sslcontext
            sslcontext._sslprotocol_sockets[self._server_hostname] = sock
        super().connection_made(transport)
        debug("POST CONNECTION MADE")
