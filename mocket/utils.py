from __future__ import annotations

import ssl
from typing import Callable

from mocket.compat import decode_from_bytes, encode_to_bytes

# NOTE this is here for backwards-compat to keep old import-paths working
from mocket.io import MocketSocketIO as MocketSocketCore

# NOTE this is here for backwards-compat to keep old import-paths working
from mocket.mode import MocketMode

SSL_PROTOCOL = ssl.PROTOCOL_TLSv1_2


def get_mocketize(wrapper_: Callable) -> Callable:
    import decorator

    if decorator.__version__ < "5":  # type: ignore[attr-defined] # pragma: no cover
        return decorator.decorator(wrapper_)
    return decorator.decorator(  # type: ignore[call-arg] # kwsyntax
        wrapper_,
        kwsyntax=True,
    )


__all__ = (
    "MocketSocketCore",
    "MocketMode",
    "SSL_PROTOCOL",
    "hexdump",
    "hexload",
    "get_mocketize",
)
