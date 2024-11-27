from __future__ import annotations

from io import BufferedReader
from typing import Any

from mocket.http import (
    MocketHttpEntry,
    MocketHttpMethod,
    MocketHttpRequest as Request,
    MocketHttpResponse,
)
from mocket.mocket import Mocket


class Response(MocketHttpResponse):
    def __init__(
        self,
        body: bytes | str | BufferedReader = b"",
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=status,
            headers=headers,
            body=body,
        )

    @property
    def status(self) -> int:
        return self.status_code


class Entry(MocketHttpEntry):
    CONNECT = MocketHttpMethod.CONNECT
    DELETE = MocketHttpMethod.DELETE
    GET = MocketHttpMethod.GET
    HEAD = MocketHttpMethod.HEAD
    OPTIONS = MocketHttpMethod.OPTIONS
    PATCH = MocketHttpMethod.PATCH
    POST = MocketHttpMethod.POST
    PUT = MocketHttpMethod.PUT
    TRACE = MocketHttpMethod.TRACE

    METHODS = list(MocketHttpMethod)

    def __init__(
        self,
        uri: str,
        method: MocketHttpMethod,
        responses: list[Response | Exception],
        match_querystring: bool = True,
        add_trailing_slash: bool = True,
    ) -> None:
        super().__init__(
            method=method,
            uri=uri,
            responses=responses,
            match_querystring=match_querystring,
            add_trailing_slash=add_trailing_slash,
        )

    @property
    def schema(self) -> str:
        return self.scheme

    @classmethod
    def register(
        cls,
        method: MocketHttpMethod,
        uri: str,
        *responses: Response | Exception,
        **config: Any,
    ) -> None:
        if "body" in config or "status" in config:
            raise AttributeError("Did you mean `Entry.single_register(...)`?")

        if isinstance(config, dict):
            match_querystring = config.get("match_querystring", True)
            add_trailing_slash = config.get("add_trailing_slash", True)

        entry = cls(
            method=method,
            uri=uri,
            responses=list(responses),
            match_querystring=match_querystring,
            add_trailing_slash=add_trailing_slash,
        )
        Mocket.register(entry)

    @classmethod
    def single_register(
        cls,
        method: MocketHttpMethod,
        uri: str,
        body: bytes | str | BufferedReader = b"",
        status: int = 200,
        headers: dict[str, str] | None = None,
        match_querystring: bool = True,
        exception: Exception | None = None,
    ) -> None:
        response: MocketHttpResponse | Exception
        if exception is not None:
            response = exception
        else:
            response = Response(
                body=body,
                status=status,
                headers=headers,
            )

        cls.register(
            method,
            uri,
            response,
            match_querystring=match_querystring,
        )


__all__ = [
    "Entry",
    "Request",
    "Response",
]
