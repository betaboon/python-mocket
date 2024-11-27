from __future__ import annotations

from typing import Any, Sequence

from mocket.types import Address


# TODO maybe we don't need the separation of base vs bytes
class MocketBaseRequest:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(data='{self.data!r}')"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, MocketBaseRequest):
            return other.data == self.data

        if isinstance(other, bytes):
            return other == self.data

        return False

    @property
    def data(self) -> bytes:
        return self._data


class MocketBaseResponse:
    def __init__(self, data: bytes = b"") -> None:
        self._data = data

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(data='{self.data!r}')"

    @property
    def data(self) -> bytes:
        return self._data


class MocketBaseEntry:
    def __init__(
        self,
        location: Address,
        responses: Sequence[MocketBaseResponse | Exception],
    ) -> None:
        self._location = location
        self._responses = responses or [MocketBaseResponse(data=b"")]
        self._served_response = False
        self._current_response_index = 0

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(location={self.location})"

    @property
    def location(self) -> Address:
        return self._location

    @property
    def responses(self) -> Sequence[MocketBaseResponse | Exception]:
        return self._responses

    @property
    def served_response(self) -> bool:
        return self._served_response

    def can_handle(self, data: bytes) -> bool:
        return True

    def get_response(self) -> bytes:
        response = self._responses[self._current_response_index]

        self._served_response = True

        self._current_response_index = min(
            self._current_response_index + 1,
            len(self._responses) - 1,
        )

        if isinstance(response, BaseException):
            raise response

        return response.data


# class MocketBytesRequest(MocketBaseRequest): ...


# class MocketBytesResponse(MocketBaseResponse): ...


# class MocketBytesEntry(MocketBaseEntry):
#     def __init__(
#         self,
#         location: Address,
#         responses: list[MocketBytesResponse | Exception],
#     ) -> None:
#         pass


# NOTE for backward-compat
MocketEntry = MocketBaseEntry
# class MocketEntry(MocketBaseEntry): ...
