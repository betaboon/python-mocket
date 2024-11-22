from __future__ import annotations

import binascii
import contextlib
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from devtools import debug

from mocket.compat import decode_from_bytes, encode_to_bytes
from mocket.types import Address

hash_function = hashlib.md5

with contextlib.suppress(ImportError):
    from xxhash_cffi import xxh32 as xxhash_cffi_xxh32

    hash_function = xxhash_cffi_xxh32

with contextlib.suppress(ImportError):
    from xxhash import xxh32 as xxhash_xxh32

    hash_function = xxhash_xxh32


def _hash_prepare_request(data: bytes) -> bytes:
    _data = decode_from_bytes(data)
    return encode_to_bytes("".join(sorted(_data.split("\r\n"))))


def _hash_request(data: bytes) -> str:
    _data = _hash_prepare_request(data)
    return hash_function(_data).hexdigest()


def _hash_request_fallback(data: bytes) -> str:
    _data = _hash_prepare_request(data)
    return hashlib.md5(_data).hexdigest()


def hexdump(binary_string: bytes) -> str:
    r"""
    >>> hexdump(b"bar foobar foo") == decode_from_bytes(encode_to_bytes("62 61 72 20 66 6F 6F 62 61 72 20 66 6F 6F"))
    True
    """
    bs = decode_from_bytes(binascii.hexlify(binary_string).upper())
    return " ".join(a + b for a, b in zip(bs[::2], bs[1::2]))


def hexload(string: str) -> bytes:
    r"""
    >>> hexload("62 61 72 20 66 6F 6F 62 61 72 20 66 6F 6F") == encode_to_bytes("bar foobar foo")
    True
    """
    string_no_spaces = "".join(string.split())
    return encode_to_bytes(binascii.unhexlify(string_no_spaces))


@dataclass
class MocketRecord:
    host: str
    port: int
    request: bytes
    response: bytes


class MocketRecordStorage:
    def __init__(self, file: Path | None = None) -> None:
        self._file = file
        self._records: defaultdict[Address, defaultdict[str, MocketRecord]]

        self.reset()
        if self._file is not None and self._file.exists():
            self.load(self._file)

    def reset(self) -> None:
        self._records = defaultdict(defaultdict)

    def load(self, file: Path, reset: bool = True) -> None:
        if reset:
            self.reset()

        if not file.exists():
            return

        json_data = file.read_text()
        records = json.loads(json_data)
        for host, port_signature_record in records.items():
            for port, signature_record in port_signature_record.items():
                for signature, record in signature_record.items():
                    # NOTE backward-compat
                    try:
                        request_data = hexload(record["request"])
                    except binascii.Error:
                        request_data = record["request"]

                    self._records[(host, int(port))][signature] = MocketRecord(
                        host=host,
                        port=port,
                        request=request_data,
                        response=hexload(record["response"]),
                    )

    def save(self, file: Path) -> None:
        # FIXME change name and type
        d = defaultdict(lambda: defaultdict(defaultdict))
        for address, signature_record in self._records.items():
            host, port = address
            for signature, record in signature_record.items():
                d[host][str(port)][signature] = dict(
                    request=decode_from_bytes(record.request),
                    response=hexdump(record.response),
                )

        json_data = json.dumps(d, indent=4, sort_keys=True)
        file.parent.mkdir(exist_ok=True)
        file.write_text(json_data)

    def get_records(self, address: Address) -> list[MocketRecord]:
        return list(self._records[address].values())

    def get_record(self, address: Address, request: bytes) -> MocketRecord | None:
        # FIXME encode should not be required
        request = encode_to_bytes(request)

        # NOTE for backward-compat
        request_signature_fallback = _hash_request_fallback(request)
        if request_signature_fallback in self._records[address]:
            return self._records[address].get(request_signature_fallback)

        request_signature = _hash_request(request)
        if request_signature in self._records[address]:
            return self._records[address][request_signature]

        return None

    def put_record(
        self,
        address: Address,
        request: bytes,
        response: bytes,
    ) -> None:
        # FIXME encode should not be required
        request = encode_to_bytes(request)

        host, port = address
        record = MocketRecord(
            host=host,
            port=port,
            request=request,
            response=response,
        )

        # NOTE for backward-compat
        request_signature_fallback = _hash_request_fallback(request)
        if request_signature_fallback in self._records[address]:
            self._records[address][request_signature_fallback] = record
            return

        request_signature = _hash_request(request)
        self._records[address][request_signature] = record

        if self._file is not None:
            self.save(file=self._file)
