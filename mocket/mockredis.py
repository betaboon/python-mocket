from itertools import chain

from .compat import byte_type, decode_from_bytes, encode_to_bytes, shsplit, text_type
from .mocket import Mocket, MocketEntry


class Request:
    def __init__(self, data):
        self.data = data


class Response:
    def __init__(self, data=None):
        self.data = Redisizer.redisize(data or OK)


class Redisizer(byte_type):
    @staticmethod
    def tokens(iterable):
        iterable = [encode_to_bytes(x) for x in iterable]
        return [f"*{len(iterable)}".encode()] + list(
            chain(*zip([f"${len(x)}".encode() for x in iterable], iterable))
        )

    @staticmethod
    def redisize(data):
        def get_conversion(t):
            return {
                dict: lambda x: b"\r\n".join(
                    Redisizer.tokens(list(chain(*tuple(x.items()))))
                ),
                int: lambda x: f":{x}".encode(),
                text_type: lambda x: "${}\r\n{}".format(
                    len(x.encode("utf-8")), x
                ).encode("utf-8"),
                list: lambda x: b"\r\n".join(Redisizer.tokens(x)),
            }[t]

        if isinstance(data, Redisizer):
            return data
        if isinstance(data, byte_type):
            data = decode_from_bytes(data)
        return Redisizer(get_conversion(data.__class__)(data) + b"\r\n")

    @staticmethod
    def command(description, _type="+"):
        return Redisizer("{}{}{}".format(_type, description, "\r\n").encode("utf-8"))

    @staticmethod
    def error(description):
        return Redisizer.command(description, _type="-")


OK = Redisizer.command("OK")
QUEUED = Redisizer.command("QUEUED")
ERROR = Redisizer.error


class Entry(MocketEntry):
    request_cls = Request
    response_cls = Response

    def __init__(self, addr, command, responses):
        super().__init__(addr or ("localhost", 6379), responses)
        d = shsplit(command)
        d[0] = d[0].upper()
        self.command = Redisizer.tokens(d)

    def can_handle(self, data):
        return data.splitlines() == self.command

    @classmethod
    def register(cls, addr, command, *responses):
        responses = [
            r if isinstance(r, BaseException) else cls.response_cls(r)
            for r in responses
        ]
        Mocket.register(cls(addr, command, responses))

    @classmethod
    def register_response(cls, command, response, addr=None):
        cls.register(addr, command, response)

    @classmethod
    def register_responses(cls, command, responses, addr=None):
        cls.register(addr, command, *responses)
