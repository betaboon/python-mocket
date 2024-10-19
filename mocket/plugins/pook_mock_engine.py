try:
    from pook.engine import MockEngine
except ModuleNotFoundError:
    MockEngine = object

from mocket.mocket import Mocket
from mocket.mockhttp import Entry, Response


class MocketPookEntry(Entry):
    pook_request = None
    pook_engine = None

    def can_handle(self, data):
        can_handle = super().can_handle(data)

        if can_handle:
            self.pook_engine.match(self.pook_request)
        return can_handle

    @classmethod
    def single_register(
        cls,
        method,
        uri,
        body="",
        status=200,
        headers=None,
        match_querystring=True,
        exception=None,
    ):
        entry = cls(
            uri,
            method,
            [Response(body=body, status=status, headers=headers)],
            match_querystring=match_querystring,
        )
        Mocket.register(entry)
        return entry


class MocketEngine(MockEngine):
    def __init__(self, engine):
        def mocket_mock_fun(*args, **kwargs):
            mock = self.pook_mock_fun(*args, **kwargs)

            request = mock._request
            method = request.method
            url = request.rawurl

            response = mock._response
            body = response._body
            status = response._status
            headers = response._headers

            entry = MocketPookEntry.single_register(method, url, body, status, headers)
            entry.pook_engine = self.engine
            entry.pook_request = request

            return mock

        from pook.interceptors.base import BaseInterceptor

        class MocketInterceptor(BaseInterceptor):
            @staticmethod
            def activate():
                Mocket.disable()
                Mocket.enable()

            @staticmethod
            def disable():
                Mocket.disable()

        # Store plugins engine
        self.engine = engine
        # Store HTTP client interceptors
        self.interceptors = []
        # Self-register MocketInterceptor
        self.add_interceptor(MocketInterceptor)

        # mocking pook.mock()
        self.pook_mock_fun = self.engine.mock
        self.engine.mock = mocket_mock_fun
