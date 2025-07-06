"""Mocked requests library."""

import json
from typing import Callable

import requests

from libdyson.cloud.account import DYSON_API_HEADERS, DYSON_API_HOST, DYSON_API_HOST_CN


class MockedRequests:
    """Mocked requests library."""

    def __init__(self):
        """Initialize the mock."""
        self.host = DYSON_API_HOST
        self._handlers = {}

    @property
    def country(self) -> str:
        """Return the country."""
        return self._country

    def register_handler(self, method: str, path: str, handler: Callable) -> None:
        """Register request handler."""
        self._handlers[(method, path)] = handler

    def request(
        self, method: str, url: str, headers=None, verify=True, **kwargs
    ) -> requests.Response:
        """Run mocked request function."""
        assert headers == DYSON_API_HEADERS
        # Support both regular and China API hosts
        assert url.startswith(self.host) or url.startswith(DYSON_API_HOST_CN)
        # Use the appropriate host for path extraction
        host_to_use = self.host if url.startswith(self.host) else DYSON_API_HOST_CN
        path = url[len(host_to_use) :]
        response = requests.Response()
        if not (method, path) in self._handlers:
            response.status_code = 404
            return response
        try:
            status_code, payload = self._handlers[(method, path)](**kwargs)
            response.status_code = status_code
            if isinstance(payload, bytes):
                response._content = payload
            elif payload is not None:
                response.encoding = "utf-8"
                content = json.dumps(payload).encode("utf-8")
                response._content = content
            return response
        except Exception as e:
            # Allow handlers to raise exceptions - they should be caught by the calling code
            raise e
