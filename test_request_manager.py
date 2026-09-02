"""Tests for the single outbound HTTP boundary."""
from __future__ import annotations

import pytest

from request_manager import HTTPResponseData, RequestError, RequestManager
from scope import ScopeValidator


class FakeHTTPResponse:
    def __init__(self, url: str, status: int, headers: dict[str, str], body: bytes):
        self._url = url
        self.status = status
        self.headers = headers
        self._body = body
        self.closed = False

    def getcode(self):
        return self.status

    def geturl(self):
        return self._url

    def read(self, size: int = -1):
        if size < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:size], self._body[size:]
        return data

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return next(self.responses)


def test_request_manager_reads_response_and_closes_resource():
    response = FakeHTTPResponse(
        "https://example.com/",
        200,
        {"Content-Type": "text/html; charset=utf-8"},
        b"hello",
    )
    manager = RequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
    )
    opener = FakeOpener([response])
    manager._opener = opener

    result = manager.get("https://example.com/")
    assert result == HTTPResponseData(
        "https://example.com/",
        200,
        {"content-type": "text/html; charset=utf-8"},
        b"hello",
    )
    assert result.text == "hello"
    assert response.closed is True


def test_request_manager_follows_in_scope_redirect():
    first = FakeHTTPResponse(
        "https://example.com/",
        302,
        {"Location": "/next"},
        b"",
    )
    second = FakeHTTPResponse(
        "https://example.com/next",
        200,
        {"Content-Type": "text/plain"},
        b"ok",
    )
    manager = RequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
    )
    manager._opener = FakeOpener([first, second])
    result = manager.get("https://example.com/")
    assert result.url == "https://example.com/next"
    assert result.body == b"ok"


def test_request_manager_blocks_out_of_scope_redirect():
    first = FakeHTTPResponse(
        "https://example.com/",
        302,
        {"Location": "https://evil.example/"},
        b"",
    )
    manager = RequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
    )
    manager._opener = FakeOpener([first])
    with pytest.raises(RequestError, match="out-of-scope"):
        manager.get("https://example.com/")


def test_request_manager_enforces_body_size_limit():
    response = FakeHTTPResponse(
        "https://example.com/",
        200,
        {"Content-Type": "text/plain", "Content-Length": "6"},
        b"123456",
    )
    manager = RequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
        max_response_bytes=5,
    )
    manager._opener = FakeOpener([response])
    with pytest.raises(RequestError, match="size limit"):
        manager.get("https://example.com/")
    assert response.closed is True


def test_request_manager_reset_session_clears_cookie_jar():
    manager = RequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
    )
    manager._cookie_jar.set_cookie_next(None)
    assert len(manager._cookie_jar) == 0
    manager.reset_session()
    assert len(manager._cookie_jar) == 0


def test_request_manager_rejects_invalid_configuration():
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    with pytest.raises(ValueError, match="timeout"):
        RequestManager(scope, timeout=0)
    with pytest.raises(ValueError, match="max_redirects"):
        RequestManager(scope, max_redirects=21)
