"""Tests for the single outbound HTTP boundary."""
from __future__ import annotations

import pytest

from request_manager import HTTPResponseData, RequestError, RequestManager
from scope import ScopeValidator


class FakeHTTPResponse:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self._headers = headers
        self._body = body
        self.closed = False

    def getheader(self, name: str, default=None):
        for key, value in self._headers:
            if key.lower() == name.lower():
                return value
        return default

    def getheaders(self):
        return list(self._headers)

    def read(self, size: int = -1):
        if size < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:size], self._body[size:]
        return data

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        return next(self.responses)

    def close(self):
        self.closed = True


def _manager(monkeypatch, responses, *, allow_private=True):
    manager = RequestManager(
        ScopeValidator(("example.com",), allow_private_targets=allow_private),
    )
    connection = FakeConnection(responses)
    monkeypatch.setattr(manager, "_resolve_pinned", lambda url: (__import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(url), "203.0.113.10"))
    monkeypatch.setattr(manager, "_connection", lambda parsed, resolved_ip: connection)
    return manager, connection


def test_request_manager_reads_response_and_closes_resource(monkeypatch):
    response = FakeHTTPResponse(
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        b"hello",
    )
    manager, connection = _manager(monkeypatch, [response])

    result = manager.get("https://example.com/")
    assert result == HTTPResponseData(
        "https://example.com/",
        200,
        {"content-type": "text/html; charset=utf-8"},
        b"hello",
    )
    assert result.text == "hello"
    assert response.closed is True
    assert connection.closed is True


def test_request_manager_follows_in_scope_redirect(monkeypatch):
    first = FakeHTTPResponse(302, [("Location", "/next")], b"")
    second = FakeHTTPResponse(200, [("Content-Type", "text/plain")], b"ok")
    manager, connection = _manager(monkeypatch, [first, second])

    result = manager.get("https://example.com/")
    assert result.url == "https://example.com/next"
    assert result.body == b"ok"
    assert [item[1] for item in connection.requests] == ["/", "/next"]


def test_request_manager_blocks_out_of_scope_redirect(monkeypatch):
    first = FakeHTTPResponse(302, [("Location", "https://evil.example/")], b"")
    manager, _ = _manager(monkeypatch, [first])

    with pytest.raises(RequestError, match="out-of-scope"):
        manager.get("https://example.com/")


def test_request_manager_enforces_body_size_limit(monkeypatch):
    response = FakeHTTPResponse(
        200,
        [("Content-Type", "text/plain"), ("Content-Length", "6")],
        b"123456",
    )
    manager, _ = _manager(monkeypatch, [response])
    manager.max_response_bytes = 5

    with pytest.raises(RequestError, match="size limit"):
        manager.get("https://example.com/")
    assert response.closed is True


def test_request_manager_carries_session_cookie_across_requests(monkeypatch):
    first = FakeHTTPResponse(200, [("Set-Cookie", "session=abc; Path=/")], b"ok")
    second = FakeHTTPResponse(200, [], b"ok")
    manager, connection = _manager(monkeypatch, [first, second])

    manager.get("https://example.com/login")
    manager.get("https://example.com/account")
    assert connection.requests[0][3].get("Cookie") is None
    assert connection.requests[1][3]["Cookie"] == "session=abc"


def test_request_manager_reset_session_clears_cookies(monkeypatch):
    first = FakeHTTPResponse(200, [("Set-Cookie", "session=abc; Path=/")], b"ok")
    second = FakeHTTPResponse(200, [], b"ok")
    manager, connection = _manager(monkeypatch, [first, second])

    manager.get("https://example.com/login")
    manager.reset_session()
    manager.get("https://example.com/account")
    assert connection.requests[1][3].get("Cookie") is None


def test_request_manager_uses_pinned_ip_and_original_host(monkeypatch):
    response = FakeHTTPResponse(200, [], b"ok")
    manager, connection = _manager(monkeypatch, [response])
    manager.get("https://example.com:8443/path?x=1")
    method, path, _, headers = connection.requests[0]
    assert method == "GET"
    assert path == "/path?x=1"
    assert headers["Host"] == "example.com:8443"


def test_request_manager_rejects_invalid_configuration():
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    with pytest.raises(ValueError, match="timeout"):
        RequestManager(scope, timeout=0)
    with pytest.raises(ValueError, match="max_redirects"):
        RequestManager(scope, max_redirects=21)
