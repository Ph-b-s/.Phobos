"""Single outbound HTTP request boundary for Phobos."""

from __future__ import annotations

from dataclasses import dataclass
from http.client import HTTPResponse
from urllib.error import HTTPError, HTTPRedirectHandler, URLError
from urllib.parse import urljoin
from urllib.request import Request, build_opener

from .scope import ScopeError, ScopeValidator


class RequestError(RuntimeError):
    """Raised when an HTTP request cannot be completed safely."""


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from following redirects before Phobos validates them."""

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    def http_error_303(self, req, fp, code, msg, headers):
        return fp

    def http_error_307(self, req, fp, code, msg, headers):
        return fp

    def http_error_308(self, req, fp, code, msg, headers):
        return fp


@dataclass(frozen=True, slots=True)
class HTTPResponseData:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in content_type.lower():
            charset = content_type.lower().split("charset=", 1)[1].split(";", 1)[0].strip() or charset
        return self.body.decode(charset, errors="replace")


class RequestManager:
    """Owns HTTP traffic and enforces scope before every network hop."""

    def __init__(
        self,
        scope: ScopeValidator,
        *,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = "Phobos/0.1",
        max_response_bytes: int = 2_000_000,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.max_response_bytes = max_response_bytes
        self._opener = build_opener(_NoRedirectHandler())

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HTTPResponseData:
        return self.request("GET", url, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> HTTPResponseData:
        current_url = self._validate(url)
        merged_headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if headers:
            merged_headers.update(headers)

        for redirect_count in range(self.max_redirects + 1):
            request = Request(current_url, data=body, method=method.upper(), headers=merged_headers)
            try:
                response = self._opener.open(request, timeout=self.timeout)
            except HTTPError as exc:
                response = exc
            except URLError as exc:
                raise RequestError(f"request failed for {current_url}: {exc.reason}") from exc
            except TimeoutError as exc:
                raise RequestError(f"request timed out for {current_url}") from exc

            status = getattr(response, "status", response.getcode())
            location = response.headers.get("Location")
            final_url = self._validate(response.geturl())

            if location and status in {301, 302, 303, 307, 308}:
                if redirect_count >= self.max_redirects:
                    raise RequestError(f"maximum redirects exceeded for {url}")
                next_url = self._validate(urljoin(final_url, location))
                current_url = next_url
                if status == 303 or (status in {301, 302} and method.upper() == "POST"):
                    method = "GET"
                    body = None
                continue

            data = self._read_limited(response)
            return HTTPResponseData(
                url=final_url,
                status=status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=data,
            )

        raise RequestError(f"maximum redirects exceeded for {url}")

    def _validate(self, url: str) -> str:
        try:
            return self.scope.validate(url)
        except ScopeError as exc:
            raise RequestError(str(exc)) from exc

    def _read_limited(self, response: HTTPResponse) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length and content_length.isdigit() and int(content_length) > self.max_response_bytes:
            raise RequestError("response exceeds configured size limit")

        chunks: list[bytes] = []
        remaining = self.max_response_bytes
        while remaining:
            chunk = response.read(min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            extra = response.read(1)
            if extra:
                raise RequestError("response exceeds configured size limit")
        return b"".join(chunks)
