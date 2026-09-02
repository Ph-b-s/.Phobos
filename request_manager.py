"""Single outbound HTTP boundary with scope-aware redirects and size limits."""
from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import (
    HTTPRedirectHandler,
    HTTPCookieProcessor,
    Request,
    build_opener,
)

from scope import ScopeError, ScopeValidator


PHOBOS_HTTP_USER_AGENT = "Phobos/0.3.1"


class RequestError(RuntimeError):
    """Raised when an outbound HTTP request cannot be completed safely."""


class _NoRedirectHandler(HTTPRedirectHandler):
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
        for part in content_type.split(";"):
            if part.strip().lower().startswith("charset="):
                candidate = part.split("=", 1)[1].strip().strip('"')
                if candidate:
                    charset = candidate
                break
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class RequestManager:
    """The only component allowed to make outbound HTTP requests.

    A manager owns one bounded cookie jar, allowing authenticated multi-request
    assessment flows without exposing a global session. ``reset_session``
    explicitly clears that state between identities or test runs.
    """

    def __init__(
        self,
        scope: ScopeValidator,
        *,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = PHOBOS_HTTP_USER_AGENT,
        max_response_bytes: int = 2_000_000,
    ):
        if timeout <= 0:
            raise ValueError("HTTP timeout must be positive")
        if not 0 <= max_redirects <= 20:
            raise ValueError("max_redirects must be between 0 and 20")
        if not user_agent.strip():
            raise ValueError("user_agent must not be empty")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.scope = scope
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.max_response_bytes = max_response_bytes
        self._cookie_jar = CookieJar()
        self._opener = self._build_opener()

    def _build_opener(self):
        return build_opener(
            _NoRedirectHandler(),
            HTTPCookieProcessor(self._cookie_jar),
        )

    def reset_session(self) -> None:
        """Clear authentication/session cookies while keeping transport settings."""
        self._cookie_jar.clear()

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
        method = method.strip().upper()
        if not method or not method.isalpha():
            raise RequestError("HTTP method must be alphabetic")
        if body is not None and not isinstance(body, bytes):
            raise RequestError("HTTP request body must be bytes")

        current = self._validate(url)
        merged = {"User-Agent": self.user_agent, "Accept": "*/*"}
        merged.update(headers or {})

        for count in range(self.max_redirects + 1):
            request = Request(current, data=body, method=method, headers=merged)
            response = None
            try:
                try:
                    response = self._opener.open(request, timeout=self.timeout)
                except HTTPError as exc:
                    response = exc
                except URLError as exc:
                    raise RequestError(f"request failed for {current}: {exc.reason}") from exc
                except TimeoutError as exc:
                    raise RequestError(f"request timed out for {current}") from exc

                status = getattr(response, "status", response.getcode())
                final = self._validate(response.geturl())
                location = response.headers.get("Location")
                if location and status in {301, 302, 303, 307, 308}:
                    if count >= self.max_redirects:
                        raise RequestError(f"maximum redirects exceeded for {url}")
                    current = self._validate(urljoin(final, location))
                    if status == 303 or (status in {301, 302} and method == "POST"):
                        method = "GET"
                        body = None
                    continue

                return HTTPResponseData(
                    final,
                    status,
                    {key.lower(): value for key, value in response.headers.items()},
                    self._read_limited(response),
                )
            finally:
                if response is not None:
                    response.close()

        raise RequestError(f"maximum redirects exceeded for {url}")

    def _validate(self, url: str) -> str:
        try:
            return self.scope.validate(url)
        except ScopeError as exc:
            raise RequestError(str(exc)) from exc

    def _read_limited(self, response) -> bytes:
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > self.max_response_bytes:
            raise RequestError("response exceeds configured size limit")

        chunks: list[bytes] = []
        remaining = self.max_response_bytes
        while remaining:
            chunk = response.read(min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and response.read(1):
            raise RequestError("response exceeds configured size limit")
        return b"".join(chunks)
