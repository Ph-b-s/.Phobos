"""Single outbound HTTP boundary with scope-aware redirects and pinned DNS."""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from http.cookies import Morsel, SimpleCookie
from urllib.parse import urljoin, urlsplit

from config import PHOBOS_VERSION
from scope import ScopeError, ScopeValidator


PHOBOS_HTTP_USER_AGENT = f"Phobos/{PHOBOS_VERSION}"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class RequestError(RuntimeError):
    """Raised when an outbound HTTP request cannot be completed safely."""


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


@dataclass(frozen=True, slots=True)
class _SessionCookie:
    name: str
    value: str
    domain: str
    path: str
    secure: bool = False


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that connects to an already-validated IP address."""

    def __init__(self, hostname: str, port: int, resolved_ip: str, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._resolved_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an IP while preserving hostname/SNI validation."""

    def __init__(
        self,
        hostname: str,
        port: int,
        resolved_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ):
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._resolved_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self._tunnel_host or self.host,
            )
        except Exception:
            raw_socket.close()
            raise


class RequestManager:
    """The only component allowed to make outbound HTTP requests.

    Each request is scope-validated, resolved once, checked for a permitted
    destination, and then connected to that exact IP. HTTPS retains the original
    hostname for Host/SNI/certificate validation. Redirect destinations repeat
    the complete validation and pinning process.
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
        self._cookies: list[_SessionCookie] = []
        self._ssl_context = ssl.create_default_context()

    def reset_session(self) -> None:
        """Clear authentication/session cookies while keeping transport settings."""
        self._cookies.clear()

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
        merged = {"User-Agent": self.user_agent, "Accept": "*/*", "Connection": "close"}
        merged.update(headers or {})

        for count in range(self.max_redirects + 1):
            parsed, resolved_ip = self._resolve_pinned(current)
            request_headers = dict(merged)
            request_headers["Host"] = self._host_header(parsed)
            cookie_header = self._cookie_header(parsed)
            if cookie_header and "Cookie" not in request_headers:
                request_headers["Cookie"] = cookie_header

            connection = self._connection(parsed, resolved_ip)
            response = None
            try:
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                connection.request(method, path, body=body, headers=request_headers)
                response = connection.getresponse()
                self._store_cookies(parsed, response.getheaders())

                status = response.status
                location = response.getheader("Location")
                if location and status in REDIRECT_STATUSES:
                    if count >= self.max_redirects:
                        raise RequestError(f"maximum redirects exceeded for {url}")
                    current = self._validate(urljoin(current, location))
                    if status == 303 or (status in {301, 302} and method == "POST"):
                        method = "GET"
                        body = None
                    continue

                return HTTPResponseData(
                    current,
                    status,
                    {key.lower(): value for key, value in response.getheaders()},
                    self._read_limited(response),
                )
            except (OSError, ssl.SSLError) as exc:
                raise RequestError(f"request failed for {current}: {exc}") from exc
            finally:
                if response is not None:
                    response.close()
                connection.close()

        raise RequestError(f"maximum redirects exceeded for {url}")

    def _validate(self, url: str) -> str:
        try:
            return self.scope.validate(url)
        except ScopeError as exc:
            raise RequestError(str(exc)) from exc

    def _resolve_pinned(self, url: str):
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            raise RequestError("URL has no hostname")
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise RequestError("URL contains an invalid port") from exc

        try:
            addresses = (str(ipaddress.ip_address(host)),)
        except ValueError:
            try:
                results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise RequestError(f"could not resolve destination safely: {host}") from exc
            addresses = tuple(dict.fromkeys(result[4][0] for result in results))

        if not addresses:
            raise RequestError(f"destination has no resolvable address: {host}")
        if not self.scope.allow_private_targets and any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise RequestError("destination resolves to a non-public IP address")

        return parsed, addresses[0]

    @staticmethod
    def _host_header(parsed) -> str:
        host = parsed.hostname or ""
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        if parsed.port and parsed.port != default_port:
            return f"[{host}]" if ":" in host else f"{host}:{parsed.port}"
        return f"[{host}]" if ":" in host else host

    def _connection(self, parsed, resolved_ip: str):
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if parsed.scheme.lower() == "https":
            return _PinnedHTTPSConnection(
                host,
                port,
                resolved_ip,
                self.timeout,
                self._ssl_context,
            )
        return _PinnedHTTPConnection(host, port, resolved_ip, self.timeout)

    def _cookie_header(self, parsed) -> str:
        host = parsed.hostname or ""
        path = parsed.path or "/"
        secure = parsed.scheme.lower() == "https"
        values = [
            f"{cookie.name}={cookie.value}"
            for cookie in self._cookies
            if self._cookie_matches(cookie, host, path, secure)
        ]
        return "; ".join(values)

    @staticmethod
    def _cookie_matches(cookie: _SessionCookie, host: str, path: str, secure: bool) -> bool:
        domain = cookie.domain.lstrip(".")
        domain_ok = host == domain or host.endswith("." + domain)
        path_ok = path == cookie.path or path.startswith(cookie.path.rstrip("/") + "/")
        return domain_ok and path_ok and (not cookie.secure or secure)

    def _store_cookies(self, parsed, headers) -> None:
        host = parsed.hostname or ""
        default_path = parsed.path.rpartition("/")[0] or "/"
        if not default_path.startswith("/"):
            default_path = "/"
        for key, value in headers:
            if key.lower() != "set-cookie":
                continue
            jar = SimpleCookie()
            jar.load(value)
            for morsel in jar.values():
                assert isinstance(morsel, Morsel)
                name = morsel.key
                cookie_domain = morsel["domain"].strip().lower() or host
                cookie_path = morsel["path"].strip() or default_path
                secure = bool(morsel["secure"])
                if morsel["max-age"].strip() in {"0", "-1"}:
                    self._cookies = [
                        cookie
                        for cookie in self._cookies
                        if not (
                            cookie.name == name
                            and cookie.domain == cookie_domain
                            and cookie.path == cookie_path
                        )
                    ]
                    continue
                replacement = _SessionCookie(name, morsel.value, cookie_domain, cookie_path, secure)
                self._cookies = [
                    cookie
                    for cookie in self._cookies
                    if not (
                        cookie.name == name
                        and cookie.domain == cookie_domain
                        and cookie.path == cookie_path
                    )
                ]
                self._cookies.append(replacement)

    def _read_limited(self, response) -> bytes:
        length = response.getheader("Content-Length")
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
