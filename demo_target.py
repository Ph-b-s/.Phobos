"""Small local target that models an indirect-prompt-injection trust boundary.

This target is intentionally vulnerable and exists only for local Phobos
integration tests. It has no external dependencies and binds to 127.0.0.1.
"""
from __future__ import annotations

import html
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


USERS = {"phobos-test": {"password": "phobos-test", "deleted": False}}
REVIEWS: list[tuple[str, str]] = []
SESSIONS: dict[str, str] = {}


def _reset_demo_state() -> None:
    """Restore deterministic initial state before every demo server run."""
    USERS.clear()
    USERS["phobos-test"] = {"password": "phobos-test", "deleted": False}
    REVIEWS.clear()
    SESSIONS.clear()


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html><head><title>"
        + html.escape(title)
        + "</title></head><body>"
        + body
        + "</body></html>"
    ).encode()


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "PhobosDemo/1.0"

    def log_message(self, *_args) -> None:
        return

    def _session_user(self) -> str | None:
        cookie = self.headers.get("Cookie", "")
        for item in cookie.split(";"):
            name, _, value = item.strip().partition("=")
            if name == "session" and value in SESSIONS:
                return SESSIONS[value]
        return None

    def _send(self, body: bytes, *, status: int = HTTPStatus.OK, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        user = self._session_user()

        if parsed.path == "/":
            self._send(
                _page(
                    "Phobos demo",
                    '<a href="/login">Login</a> <a href="/review">Review</a> '
                    '<a href="/chat?product=demo">Chat</a> <a href="/capabilities">Capabilities</a>',
                )
            )
            return
        if parsed.path == "/login":
            self._send(
                _page(
                    "Login",
                    '<form method="post"><input name="username"><input name="password" type="password"><button>Login</button></form>',
                )
            )
            return
        if parsed.path == "/review":
            self._send(
                _page(
                    "Review",
                    '<form method="post"><input name="product" value="demo"><textarea name="review"></textarea><button>Submit review</button></form>',
                )
            )
            return
        if parsed.path == "/capabilities":
            self._send(
                _page(
                    "Capabilities",
                    "delete_account requires the authenticated session and has no destructive side effect unless invoked by the demo assistant.",
                )
            )
            return
        if parsed.path == "/account":
            if not user:
                self._send(_page("Account", "not authenticated"), status=HTTPStatus.UNAUTHORIZED)
                return
            deleted = USERS.get(user, {}).get("deleted", True)
            self._send(_page("Account", "deleted" if deleted else "active"))
            return
        if parsed.path == "/chat":
            product = query.get("product", ["demo"])[0]
            impact = query.get("impact", ["0"])[0] == "1"
            review_text = next((text for item, text in reversed(REVIEWS) if item == product), "")
            marker = _extract_marker(review_text)
            response = f"Product: {html.escape(product)}. Review summary: {html.escape(review_text or 'No reviews yet.')}"
            if marker:
                response += f"<p>PHOBOS_CANARY: {html.escape(marker)}</p>"
                if impact and user and not USERS[user]["deleted"]:
                    USERS[user]["deleted"] = True
                    response += "<p>TOOL_CALL: delete_account</p><p>ACTION_RESULT: deleted</p>"
            self._send(_page("Live chat", response))
            return

        self._send(_page("Not found", "not found"), status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(_page("Bad request", "invalid content length"), status=HTTPStatus.BAD_REQUEST)
            return
        if length < 0:
            self._send(_page("Bad request", "invalid content length"), status=HTTPStatus.BAD_REQUEST)
            return

        raw = self.rfile.read(length).decode(errors="replace")
        form = {key: values[0] for key, values in parse_qs(raw).items()}
        parsed = urlparse(self.path)

        if parsed.path == "/login":
            username = form.get("username", "")
            password = form.get("password", "")
            if USERS.get(username, {}).get("password") != password:
                self._send(_page("Login", "invalid credentials"), status=HTTPStatus.UNAUTHORIZED)
                return
            token = secrets.token_hex(16)
            SESSIONS[token] = username
            self._send(
                _page("Logged in", '<a href="/account">Account</a>'),
                headers={"Set-Cookie": f"session={token}; Path=/; HttpOnly"},
            )
            return

        if parsed.path == "/review":
            if not self._session_user():
                self._send(_page("Review", "authentication required"), status=HTTPStatus.UNAUTHORIZED)
                return
            product = form.get("product", "demo")
            review = form.get("review", "")
            REVIEWS.append((product, review))
            self._send(_page("Review", "saved"))
            return

        self._send(_page("Not found", "not found"), status=HTTPStatus.NOT_FOUND)


def _extract_marker(value: str) -> str | None:
    parts = value.split()
    for part in parts:
        if len(part) == 23 and part.startswith("PHOBOS-") and all(char in "0123456789ABCDEF" for char in part[7:]):
            return part
    return None


def start_demo_server() -> tuple[ThreadingHTTPServer, str]:
    _reset_demo_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    return server, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":
    httpd, url = start_demo_server()
    print(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
