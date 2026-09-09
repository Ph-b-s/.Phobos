"""Test-account lifecycle management for authorized Phobos workflows."""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

MAX_ACCOUNTS = 100
MAX_PASSWORD_LENGTH = 128


class AccountState(StrEnum):
    CREATED = "created"
    VERIFIED = "verified"
    AUTHENTICATED = "authenticated"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AccountCredentials:
    username: str
    email: str
    password: str

    def __post_init__(self) -> None:
        if not self.username.strip() or not self.email.strip() or not self.password:
            raise ValueError("account credentials require username, email, and password")
        if len(self.password) > MAX_PASSWORD_LENGTH:
            raise ValueError("account password exceeds size limit")

    def redacted(self) -> dict[str, str]:
        return {"username": self.username, "email": self.email, "password": "<redacted>"}


@dataclass(slots=True)
class TestAccount:
    id: str
    credentials: AccountCredentials
    state: AccountState = AccountState.CREATED
    role: str = "user"
    metadata: dict[str, Any] = field(default_factory=dict)
    session_state: dict[str, Any] | None = None
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("account id cannot be empty")
        if not self.role.strip():
            raise ValueError("account role cannot be empty")
        self.metadata = dict(self.metadata)

    def to_dict(self, *, include_secret: bool = False) -> dict[str, Any]:
        credentials = (
            {"username": self.credentials.username, "email": self.credentials.email, "password": self.credentials.password}
            if include_secret
            else self.credentials.redacted()
        )
        return {
            "id": self.id,
            "credentials": credentials,
            "state": self.state.value,
            "role": self.role,
            "metadata": self.metadata,
            "session_state_present": self.session_state is not None,
            "created_at": self.created_at,
        }


class AccountManager:
    """Own test identities and their lifecycle without leaking credentials to evidence."""

    def __init__(self, *, namespace: str = "phobos", max_accounts: int = MAX_ACCOUNTS) -> None:
        namespace = namespace.strip()
        if not namespace:
            raise ValueError("account namespace cannot be empty")
        if not 1 <= max_accounts <= MAX_ACCOUNTS:
            raise ValueError(f"max_accounts must be between 1 and {MAX_ACCOUNTS}")
        self.namespace = namespace
        self.max_accounts = max_accounts
        self._accounts: dict[str, TestAccount] = {}

    @property
    def accounts(self) -> tuple[TestAccount, ...]:
        return tuple(self._accounts.values())

    def create(self, *, email_domain: str = "invalid.test", role: str = "user", label: str = "test") -> TestAccount:
        if len(self._accounts) >= self.max_accounts:
            raise RuntimeError("account limit exceeded")
        domain = email_domain.strip().lower().rstrip(".")
        if not domain or "." not in domain:
            raise ValueError("email_domain must be a hostname")
        safe_label = "".join(ch.lower() if ch.isalnum() else "-" for ch in label.strip()) or "test"
        token = secrets.token_hex(6)
        username = f"{self.namespace}-{safe_label}-{token}"
        email = f"{username}@{domain}"
        password = secrets.token_urlsafe(24)[:32]
        account = TestAccount(
            id=f"account-{token}",
            credentials=AccountCredentials(username, email, password),
            role=role,
        )
        self._accounts[account.id] = account
        return account

    def get(self, account_id: str) -> TestAccount:
        try:
            return self._accounts[account_id]
        except KeyError as exc:
            raise KeyError(f"unknown test account: {account_id}") from exc

    def set_state(self, account_id: str, state: AccountState) -> TestAccount:
        account = self.get(account_id)
        account.state = state
        return account

    def attach_session(self, account_id: str, session_state: dict[str, Any]) -> TestAccount:
        account = self.get(account_id)
        account.session_state = dict(session_state)
        account.state = AccountState.AUTHENTICATED
        return account

    def remove(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)
