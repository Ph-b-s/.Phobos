from pathlib import Path

import pytest

from phobos.core.scope import ScopeError, ScopeValidator
from phobos.storage.evidence import EvidenceStore


def test_private_destination_is_rejected_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "phobos.core.scope.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("10.0.0.8", 0))],
    )
    scope = ScopeValidator(("example.com",))
    with pytest.raises(ScopeError, match="non-public"):
        scope.validate("https://example.com/")


def test_private_destination_can_be_explicitly_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "phobos.core.scope.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("10.0.0.8", 0))],
    )
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    assert scope.validate("https://example.com/path") == "https://example.com/path"


def test_fragment_is_removed_before_network_validation() -> None:
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    assert scope.validate("https://example.com/page#client-state") == "https://example.com/page"


def test_evidence_store_rejects_path_traversal(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".phobos")
    with pytest.raises(ValueError, match="inside the evidence store"):
        store.write_json("../escape.json", {"unsafe": True})


def test_evidence_store_rejects_non_json_names(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".phobos")
    with pytest.raises(ValueError, match="only writes JSON"):
        store.write_json("scan.txt", {"unsafe": True})
