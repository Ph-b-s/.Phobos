import pytest

from scope import ScopeError, ScopeValidator


def test_requires_at_least_one_scope():
    with pytest.raises(ValueError, match="at least one allowed domain"):
        ScopeValidator([])


def test_normalizes_domains_and_urls():
    validator = ScopeValidator(["Example.COM."] , allow_private_targets=True)

    assert validator.allowed_domains == ("example.com",)
    assert validator.validate("HTTPS://EXAMPLE.COM/path#fragment") == "https://example.com/path"


def test_allows_subdomains_but_not_sibling_domains():
    validator = ScopeValidator(["example.com"], allow_private_targets=True)

    assert validator.is_in_scope("https://api.example.com/v1")
    assert validator.is_in_scope("https://example.com")
    assert not validator.is_in_scope("https://example.com.evil.test")
    assert not validator.is_in_scope("https://evil-example.com")


def test_rejects_non_http_schemes_and_userinfo():
    validator = ScopeValidator(["example.com"], allow_private_targets=True)

    with pytest.raises(ScopeError, match="only http and https"):
        validator.validate("ftp://example.com/file")
    with pytest.raises(ScopeError, match="userinfo"):
        validator.validate("https://user:pass@example.com/")


def test_private_literal_targets_are_blocked_by_default():
    validator = ScopeValidator(["127.0.0.1"])

    with pytest.raises(ScopeError, match="non-public IP"):
        validator.validate("http://127.0.0.1/")


def test_literal_ip_can_be_explicitly_allowed():
    validator = ScopeValidator(["127.0.0.1"], allow_private_targets=True)

    assert validator.validate("http://127.0.0.1:8080/test") == "http://127.0.0.1:8080/test"
