from phobos.core.scope import ScopeError, ScopeValidator


def test_exact_domain_and_subdomain_are_in_scope():
    scope = ScopeValidator(("example.com",))
    assert scope.is_in_scope("https://example.com/")
    assert scope.is_in_scope("https://app.example.com/login")


def test_suffix_domain_bypass_is_rejected():
    scope = ScopeValidator(("example.com",))
    assert not scope.is_in_scope("https://example.com.evil.test/")
    assert not scope.is_in_scope("https://evil-example.com/")


def test_validate_requires_http_and_scope():
    scope = ScopeValidator(("example.com",))
    try:
        scope.validate("ftp://example.com/file")
    except ScopeError as exc:
        assert "scheme" in str(exc)
    else:
        raise AssertionError("expected ScopeError")


def test_userinfo_cannot_hide_host():
    scope = ScopeValidator(("example.com",))
    assert not scope.is_in_scope("https://example.com@evil.test/")
