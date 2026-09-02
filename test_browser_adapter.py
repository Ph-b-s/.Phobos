"""Regression tests for the dependency-free parts of the browser adapter."""
from __future__ import annotations

import pytest

from browser_adapter import BrowserAdapterError, BrowserLimits, NetworkRecord


def test_browser_limits_are_bounded():
    assert BrowserLimits().max_requests == 2_000
    with pytest.raises(ValueError):
        BrowserLimits(max_requests=0)
    with pytest.raises(ValueError):
        BrowserLimits(max_requests=2_001)
    with pytest.raises(ValueError):
        BrowserLimits(navigation_timeout_ms=99)


def test_network_record_redacts_query_and_fragment_from_evidence():
    record = NetworkRecord(
        event="response",
        method="GET",
        url="https://example.com/account?token=secret#fragment",
        resource_type="document",
        status=200,
    )
    observation = record.to_observation()
    assert "token=secret" not in observation.description
    assert "#fragment" not in observation.description
    assert observation.metadata["url"] == "https://example.com/account"


def test_browser_adapter_error_is_specific_runtime_error():
    assert issubclass(BrowserAdapterError, RuntimeError)
