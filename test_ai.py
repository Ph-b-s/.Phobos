from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import ai
import nmap_runner
from nmap_runner import NmapError, prepare_top_ports_scan, run_top_ports_scan, target_host
from scope import ScopeValidator


def test_parse_decision_accepts_module_plan() -> None:
    result = ai._parse_decision(
        '{"action":"plan_scan","modules":["web.auth","ai.prompt_injection"],"reason":"test"}'
    )
    assert result == {
        "action": "plan_scan",
        "modules": ["web.auth", "ai.prompt_injection"],
        "reason": "test",
    }


def test_parse_decision_rejects_unknown_module() -> None:
    with pytest.raises(ai.AIError, match="unsupported module"):
        ai._parse_decision(
            '{"action":"plan_scan","modules":["shell"],"reason":"bad"}'
        )


def test_parse_decision_accepts_refusal() -> None:
    assert ai._parse_decision('{"action":"refuse","modules":[],"reason":"unsupported"}') == {
        "action": "refuse",
        "modules": [],
        "reason": "unsupported",
    }


def test_parse_decision_rejects_extra_fields() -> None:
    with pytest.raises(ai.AIError, match="exactly action, modules, and reason"):
        ai._parse_decision(
            '{"action":"refuse","modules":[],"reason":"no","extra":"bad"}'
        )


def test_parse_decision_rejects_empty_reason() -> None:
    with pytest.raises(ai.AIError, match="reason must not be empty"):
        ai._parse_decision('{"action":"plan_scan","modules":["web.auth"],"reason":"   "}')


def test_parse_decision_handles_markdown_json() -> None:
    result = ai._parse_decision(
        '```json\n{"action":"plan_scan","modules":["web.xss"],"reason":"test"}\n```'
    )
    assert result["modules"] == ["web.xss"]


def test_target_host_accepts_web_path() -> None:
    assert target_host("https://example.com/admin/lab?id=1") == "example.com"


def test_target_host_rejects_explicit_port() -> None:
    with pytest.raises(NmapError):
        target_host("example.com:8080")


def test_nmap_prepare_is_side_effect_free(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("scanme.nmap.org",), allow_private_targets=True)
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda name: "/usr/bin/nmap")
    command = prepare_top_ports_scan("scanme.nmap.org", scope)
    assert command[-1] == "scanme.nmap.org"


def test_nmap_runner_uses_fixed_safe_command(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("scanme.nmap.org",), allow_private_targets=True)
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda name: "/usr/bin/nmap")
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout='<nmaprun></nmaprun>', stderr="")

    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)
    result = run_top_ports_scan("scanme.nmap.org", scope)
    assert result.returncode == 0
    assert result.command == (
        "/usr/bin/nmap", "-sT", "--top-ports", "100", "--open", "--reason", "-oX", "-", "--", "scanme.nmap.org"
    )
    assert captured["command"] == result.command
    assert captured["kwargs"]["shell"] is False


def test_nmap_dry_run_never_executes_or_requires_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    monkeypatch.setattr(nmap_runner.shutil, "which", pytest.fail)
    monkeypatch.setattr(nmap_runner.subprocess, "run", pytest.fail)
    result = run_top_ports_scan("example.com", scope, execute=False)
    assert result.returncode == 0
    assert result.command[-1] == "example.com"


def test_nmap_runner_blocks_out_of_scope_host() -> None:
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    with pytest.raises(NmapError, match="out-of-scope"):
        run_top_ports_scan("evil-example.com", scope, execute=False)


def test_ai_config_defaults_to_venice_uncensored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENICE_API_KEY", "test-key")
    config = ai.AIConfig.from_env()
    assert config.model == "venice-uncensored"
    assert config.base_url == "https://api.venice.ai/api/v1/chat/completions"


def test_response_text_supports_openai_compatible_shape() -> None:
    payload = {
        "choices": [{"message": {"content": json.dumps({"action": "refuse", "modules": [], "reason": "no"})}}]
    }
    assert ai._extract_text(payload).startswith("{")


def test_venice_client_builds_module_plan_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size):
            return json.dumps({
                "choices": [{"message": {"content": '{"action":"plan_scan","modules":["web.auth"],"reason":"test"}'}}]
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(ai, "urlopen", fake_urlopen)
    client = ai.VeniceClient(ai.AIConfig(api_key="secret"))
    decision = client.plan("map this application")
    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))
    assert decision["action"] == "plan_scan"
    assert decision["modules"] == ["web.auth"]
    assert payload["model"] == "venice-uncensored"
    assert captured["timeout"] == 30.0


def test_ai_client_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size):
            return b"x" * (ai.MAX_RESPONSE_BYTES + 1)

    monkeypatch.setattr(ai, "urlopen", lambda request, timeout: FakeResponse())
    client = ai.VeniceClient(ai.AIConfig(api_key="secret"))
    with pytest.raises(ai.AIError, match="size limit"):
        client.plan("test")


def test_ai_client_rejects_oversized_request() -> None:
    client = ai.VeniceClient(ai.AIConfig(api_key="secret"))
    with pytest.raises(ai.AIError, match="8,000-character limit"):
        client.plan("x" * (ai.MAX_REQUEST_CHARS + 1))
