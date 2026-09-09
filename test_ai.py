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


def test_parse_decision_handles_json_wrapped_in_text() -> None:
    result = ai._parse_decision(
        'Here is the plan:\n{"action":"plan_scan","modules":["web.xss"],"reason":"test"}'
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


def test_ai_config_defaults_to_local_mistral(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "PHOBOS_AI_PROVIDER",
        "PHOBOS_AI_URL",
        "PHOBOS_AI_MODEL",
        "PHOBOS_AI_TIMEOUT",
        "PHOBOS_AI_AUTOSTART",
        "PHOBOS_AI_AUTO_PULL",
    ):
        monkeypatch.delenv(name, raising=False)
    config = ai.AIConfig.from_env()
    assert config.model == ai.MODEL_NAME
    assert config.model == "mistral-small3.2:24b-instruct-2506-q4_K_M"
    assert config.base_url == "http://127.0.0.1:11434/api/chat"
    assert config.auto_start_runtime is True
    assert config.auto_pull_model is True


def test_ai_config_rejects_remote_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHOBOS_AI_URL", "https://example.com/api/chat")
    with pytest.raises(ai.AIError, match="local HTTP endpoint"):
        ai.AIConfig.from_env()


def test_response_text_supports_ollama_shape() -> None:
    payload = {
        "message": {"content": json.dumps({"action": "refuse", "modules": [], "reason": "no"})}
    }
    assert ai._extract_text(payload).startswith("{")


def test_response_text_supports_openai_compatible_shape() -> None:
    payload = {
        "choices": [{"message": {"content": json.dumps({"action": "refuse", "modules": [], "reason": "no"})}}]
    }
    assert ai._extract_text(payload).startswith("{")


def test_local_mistral_client_builds_ollama_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_json(url, **kwargs):
        captured.setdefault("calls", []).append((url, kwargs))
        if url.endswith("/api/version"):
            return {"version": "0.12.0"}
        if url.endswith("/api/tags"):
            return {"models": [{"name": ai.MODEL_NAME}]}
        if url.endswith("/api/chat"):
            return {
                "message": {
                    "content": '{"action":"plan_scan","modules":["web.auth"],"reason":"test"}'
                }
            }
        raise AssertionError(url)

    monkeypatch.setattr(ai, "_http_json", fake_json)
    client = ai.LocalMistralClient(ai.AIConfig())
    decision = client.plan("map this application")
    assert decision["action"] == "plan_scan"
    assert decision["modules"] == ["web.auth"]
    urls = [url for url, _ in captured["calls"]]
    assert urls == [
        ai.DEFAULT_HEALTH_URL,
        ai.DEFAULT_TAGS_URL,
        ai.DEFAULT_BASE_URL,
    ]
    chat_kwargs = captured["calls"][2][1]
    assert chat_kwargs["method"] == "POST"
    assert chat_kwargs["body"]["model"] == ai.MODEL_NAME
    assert chat_kwargs["body"]["format"] == "json"
    assert chat_kwargs["body"]["options"]["temperature"] == 0.1


def test_local_mistral_client_can_start_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"health": 0, "start": 0}

    def fake_json(url, **kwargs):
        if url.endswith("/api/version"):
            calls["health"] += 1
            if calls["health"] < 3:
                raise ai.AIError("not running")
            return {"version": "0.12.0"}
        if url.endswith("/api/tags"):
            return {"models": [{"name": ai.MODEL_NAME}]}
        if url.endswith("/api/chat"):
            return {"message": {"content": '{"action":"refuse","modules":[],"reason":"no"}'}}
        raise AssertionError(url)

    monkeypatch.setattr(ai, "_http_json", fake_json)
    monkeypatch.setattr(ai, "_start_ollama", lambda: calls.__setitem__("start", calls["start"] + 1) or SimpleNamespace())
    monkeypatch.setattr(ai, "_wait_for_runtime", lambda timeout: None)
    client = ai.LocalMistralClient(ai.AIConfig())
    result = client.plan("test")
    assert result["action"] == "refuse"
    assert calls["start"] == 1


def test_local_mistral_client_requires_model_when_auto_pull_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_json(url, **kwargs):
        if url.endswith("/api/version"):
            return {"version": "0.12.0"}
        if url.endswith("/api/tags"):
            return {"models": []}
        raise AssertionError(url)

    monkeypatch.setattr(ai, "_http_json", fake_json)
    config = ai.AIConfig(auto_pull_model=False)
    client = ai.LocalMistralClient(config)
    with pytest.raises(ai.AIError, match="not installed"):
        client.plan("test")


def test_ai_client_rejects_oversized_request() -> None:
    client = ai.LocalMistralClient(ai.AIConfig())
    with pytest.raises(ai.AIError, match="24,000-character limit"):
        client.plan("x" * (ai.MAX_REQUEST_CHARS + 1))
