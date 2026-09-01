from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import ai
import nmap_runner
from nmap_runner import NmapError, prepare_top_ports_scan, run_top_ports_scan, target_host
from scope import ScopeValidator


def test_parse_decision_accepts_supported_action() -> None:
    assert ai._parse_decision('{"action":"nmap_top_ports","reason":"basic recon"}') == {
        "action": "nmap_top_ports",
        "reason": "basic recon",
    }


def test_parse_decision_rejects_arbitrary_action() -> None:
    with pytest.raises(ai.AIError):
        ai._parse_decision('{"action":"shell","reason":"run anything"}')


def test_parse_decision_handles_markdown_json() -> None:
    result = ai._parse_decision('```json\n{"action":"refuse","reason":"unsupported"}\n```')
    assert result["action"] == "refuse"


def test_parse_decision_rejects_non_object() -> None:
    with pytest.raises(ai.AIError):
        ai._parse_decision('[{"action":"nmap_top_ports"}]')


def test_parse_decision_rejects_missing_reason_type() -> None:
    with pytest.raises(ai.AIError):
        ai._parse_decision('{"action":"refuse","reason":123}')


def test_target_host_rejects_ports_and_paths() -> None:
    with pytest.raises(NmapError):
        target_host("example.com:8080")
    with pytest.raises(NmapError):
        target_host("https://example.com/admin")


def test_target_host_accepts_hostname() -> None:
    assert target_host("https://Example.COM/") == "example.com"


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
        return SimpleNamespace(returncode=0, stdout="Nmap test output\n", stderr="")

    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)
    result = run_top_ports_scan("scanme.nmap.org", scope)

    assert result.returncode == 0
    assert result.command == (
        "/usr/bin/nmap",
        "-sT",
        "--top-ports",
        "100",
        "--open",
        "--reason",
        "--",
        "scanme.nmap.org",
    )
    assert captured["command"] == result.command
    assert captured["kwargs"] == {
        "stdin": nmap_runner.subprocess.DEVNULL,
        "stdout": nmap_runner.subprocess.PIPE,
        "stderr": nmap_runner.subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": 60.0,
        "check": False,
        "shell": False,
    }


def test_nmap_dry_run_never_executes_or_requires_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    monkeypatch.setattr(nmap_runner.shutil, "which", pytest.fail)
    monkeypatch.setattr(nmap_runner.subprocess, "run", pytest.fail)
    result = run_top_ports_scan("example.com", scope, execute=False)
    assert result.returncode == 0
    assert result.command == (
        "nmap",
        "-sT",
        "--top-ports",
        "100",
        "--open",
        "--reason",
        "--",
        "example.com",
    )
    assert result.stdout == ""


def test_nmap_runner_blocks_out_of_scope_host(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda name: "/usr/bin/nmap")
    with pytest.raises(NmapError, match="out-of-scope"):
        run_top_ports_scan("evil-example.com", scope)


def test_ai_config_defaults_to_venice_uncensored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENICE_API_KEY", "test-key")
    config = ai.AIConfig.from_env()
    assert config.model == "venice-uncensored"
    assert config.base_url == "https://api.venice.ai/api/v1/chat/completions"
    assert config.api_key == "test-key"


def test_ai_config_requires_venice_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VENICE_API_KEY", raising=False)
    with pytest.raises(ai.AIError, match="VENICE_API_KEY"):
        ai.AIConfig.from_env()


def test_ai_config_allows_https_endpoint_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENICE_API_KEY", "test-key")
    monkeypatch.setenv("PHOBOS_AI_URL", "https://proxy.example/v1/chat/completions")
    monkeypatch.setenv("PHOBOS_AI_MODEL", "custom-model")
    config = ai.AIConfig.from_env()
    assert config.base_url == "https://proxy.example/v1/chat/completions"
    assert config.model == "custom-model"


def test_ai_config_rejects_http_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENICE_API_KEY", "test-key")
    monkeypatch.setenv("PHOBOS_AI_URL", "http://127.0.0.1:8000/v1/chat/completions")
    with pytest.raises(ai.AIError, match="https"):
        ai.AIConfig.from_env()


def test_response_text_supports_openai_compatible_shape() -> None:
    payload = {
        "choices": [{"message": {"content": json.dumps({"action": "refuse", "reason": "no"})}}]
    }
    assert ai._extract_text(payload).startswith("{")


def test_venice_client_builds_expected_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return json.dumps({
                "choices": [{"message": {"content": '{"action":"refuse","reason":"test"}'}}]
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(ai, "urlopen", fake_urlopen)
    client = ai.VeniceClient(ai.AIConfig(api_key="secret"))
    decision = client.decide("say no")

    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))
    assert decision["action"] == "refuse"
    assert payload["model"] == "venice-uncensored"
    assert payload["messages"][1]["content"] == "say no"
    assert request.get_header("Authorization") == "Bearer secret"
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
        client.decide("test")
