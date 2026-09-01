from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import ai
import nmap_runner
from nmap_runner import NmapError, run_top_ports_scan, target_host
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


def test_target_host_rejects_ports_and_paths() -> None:
    with pytest.raises(NmapError):
        target_host("example.com:8080")
    with pytest.raises(NmapError):
        target_host("https://example.com/admin")


def test_target_host_accepts_hostname() -> None:
    assert target_host("https://Example.COM/") == "example.com"


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


def test_nmap_runner_blocks_out_of_scope_host(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda name: "/usr/bin/nmap")
    with pytest.raises(NmapError, match="out-of-scope"):
        run_top_ports_scan("evil-example.com", scope)


def test_ai_config_defaults_to_dolphin_mistral() -> None:
    config = ai.AIConfig.from_env()
    assert config.model == "dphn/Dolphin-Mistral-24B-Venice-Edition"
    assert config.base_url == "http://127.0.0.1:8000/v1/chat/completions"


def test_ai_config_allows_local_endpoint_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHOBOS_AI_URL", "http://127.0.0.1:9000/v1/chat/completions")
    monkeypatch.setenv("PHOBOS_AI_MODEL", "custom-model")
    config = ai.AIConfig.from_env()
    assert config.base_url == "http://127.0.0.1:9000/v1/chat/completions"
    assert config.model == "custom-model"


def test_response_text_supports_openai_compatible_shape() -> None:
    payload = {
        "choices": [{"message": {"content": json.dumps({"action": "refuse", "reason": "no"})}}]
    }
    assert ai._extract_text(payload).startswith("{")
