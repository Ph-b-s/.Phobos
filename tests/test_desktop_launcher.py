from pathlib import Path
import tomllib


def test_desktop_entrypoint_is_packaged():
    config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["scripts"]["phobos-desktop"] == "desktop_launcher:main"
    assert "desktop_launcher" in config["tool"]["setuptools"]["py-modules"]


def test_desktop_extra_contains_gui_and_browser_runtime():
    config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    desktop = config["project"]["optional-dependencies"]["desktop"]
    assert any(item.startswith("pyside6") for item in desktop)
    assert any(item.startswith("playwright") for item in desktop)
    assert any(item.startswith("pyinstaller") for item in desktop)


def test_desktop_quick_start_script_exists():
    script = Path("run_desktop.ps1")
    assert script.exists()
    text = script.read_text(encoding="utf-8")
    assert "playwright install chromium" in text
    assert "desktop_launcher" in text
