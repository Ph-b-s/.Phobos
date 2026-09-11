from ai_boundary_modules import run_ai_context_manipulation, run_ai_goal_hijacking
from module_runner import ModuleRunner, default_module_registry
from security_modules import ModuleContext


class FakeBrowser:
    def __init__(self, text: str = ""):
        self._text = text
        self.opened = []

    def open(self, url):
        self.opened.append(url)

    def fill(self, selector, value):
        self.filled = (selector, value)

    def click(self, selector):
        self.clicked = selector

    def snapshot(self):
        class Snapshot:
            text = self._text
        return Snapshot()

    def links_matching(self, keywords):
        return ()


def context(config_name, config, text):
    return ModuleContext(
        target="https://example.com",
        browser=FakeBrowser(text),
        metadata={config_name: config},
    )


def test_goal_hijacking_marker_signal():
    ctx = context("ai_goal_hijacking", {
        "chat_url": "https://example.com/chat",
        "chat_input_selector": "#input",
        "chat_submit_selector": "#send",
        "marker": "PHOBOS_GOAL_TEST",
    }, "PHOBOS_GOAL_TEST")
    result = run_ai_goal_hijacking(ctx)
    assert result.findings[0].type == "ai_goal_hijacking_signal"


def test_context_manipulation_requires_valid_marker():
    ctx = context("ai_context_manipulation", {
        "chat_url": "https://example.com/chat",
        "chat_input_selector": "#input",
        "chat_submit_selector": "#send",
        "marker": "bad marker",
    }, "")
    try:
        run_ai_context_manipulation(ctx)
    except ValueError as exc:
        assert "PHOBOS_" in str(exc)
    else:
        raise AssertionError("expected marker validation error")


def test_new_ai_modules_are_registered():
    registry = default_module_registry()
    assert {"ai.output_handling", "ai.goal_hijacking", "ai.context_manipulation"}.issubset(registry.ids())
