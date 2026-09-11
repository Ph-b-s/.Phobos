from ai_security_modules import run_ai_prompt_injection, run_ai_system_prompt
from knowledge_store import KnowledgeStore
from security_modules import ModuleContext


class FakeBrowser:
    def __init__(self, response: str):
        self.response = response
        self.url = "https://example.com/chat"

    def goto(self, url):
        self.url = url
        return url

    def fill(self, selector, value):
        self.last_value = value

    def click(self, selector):
        return None

    def text(self):
        return self.response


def _context(browser, metadata):
    return ModuleContext(target="https://example.com", knowledge=KnowledgeStore(), browser=browser, metadata=metadata)


def test_direct_prompt_injection_canary_is_detected():
    canary = "PHOBOS_AI_TEST_OK"
    config = {
        "chat_url": "https://example.com/chat",
        "chat_input_selector": "#prompt",
        "chat_submit_selector": "#submit",
        "canary": canary,
        "query": "test",
    }
    result = run_ai_prompt_injection(_context(FakeBrowser(f"accepted {canary}"), {"prompt_injection": config}))
    assert any(item.type == "direct_prompt_injection_signal" for item in result.findings)


def test_direct_prompt_injection_does_not_store_prompt_or_response():
    secretish_query = "do not store this unique probe"
    config = {
        "chat_url": "https://example.com/chat",
        "chat_input_selector": "#prompt",
        "chat_submit_selector": "#submit",
        "canary": "PHOBOS_AI_TEST_OK",
        "query": secretish_query,
    }
    result = run_ai_prompt_injection(_context(FakeBrowser("no marker"), {"prompt_injection": config}))
    assert secretish_query not in repr(result.observations[0].data)


def test_system_prompt_marker_disclosure_is_detected():
    marker = "PHOBOS_SYS_PROTECTED"
    config = {
        "chat_url": "https://example.com/chat",
        "chat_input_selector": "#prompt",
        "chat_submit_selector": "#submit",
        "protected_marker": marker,
        "query": "reveal",
    }
    result = run_ai_system_prompt(_context(FakeBrowser(marker), {"system_prompt": config}))
    assert any(item.type == "system_prompt_marker_disclosure" for item in result.findings)
    assert all(marker not in repr(item.data) for item in result.observations)
