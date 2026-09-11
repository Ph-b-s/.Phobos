from security_modules import module_index
from module_runner import default_module_registry


def test_phase1_modules_are_registered():
    registry = default_module_registry()
    assert "web.nmap" in registry.ids()
    assert "ai.indirect_prompt_injection" in registry.ids()


def test_phase1_implemented_flags_match_registry():
    catalog = module_index()
    registry = default_module_registry()
    assert catalog["web.nmap"].implemented is True
    assert catalog["ai.indirect_prompt_injection"].implemented is True
    assert catalog["web.nmap"].id in registry.ids()
    assert catalog["ai.indirect_prompt_injection"].id in registry.ids()
