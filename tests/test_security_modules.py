from module_runner import default_module_registry
from security_modules import module_index, module_specs


def test_catalog_ids_are_unique():
    specs = module_specs()
    assert len(specs) == len({spec.id for spec in specs})
    assert set(module_index()) == {spec.id for spec in specs}


def test_catalog_uses_implemented_flag_only_for_registered_modules():
    registry = default_module_registry()
    registered = registry.ids()

    for spec in module_specs():
        if spec.implemented:
            assert spec.id in registered
        else:
            assert spec.id not in registered


def test_every_registered_module_is_active_and_implemented():
    registry = default_module_registry()
    index = module_index()

    for module_id in registry.ids():
        spec = index[module_id]
        assert spec.active
        assert spec.implemented


def test_inactive_modules_are_not_marked_implemented():
    for spec in module_specs():
        if not spec.active:
            assert not spec.implemented
