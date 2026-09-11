from access_control_module import run_web_access_control
from graph import Graph
from knowledge_store import KnowledgeStore
from security_modules import ModuleContext
from workflow_engine import WorkflowContext, WorkflowEngine, WorkflowState


class FakeInteractor:
    def __init__(self):
        self.current_url = "https://example.com/"
        self.role = "high"

    def open(self, url):
        self.current_url = url
        return None

    def snapshot(self):
        class Snapshot:
            def __init__(self, role, url):
                self.url = url
                self.text = "protected-data" if role in {"low", "high"} else "denied"
                self.title = "Protected"
        return Snapshot(self.role, self.current_url)


def _context(interactor):
    engine = WorkflowEngine()
    engine.register_action("set_role", lambda context, step: setattr(interactor, "role", str(step.metadata["role"])))
    return ModuleContext(
        target="https://example.com/",
        assets=(),
        knowledge=KnowledgeStore(),
        graph=Graph(),
        interactor=interactor,
        accounts=object(),
        workflow=engine,
    )


def _config():
    return {
        "protected_urls": ["https://example.com/account/42"],
        "low_workflow_id": "low",
        "low_workflow": [{"id": "role", "action": "set_role", "description": "set low role", "metadata": {"role": "low"}}],
        "high_workflow_id": "high",
        "high_workflow": [{"id": "role", "action": "set_role", "description": "set high role", "metadata": {"role": "high"}}],
    }


def test_access_control_flags_identical_protected_response():
    interactor = FakeInteractor()
    context = _context(interactor)
    context.metadata["access_control"] = _config()
    result = run_web_access_control(context)
    assert any(item.type == "potential_authorization_boundary_failure" for item in result.findings)


def test_access_control_requires_configuration():
    context = _context(FakeInteractor())
    try:
        run_web_access_control(context)
    except RuntimeError as exc:
        assert "access_control configuration" in str(exc)
    else:
        raise AssertionError("missing configuration should fail closed")
