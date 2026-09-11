from planner import ScanPlanner


class FakeClient:
    def __init__(self, modules):
        self.modules = modules

    def plan(self, context):
        return {"action": "plan_scan", "modules": list(self.modules), "reason": "evidence-driven next step"}


def test_planner_filters_to_eligible_executable_modules():
    planner = ScanPlanner(FakeClient(["web.headers", "web.nmap", "web.sqli"]))
    decision = planner.next_decision(
        target="https://example.com",
        iteration=1,
        completed_modules=(),
        knowledge={},
        eligible_modules=("web.headers",),
    )
    assert decision.modules == ("web.headers",)
