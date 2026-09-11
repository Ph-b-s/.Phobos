from dataclasses import dataclass

from models import Asset, AssetType
from nosql_module import run_web_nosql


@dataclass
class Response:
    status: int
    body: bytes


class Requests:
    def get(self, url, **kwargs):
        if "%24ne" in url or "%24regex" in url:
            return Response(200, b"operator-accepted" + b"x" * 600)
        return Response(200, b"baseline")


def test_nosql_operator_differential_is_reported_as_unconfirmed_signal():
    asset = Asset("e1", AssetType.ENDPOINT, "search", "https://example.com/search?q=test")
    context = type("Context", (), {
        "assets": (asset,),
        "metadata": {"request_manager": Requests()},
    })()

    result = run_web_nosql(context)

    assert result.observations
    assert result.findings
    assert result.findings[0].type == "potential_nosql_injection_differential"
    assert result.findings[0].metadata["status"] == "needs_context_confirmation"
