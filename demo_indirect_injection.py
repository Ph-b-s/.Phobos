"""Run the indirect prompt-injection procedure against the local demo target."""
from __future__ import annotations

import argparse
import threading

from assessment_engine import AssessmentEngine
from ai_testing import build_indirect_canary, build_test_queries, new_canary
from browser_adapter import BrowserAdapterError, PlaywrightBrowserSession
from demo_target import start_demo_server
from scope import ScopeValidator


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Phobos against the local vulnerable demo target")
    parser.add_argument("--impact", action="store_true", help="also execute the demo state-changing action")
    args = parser.parse_args()

    server, target = start_demo_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        scope = ScopeValidator(("127.0.0.1",), allow_private_targets=True)
        canary = new_canary()
        baseline: dict[str, str] = {}
        session = PlaywrightBrowserSession(scope, headless=True)
        try:
            def discover_chat(_):
                session.goto(f"{target}/chat?product=demo")
                return [
                    __import__("ai_testing").Observation(
                        "chat_surface",
                        "local live-chat surface discovered",
                        source="demo",
                        evidence=(session.title(),),
                    )
                ]

            def map_ai_api(_):
                session.goto(f"{target}/capabilities")
                return [
                    __import__("ai_testing").Observation(
                        "tool_inventory",
                        "demo exposes delete_account capability",
                        source="demo",
                        evidence=(session.text(),),
                    )
                ]

            def map_tool_arguments(_):
                return [
                    __import__("ai_testing").Observation(
                        "tool_arguments",
                        "demo delete_account requires the authenticated session",
                        source="demo",
                    )
                ]

            def establish_auth_boundary(_):
                session.goto(f"{target}/login")
                session.fill('input[name="username"]', "phobos-test")
                session.fill('input[name="password"]', "phobos-test")
                session.click('button')
                session.goto(f"{target}/account")
                return [
                    __import__("ai_testing").Observation(
                        "authenticated_tool_execution",
                        "assessment identity is authenticated and account is active",
                        source="demo",
                        evidence=(session.text(),),
                    )
                ]

            def discover_indirect_input(_):
                session.goto(f"{target}/review")
                return [
                    __import__("ai_testing").Observation(
                        "indirect_input_source",
                        "stored review content is consumed by the live chat",
                        source="demo",
                    )
                ]

            def seed_canary(_):
                session.goto(f"{target}/review")
                session.fill('input[name="product"]', "demo")
                session.fill("textarea[name=\"review\"]", build_indirect_canary(canary))
                session.click('button')
                return [
                    __import__("ai_testing").Observation(
                        "canary_seeded",
                        "unique canary stored in the indirect review source",
                        source="demo",
                        canary=canary,
                    )
                ]

            def prove_influence(_):
                session.goto(f"{target}/chat?product=demo")
                baseline["text"] = session.text()
                session.goto(f"{target}/chat?product=demo")
                text = session.text()
                observations = [
                    __import__("ai_testing").Observation(
                        "baseline_compared",
                        "clean baseline captured before induced observation",
                        source="demo",
                        evidence=(baseline["text"],),
                    )
                ]
                if canary in text and canary not in baseline["text"]:
                    observations.append(
                        __import__("ai_testing").Observation(
                            "canary_observed",
                            "exact canary returned through the LLM workflow",
                            source="demo",
                            evidence=(text,),
                            canary=canary,
                        )
                    )
                return observations

            def validate_impact(_):
                session.goto(f"{target}/chat?product=demo&impact=1")
                chat = session.text()
                session.goto(f"{target}/account")
                return [
                    __import__("ai_testing").Observation(
                        "state_change_validated",
                        "same influenced path caused the controlled demo account state change",
                        source="demo",
                        evidence=(chat, session.text()),
                        canary=canary,
                    )
                ]

            handlers = {
                "discover_chat": discover_chat,
                "map_ai_api": map_ai_api,
                "map_tool_arguments": map_tool_arguments,
                "establish_auth_boundary": establish_auth_boundary,
                "discover_indirect_input": discover_indirect_input,
                "seed_canary": seed_canary,
                "prove_influence": prove_influence,
                "validate_impact": validate_impact,
            }

            run = AssessmentEngine().run(
                __import__("ai_testing").INDIRECT_PROMPT_INJECTION_PROCEDURE,
                handlers,
                canary=canary,
                allow_state_change=args.impact,
                metadata={"target": target, "demo": True},
            )
            print(run.result.to_dict())
            print(f"queries={build_test_queries('demo')}")
            return 0 if run.result.status in {"confirmed", "strong_signal", "suspected", "not_confirmed"} else 2
        finally:
            session.close()
    except BrowserAdapterError as exc:
        print(f"Browser adapter unavailable: {exc}")
        print("Install browser support with: python -m pip install -e '.[browser]' && playwright install chromium")
        return 2
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
