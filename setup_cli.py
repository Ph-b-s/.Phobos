from __future__ import annotations

import json

from ai import AIConfig, LocalMistralClient
from ai_setup import prepare_model, setup_status


def run_setup() -> int:
    config = AIConfig.from_env()
    before = setup_status(config.base_url, model_name=config.model)
    model = prepare_model(LocalMistralClient(config))
    after = setup_status(config.base_url, model_name=model.name)
    print(json.dumps({"before": before, "after": after}, indent=2))
    return 0
