"""Safe, atomic filesystem storage for JSON scan artifacts."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


class EvidenceStore:
    def __init__(self, root: Path | str = ".phobos") -> None:
        self.root = Path(root)
        self.evidence_dir = self.root / "evidence"

    def initialize(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, name: str, payload: Any) -> Path:
        relative = Path(name)
        if not name or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("artifact name must be relative and stay inside the evidence store")
        if relative.suffix.lower() != ".json":
            raise ValueError("EvidenceStore only writes JSON artifacts")

        root = self.root.resolve()
        destination = (self.root / relative).resolve()
        if destination != root and root not in destination.parents:
            raise ValueError("artifact must stay inside the evidence store")

        destination.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(
            self._serialize(payload),
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        ) + "\n"
        temporary = destination.with_name(f".{destination.name}.tmp")
        temporary.write_text(serialized, encoding="utf-8")
        os.replace(temporary, destination)
        return destination

    def write_evidence(self, evidence_id: str, payload: Any) -> Path:
        if not evidence_id or Path(evidence_id).name != evidence_id or evidence_id in {".", ".."}:
            raise ValueError("evidence_id must be a simple filename-safe identifier")
        return self.write_json(f"evidence/{evidence_id}.json", payload)

    @staticmethod
    def _serialize(value: Any) -> Any:
        if hasattr(value, "to_dict"):
            return EvidenceStore._serialize(value.to_dict())
        if is_dataclass(value):
            return EvidenceStore._serialize(asdict(value))
        if isinstance(value, dict):
            return {str(key): EvidenceStore._serialize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [EvidenceStore._serialize(item) for item in value]
        if isinstance(value, Path):
            return str(value)
        if hasattr(value, "value"):
            return value.value
        return value
