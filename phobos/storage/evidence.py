"""Filesystem storage for scan state, assets, graph and evidence."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


class EvidenceStore:
    """Writes a stable, human-readable .phobos scan workspace."""

    def __init__(self, root: Path | str = ".phobos") -> None:
        self.root = Path(root)
        self.evidence_dir = self.root / "evidence"

    def initialize(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, name: str, payload: Any) -> Path:
        self.initialize()
        destination = self.root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        serializable = self._serialize(payload)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(
            json.dumps(serializable, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination

    def write_evidence(self, evidence_id: str, payload: Any) -> Path:
        if not evidence_id or "/" in evidence_id or "\\" in evidence_id:
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
