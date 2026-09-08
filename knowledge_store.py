"""Shared security knowledge state for all Phobos modules.

The knowledge store is the authoritative in-memory state exchanged between
reconnaissance, vulnerability modules, AI reasoning, and cross-layer analysis.
It deliberately separates *facts observed by modules* from conclusions such as
findings. Modules may add information and query prior information, but the store
is the single exchange boundary so modules do not need direct references to one
another.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from models import Asset, Finding

MAX_OBSERVATIONS = 10_000
MAX_FACTS = 10_000
MAX_EVENTS = 20_000


@dataclass(frozen=True, slots=True)
class SecurityObservation:
    """A bounded observation emitted by a module or execution adapter."""

    id: str
    kind: str
    source: str
    description: str
    asset_ids: tuple[str, ...] = ()
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.kind.strip() or not self.source.strip():
            raise ValueError("observation id, kind, and source are required")
        if not self.description.strip():
            raise ValueError("observation description is required")
        if not 0 <= self.confidence <= 1:
            raise ValueError("observation confidence must be between 0 and 1")
        object.__setattr__(self, "asset_ids", tuple(dict.fromkeys(item.strip() for item in self.asset_ids if item.strip())))
        object.__setattr__(self, "data", dict(self.data))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source": self.source,
            "description": self.description,
            "asset_ids": list(self.asset_ids),
            "data": self.data,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class SecurityFact:
    """A normalized cross-module fact derived from one or more observations."""

    key: str
    value: Any
    source: str
    confidence: float = 1.0
    observation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.key.strip() or not self.source.strip():
            raise ValueError("fact key and source are required")
        if not 0 <= self.confidence <= 1:
            raise ValueError("fact confidence must be between 0 and 1")
        object.__setattr__(self, "observation_ids", tuple(dict.fromkeys(item.strip() for item in self.observation_ids if item.strip())))

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "observation_ids": list(self.observation_ids),
        }


class KnowledgeStore:
    """Authoritative shared state used by every scanner subsystem."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._observations: dict[str, SecurityObservation] = {}
        self._facts: dict[str, SecurityFact] = {}
        self._findings: dict[str, Finding] = {}
        self._events: list[dict[str, Any]] = []

    @property
    def assets(self) -> tuple[Asset, ...]:
        return tuple(self._assets.values())

    @property
    def observations(self) -> tuple[SecurityObservation, ...]:
        return tuple(self._observations.values())

    @property
    def facts(self) -> tuple[SecurityFact, ...]:
        return tuple(self._facts.values())

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(self._findings.values())

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def add_asset(self, asset: Asset) -> Asset:
        existing = self._assets.get(asset.id)
        if existing is not None and existing != asset:
            raise ValueError(f"asset already exists with different data: {asset.id}")
        self._assets[asset.id] = asset
        self._record("asset_added", {"asset_id": asset.id, "type": asset.type.value})
        return asset

    def add_assets(self, assets: Iterable[Asset]) -> None:
        for asset in assets:
            self.add_asset(asset)

    def add_observation(self, observation: SecurityObservation) -> SecurityObservation:
        if observation.id not in self._observations and len(self._observations) >= MAX_OBSERVATIONS:
            raise ValueError("knowledge-store observation limit exceeded")
        existing = self._observations.get(observation.id)
        if existing is not None and existing != observation:
            raise ValueError(f"observation already exists with different data: {observation.id}")
        self._observations[observation.id] = observation
        self._record("observation_added", {"observation_id": observation.id, "kind": observation.kind, "source": observation.source})
        return observation

    def add_fact(self, fact: SecurityFact) -> SecurityFact:
        if fact.key not in self._facts and len(self._facts) >= MAX_FACTS:
            raise ValueError("knowledge-store fact limit exceeded")
        self._facts[fact.key] = fact
        self._record("fact_updated", {"key": fact.key, "source": fact.source})
        return fact

    def add_finding(self, finding: Finding) -> Finding:
        if finding.id not in self._findings and len(self._findings) >= MAX_EVENTS:
            raise ValueError("knowledge-store finding limit exceeded")
        existing = self._findings.get(finding.id)
        if existing is not None and existing != finding:
            raise ValueError(f"finding already exists with different data: {finding.id}")
        self._findings[finding.id] = finding
        self._record("finding_added", {"finding_id": finding.id, "type": finding.type})
        return finding

    def observations_for_asset(self, asset_id: str) -> tuple[SecurityObservation, ...]:
        return tuple(item for item in self._observations.values() if asset_id in item.asset_ids)

    def observations_by_kind(self, kind: str) -> tuple[SecurityObservation, ...]:
        return tuple(item for item in self._observations.values() if item.kind == kind)

    def facts_by_prefix(self, prefix: str) -> tuple[SecurityFact, ...]:
        return tuple(item for item in self._facts.values() if item.key.startswith(prefix))

    def findings_by_type(self, finding_type: str) -> tuple[Finding, ...]:
        return tuple(item for item in self._findings.values() if item.type == finding_type)

    def has_fact(self, key: str) -> bool:
        return key in self._facts

    def get_fact(self, key: str, default: Any = None) -> Any:
        fact = self._facts.get(key)
        return default if fact is None else fact.value

    def context(self, *, max_items: int = 500) -> dict[str, Any]:
        """Return bounded structured state suitable for module/AI consumption."""
        if max_items < 1:
            raise ValueError("max_items must be positive")
        return {
            "assets": [asset.to_dict() for asset in self.assets[:max_items]],
            "observations": [item.to_dict() for item in self.observations[:max_items]],
            "facts": [item.to_dict() for item in self.facts[:max_items]],
            "findings": [item.to_dict() for item in self.findings[:max_items]],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "assets": [asset.to_dict() for asset in self.assets],
            "observations": [item.to_dict() for item in self.observations],
            "facts": [item.to_dict() for item in self.facts],
            "findings": [item.to_dict() for item in self.findings],
            "events": list(self.events),
        }

    def _record(self, event_type: str, data: dict[str, Any]) -> None:
        if len(self._events) >= MAX_EVENTS:
            return
        self._events.append({"type": event_type, "data": dict(data)})
