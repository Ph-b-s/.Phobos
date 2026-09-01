"""Scanner registry and discovery."""

from collections.abc import Iterable

from .core.scanner import Scanner


class ScannerRegistry:
    """Central registry for scanner implementations."""

    def __init__(self, scanners: Iterable[Scanner] = ()) -> None:
        self._scanners: dict[str, Scanner] = {}
        for scanner in scanners:
            self.register(scanner)

    def register(self, scanner: Scanner) -> None:
        if not scanner.name or scanner.name == "unnamed":
            raise ValueError("scanner must define a unique name")
        if scanner.name in self._scanners:
            raise ValueError(f"scanner already registered: {scanner.name}")
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> Scanner:
        try:
            return self._scanners[name]
        except KeyError as exc:
            raise KeyError(f"unknown scanner: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._scanners))
