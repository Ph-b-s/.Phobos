"""Command-line interface for the Phobos framework."""

import argparse

from .registry import ScannerRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phobos",
        description="Phobos — modular AI security testing framework",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("scanners", help="list registered scanners")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    registry = ScannerRegistry()

    if args.command == "scanners":
        for name in registry.names():
            print(name)
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
