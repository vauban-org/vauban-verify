"""
CLI entry-point for `vauban-verify`.

Usage:
    vauban-verify <path/to/cert.json>

Exit codes:
    0 — certificate verified successfully
    1 — certificate failed verification (mismatched root, malformed felt, etc.)
    2 — usage error (missing file, bad arguments)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .cert import VerifierError, load_certificate, verify_offline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vauban-verify",
        description=(
            "Offline verifier for Vauban Command Center proof certificates. "
            "Recomputes the Poseidon Merkle root from the certificate's "
            "decision chain and asserts it matches the anchored root. "
            "No network calls; trust derives from the on-chain anchor "
            "(verify cert.merkle_root against Starknet separately)."
        ),
    )
    parser.add_argument(
        "certificate",
        type=Path,
        help="Path to a Vauban run-proof certificate (JSON).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"vauban-verify {__version__}",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress success output; only emit on failure.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cert_path: Path = args.certificate
    if not cert_path.exists():
        print(f"vauban-verify: certificate not found: {cert_path}", file=sys.stderr)
        return 2

    try:
        cert = load_certificate(cert_path)
        verify_offline(cert)
    except VerifierError as exc:
        print(f"vauban-verify: VERIFICATION FAILED — {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:  # JSON decode errors, IO errors
        print(f"vauban-verify: cannot read certificate — {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(
            f"vauban-verify: OK — run_id={cert.run_id} "
            f"leaves={len(cert.decision_chain)} root={cert.merkle_root}"
        )
    return 0


def main() -> None:  # pragma: no cover — wrapper for entry-point
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
