"""
RunProofCertificate — minimal model + offline verifier.

A proof certificate is a JSON document emitted by the Command Center after a
run completes. It contains:

    - merkle_root:    the Poseidon Merkle root anchored on Starknet
    - decision_chain: ordered list of run_step entries, each carrying its
                      own `leaf_hash_poseidon` (felt252 hex)
    - run_id:         the Command Center run identifier
    - anchored_at:    ISO-8601 timestamp of the on-chain anchor (informational)

`verify_offline(cert)` recomputes the Merkle root from the chain leaf hashes
and asserts it equals `cert.merkle_root`. No network calls; the operator's
chain hash is the trust anchor (operator runs `starknet.read_contract` to fetch
it independently — that comparison happens *outside* this verifier).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from .poseidon import compute_poseidon_merkle_root

__all__ = [
    "RunProofCertificate",
    "load_certificate",
    "verify_offline",
    "VerifierError",
]


_FELT252_RE = re.compile(r"^0x[0-9a-f]{1,63}$")


class VerifierError(ValueError):
    """Raised when a certificate is structurally invalid or tampered."""


@dataclass
class RunProofCertificate:
    """Minimal proof certificate model — only fields required for verification."""

    run_id: str
    merkle_root: str
    decision_chain: List[Dict[str, Any]]
    anchored_at: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunProofCertificate":
        if not isinstance(data, dict):
            raise VerifierError(
                f"certificate must be a JSON object, got {type(data).__name__}"
            )
        for required in ("run_id", "merkle_root", "decision_chain"):
            if required not in data:
                raise VerifierError(f"certificate missing required field: {required}")
        chain = data["decision_chain"]
        if not isinstance(chain, list):
            raise VerifierError(
                f"decision_chain must be a list, got {type(chain).__name__}"
            )
        return cls(
            run_id=str(data["run_id"]),
            merkle_root=str(data["merkle_root"]),
            decision_chain=chain,
            anchored_at=str(data.get("anchored_at", "")),
            raw=data,
        )


def load_certificate(path: str | Path) -> RunProofCertificate:
    """Load a certificate from a JSON file path."""
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    return RunProofCertificate.from_dict(data)


def _validate_felt(felt: str, *, where: str) -> None:
    if not isinstance(felt, str) or not _FELT252_RE.match(felt):
        raise VerifierError(
            f"{where}: invalid felt252 hex (expected lowercase /^0x[0-9a-f]{{1,63}}$/), got {felt!r}"
        )


def verify_offline(cert: RunProofCertificate) -> bool:
    """Verify a certificate offline — no network, no operator trust required.

    Steps:
        1. Validate `merkle_root` is a valid felt252.
        2. Extract `leaf_hash_poseidon` from every chain entry; validate each.
        3. Recompute Poseidon Merkle root from those leaves.
        4. Assert recomputed root == `cert.merkle_root`.

    Returns:
        True iff the certificate is internally consistent.
    Raises:
        VerifierError: on any structural issue. Never returns False — either the
        certificate parses and verifies, or it raises.
    """
    _validate_felt(cert.merkle_root, where="merkle_root")

    if not cert.decision_chain:
        raise VerifierError("decision_chain is empty — no leaves to verify")

    leaves: List[str] = []
    for i, step in enumerate(cert.decision_chain):
        if not isinstance(step, dict):
            raise VerifierError(
                f"decision_chain[{i}]: expected object, got {type(step).__name__}"
            )
        leaf = step.get("leaf_hash_poseidon")
        if leaf is None:
            raise VerifierError(f"decision_chain[{i}]: missing leaf_hash_poseidon")
        _validate_felt(leaf, where=f"decision_chain[{i}].leaf_hash_poseidon")
        leaves.append(leaf)

    recomputed = compute_poseidon_merkle_root(leaves)
    if recomputed != cert.merkle_root:
        raise VerifierError(
            f"merkle_root mismatch: recomputed={recomputed} cert={cert.merkle_root}"
        )
    return True
