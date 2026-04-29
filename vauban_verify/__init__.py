"""
vauban-verify — offline cryptographic verifier for Vauban proof certificates.

Verifies Poseidon Merkle roots produced by the TypeScript reference
implementation in `command-center/src/proof/poseidon-hasher.ts` (sprint-521).

Pure Python; the only runtime dependency is `starknet-py`'s vendored
`poseidon_py` (algebraic Poseidon over felt252).

Public API:
    - compute_step_leaf_hash(payload)
    - compute_poseidon_merkle_root(leaves)
    - compute_poseidon_merkle_proof(leaves, leaf_index)
    - verify_poseidon_merkle_proof(leaf, proof, root)
    - POSEIDON_NULL_LEAF
    - jcs_canonicalize(payload)
    - load_certificate(path) / verify_offline(cert)
"""

from __future__ import annotations

from .cert import (
    RunProofCertificate,
    load_certificate,
    verify_offline,
)
from .jcs import jcs_canonicalize
from .poseidon import (
    POSEIDON_NULL_LEAF,
    STEP_MARKER_FELT,
    compute_poseidon_merkle_proof,
    compute_poseidon_merkle_root,
    compute_step_leaf_hash,
    verify_poseidon_merkle_proof,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "POSEIDON_NULL_LEAF",
    "STEP_MARKER_FELT",
    "RunProofCertificate",
    "compute_poseidon_merkle_proof",
    "compute_poseidon_merkle_root",
    "compute_step_leaf_hash",
    "jcs_canonicalize",
    "load_certificate",
    "verify_offline",
    "verify_poseidon_merkle_proof",
]
