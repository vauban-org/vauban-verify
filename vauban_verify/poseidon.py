"""
Pure-Python port of `command-center/src/proof/poseidon-hasher.ts`.

Cross-language guarantees:
    * `compute_step_leaf_hash` returns the same felt252 hex as the TS function
      for any JCS-equivalent payload.
    * `compute_poseidon_merkle_root` returns the same root as the TS function
      for the same set of leaves (order-invariant by sort + commutative merge).
    * Hex format matches `starknet.js`: lowercase, "0x"-prefixed, NO leading-zero
      padding (matches Python's built-in `hex()` and `starknet.js`'s
      `BigInt.toString(16)`). Comparing hex strings as Python `str` reproduces
      JavaScript `<=` semantics, which is what the TS commutative pair-sort uses.

Algorithm (computeStepLeafHash):
    1. JCS-canonicalise the payload (UTF-8 bytes)
    2. SHA-256 the bytes → 32-byte digest
    3. First 31 bytes (62 hex chars) → felt252-safe value (matches sha256To31Felt)
    4. Poseidon([0x1, sha_felt, run_step_marker]) → felt252 leaf

Merkle:
    * Leaves sorted lexicographically (Python str sort == TS sort default)
    * Padded with NULL_LEAF = Poseidon([0x0, 0x0]) to next power of 2
    * Each pair commutatively sorted before Poseidon([a, b])
"""

from __future__ import annotations

import hashlib
from typing import Any, List

# starknet-py vendors poseidon-py for native felt arithmetic.
from poseidon_py.poseidon_hash import poseidon_hash_many

from .jcs import jcs_canonicalize

__all__ = [
    "POSEIDON_NULL_LEAF",
    "STEP_MARKER_FELT",
    "compute_poseidon_merkle_proof",
    "compute_poseidon_merkle_root",
    "compute_step_leaf_hash",
    "verify_poseidon_merkle_proof",
]


# ─── felt helpers ─────────────────────────────────────────────────────────────


def _hex_to_int(felt: str) -> int:
    """Parse a `0x`-prefixed (or bare) hex string into an int."""
    if felt.startswith("0x") or felt.startswith("0X"):
        return int(felt[2:], 16) if felt[2:] else 0
    return int(felt, 16) if felt else 0


def _int_to_felt_hex(value: int) -> str:
    """Format an int as lowercase `0x` hex with no leading-zero padding.

    Matches `starknet.js`'s `BigInt.toString(16)` output and the on-chain
    felt252 wire format used in the TS reference.
    """
    return hex(value)


def _poseidon(values: List[Any]) -> str:
    """Wrap `poseidon_hash_many` with hex-string IO matching the TS API."""
    ints = [_hex_to_int(v) if isinstance(v, str) else int(v) for v in values]
    return _int_to_felt_hex(poseidon_hash_many(ints))


def _sha256_to_31_felt(hex_digest: str) -> str:
    """First 31 bytes (62 hex chars) of a SHA-256 hex digest as a felt252.

    Matches `sha256To31Felt` in the TS reference: drops the 32nd byte to fit
    inside felt252 bounds.
    """
    return "0x" + hex_digest[:62]


# ─── constants ────────────────────────────────────────────────────────────────


# Pre-compute Poseidon([0, 0]) for padding the Merkle base layer.
# Pinned to TS reference: 0x1fb7169b936dd880cb7ebc50e932a495a60e0084cdab94a681040cb4006e1a0
POSEIDON_NULL_LEAF: str = _poseidon(["0x0", "0x0"])


# Domain separator: UTF-8 "run_step" right-padded as felt252.
# In the TS source: 0x + Buffer.from("run_step", "utf8").toString("hex").padStart(62, "0")
# That produces a 31-byte felt where the *low* bytes carry the ASCII (left-padded
# with zero bytes). Python equivalent below preserves the same bit pattern.
STEP_MARKER_FELT: str = "0x" + "run_step".encode("utf-8").hex().rjust(62, "0")


# ─── leaf hash ────────────────────────────────────────────────────────────────


def compute_step_leaf_hash(payload: dict) -> str:
    """Compute a Poseidon leaf hash for a run_step payload.

    Bit-identical to `computeStepLeafHash` in the TS reference for every
    JCS-equivalent input. Output: lowercase `0x` hex felt252.
    """
    canonical = jcs_canonicalize(payload)
    sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return _poseidon(["0x1", _sha256_to_31_felt(sha), STEP_MARKER_FELT])


# ─── Merkle helpers ───────────────────────────────────────────────────────────


def _next_power_of_2(n: int) -> int:
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


def _build_base_layer(leaves: List[str]) -> List[str]:
    """Sort leaves lexicographically and pad with NULL_LEAF to next pow2.

    The lexicographic sort matches TS `[...leaves].sort()` (default JS string
    compare = Unicode codepoint compare = Python str compare for ASCII hex).
    """
    sorted_leaves = sorted(leaves)
    target = _next_power_of_2(len(sorted_leaves))
    while len(sorted_leaves) < target:
        sorted_leaves.append(POSEIDON_NULL_LEAF)
    return sorted_leaves


def _build_tree_layers(base_layer: List[str]) -> List[List[str]]:
    """Build the full Merkle layer stack — `tree[-1] == [root]`."""
    tree: List[List[str]] = [base_layer]
    current = base_layer
    while len(current) > 1:
        nxt: List[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1]
            # Commutative pair-sort: STRING comparison (TS `left <= right`).
            a, b = (left, right) if left <= right else (right, left)
            nxt.append(_poseidon([a, b]))
        tree.append(nxt)
        current = nxt
    return tree


# ─── public Merkle API ───────────────────────────────────────────────────────


def compute_poseidon_merkle_root(leaves: List[str]) -> str:
    """Compute the Poseidon Merkle root from a list of leaf felts.

    Args:
        leaves: at least one `0x` hex felt252.
    Returns:
        Lowercase `0x` hex felt252 root.
    Raises:
        ValueError: if leaves is empty.
    """
    if not leaves:
        raise ValueError(
            "[vauban-verify] compute_poseidon_merkle_root: at least 1 leaf required"
        )
    base = _build_base_layer(leaves)
    tree = _build_tree_layers(base)
    return tree[-1][0]


def compute_poseidon_merkle_proof(leaves: List[str], leaf_index: int) -> List[str]:
    """Sibling-path proof for the leaf at `leaf_index` in the sorted+padded base.

    Indices refer to the SORTED+PADDED layer (NOT the input order). Use
    `sorted(leaves).index(leaf)` to translate from leaf value to index.
    """
    if not leaves:
        raise ValueError(
            "[vauban-verify] compute_poseidon_merkle_proof: at least 1 leaf required"
        )
    base = _build_base_layer(leaves)
    tree = _build_tree_layers(base)

    proof: List[str] = []
    idx = leaf_index
    for level in range(len(tree) - 1):
        layer = tree[level]
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        if sibling_idx < len(layer):
            proof.append(layer[sibling_idx])
        idx //= 2
    return proof


def verify_poseidon_merkle_proof(leaf: str, proof: List[str], root: str) -> bool:
    """Verify a sibling-path Merkle proof. Returns True iff proof is valid."""
    current = leaf
    for sibling in proof:
        a, b = (current, sibling) if current <= sibling else (sibling, current)
        current = _poseidon([a, b])
    return current == root
