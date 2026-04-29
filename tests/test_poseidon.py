"""
Cross-language Poseidon parity tests for vauban-verify.

Loads `tests/cross-lang-vectors.json` (generated from the TypeScript reference
implementation in `command-center/src/proof/poseidon-hasher.ts`, sprint-521,
commit 139d76e) and asserts every Python-recomputed hash matches the TS hash
bit-identically.

The vector file ships pinned in the repo. CI re-runs the TS generator and
diffs against this file — any drift fails the build, ensuring TS and Python
remain bit-for-bit synchronised.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

import pytest

# Make the package importable when running pytest from `tools/vauban-verify/`
PKG_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG_DIR))

from vauban_verify import (  # noqa: E402
    POSEIDON_NULL_LEAF,
    compute_poseidon_merkle_proof,
    compute_poseidon_merkle_root,
    compute_step_leaf_hash,
    verify_poseidon_merkle_proof,
)

VECTORS_PATH = Path(__file__).resolve().parent / "cross-lang-vectors.json"


@pytest.fixture(scope="module")
def vectors() -> list[dict]:
    with VECTORS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


# ─── coverage / shape ────────────────────────────────────────────────────────


def test_at_least_30_vectors(vectors: list[dict]) -> None:
    assert len(vectors) >= 30, "expected at least 30 cross-lang vectors"


def test_split_at_least_15_each(vectors: list[dict]) -> None:
    leaf_count = sum(1 for v in vectors if v["kind"] == "step_leaf")
    root_count = sum(1 for v in vectors if v["kind"] == "merkle_root")
    assert leaf_count >= 15, f"expected ≥15 step_leaf vectors, got {leaf_count}"
    assert root_count >= 15, f"expected ≥15 merkle_root vectors, got {root_count}"


# ─── parametrised parity ─────────────────────────────────────────────────────


def _all_vectors() -> list[dict]:
    """Load vectors at collection time so each gets its own test id."""
    with VECTORS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize(
    "vector",
    _all_vectors(),
    ids=[v["name"] for v in _all_vectors()],
)
def test_python_matches_typescript(vector: dict) -> None:
    """For each vector: recompute the hash in Python and assert ==."""
    expected: str = vector["expected_hash"]
    if vector["kind"] == "step_leaf":
        actual = compute_step_leaf_hash(vector["input"])
    elif vector["kind"] == "merkle_root":
        payloads = vector["input"]["payloads"]
        leaves: List[str] = [compute_step_leaf_hash(p) for p in payloads]
        actual = compute_poseidon_merkle_root(leaves)
    else:  # pragma: no cover — defensive
        pytest.fail(f"unknown vector kind: {vector['kind']!r}")

    assert actual == expected, (
        f"cross-lang mismatch for {vector['name']!r}: python={actual} ts={expected}"
    )


# ─── pinned constants from the TS test suite ────────────────────────────────


def test_null_leaf_matches_typescript_pin() -> None:
    """POSEIDON_NULL_LEAF = Poseidon([0, 0]) — pinned 2026-04-28 in TS tests."""
    assert (
        POSEIDON_NULL_LEAF
        == "0x1fb7169b936dd880cb7ebc50e932a495a60e0084cdab94a681040cb4006e1a0"
    )


def test_four_leaf_reference_root_matches_typescript_pin() -> None:
    """4-leaf reference root pinned in `tests/proof/poseidon-hasher.test.ts`."""
    payloads = [
        {"step": "init", "ts": 1700000000},
        {"step": "build", "ts": 1700000001},
        {"step": "test", "ts": 1700000002},
        {"step": "deploy", "ts": 1700000003},
    ]
    leaves = [compute_step_leaf_hash(p) for p in payloads]
    root = compute_poseidon_merkle_root(leaves)
    assert root == "0x553705d38a32cf531ca2ae343abf9e85d3ab515f63bc158c7cd20c66a4a2c8c"


def test_single_leaf_reference_root_matches_typescript_pin() -> None:
    """Single-leaf root = leaf itself (no padding) — pinned 2026-04-28."""
    leaf = compute_step_leaf_hash({"step": "only", "ts": 1})
    root = compute_poseidon_merkle_root([leaf])
    assert root == leaf
    assert root == "0x3728b6ce58c272be77f435d3f4f32b9ac15726f1760420384fc9bb469e016d0"


# ─── algorithmic invariants (Python-side) ────────────────────────────────────


def test_jcs_permuted_keys_yield_same_leaf() -> None:
    a = compute_step_leaf_hash({"z": 1, "a": 2, "b": "run_step"})
    b = compute_step_leaf_hash({"a": 2, "b": "run_step", "z": 1})
    assert a == b


def test_jcs_neg_zero_equals_zero() -> None:
    assert compute_step_leaf_hash({"v": -0.0}) == compute_step_leaf_hash({"v": 0})


def test_merkle_order_invariance() -> None:
    leaves = [
        compute_step_leaf_hash({"n": 0}),
        compute_step_leaf_hash({"n": 1}),
        compute_step_leaf_hash({"n": 2}),
    ]
    r1 = compute_poseidon_merkle_root(leaves)
    r2 = compute_poseidon_merkle_root(list(reversed(leaves)))
    assert r1 == r2


def test_merkle_root_changes_when_leaf_changes() -> None:
    leaves = [
        compute_step_leaf_hash({"n": 0}),
        compute_step_leaf_hash({"n": 1}),
    ]
    modified = [compute_step_leaf_hash({"n": 99}), leaves[1]]
    assert compute_poseidon_merkle_root(leaves) != compute_poseidon_merkle_root(
        modified
    )


def test_merkle_proof_round_trip() -> None:
    raw = [compute_step_leaf_hash({"step": f"step_{i}", "idx": i}) for i in range(8)]
    target = raw[2]
    sorted_leaves = sorted(raw)
    sorted_idx = sorted_leaves.index(target)
    root = compute_poseidon_merkle_root(raw)
    proof = compute_poseidon_merkle_proof(raw, sorted_idx)
    assert verify_poseidon_merkle_proof(target, proof, root) is True


def test_merkle_proof_rejects_wrong_leaf() -> None:
    raw = [compute_step_leaf_hash({"step": f"step_{i}", "idx": i}) for i in range(8)]
    sorted_leaves = sorted(raw)
    root = compute_poseidon_merkle_root(raw)
    proof = compute_poseidon_merkle_proof(raw, sorted_leaves.index(raw[2]))
    impostor = compute_step_leaf_hash({"step": "impostor", "idx": 99})
    assert verify_poseidon_merkle_proof(impostor, proof, root) is False


def test_compute_poseidon_merkle_root_rejects_empty() -> None:
    with pytest.raises(ValueError):
        compute_poseidon_merkle_root([])
