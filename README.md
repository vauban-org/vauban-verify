# vauban-verify

Offline cryptographic verifier for Vauban Command Center proof certificates.

Recomputes the Poseidon Merkle root from a certificate's `decision_chain` and
asserts it matches the certificate's anchored `merkle_root`. **No network
calls. No trust in our infrastructure or keys.** Trust derives entirely from
your independent on-chain read of the anchored root.

Pure Python; the only runtime dependency is
[`starknet-py`](https://github.com/software-mansion/starknet.py) (vendored
`poseidon-py` for native felt252 arithmetic).

The reference implementation lives in
`command-center/src/proof/poseidon-hasher.ts` (sprint-521, commit `139d76e`).
Cross-language parity is enforced by 30 deterministic test vectors checked in
CI — any drift between TypeScript and Python fails the build.

## Install

```bash
pip install vauban-verify
```

Or from source:

```bash
git clone https://github.com/seritalien/command-center
cd command-center/tools/vauban-verify
pip install -e ".[test]"
```

Requires Python ≥ 3.10.

## CLI usage

```bash
vauban-verify path/to/cert.json
# → vauban-verify: OK — run_id=<…> leaves=<N> root=0x…
echo $?  # 0 = valid, 1 = tampered/invalid, 2 = usage error
```

## Library usage

```python
from vauban_verify import (
    compute_step_leaf_hash,
    compute_poseidon_merkle_root,
    verify_poseidon_merkle_proof,
    load_certificate,
    verify_offline,
)

# Recompute a leaf from a run_step payload
leaf = compute_step_leaf_hash({"step_id": "s1", "type": "decision", "agent": "BUILDER"})

# Recompute a Merkle root from a list of leaves
root = compute_poseidon_merkle_root([leaf, ...])

# Verify a sibling-path inclusion proof
ok = verify_poseidon_merkle_proof(leaf, proof, root)

# Verify a full certificate offline
cert = load_certificate("cert.json")
verify_offline(cert)  # raises VerifierError on any inconsistency
```

## Security model

| Threat                                  | Defended by                                                |
|-----------------------------------------|-------------------------------------------------------------|
| Compromised Vauban infrastructure       | This verifier runs offline; never contacts our servers      |
| Compromised Vauban signing keys         | The verifier asserts only Merkle consistency; trust the chain anchor, not us |
| Hash-function preimage attacks          | Poseidon over felt252 — STARK-friendly, post-quantum sound  |
| Drift between TS reference and verifier | 30 cross-language vectors gated in CI (regen + diff)        |

The only thing that *should* be trusted is the on-chain `merkle_root`. Read it
yourself from Starknet (e.g. via `starknet-py`'s `read_contract`) and compare
to `cert.merkle_root` — this verifier proves the rest of the certificate is
internally consistent with that root.

## Algorithm reference

* **JCS canonicalisation** (RFC 8785 subset): keys sorted recursively, `-0 → 0`,
  arrays preserve order, `JSON.stringify`-equivalent emission.
* **Step leaf**: `Poseidon([0x1, sha256_to_31_felt(JCS(payload)), step_marker])`.
* **Merkle**: leaves sorted lexicographically, padded with
  `Poseidon([0, 0])` to next power of 2, commutative pair-merge with
  `Poseidon([min, max])`.

Hex output matches `starknet.js`: lowercase, `0x`-prefixed, no leading-zero
padding (e.g. `POSEIDON_NULL_LEAF =
0x1fb7169b936dd880cb7ebc50e932a495a60e0084cdab94a681040cb4006e1a0`).

## Publishing

Releases are published to PyPI via Trusted Publishers (sigstore-signed) using
the `.github/workflows/vauban-verify-publish.yml` workflow. Tag a release with
`vauban-verify-vX.Y.Z` to trigger publication.

## License

MIT.
