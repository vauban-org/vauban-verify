"""
JCS (JSON Canonicalization Scheme — RFC 8785 subset) port for vauban-verify.

Mirrors the rules of `command-center/src/proof/poseidon-hasher.ts`:

  - object keys sorted lexicographically (recursive)
  - -0 normalised to 0
  - null preserved
  - arrays preserve their order
  - separators = (",", ":") — no extra whitespace
  - UTF-8 emitted as-is (ensure_ascii=False) to match `JSON.stringify` defaults

The TS source treats `-0` via `Object.is(value, -0)` and re-emits 0; Python's
equivalent is `math.copysign(1.0, x) < 0 and x == 0.0`, which matches both
`-0.0` floats and any negative-zero float that arrives via `json.loads`.

Integers are passed through unchanged (Python ints are arbitrary precision and
JSON re-emission via `json.dumps` matches V8's `JSON.stringify` for the value
ranges used in run_step payloads).
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["jcs_canonicalize", "normalize_value"]


def normalize_value(value: Any) -> Any:
    """Recursively normalise a JSON-serialisable value per JCS subset."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, float):
        # -0.0 → 0 (TS Object.is(value, -0) parity)
        if value == 0.0 and math.copysign(1.0, value) < 0:
            return 0
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [normalize_value(v) for v in value]
    if isinstance(value, tuple):
        return [normalize_value(v) for v in value]
    if isinstance(value, dict):
        # `json.dumps(sort_keys=True)` does the lexicographic sort at emit-time;
        # we still normalise children eagerly so nested -0 / lists are handled.
        return {k: normalize_value(v) for k, v in value.items()}
    raise TypeError(f"unsupported type for canonicalization: {type(value).__name__}")


def jcs_canonicalize(data: Any) -> str:
    """Return the canonical JSON string per the TS poseidon-hasher subset.

    Equivalent to:
        JSON.stringify(normalizeValue(data))
    in `src/proof/poseidon-hasher.ts`, except keys are emitted sorted at
    serialisation time via ``sort_keys=True`` (matches ``Object.keys(...).sort()``).
    """
    normalised = normalize_value(data)
    return json.dumps(
        normalised,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
