#!/usr/bin/env tsx
/**
 * Generate cross-language Poseidon test vectors for vauban-verify.
 *
 * Imports the actual production functions from
 * `command-center/src/proof/poseidon-hasher.ts` (sprint-521, commit 139d76e).
 *
 * Output: tests/cross-lang-vectors.json — a JSON array of 30 vectors:
 *   - 15 step-leaf vectors  (kind: "step_leaf")
 *   - 15 merkle-root vectors (kind: "merkle_root")
 *
 * Each vector format:
 *   {
 *     name: string,
 *     kind: "step_leaf" | "merkle_root",
 *     input: {...} | { payloads: [...] },
 *     expected_hash: "0x..."   // for step_leaf: leaf hash; for merkle_root: root
 *   }
 *
 * Run via:
 *   pnpm tsx tools/vauban-verify/tests/generate-vectors.ts > tools/vauban-verify/tests/cross-lang-vectors.json
 *
 * CI verifies the JSON is bit-identical (regen drift = build failure).
 */

import {
  computePoseidonMerkleRoot,
  computeStepLeafHash,
} from "../../../src/proof/poseidon-hasher.js";

// ─── Vector definitions ──────────────────────────────────────────────────────

interface StepLeafVector {
  name: string;
  kind: "step_leaf";
  input: Record<string, unknown>;
  expected_hash: string;
}

interface MerkleVector {
  name: string;
  kind: "merkle_root";
  input: { payloads: Record<string, unknown>[] };
  expected_hash: string;
}

type Vector = StepLeafVector | MerkleVector;

// 15 step-leaf vectors: cover JCS edge cases + run_step shape variations
const stepLeafCases: Array<Pick<StepLeafVector, "name" | "input">> = [
  { name: "step_leaf_simple", input: { step: "init" } },
  { name: "step_leaf_int", input: { step: "build", ts: 1700000000 } },
  { name: "step_leaf_negative_int", input: { delta: -42 } },
  { name: "step_leaf_zero", input: { x: 0 } },
  { name: "step_leaf_neg_zero", input: { v: -0 } },
  { name: "step_leaf_large_int", input: { count: 9007199254740992 } },
  { name: "step_leaf_float_pi", input: { pi: 3.141592653589793 } },
  { name: "step_leaf_bool", input: { yes: true, no: false } },
  { name: "step_leaf_null", input: { v: null } },
  { name: "step_leaf_empty_str", input: { s: "" } },
  { name: "step_leaf_unicode_emoji", input: { msg: "hello 🌍" } },
  { name: "step_leaf_unicode_naive", input: { word: "naïve" } },
  { name: "step_leaf_quotes", input: { phrase: 'he said "hi"' } },
  { name: "step_leaf_keys_unsorted", input: { z: 1, a: 2, m: 3 } },
  {
    name: "step_leaf_run_step_realistic",
    input: {
      step_id: "step-001",
      type: "decision",
      agent: "BUILDER",
      run_id: "run-abc-123",
      status: "ok",
      ts: 1700000123,
      meta: { iteration: 2, score: 0.87 },
    },
  },
];

// 15 merkle-root vectors: cover sizes 1, 2, 3 (pad to 4), 4, 5, 8 + edge structures
const merkleCases: Array<Pick<MerkleVector, "name" | "input">> = [
  {
    name: "merkle_single_leaf",
    input: { payloads: [{ step: "only", ts: 1 }] },
  },
  {
    name: "merkle_two_leaves",
    input: { payloads: [{ step: "a" }, { step: "b" }] },
  },
  {
    name: "merkle_three_leaves_pads_to_four",
    input: {
      payloads: [{ step: "a" }, { step: "b" }, { step: "c" }],
    },
  },
  {
    name: "merkle_four_pinned_reference",
    input: {
      payloads: [
        { step: "init", ts: 1700000000 },
        { step: "build", ts: 1700000001 },
        { step: "test", ts: 1700000002 },
        { step: "deploy", ts: 1700000003 },
      ],
    },
  },
  {
    name: "merkle_five_leaves_pads_to_eight",
    input: {
      payloads: [
        { n: 0 },
        { n: 1 },
        { n: 2 },
        { n: 3 },
        { n: 4 },
      ],
    },
  },
  {
    name: "merkle_eight_leaves",
    input: {
      payloads: Array.from({ length: 8 }, (_, i) => ({
        step: `step_${i}`,
        idx: i,
      })),
    },
  },
  {
    name: "merkle_order_independence_a_b_c",
    input: { payloads: [{ n: 0 }, { n: 1 }, { n: 2 }] },
  },
  {
    name: "merkle_order_independence_c_b_a",
    input: { payloads: [{ n: 2 }, { n: 1 }, { n: 0 }] },
  },
  {
    name: "merkle_unicode_payloads",
    input: {
      payloads: [
        { msg: "café" },
        { msg: "naïve" },
        { msg: "hello 🌍" },
      ],
    },
  },
  {
    name: "merkle_mixed_types",
    input: {
      payloads: [
        { v: null },
        { v: true },
        { v: 0 },
        { v: "string" },
      ],
    },
  },
  {
    name: "merkle_nested_objects",
    input: {
      payloads: [
        { outer: { z: 1, a: 2 }, b: "x" },
        { outer: { a: 2, z: 1 }, b: "x" },
      ],
    },
  },
  {
    name: "merkle_large_int_leaf",
    input: {
      payloads: [{ count: 9007199254740992 }, { count: 9007199254740993 }],
    },
  },
  {
    name: "merkle_realistic_run_chain",
    input: {
      payloads: [
        {
          step_id: "s1",
          type: "decision",
          agent: "ARCHITECT",
          ts: 1700000001,
        },
        {
          step_id: "s2",
          type: "tool_call",
          agent: "BUILDER",
          ts: 1700000002,
        },
        {
          step_id: "s3",
          type: "verification",
          agent: "TESTER",
          ts: 1700000003,
        },
        {
          step_id: "s4",
          type: "summary",
          agent: "SCRIBE",
          ts: 1700000004,
        },
      ],
    },
  },
  {
    name: "merkle_padding_only_one_leaf",
    input: { payloads: [{ solo: true }] },
  },
  {
    name: "merkle_sixteen_leaves",
    input: {
      payloads: Array.from({ length: 16 }, (_, i) => ({
        idx: i,
        ts: 1700000100 + i,
      })),
    },
  },
];

// ─── Compute vectors ──────────────────────────────────────────────────────────

const vectors: Vector[] = [];

for (const c of stepLeafCases) {
  vectors.push({
    name: c.name,
    kind: "step_leaf",
    input: c.input,
    expected_hash: computeStepLeafHash(c.input),
  });
}

for (const c of merkleCases) {
  const leaves = c.input.payloads.map((p) => computeStepLeafHash(p));
  vectors.push({
    name: c.name,
    kind: "merkle_root",
    input: c.input,
    expected_hash: computePoseidonMerkleRoot(leaves),
  });
}

// ─── Emit JSON to stdout ──────────────────────────────────────────────────────

process.stdout.write(JSON.stringify(vectors, null, 2) + "\n");
