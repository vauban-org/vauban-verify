"""
CLI tests for `vauban-verify`.

Exercises:
    - exit code 0 on a valid synthetic certificate
    - exit code 1 when the merkle_root is tampered
    - exit code 1 when a leaf hash is malformed
    - exit code 2 when the certificate file does not exist
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PKG_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG_DIR))

from vauban_verify import compute_poseidon_merkle_root, compute_step_leaf_hash  # noqa: E402
from vauban_verify.cli import run  # noqa: E402


def _build_valid_cert() -> dict:
    payloads = [
        {"step_id": "s1", "type": "decision", "agent": "ARCHITECT", "ts": 1700000001},
        {"step_id": "s2", "type": "tool_call", "agent": "BUILDER", "ts": 1700000002},
        {"step_id": "s3", "type": "verification", "agent": "TESTER", "ts": 1700000003},
        {"step_id": "s4", "type": "summary", "agent": "SCRIBE", "ts": 1700000004},
    ]
    leaves = [compute_step_leaf_hash(p) for p in payloads]
    root = compute_poseidon_merkle_root(leaves)
    return {
        "run_id": "run-cli-fixture-001",
        "anchored_at": "2026-04-28T12:00:00Z",
        "merkle_root": root,
        "decision_chain": [
            {**p, "leaf_hash_poseidon": leaf}
            for p, leaf in zip(payloads, leaves, strict=True)
        ],
    }


def test_cli_valid_certificate_returns_zero(tmp_path, capsys):
    cert = _build_valid_cert()
    cert_path = tmp_path / "cert.json"
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    rc = run([str(cert_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK" in out
    assert cert["merkle_root"] in out


def test_cli_quiet_mode_no_stdout_on_success(tmp_path, capsys):
    cert = _build_valid_cert()
    cert_path = tmp_path / "cert.json"
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    rc = run([str(cert_path), "--quiet"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_cli_tampered_root_returns_one(tmp_path, capsys):
    cert = _build_valid_cert()
    # Flip a single hex char in the root
    bad_root = cert["merkle_root"][:-1] + (
        "0" if cert["merkle_root"][-1] != "0" else "1"
    )
    cert["merkle_root"] = bad_root
    cert_path = tmp_path / "tampered.json"
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    rc = run([str(cert_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "VERIFICATION FAILED" in err
    assert "merkle_root mismatch" in err


def test_cli_tampered_leaf_returns_one(tmp_path, capsys):
    cert = _build_valid_cert()
    # Replace one leaf hash with a different (valid felt) — root recompute fails
    cert["decision_chain"][0]["leaf_hash_poseidon"] = (
        "0x1111111111111111111111111111111111111111111111111111111111111"
    )
    cert_path = tmp_path / "tampered_leaf.json"
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    rc = run([str(cert_path)])
    assert rc == 1


def test_cli_malformed_felt_returns_one(tmp_path, capsys):
    cert = _build_valid_cert()
    cert["decision_chain"][0]["leaf_hash_poseidon"] = "NOT_A_HEX_VALUE"
    cert_path = tmp_path / "malformed.json"
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    rc = run([str(cert_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "invalid felt252" in err


def test_cli_missing_decision_chain_returns_one(tmp_path, capsys):
    cert_path = tmp_path / "incomplete.json"
    cert_path.write_text(
        json.dumps({"run_id": "x", "merkle_root": "0xabc"}),
        encoding="utf-8",
    )
    rc = run([str(cert_path)])
    assert rc == 1


def test_cli_missing_file_returns_two(tmp_path, capsys):
    rc = run([str(tmp_path / "does_not_exist.json")])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_cli_invalid_json_returns_two(tmp_path, capsys):
    cert_path = tmp_path / "bad.json"
    cert_path.write_text("{not valid json", encoding="utf-8")
    rc = run([str(cert_path)])
    assert rc == 2


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(["--version"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "vauban-verify" in out
