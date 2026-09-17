import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).parents[1]
CLI = ROOT / "examples" / "validate_hunter_snapshot_contract.py"


def run_cli(path: Path, *args: str):
    return subprocess.run(
        [sys.executable, str(CLI), str(path), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_validator_emits_aggregate_contract_summary_without_raw_values(tmp_path):
    raw_ip = "192.0.2.44"
    raw_domain = "lab.example.edu"
    snapshot = tmp_path / "sample.jsonl"
    snapshot.write_text(json.dumps({
        "ip": raw_ip,
        "port": 8443,
        "asn": 64500,
        "root_domain": "example.edu",
        "domain": raw_domain,
        "host": f"https://{raw_domain}:8443",
        "web_title": "Example University Portal",
        "country": "US",
        "full_name": "example/service",
        "http_head": "HTTP/1.1 200 OK",
        "protocol_type": "https",
        "favicon": "deadbeef",
    }) + "\n", encoding="utf-8")

    completed = run_cli(snapshot, "--limit", "1")
    assert completed.returncode == 0, completed.stderr or completed.stdout
    summary = json.loads(completed.stdout)
    assert summary["records_checked"] == 1
    assert summary["records_projected"] == 1
    assert summary["records_failed"] == 0
    assert summary["raw_values_emitted"] is False
    assert summary["ignored_known_field_counts"]["full_name"] == 1
    assert raw_ip not in completed.stdout
    assert raw_domain not in completed.stdout


def test_validator_strict_mode_reports_schema_drift_by_field_name_only(tmp_path):
    secret_value = "must-not-be-emitted"
    snapshot = tmp_path / "drift.jsonl"
    snapshot.write_text(json.dumps({
        "ip": "192.0.2.45",
        "mystery_field": secret_value,
    }) + "\n", encoding="utf-8")

    completed = run_cli(snapshot, "--limit", "1")
    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    assert summary["unknown_raw_field_counts"] == {"mystery_field": 1}
    assert summary["records_failed"] == 1
    assert secret_value not in completed.stdout


def test_validator_allow_unreviewed_audits_drift_without_exposing_it_to_rules(tmp_path):
    snapshot = tmp_path / "drift-audit.jsonl"
    snapshot.write_text(json.dumps({
        "ip": "192.0.2.46",
        "mystery_field": "ignored-value",
    }) + "\n", encoding="utf-8")

    completed = run_cli(snapshot, "--allow-unreviewed")
    assert completed.returncode == 0
    summary = json.loads(completed.stdout)
    assert summary["records_projected"] == 1
    assert summary["unknown_raw_field_counts"] == {"mystery_field": 1}
    assert "ignored-value" not in completed.stdout
