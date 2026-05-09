"""Unit tests for the alert engine — no Loki, no network."""
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "alerting"))
from engine import load_rules, Rule, Alert, _severity_label


SAMPLE_RULES = {
    "defaults": [
        {
            "name": "ssh_brute",
            "query": '{job="auth"}',
            "match": "Failed password",
            "condition": "count",
            "window": 300,
            "threshold": 10,
            "severity": "critical",
            "message": "Brute force",
            "enabled": True,
        }
    ],
    "custom": [
        {
            "name": "custom_rule",
            "query": '{job="app"}',
            "condition": "count",
            "window": 60,
            "threshold": 5,
            "severity": "medium",
            "message": "Custom alert",
            "enabled": True,
        },
        {
            "name": "disabled_rule",
            "query": '{job="app"}',
            "condition": "count",
            "window": 60,
            "threshold": 1,
            "severity": "low",
            "message": "Should not load",
            "enabled": False,
        },
    ],
}


def _write_rules(data: dict) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        return f.name


def test_load_rules_counts():
    path = _write_rules(SAMPLE_RULES)
    import engine
    engine.RULES_FILE = Path(path)
    rules = load_rules()
    # 1 default + 1 enabled custom = 2 (disabled excluded)
    assert len(rules) == 2
    Path(path).unlink()


def test_disabled_rule_excluded():
    path = _write_rules(SAMPLE_RULES)
    import engine
    engine.RULES_FILE = Path(path)
    rules = load_rules()
    names = [r.name for r in rules]
    assert "disabled_rule" not in names
    Path(path).unlink()


def test_rule_fields():
    path = _write_rules(SAMPLE_RULES)
    import engine
    engine.RULES_FILE = Path(path)
    rules = load_rules()
    ssh = next(r for r in rules if r.name == "ssh_brute")
    assert ssh.threshold == 10
    assert ssh.window == 300
    assert ssh.severity == "critical"
    assert ssh.match == "Failed password"
    Path(path).unlink()


def test_load_rules_missing_file():
    import engine
    engine.RULES_FILE = Path("/nonexistent/rules.yaml")
    rules = load_rules()
    assert rules == []


def test_severity_labels():
    assert "🔴" in _severity_label("critical")
    assert "🟠" in _severity_label("high")
    assert "🟡" in _severity_label("medium")
    assert "🔵" in _severity_label("info")


def test_alert_to_dict():
    alert = Alert(
        rule_name="test_rule",
        severity="critical",
        message="Test alert",
        count=15,
        log_sample="Failed password for root",
    )
    d = alert.to_dict()
    assert d["rule"] == "test_rule"
    assert d["count"] == 15
    assert "fired_at" in d


def test_empty_custom_section():
    data = {"defaults": SAMPLE_RULES["defaults"], "custom": None}
    path = _write_rules(data)
    import engine
    engine.RULES_FILE = Path(path)
    rules = load_rules()
    assert len(rules) == 1
    Path(path).unlink()
