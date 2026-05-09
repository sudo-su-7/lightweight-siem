"""
SIEM Alert Engine
Polls Loki on a schedule, evaluates default + custom rules, fires alerts.
"""
from __future__ import annotations

import os
import re
import time
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("siem.engine")

LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
RULES_FILE = Path(os.getenv("RULES_FILE", "/app/alerting/rules.yaml"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))        # seconds
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")                   # optional


# ── Models ────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    name: str
    query: str
    condition: str
    window: int
    threshold: int
    severity: str
    message: str
    match: str = ""
    enabled: bool = True


@dataclass
class Alert:
    rule_name: str
    severity: str
    message: str
    count: int
    log_sample: str
    fired_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "count": self.count,
            "sample": self.log_sample,
            "fired_at": self.fired_at.isoformat(),
        }


# ── Rule loading ──────────────────────────────────────────────────────────────

def load_rules() -> list[Rule]:
    if not RULES_FILE.exists():
        log.warning("Rules file not found: %s — using empty ruleset", RULES_FILE)
        return []

    raw = yaml.safe_load(RULES_FILE.read_text())
    rules: list[Rule] = []

    for section in ("defaults", "custom"):
        for r in raw.get(section) or []:
            if not r.get("enabled", True):
                continue
            rules.append(Rule(
                name=r["name"],
                query=r["query"],
                match=r.get("match", ""),
                condition=r.get("condition", "count"),
                window=int(r.get("window", 300)),
                threshold=int(r.get("threshold", 1)),
                severity=r.get("severity", "medium"),
                message=r.get("message", r["name"]),
            ))

    log.info("Loaded %d rules (%d defaults, %d custom)", len(rules),
             len(raw.get("defaults") or []), len(raw.get("custom") or []))
    return rules


# ── Loki query ────────────────────────────────────────────────────────────────

def _query_loki(rule: Rule) -> tuple[int, str]:
    """
    Query Loki for log count matching the rule over its window.
    Returns (count, sample_log_line).
    """
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - (rule.window * int(1e9))

    # Build LogQL: selector + optional line filter
    logql = rule.query
    if rule.match:
        escaped = rule.match.replace('"', '\\"')
        logql = f'{logql} |~ "{escaped}"'

    params = {
        "query": logql,
        "start": str(start_ns),
        "end": str(now_ns),
        "limit": "100",
        "direction": "backward",
    }

    try:
        resp = httpx.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning("Loki query failed for rule '%s': %s", rule.name, e)
        return 0, ""

    results = data.get("data", {}).get("result", [])
    total = 0
    sample = ""

    for stream in results:
        values = stream.get("values", [])
        total += len(values)
        if values and not sample:
            sample = values[0][1][:200]  # first log line, truncated

    return total, sample


# ── Alert dispatch ────────────────────────────────────────────────────────────

def _severity_label(severity: str) -> str:
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}
    return f"{icons.get(severity, '⚪')} [{severity.upper()}]"


def fire_alert(alert: Alert) -> None:
    label = _severity_label(alert.severity)
    log.warning(
        "ALERT %s %s | count=%d | %s | sample: %s",
        label, alert.rule_name, alert.count, alert.message, alert.log_sample[:100]
    )

    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json=alert.to_dict(), timeout=5)
        except Exception as e:
            log.warning("Webhook delivery failed: %s", e)


# ── Engine loop ───────────────────────────────────────────────────────────────

def run() -> None:
    log.info("SIEM Alert Engine starting — Loki: %s | poll interval: %ds", LOKI_URL, POLL_INTERVAL)
    rules = load_rules()

    # Track last-fired time per rule to avoid alert spam (one alert per window)
    last_fired: dict[str, float] = {}

    while True:
        for rule in rules:
            count, sample = _query_loki(rule)

            if count < rule.threshold:
                continue

            # Suppress re-firing within the same window
            last = last_fired.get(rule.name, 0)
            if time.monotonic() - last < rule.window:
                continue

            alert = Alert(
                rule_name=rule.name,
                severity=rule.severity,
                message=rule.message,
                count=count,
                log_sample=sample,
            )
            fire_alert(alert)
            last_fired[rule.name] = time.monotonic()

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
