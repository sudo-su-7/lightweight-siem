 # 🔍 lightweight-siem

> Production-ready SIEM prototype: generic multi-source log ingestion via Promtail → Loki → Grafana dashboards + Python alert engine with configurable detection rules.

![Docker](https://img.shields.io/badge/Docker-Compose-2496ED) ![Grafana](https://img.shields.io/badge/Grafana-11-F46800) ![Loki](https://img.shields.io/badge/Loki-3.0-yellow) ![Python](https://img.shields.io/badge/Python-3.11-blue)

---

## Architecture

```
 /var/log/* ──► Promtail ──► Loki ──► Grafana  (port 3000)
                                  └──► Alert Engine  (stdout / webhook)
```

| Component | Role |
|-----------|------|
| **Promtail** | Tails log files, adds labels, ships to Loki |
| **Loki** | Stores and indexes log streams |
| **Grafana** | Pre-built SIEM dashboards, auto-provisioned |
| **Alert Engine** | Python — polls Loki, evaluates rules, fires alerts |

---

## Quick Start (Docker)

```bash
git clone https://github.com/sudo-su-7/lightweight-siem
cd lightweight-siem
cp .env.example .env          # edit credentials

docker compose up --build -d
```

Open **http://localhost:3000** — log in with `admin / changeme`.
The **SIEM Overview** dashboard loads automatically.

---

## Production Install (bare Ubuntu 22.04 / 24.04)

```bash
sudo bash scripts/install.sh
```

Installs Loki, Promtail, Grafana, and the Alert Engine as **systemd services**.

```bash
# Check status
systemctl status loki promtail grafana-server siem-alerts

# Watch alerts live
journalctl -u siem-alerts -f
```

---

## Log Sources

Promtail ships from these paths out of the box:

| Source | Path |
|--------|------|
| Auth / SSH | `/var/log/auth.log` |
| Syslog | `/var/log/syslog` |
| Nginx access | `/var/log/nginx/access.log` |
| Nginx error | `/var/log/nginx/error.log` |
| Apache | `/var/log/apache2/access.log` |
| Custom apps | `/var/log/apps/*.log` |
| Kernel | `/var/log/kern.log` |

Add more sources by editing `promtail/promtail-config.yaml`.

---

## Alert Rules

Default rules fire on:

| Rule | Condition | Severity |
|------|-----------|----------|
| SSH brute force | >10 failed passwords / 5min | 🔴 CRITICAL |
| Root SSH login | Any root login | 🔴 CRITICAL |
| Break-in attempt | sshd BREAK-IN flag | 🔴 CRITICAL |
| Sudo auth failure | Any sudo failure | 🟠 HIGH |
| Unknown SSH user | >3 invalid users / 1min | 🟠 HIGH |

### Adding custom rules

Edit `alerting/rules.yaml` — no code needed:

```yaml
custom:
  - name: nginx_5xx_spike
    query: '{job="nginx", status=~"5.."}'
    condition: count
    window: 300
    threshold: 20
    severity: high
    message: "Nginx 5xx error spike"
    enabled: true
```

Restart the alert engine to pick up changes:
```bash
# Docker
docker compose restart alert-engine

# Prod
systemctl restart siem-alerts
```

### Webhook alerts

Set `WEBHOOK_URL` in `.env` to receive JSON POSTs on every alert:

```json
{
  "rule": "ssh_brute_force",
  "severity": "critical",
  "message": "SSH brute force detected",
  "count": 23,
  "sample": "Failed password for root from 1.2.3.4",
  "fired_at": "2026-05-07T10:30:00+00:00"
}
```

---

## Grafana Dashboard Panels

- Critical event count (1h)
- SSH failed vs accepted logins over time
- Log volume by source
- Recent security events (live log tail)
- Nginx HTTP status codes
- Kernel errors

---

## Author

**Daniel Mutuma** — Junior Cybersecurity Analyst 
[github.com/sudo-su-7](https://github.com/sudo-su-7)
