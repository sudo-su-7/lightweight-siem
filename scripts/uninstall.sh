#!/usr/bin/env bash
# Remove lightweight-siem from a production server
set -euo pipefail
[[ $EUID -ne 0 ]] && echo "Run as root" && exit 1

for svc in loki promtail grafana-server siem-alerts; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

rm -f /usr/local/bin/loki /usr/local/bin/promtail
dpkg -r grafana 2>/dev/null || true
rm -rf /etc/loki /etc/promtail /var/lib/loki /opt/lightweight-siem
rm -f /etc/systemd/system/{loki,promtail,siem-alerts}.service
systemctl daemon-reload

echo "lightweight-siem removed."
