#!/usr/bin/env bash
# lightweight-siem — production install script
# Tested on Ubuntu 22.04 / 24.04
# Usage: sudo bash scripts/install.sh
set -euo pipefail

LOKI_VERSION="3.0.0"
PROMTAIL_VERSION="3.0.0"
GRAFANA_VERSION="11.0.0"
INSTALL_DIR="/opt/lightweight-siem"
LOKI_USER="loki"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0"

# ── Dependencies ──────────────────────────────────────────────────────────────
info "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq curl wget unzip python3-pip python3-venv adduser libfontconfig1

# ── Loki ──────────────────────────────────────────────────────────────────────
info "Installing Loki $LOKI_VERSION..."
useradd --system --no-create-home --shell /bin/false "$LOKI_USER" 2>/dev/null || true
mkdir -p /etc/loki /var/lib/loki/{chunks,rules,compactor}
chown -R "$LOKI_USER:$LOKI_USER" /var/lib/loki

LOKI_URL="https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-amd64.zip"
wget -q "$LOKI_URL" -O /tmp/loki.zip
unzip -o /tmp/loki.zip loki-linux-amd64 -d /usr/local/bin/
mv /usr/local/bin/loki-linux-amd64 /usr/local/bin/loki
chmod +x /usr/local/bin/loki

cp "$REPO_ROOT/loki/loki-config.yaml" /etc/loki/config.yaml
sed -i 's|/loki|/var/lib/loki|g' /etc/loki/config.yaml

cat > /etc/systemd/system/loki.service <<EOF
[Unit]
Description=Loki log aggregation
After=network.target

[Service]
User=$LOKI_USER
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ── Promtail ──────────────────────────────────────────────────────────────────
info "Installing Promtail $PROMTAIL_VERSION..."
PROMTAIL_URL="https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-amd64.zip"
wget -q "$PROMTAIL_URL" -O /tmp/promtail.zip
unzip -o /tmp/promtail.zip promtail-linux-amd64 -d /usr/local/bin/
mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
chmod +x /usr/local/bin/promtail

mkdir -p /etc/promtail
cp "$REPO_ROOT/promtail/promtail-config.yaml" /etc/promtail/config.yaml
# Rewrite Docker-style paths to host paths
sed -i 's|/host-logs/|/var/log/|g' /etc/promtail/config.yaml
sed -i 's|url: http://loki:3100|url: http://localhost:3100|g' /etc/promtail/config.yaml

cat > /etc/systemd/system/promtail.service <<EOF
[Unit]
Description=Promtail log shipper
After=loki.service

[Service]
User=root
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/config.yaml -config.expand-env=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ── Grafana ───────────────────────────────────────────────────────────────────
info "Installing Grafana $GRAFANA_VERSION..."
wget -q "https://dl.grafana.com/oss/release/grafana_${GRAFANA_VERSION}_amd64.deb" -O /tmp/grafana.deb
dpkg -i /tmp/grafana.deb

cp -r "$REPO_ROOT/grafana/provisioning/." /etc/grafana/provisioning/
mkdir -p /var/lib/grafana/dashboards
cp "$REPO_ROOT/dashboards/"*.json /var/lib/grafana/dashboards/
chown -R grafana:grafana /var/lib/grafana/dashboards

# ── Alert Engine ──────────────────────────────────────────────────────────────
info "Installing Alert Engine..."
mkdir -p "$INSTALL_DIR"
cp -r "$REPO_ROOT/alerting/." "$INSTALL_DIR/alerting/"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/alerting/requirements.txt"

cat > /etc/systemd/system/siem-alerts.service <<EOF
[Unit]
Description=SIEM Alert Engine
After=loki.service

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
Environment=LOKI_URL=http://localhost:3100
Environment=RULES_FILE=$INSTALL_DIR/alerting/rules.yaml
Environment=POLL_INTERVAL=60
ExecStart=$INSTALL_DIR/venv/bin/python -u $INSTALL_DIR/alerting/engine.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ── Enable + start ────────────────────────────────────────────────────────────
info "Enabling and starting services..."
systemctl daemon-reload
for svc in loki promtail grafana-server siem-alerts; do
    systemctl enable "$svc"
    systemctl restart "$svc"
    info "$svc started"
done

rm -f /tmp/loki.zip /tmp/promtail.zip /tmp/grafana.deb

echo ""
echo -e "${GREEN}✔ lightweight-siem installed successfully${NC}"
echo ""
echo "  Grafana  →  http://$(hostname -I | awk '{print $1}'):3000"
echo "  Loki     →  http://$(hostname -I | awk '{print $1}'):3100"
echo ""
echo "  Default credentials: admin / changeme"
echo "  Change password: grafana-cli admin reset-admin-password <newpass>"
echo ""
echo "  Alert logs: journalctl -u siem-alerts -f"
