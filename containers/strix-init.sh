#!/bin/bash
# Privileged sandbox setup.
#
# The image has no sudo: nothing the agent runs can become root. This script is
# the only root step. The Strix host runs it through the Docker API
# (`docker exec --user 0`) right after the container starts, and again if the
# container is ever restarted. It:
#
#   1. maps the `pentester` user onto the host UID/GID (first start only),
#   2. generates a per-container MITM CA for Caido (first start only), so no
#      two sandboxes share a CA key,
#   3. installs the egress firewall (every start; netfilter state does not
#      survive a restart),
#   4. starts Caido as `pentester`, listening for the host only.
#
# Inputs come from the container environment set by the host at create time:
# STRIX_HOST_UID / STRIX_HOST_GID, STRIX_EGRESS_MODE (restricted|strict|open),
# STRIX_EGRESS_ALLOW (comma-separated IPs/CIDRs of scan targets) and
# STRIX_ALLOW_HOST_GATEWAY (1 when a target runs on the host).
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
  echo "strix-init must run as root" >&2
  exit 1
fi

CAIDO_PORT=48080
CAIDO_LOG=/tmp/caido_startup.log
STATE_DIR=/var/lib/strix-init
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

# ---------------------------------------------------------------------------
# 1. Host identity (first start)
# ---------------------------------------------------------------------------
provision_identity() {
  local uid="${STRIX_HOST_UID:-}"
  local gid="${STRIX_HOST_GID:-${STRIX_HOST_UID:-}}"
  local old_uid old_gid
  old_uid="$(id -u pentester)"
  old_gid="$(id -g pentester)"
  if [ -n "$uid" ] && [ "$uid" != "0" ] && [ "$uid" != "$old_uid" ]; then
    case "$uid$gid" in *[!0-9]*) echo "invalid host uid/gid" >&2; exit 1 ;; esac
    sed -i "s|^pentester:x:${old_uid}:${old_gid}:|pentester:x:${uid}:${gid}:|" /etc/passwd
    sed -i "s|^pentester:x:${old_gid}:|pentester:x:${gid}:|" /etc/group
    chown -R "${uid}:${gid}" /home/pentester /app/certs
    chown "${uid}:${gid}" /workspace
  fi
}

# ---------------------------------------------------------------------------
# 2. Per-container CA and proxy environment (first start)
# ---------------------------------------------------------------------------
provision_ca() {
  local certs=/app/certs
  rm -f "$certs/ca.key" "$certs/ca.crt" "$certs/ca.p12"
  openssl ecparam -name prime256v1 -genkey -noout -out "$certs/ca.key"
  openssl req -x509 -new -key "$certs/ca.key" \
    -out "$certs/ca.crt" \
    -days 30 \
    -subj "/O=Strix Sandbox/CN=Strix Sandbox CA $(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign"
  # Caido imports the p12; it only ever lives inside this container.
  openssl pkcs12 -export -out "$certs/ca.p12" -inkey "$certs/ca.key" \
    -in "$certs/ca.crt" -passout pass:"" -name "Strix Sandbox CA"
  chown pentester:pentester "$certs/ca.key" "$certs/ca.crt" "$certs/ca.p12"
  chmod 644 "$certs/ca.crt"
  chmod 600 "$certs/ca.key" "$certs/ca.p12"

  cp "$certs/ca.crt" /usr/local/share/ca-certificates/strix-sandbox-ca.crt
  update-ca-certificates >/dev/null

  as_pentester mkdir -p /home/pentester/.pki/nssdb
  as_pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
  as_pentester certutil -A -n "Strix Sandbox CA" -t "C,," -i "$certs/ca.crt" \
    -d sql:/home/pentester/.pki/nssdb
}

provision_proxy_env() {
  local url="http://127.0.0.1:${CAIDO_PORT}"
  cat > /etc/profile.d/proxy.sh << EOF
export http_proxy=${url}
export https_proxy=${url}
export HTTP_PROXY=${url}
export HTTPS_PROXY=${url}
export ALL_PROXY=${url}
export NO_PROXY=localhost,127.0.0.1
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EOF
  cat > /etc/environment << EOF
http_proxy=${url}
https_proxy=${url}
HTTP_PROXY=${url}
HTTPS_PROXY=${url}
ALL_PROXY=${url}
NO_PROXY=localhost,127.0.0.1
EOF
  cat > /etc/wgetrc << EOF
use_proxy=yes
http_proxy=${url}
https_proxy=${url}
EOF
  # POSIX `.` so a POSIX shell reading the rc files does not choke on `source`.
  for rc in /home/pentester/.bashrc /home/pentester/.zshrc; do
    grep -qxF ". /etc/profile.d/proxy.sh" "$rc" 2>/dev/null \
      || echo ". /etc/profile.d/proxy.sh" >> "$rc"
    chown pentester:pentester "$rc"
  done
  as_pentester mkdir -p /workspace/.agent-browser-screenshots
}

as_pentester() {
  setpriv --reuid "$(id -u pentester)" --regid "$(id -g pentester)" --init-groups \
    --inh-caps=-all --bounding-set=-all env HOME=/home/pentester "$@"
}

# ---------------------------------------------------------------------------
# 3. Egress firewall (every start)
# ---------------------------------------------------------------------------
# Ranges no pentest traffic needs unless a target lives there: cloud metadata
# and link-local, loopback-adjacent and private networks, CGNAT, multicast.
BLOCKED_V4="169.254.0.0/16 100.100.100.200/32 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 192.0.0.0/24 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
BLOCKED_V6="fd00:ec2::254/128 fe80::/10 fc00::/7 ff00::/8"

install_firewall() {
  local mode="${STRIX_EGRESS_MODE:-restricted}"
  local gateway
  gateway="$(ip -4 route show default | awk '{print $3; exit}')"

  for cmd in iptables ip6tables; do
    "$cmd" -F OUTPUT
    "$cmd" -F INPUT
    "$cmd" -P OUTPUT ACCEPT
    "$cmd" -P INPUT ACCEPT
  done

  # Inbound: only the host may reach Caido. Other containers on the same
  # Docker network cannot log in to it as a guest and read proxy history.
  for cmd in iptables ip6tables; do
    "$cmd" -A INPUT -i lo -j ACCEPT
    "$cmd" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done
  # The host reaches the container from the bridge gateway (or, on Docker
  # Desktop, from outside the container subnet); peers share the subnet.
  local subnet
  subnet="$(ip -4 route show scope link | awk '!/^default/ {print $1; exit}')"
  if [ -n "$gateway" ]; then
    iptables -A INPUT -p tcp --dport "$CAIDO_PORT" -s "$gateway" -j ACCEPT
  fi
  # On a shared network (STRIX_DOCKER_SANDBOX_NETWORK) the host side may itself
  # be a peer container; it is let in via STRIX_CAIDO_ALLOWED_SOURCES.
  local src
  IFS=',' read -ra sources <<< "${STRIX_CAIDO_ALLOWED_SOURCES:-}"
  for src in "${sources[@]}"; do
    [ -n "$src" ] && iptables -A INPUT -p tcp --dport "$CAIDO_PORT" -s "$src" -j ACCEPT
  done
  if [ "${STRIX_SANDBOX_SHARED_NETWORK:-0}" = "1" ] && [ -z "${STRIX_CAIDO_ALLOWED_SOURCES:-}" ]; then
    echo "strix-init: shared network without STRIX_CAIDO_ALLOWED_SOURCES; Caido is open to peers" >&2
    subnet=""
  fi
  if [ -n "$subnet" ]; then
    iptables -A INPUT -p tcp --dport "$CAIDO_PORT" -s "$subnet" -j DROP
  fi
  ip6tables -A INPUT -p tcp --dport "$CAIDO_PORT" -j DROP

  if [ "$mode" = "open" ]; then
    echo "strix-init: egress mode 'open' (no outbound filtering)"
    return
  fi

  for cmd in iptables ip6tables; do
    "$cmd" -A OUTPUT -o lo -j ACCEPT
    "$cmd" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done

  # Addresses of scan targets the operator named are always reachable, even in
  # a blocked range (testing an internal app is legitimate when it is in scope).
  local entry
  IFS=',' read -ra allow <<< "${STRIX_EGRESS_ALLOW:-}"
  for entry in "${allow[@]}"; do
    [ -z "$entry" ] && continue
    if [[ "$entry" == *:* ]]; then
      ip6tables -A OUTPUT -d "$entry" -j ACCEPT
    else
      iptables -A OUTPUT -d "$entry" -j ACCEPT
    fi
  done

  if [ "${STRIX_ALLOW_HOST_GATEWAY:-0}" = "1" ]; then
    local host_ip
    host_ip="$(getent ahostsv4 host.docker.internal | awk '{print $1; exit}' || true)"
    [ -n "$host_ip" ] && iptables -A OUTPUT -d "$host_ip" -j ACCEPT
  fi

  # DNS goes to Docker's embedded resolver or the host-provided nameservers.
  local ns
  for ns in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf); do
    if [[ "$ns" == *:* ]]; then
      ip6tables -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT
      ip6tables -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT
    else
      iptables -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT
      iptables -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT
    fi
  done

  # The host itself (bridge gateway) is never a target unless allowed above.
  [ -n "$gateway" ] && iptables -A OUTPUT -d "$gateway" -j REJECT

  if [ "$mode" = "strict" ]; then
    iptables -A OUTPUT -j REJECT
    ip6tables -A OUTPUT -j REJECT
    echo "strix-init: egress mode 'strict' (targets only)"
    return
  fi

  local range
  for range in $BLOCKED_V4; do iptables -A OUTPUT -d "$range" -j REJECT; done
  for range in $BLOCKED_V6; do ip6tables -A OUTPUT -d "$range" -j REJECT; done
  echo "strix-init: egress mode 'restricted' (metadata and private ranges blocked)"
}

# ---------------------------------------------------------------------------
# 4. Caido (every start)
# ---------------------------------------------------------------------------
start_caido() {
  if pgrep -x caido-cli >/dev/null; then
    return
  fi

  # Caido enforces a Host allowlist (DNS-rebinding protection). To reach it
  # over a hostname rather than an IP literal, set STRIX_CAIDO_ALLOWED_DOMAINS.
  local domain_args=() d
  if [ -n "${STRIX_CAIDO_ALLOWED_DOMAINS:-}" ]; then
    IFS=',' read -ra domains <<< "${STRIX_CAIDO_ALLOWED_DOMAINS}"
    for d in "${domains[@]}"; do
      [ -n "$d" ] && domain_args+=(--ui-domain "$d")
    done
  fi

  # Guest login stays on because the host bootstraps its token with it; the
  # INPUT rules above keep anything but the host (and this container) out.
  as_pentester setsid caido-cli --listen "0.0.0.0:${CAIDO_PORT}" \
    --allow-guests \
    --no-logging \
    --no-open \
    "${domain_args[@]}" \
    --import-ca-cert /app/certs/ca.p12 \
    --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 < /dev/null &

  local i
  for i in $(seq 1 30); do
    if curl -s --noproxy '*' -o /dev/null -w "%{http_code}" \
      "http://127.0.0.1:${CAIDO_PORT}/graphql/" | grep -qE "^(200|400)$"; then
      echo "strix-init: Caido ready (attempt $i)"
      return
    fi
    sleep 1
  done
  echo "strix-init: Caido did not become ready" >&2
  cat "$CAIDO_LOG" >&2 2>/dev/null || true
  exit 1
}

if [ ! -f "$STATE_DIR/provisioned" ]; then
  provision_identity
  provision_ca
  provision_proxy_env
  touch "$STATE_DIR/provisioned"
fi
install_firewall
start_caido
echo "strix-init: sandbox ready"
