#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP="flowcollector"
SERVICE="flowcollector.service"
VERSION="4.0.0"
PREFIX="/usr/local/bin"
CONFIG_DIR="/etc/flowcollector"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
DATA_DIR="/var/lib/flowcollector"
LOG_DIR="/var/log/flowcollector"
SERVICE_USER="flowcollector"
SERVICE_GROUP="flowcollector"
ENABLE_SERVICE=1
START_SERVICE=1
FORCE=0
MODE="install"
AUTO_ROLLBACK=1
BACKUP_ROOT="/var/backups/flowcollector"
SNAPSHOT=""
WEB_BIND="127.0.0.1"
WEB_PORT="8080"
WEB_BIND_SET=0
WEB_PORT_SET=0
FORCE_HTTP=0
HTTPS_CERT=""
HTTPS_KEY=""
CLUSTER_HEARTBEAT_URL=""
CLUSTER_HEARTBEAT_URL_SET=0
CLUSTER_TOKEN_SOURCE=""
CLUSTER_HEARTBEAT_SECONDS="30"
CLUSTER_HEARTBEAT_SECONDS_SET=0
CLUSTER_NODE_TIMEOUT_SECONDS="90"
CLUSTER_NODE_TIMEOUT_SECONDS_SET=0
CLUSTER_ALLOW_INSECURE_HTTP=0
CLUSTER_TOKEN_TARGET=""
CLUSTER_GLOBAL_DEDUP_ENABLED=0
CLUSTER_GLOBAL_DEDUP_ENABLED_SET=0
CLUSTER_GLOBAL_DEDUP_URL=""
CLUSTER_GLOBAL_DEDUP_URL_SET=0
CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS="300"
CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS_SET=0
CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES="500000"
CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES_SET=0

# Storage/ClickHouse installation profile. Fresh installations start a
# Docker-managed ClickHouse. Upgrades preserve the existing backend
# unless an explicit ClickHouse/local-storage option is supplied.
CLICKHOUSE_MODE="auto"          # auto | docker | local | remote | disabled
CLICKHOUSE_MODE_SET=0
CLICKHOUSE_HOST="127.0.0.1"
CLICKHOUSE_PORT="8123"
CLICKHOUSE_SCHEME="http"
CLICKHOUSE_DATABASE="flowcollector"
CLICKHOUSE_TABLE="flows"
CLICKHOUSE_USER="flowcollector"
CLICKHOUSE_PASSWORD=""
CLICKHOUSE_PASSWORD_SET=0
CLICKHOUSE_ADMIN_USER="default"
CLICKHOUSE_ADMIN_PASSWORD=""
CLICKHOUSE_ADMIN_PASSWORD_SET=0
CLICKHOUSE_ADMIN_PASSWORD_FILE=""
CLICKHOUSE_CHANNEL="stable"
CLICKHOUSE_RETENTION_DAYS="7"
CLICKHOUSE_NO_PROVISION=0
CLICKHOUSE_ENV_FILE=""
CLICKHOUSE_REPO_ADDED=0
CLICKHOUSE_CLUSTER=""
CLICKHOUSE_DISTRIBUTED_TABLE="flows_distributed"
CLICKHOUSE_REPLICA_PATH="/clickhouse/tables/{shard}/flowcollector/flows"
CLICKHOUSE_REPLICA_NAME="{replica}"

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_DIR="${FLOWCOLLECTOR_SYSTEMD_DIR:-/etc/systemd/system}"
DISTRO_ID="unknown"
DISTRO_VERSION="unknown"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_VERSION="${VERSION_ID:-unknown}"
fi

if [[ -t 1 ]]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[36m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_BLUE='\033[34m'
else
  C_RESET=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_BLUE=''
fi
info(){ printf "%b[INFO]%b %s\n" "$C_CYAN" "$C_RESET" "$*"; }
ok(){ printf "%b[ OK ]%b %s\n" "$C_GREEN" "$C_RESET" "$*"; }
warn(){ printf "%b[WARN]%b %s\n" "$C_YELLOW" "$C_RESET" "$*"; }
die(){ printf "%b[FAIL]%b %s\n" "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
step(){ printf "\n%b==>%b %b%s%b\n" "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }

usage(){ cat <<USAGE
Central Flow Collector v$VERSION installer

Usage: sudo ./install.sh [options]

Web transport defaults are deliberately certificate-free:
  HTTP http://127.0.0.1:8080

Options:
  --prefix DIR            Binary directory (default: $PREFIX)
  --config-dir DIR        Configuration directory (default: $CONFIG_DIR)
  --data-dir DIR          Data directory (default: $DATA_DIR)
  --log-dir DIR           Log directory (default: $LOG_DIR)
  --user USER             Service user (default: $SERVICE_USER)
  --group GROUP           Service group (default: $SERVICE_GROUP)
  --web-bind HOST         Web bind address (default: $WEB_BIND)
  --web-port PORT         Web port (default: $WEB_PORT)
  --http                  Force certificate-free HTTP mode
  --https-cert FILE       Enable HTTPS with this administrator-supplied certificate
  --https-key FILE        Private key matching --https-cert

Collector cluster / heartbeat:
  --cluster-heartbeat-url URL
                           Send authenticated node heartbeat to central collector
  --cluster-token-file FILE
                           Copy the central cluster token into this collector
  --cluster-heartbeat-seconds N
                           Heartbeat interval (default: 30)
  --cluster-node-timeout N Node offline timeout (default: 90)
  --cluster-allow-insecure-http
                           Explicitly permit non-loopback HTTP heartbeats
  --cluster-global-dedup    Enable authenticated cluster-wide deduplication
  --cluster-global-dedup-url URL
                           Central /api/v1/cluster/dedup URL for edge collectors; blank = local coordinator
  --cluster-global-dedup-timeout-ms N
                           Coordinator timeout (default: 300)
  --cluster-global-dedup-max N
                           Coordinator bounded fingerprint entries (default: 500000)

Storage / ClickHouse:
  --clickhouse-docker      Start managed ClickHouse in Docker (fresh install default)
  --clickhouse-local       Install/configure native ClickHouse packages on this machine
  --clickhouse-host HOST   Use ClickHouse on another host (implies remote mode)
  --clickhouse-port PORT   ClickHouse HTTP(S) port (default: 8123)
  --clickhouse-scheme S    http or https (default: http)
  --clickhouse-database DB Database name (default: flowcollector)
  --clickhouse-table TBL   Flow table name (default: flows)
  --clickhouse-cluster NAME
                           Use a preconfigured ClickHouse cluster (ReplicatedMergeTree + Distributed table)
  --clickhouse-distributed-table TBL
                           Distributed table name (default: flows_distributed)
  --clickhouse-replica-path PATH
                           ReplicatedMergeTree Keeper path
  --clickhouse-replica-name NAME
                           Replica macro/name (default: {replica})
  --clickhouse-user USER   Dedicated application user (default: flowcollector)
  --clickhouse-password P  Application password; generated for managed local installs
  --clickhouse-password-file FILE
                           Read application password from FILE instead of argv
  --clickhouse-admin-user USER
                           Bootstrap/admin user for DB/user provisioning (default: default)
  --clickhouse-admin-password P
                           Bootstrap/admin password (prefer --clickhouse-admin-password-file)
  --clickhouse-admin-password-file FILE
                           Read bootstrap/admin password from FILE
  --clickhouse-retention DAYS
                           Raw-flow TTL in days (default: 7)
  --clickhouse-channel CH  stable or lts for local package install (default: stable)
  --clickhouse-no-provision
                           Do not create DB/user/grants; only validate supplied app credentials
  --local-storage          Keep/use local JSONL storage and do not install ClickHouse

  --no-enable             Do not enable systemd autostart
  --no-start              Install but do not start the service
  --upgrade               Require an existing installation and create a rollback snapshot
  --rollback              Restore the most recent installer snapshot and restart the service
  --no-rollback            Do not automatically restore the previous release if health validation fails
  --force                 Replace managed binary/unit without confirmation
  -h, --help              Show this help

Important:
  * Running without --upgrade detects an existing binary and config, then updates it automatically.
  * Fresh installs start ClickHouse in Docker; --local-storage opts out.
  * Upgrades preserve the current storage backend unless ClickHouse/local-storage is explicit.
  * Remote ClickHouse is configured with --clickhouse-host plus credentials.
  * Secrets are stored in /etc/flowcollector/clickhouse.env, not in config.yaml.
  * No self-signed web certificate is generated by v2.0.0.
  * Default web binding is loopback-only, so plaintext HTTP is not exposed remotely.
  * Exporter policy remains DEFAULT DENY.
USAGE
}

while (($#)); do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; CONFIG_FILE="$2/config.yaml"; shift 2;;
    --data-dir) DATA_DIR="$2"; shift 2;;
    --log-dir) LOG_DIR="$2"; shift 2;;
    --user) SERVICE_USER="$2"; shift 2;;
    --group) SERVICE_GROUP="$2"; shift 2;;
    --web-bind) WEB_BIND="$2"; WEB_BIND_SET=1; shift 2;;
    --web-port) WEB_PORT="$2"; WEB_PORT_SET=1; shift 2;;
    --http) FORCE_HTTP=1; shift;;
    --https-cert) HTTPS_CERT="$2"; shift 2;;
    --https-key) HTTPS_KEY="$2"; shift 2;;
    --cluster-heartbeat-url) CLUSTER_HEARTBEAT_URL="$2"; CLUSTER_HEARTBEAT_URL_SET=1; shift 2;;
    --cluster-token-file) [[ -r "$2" ]] || die "Cannot read cluster token file: $2"; CLUSTER_TOKEN_SOURCE="$2"; shift 2;;
    --cluster-heartbeat-seconds) CLUSTER_HEARTBEAT_SECONDS="$2"; CLUSTER_HEARTBEAT_SECONDS_SET=1; shift 2;;
    --cluster-node-timeout) CLUSTER_NODE_TIMEOUT_SECONDS="$2"; CLUSTER_NODE_TIMEOUT_SECONDS_SET=1; shift 2;;
    --cluster-allow-insecure-http) CLUSTER_ALLOW_INSECURE_HTTP=1; shift;;
    --cluster-global-dedup) CLUSTER_GLOBAL_DEDUP_ENABLED=1; CLUSTER_GLOBAL_DEDUP_ENABLED_SET=1; shift;;
    --cluster-global-dedup-url) CLUSTER_GLOBAL_DEDUP_ENABLED=1; CLUSTER_GLOBAL_DEDUP_ENABLED_SET=1; CLUSTER_GLOBAL_DEDUP_URL="$2"; CLUSTER_GLOBAL_DEDUP_URL_SET=1; shift 2;;
    --cluster-global-dedup-timeout-ms) CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS="$2"; CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS_SET=1; shift 2;;
    --cluster-global-dedup-max) CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES="$2"; CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES_SET=1; shift 2;;
    --clickhouse-docker) CLICKHOUSE_MODE="docker"; CLICKHOUSE_MODE_SET=1; CLICKHOUSE_HOST="127.0.0.1"; shift;;
    --clickhouse-local) CLICKHOUSE_MODE="local"; CLICKHOUSE_MODE_SET=1; CLICKHOUSE_HOST="127.0.0.1"; shift;;
    --clickhouse-host) CLICKHOUSE_HOST="$2"; CLICKHOUSE_MODE="remote"; CLICKHOUSE_MODE_SET=1; shift 2;;
    --clickhouse-port) CLICKHOUSE_PORT="$2"; shift 2;;
    --clickhouse-scheme) CLICKHOUSE_SCHEME="$2"; shift 2;;
    --clickhouse-database) CLICKHOUSE_DATABASE="$2"; shift 2;;
    --clickhouse-table) CLICKHOUSE_TABLE="$2"; shift 2;;
    --clickhouse-cluster) CLICKHOUSE_CLUSTER="$2"; shift 2;;
    --clickhouse-distributed-table) CLICKHOUSE_DISTRIBUTED_TABLE="$2"; shift 2;;
    --clickhouse-replica-path) CLICKHOUSE_REPLICA_PATH="$2"; shift 2;;
    --clickhouse-replica-name) CLICKHOUSE_REPLICA_NAME="$2"; shift 2;;
    --clickhouse-user) CLICKHOUSE_USER="$2"; shift 2;;
    --clickhouse-password) CLICKHOUSE_PASSWORD="$2"; CLICKHOUSE_PASSWORD_SET=1; shift 2;;
    --clickhouse-password-file) [[ -r "$2" ]] || die "Cannot read ClickHouse password file: $2"; CLICKHOUSE_PASSWORD="$(tr -d '\r\n' < "$2")"; CLICKHOUSE_PASSWORD_SET=1; shift 2;;
    --clickhouse-admin-user) CLICKHOUSE_ADMIN_USER="$2"; shift 2;;
    --clickhouse-admin-password) CLICKHOUSE_ADMIN_PASSWORD="$2"; CLICKHOUSE_ADMIN_PASSWORD_SET=1; shift 2;;
    --clickhouse-admin-password-file) CLICKHOUSE_ADMIN_PASSWORD_FILE="$2"; CLICKHOUSE_ADMIN_PASSWORD_SET=1; shift 2;;
    --clickhouse-retention) CLICKHOUSE_RETENTION_DAYS="$2"; shift 2;;
    --clickhouse-channel) CLICKHOUSE_CHANNEL="$2"; shift 2;;
    --clickhouse-no-provision) CLICKHOUSE_NO_PROVISION=1; shift;;
    --local-storage) CLICKHOUSE_MODE="disabled"; CLICKHOUSE_MODE_SET=1; shift;;
    --no-enable) ENABLE_SERVICE=0; shift;;
    --no-start) START_SERVICE=0; shift;;
    --upgrade) MODE="upgrade"; shift;;
    --rollback) MODE="rollback"; shift;;
    --no-rollback) AUTO_ROLLBACK=0; shift;;
    --force) FORCE=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown option: $1";;
  esac
done

if [[ "$MODE" == "install" && -x "$PREFIX/flowcollector" && -f "$CONFIG_FILE" ]]; then
  MODE="upgrade"
  info "Existing installation detected at $PREFIX/flowcollector; switching to upgrade mode."
fi

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this installer as root (for example: sudo ./install.sh)."
if ! command -v systemctl >/dev/null 2>&1; then
  if command -v rc-service >/dev/null 2>&1; then
    SERVICE_MANAGER="openrc"
    systemctl(){
      local action="" svc="" arg
      for arg in "$@"; do
        [[ "$arg" == --* ]] && continue
        [[ -z "$action" ]] && action="$arg" || svc="${arg%.service}"
      done
      case "$action" in
        enable) rc-update add "$svc" default 2>/dev/null || true;;
        start) rc-service "$svc" start;; stop) rc-service "$svc" stop;; restart) rc-service "$svc" restart;;
        is-active) rc-service "$svc" status >/dev/null 2>&1;;
        daemon-reload|reset-failed) return 0;;
        status) rc-service "$svc" status;;
        show) [[ "$1" == "-p" ]] && { echo 0; return 0; };;
        *) return 0;;
      esac
    }
  elif command -v service >/dev/null 2>&1; then
    SERVICE_MANAGER="sysvinit"
    systemctl(){
      local action="" svc="" arg
      for arg in "$@"; do
        [[ "$arg" == --* ]] && continue
        [[ -z "$action" ]] && action="$arg" || svc="${arg%.service}"
      done
      case "$action" in
        enable|daemon-reload|reset-failed) return 0;;
        is-active) service "$svc" status >/dev/null 2>&1;;
        show) echo 0;; status) service "$svc" status;;
        start|stop|restart) service "$svc" "$action";; *) return 0;;
      esac
    }
  else
    die "No supported service manager found (systemd, OpenRC or SysVinit)."
  fi
fi
command -v install >/dev/null 2>&1 || die "'install' utility is required."

[[ "$WEB_PORT" =~ ^[0-9]+$ ]] && (( WEB_PORT >= 1 && WEB_PORT <= 65535 )) || die "--web-port must be 1..65535"
[[ "$CLUSTER_HEARTBEAT_SECONDS" =~ ^[0-9]+$ ]] && (( CLUSTER_HEARTBEAT_SECONDS >= 5 && CLUSTER_HEARTBEAT_SECONDS <= 3600 )) || die "--cluster-heartbeat-seconds must be 5..3600"
[[ "$CLUSTER_NODE_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] && (( CLUSTER_NODE_TIMEOUT_SECONDS >= CLUSTER_HEARTBEAT_SECONDS*2 && CLUSTER_NODE_TIMEOUT_SECONDS <= 86400 )) || die "--cluster-node-timeout must be at least 2x heartbeat interval and <=86400"
[[ "$CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS" =~ ^[0-9]+$ ]] && (( CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS >= 50 && CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS <= 5000 )) || die "--cluster-global-dedup-timeout-ms must be 50..5000"
[[ "$CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES" =~ ^[0-9]+$ ]] && (( CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES >= 1000 && CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES <= 5000000 )) || die "--cluster-global-dedup-max must be 1000..5000000"
if [[ -n "$CLUSTER_HEARTBEAT_URL" ]]; then
  [[ "$CLUSTER_HEARTBEAT_URL" =~ ^https?://[^[:space:]]+$ ]] || die "--cluster-heartbeat-url must be an absolute http(s) URL"
  if [[ "$CLUSTER_HEARTBEAT_URL" == http://* ]] && (( CLUSTER_ALLOW_INSECURE_HTTP == 0 )); then
    case "$CLUSTER_HEARTBEAT_URL" in
      http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) ;;
      *) die "Remote cluster heartbeats must use HTTPS unless --cluster-allow-insecure-http is supplied";;
    esac
  fi
fi
if [[ -n "$HTTPS_CERT" || -n "$HTTPS_KEY" ]]; then
  [[ -n "$HTTPS_CERT" && -n "$HTTPS_KEY" ]] || die "--https-cert and --https-key must be supplied together."
  [[ -r "$HTTPS_CERT" ]] || die "Cannot read HTTPS certificate: $HTTPS_CERT"
  [[ -r "$HTTPS_KEY" ]] || die "Cannot read HTTPS key: $HTTPS_KEY"
  (( FORCE_HTTP == 0 )) || die "--http cannot be combined with --https-cert/--https-key."
fi


if [[ -n "$CLUSTER_GLOBAL_DEDUP_URL" ]]; then
  [[ "$CLUSTER_GLOBAL_DEDUP_URL" =~ ^https?://[^[:space:]]+$ ]] || die "--cluster-global-dedup-url must be an absolute http(s) URL"
  if [[ "$CLUSTER_GLOBAL_DEDUP_URL" == http://* ]] && (( CLUSTER_ALLOW_INSECURE_HTTP == 0 )); then
    case "$CLUSTER_GLOBAL_DEDUP_URL" in
      http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) ;;
      *) die "Remote global dedup URL must use HTTPS unless --cluster-allow-insecure-http is explicit";;
    esac
  fi
fi
[[ "$CLICKHOUSE_PORT" =~ ^[0-9]+$ ]] && (( CLICKHOUSE_PORT >= 1 && CLICKHOUSE_PORT <= 65535 )) || die "--clickhouse-port must be 1..65535"
[[ "$CLICKHOUSE_RETENTION_DAYS" =~ ^[0-9]+$ ]] && (( CLICKHOUSE_RETENTION_DAYS >= 1 && CLICKHOUSE_RETENTION_DAYS <= 3650 )) || die "--clickhouse-retention must be 1..3650"
[[ "$CLICKHOUSE_SCHEME" == "http" || "$CLICKHOUSE_SCHEME" == "https" ]] || die "--clickhouse-scheme must be http or https"
[[ "$CLICKHOUSE_CHANNEL" == "stable" || "$CLICKHOUSE_CHANNEL" == "lts" ]] || die "--clickhouse-channel must be stable or lts"
for ident in "$CLICKHOUSE_DATABASE" "$CLICKHOUSE_TABLE" "$CLICKHOUSE_USER" "$CLICKHOUSE_ADMIN_USER"; do
  [[ "$ident" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "ClickHouse database/table/user identifiers may contain only letters, digits and underscore and may not start with a digit: $ident"
done
if [[ -n "$CLICKHOUSE_ADMIN_PASSWORD_FILE" ]]; then
  [[ -r "$CLICKHOUSE_ADMIN_PASSWORD_FILE" ]] || die "Cannot read ClickHouse admin password file: $CLICKHOUSE_ADMIN_PASSWORD_FILE"
  CLICKHOUSE_ADMIN_PASSWORD="$(tr -d '\r\n' < "$CLICKHOUSE_ADMIN_PASSWORD_FILE")"
fi

web_value(){
  local key="$1" file="$2"
  awk -v key="$key" '
    /^web:[[:space:]]*$/ { inweb=1; next }
    inweb && /^[^[:space:]]/ { exit }
    inweb {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      if (index(line, key ":") == 1) {
        sub(/^[^:]+:[[:space:]]*/, "", line)
        first=substr(line,1,1)
        last=substr(line,length(line),1)
        squote=sprintf("%c",39)
        if ((first=="\"" && last=="\"") || (first==squote && last==squote)) {
          line=substr(line,2,length(line)-2)
        }
        print line
        exit
      }
    }
  ' "$file"
}

set_web_value(){
  local key="$1" value="$2" file="$3"
  sed -i "/^web:[[:space:]]*$/,/^[^[:space:]]/ s#^  ${key}:.*#  ${key}: ${value}#" "$file"
}

section_value(){
  local section="$1" key="$2" file="$3"
  awk -v section="$section" -v key="$key" '
    $0 ~ "^" section ":[[:space:]]*$" { inside=1; next }
    inside && /^[^[:space:]]/ { exit }
    inside {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      if (index(line, key ":") == 1) {
        sub(/^[^:]+:[[:space:]]*/, "", line)
        first=substr(line,1,1); last=substr(line,length(line),1); squote=sprintf("%c",39)
        if ((first=="\"" && last=="\"") || (first==squote && last==squote)) line=substr(line,2,length(line)-2)
        print line; exit
      }
    }
  ' "$file"
}

set_section_value(){
  local section="$1" key="$2" value="$3" file="$4"
  if ! grep -q "^${section}:[[:space:]]*$" "$file"; then
    printf '\n%s:\n  %s: %s\n' "$section" "$key" "$value" >> "$file"
    return
  fi
  if sed -n "/^${section}:[[:space:]]*$/,/^[^[:space:]]/p" "$file" | grep -q "^[[:space:]]\{2\}${key}:"; then
    sed -i "/^${section}:[[:space:]]*$/,/^[^[:space:]]/ s#^  ${key}:.*#  ${key}: ${value}#" "$file"
  else
    awk -v sec="$section" -v entry="  ${key}: ${value}" '
      $0 ~ "^" sec ":[[:space:]]*$" { print; print entry; next }
      { print }
    ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
  fi
}

random_secret(){
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 36 | tr -d '\n' | tr '/+' '_-';
  else od -An -N36 -tx1 /dev/urandom | tr -d ' \n'; fi
}

sql_quote(){
  # ClickHouse string literal escaping: backslash and single quote.
  printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g"
}

clickhouse_url(){
  local host="$CLICKHOUSE_HOST"
  [[ "$host" == *:* && "$host" != \[*\] ]] && host="[$host]"
  printf '%s://%s:%s' "$CLICKHOUSE_SCHEME" "$host" "$CLICKHOUSE_PORT"
}

ch_query(){
  local user="$1" password="$2" query="$3" url
  url="$(clickhouse_url)"
  local args=(--fail --silent --show-error --connect-timeout 5 --max-time 30 -X POST --data-binary "$query")
  [[ -n "$user" ]] && args+=(-u "$user:$password")
  curl "${args[@]}" "$url/"
}

wait_clickhouse(){
  local user="$1" password="$2"
  for _ in {1..60}; do
    if ch_query "$user" "$password" "SELECT 1" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

install_clickhouse_packages(){
  if command -v clickhouse-server >/dev/null 2>&1 && command -v clickhouse-client >/dev/null 2>&1; then
    ok "ClickHouse packages already installed"
    return 0
  fi
  step "Installing ClickHouse server/client ($CLICKHOUSE_CHANNEL channel)"
  if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends ca-certificates curl gnupg apt-transport-https
    install -d -m 0755 /usr/share/keyrings
    if [[ ! -s /usr/share/keyrings/clickhouse-keyring.gpg ]]; then
      curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
    fi
    local arch
    arch="$(dpkg --print-architecture)"
    printf 'deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=%s] https://packages.clickhouse.com/deb %s main\n' "$arch" "$CLICKHOUSE_CHANNEL" > /etc/apt/sources.list.d/clickhouse.list
    apt-get update -qq
    apt-get install -y clickhouse-server clickhouse-client
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    local pm="yum"; command -v dnf >/dev/null 2>&1 && pm="dnf"
    if [[ ! -f /etc/yum.repos.d/clickhouse.repo ]]; then
      curl -fsSL https://packages.clickhouse.com/rpm/clickhouse.repo -o /etc/yum.repos.d/clickhouse.repo
    fi
    if [[ "$CLICKHOUSE_CHANNEL" == "lts" ]]; then
      "$pm" --disablerepo=clickhouse-stable --enablerepo=clickhouse-lts install -y clickhouse-server clickhouse-client
    else
      "$pm" --disablerepo=clickhouse-lts --enablerepo=clickhouse-stable install -y clickhouse-server clickhouse-client
    fi
  else
    die "Automatic local ClickHouse installation supports apt/dpkg and dnf/yum systems. Use --clickhouse-host for a remote server or install ClickHouse manually."
  fi
  command -v clickhouse-client >/dev/null 2>&1 || die "ClickHouse client was not installed successfully"
  ok "ClickHouse packages installed"
}

install_docker_runtime(){
  command -v docker >/dev/null 2>&1 && return 0
  step "Installing Docker runtime for $DISTRO_ID $DISTRO_VERSION"
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y --no-install-recommends docker.io
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y docker
  elif command -v yum >/dev/null 2>&1; then
    yum install -y docker
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm docker
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install docker
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache docker
  else
    die "Docker is required for the default ClickHouse installation; unsupported package manager on $DISTRO_ID"
  fi
  command -v docker >/dev/null 2>&1 || die "Docker installation did not provide the docker command"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || systemctl start docker >/dev/null 2>&1 || true
  elif command -v rc-service >/dev/null 2>&1; then
    rc-update add docker default >/dev/null 2>&1 || true
    rc-service docker start >/dev/null 2>&1 || true
  elif command -v service >/dev/null 2>&1; then
    service docker start >/dev/null 2>&1 || true
  fi
}

configure_local_clickhouse_service(){
  systemctl enable clickhouse-server.service >/dev/null 2>&1 || systemctl enable clickhouse-server >/dev/null 2>&1 || true
  systemctl restart clickhouse-server.service >/dev/null 2>&1 || systemctl restart clickhouse-server >/dev/null 2>&1 || die "Could not start ClickHouse server"
  wait_clickhouse "$CLICKHOUSE_ADMIN_USER" "$CLICKHOUSE_ADMIN_PASSWORD" || {
    journalctl -u clickhouse-server -n 100 --no-pager 2>/dev/null || true
    die "Local ClickHouse did not become ready. If an existing default/admin password is configured, pass --clickhouse-admin-password-file."
  }
  ok "Local ClickHouse is active and answers SQL over HTTP"
}

provision_clickhouse(){
  local admin_user="$CLICKHOUSE_ADMIN_USER" admin_password="$CLICKHOUSE_ADMIN_PASSWORD"
  local db="$CLICKHOUSE_DATABASE" tbl="$CLICKHOUSE_TABLE" app="$CLICKHOUSE_USER"
  local pwq; pwq="$(sql_quote "$CLICKHOUSE_PASSWORD")"
  if (( CLICKHOUSE_NO_PROVISION )); then
    info "ClickHouse provisioning disabled; validating application credentials only"
    wait_clickhouse "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" || die "Cannot authenticate to ClickHouse with the supplied application credentials"
    return 0
  fi
  wait_clickhouse "$admin_user" "$admin_password" || die "Cannot authenticate to ClickHouse bootstrap/admin account at $(clickhouse_url). Supply working --clickhouse-admin-* credentials or use --clickhouse-no-provision for a pre-provisioned database."
  ch_query "$admin_user" "$admin_password" "CREATE DATABASE IF NOT EXISTS \`$db\`" >/dev/null
  ch_query "$admin_user" "$admin_password" "CREATE USER IF NOT EXISTS \`$app\` IDENTIFIED WITH sha256_password BY '$pwq'" >/dev/null
  # Keep repeated installer runs deterministic: the service credential in the
  # root-owned environment file and ClickHouse are intentionally synchronized.
  ch_query "$admin_user" "$admin_password" "ALTER USER \`$app\` IDENTIFIED WITH sha256_password BY '$pwq'" >/dev/null
  ch_query "$admin_user" "$admin_password" "GRANT SELECT, INSERT, ALTER, CREATE ON \`$db\`.* TO \`$app\`" >/dev/null
  wait_clickhouse "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" || die "Provisioned ClickHouse user cannot authenticate"
  # Application startup owns the exact schema migrations. Verify DDL/DML/read
  # rights independently with a disposable table before switching the service.
  local probe="_flowcollector_install_probe_$$"
  ch_query "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" "CREATE TABLE \`$db\`.\`$probe\` (n UInt8) ENGINE=Memory" >/dev/null || die "ClickHouse application user cannot create tables in $db"
  ch_query "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" "INSERT INTO \`$db\`.\`$probe\` VALUES (1)" >/dev/null || die "ClickHouse application user cannot insert"
  [[ "$(ch_query "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" "SELECT count() FROM \`$db\`.\`$probe\`" | tr -d '[:space:]')" == "1" ]] || die "ClickHouse read/write probe failed"
  ch_query "$admin_user" "$admin_password" "DROP TABLE IF EXISTS \`$db\`.\`$probe\`" >/dev/null || true
  ok "ClickHouse database/user/grants and read/write probe completed"
}

rollback_snapshot(){
  local snap="$1"
  [[ -d "$snap" ]] || return 1
  warn "Restoring previous release from $snap"
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  [[ -f "$snap/flowcollector" ]] && install -m 0755 -o root -g root "$snap/flowcollector" "$PREFIX/flowcollector"
  [[ -f "$snap/flowgen" ]] && install -m 0755 -o root -g root "$snap/flowgen" "$PREFIX/flowgen"
  [[ -f "$snap/chbench" ]] && install -m 0755 -o root -g root "$snap/chbench" "$PREFIX/chbench"
  [[ -f "$snap/config.yaml" ]] && install -m 0640 -o root -g "$SERVICE_GROUP" "$snap/config.yaml" "$CONFIG_FILE"
  if [[ -f "$snap/clickhouse.env" ]]; then
    install -m 0640 -o root -g "$SERVICE_GROUP" "$snap/clickhouse.env" "$CONFIG_DIR/clickhouse.env"
  elif [[ -f "$CONFIG_DIR/clickhouse.env" ]]; then
    rm -f "$CONFIG_DIR/clickhouse.env"
  fi
  if [[ -f "$snap/cluster.token" ]]; then
    install -m 0640 -o root -g "$SERVICE_GROUP" "$snap/cluster.token" "$CONFIG_DIR/cluster.token"
  fi
  [[ -f "$snap/$SERVICE" ]] && install -m 0644 -o root -g root "$snap/$SERVICE" "$SYSTEMD_DIR/$SERVICE"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE" || true
  sleep 1
  if systemctl is-active --quiet "$SERVICE"; then ok "Rollback restored an active service"; return 0; fi
  warn "Rollback files were restored but the previous service did not become active"
  return 1
}

if [[ "$MODE" == "rollback" ]]; then
  step "Rolling back to previous installer snapshot"
  LATEST="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2- || true)"
  [[ -n "$LATEST" ]] || die "No rollback snapshot found under $BACKUP_ROOT"
  rollback_snapshot "$LATEST" || die "Rollback restoration failed; inspect systemctl/journalctl output."
  ok "Rollback complete: $LATEST"
  exit 0
fi

if [[ "$MODE" == "upgrade" ]]; then
  [[ -x "$PREFIX/flowcollector" && -f "$CONFIG_FILE" ]] || die "--upgrade requires an existing flowcollector binary and configuration."
fi

printf "%bCentral Flow Collector %s — Zero-TLS-Friction Installer%b\n" "$C_BOLD" "$VERSION" "$C_RESET"
printf "Source: %s\n" "$SOURCE_DIR"

step "Preflight checks"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64";;
  aarch64|arm64) ARCH="arm64";;
  *) die "Unsupported Linux architecture: $ARCH_RAW";;
esac
BINARY=""
for f in "$SOURCE_DIR/dist/flowcollector-linux-$ARCH" "$SOURCE_DIR/flowcollector-linux-$ARCH" "$SOURCE_DIR/flowcollector"; do
  [[ -x "$f" ]] && BINARY="$f" && break
done
[[ -n "$BINARY" ]] || die "No executable flowcollector binary found for linux/$ARCH."
FLOWGEN=""
for f in "$SOURCE_DIR/dist/flowgen-linux-$ARCH" "$SOURCE_DIR/flowgen-linux-$ARCH"; do
  [[ -x "$f" ]] && FLOWGEN="$f" && break
done
ok "Architecture: linux/$ARCH"
ok "Application binary: $BINARY"
[[ -n "$FLOWGEN" ]] && ok "Flow generator binary: $FLOWGEN" || warn "flowgen binary not found; collector installation can continue."
CHBENCH=""
for f in "$SOURCE_DIR/dist/chbench-linux-$ARCH" "$SOURCE_DIR/chbench-linux-$ARCH"; do
  [[ -x "$f" ]] && CHBENCH="$f" && break
done
[[ -n "$CHBENCH" ]] && ok "ClickHouse benchmark binary: $CHBENCH" || info "chbench binary not found; optional benchmark tool will not be installed."

CHECKSUM_DIR=""
if [[ -f "$SOURCE_DIR/dist/checksums.txt" ]]; then
  CHECKSUM_DIR="$SOURCE_DIR/dist"
elif [[ -f "$SOURCE_DIR/checksums.txt" ]]; then
  CHECKSUM_DIR="$SOURCE_DIR"
fi
if command -v sha256sum >/dev/null 2>&1 && [[ -n "$CHECKSUM_DIR" ]]; then
  info "Verifying packaged SHA256 checksums"
  (cd "$CHECKSUM_DIR" && sha256sum -c checksums.txt --ignore-missing) || die "Checksum verification failed."
  ok "Checksums verified"
fi

step "Service identity and filesystem"
install -d -m 0755 -o root -g root "$PREFIX"
if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then groupadd --system "$SERVICE_GROUP"; ok "Created group $SERVICE_GROUP"; fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "Created service user $SERVICE_USER"
fi
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR" "$DATA_DIR/flows" "$DATA_DIR/enrichment" "$DATA_DIR/threat-intel"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR/clickhouse" "$DATA_DIR/clickhouse-logs"
GEOASN_SOURCE=""
[[ -f "$SOURCE_DIR/geoasn.csv" ]] && GEOASN_SOURCE="$SOURCE_DIR/geoasn.csv"
[[ -f "$SOURCE_DIR/assets/geoasn.csv" ]] && GEOASN_SOURCE="$SOURCE_DIR/assets/geoasn.csv"
if [[ ! -e "$DATA_DIR/enrichment/geoasn.csv" && -n "$GEOASN_SOURCE" ]]; then
  install -m 0640 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$GEOASN_SOURCE" "$DATA_DIR/enrichment/geoasn.csv"
  ok "Installed default GeoIP/ASN CSV at $DATA_DIR/enrichment/geoasn.csv"
fi
TI_SAMPLE_SRC=""
if [[ -r "$SOURCE_DIR/threat-intel.sample.csv" ]]; then TI_SAMPLE_SRC="$SOURCE_DIR/threat-intel.sample.csv";
elif [[ -r "$SOURCE_DIR/testdata/threatintel/iocs.sample.csv" ]]; then TI_SAMPLE_SRC="$SOURCE_DIR/testdata/threatintel/iocs.sample.csv"; fi
if [[ -n "$TI_SAMPLE_SRC" && ! -e "$DATA_DIR/threat-intel/iocs.sample.csv" ]]; then
  install -m 0640 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$TI_SAMPLE_SRC" "$DATA_DIR/threat-intel/iocs.sample.csv"
fi
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR/tls"
CLUSTER_TOKEN_TARGET="$CONFIG_DIR/cluster.token"
if [[ -n "$CLUSTER_TOKEN_SOURCE" ]]; then
  install -m 0640 -o root -g "$SERVICE_GROUP" "$CLUSTER_TOKEN_SOURCE" "$CLUSTER_TOKEN_TARGET"
  ok "Installed supplied cluster heartbeat token"
elif [[ ! -s "$CLUSTER_TOKEN_TARGET" ]]; then
  if [[ -n "$CLUSTER_HEARTBEAT_URL" ]]; then
    die "Remote heartbeat mode requires --cluster-token-file copied securely from the central collector."
  fi
  umask 0027
  random_secret > "$CLUSTER_TOKEN_TARGET"
  chown root:"$SERVICE_GROUP" "$CLUSTER_TOKEN_TARGET"
  chmod 0640 "$CLUSTER_TOKEN_TARGET"
  ok "Generated cluster registration token: $CLUSTER_TOKEN_TARGET"
fi

# A previous manual root run or older installer may have created persistent files
# as root:root.  The hardened systemd service intentionally runs unprivileged, so
# repair only the application data tree before the service starts.  -xdev avoids
# crossing into another mounted filesystem and chown -h never follows symlinks.
if find "$DATA_DIR" -xdev \( ! -user "$SERVICE_USER" -o ! -group "$SERVICE_GROUP" \) -print -quit 2>/dev/null | grep -q .; then
  info "Repairing ownership of existing application data for $SERVICE_USER:$SERVICE_GROUP"
  find "$DATA_DIR" -xdev \( ! -user "$SERVICE_USER" -o ! -group "$SERVICE_GROUP" \) -exec chown -h "$SERVICE_USER:$SERVICE_GROUP" {} +
  ok "Existing application data ownership repaired"
fi
# Keep bootstrap credentials private even when migrating a root-created first run.
if [[ -e "$DATA_DIR/bootstrap-admin.txt" ]]; then
  chown -h "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/bootstrap-admin.txt"
  chmod 0600 "$DATA_DIR/bootstrap-admin.txt"
fi

# Snapshot the managed release before replacing it. Persistent telemetry is not copied;
# v2.0.0 schema changes are additive/non-destructive and data remains in place.
if [[ -x "$PREFIX/flowcollector" || -f "$CONFIG_FILE" || -f "$SYSTEMD_DIR/$SERVICE" ]]; then
  install -d -m 0700 -o root -g root "$BACKUP_ROOT"
  SNAPSHOT="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -m 0700 -o root -g root "$SNAPSHOT"
  [[ -x "$PREFIX/flowcollector" ]] && cp -a "$PREFIX/flowcollector" "$SNAPSHOT/flowcollector"
  [[ -x "$PREFIX/flowgen" ]] && cp -a "$PREFIX/flowgen" "$SNAPSHOT/flowgen"
  [[ -x "$PREFIX/chbench" ]] && cp -a "$PREFIX/chbench" "$SNAPSHOT/chbench"
  [[ -f "$CONFIG_FILE" ]] && cp -a "$CONFIG_FILE" "$SNAPSHOT/config.yaml"
  [[ -f "$CONFIG_DIR/clickhouse.env" ]] && cp -a "$CONFIG_DIR/clickhouse.env" "$SNAPSHOT/clickhouse.env"
  [[ -f "$CONFIG_DIR/cluster.token" ]] && cp -a "$CONFIG_DIR/cluster.token" "$SNAPSHOT/cluster.token"
  [[ -f "$SYSTEMD_DIR/$SERVICE" ]] && cp -a "$SYSTEMD_DIR/$SERVICE" "$SNAPSHOT/$SERVICE"
  { date -u +%Y-%m-%dT%H:%M:%SZ; "$PREFIX/flowcollector" version 2>/dev/null || true; } > "$SNAPSHOT/metadata.txt"
  ok "Rollback snapshot: $SNAPSHOT"
fi

step "Installing binaries"
install -m 0755 -o root -g root "$BINARY" "$PREFIX/flowcollector"
[[ -n "$FLOWGEN" ]] && install -m 0755 -o root -g root "$FLOWGEN" "$PREFIX/flowgen"
[[ -n "$CHBENCH" ]] && install -m 0755 -o root -g root "$CHBENCH" "$PREFIX/chbench"
ok "Installed $PREFIX/flowcollector"
"$PREFIX/flowcollector" version | sed 's/^/    /'

step "Configuration and v1.0.0 migration"
FRESH=0
if [[ -f "$CONFIG_FILE" ]]; then
  BACKUP="$CONFIG_FILE.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$CONFIG_FILE" "$BACKUP"
  info "Existing configuration backed up to $BACKUP"
else
  [[ -f "$SOURCE_DIR/config.example.yaml" ]] || die "config.example.yaml is missing from release."
  cp "$SOURCE_DIR/config.example.yaml" "$CONFIG_FILE"
  FRESH=1
  ok "Created configuration from v2.0.0 defaults"
fi

# Always update data paths to the chosen installation location.
sed -i \
  -e "s#data_dir: \"/var/lib/flowcollector\"#data_dir: \"$DATA_DIR\"#" \
  -e "s#bootstrap_file: \"/var/lib/flowcollector/bootstrap-admin.txt\"#bootstrap_file: \"$DATA_DIR/bootstrap-admin.txt\"#" \
  -e "s#prefix_file: \"/var/lib/flowcollector/enrichment/geoasn.csv\"#prefix_file: \"$DATA_DIR/enrichment/geoasn.csv\"#" \
  -e "s#feed_file: \"/var/lib/flowcollector/threat-intel/iocs.csv\"#feed_file: \"$DATA_DIR/threat-intel/iocs.csv\"#" \
  -e "s#baseline_state_file: \"/var/lib/flowcollector/baseline-state.json\"#baseline_state_file: \"$DATA_DIR/baseline-state.json\"#" \
  "$CONFIG_FILE"

set_section_value cluster shared_token_file "\"$CLUSTER_TOKEN_TARGET\"" "$CONFIG_FILE"
if (( FRESH || CLUSTER_HEARTBEAT_SECONDS_SET )); then set_section_value cluster heartbeat_seconds "$CLUSTER_HEARTBEAT_SECONDS" "$CONFIG_FILE"; fi
if (( FRESH || CLUSTER_NODE_TIMEOUT_SECONDS_SET )); then set_section_value cluster node_timeout_seconds "$CLUSTER_NODE_TIMEOUT_SECONDS" "$CONFIG_FILE"; fi
if (( CLUSTER_HEARTBEAT_URL_SET )); then set_section_value cluster heartbeat_url "\"$CLUSTER_HEARTBEAT_URL\"" "$CONFIG_FILE"; fi
if (( CLUSTER_ALLOW_INSECURE_HTTP )); then set_section_value cluster allow_insecure_http "true" "$CONFIG_FILE"; fi
if (( FRESH || CLUSTER_GLOBAL_DEDUP_ENABLED_SET )); then set_section_value cluster global_dedup_enabled "$([[ $CLUSTER_GLOBAL_DEDUP_ENABLED -eq 1 ]] && echo true || echo false)" "$CONFIG_FILE"; fi
if (( FRESH || CLUSTER_GLOBAL_DEDUP_URL_SET )); then set_section_value cluster global_dedup_url "\"$CLUSTER_GLOBAL_DEDUP_URL\"" "$CONFIG_FILE"; fi
if (( FRESH || CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS_SET )); then set_section_value cluster global_dedup_timeout_ms "$CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS" "$CONFIG_FILE"; fi
if (( FRESH || CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES_SET )); then set_section_value cluster global_dedup_max_entries "$CLUSTER_GLOBAL_DEDUP_MAX_ENTRIES" "$CONFIG_FILE"; fi

CURRENT_TLS="$(web_value tls "$CONFIG_FILE" || true)"
CURRENT_CERT="$(web_value cert_file "$CONFIG_FILE" || true)"
CURRENT_KEY="$(web_value key_file "$CONFIG_FILE" || true)"
CURRENT_PORT="$(web_value port "$CONFIG_FILE" || true)"
CURRENT_BIND="$(web_value bind "$CONFIG_FILE" || true)"

# Migrate the v1.0.0 auto-self-signed profile. Custom explicit TLS is preserved.
if (( FRESH == 0 )) && [[ "$CURRENT_TLS" == "true" ]] && [[ -z "$CURRENT_CERT" || -z "$CURRENT_KEY" ]]; then
  warn "Legacy auto/self-signed TLS profile detected. Migrating to certificate-free loopback HTTP mode."
  set_web_value tls "false" "$CONFIG_FILE"
  set_web_value cert_file '""' "$CONFIG_FILE"
  set_web_value key_file '""' "$CONFIG_FILE"
  if [[ "$CURRENT_PORT" == "8443" ]]; then set_web_value port "8080" "$CONFIG_FILE"; fi
  if (( WEB_BIND_SET == 0 )); then set_web_value bind '"127.0.0.1"' "$CONFIG_FILE"; fi
fi

# v1.0.1 could leave a legacy 0.0.0.0 HTTP bind behind after TLS migration.
# For a secure zero-friction upgrade, narrow unmanaged plaintext HTTP to loopback.
# Administrators who intentionally need remote HTTP must opt in explicitly with
# --web-bind 0.0.0.0 (prefer a trusted TLS reverse proxy in real deployments).
if (( FRESH == 0 && WEB_BIND_SET == 0 )) && [[ "$CURRENT_TLS" != "true" ]]    && [[ "$CURRENT_PORT" == "8080" ]]    && { [[ "$CURRENT_BIND" == "0.0.0.0" ]] || [[ "$CURRENT_BIND" == "::" ]] || [[ -z "$CURRENT_BIND" ]]; }; then
  warn "Legacy plaintext all-interface web bind detected; narrowing Web UI to 127.0.0.1."
  set_web_value bind '"127.0.0.1"' "$CONFIG_FILE"
fi

if (( WEB_BIND_SET )); then set_web_value bind "\"$WEB_BIND\"" "$CONFIG_FILE"; fi
if (( WEB_PORT_SET )); then set_web_value port "$WEB_PORT" "$CONFIG_FILE"; fi
if (( FRESH )); then
  set_web_value bind "\"$WEB_BIND\"" "$CONFIG_FILE"
  set_web_value port "$WEB_PORT" "$CONFIG_FILE"
fi

if (( FORCE_HTTP )); then
  set_web_value tls "false" "$CONFIG_FILE"
  set_web_value cert_file '""' "$CONFIG_FILE"
  set_web_value key_file '""' "$CONFIG_FILE"
elif [[ -n "$HTTPS_CERT" ]]; then
  DEST_CERT="$CONFIG_DIR/tls/server.crt"
  DEST_KEY="$CONFIG_DIR/tls/server.key"
  install -m 0644 -o root -g "$SERVICE_GROUP" "$HTTPS_CERT" "$DEST_CERT"
  install -m 0640 -o root -g "$SERVICE_GROUP" "$HTTPS_KEY" "$DEST_KEY"
  set_web_value tls "true" "$CONFIG_FILE"
  set_web_value cert_file "\"$DEST_CERT\"" "$CONFIG_FILE"
  set_web_value key_file "\"$DEST_KEY\"" "$CONFIG_FILE"
  ok "Installed administrator-supplied HTTPS certificate/key"
fi

# ---- Storage profile / ClickHouse provisioning ---------------------------------
CLICKHOUSE_ENV_FILE="$CONFIG_DIR/clickhouse.env"
CURRENT_STORAGE_BACKEND="$(section_value storage backend "$CONFIG_FILE" || true)"
CURRENT_STORAGE_BACKEND="${CURRENT_STORAGE_BACKEND:-local}"

if [[ "$CLICKHOUSE_MODE" == "auto" ]]; then
  if (( FRESH )); then
    CLICKHOUSE_MODE="docker"
  elif [[ "$CURRENT_STORAGE_BACKEND" == "clickhouse" ]]; then
    CLICKHOUSE_MODE="existing"
  else
    # Never silently move historical JSONL data to a different backend during
    # an upgrade. The operator can opt in with --clickhouse-local/--clickhouse-host.
    CLICKHOUSE_MODE="disabled"
    info "Upgrade preserves existing local storage. Use --clickhouse-local or --clickhouse-host to switch explicitly."
  fi
fi

if [[ "$CLICKHOUSE_MODE" == "docker" || "$CLICKHOUSE_MODE" == "local" || "$CLICKHOUSE_MODE" == "remote" ]]; then
  [[ -n "$CLICKHOUSE_HOST" && "$CLICKHOUSE_HOST" != *"://"* && "$CLICKHOUSE_HOST" != *[[:space:]]* ]] || die "--clickhouse-host must be a hostname/IP without scheme or whitespace"
  if (( CLICKHOUSE_NO_PROVISION == 0 )) && [[ "$CLICKHOUSE_USER" == "$CLICKHOUSE_ADMIN_USER" ]]; then
    die "ClickHouse application user and bootstrap/admin user must be different; use a dedicated --clickhouse-user"
  fi
  command -v curl >/dev/null 2>&1 || {
    if [[ "$CLICKHOUSE_MODE" == "local" ]] && command -v apt-get >/dev/null 2>&1; then :; else die "curl is required for ClickHouse provisioning"; fi
  }

  if [[ "$CLICKHOUSE_MODE" == "docker" ]]; then
    install_docker_runtime
    docker info >/dev/null 2>&1 || die "Docker daemon is unavailable. Start Docker or use --local-storage."
    CLICKHOUSE_HOST="127.0.0.1"
    CLICKHOUSE_SCHEME="http"
    CLICKHOUSE_PORT="8123"
    if (( CLICKHOUSE_PASSWORD_SET == 0 )); then
      CLICKHOUSE_PASSWORD="$(random_secret)"
      CLICKHOUSE_PASSWORD_SET=1
      info "Generated a strong dedicated ClickHouse application password"
    fi
    [[ -n "$CLICKHOUSE_PASSWORD" ]] || die "ClickHouse application password must not be empty"
    if docker container inspect flowcollector-clickhouse >/dev/null 2>&1; then
      die "Docker container flowcollector-clickhouse already exists; provide its credentials and manage it explicitly before rerunning."
    fi
    docker run -d --name flowcollector-clickhouse --restart unless-stopped \
      --user "$(id -u "$SERVICE_USER"):$(id -g "$SERVICE_USER")" --ulimit nofile=262144:262144 \
      -p 127.0.0.1:8123:8123 \
      --mount "type=bind,src=$DATA_DIR/clickhouse,dst=/var/lib/clickhouse" \
      --mount "type=bind,src=$DATA_DIR/clickhouse-logs,dst=/var/log/clickhouse-server" \
      -e CLICKHOUSE_DB="$CLICKHOUSE_DATABASE" -e CLICKHOUSE_USER="$CLICKHOUSE_USER" \
      -e CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
      clickhouse/clickhouse-server:26.8 >/dev/null || die "Could not start ClickHouse Docker container"
    wait_clickhouse "$CLICKHOUSE_USER" "$CLICKHOUSE_PASSWORD" || die "Docker ClickHouse did not become ready"
    CLICKHOUSE_NO_PROVISION=1
    ok "Docker ClickHouse is ready on 127.0.0.1:8123"
  elif [[ "$CLICKHOUSE_MODE" == "local" ]]; then
    CLICKHOUSE_HOST="127.0.0.1"
    CLICKHOUSE_SCHEME="http"
    CLICKHOUSE_PORT="8123"
    install_clickhouse_packages
    command -v curl >/dev/null 2>&1 || die "curl is required after ClickHouse package installation"
    configure_local_clickhouse_service
  else
    info "Remote ClickHouse mode: $(clickhouse_url)"
  fi

  if (( CLICKHOUSE_NO_PROVISION && CLICKHOUSE_PASSWORD_SET == 0 )); then
    die "--clickhouse-no-provision requires --clickhouse-password or --clickhouse-password-file so existing application credentials can be validated"
  fi
  if (( CLICKHOUSE_PASSWORD_SET == 0 )); then
    CLICKHOUSE_PASSWORD="$(random_secret)"
    CLICKHOUSE_PASSWORD_SET=1
    info "Generated a strong dedicated ClickHouse application password"
  fi
  [[ -n "$CLICKHOUSE_PASSWORD" ]] || die "ClickHouse application password must not be empty"

  if [[ -n "$CLICKHOUSE_CLUSTER" && $CLICKHOUSE_NO_PROVISION -eq 0 ]]; then
    die "--clickhouse-cluster targets an existing multi-node ClickHouse cluster. Pre-provision the database/application user across all nodes and use --clickhouse-no-provision with the application password; the installer will validate credentials and create the Replicated/Distributed schema."
  fi
  provision_clickhouse

  # Keep secrets outside YAML and outside command lines used by the service.
  CH_ENV_ESCAPED="$(printf '%s' "$CLICKHOUSE_PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  umask 0027
  printf 'FLOWCOLLECTOR_CLICKHOUSE_PASSWORD="%s"\n' "$CH_ENV_ESCAPED" > "$CLICKHOUSE_ENV_FILE"
  chown root:"$SERVICE_GROUP" "$CLICKHOUSE_ENV_FILE"
  chmod 0640 "$CLICKHOUSE_ENV_FILE"

  CH_URL="$(clickhouse_url)"
  set_section_value storage backend '"clickhouse"' "$CONFIG_FILE"
  set_section_value storage clickhouse_url "\"$CH_URL\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_database "\"$CLICKHOUSE_DATABASE\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_table "\"$CLICKHOUSE_TABLE\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_user "\"$CLICKHOUSE_USER\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_password '""' "$CONFIG_FILE"
  set_section_value storage retention_days "$CLICKHOUSE_RETENTION_DAYS" "$CONFIG_FILE"
  set_section_value storage clickhouse_cluster "\"$CLICKHOUSE_CLUSTER\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_distributed_table "\"$CLICKHOUSE_DISTRIBUTED_TABLE\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_replica_path "\"$CLICKHOUSE_REPLICA_PATH\"" "$CONFIG_FILE"
  set_section_value storage clickhouse_replica_name "\"$CLICKHOUSE_REPLICA_NAME\"" "$CONFIG_FILE"
  ok "Collector storage configured for ClickHouse: $CH_URL/$CLICKHOUSE_DATABASE.$CLICKHOUSE_TABLE"
elif [[ "$CLICKHOUSE_MODE" == "disabled" ]]; then
  if (( CLICKHOUSE_MODE_SET )); then
    set_section_value storage backend '"local"' "$CONFIG_FILE"
    rm -f "$CLICKHOUSE_ENV_FILE"
    ok "Collector storage explicitly configured for local JSONL mode"
  fi
elif [[ "$CLICKHOUSE_MODE" == "existing" ]]; then
  info "Preserving existing ClickHouse storage configuration and credentials"
else
  die "Internal installer error: unknown ClickHouse mode $CLICKHOUSE_MODE"
fi

chmod 0640 "$CONFIG_FILE"
chown root:"$SERVICE_GROUP" "$CONFIG_FILE"
"$PREFIX/flowcollector" config validate --config "$CONFIG_FILE" || die "Configuration validation failed."
ok "Configuration validation passed"

if [[ "$CLICKHOUSE_MODE" == "docker" || "$CLICKHOUSE_MODE" == "local" || "$CLICKHOUSE_MODE" == "remote" ]]; then
  step "Initializing ClickHouse flow schema"
  FLOWCOLLECTOR_CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" "$PREFIX/flowcollector" migrate --config "$CONFIG_FILE" || die "ClickHouse schema initialization failed"
  ok "ClickHouse schema/TTL migration completed"
fi

FINAL_BIND="$(web_value bind "$CONFIG_FILE")"
FINAL_PORT="$(web_value port "$CONFIG_FILE")"
FINAL_TLS="$(web_value tls "$CONFIG_FILE")"
if [[ "$FINAL_TLS" != "true" && "$FINAL_BIND" != "127.0.0.1" && "$FINAL_BIND" != "::1" && "$FINAL_BIND" != "localhost" ]]; then
  warn "HTTP is bound to $FINAL_BIND. Credentials are plaintext on the network; use only on a trusted management network or behind a TLS reverse proxy."
fi

if command -v ss >/dev/null 2>&1; then
  for port in "$FINAL_PORT" 2055 4739 6343; do
    if ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${port}$"; then warn "Port $port appears to be in use."; fi
  done
fi

step "Installing hardened systemd service"
install -d -m 0755 "$SYSTEMD_DIR"
UNIT_PATH="$SYSTEMD_DIR/$SERVICE"
UNIT_AFTER="network-online.target"
UNIT_REQUIRES=""
if [[ "$CLICKHOUSE_MODE" == "local" ]]; then
  UNIT_AFTER="$UNIT_AFTER clickhouse-server.service"
  UNIT_REQUIRES="Requires=clickhouse-server.service"
fi
cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=Central Flow Collector and Analytics Platform
Documentation=file://$CONFIG_DIR/README
After=$UNIT_AFTER
Wants=network-online.target
$UNIT_REQUIRES

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStart=$PREFIX/flowcollector run --config $CONFIG_FILE
Restart=on-failure
RestartSec=3s
TimeoutStopSec=20s
KillSignal=SIGTERM
UMask=0027
WorkingDirectory=$DATA_DIR
Environment=FLOWCOLLECTOR_CONFIG=$CONFIG_FILE
EnvironmentFile=-$CONFIG_DIR/clickhouse.env
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
ReadWritePaths=$DATA_DIR $LOG_DIR
ReadOnlyPaths=$CONFIG_DIR
LimitNOFILE=262144
TasksMax=4096

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT_PATH"
if [[ "${SERVICE_MANAGER:-systemd}" == "openrc" ]]; then
  cat > "/etc/init.d/$APP" <<INIT
#!/sbin/openrc-run
name="Central Flow Collector"
command="$PREFIX/flowcollector"
command_args="run --config $CONFIG_FILE"
command_user="$SERVICE_USER:$SERVICE_GROUP"
directory="$DATA_DIR"
pidfile="/run/$APP.pid"
depend() { need net; after firewall; }
INIT
  chmod 0755 "/etc/init.d/$APP"
elif [[ "${SERVICE_MANAGER:-systemd}" == "sysvinit" ]]; then
  cat > "/etc/init.d/$APP" <<INIT
#!/bin/sh
### BEGIN INIT INFO
# Provides:          $APP
# Required-Start:    $remote_fs $network
# Required-Stop:     $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO
case "\$1" in
  start) start-stop-daemon --start --background --make-pidfile --pidfile /run/$APP.pid --chuid $SERVICE_USER:$SERVICE_GROUP --chdir $DATA_DIR --exec $PREFIX/flowcollector -- run --config $CONFIG_FILE ;;
  stop) start-stop-daemon --stop --pidfile /run/$APP.pid --retry TERM/20/KILL/5 ;;
  restart) \$0 stop; \$0 start ;;
  status) test -s /run/$APP.pid && kill -0 \$(cat /run/$APP.pid) ;;
  *) echo "Usage: \$0 {start|stop|restart|status}"; exit 2 ;;
esac
INIT
  chmod 0755 "/etc/init.d/$APP"
fi
cat > "$CONFIG_DIR/README" <<EOF2
Managed by Central Flow Collector install.sh v$VERSION.
Configuration: $CONFIG_FILE
Data: $DATA_DIR
Logs: journalctl -u $SERVICE
CLI: $PREFIX/flowcollector diagnostics --config $CONFIG_FILE
ClickHouse credentials (when used): $CONFIG_DIR/clickhouse.env
Cluster registration token: $CONFIG_DIR/cluster.token
EOF2
systemctl daemon-reload
ok "Installed $UNIT_PATH"

if (( ENABLE_SERVICE )); then systemctl enable "$SERVICE" >/dev/null; ok "Enabled service at boot"; fi

if (( START_SERVICE )); then
  step "Starting and validating service"
  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE"

  START_OK=0
  if [[ "$FINAL_TLS" != "true" ]]; then
    HEALTH_HOST="$FINAL_BIND"
    [[ "$HEALTH_HOST" == "0.0.0.0" ]] && HEALTH_HOST="127.0.0.1"
    [[ "$HEALTH_HOST" == "::" ]] && HEALTH_HOST="::1"
    [[ "$HEALTH_HOST" == *:* ]] && HEALTH_HOST="[$HEALTH_HOST]"
    HEALTH_URL="http://$HEALTH_HOST:$FINAL_PORT/ready"

    # Do not treat the short systemd 'active' window before a crash as success.
    # Installation succeeds only after the real HTTP health endpoint responds.
    for _ in {1..50}; do
      if ! systemctl is-active --quiet "$SERVICE"; then
        sleep 0.2
        continue
      fi
      if "$PREFIX/flowcollector" health --url "$HEALTH_URL" >/dev/null 2>&1; then
        # A stale/manual collector can already own the web port. In that case
        # /ready may succeed even while the new systemd service is failing to
        # bind and entering its restart loop. Verify that the process actually
        # listening on the configured TCP port is systemd's current MainPID.
        MAIN_PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)"
        PORT_OWNER_OK=1
        if command -v ss >/dev/null 2>&1 && [[ "$MAIN_PID" =~ ^[1-9][0-9]*$ ]]; then
          PORT_OWNER_OK=0
          while IFS= read -r OWNER_PID; do
            if [[ "$OWNER_PID" == "$MAIN_PID" ]]; then
              PORT_OWNER_OK=1
              break
            fi
          done < <(ss -H -ltnp "sport = :$FINAL_PORT" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u)
        fi
        if (( PORT_OWNER_OK )); then
          # Require a short stable period with the same MainPID to avoid
          # accepting the transient 'active' state immediately before a crash.
          sleep 0.8
          CHECK_PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)"
          if systemctl is-active --quiet "$SERVICE" && [[ "$CHECK_PID" == "$MAIN_PID" ]]; then
            START_OK=1
            break
          fi
        fi
      fi
      sleep 0.2
    done
  else
    # HTTPS is administrator-supplied only.  Certificate trust/hostname policy is
    # client-specific, so verify that the service remains active and is listening.
    for _ in {1..25}; do
      if systemctl is-active --quiet "$SERVICE"; then
        sleep 0.4
        if systemctl is-active --quiet "$SERVICE"; then START_OK=1; break; fi
      fi
      sleep 0.2
    done
  fi

  if (( ! START_OK )); then
    printf "\n" >&2
    systemctl --no-pager --full status "$SERVICE" || true
    journalctl -u "$SERVICE" -n 100 --no-pager || true
    if [[ -n "$SNAPSHOT" && "$AUTO_ROLLBACK" == "1" ]]; then
      rollback_snapshot "$SNAPSHOT" || true
      die "New release did not reach readiness; previous binary/config/unit were restored automatically."
    fi
    die "Service did not reach a healthy steady state. Automatic rollback was unavailable or disabled."
  fi

  ok "Service is active and healthy"
  if [[ "$FINAL_TLS" != "true" ]]; then
    ok "HTTP health endpoint: $HEALTH_URL"
  fi
fi

step "Installation summary"
SCHEME="http"; [[ "$FINAL_TLS" == "true" ]] && SCHEME="https"
DISPLAY_HOST="$FINAL_BIND"
[[ "$DISPLAY_HOST" == "0.0.0.0" ]] && DISPLAY_HOST="127.0.0.1"
[[ "$DISPLAY_HOST" == "::" ]] && DISPLAY_HOST="::1"
[[ "$DISPLAY_HOST" == *:* ]] && DISPLAY_HOST="[$DISPLAY_HOST]"
printf "  Binary        : %s\n" "$PREFIX/flowcollector"
printf "  Configuration : %s\n" "$CONFIG_FILE"
printf "  Data          : %s\n" "$DATA_DIR"
printf "  Service       : %s\n" "$SERVICE"
printf "  Web UI        : %s://%s:%s\n" "$SCHEME" "$DISPLAY_HOST" "$FINAL_PORT"
printf "  Web TLS       : %s\n" "$FINAL_TLS"
printf "  Flow listeners: UDP/2055 NetFlow, UDP/4739 IPFIX, UDP/6343 sFlow\n"
printf "  Policy default: DENY\n"
printf "  Cluster token : %s (root/%s readable; secret not printed)\n" "$CONFIG_DIR/cluster.token" "$SERVICE_GROUP"
CLUSTER_URL_SUMMARY="$(section_value cluster heartbeat_url "$CONFIG_FILE" || true)"
[[ -n "$CLUSTER_URL_SUMMARY" ]] && printf "  Central HB    : %s\n" "$CLUSTER_URL_SUMMARY"
FINAL_STORAGE_BACKEND="$(section_value storage backend "$CONFIG_FILE" || true)"
printf "  Storage       : %s\n" "${FINAL_STORAGE_BACKEND:-local}"
if [[ "${FINAL_STORAGE_BACKEND:-local}" == "clickhouse" ]]; then
  CH_SUMMARY_URL="$(section_value storage clickhouse_url "$CONFIG_FILE" || true)"
  CH_SUMMARY_DB="$(section_value storage clickhouse_database "$CONFIG_FILE" || true)"
  CH_SUMMARY_TABLE="$(section_value storage clickhouse_table "$CONFIG_FILE" || true)"
  CH_SUMMARY_USER="$(section_value storage clickhouse_user "$CONFIG_FILE" || true)"
  printf "  ClickHouse    : %s/%s.%s (user=%s)\n" "$CH_SUMMARY_URL" "$CH_SUMMARY_DB" "$CH_SUMMARY_TABLE" "$CH_SUMMARY_USER"
  [[ -f "$CONFIG_DIR/clickhouse.env" ]] && printf "  CH credential : %s (root/%s readable, password not printed)\n" "$CONFIG_DIR/clickhouse.env" "$SERVICE_GROUP"
fi
[[ -n "$SNAPSHOT" ]] && printf "  Rollback      : %s\n" "$SNAPSHOT"

if [[ "$FINAL_TLS" != "true" ]]; then
  printf "\n%bCertificate-free mode active.%b No SSL/TLS handshake or self-signed certificate is involved.\n" "$C_GREEN" "$C_RESET"
fi
if (( START_SERVICE )) && [[ -s "$DATA_DIR/bootstrap-admin.txt" ]]; then
  printf "\n%bFirst login credentials%b\n" "$C_BOLD" "$C_RESET"
  printf "  Stored at: %s\n" "$DATA_DIR/bootstrap-admin.txt"
  if [[ -t 1 ]]; then sed 's/^/  /' "$DATA_DIR/bootstrap-admin.txt"; fi
  printf "  Change the temporary password immediately after first login.\n"
fi
printf "\nUseful commands:\n"
printf "  systemctl status %s\n" "$SERVICE"
printf "  journalctl -u %s -f\n" "$SERVICE"
printf "  %s/flowcollector diagnostics --config %s\n" "$PREFIX" "$CONFIG_FILE"
printf "  %s/flowcollector backup create --config %s --output /secure/path/flowcollector-backup.tar.gz\n" "$PREFIX" "$CONFIG_FILE"
printf "  %s/flowcollector repair check --config %s\n" "$PREFIX" "$CONFIG_FILE"
if [[ "${FINAL_STORAGE_BACKEND:-local}" == "clickhouse" ]]; then
  printf "  %s/flowcollector clickhouse-backup create --config %s --output /secure/path/clickhouse-flows.jsonl.gz\n" "$PREFIX" "$CONFIG_FILE"
fi
printf "  cat %s   # securely copy this token to edge collectors that should heartbeat here\n" "$CONFIG_DIR/cluster.token"
if [[ -x "$PREFIX/chbench" ]]; then printf "  %s/chbench --help   # ClickHouse benchmark tool\n" "$PREFIX"; fi
printf "  sudo %s --rollback   # restore latest installer snapshot\n" "$SOURCE_DIR/install.sh"
printf "%bInstallation complete.%b\n" "$C_GREEN" "$C_RESET"
