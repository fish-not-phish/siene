#!/usr/bin/env bash
# ── Siene setup script ────────────────────────────────────────────────────────
#
# Interactively configures docker/.env and launches the chosen compose stack.
#
# Usage:
#   ./setup.sh                 — interactive setup
#   ./setup.sh --rotate-keys   — same, but regenerates all secret keys even if
#                                they already exist
#
# The script never overwrites keys that already hold non-default values unless
# --rotate-keys is passed. All other values are always written (re-run to
# update DOMAIN, TIME_ZONE, etc.).
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}  →${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  !${RESET} $*"; }
header()  { echo -e "\n${BOLD}$*${RESET}"; }
die()     { echo -e "${RED}  ✗ $*${RESET}" >&2; exit 1; }

# Read a single value from the .env file (returns empty string if not set)
env_get() {
    local key="$1"
    local file="$2"
    if [[ -f "$file" ]]; then
        grep -E "^${key}=" "$file" | head -1 | cut -d'=' -f2- | tr -d '[:space:]' || true
    fi
}

# Set or replace a key=value line in the .env file.
# Uses Python for the rewrite so no character in the value can break the
# substitution (dots, slashes, pipes, colons in IPs/URLs are all safe).
env_set() {
    local key="$1"
    local value="$2"
    local file="$3"
    python3 - "$key" "$value" "$file" <<'EOF'
import sys, os

key, value, path = sys.argv[1], sys.argv[2], sys.argv[3]
line_to_write = f"{key}={value}\n"
found = False

with open(path, 'r') as f:
    lines = f.readlines()

with open(path, 'w') as f:
    for line in lines:
        if line.startswith(f"{key}=") or line.strip() == key:
            if not found:
                f.write(line_to_write)
                found = True
            # skip duplicate occurrences
        else:
            f.write(line)
    if not found:
        f.write(line_to_write)
EOF
}

# Generate a 48-byte URL-safe random token
gen_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(48))"
}

# Prompt for a value; show current/default in brackets; return input or default.
# Labels and prompts go to stderr so that capturing stdout with $() only gets
# the entered value, not the label text.
prompt() {
    local label="$1"
    local default="$2"
    local hint="${3:-}"
    local input

    if [[ -n "$hint" ]]; then
        echo -e "  ${BOLD}${label}${RESET} ${YELLOW}(${hint})${RESET}" >&2
    else
        echo -e "  ${BOLD}${label}${RESET}" >&2
    fi

    if [[ -n "$default" ]]; then
        read -rp "    [${default}]: " input </dev/tty
    else
        read -rp "    : " input </dev/tty
    fi

    echo "${input:-$default}"
}

# y/n prompt — returns 0 for yes, 1 for no
confirm() {
    local label="$1"
    local default="${2:-y}"   # y or n
    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "  ${label} [Y/n]: " yn
        yn="${yn:-y}"
    else
        read -rp "  ${label} [y/N]: " yn
        yn="${yn:-n}"
    fi
    [[ "${yn,,}" == "y" ]]
}

# Numbered menu — sets $MENU_INDEX (1-based) and $MENU_RESULT (label string)
menu() {
    local prompt_text="$1"; shift
    local options=("$@")
    echo -e "  ${BOLD}${prompt_text}${RESET}"
    local i=1
    for opt in "${options[@]}"; do
        echo "    $i) $opt"
        ((i++))
    done
    local choice
    while true; do
        read -rp "    Choice [1-${#options[@]}]: " choice </dev/tty
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            MENU_INDEX="$choice"
            MENU_RESULT="${options[$((choice-1))]}"
            return
        fi
        warn "Enter a number between 1 and ${#options[@]}"
    done
}

# ── Arg parsing ───────────────────────────────────────────────────────────────

ROTATE_KEYS=false
for arg in "$@"; do
    case "$arg" in
        --rotate-keys) ROTATE_KEYS=true ;;
        --help|-h)
            echo "Usage: $0 [--rotate-keys]"
            echo "  --rotate-keys   Regenerate all secret keys even if they are already set"
            exit 0
            ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── Locate paths ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="${SCRIPT_DIR}/docker"
ENV_FILE="${DOCKER_DIR}/.env"
EXAMPLE_ENV="${DOCKER_DIR}/../backend/example.env"

[[ -d "$DOCKER_DIR" ]] || die "docker/ directory not found at ${DOCKER_DIR}"

# ── Banner ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}  ███████╗██╗███████╗███╗   ██╗███████╗${RESET}"
echo -e "${BOLD}  ██╔════╝██║██╔════╝████╗  ██║██╔════╝${RESET}"
echo -e "${BOLD}  ███████╗██║█████╗  ██╔██╗ ██║█████╗  ${RESET}"
echo -e "${BOLD}  ╚════██║██║██╔══╝  ██║╚██╗██║██╔══╝  ${RESET}"
echo -e "${BOLD}  ███████║██║███████╗██║ ╚████║███████╗ ${RESET}"
echo -e "${BOLD}  ╚══════╝╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝${RESET}"
echo ""
echo -e "  Container Registry UI — Setup"
echo ""

if [[ "$ROTATE_KEYS" == true ]]; then
    warn "--rotate-keys is set: all secret keys will be regenerated."
    warn "rotating keys will make any existing data inaccessible."
fi

# ── Initialise .env from example if it doesn't exist ─────────────────────────

if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$EXAMPLE_ENV" ]]; then
        cp "$EXAMPLE_ENV" "$ENV_FILE"
        info "Created ${ENV_FILE} from example.env"
    else
        touch "$ENV_FILE"
        info "Created blank ${ENV_FILE}"
    fi
fi

# ── Known "default / placeholder" values that should be rotated ───────────────

DEFAULT_SECRET_KEY="changeme-secret-key"
DEFAULT_DB_PASSWORD="siene"
DEFAULT_INTERNAL_TOKEN="changeme-internal-token"
DEFAULT_HTTP_SECRET="changeme-registry-secret"

# Returns true if a key should be (re)generated
should_generate() {
    local key="$1"
    local current
    current="$(env_get "$key" "$ENV_FILE")"

    # No value at all → generate
    [[ -z "$current" ]] && return 0

    # --rotate-keys → always regenerate
    [[ "$ROTATE_KEYS" == true ]] && return 0

    # Still holds a placeholder → generate
    case "$key" in
        DJANGO_SECRET_KEY)   [[ "$current" == "$DEFAULT_SECRET_KEY"    ]] && return 0 ;;
        DB_PASSWORD)         [[ "$current" == "$DEFAULT_DB_PASSWORD"   ]] && return 0 ;;
        REGISTRY_INTERNAL_TOKEN) [[ "$current" == "$DEFAULT_INTERNAL_TOKEN" ]] && return 0 ;;
        REGISTRY_HTTP_SECRET) [[ "$current" == "$DEFAULT_HTTP_SECRET"  ]] && return 0 ;;
    esac

    return 1
}

# ── Step 1 — Deployment mode ──────────────────────────────────────────────────

header "Step 1 — Deployment mode"
menu "Which deployment mode?" \
    "Basic (no reverse proxy, ports 8000/3000 exposed directly)" \
    "Traefik (automatic TLS via Cloudflare DNS-01)" \
    "Nginx (bring your own TLS certificates)"

MODE="$MENU_RESULT"
DEPLOY_MODE_INDEX="$MENU_INDEX"   # saved before storage menu overwrites MENU_INDEX

case "$DEPLOY_MODE_INDEX" in
    1) COMPOSE_FILE="docker-compose.yml" ;;
    2) COMPOSE_FILE="docker-compose.traefik.yml" ;;
    3) COMPOSE_FILE="docker-compose.nginx.yml" ;;
esac

success "Mode: ${MODE}"

# ── Step 2 — Domain / hostname ────────────────────────────────────────────────

header "Step 2 — Domain / hostname"
info "This is the public hostname (or private IP) that clients will reach."
info "No scheme, no trailing slash. Examples: siene.example.com  10.0.0.10"

current_domain="$(env_get DOMAIN "$ENV_FILE")"
DOMAIN="$(prompt "DOMAIN" "${current_domain:-localhost}")"
env_set DOMAIN "$DOMAIN" "$ENV_FILE"
success "DOMAIN=${DOMAIN}"

# ── Step 3 — External URL ─────────────────────────────────────────────────────

header "Step 3 — Registry external URL"
info "The full public URL of the backend (no trailing slash)."
info "Docker clients use this for token auth. Baked into the frontend bundle."

if [[ "$MODE" == Traefik* || "$MODE" == Nginx* ]]; then
    default_ext_url="https://${DOMAIN}"
else
    default_ext_url="http://${DOMAIN}:8000"
fi

current_ext="$(env_get REGISTRY_EXTERNAL_URL "$ENV_FILE")"
# If the stored value is a placeholder, or its embedded hostname no longer
# matches DOMAIN (user changed the domain), derive a fresh default so the
# prompt pre-fills the correct value.
stored_host="$(python3 -c "
import sys
try:
    from urllib.parse import urlparse
    print(urlparse(sys.argv[1]).hostname or '')
except Exception:
    print('')
" "$current_ext" 2>/dev/null || true)"
if [[ -z "$current_ext" || "$current_ext" == "http://localhost:8000" || "$current_ext" == "http://localhost:3000" || "$stored_host" != "$DOMAIN" ]]; then
    current_ext="$default_ext_url"
fi
EXT_URL="$(prompt "REGISTRY_EXTERNAL_URL" "$current_ext")"
env_set REGISTRY_EXTERNAL_URL "$EXT_URL" "$ENV_FILE"
success "REGISTRY_EXTERNAL_URL=${EXT_URL}"

# ── Step 4 — Timezone ─────────────────────────────────────────────────────────

header "Step 4 — Timezone"
info "Used by Django and Celery Beat. Any tz database name, e.g. America/New_York"

current_tz="$(env_get TIME_ZONE "$ENV_FILE")"
TZ_VAL="$(prompt "TIME_ZONE" "${current_tz:-UTC}")"
env_set TIME_ZONE "$TZ_VAL" "$ENV_FILE"
success "TIME_ZONE=${TZ_VAL}"

# ── Step 5 — Storage backend ──────────────────────────────────────────────────

header "Step 5 — Storage backend"
info "Filesystem stores images on the local Docker volume (default, zero config)."
info "S3 stores images in an S3-compatible bucket (AWS S3, MinIO, Cloudflare R2, etc.)."

menu "Storage backend?" \
    "Filesystem (local Docker volume — default)" \
    "S3 / S3-compatible (AWS S3, MinIO, Cloudflare R2, …)"

STORAGE_BACKEND_INDEX="$MENU_INDEX"

if [[ "$MENU_INDEX" == 1 ]]; then
    env_set REGISTRY_STORAGE_BACKEND      "filesystem" "$ENV_FILE"
    env_set REGISTRY_S3_REGION            ""           "$ENV_FILE"
    env_set REGISTRY_S3_BUCKET            ""           "$ENV_FILE"
    env_set REGISTRY_S3_ACCESS_KEY        ""           "$ENV_FILE"
    env_set REGISTRY_S3_SECRET_KEY        ""           "$ENV_FILE"
    env_set REGISTRY_S3_ENDPOINT          ""           "$ENV_FILE"
    env_set REGISTRY_S3_ROOT_DIRECTORY    ""           "$ENV_FILE"
    env_set REGISTRY_S3_FORCE_PATH_STYLE  "false"      "$ENV_FILE"
    env_set REGISTRY_S3_SECURE            "true"       "$ENV_FILE"
    env_set REGISTRY_S3_REDIRECT_ENDPOINT ""           "$ENV_FILE"
    success "Storage: filesystem"
else
    env_set REGISTRY_STORAGE_BACKEND "s3" "$ENV_FILE"

    echo ""
    info "Enter your S3 / S3-compatible credentials."
    info "For AWS S3: leave endpoint blank."
    info "For MinIO / Cloudflare R2 / other: enter the endpoint URL."
    echo ""

    current_bucket="$(env_get REGISTRY_S3_BUCKET "$ENV_FILE")"
    S3_BUCKET="$(prompt "S3 bucket name" "${current_bucket:-}")"
    env_set REGISTRY_S3_BUCKET "$S3_BUCKET" "$ENV_FILE"

    current_region="$(env_get REGISTRY_S3_REGION "$ENV_FILE")"
    S3_REGION="$(prompt "S3 region" "${current_region:-us-east-1}" "e.g. us-east-1, eu-west-1 — use any value for non-AWS providers")"
    env_set REGISTRY_S3_REGION "$S3_REGION" "$ENV_FILE"

    current_access="$(env_get REGISTRY_S3_ACCESS_KEY "$ENV_FILE")"
    S3_ACCESS_KEY="$(prompt "S3 access key" "${current_access:-}")"
    env_set REGISTRY_S3_ACCESS_KEY "$S3_ACCESS_KEY" "$ENV_FILE"

    current_secret="$(env_get REGISTRY_S3_SECRET_KEY "$ENV_FILE")"
    S3_SECRET_KEY="$(prompt "S3 secret key" "${current_secret:-}")"
    env_set REGISTRY_S3_SECRET_KEY "$S3_SECRET_KEY" "$ENV_FILE"

    current_endpoint="$(env_get REGISTRY_S3_ENDPOINT "$ENV_FILE")"
    S3_ENDPOINT="$(prompt "S3 endpoint URL" "${current_endpoint:-}" "blank for AWS S3; e.g. https://minio.example.com or https://<account>.r2.cloudflarestorage.com")"
    env_set REGISTRY_S3_ENDPOINT "$S3_ENDPOINT" "$ENV_FILE"

    current_rootdir="$(env_get REGISTRY_S3_ROOT_DIRECTORY "$ENV_FILE")"
    S3_ROOT_DIRECTORY="$(prompt "S3 key prefix / root directory" "${current_rootdir:-}" "optional — leave blank to use the bucket root")"
    env_set REGISTRY_S3_ROOT_DIRECTORY "$S3_ROOT_DIRECTORY" "$ENV_FILE"

    # secure — set false for HTTP-only MinIO or non-TLS custom endpoints
    if [[ -n "$S3_ENDPOINT" ]]; then
        echo ""
        info "Does your S3-compatible endpoint use HTTPS (TLS)?"
        info "Set to 'no' for plain-HTTP internal endpoints (e.g. http://minio:9000)."
        if confirm "S3 endpoint uses HTTPS?" y; then
            env_set REGISTRY_S3_SECURE "true" "$ENV_FILE"
        else
            env_set REGISTRY_S3_SECURE "false" "$ENV_FILE"
        fi
    else
        env_set REGISTRY_S3_SECURE "true" "$ENV_FILE"
    fi

    # forcepathstyle — required by Distribution v3 for custom endpoints
    if [[ -n "$S3_ENDPOINT" ]]; then
        echo ""
        info "Path-style access is required by Distribution v3 when using a custom endpoint."
        info "(MinIO, Cloudflare R2, and other S3-compatible services always need this.)"
        if confirm "Enable path-style S3 access?" y; then
            env_set REGISTRY_S3_FORCE_PATH_STYLE "true" "$ENV_FILE"
        else
            env_set REGISTRY_S3_FORCE_PATH_STYLE "false" "$ENV_FILE"
        fi
    else
        env_set REGISTRY_S3_FORCE_PATH_STYLE "false" "$ENV_FILE"
    fi

    # redirectendpoint — needed when endpoint is internal-only
    current_redirect="$(env_get REGISTRY_S3_REDIRECT_ENDPOINT "$ENV_FILE")"
    S3_REDIRECT_ENDPOINT="$(prompt "Public S3 redirect endpoint" "${current_redirect:-}" "optional — only needed if your S3 endpoint is internal (e.g. http://minio:9000) and Docker clients can't reach it directly; set to your public MinIO/R2 URL")"
    env_set REGISTRY_S3_REDIRECT_ENDPOINT "$S3_REDIRECT_ENDPOINT" "$ENV_FILE"

    success "Storage: S3 (bucket=${S3_BUCKET}, region=${S3_REGION})"
    if [[ -n "$S3_ENDPOINT" ]]; then
        success "Endpoint: ${S3_ENDPOINT}"
    fi
fi

# ── Step 6 — Secret keys (auto-generated) ─────────────────────────────────────

header "Step 6 — Secret keys"

if should_generate DJANGO_SECRET_KEY; then
    NEW_KEY="$(gen_secret)"
    env_set DJANGO_SECRET_KEY "$NEW_KEY" "$ENV_FILE"
    success "DJANGO_SECRET_KEY generated"
else
    info "DJANGO_SECRET_KEY already set — skipping (pass --rotate-keys to regenerate)"
fi

if should_generate DB_PASSWORD; then
    NEW_PW="$(gen_secret)"
    env_set DB_PASSWORD "$NEW_PW" "$ENV_FILE"
    success "DB_PASSWORD generated"
else
    info "DB_PASSWORD already set — skipping"
fi

if should_generate REGISTRY_INTERNAL_TOKEN; then
    NEW_TOK="$(gen_secret)"
    env_set REGISTRY_INTERNAL_TOKEN "$NEW_TOK" "$ENV_FILE"
    success "REGISTRY_INTERNAL_TOKEN generated"
else
    info "REGISTRY_INTERNAL_TOKEN already set — skipping"
fi

if should_generate REGISTRY_HTTP_SECRET; then
    NEW_REG="$(gen_secret)"
    env_set REGISTRY_HTTP_SECRET "$NEW_REG" "$ENV_FILE"
    success "REGISTRY_HTTP_SECRET generated"
else
    info "REGISTRY_HTTP_SECRET already set — skipping"
fi

# ── Step 7 — Proxy / TLS mode-specific variables ──────────────────────────────

if [[ "$DEPLOY_MODE_INDEX" == 2 ]]; then
    header "Step 7 — Traefik / TLS"
    # Traefik terminates TLS — Django must never double-redirect.
    # Secure cookies are always correct here since the browser sees HTTPS.
    env_set SECURE_SSL_REDIRECT "0" "$ENV_FILE"
    env_set SESSION_COOKIE_SECURE "1" "$ENV_FILE"
    env_set CSRF_COOKIE_SECURE "1" "$ENV_FILE"
    info "SECURE_SSL_REDIRECT=0 (Traefik handles TLS termination — Django will not double-redirect)"
    info "SESSION_COOKIE_SECURE=1, CSRF_COOKIE_SECURE=1"

    echo ""
    info "Are you running behind a Cloudflare proxy (orange cloud / Full SSL mode)?"
    info "If yes, ensure Cloudflare SSL mode is set to Full or Full (strict)."
    if confirm "Behind Cloudflare proxy?" n; then
        success "Cloudflare proxy: yes — ensure SSL mode is Full or Full (strict) in the Cloudflare dashboard"
    else
        success "Cloudflare proxy: no"
    fi

elif [[ "$DEPLOY_MODE_INDEX" == 3 ]]; then
    header "Step 7 — Nginx / TLS certificates"
    info "CERT_DIR must contain fullchain.pem and privkey.pem."
    info "Default: /etc/letsencrypt/live/${DOMAIN}"

    current_cert="$(env_get CERT_DIR "$ENV_FILE")"
    CERT_DIR="$(prompt "CERT_DIR" "${current_cert:-/etc/letsencrypt/live/${DOMAIN}}")"
    env_set CERT_DIR "$CERT_DIR" "$ENV_FILE"
    success "CERT_DIR=${CERT_DIR}"

    # Nginx terminates TLS — Django must never double-redirect.
    # Secure cookies are always correct here since the browser sees HTTPS.
    env_set SECURE_SSL_REDIRECT "0" "$ENV_FILE"
    env_set SESSION_COOKIE_SECURE "1" "$ENV_FILE"
    env_set CSRF_COOKIE_SECURE "1" "$ENV_FILE"
    info "SECURE_SSL_REDIRECT=0 (Nginx handles TLS termination — Django will not double-redirect)"
    info "SESSION_COOKIE_SECURE=1, CSRF_COOKIE_SECURE=1"

    echo ""
    info "Are you running behind a Cloudflare proxy (orange cloud / Full SSL mode)?"
    info "If yes, ensure Cloudflare SSL mode is set to Full or Full (strict)."
    if confirm "Behind Cloudflare proxy?" n; then
        success "Cloudflare proxy: yes — ensure SSL mode is Full or Full (strict) in the Cloudflare dashboard"
    else
        success "Cloudflare proxy: no"
    fi

else
    # Basic mode — no reverse proxy
    header "Step 6 — SSL redirect"
    info "Are you running behind a Cloudflare proxy (orange cloud / Full SSL mode)?"
    if confirm "Behind Cloudflare proxy?" n; then
        env_set SECURE_SSL_REDIRECT "0" "$ENV_FILE"
        env_set SESSION_COOKIE_SECURE "1" "$ENV_FILE"
        env_set CSRF_COOKIE_SECURE "1" "$ENV_FILE"
        info "SECURE_SSL_REDIRECT=0 — Cloudflare handles HTTPS; Django trusts X-Forwarded-Proto"
    else
        echo ""
        info "Is Django itself serving HTTPS directly (e.g. via a local cert)?"
        if confirm "Django serving HTTPS directly?" n; then
            env_set SECURE_SSL_REDIRECT "1" "$ENV_FILE"
            env_set SESSION_COOKIE_SECURE "1" "$ENV_FILE"
            env_set CSRF_COOKIE_SECURE "1" "$ENV_FILE"
            success "SECURE_SSL_REDIRECT=1"
        else
            env_set SECURE_SSL_REDIRECT "0" "$ENV_FILE"
            env_set SESSION_COOKIE_SECURE "0" "$ENV_FILE"
            env_set CSRF_COOKIE_SECURE "0" "$ENV_FILE"
            info "SECURE_SSL_REDIRECT=0 (plain HTTP — not recommended for production)"
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

header "Configuration written to ${ENV_FILE}"
echo ""
echo -e "  ${BOLD}DOMAIN${RESET}                 ${DOMAIN}"
echo -e "  ${BOLD}REGISTRY_EXTERNAL_URL${RESET}  ${EXT_URL}"
echo -e "  ${BOLD}TIME_ZONE${RESET}              ${TZ_VAL}"
echo -e "  ${BOLD}COMPOSE_FILE${RESET}           ${COMPOSE_FILE}"
if [[ "$STORAGE_BACKEND_INDEX" == 2 ]]; then
    echo -e "  ${BOLD}STORAGE${RESET}                S3 (bucket=${S3_BUCKET})"
else
    echo -e "  ${BOLD}STORAGE${RESET}                filesystem"
fi
echo ""

# ── Launch ────────────────────────────────────────────────────────────────────

header "Launch"

if [[ "$STORAGE_BACKEND_INDEX" == 2 ]]; then
    echo ""
    warn "S3 storage selected — please verify your credentials before starting."
    warn "Ensure the bucket '${S3_BUCKET}' exists and the access key has"
    warn "s3:GetObject, s3:PutObject, s3:DeleteObject, s3:ListBucket permissions."
    echo ""
    info "When ready, start Siene with:"
    echo ""
    echo -e "    cd docker && docker compose -f ${COMPOSE_FILE} up -d --build"
    echo ""
    if [[ "$DEPLOY_MODE_INDEX" == 1 ]]; then
        echo -e "  UI:  ${CYAN}http://${DOMAIN}:3000${RESET}"
        echo -e "  API: ${CYAN}http://${DOMAIN}:8000/api/${RESET}"
    else
        echo -e "  UI:  ${CYAN}https://${DOMAIN}${RESET}"
        echo -e "  API: ${CYAN}https://${DOMAIN}/api/${RESET}"
    fi
    echo ""
    echo -e "  The first account to register is automatically made admin."
    echo ""
elif confirm "Build and start Siene now?" y; then
    echo ""
    info "Running: docker compose -f ${COMPOSE_FILE} up -d --build"
    echo ""
    cd "$DOCKER_DIR"
    docker compose -f "$COMPOSE_FILE" up -d --build
    echo ""
    success "Siene is starting."

    if [[ "$DEPLOY_MODE_INDEX" == 1 ]]; then
        echo ""
        echo -e "  UI:  ${CYAN}http://${DOMAIN}:3000${RESET}"
        echo -e "  API: ${CYAN}http://${DOMAIN}:8000/api/${RESET}"
    else
        echo ""
        echo -e "  UI:  ${CYAN}https://${DOMAIN}${RESET}"
        echo -e "  API: ${CYAN}https://${DOMAIN}/api/${RESET}"
    fi
    echo ""
    echo -e "  The first account to register is automatically made admin."
    echo ""
    info "Tip: run 'docker compose -f ${COMPOSE_FILE} logs -f' to follow logs."
else
    echo ""
    info "Skipped. When ready, run:"
    echo ""
    echo -e "    cd docker && docker compose -f ${COMPOSE_FILE} up -d --build"
    echo ""
fi
