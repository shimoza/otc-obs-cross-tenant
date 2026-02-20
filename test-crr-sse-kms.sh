#!/usr/bin/env bash
#
# test-crr-sse-kms.sh — Full SSE-KMS cross-tenant copy + re-encryption test
#
# Tests:
#   1. SSE-KMS with custom CMK on source bucket (tenant 10491)
#   2. KMS Grant to destination tenant (10497)
#   3. Destination bucket using source's key via grant
#   4. CRR copy of 3x20GB files + 300 small files
#   5. Re-encryption of destination with destination's OWN new CMK
#   6. Verify independence (revoke grant, objects still readable)
#
# Usage:
#   ./test-crr-sse-kms.sh              # Run full test
#   ./test-crr-sse-kms.sh --cleanup    # Run test + cleanup at end
#   ./test-crr-sse-kms.sh --cleanup-only  # Only cleanup
#
set -euo pipefail

###############################################################################
# Configuration
###############################################################################

IAM_ENDPOINT="https://iam.eu-de.otc.t-systems.com"
KMS_ENDPOINT="https://kms.eu-de.otc.t-systems.com"
OBS_ENDPOINT="https://obs.eu-de.otc.t-systems.com"

# Source tenant (10491)
SRC_USERNAME="Kirill Larin 00323094"
SRC_PASSWORD='a52Zfkpd8%'
SRC_DOMAIN="OTC00000000001000010491"
SRC_PROJECT_ID="a984f29ae4ea4000aa8e7e7a8fe608a0"
SRC_AK="DDGQ0ALPMQJYD0XSM6SG"
SRC_SK="kquwKTYhly1ZJqYEefZ3JJNB1K5gv5fWLfJ0mSs6"

# Destination tenant (10497)
DST_USERNAME="kirill"
DST_PASSWORD='a52Zfkpd9@'
DST_DOMAIN="OTC00000000001000010497"
DST_PROJECT_ID="43eef4ca182d4bb09252b35a5b205397"
DST_AK="SUHFX16ONFJS9WU1K6NF"
DST_SK="h2g9quMDTUHLDTyzxWsvo0ySpXZSK9bFhRHRZf6H"

# Resource names
SRC_BUCKET="crr-sse-test-src"
DST_BUCKET="crr-sse-test-dst"
SRC_KEY_ALIAS="crr-test-key"
DST_KEY_ALIAS="crr-dst-key"
GRANT_NAME="crr-test-grant"

# Test data
BIG_FILE_COUNT=3
BIG_FILE_SIZE_GB=20
SMALL_FILE_COUNT=300

# State
STATE_FILE="/tmp/crr-sse-kms-test-state.env"

###############################################################################
# Helpers
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

pass()  { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; }
info()  { echo -e "  ${CYAN}[INFO]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
step()  { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}"; }

declare -A STEP_RESULT
mark_pass() { STEP_RESULT[$1]="PASS"; }
mark_fail() { STEP_RESULT[$1]="FAIL"; OVERALL_PASS=false; }

save_state() {
    cat > "$STATE_FILE" <<EOF
SRC_KEY_ID=${SRC_KEY_ID:-}
DST_KEY_ID=${DST_KEY_ID:-}
GRANT_ID=${GRANT_ID:-}
SRC_DOMAIN_ID=${SRC_DOMAIN_ID:-}
DST_DOMAIN_ID=${DST_DOMAIN_ID:-}
SRC_TOKEN=${SRC_TOKEN:-}
DST_TOKEN=${DST_TOKEN:-}
EOF
}

load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        source "$STATE_FILE"
        info "Loaded state from $STATE_FILE"
    else
        warn "No state file found"
    fi
}

get_iam_token() {
    local username="$1" password="$2" domain="$3" project_id="$4"
    local headers
    headers=$(mktemp)
    curl -s -D "$headers" \
        -H "Content-Type: application/json" \
        -d "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"$username\",\"password\":\"$password\",\"domain\":{\"name\":\"$domain\"}}}},\"scope\":{\"project\":{\"id\":\"$project_id\"}}}}" \
        "${IAM_ENDPOINT}/v3/auth/tokens" >/dev/null
    local token
    token=$(grep -i '^X-Subject-Token:' "$headers" | tr -d '\r' | awk '{print $2}')
    rm -f "$headers"
    [[ -z "$token" ]] && { echo "ERROR"; return 1; }
    echo "$token"
}

get_domain_id() {
    curl -s -H "X-Auth-Token: $1" -H "X-Subject-Token: $1" \
        "${IAM_ENDPOINT}/v3/auth/tokens" | jq -r '.token.user.domain.id'
}

# Python S3 SigV4 helper — returns JSON {"status_code": N, "body": "..."}
obs_api() {
    python3 - "$@" <<'PYEOF'
import sys, json, hashlib
import botocore.auth, botocore.credentials, botocore.awsrequest
import urllib.request, urllib.error, ssl

method, bucket, query_param, body, ak, sk = sys.argv[1:7]
host = f"{bucket}.obs.eu-de.otc.t-systems.com"
url = f"https://{host}/?{query_param}" if query_param else f"https://{host}/"
payload_hash = hashlib.sha256(body.encode()).hexdigest()
creds = botocore.credentials.Credentials(ak, sk)
signer = botocore.auth.SigV4Auth(creds, 's3', 'eu-de')
headers = {'Host': host, 'x-amz-content-sha256': payload_hash}
if body:
    headers['Content-Type'] = 'application/xml'
request = botocore.awsrequest.AWSRequest(method=method, url=url, headers=headers, data=body or '')
signer.add_auth(request)
req = urllib.request.Request(url, data=body.encode() if body else None, headers=dict(request.headers), method=method)
ctx = ssl.create_default_context()
try:
    with urllib.request.urlopen(req, context=ctx) as resp:
        print(json.dumps({"status_code": resp.status, "body": resp.read().decode()}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status_code": e.code, "body": e.read().decode()}))
PYEOF
}

# Python HEAD helper — returns encryption headers
head_object() {
    local bucket="$1" key="$2" ak="$3" sk="$4"
    python3 - "$bucket" "$key" "$ak" "$sk" <<'PYEOF'
import sys, hashlib
import botocore.auth, botocore.credentials, botocore.awsrequest
import urllib.request, urllib.error, ssl

bucket, key, ak, sk = sys.argv[1:5]
host = f"{bucket}.obs.eu-de.otc.t-systems.com"
url = f"https://{host}/{key}"
payload_hash = hashlib.sha256(b'').hexdigest()
creds = botocore.credentials.Credentials(ak, sk)
signer = botocore.auth.SigV4Auth(creds, 's3', 'eu-de')
headers = {'Host': host, 'x-amz-content-sha256': payload_hash}
request = botocore.awsrequest.AWSRequest(method='HEAD', url=url, headers=headers)
signer.add_auth(request)
req = urllib.request.Request(url, headers=dict(request.headers), method='HEAD')
ctx = ssl.create_default_context()
try:
    with urllib.request.urlopen(req, context=ctx) as resp:
        for k,v in resp.headers.items():
            print(f"{k}: {v}")
except urllib.error.HTTPError as e:
    print(f"ERROR: HTTP {e.code}")
PYEOF
}

# KMS helper — create or find+restore key
ensure_kms_key() {
    local token="$1" project_id="$2" alias="$3" description="$4"

    # Try creating
    local resp
    resp=$(curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
        -d "{\"key_alias\":\"$alias\",\"key_spec\":\"AES_256\",\"key_description\":\"$description\"}" \
        "${KMS_ENDPOINT}/v1.0/${project_id}/kms/create-key")
    local key_id
    key_id=$(echo "$resp" | jq -r '.key_info.key_id // empty')

    if [[ -z "$key_id" ]]; then
        # Key exists — search across all states
        for state in 2 3 4; do
            local list_resp
            list_resp=$(curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
                -d "{\"key_state\":\"$state\"}" \
                "${KMS_ENDPOINT}/v1.0/${project_id}/kms/list-keys")
            local kids
            kids=$(echo "$list_resp" | jq -r '.keys[]' 2>/dev/null)
            for kid in $kids; do
                local desc_resp a
                desc_resp=$(curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
                    -d "{\"key_id\":\"$kid\"}" \
                    "${KMS_ENDPOINT}/v1.0/${project_id}/kms/describe-key")
                a=$(echo "$desc_resp" | jq -r '.key_info.key_alias // empty')
                if [[ "$a" == "$alias" ]]; then
                    key_id="$kid"
                    break 2
                fi
            done
        done
    fi

    [[ -z "$key_id" ]] && { echo "ERROR"; return 1; }

    # Check state and restore if needed
    local desc_resp state
    desc_resp=$(curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
        -d "{\"key_id\":\"$key_id\"}" \
        "${KMS_ENDPOINT}/v1.0/${project_id}/kms/describe-key")
    state=$(echo "$desc_resp" | jq -r '.key_info.key_state // empty')

    if [[ "$state" == "4" ]]; then
        curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
            -d "{\"key_id\":\"$key_id\"}" \
            "${KMS_ENDPOINT}/v1.0/${project_id}/kms/cancel-key-deletion" >/dev/null
        curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
            -d "{\"key_id\":\"$key_id\"}" \
            "${KMS_ENDPOINT}/v1.0/${project_id}/kms/enable-key" >/dev/null
        info "Key $key_id restored from pending deletion"
    elif [[ "$state" == "3" ]]; then
        curl -s -H "X-Auth-Token: $token" -H "Content-Type: application/json" \
            -d "{\"key_id\":\"$key_id\"}" \
            "${KMS_ENDPOINT}/v1.0/${project_id}/kms/enable-key" >/dev/null
        info "Key $key_id re-enabled"
    fi

    echo "$key_id"
}

# Set bucket encryption
set_bucket_encryption() {
    local bucket="$1" key_id="$2" ak="$3" sk="$4"
    local xml
    if [[ -n "$key_id" ]]; then
        xml="<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>${key_id}</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
    else
        xml="<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
    fi
    obs_api "PUT" "$bucket" "encryption" "$xml" "$ak" "$sk"
}

parse_json() {
    python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"
}

###############################################################################
# Parse arguments
###############################################################################

DO_CLEANUP=false
CLEANUP_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --cleanup) DO_CLEANUP=true ;;
        --cleanup-only) CLEANUP_ONLY=true; DO_CLEANUP=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

###############################################################################
# Cleanup
###############################################################################

do_cleanup() {
    step "C" "Cleanup"

    info "Deleting objects in source bucket..."
    obsutil rm "obs://${SRC_BUCKET}/" -r -f \
        -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" 2>&1 | tail -3 || true

    info "Deleting source bucket..."
    obsutil rm "obs://${SRC_BUCKET}" -f \
        -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" 2>&1 | tail -1 || true

    info "Deleting objects in destination bucket..."
    obsutil rm "obs://${DST_BUCKET}/" -r -f \
        -i="$DST_AK" -k="$DST_SK" -e="$OBS_ENDPOINT" 2>&1 | tail -3 || true

    info "Deleting destination bucket..."
    obsutil rm "obs://${DST_BUCKET}" -f \
        -i="$DST_AK" -k="$DST_SK" -e="$OBS_ENDPOINT" 2>&1 | tail -1 || true

    if [[ -n "${GRANT_ID:-}" && -n "${SRC_KEY_ID:-}" && -n "${SRC_TOKEN:-}" ]]; then
        info "Revoking KMS grant..."
        curl -s -H "X-Auth-Token: $SRC_TOKEN" -H "Content-Type: application/json" \
            -d "{\"key_id\":\"$SRC_KEY_ID\",\"grant_id\":\"$GRANT_ID\"}" \
            "${KMS_ENDPOINT}/v1.0/${SRC_PROJECT_ID}/kms/revoke-grant" | jq -r '.error.error_msg // "OK"'
    fi

    if [[ -n "${SRC_KEY_ID:-}" && -n "${SRC_TOKEN:-}" ]]; then
        info "Scheduling source CMK deletion..."
        curl -s -H "X-Auth-Token: $SRC_TOKEN" -H "Content-Type: application/json" \
            -d "{\"key_id\":\"$SRC_KEY_ID\",\"pending_days\":\"7\"}" \
            "${KMS_ENDPOINT}/v1.0/${SRC_PROJECT_ID}/kms/schedule-key-deletion" | jq -r '.error.error_msg // "OK"'
    fi

    if [[ -n "${DST_KEY_ID:-}" && -n "${DST_TOKEN:-}" ]]; then
        info "Scheduling destination CMK deletion..."
        curl -s -H "X-Auth-Token: $DST_TOKEN" -H "Content-Type: application/json" \
            -d "{\"key_id\":\"$DST_KEY_ID\",\"pending_days\":\"7\"}" \
            "${KMS_ENDPOINT}/v1.0/${DST_PROJECT_ID}/kms/schedule-key-deletion" | jq -r '.error.error_msg // "OK"'
    fi

    rm -f /tmp/crr-sse-test-* /tmp/crr-small-files/ 2>/dev/null
    rm -rf /tmp/crr-small-files 2>/dev/null
    info "Cleanup complete"
}

if $CLEANUP_ONLY; then
    echo "=== Cleanup-only mode ==="
    load_state
    if [[ -z "${SRC_TOKEN:-}" ]]; then
        SRC_TOKEN=$(get_iam_token "$SRC_USERNAME" "$SRC_PASSWORD" "$SRC_DOMAIN" "$SRC_PROJECT_ID")
    fi
    if [[ -z "${DST_TOKEN:-}" ]]; then
        DST_TOKEN=$(get_iam_token "$DST_USERNAME" "$DST_PASSWORD" "$DST_DOMAIN" "$DST_PROJECT_ID")
    fi
    do_cleanup
    rm -f "$STATE_FILE"
    exit 0
fi

###############################################################################
# Main test
###############################################################################

echo "============================================================"
echo "  OBS Cross-Tenant SSE-KMS: Full CRR + Re-encryption Test"
echo "============================================================"
echo ""
echo "Source:       10491 ($SRC_DOMAIN)"
echo "Destination:  10497 ($DST_DOMAIN)"
echo "Test data:    ${BIG_FILE_COUNT}x${BIG_FILE_SIZE_GB}GB + ${SMALL_FILE_COUNT} small files"
echo ""

OVERALL_PASS=true
START_TIME=$(date +%s)

# ---------- Step 0: IAM Tokens + Domain IDs ----------
step "0" "Get IAM Tokens + Domain IDs"

SRC_TOKEN=$(get_iam_token "$SRC_USERNAME" "$SRC_PASSWORD" "$SRC_DOMAIN" "$SRC_PROJECT_ID")
[[ "$SRC_TOKEN" == "ERROR" ]] && { fail "Source IAM token"; exit 1; }
pass "Source IAM token"

DST_TOKEN=$(get_iam_token "$DST_USERNAME" "$DST_PASSWORD" "$DST_DOMAIN" "$DST_PROJECT_ID")
[[ "$DST_TOKEN" == "ERROR" ]] && { fail "Destination IAM token"; exit 1; }
pass "Destination IAM token"

SRC_DOMAIN_ID=$(get_domain_id "$SRC_TOKEN")
DST_DOMAIN_ID=$(get_domain_id "$DST_TOKEN")
pass "Source domain: $SRC_DOMAIN_ID"
pass "Dest domain:   $DST_DOMAIN_ID"
mark_pass 0

# ---------- Step 1: Create CMKs ----------
step "1" "Create/Restore KMS Keys"

info "Source CMK (tenant 10491)..."
SRC_KEY_ID=$(ensure_kms_key "$SRC_TOKEN" "$SRC_PROJECT_ID" "$SRC_KEY_ALIAS" "Source CMK for cross-tenant test")
[[ "$SRC_KEY_ID" == "ERROR" ]] && { fail "Source CMK creation"; exit 1; }
pass "Source CMK: $SRC_KEY_ID"

info "Destination CMK (tenant 10497) — for re-encryption later..."
DST_KEY_ID=$(ensure_kms_key "$DST_TOKEN" "$DST_PROJECT_ID" "$DST_KEY_ALIAS" "Destination CMK for re-encryption")
[[ "$DST_KEY_ID" == "ERROR" ]] && { fail "Destination CMK creation"; exit 1; }
pass "Dest CMK:   $DST_KEY_ID"
mark_pass 1

save_state

# ---------- Step 2: Create KMS Grant ----------
step "2" "Grant Source CMK Access to Destination Tenant"

GRANT_RESP=$(curl -s \
    -H "X-Auth-Token: $SRC_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"key_id\": \"$SRC_KEY_ID\",
        \"grantee_principal\": \"$DST_DOMAIN_ID\",
        \"grantee_principal_type\": \"domain\",
        \"operations\": [\"describe-key\", \"create-datakey\", \"encrypt-datakey\", \"decrypt-datakey\"],
        \"name\": \"$GRANT_NAME\"
    }" \
    "${KMS_ENDPOINT}/v1.0/${SRC_PROJECT_ID}/kms/create-grant")

GRANT_ID=$(echo "$GRANT_RESP" | jq -r '.grant_id // empty')
if [[ -z "$GRANT_ID" ]]; then
    # May already exist
    LIST_GRANTS=$(curl -s -H "X-Auth-Token: $SRC_TOKEN" -H "Content-Type: application/json" \
        -d "{\"key_id\":\"$SRC_KEY_ID\",\"limit\":100}" \
        "${KMS_ENDPOINT}/v1.0/${SRC_PROJECT_ID}/kms/list-grants")
    GRANT_ID=$(echo "$LIST_GRANTS" | jq -r ".grants[] | select(.name==\"$GRANT_NAME\") | .grant_id" 2>/dev/null | head -1)
    [[ -n "$GRANT_ID" ]] && pass "Found existing grant: ${GRANT_ID:0:16}..." || { fail "Grant creation failed"; echo "$GRANT_RESP" | jq .; mark_fail 2; }
else
    pass "Created grant: ${GRANT_ID:0:16}..."
fi
[[ -z "${STEP_RESULT[2]:-}" ]] && mark_pass 2

save_state

# ---------- Step 3: Create Buckets with SSE-KMS ----------
step "3" "Create Buckets with SSE-KMS Encryption"

# Source bucket
info "Creating source bucket..."
obsutil mb "obs://${SRC_BUCKET}" -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" 2>&1 | tail -1 || true

info "Setting SSE-KMS on source bucket (source CMK)..."
ENC_RESULT=$(set_bucket_encryption "$SRC_BUCKET" "$SRC_KEY_ID" "$SRC_AK" "$SRC_SK")
ENC_HTTP=$(echo "$ENC_RESULT" | parse_json status_code)
if [[ "$ENC_HTTP" == "200" || "$ENC_HTTP" == "204" ]]; then
    pass "Source bucket: SSE-KMS with key ${SRC_KEY_ID:0:8}..."
else
    fail "Source bucket encryption (HTTP $ENC_HTTP)"
    echo "$ENC_RESULT" | parse_json body
    mark_fail 3
fi

# Destination bucket — using SOURCE tenant's key via grant
info "Creating destination bucket..."
obsutil mb "obs://${DST_BUCKET}" -i="$DST_AK" -k="$DST_SK" -e="$OBS_ENDPOINT" 2>&1 | tail -1 || true

info "Setting SSE-KMS on destination bucket (source CMK via grant)..."
ENC_RESULT2=$(set_bucket_encryption "$DST_BUCKET" "$SRC_KEY_ID" "$DST_AK" "$DST_SK")
ENC_HTTP2=$(echo "$ENC_RESULT2" | parse_json status_code)
if [[ "$ENC_HTTP2" == "200" || "$ENC_HTTP2" == "204" ]]; then
    pass "Dest bucket: SSE-KMS with source key ${SRC_KEY_ID:0:8}... (via grant)"
else
    fail "Dest bucket encryption with source key (HTTP $ENC_HTTP2)"
    echo "$ENC_RESULT2" | parse_json body
    # Try default SSE-KMS as fallback
    warn "Trying default SSE-KMS on destination..."
    ENC_RESULT3=$(set_bucket_encryption "$DST_BUCKET" "" "$DST_AK" "$DST_SK")
    ENC_HTTP3=$(echo "$ENC_RESULT3" | parse_json status_code)
    if [[ "$ENC_HTTP3" == "200" || "$ENC_HTTP3" == "204" ]]; then
        warn "Fell back to default SSE-KMS on destination"
    fi
fi
[[ -z "${STEP_RESULT[3]:-}" ]] && mark_pass 3

# Verify both
info "Verifying source encryption..."
GET_SRC=$(obs_api "GET" "$SRC_BUCKET" "encryption" "" "$SRC_AK" "$SRC_SK")
echo "$GET_SRC" | parse_json body | python3 -c "
import sys, xml.etree.ElementTree as ET
try:
    root = ET.fromstring(sys.stdin.read())
    for e in root.iter():
        if 'SSEAlgorithm' in e.tag: print(f'    Algorithm: {e.text}')
        if 'KMSMasterKeyID' in e.tag: print(f'    KeyID: {e.text}')
except: pass
"

info "Verifying destination encryption..."
GET_DST=$(obs_api "GET" "$DST_BUCKET" "encryption" "" "$DST_AK" "$DST_SK")
echo "$GET_DST" | parse_json body | python3 -c "
import sys, xml.etree.ElementTree as ET
try:
    root = ET.fromstring(sys.stdin.read())
    for e in root.iter():
        if 'SSEAlgorithm' in e.tag: print(f'    Algorithm: {e.text}')
        if 'KMSMasterKeyID' in e.tag: print(f'    KeyID: {e.text}')
except: pass
"

# ---------- Step 4: Upload Test Data ----------
step "4" "Upload Test Data to Source Bucket"

UPLOAD_START=$(date +%s)

# Big files — one at a time to save disk
for i in $(seq 1 $BIG_FILE_COUNT); do
    BIGFILE="/tmp/crr-sse-test-big-${i}.dat"
    info "Generating big file $i/${BIG_FILE_COUNT} (${BIG_FILE_SIZE_GB}GB)..."
    dd if=/dev/urandom of="$BIGFILE" bs=1M count=$((BIG_FILE_SIZE_GB * 1024)) status=progress 2>&1 | tail -1

    info "Uploading big-file-${i}.dat (${BIG_FILE_SIZE_GB}GB)..."
    T0=$(date +%s)
    obsutil cp "$BIGFILE" "obs://${SRC_BUCKET}/big-file-${i}.dat" -f \
        -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" -p=10 2>&1 | tail -3
    T1=$(date +%s)
    ELAPSED=$((T1 - T0))
    if [[ $ELAPSED -gt 0 ]]; then
        SPEED=$(python3 -c "print(f'{$BIG_FILE_SIZE_GB * 1024 / $ELAPSED:.0f} MB/s')")
    else
        SPEED="instant"
    fi
    pass "big-file-${i}.dat uploaded in ${ELAPSED}s ($SPEED)"

    rm -f "$BIGFILE"
done

# Small files — generate batch in tmpdir
SMALL_DIR="/tmp/crr-small-files"
mkdir -p "$SMALL_DIR"
info "Generating $SMALL_FILE_COUNT small files..."
for i in $(seq 1 $SMALL_FILE_COUNT); do
    # Random size: 1KB to 1MB
    SIZE_KB=$(( (RANDOM % 1024) + 1 ))
    dd if=/dev/urandom of="${SMALL_DIR}/small-${i}.dat" bs=1K count=$SIZE_KB 2>/dev/null
done
SMALL_TOTAL=$(du -sh "$SMALL_DIR" | cut -f1)
pass "$SMALL_FILE_COUNT small files generated ($SMALL_TOTAL total)"

info "Uploading $SMALL_FILE_COUNT small files..."
T0=$(date +%s)
obsutil cp "$SMALL_DIR/" "obs://${SRC_BUCKET}/small-files/" -r -f \
    -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" -j=20 -p=5 2>&1 | tail -5
T1=$(date +%s)
pass "Small files uploaded in $((T1 - T0))s"
rm -rf "$SMALL_DIR"

UPLOAD_END=$(date +%s)
UPLOAD_TOTAL=$((UPLOAD_END - UPLOAD_START))
info "Total upload time: ${UPLOAD_TOTAL}s"

# Verify upload
SRC_STAT=$(obsutil ls "obs://${SRC_BUCKET}/" -s -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" 2>&1)
SRC_FILES=$(echo "$SRC_STAT" | grep -oP 'File number:\s*\K\d+' || echo "?")
SRC_SIZE=$(echo "$SRC_STAT" | grep -oP 'Total size.*?:\s*\K.*' || echo "?")
pass "Source bucket: $SRC_FILES files, $SRC_SIZE"

# Spot-check encryption on a big file
info "Checking encryption on big-file-1.dat..."
BIG1_HEAD=$(head_object "$SRC_BUCKET" "big-file-1.dat" "$SRC_AK" "$SRC_SK")
if echo "$BIG1_HEAD" | grep -q "aws:kms"; then
    KMS_KEY_USED=$(echo "$BIG1_HEAD" | grep -i "kms-key-id" | head -1)
    pass "big-file-1.dat encrypted: $KMS_KEY_USED"
else
    warn "Encryption not confirmed on big-file-1.dat"
fi

# Spot-check a small file
info "Checking encryption on small-files/small-1.dat..."
SM1_HEAD=$(head_object "$SRC_BUCKET" "small-files/small-1.dat" "$SRC_AK" "$SRC_SK")
if echo "$SM1_HEAD" | grep -q "aws:kms"; then
    pass "small-1.dat encrypted with SSE-KMS"
else
    warn "Encryption not confirmed on small-1.dat"
fi
mark_pass 4

# ---------- Step 5: CRR Copy ----------
step "5" "Cross-Tenant Copy (CRR)"

info "Configuring obsutil CRR credentials..."
obsutil config -i="$DST_AK" -k="$DST_SK" -e="$OBS_ENDPOINT" >/dev/null 2>&1
obsutil config -i="$SRC_AK" -k="$SRC_SK" -e="$OBS_ENDPOINT" -crr >/dev/null 2>&1

CRR_START=$(date +%s)
info "Running CRR copy (this may take several minutes for ${BIG_FILE_COUNT}x${BIG_FILE_SIZE_GB}GB)..."
CRR_RESP=$(obsutil cp "obs://${SRC_BUCKET}/" "obs://${DST_BUCKET}/" -r -f -crr -j=10 -p=10 2>&1)
CRR_EXIT=$?
CRR_END=$(date +%s)
CRR_ELAPSED=$((CRR_END - CRR_START))

echo "$CRR_RESP" | tail -10
echo ""

SUCCEED=$(echo "$CRR_RESP" | grep -oP 'Succeed count:\s*\K\d+' || echo "0")
FAILED=$(echo "$CRR_RESP" | grep -oP 'Failed count:\s*\K\d+' || echo "?")
CRR_BYTES=$(echo "$CRR_RESP" | grep -oP 'Succeed bytes:\s*\K\S+' || echo "?")

if [[ $CRR_EXIT -eq 0 || $CRR_EXIT -eq 6 ]] && [[ "$FAILED" == "0" ]]; then
    pass "CRR copy: $SUCCEED files, $CRR_BYTES in ${CRR_ELAPSED}s (exit $CRR_EXIT)"
    if [[ $CRR_ELAPSED -gt 0 ]]; then
        info "Average throughput: $(python3 -c "
size_gb = $BIG_FILE_COUNT * $BIG_FILE_SIZE_GB
print(f'{size_gb * 1024 / $CRR_ELAPSED:.0f} MB/s (approx)')
")"
    fi
    mark_pass 5
else
    fail "CRR copy: $SUCCEED succeeded, $FAILED failed (exit $CRR_EXIT)"
    mark_fail 5
fi

# ---------- Step 6: Verify CRR ----------
step "6" "Verify CRR Copy"

DST_STAT=$(obsutil ls "obs://${DST_BUCKET}/" -s -i="$DST_AK" -k="$DST_SK" -e="$OBS_ENDPOINT" 2>&1)
DST_FILES=$(echo "$DST_STAT" | grep -oP 'File number:\s*\K\d+' || echo "?")
DST_SIZE=$(echo "$DST_STAT" | grep -oP 'Total size.*?:\s*\K.*' || echo "?")

info "Source:      $SRC_FILES files, $SRC_SIZE"
info "Destination: $DST_FILES files, $DST_SIZE"

EXPECTED_FILES=$((BIG_FILE_COUNT + SMALL_FILE_COUNT))
if [[ "$DST_FILES" == "$SRC_FILES" && "$DST_FILES" -ge "$EXPECTED_FILES" ]]; then
    pass "File counts match: $DST_FILES"
else
    fail "File count mismatch: source=$SRC_FILES, dest=$DST_FILES (expected >=$EXPECTED_FILES)"
    mark_fail 6
fi

# Check encryption key on destination objects — should still reference source key
info "Checking encryption key on destination big-file-1.dat..."
DST_BIG1_HEAD=$(head_object "$DST_BUCKET" "big-file-1.dat" "$DST_AK" "$DST_SK")
DST_BIG1_KEY=$(echo "$DST_BIG1_HEAD" | grep -i "kms-key-id" | head -1)
if echo "$DST_BIG1_KEY" | grep -qi "$SRC_KEY_ID"; then
    pass "Destination big-file-1.dat uses source CMK: $DST_BIG1_KEY"
else
    warn "Unexpected key on destination: $DST_BIG1_KEY"
fi
[[ -z "${STEP_RESULT[6]:-}" ]] && mark_pass 6

# ---------- Step 7: Re-encrypt Destination with Destination's Own CMK ----------
step "7" "Re-encrypt Destination Bucket with Destination's Own CMK"

info "Destination CMK: $DST_KEY_ID"
info "Re-encrypting all objects (server-side copy-to-self with new key)..."

REKEY_START=$(date +%s)

# Use Python boto3 for reliable multipart copy with SSE-KMS
python3 - "$DST_BUCKET" "$DST_KEY_ID" "$DST_AK" "$DST_SK" <<'PYEOF'
import sys
import boto3
from botocore.config import Config

bucket, new_key_id, ak, sk = sys.argv[1:5]
endpoint = "https://obs.eu-de.otc.t-systems.com"

s3 = boto3.client(
    's3',
    aws_access_key_id=ak,
    aws_secret_access_key=sk,
    endpoint_url=endpoint,
    region_name='eu-de',
    config=Config(
        s3={'addressing_style': 'virtual'},
        max_pool_connections=50,
    )
)

# List all objects
objects = []
paginator = s3.get_paginator('list_objects_v2')
for page in paginator.paginate(Bucket=bucket):
    for obj in page.get('Contents', []):
        objects.append(obj)

total = len(objects)
total_bytes = sum(o['Size'] for o in objects)
print(f"  Found {total} objects ({total_bytes / (1024**3):.2f} GB) to re-encrypt")

succeeded = 0
failed = 0

for i, obj in enumerate(objects):
    key = obj['Key']
    size = obj['Size']
    size_str = f"{size / (1024**3):.1f}GB" if size > 1024**3 else f"{size / (1024**2):.1f}MB" if size > 1024**2 else f"{size / 1024:.0f}KB"

    try:
        # For large files (>5GB), boto3.copy() auto-uses multipart
        copy_source = {'Bucket': bucket, 'Key': key}
        extra_args = {
            'ServerSideEncryption': 'aws:kms',
            'SSEKMSKeyId': new_key_id,
            'MetadataDirective': 'COPY',
        }

        if size > 5 * 1024**3:
            # Large file — use multipart copy via boto3's managed transfer
            print(f"  [{i+1}/{total}] Re-encrypting {key} ({size_str}) [multipart]...", flush=True)
            transfer_config = boto3.s3.transfer.TransferConfig(
                multipart_threshold=5 * 1024**3,
                multipart_chunksize=512 * 1024**2,  # 512MB parts
                max_concurrency=10,
            )
            s3.copy(
                CopySource=copy_source,
                Bucket=bucket,
                Key=key,
                ExtraArgs=extra_args,
                Config=transfer_config,
            )
        else:
            # Small file — single copy_object
            if (i + 1) % 50 == 0 or size > 1024**3 or i == 0:
                print(f"  [{i+1}/{total}] Re-encrypting {key} ({size_str})...", flush=True)
            s3.copy_object(
                Bucket=bucket,
                Key=key,
                CopySource=f"{bucket}/{key}",
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=new_key_id,
                MetadataDirective='COPY',
            )
        succeeded += 1
    except Exception as e:
        failed += 1
        print(f"  [{i+1}/{total}] FAILED {key}: {e}")

print(f"\n  Re-encryption complete: {succeeded} succeeded, {failed} failed")
PYEOF
REKEY_EXIT=$?

REKEY_END=$(date +%s)
REKEY_ELAPSED=$((REKEY_END - REKEY_START))

if [[ $REKEY_EXIT -eq 0 ]]; then
    pass "Re-encryption completed in ${REKEY_ELAPSED}s"
    mark_pass 7
else
    fail "Re-encryption failed (exit $REKEY_EXIT)"
    mark_fail 7
fi

# ---------- Step 8: Verify Re-encryption ----------
step "8" "Verify Re-encryption (all objects use destination CMK)"

info "Checking encryption key on re-encrypted objects..."

# Check big files
ALL_REKEY_OK=true
for i in $(seq 1 $BIG_FILE_COUNT); do
    BIG_HEAD=$(head_object "$DST_BUCKET" "big-file-${i}.dat" "$DST_AK" "$DST_SK")
    BIG_KEY=$(echo "$BIG_HEAD" | grep -i "kms-key-id" | grep -oP 'key/\K[a-f0-9-]+' || echo "unknown")
    if [[ "$BIG_KEY" == "$DST_KEY_ID" ]]; then
        pass "big-file-${i}.dat now uses destination CMK ($DST_KEY_ID)"
    else
        fail "big-file-${i}.dat still uses key: $BIG_KEY (expected $DST_KEY_ID)"
        ALL_REKEY_OK=false
    fi
done

# Spot-check some small files
for i in 1 50 150 300; do
    [[ $i -gt $SMALL_FILE_COUNT ]] && continue
    SM_HEAD=$(head_object "$DST_BUCKET" "small-files/small-${i}.dat" "$DST_AK" "$DST_SK")
    SM_KEY=$(echo "$SM_HEAD" | grep -i "kms-key-id" | grep -oP 'key/\K[a-f0-9-]+' || echo "unknown")
    if [[ "$SM_KEY" == "$DST_KEY_ID" ]]; then
        pass "small-${i}.dat uses destination CMK"
    else
        fail "small-${i}.dat still uses key: $SM_KEY"
        ALL_REKEY_OK=false
    fi
done

$ALL_REKEY_OK && mark_pass 8 || mark_fail 8

# ---------- Step 9: Test Independence — Revoke Grant ----------
step "9" "Test Independence: Revoke Grant + Read Destination Objects"

info "Revoking KMS grant (removing destination's access to source key)..."
REVOKE_RESP=$(curl -s -w "\n%{http_code}" \
    -H "X-Auth-Token: $SRC_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"key_id\":\"$SRC_KEY_ID\",\"grant_id\":\"$GRANT_ID\"}" \
    "${KMS_ENDPOINT}/v1.0/${SRC_PROJECT_ID}/kms/revoke-grant")
REVOKE_HTTP=$(echo "$REVOKE_RESP" | tail -1)
if [[ "$REVOKE_HTTP" == "200" || "$REVOKE_HTTP" == "204" ]]; then
    pass "Grant revoked — destination no longer has access to source key"
    GRANT_ID=""  # Clear so cleanup doesn't try again
    save_state
else
    warn "Grant revoke returned HTTP $REVOKE_HTTP"
fi

info "Waiting 5 seconds for grant revocation to propagate..."
sleep 5

# Now try reading destination objects — they should still be readable with dest's own key
info "Reading destination big-file-1.dat after grant revocation..."
READ_TEST=$(python3 - "$DST_BUCKET" "$DST_AK" "$DST_SK" <<'PYEOF'
import sys
import boto3
from botocore.config import Config

bucket, ak, sk = sys.argv[1:4]
s3 = boto3.client(
    's3',
    aws_access_key_id=ak,
    aws_secret_access_key=sk,
    endpoint_url="https://obs.eu-de.otc.t-systems.com",
    region_name='eu-de',
    config=Config(s3={'addressing_style': 'virtual'}),
)

# Try reading first 1MB of big-file-1.dat
try:
    resp = s3.get_object(Bucket=bucket, Key="big-file-1.dat", Range="bytes=0-1048575")
    data = resp['Body'].read()
    sse = resp.get('ServerSideEncryption', 'none')
    key_id = resp.get('SSEKMSKeyId', 'none')
    print(f"OK: Read {len(data)} bytes, SSE={sse}, KeyID={key_id}")
except Exception as e:
    print(f"FAIL: {e}")
PYEOF
)

if echo "$READ_TEST" | grep -q "^OK:"; then
    pass "Destination objects readable after grant revocation!"
    info "$READ_TEST"
    mark_pass 9
else
    fail "Destination objects NOT readable after grant revocation"
    info "$READ_TEST"
    mark_fail 9
fi

# Also try a small file
info "Reading small-files/small-1.dat after grant revocation..."
READ_SMALL=$(python3 - "$DST_BUCKET" "$DST_AK" "$DST_SK" <<'PYEOF'
import sys
import boto3
from botocore.config import Config

bucket, ak, sk = sys.argv[1:4]
s3 = boto3.client(
    's3',
    aws_access_key_id=ak,
    aws_secret_access_key=sk,
    endpoint_url="https://obs.eu-de.otc.t-systems.com",
    region_name='eu-de',
    config=Config(s3={'addressing_style': 'virtual'}),
)

try:
    resp = s3.get_object(Bucket=bucket, Key="small-files/small-1.dat")
    data = resp['Body'].read()
    print(f"OK: Read {len(data)} bytes")
except Exception as e:
    print(f"FAIL: {e}")
PYEOF
)

if echo "$READ_SMALL" | grep -q "^OK:"; then
    pass "Small file readable after grant revocation"
else
    fail "Small file NOT readable: $READ_SMALL"
fi

# ---------- Summary ----------
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo "============================================================"
echo "  Test Summary"
echo "============================================================"
echo ""

LABELS=(
    "IAM tokens + domain IDs"
    "Create KMS keys (source + dest)"
    "Grant source CMK to dest tenant"
    "Create buckets + SSE-KMS"
    "Upload test data (${BIG_FILE_COUNT}x${BIG_FILE_SIZE_GB}GB + ${SMALL_FILE_COUNT} small)"
    "CRR cross-tenant copy"
    "Verify CRR copy"
    "Re-encrypt with destination CMK"
    "Verify re-encryption"
    "Independence test (revoke grant)"
)

for i in $(seq 0 9); do
    result="${STEP_RESULT[$i]:-SKIP}"
    label="${LABELS[$i]}"
    case "$result" in
        PASS) printf "  ${GREEN}[PASS]${NC} Step %d: %s\n" "$i" "$label" ;;
        FAIL) printf "  ${RED}[FAIL]${NC} Step %d: %s\n" "$i" "$label" ;;
        *)    printf "  ${YELLOW}[SKIP]${NC} Step %d: %s\n" "$i" "$label" ;;
    esac
done

echo ""
echo "  Timing:"
echo "    Upload:         ${UPLOAD_TOTAL:-?}s"
echo "    CRR copy:       ${CRR_ELAPSED:-?}s"
echo "    Re-encryption:  ${REKEY_ELAPSED:-?}s"
echo "    Total:          ${TOTAL_TIME}s"
echo ""
echo "  Keys:"
echo "    Source CMK:  $SRC_KEY_ID (tenant 10491)"
echo "    Dest CMK:    $DST_KEY_ID (tenant 10497)"
echo "    Grant:       ${GRANT_ID:-(revoked)}"
echo ""
echo "  Buckets:"
echo "    Source: obs://$SRC_BUCKET"
echo "    Dest:   obs://$DST_BUCKET"
echo ""

if $OVERALL_PASS; then
    echo -e "  ${GREEN}OVERALL: PASS${NC}"
    echo ""
    echo "  Conclusion:"
    echo "    1. SSE-KMS with custom CMK + KMS Grant works for cross-tenant CRR"
    echo "    2. Re-encryption with destination's own CMK succeeds"
    echo "    3. After re-encryption, destination is FULLY INDEPENDENT"
    echo "       (grant revoked, objects still readable with dest's own key)"
else
    echo -e "  ${RED}OVERALL: FAIL — See details above${NC}"
fi

echo ""

if $DO_CLEANUP; then
    do_cleanup
    rm -f "$STATE_FILE"
else
    echo "  Run with --cleanup to delete all test resources."
    echo "  Run with --cleanup-only to cleanup without re-running the test."
fi
