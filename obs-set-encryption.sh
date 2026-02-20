#!/usr/bin/env bash
#
# obs-set-encryption.sh — Set SSE-KMS default encryption on an OTC OBS bucket
#
# Sets the bucket-level default encryption policy so that all new objects
# uploaded to the bucket are automatically encrypted with the specified
# KMS key. Existing objects are NOT affected — use obs-reencrypt.py for that.
#
# Prerequisites:
#   - python3 with botocore installed (pip3 install botocore)
#   - AK/SK credentials with write access to the bucket
#   - A KMS key ID (create one in OTC Console → KMS → Create Key → AES_256)
#
# Usage:
#   ./obs-set-encryption.sh -b BUCKET -k KEY_ID -a AK -s SK [-e ENDPOINT]
#   ./obs-set-encryption.sh -b BUCKET -k KEY_ID -a AK -s SK --verify
#
# Examples:
#   # Set encryption
#   ./obs-set-encryption.sh -b my-bucket -k 12345678-abcd-1234-efgh-123456789012 \
#       -a MYACCESSKEY -s MYSECRETKEY
#
#   # Set encryption and verify
#   ./obs-set-encryption.sh -b my-bucket -k 12345678-abcd-1234-efgh-123456789012 \
#       -a MYACCESSKEY -s MYSECRETKEY --verify
#
set -euo pipefail

###############################################################################
# Defaults
###############################################################################

ENDPOINT="https://obs.eu-de.otc.t-systems.com"
REGION="eu-de"
VERIFY=false

###############################################################################
# Usage
###############################################################################

usage() {
    echo "Usage: $0 -b BUCKET -k KMS_KEY_ID -a AK -s SK [-e ENDPOINT] [--verify]"
    echo ""
    echo "Options:"
    echo "  -b    OBS bucket name"
    echo "  -k    KMS key ID (UUID)"
    echo "  -a    Access Key"
    echo "  -s    Secret Key"
    echo "  -e    OBS endpoint (default: $ENDPOINT)"
    echo "  --verify  Verify encryption config after setting it"
    exit 1
}

###############################################################################
# Parse arguments
###############################################################################

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b) BUCKET="$2"; shift 2 ;;
        -k) KEY_ID="$2"; shift 2 ;;
        -a) AK="$2"; shift 2 ;;
        -s) SK="$2"; shift 2 ;;
        -e) ENDPOINT="$2"; shift 2 ;;
        --verify) VERIFY=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

[[ -z "${BUCKET:-}" ]] && { echo "Error: -b BUCKET required"; usage; }
[[ -z "${KEY_ID:-}" ]] && { echo "Error: -k KMS_KEY_ID required"; usage; }
[[ -z "${AK:-}" ]]     && { echo "Error: -a AK required"; usage; }
[[ -z "${SK:-}" ]]     && { echo "Error: -s SK required"; usage; }

# Extract region from endpoint (e.g., obs.eu-de.otc... → eu-de)
REGION=$(echo "$ENDPOINT" | grep -oP 'obs\.\K[^.]+' || echo "eu-de")

###############################################################################
# Set encryption
###############################################################################

echo "Setting SSE-KMS encryption on bucket: $BUCKET"
echo "  KMS Key: $KEY_ID"
echo "  Endpoint: $ENDPOINT"
echo ""

RESULT=$(python3 - "$BUCKET" "$KEY_ID" "$AK" "$SK" "$ENDPOINT" "$REGION" <<'PYEOF'
import sys, hashlib, json
import botocore.auth, botocore.credentials, botocore.awsrequest
import urllib.request, urllib.error, ssl

bucket, key_id, ak, sk, endpoint, region = sys.argv[1:7]

body = (
    "<ServerSideEncryptionConfiguration>"
    "<Rule><ApplyServerSideEncryptionByDefault>"
    f"<SSEAlgorithm>aws:kms</SSEAlgorithm>"
    f"<KMSMasterKeyID>{key_id}</KMSMasterKeyID>"
    "</ApplyServerSideEncryptionByDefault></Rule>"
    "</ServerSideEncryptionConfiguration>"
)

host = f"{bucket}.{endpoint.replace('https://', '')}"
url = f"https://{host}/?encryption"
payload_hash = hashlib.sha256(body.encode()).hexdigest()

creds = botocore.credentials.Credentials(ak, sk)
signer = botocore.auth.SigV4Auth(creds, "s3", region)
headers = {
    "Host": host,
    "Content-Type": "application/xml",
    "x-amz-content-sha256": payload_hash,
}
request = botocore.awsrequest.AWSRequest(method="PUT", url=url, headers=headers, data=body)
signer.add_auth(request)

req = urllib.request.Request(url, data=body.encode(), headers=dict(request.headers), method="PUT")
ctx = ssl.create_default_context()
try:
    with urllib.request.urlopen(req, context=ctx) as resp:
        print(json.dumps({"status": resp.status, "ok": True}))
except urllib.error.HTTPError as e:
    err_body = e.read().decode()
    print(json.dumps({"status": e.code, "ok": False, "error": err_body}))
PYEOF
)

STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
OK=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['ok'])")

if [[ "$OK" == "True" ]]; then
    echo "OK: Encryption set (HTTP $STATUS)"
else
    echo "FAILED: HTTP $STATUS"
    echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" | head -5
    exit 1
fi

###############################################################################
# Verify (optional)
###############################################################################

if $VERIFY; then
    echo ""
    echo "Verifying encryption configuration..."

    python3 - "$BUCKET" "$AK" "$SK" "$ENDPOINT" "$REGION" <<'PYEOF'
import sys, hashlib
import botocore.auth, botocore.credentials, botocore.awsrequest
import urllib.request, urllib.error, ssl
import xml.etree.ElementTree as ET

bucket, ak, sk, endpoint, region = sys.argv[1:6]

host = f"{bucket}.{endpoint.replace('https://', '')}"
url = f"https://{host}/?encryption"
payload_hash = hashlib.sha256(b"").hexdigest()

creds = botocore.credentials.Credentials(ak, sk)
signer = botocore.auth.SigV4Auth(creds, "s3", region)
headers = {"Host": host, "x-amz-content-sha256": payload_hash}
request = botocore.awsrequest.AWSRequest(method="GET", url=url, headers=headers)
signer.add_auth(request)

req = urllib.request.Request(url, headers=dict(request.headers), method="GET")
ctx = ssl.create_default_context()
try:
    with urllib.request.urlopen(req, context=ctx) as resp:
        body = resp.read().decode()
        root = ET.fromstring(body)
        for elem in root.iter():
            if "SSEAlgorithm" in elem.tag:
                print(f"  Algorithm: {elem.text}")
            if "KMSMasterKeyID" in elem.tag:
                print(f"  KMS Key:   {elem.text}")
        print("  Status:    OK")
except urllib.error.HTTPError as e:
    print(f"  FAILED: HTTP {e.code}")
    print(f"  {e.read().decode()[:200]}")
PYEOF
fi
