# OTC OBS Cross-Tenant Copy & Encryption Tools

Tools for copying OBS buckets between OTC tenants and encrypting them with SSE-KMS.

## Prerequisites

- Python 3 with `boto3` (`pip3 install boto3`)
- [obsutil](https://support.huaweicloud.com/intl/en-us/utiltg-obs/obs_11_0003.html) for cross-tenant copy
- AK/SK credentials for source and/or destination tenant
- KMS key ID (create in OTC Console: KMS → Create Key → AES_256)

## Scripts

| Script | Purpose |
|---|---|
| `obs-encrypt.py` | Set SSE-KMS bucket encryption + re-encrypt existing objects |
| `credentials.example.md` | Credential template for AK/SK and obsutil CRR setup |

## obs-encrypt.py

Sets SSE-KMS default encryption on OBS buckets and re-encrypts all existing objects server-side (no data downloaded/uploaded).

### Usage

```bash
# Encrypt a single bucket (set policy + re-encrypt all objects)
python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK

# Encrypt multiple buckets
python3 obs-encrypt.py -b bucket1 -b bucket2 -b bucket3 -k KEY_ID --ak AK --sk SK

# Dry run — see what would happen without changing anything
python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --dry-run

# Only set bucket policy, skip re-encrypting existing objects
python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --policy-only

# Re-encrypt only objects under a prefix
python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --prefix data/2025/

# Custom endpoint and concurrency
python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK -e https://obs.eu-nl.otc.t-systems.com -j 20
```

### Notes

- Setting the bucket policy only affects **new** objects — existing objects must be re-encrypted
- Re-encryption is a server-side copy-to-self, no local disk or bandwidth used
- Objects over 5GB are handled automatically via multipart copy
- The `--dry-run` flag lists all objects that would be affected without making changes

## Cross-Tenant Copy (obsutil CRR)

```bash
# Configure destination as default
obsutil config -i=DEST_AK -k=DEST_SK -e=https://obs.eu-de.otc.t-systems.com

# Configure source as CRR
obsutil config -i=SRC_AK -k=SRC_SK -e=https://obs.eu-de.otc.t-systems.com -crr

# Copy entire bucket
obsutil cp obs://source-bucket/ obs://dest-bucket/ -r -f -crr -j=10 -p=10
```

See `OBS-Cross-Tenant-Copy-Guide.md` for full details including performance benchmarks.

## Typical Workflow

```bash
# 1. Copy buckets cross-tenant
obsutil cp obs://src-bucket/ obs://dst-bucket/ -r -f -crr -j=10 -p=10

# 2. Encrypt destination buckets with customer's own KMS key
python3 obs-encrypt.py -b dst-bucket1 -b dst-bucket2 -b dst-bucket3 \
    -k CUSTOMER_KEY_ID --ak DST_AK --sk DST_SK
```
