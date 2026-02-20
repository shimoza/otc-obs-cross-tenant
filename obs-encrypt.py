#!/usr/bin/env python3
"""
obs-encrypt.py — Set SSE-KMS encryption and re-encrypt objects in OTC OBS buckets

Sets bucket-level default SSE-KMS encryption and optionally re-encrypts all
existing objects with a server-side copy-to-self. Supports multiple buckets
in a single invocation.

New objects uploaded after setting the bucket policy are encrypted automatically.
Existing objects must be re-encrypted explicitly (the default behavior).

Re-encryption is a server-side copy — no data is downloaded or uploaded.
Objects >5GB are handled automatically via multipart copy.

Prerequisites:
    pip3 install boto3

Usage:
    # Set encryption + re-encrypt all objects in one bucket
    python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK

    # Multiple buckets
    python3 obs-encrypt.py -b bucket1 -b bucket2 -b bucket3 -k KEY_ID --ak AK --sk SK

    # Dry run — show what would happen
    python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --dry-run

    # Only set bucket policy, don't re-encrypt existing objects
    python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --policy-only

    # Re-encrypt only objects under a prefix
    python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --prefix data/2025/
"""

import argparse
import hashlib
import ssl
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import boto3
import boto3.s3.transfer
import botocore.auth
import botocore.awsrequest
import botocore.credentials
from botocore.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def human_size(size_bytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def obs_signed_request(method, bucket, query, body, ak, sk, endpoint, region):
    """Make a SigV4-signed request to the OBS S3 API. Returns (status, body)."""
    host = f"{bucket}.{endpoint.replace('https://', '')}"
    url = f"https://{host}/?{query}" if query else f"https://{host}/"
    payload_hash = hashlib.sha256(body.encode() if body else b"").hexdigest()

    creds = botocore.credentials.Credentials(ak, sk)
    signer = botocore.auth.SigV4Auth(creds, "s3", region)
    headers = {"Host": host, "x-amz-content-sha256": payload_hash}
    if body:
        headers["Content-Type"] = "application/xml"

    request = botocore.awsrequest.AWSRequest(
        method=method, url=url, headers=headers, data=body or ""
    )
    signer.add_auth(request)

    req = urllib.request.Request(
        url,
        data=body.encode() if body else None,
        headers=dict(request.headers),
        method=method,
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# ---------------------------------------------------------------------------
# Set bucket encryption
# ---------------------------------------------------------------------------

def set_bucket_encryption(bucket, key_id, ak, sk, endpoint, region):
    """Set SSE-KMS default encryption on a bucket. Returns True on success."""
    body = (
        "<ServerSideEncryptionConfiguration>"
        "<Rule><ApplyServerSideEncryptionByDefault>"
        "<SSEAlgorithm>aws:kms</SSEAlgorithm>"
        f"<KMSMasterKeyID>{key_id}</KMSMasterKeyID>"
        "</ApplyServerSideEncryptionByDefault></Rule>"
        "</ServerSideEncryptionConfiguration>"
    )
    status, resp_body = obs_signed_request(
        "PUT", bucket, "encryption", body, ak, sk, endpoint, region
    )
    if status in (200, 204):
        return True, "OK"
    # Extract error message from XML
    try:
        root = ET.fromstring(resp_body)
        msg = root.findtext(".//{*}Message") or root.findtext(".//Message") or resp_body[:200]
    except ET.ParseError:
        msg = resp_body[:200]
    return False, f"HTTP {status}: {msg}"


def verify_bucket_encryption(bucket, ak, sk, endpoint, region):
    """Verify bucket encryption config. Returns (algorithm, key_id) or None."""
    status, resp_body = obs_signed_request(
        "GET", bucket, "encryption", "", ak, sk, endpoint, region
    )
    if status != 200:
        return None
    try:
        root = ET.fromstring(resp_body)
        algo = key_id = None
        for elem in root.iter():
            if "SSEAlgorithm" in elem.tag:
                algo = elem.text
            if "KMSMasterKeyID" in elem.tag:
                key_id = elem.text
        return (algo, key_id)
    except ET.ParseError:
        return None


# ---------------------------------------------------------------------------
# Re-encrypt objects
# ---------------------------------------------------------------------------

def reencrypt_bucket(bucket, key_id, ak, sk, endpoint, region, prefix="",
                     dry_run=False, concurrency=10):
    """Re-encrypt all objects in a bucket with the given KMS key.
    Returns (succeeded, failed, bytes_done, elapsed_seconds).
    """
    s3 = boto3.client(
        "s3",
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        endpoint_url=endpoint,
        region_name=region,
        config=Config(
            s3={"addressing_style": "virtual"},
            max_pool_connections=50,
        ),
    )

    # List objects
    objects = []
    paginate_args = {"Bucket": bucket}
    if prefix:
        paginate_args["Prefix"] = prefix

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(**paginate_args):
        for obj in page.get("Contents", []):
            objects.append(obj)

    if not objects:
        print(f"    No objects found in obs://{bucket}/{prefix}")
        return 0, 0, 0, 0

    total = len(objects)
    total_bytes = sum(o["Size"] for o in objects)
    big_count = sum(1 for o in objects if o["Size"] > 5 * 1024**3)
    print(
        f"    {total} objects ({human_size(total_bytes)})"
        + (f", {big_count} over 5GB (multipart)" if big_count else "")
    )

    if dry_run:
        for i, obj in enumerate(objects):
            print(f"      {obj['Key']:60s} {human_size(obj['Size']):>10s}")
            if i >= 19 and total > 20:
                print(f"      ... and {total - 20} more")
                break
        return total, 0, total_bytes, 0

    # Re-encrypt
    multipart_threshold = 5 * 1024**3
    transfer_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=multipart_threshold,
        multipart_chunksize=512 * 1024**2,
        max_concurrency=concurrency,
    )

    succeeded = 0
    failed = 0
    bytes_done = 0
    start_time = time.time()

    for i, obj in enumerate(objects):
        key = obj["Key"]
        size = obj["Size"]

        is_big = size > multipart_threshold
        show = (i == 0) or ((i + 1) % 100 == 0) or is_big or (i + 1 == total)
        if show:
            elapsed = time.time() - start_time
            pct = (i / total) * 100
            rate = f", {human_size(bytes_done / elapsed)}/s" if elapsed > 1 else ""
            tag = " [multipart]" if is_big else ""
            print(
                f"    [{i+1}/{total} {pct:.0f}%] {key} ({human_size(size)}){tag}{rate}",
                flush=True,
            )

        try:
            extra_args = {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": key_id,
                "MetadataDirective": "COPY",
            }

            if is_big:
                s3.copy(
                    CopySource={"Bucket": bucket, "Key": key},
                    Bucket=bucket,
                    Key=key,
                    ExtraArgs=extra_args,
                    Config=transfer_config,
                )
            else:
                s3.copy_object(
                    Bucket=bucket,
                    Key=key,
                    CopySource=f"{bucket}/{key}",
                    **extra_args,
                )
            succeeded += 1
            bytes_done += size

        except Exception as e:
            failed += 1
            print(f"    FAILED: {key} — {e}", file=sys.stderr)

    elapsed = time.time() - start_time
    return succeeded, failed, bytes_done, elapsed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Set SSE-KMS encryption and re-encrypt objects in OTC OBS buckets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single bucket
  python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK

  # Multiple buckets
  python3 obs-encrypt.py -b bucket1 -b bucket2 -b bucket3 -k KEY_ID --ak AK --sk SK

  # Dry run
  python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --dry-run

  # Policy only (skip re-encryption of existing objects)
  python3 obs-encrypt.py -b my-bucket -k KEY_ID --ak AK --sk SK --policy-only
""",
    )
    parser.add_argument(
        "--bucket", "-b", action="append", required=True,
        help="OBS bucket name (repeat for multiple buckets)",
    )
    parser.add_argument("--key-id", "-k", required=True, help="KMS key ID (UUID)")
    parser.add_argument("--ak", required=True, help="Access Key")
    parser.add_argument("--sk", required=True, help="Secret Key")
    parser.add_argument(
        "--endpoint", "-e", default="https://obs.eu-de.otc.t-systems.com",
        help="OBS endpoint (default: %(default)s)",
    )
    parser.add_argument("--region", default="eu-de", help="Region (default: %(default)s)")
    parser.add_argument("--prefix", default="", help="Only re-encrypt objects under this prefix")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--policy-only", action="store_true",
        help="Only set bucket encryption policy, skip re-encrypting existing objects",
    )
    parser.add_argument(
        "--concurrency", "-j", type=int, default=10,
        help="Max concurrent multipart copy threads (default: %(default)s)",
    )
    args = parser.parse_args()

    buckets = args.bucket
    action = "DRY RUN" if args.dry_run else ("policy only" if args.policy_only else "encrypt + re-encrypt")

    print("=" * 65)
    print(f"  OBS SSE-KMS Encryption — {action}")
    print("=" * 65)
    print(f"  Buckets:  {', '.join(buckets)}")
    print(f"  KMS Key:  {args.key_id}")
    print(f"  Endpoint: {args.endpoint}")
    if args.prefix:
        print(f"  Prefix:   {args.prefix}")
    print()

    overall_ok = True
    results = []

    for bucket in buckets:
        print(f"--- {bucket} ---")

        # Step 1: Set bucket encryption policy
        if args.dry_run:
            print(f"  [DRY RUN] Would set SSE-KMS policy (key: {args.key_id})")
            policy_ok = True
        else:
            print(f"  Setting SSE-KMS bucket policy...")
            policy_ok, msg = set_bucket_encryption(
                bucket, args.key_id, args.ak, args.sk, args.endpoint, args.region
            )
            if policy_ok:
                print(f"  [OK] Bucket policy set")
            else:
                print(f"  [FAIL] {msg}")
                overall_ok = False

        # Verify
        if not args.dry_run:
            enc = verify_bucket_encryption(
                bucket, args.ak, args.sk, args.endpoint, args.region
            )
            if enc:
                print(f"  [OK] Verified: algorithm={enc[0]}, key={enc[1]}")
            else:
                print(f"  [WARN] Could not verify encryption config")

        # Step 2: Re-encrypt existing objects
        if args.policy_only and not args.dry_run:
            print(f"  Skipping re-encryption (--policy-only)")
            results.append((bucket, policy_ok, "policy-only", 0, 0, 0, 0))
            print()
            continue

        print(f"  {'[DRY RUN] Listing' if args.dry_run else 'Re-encrypting'} objects...")
        ok, fail, nbytes, elapsed = reencrypt_bucket(
            bucket, args.key_id, args.ak, args.sk, args.endpoint, args.region,
            prefix=args.prefix, dry_run=args.dry_run, concurrency=args.concurrency,
        )

        if args.dry_run:
            print(f"  [DRY RUN] Would re-encrypt {ok} objects ({human_size(nbytes)})")
        else:
            rate = human_size(nbytes / elapsed) + "/s" if elapsed > 0 else "n/a"
            print(f"  [{'OK' if fail == 0 else 'WARN'}] {ok} succeeded, {fail} failed, "
                  f"{human_size(nbytes)} in {elapsed:.0f}s ({rate})")
            if fail > 0:
                overall_ok = False

        results.append((bucket, policy_ok, "ok" if fail == 0 else "fail", ok, fail, nbytes, elapsed))
        print()

    # Summary
    print("=" * 65)
    print("  Summary")
    print("=" * 65)
    total_ok = total_fail = total_bytes = total_time = 0
    for bucket, policy_ok, status, ok, fail, nbytes, elapsed in results:
        policy_str = "OK" if policy_ok else "FAIL"
        if args.dry_run:
            reencrypt_str = f"{ok} objects ({human_size(nbytes)})"
        elif args.policy_only:
            reencrypt_str = "skipped"
        else:
            reencrypt_str = f"{ok} ok / {fail} fail ({human_size(nbytes)})"
        print(f"  {bucket:30s}  policy={policy_str:4s}  objects={reencrypt_str}")
        total_ok += ok
        total_fail += fail
        total_bytes += nbytes
        total_time += elapsed

    if not args.dry_run and not args.policy_only:
        rate = human_size(total_bytes / total_time) + "/s" if total_time > 0 else "n/a"
        print(f"\n  Total: {total_ok} succeeded, {total_fail} failed, "
              f"{human_size(total_bytes)}, {total_time:.0f}s ({rate})")

    print()
    if overall_ok:
        print("  RESULT: OK")
    else:
        print("  RESULT: ERRORS — see details above")
        sys.exit(1)


if __name__ == "__main__":
    main()
