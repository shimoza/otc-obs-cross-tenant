#!/usr/bin/env python3
"""
obs-reencrypt.py — Re-encrypt all objects in an OTC OBS bucket with a KMS key

Performs a server-side copy-to-self on every object in the bucket, applying
SSE-KMS encryption with the specified key. Objects >5GB are handled
automatically via multipart copy.

This does NOT download/re-upload data — the copy happens entirely server-side
within OBS, so it's fast and uses no local disk or bandwidth.

Prerequisites:
    pip3 install boto3

Usage:
    python3 obs-reencrypt.py --bucket BUCKET --key-id KMS_KEY_ID --ak AK --sk SK
    python3 obs-reencrypt.py --bucket BUCKET --key-id KMS_KEY_ID --ak AK --sk SK --dry-run
    python3 obs-reencrypt.py --bucket BUCKET --key-id KMS_KEY_ID --ak AK --sk SK --prefix some/path/

Examples:
    # Re-encrypt all objects in a bucket
    python3 obs-reencrypt.py \\
        --bucket my-data-bucket \\
        --key-id 12345678-abcd-1234-efgh-123456789012 \\
        --ak MYACCESSKEY --sk MYSECRETKEY

    # Dry run (list what would be re-encrypted, don't change anything)
    python3 obs-reencrypt.py \\
        --bucket my-data-bucket \\
        --key-id 12345678-abcd-1234-efgh-123456789012 \\
        --ak MYACCESSKEY --sk MYSECRETKEY --dry-run

    # Re-encrypt only objects under a prefix
    python3 obs-reencrypt.py \\
        --bucket my-data-bucket \\
        --key-id 12345678-abcd-1234-efgh-123456789012 \\
        --ak MYACCESSKEY --sk MYSECRETKEY --prefix data/2025/
"""

import argparse
import sys
import time

import boto3
import boto3.s3.transfer
from botocore.config import Config


def human_size(size_bytes):
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def main():
    parser = argparse.ArgumentParser(
        description="Re-encrypt all objects in an OTC OBS bucket with SSE-KMS"
    )
    parser.add_argument("--bucket", "-b", required=True, help="OBS bucket name")
    parser.add_argument("--key-id", "-k", required=True, help="KMS key ID (UUID)")
    parser.add_argument("--ak", required=True, help="Access Key")
    parser.add_argument("--sk", required=True, help="Secret Key")
    parser.add_argument(
        "--endpoint",
        "-e",
        default="https://obs.eu-de.otc.t-systems.com",
        help="OBS endpoint (default: %(default)s)",
    )
    parser.add_argument(
        "--region", default="eu-de", help="Region (default: %(default)s)"
    )
    parser.add_argument(
        "--prefix", "-p", default="", help="Only re-encrypt objects under this prefix"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List objects that would be re-encrypted without changing anything",
    )
    parser.add_argument(
        "--concurrency",
        "-j",
        type=int,
        default=10,
        help="Max concurrent multipart copy threads (default: %(default)s)",
    )
    args = parser.parse_args()

    # Connect to OBS
    s3 = boto3.client(
        "s3",
        aws_access_key_id=args.ak,
        aws_secret_access_key=args.sk,
        endpoint_url=args.endpoint,
        region_name=args.region,
        config=Config(
            s3={"addressing_style": "virtual"},
            max_pool_connections=50,
        ),
    )

    # List all objects
    print(f"Listing objects in obs://{args.bucket}/{args.prefix}...")
    objects = []
    paginate_args = {"Bucket": args.bucket}
    if args.prefix:
        paginate_args["Prefix"] = args.prefix

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(**paginate_args):
        for obj in page.get("Contents", []):
            objects.append(obj)

    if not objects:
        print("No objects found.")
        return

    total_bytes = sum(o["Size"] for o in objects)
    big_count = sum(1 for o in objects if o["Size"] > 5 * 1024**3)
    print(
        f"Found {len(objects)} objects ({human_size(total_bytes)})"
        + (f", {big_count} over 5GB (multipart)" if big_count else "")
    )
    print(f"KMS key: {args.key_id}")
    print()

    if args.dry_run:
        print("DRY RUN — no changes will be made:\n")
        for i, obj in enumerate(objects):
            print(f"  {obj['Key']:60s} {human_size(obj['Size']):>10s}")
            if i >= 49 and len(objects) > 50:
                print(f"  ... and {len(objects) - 50} more")
                break
        print(f"\nTotal: {len(objects)} objects, {human_size(total_bytes)}")
        return

    # Re-encrypt
    multipart_threshold = 5 * 1024**3  # 5GB
    transfer_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=multipart_threshold,
        multipart_chunksize=512 * 1024**2,  # 512MB parts
        max_concurrency=args.concurrency,
    )

    succeeded = 0
    failed = 0
    failed_keys = []
    start_time = time.time()
    bytes_done = 0

    for i, obj in enumerate(objects):
        key = obj["Key"]
        size = obj["Size"]

        # Progress indicator
        is_big = size > 1024**3
        show_progress = (i == 0) or ((i + 1) % 100 == 0) or is_big or (i + 1 == len(objects))
        if show_progress:
            elapsed = time.time() - start_time
            pct = (i / len(objects)) * 100
            rate = f", {human_size(bytes_done / elapsed)}/s" if elapsed > 1 else ""
            print(
                f"  [{i+1}/{len(objects)} {pct:.0f}%] {key} ({human_size(size)})"
                + (" [multipart]" if size > multipart_threshold else "")
                + rate,
                flush=True,
            )

        try:
            extra_args = {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": args.key_id,
                "MetadataDirective": "COPY",
            }

            if size > multipart_threshold:
                s3.copy(
                    CopySource={"Bucket": args.bucket, "Key": key},
                    Bucket=args.bucket,
                    Key=key,
                    ExtraArgs=extra_args,
                    Config=transfer_config,
                )
            else:
                s3.copy_object(
                    Bucket=args.bucket,
                    Key=key,
                    CopySource=f"{args.bucket}/{key}",
                    **extra_args,
                )
            succeeded += 1
            bytes_done += size

        except Exception as e:
            failed += 1
            failed_keys.append(key)
            print(f"  FAILED: {key} — {e}", file=sys.stderr)

    # Summary
    elapsed = time.time() - start_time
    rate = human_size(bytes_done / elapsed) + "/s" if elapsed > 0 else "n/a"

    print()
    print("=" * 60)
    print(f"  Bucket:    {args.bucket}")
    print(f"  KMS key:   {args.key_id}")
    print(f"  Succeeded: {succeeded}")
    print(f"  Failed:    {failed}")
    print(f"  Data:      {human_size(bytes_done)}")
    print(f"  Time:      {elapsed:.0f}s")
    print(f"  Rate:      {rate}")
    print("=" * 60)

    if failed_keys:
        print(f"\nFailed objects ({failed}):")
        for k in failed_keys:
            print(f"  {k}")
        sys.exit(1)


if __name__ == "__main__":
    main()
