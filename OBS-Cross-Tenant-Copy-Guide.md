# OBS Cross-Tenant Bucket Copy Guide

## Overview

This guide explains how to copy OBS bucket contents between two OTC (Open Telekom Cloud) tenants using **obsutil** — the official OBS command-line tool.

obsutil supports direct cross-tenant (cross-account) copy using the `-crr` parameter. Data flows server-side between buckets without being staged on local disk.

## Prerequisites

- A Linux or Windows VM with network access to OBS (see "ECS Sizing" below)
- AK/SK credentials for **both** tenants (source and destination)
- obsutil installed on the VM

## ECS Sizing

Transfer speed is determined by the **network bandwidth of the ECS** running obsutil. OBS itself has no bandwidth limit to configure or pay for. Choose an ECS flavor based on the data volume:

| Data Volume | Recommended ECS | Bandwidth | Estimated Time |
|-------------|----------------|-----------|----------------|
| < 100 GB | Any ECS | 1 Gbps | Minutes |
| 100 GB - 1 TB | 4 vCPU / 8 GB | 3-5 Gbps | 10-30 min |
| 1 TB - 10 TB | 8+ vCPU / 16 GB | 10+ Gbps | 1-3 hours |
| 10 TB+ | 16+ vCPU / 32 GB or multiple VMs | 10+ Gbps | Hours-days |

Key points:
- **Same region**: Always run the ECS in the **same region** as both buckets. Cross-region adds latency and may incur egress costs.
- **No OBS-side bandwidth setting**: The bottleneck is always the ECS NIC, not OBS.
- **Multiple VMs**: For very large transfers (tens of TB), run multiple obsutil instances on separate VMs, each copying a subset of objects, to multiply throughput.
- **Temporary VM**: The ECS is only needed during the transfer — create it, run the copy, tear it down.

## 1. Install obsutil

Download the appropriate binary from the [official download page](https://support.huaweicloud.com/intl/en-us/utiltg-obs/obs_11_0003.html). No installation required — just extract and run.

**Linux:**
```bash
curl -sLO "https://obs-community.obs.cn-north-1.myhuaweicloud.com/obsutil/current/obsutil_linux_amd64.tar.gz"
tar xzf obsutil_linux_amd64.tar.gz
sudo cp obsutil_linux_amd64_*/obsutil /usr/local/bin/
sudo chmod +x /usr/local/bin/obsutil
obsutil version
```

**Windows:**

Download `obsutil_windows_amd64.zip` from the link above, extract it, and run `obsutil.exe` from Command Prompt or PowerShell. All commands are identical.

## 2. Configure Credentials

Configure **destination** tenant as the default credentials:

```bash
obsutil config \
  -i=<DEST_AK> \
  -k=<DEST_SK> \
  -e=https://obs.eu-de.otc.t-systems.com
```

Configure **source** tenant using the `-crr` flag:

```bash
obsutil config \
  -i=<SOURCE_AK> \
  -k=<SOURCE_SK> \
  -e=https://obs.eu-de.otc.t-systems.com \
  -crr
```

This stores two credential sets in `~/.obsutilconfig`:
- Default (`ak`/`sk`/`endpoint`) — used for the **destination**
- CRR (`akCrr`/`skCrr`/`endpointCrr`) — used for the **source**

## 3. Copy a Single File

```bash
obsutil cp obs://source-bucket/path/to/file.dat obs://dest-bucket/path/to/file.dat -f -crr
```

## 4. Copy an Entire Bucket

```bash
obsutil cp obs://source-bucket/ obs://dest-bucket/ -r -f -crr
```

For large transfers, increase parallelism:

```bash
obsutil cp obs://source-bucket/ obs://dest-bucket/ -r -f -crr -p=10 -j=10
```

Flags:
- `-crr` — use cross-account replication (source credentials from CRR config)
- `-r` — recursive (copy all objects and subdirectories)
- `-f` — force (do not prompt for confirmation)
- `-p=N` — parallel threads per file (default 5). Each large file is split into N parts transferred simultaneously.
- `-j=N` — concurrent files (default 5). Number of files being transferred at the same time.

With defaults (`-p=5 -j=5`), up to 25 concurrent streams. With `-p=10 -j=10`, up to 100 concurrent streams. Increase these values to saturate higher-bandwidth ECS instances.

## 5. Verify

```bash
# Check object count and size on source (using CRR credentials)
obsutil ls obs://source-bucket/ -s \
  -i=<SOURCE_AK> \
  -k=<SOURCE_SK> \
  -e=https://obs.eu-de.otc.t-systems.com

# Check object count and size on destination (default credentials)
obsutil ls obs://dest-bucket/ -s
```

## Limitations

### Standard Metadata Not Copied
When using `-crr`, the following standard metadata is **not** transferred to destination objects:
- Cache-Control
- Expires
- Content-Encoding
- Content-Disposition
- Content-Type
- Content-Language

Content-Type may need to be set manually on the destination if it matters for your use case.

### Object ACLs Not Copied
Source object ACLs are not replicated. All copied objects inherit the destination bucket's default ACL. You can specify an ACL per copy with `-acl=xxx` (e.g., `-acl=public-read`).

### Bucket-Level Configuration Not Copied
obsutil copies object data only. The following must be reconfigured manually on the destination bucket:
- Bucket policies and ACLs
- Lifecycle rules
- CORS configuration
- Versioning settings
- Logging configuration

### No Native Server-Side Cross-Tenant Replication
OBS's built-in cross-region replication feature only works within the **same account**. The `-crr` flag in obsutil is a client-side workaround — data flows through the VM running obsutil, not directly between OBS servers.

### Cross-Region Transfer
To copy between regions (e.g., `eu-de` to `eu-nl`), configure different endpoints for source (`-crr`) and destination (default). Data still passes through the VM.

### Large File Handling
- Files over 50 MB are automatically split into multipart uploads
- obsutil supports checkpoint-based resumable transfers — if interrupted, re-running the same command resumes from the last checkpoint

### Performance

Tested from an ECS in eu-de (same region as both buckets):

| Test | Size | Flags | Throughput | Time |
|------|------|-------|------------|------|
| Single file (`-crr`) | 1 GB | defaults | ~577 MB/s | ~2s |
| Single file (two-step) | 1 GB | download+upload | ~350 MB/s | ~7s |
| Full bucket (`-crr`) | 25 GB (5x5GB) | `-p=10 -j=10` | **~934 MB/s** | **27.6s** |

The `-crr` method is faster and requires no local disk space. Higher `-p`/`-j` values and a larger ECS directly improve throughput.

**Projected transfer times at ~900 MB/s:**
| Data Volume | Time |
|-------------|------|
| 100 GB | ~2 min |
| 1 TB | ~19 min |
| 10 TB | ~3.1 hours |

For large-scale migrations (thousands of objects, terabytes of data), consider using **OMS** (Object Migration Service) in the OTC console, or the RDA OMS plugin for managed, parallel transfers.

## Reference

- [Using obsutil to Replicate Data Across Regions on the Client Side (Huawei Cloud)](https://support.huaweicloud.com/intl/en-us/utiltg-obs/obs_11_0039.html)
