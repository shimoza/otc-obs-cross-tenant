# OTC Credentials — Example

## Source Tenant

- **Domain**: `OTC00000000001000010XXX`
- **Region**: `eu-de`
- **Project ID**: `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- **AK**: `XXXXXXXXXXXXXXXXXXXX`
- **SK**: `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

## Destination Tenant

- **Domain**: `OTC00000000001000010YYY`
- **Region**: `eu-de`
- **Project ID**: `yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy`
- **AK**: `YYYYYYYYYYYYYYYYYYYY`
- **SK**: `yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy`

## OBS Endpoint

- `https://obs.eu-de.otc.t-systems.com`

## Quick Setup — obsutil CRR

```bash
# Configure DESTINATION as default
obsutil config \
  -i=YYYYYYYYYYYYYYYYYYYY \
  -k=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy \
  -e=https://obs.eu-de.otc.t-systems.com

# Configure SOURCE as CRR
obsutil config \
  -i=XXXXXXXXXXXXXXXXXXXX \
  -k=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -e=https://obs.eu-de.otc.t-systems.com \
  -crr
```
