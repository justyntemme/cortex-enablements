# XQL queries

These are the copy/paste versions of the XQL queries embedded in this repository.
Replace values in angle brackets before running a parameterized query.

## Query 8: images with nested CVE object arrays

Source: `query_8_image_vulnerability_summary/main.py`

This is the preferred inventory/dashboard script. XQL reduces duplicate
package findings to one row per image/CVE and chooses the greatest CVSS score
seen for that CVE. The script then groups that single result set by image ID
and emits a deduplicated `cves` array of `{id, severity_score}` objects.

Nesting is deliberately performed after retrieval. The equivalent XQL
`values(object_create(...))` aggregation timed out even when bounded to one
image, while the deduplicating query below completes quickly. This is distinct
from Query 5: Query 5 returns raw detailed findings for one image; Query 8
returns minimal, deduplicated CVE rows for all images and produces the nested
fleet response. When the result exceeds the inline API's 1,000-row maximum,
the script follows the returned stream ID and reads the full result through
`get_query_results_stream`. The script caps `--limit` at the XQL API maximum
of 1,000,000 unique image/CVE rows and warns when that ceiling is reached.

```xql
config case_sensitive = false
| dataset = uvm_findings
| filter asset_category = "Container Image" and asset_type = "CORE_IMAGE"
| filter asset_id != null and asset_name != null and vulnerability_id != null
| comp max(cvss_score) as severity_score by asset_id, asset_name, vulnerability_id
| fields asset_id as id, asset_name as image_digest, vulnerability_id as cve_id, severity_score
```

The script's final JSON shape is:

```json
[
  {
    "id": "<CORTEX_IMAGE_ASSET_ID>",
    "image_digest": "sha256:<DIGEST>",
    "cve_count": 2,
    "max_severity_score": 9.8,
    "cves": [
      {"id": "CVE-2026-1234", "severity_score": 8.1},
      {"id": "CVE-2026-5678", "severity_score": 9.8}
    ]
  }
]
```

To bound Query 8 to one image, add this immediately after its second `filter`:

```xql
| filter asset_name = "<IMAGE_DIGEST>"
```

## Query 9: batched image vulnerability stream for ETL

Source: `query_9_batched_image_vulnerability_stream/main.py`

Query 9 independently implements Query 8's output contract while leaving Query
8 unchanged as the basic example. It divides the environment into 16 disjoint
hexadecimal `asset_id` ranges, runs three XQL queries concurrently by default,
and streams one complete image object per NDJSON line. Three workers leave one
of Cortex's four public-API XQL query slots available for console activity.
Before scheduling work, it checks the tenant's XQL quota and active-query
count; existing activity further reduces its worker count. Concurrency
rejections use bounded exponential backoff, and the final log reports the
extraction's quota usage delta. Streamed rows are folded directly into their
image objects rather than first retaining a second full list of result
dictionaries in memory.

Every shard uses the same absolute `from` and `to` timestamps. A shard reaching
the configured result ceiling is not emitted; it is split into another 16
prefixes and retried. This guarantees that an image is never divided between
shards because all CVEs for an image share the same `asset_id`.

```xql
config case_sensitive = false
| dataset = uvm_findings
| filter asset_category = "Container Image" and asset_type = "CORE_IMAGE"
| filter asset_id != null and asset_name != null and vulnerability_id != null
| filter asset_id ~= "^(<HEX_PREFIX_1>|<HEX_PREFIX_2>|...)"
| comp max(cvss_score) as severity_score by asset_id, asset_name, vulnerability_id
| fields asset_id as id, asset_name as image_digest, vulnerability_id as cve_id, severity_score
```

Default ETL execution:

```bash
python3 query_9_batched_image_vulnerability_stream/main.py > image-vulnerabilities.ndjson
```

The script writes progress and its fixed snapshot timestamps to standard error.
To retry one failed shard against the identical snapshot, reuse those timestamps:

```bash
python3 query_9_batched_image_vulnerability_stream/main.py \
  --prefix a \
  --from-ms <SNAPSHOT_FROM_MS> \
  --to-ms <SNAPSHOT_TO_MS>
```

## Query 1: all hosts

Source: `query_1_all_hosts/main.py`

```xql
dataset = host_inventory
| dedup host_name by desc _time
| fields host_name, agent_id, os_type, os_caption, ip_addresses, manufacturer, model, serial_number
| limit 1000
```

## Query 2: all Core and Runtime images

Source: `query_2_all_images/main.py`

```xql
config case_sensitive = false
| dataset = asset_inventory
| filter xdm.asset.type.class = "Compute"
| filter (xdm.asset.type.id = "CORE_IMAGE" or xdm.asset.type.id = "RUNTIME_IMAGE")
| fields xdm.asset.id as image_id, xdm.asset.name as image_name, xdm.asset.type.id as image_type_id, xdm.asset.type.name as image_type
| sort asc image_name
| limit 1000
```

## Query 3: CVEs for one host

Source: `query_3_cves_for_host/main.py`

```xql
dataset = va_endpoints
| filter endpoint_name = "<HOST_NAME>"
| filter cves != null
| arrayexpand cves
| fields endpoint_name, cves, severity, severity_score
| sort asc cves
| limit 1000
```

## Query 4: vulnerability rows for all hosts

Source: `query_4_vulnerabilities_by_host/main.py`

```xql
dataset = va_endpoints
| filter cves != null
| arrayexpand cves
| fields endpoint_name, cves, severity, severity_score
| sort asc endpoint_name
| limit 1000
```

## Query 5: vulnerability findings for one image

Source: `query_5_vulnerabilities_by_image/main.py`

```xql
dataset = uvm_findings
| filter asset_name = "<IMAGE_NAME_OR_DIGEST>" and vulnerability_id != null
| fields asset_name, vulnerability_id, cvss_score, cvss_severity, affected_software, package_version, package_type, os_distribution, file_path, first_observed, cve_publish_date, last_observed, fix_available, fix_versions, remediation, cortex_vulnerability_risk_score, exploitable, epss_score, cve_risk_factors, exploit_level
| sort asc vulnerability_id
| limit 1000
```

## Utility: list host names

Source: `utils/list_hostnames.py`

```xql
config case_sensitive = false
| dataset = va_endpoints
| filter endpoint_name != null
| fields endpoint_name
| limit 100
```

## Utility: candidate running-container assets

Source: `utils/list_running_containers.py`

The Python utility performs the provider-specific status, host, container ID,
and image ID normalization after this query returns the raw asset fields.

```xql
config case_sensitive = false
| dataset = asset_inventory
| filter xdm.asset.type.class = "Compute"
| filter xdm.asset.type.name contains "container"
| fields xdm.asset.id as asset_id, xdm.asset.name as asset_name, xdm.asset.type.name as asset_type, xdm.asset.raw_fields as raw_fields
| limit 1000
```

## API-only scripts

The following scripts do not contain XQL and therefore have no query block to
copy: `container_images_api`, `container_image_vulnerabilities_api`,
`vulnerability_affected_software_api`, `vulnerability_findings_api`, and
`vulnerability_intelligence_api`.
