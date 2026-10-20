# XQL queries

These are the copy/paste versions of the XQL queries embedded in this repository.
Replace values in angle brackets before running a parameterized query.

## Query 8: images with nested CVE object arrays

Source: `query_8_image_vulnerability_summary/main.py`

This is the simple, single-query counterpart to Query 9. It projects raw
package observations and groups them locally into the same image → CVE →
`package_findings` structure. Every package retains its own score, description,
risk, fix, and `cve_vendor_link` fields; there is no maximum-score CVE pivot.
The latest observation of each package/advisory relationship wins, using
`last_observed`, then `_time`, then `insert_time`. Exact repeats collapse;
conflicting observations with equal timestamps remain distinct, as in Query 9.

Query 8 retrieves one result set, follows a returned result-stream ID when
needed, holds the results in memory, and prints a JSON array. It does not
batch or manage quotas like Query 9. `--limit` counts raw package observations,
not unique CVEs, and is capped at 1,000,000. Reaching it prints a warning:
the output may omit images, CVEs, or package findings. Wider raw rows also
increase transfer and memory requirements; use Query 9 for large ETL exports.

```xql
config case_sensitive = false
| dataset = uvm_findings
| filter asset_category = "Container Image" and asset_type = "CORE_IMAGE"
| filter asset_id != null and asset_name != null and vulnerability_id != null
| fields asset_id as id, asset_name as image_digest, vulnerability_id as cve_id,
         package_purl, affected_software, package_version, package_type,
         os_distribution, file_path, layer_id, finding_sources, cve_vendor_link,
         cve_description, cvss_score, cvss_severity, fix_available, fix_versions,
         remediation, cortex_vulnerability_risk_score, exploitable, epss_score,
         first_observed, last_observed, _time, insert_time
```

The script's final JSON shape is (package fields abbreviated):

```json
[
  {
    "id": "<CORTEX_IMAGE_ASSET_ID>",
    "image_digest": "sha256:<DIGEST>",
    "cve_count": 1,
    "package_finding_count": 2,
    "max_severity_score": 9.1,
    "cves": [
      {
        "cve_id": "CVE-2026-1234",
        "package_findings": [
          {"affected_software": "openssl", "cvss_score": 7.5, "cve_vendor_link": "https://example.test/advisory"},
          {"affected_software": "example", "cvss_score": 9.1, "cve_vendor_link": null}
        ]
      }
    ]
  }
]
```

This replaces the old `cves[].id` and `cves[].severity_score` contract with
`cves[].cve_id` and `cves[].package_findings[].cvss_score`. Missing fields stay
null. `max_severity_score` remains an image-level summary only.

To bound Query 8 to one image, pass `--image-digest sha256:<DIGEST>` to the
script, or add this immediately after the second XQL `filter`:

```xql
| filter asset_name = "<IMAGE_DIGEST>"
```

## Query 9: batched image vulnerability stream for ETL

Source: `query_9_batched_image_vulnerability_stream/main.py`

Query 9 preserves package/CVE relationships and their actual `cvss_score` in
`cves[].package_findings[]`, matching Query 8's basic output structure.
It divides the environment into 16 disjoint
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
| fields asset_id as id, asset_name as image_digest, vulnerability_id as cve_id,
         package_purl, affected_software, package_version, package_type,
         os_distribution, file_path, layer_id, finding_sources, cve_vendor_link,
         cve_description, cvss_score, cvss_severity, fix_available, fix_versions,
         remediation, cortex_vulnerability_risk_score, exploitable, epss_score,
         first_observed, last_observed, _time, insert_time
```

Python keeps the latest observation per image/CVE/package/source relationship,
using `last_observed`, then `_time`, then `insert_time`. Equal-time conflicts
remain distinct; exact repeats collapse. It never chooses a relationship score
using `max()`. The existing root `max_severity_score` is only an image summary.
The per-shard limit defaults to 100,000 raw observations because these records
are wider than the previous CVE-only rows. See Query 9's README for full identity,
output-contract, and scalability details.

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

## Query 10: all running containers for one image ID

Source: `query_10_running_containers_by_image/main.py`

Query 10 accepts the Cortex image asset ID emitted in the `id` field by Queries
8 and 9. It first resolves that one asset to its normalized config identifier,
then puts the identifier into an early filter on XDR container telemetry. This
two-stage keyed lookup avoids a broad join over a large `xdr_data` collection.
The telemetry query keeps the newest event for each `(agent_id, container_id)`
pair and then filters the real container state. Runtime state is read from the
case-sensitive JSON path `actor_container_info.other.state`, with `State` as a
provider-case fallback; it is not inferred from the asset's `last_observed`
timestamp.

First resolve the Cortex image asset ID:

```xql
config case_sensitive = false
| dataset = asset_inventory
| filter xdm.asset.id = "<CORTEX_IMAGE_ASSET_ID>"
| fields xdm.asset.id as image_asset_id,
         xdm.asset.type.id as image_asset_type,
         xdm.image.identifier as image_identifier,
         xdm.asset.name as image_asset_name,
         xdm.asset.strong_id as image_strong_id
| limit 2
```

Then replace `<IMAGE_CONFIG_DIGEST>` below with the returned
`image_identifier`:

```xql
config case_sensitive = false
| dataset = xdr_data
| filter actor_container_info != null
| filter actor_container_info -> image_id contains "<IMAGE_CONFIG_DIGEST>"
| alter container_id = actor_container_info -> id,
        container_name = actor_container_info -> name,
        container_image_id = actor_container_info -> image_id,
        container_image_name = actor_container_info -> image_name,
        pod_name = actor_container_info -> pod_name,
        pod_namespace = actor_container_info -> pod_namespace,
        pod_uid = actor_container_info -> pod_uid,
        privileged = actor_container_info -> privileged,
        container_other = actor_container_info -> other
| alter container_state = uppercase(coalesce(json_extract_scalar(container_other, "$.state"), json_extract_scalar(container_other, "$.State"))),
        container_image_identifier = lowercase(arrayindex(regextract(container_image_id, "(sha256:[0-9a-f]{64})"), 0)),
        pod_ip = json_extract_scalar(container_other, "$.pod_ip")
| filter container_image_identifier != null and container_id != null
| filter container_image_identifier = "<IMAGE_CONFIG_DIGEST>"
| fields _time, agent_id, agent_hostname, container_id, container_name, container_state, container_image_id, container_image_name, pod_name, pod_namespace, pod_uid, pod_ip, privileged
| dedup agent_id, container_id by desc _time
| filter container_state in ("CONTAINER_RUNNING", "RUNNING")
| fields _time as state_observed_at, agent_id, agent_hostname, container_id, container_name, container_state as state, container_image_id as image_id, container_image_name as image_name, pod_name, pod_namespace, pod_uid, pod_ip, privileged
```

Run it with:

```bash
python3 query_10_running_containers_by_image/main.py \
  --image-id <CORTEX_IMAGE_ASSET_ID>
```

The script also accepts `sha256:<CONFIG_DIGEST>` and skips the asset-resolution
query. The default telemetry window is 24 hours; adjust `--relative-time-ms`
when a quiet workload requires a wider window. Only containers represented in
`xdr_data` during that window can be returned.

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
