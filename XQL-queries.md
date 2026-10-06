# XQL queries

These are the copy/paste versions of the XQL queries embedded in this repository.
Replace values in angle brackets before running a parameterized query.

## Query 8: images with nested CVE object arrays

Source: `query_8_image_vulnerability_summary/main.py`

This is the preferred inventory/dashboard query. Its first aggregation reduces
duplicate package findings to one row per image/CVE and chooses the greatest
CVSS score seen for that CVE. Its second aggregation creates one image object
with a deduplicated `cves` array. This avoids duplicating Query 5's flat
single-image retrieval.

```xql
config case_sensitive = false
| dataset = uvm_findings
| filter asset_category = "Container Image" and asset_type = "CORE_IMAGE"
| filter asset_id != null and asset_name != null and vulnerability_id != null
| comp max(cvss_score) as severity_score by asset_id, asset_name, vulnerability_id
| comp count() as cve_count,
       max(severity_score) as max_severity_score,
       values(object_create("id", vulnerability_id, "severity_score", severity_score)) as cves
  by asset_id, asset_name
| fields asset_id as id, asset_name as image_digest, cve_count, max_severity_score, cves
| sort desc cve_count
```

To bound Query 8 to one image, add this immediately after its second `filter`:

```xql
| filter asset_name = "<IMAGE_DIGEST>"
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

## Query 6: vulnerability findings for one container image

Source: `query_6_vulnerabilities_by_container/main.py`

Query 6 currently uses the same `uvm_findings` lookup as Query 5; its parameter
name is container-oriented, but the filter value must still be the image name
or digest stored in `asset_name`.

```xql
dataset = uvm_findings
| filter asset_name = "<CONTAINER_IMAGE_NAME_OR_DIGEST>" and vulnerability_id != null
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
