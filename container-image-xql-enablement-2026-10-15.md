# Container image vulnerability XQL queries

The three queries below cover the **previous complete UTC day**. The window advances automatically at 00:00 UTC each day:

- Start, inclusive: yesterday at 00:00 UTC.
- End, exclusive: today at 00:00 UTC (the start of today, already passed).
- Example: any run on October 15 UTC selects October 14 00:00 UTC through, but not including, October 15 00:00 UTC.

Run all three queries on the same UTC date for matching boundaries. Late-arriving records or source updates can still change results inside that window; the time boundaries do not freeze the dataset.

`timeframe = 2d` supplies enough source history to include all of yesterday regardless of the execution hour. The early `_time` filter narrows it to exactly the previous UTC day before projection and aggregation. Do not reduce the outer timeframe to `1d`: that would exclude part of yesterday when running after midnight. The two-day search scope may affect scan cost; the retained records cover only one day.

The boundary uses documented [date_floor](https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Runtime-Security-Documentation/date_floor?contentId=dmysIWxWrcjXcCBLN5GoWg), [to_epoch](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/to_epoch), and [to_timestamp](https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Runtime-Security-Documentation/to_timestamp) functions with explicit UTC and seconds. The modified queries have not been executed against the tenant.

## 1. Flat findings without file path

One row per distinct image/CVE/package/rating combination. This is the flat version that exceeded one million results in the user's 24-hour run. It retains every distinct rating in the window; max(last_observed) does not select only the newest rating.

```xql
config case_sensitive = true timeframe = 2d
| dataset = uvm_findings
| alter comparison_end = date_floor(current_time(), "d", "+00:00")
| alter comparison_start = to_timestamp(subtract(to_epoch(comparison_end, "SECONDS"), 86400), "SECONDS")
| filter _time >= comparison_start and _time < comparison_end
| filter asset_category = "Container Image"
    and asset_type = "CORE_IMAGE"
| filter asset_id != null
    and asset_name != null
    and vulnerability_id != null
| fields asset_id,
         asset_name,
         vulnerability_id,
         cvss_severity,
         cve_vendor_link,
         cvss_score,
         package_purl,
         affected_software,
         package_version,
         package_type,
         os_distribution,
         last_observed
| comp count() as observation_count,
       max(last_observed) as last_observed
  by asset_id,
     asset_name,
     vulnerability_id,
     cvss_severity,
     cve_vendor_link,
     cvss_score,
     package_purl,
     affected_software,
     package_version,
     package_type,
     os_distribution
```

## 2. Cross-tab pivot: severity counts per image

A severity summary, not a detailed vulnerability export. It omits CVE lists, scores, URLs, and packages. A CVE with multiple severities can contribute to multiple columns, so the columns need not sum to cve_count. The other_or_unknown_cves column counts distinct CVE/severity combinations outside the four named severities; multiple unrecognized labels for one CVE can contribute more than once.

```xql
config case_sensitive = true timeframe = 2d
| dataset = uvm_findings
| alter comparison_end = date_floor(current_time(), "d", "+00:00")
| alter comparison_start = to_timestamp(subtract(to_epoch(comparison_end, "SECONDS"), 86400), "SECONDS")
| filter _time >= comparison_start and _time < comparison_end
| filter asset_category = "Container Image"
    and asset_type = "CORE_IMAGE"
| filter asset_id != null
    and asset_name != null
    and vulnerability_id != null
| fields asset_id, asset_name, vulnerability_id, cvss_severity
| alter severity = uppercase(coalesce(cvss_severity, "UNKNOWN"))
| comp count() as observation_count
  by asset_id, asset_name, vulnerability_id, severity
| alter critical_flag = if(severity = "CRITICAL", 1, 0),
        high_flag = if(severity = "HIGH", 1, 0),
        medium_flag = if(severity = "MEDIUM", 1, 0),
        low_flag = if(severity = "LOW", 1, 0),
        other_flag = if(severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), 1, 0)
| comp count_distinct(vulnerability_id) as cve_count,
       sum(critical_flag) as critical_cves,
       sum(high_flag) as high_cves,
       sum(medium_flag) as medium_cves,
       sum(low_flag) as low_cves,
       sum(other_flag) as other_or_unknown_cves
  by asset_id, asset_name
```

## 3. Nested findings: package details, one row per image group

The package-level nested query. It preserves the finding dimensions from query 1 and collects them into findings. Each object keeps its CVE, score, severity, vendor link, and package information together. Finding counts can exceed CVE counts. This is nested aggregation, rather than a cross-tab of severity columns.

```xql
config case_sensitive = true timeframe = 2d
| dataset = uvm_findings
| alter comparison_end = date_floor(current_time(), "d", "+00:00")
| alter comparison_start = to_timestamp(subtract(to_epoch(comparison_end, "SECONDS"), 86400), "SECONDS")
| filter _time >= comparison_start and _time < comparison_end
| filter asset_category = "Container Image"
    and asset_type = "CORE_IMAGE"
| filter asset_id != null
    and asset_name != null
    and vulnerability_id != null
| fields asset_id,
         asset_name,
         vulnerability_id,
         cvss_severity,
         cve_vendor_link,
         cvss_score,
         package_purl,
         affected_software,
         package_version,
         package_type,
         os_distribution,
         last_observed
| comp count() as observation_count,
       max(last_observed) as last_observed
  by asset_id,
     asset_name,
     vulnerability_id,
     cvss_severity,
     cve_vendor_link,
     cvss_score,
     package_purl,
     affected_software,
     package_version,
     package_type,
     os_distribution
| alter finding = object_create(
    "cve_id", vulnerability_id,
    "cvss_severity", cvss_severity,
    "cve_vendor_link", cve_vendor_link,
    "cvss_score", cvss_score,
    "package_purl", package_purl,
    "affected_software", affected_software,
    "package_version", package_version,
    "package_type", package_type,
    "os_distribution", os_distribution,
    "observation_count", observation_count,
    "last_observed", last_observed
  )
| comp values(finding) as findings,
       count() as finding_count,
       count_distinct(vulnerability_id) as cve_count,
       max(cvss_score) as max_severity_score,
       sum(observation_count) as observation_count
  by asset_id, asset_name
| alter returned_finding_count = array_length(findings)
```

## 4. Kubernetes Pod Groups and Containers by Image Name

```
dataset = asset_inventory
| filter xdm.asset.type.name = "Kubernetes Pod Group"
| alter relations = json_extract_array(
    xdm.asset.normalized_fields,
    "$['xdm.asset.relations']"
  )
| arrayexpand relations
| alter rel_type = json_extract_scalar(
    relations, "$['xdm.asset.relation.type']"
  ),
  rel_asset_id = json_extract_scalar(
    relations, "$['xdm.asset.relation.asset_id']"
  ),
  container_name = json_extract_scalar(
    relations,
    "$['xdm.asset.relation.metadata']['xdm.asset.relation.metadata.container_name']"
  )
| filter rel_type = "RUNS"
| fields xdm.asset.id as pod_group_id,
         xdm.asset.name as pod_group_name,
         container_name,
         rel_asset_id
| join type = inner (
    dataset = asset_inventory
    | filter xdm.asset.type.id = "RUNTIME_IMAGE"
    | filter xdm.asset.name = "imageName:imageVersion"
    | fields xdm.asset.id as image_id,
             xdm.asset.name as image_name
  ) as images rel_asset_id = images.image_id
| fields pod_group_id, pod_group_name, container_name,
         images.image_id as image_id,
         images.image_name as image_name
```
