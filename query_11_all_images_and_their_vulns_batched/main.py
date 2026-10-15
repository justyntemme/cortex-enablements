#!/usr/bin/env python3
"""All images and their vulns-batched: XQL nested findings in image-ID shards."""

from __future__ import annotations

import argparse
from collections import deque
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from decimal import Decimal, InvalidOperation
import gzip
import io
import json
import math
import os
import random
import re
import sys
import tempfile
import time
from typing import Any, TextIO
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


HEX_DIGITS = "0123456789abcdef"
MAX_CORTEX_RESULTS = 1_000_000
MAX_CORTEX_CONCURRENT_QUERIES = 4
Shard = tuple[str, ...]

DAY_MS = 86_400_000
NESTED_PIPELINE = '''| fields asset_id,
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
| alter returned_finding_count = array_length(findings)'''


class CortexApiError(RuntimeError):
    """An HTTP or API-level error returned by Cortex Cloud."""


class CortexXqlClient:
    """XQL client optimized for incremental result-stream consumption."""

    def __init__(self, base_url: str, api_key: str, api_key_id: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": api_key,
            "x-xdr-auth-id": api_key_id,
        }

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=self.headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CortexApiError(f"Cortex API returned HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise CortexApiError(f"Could not reach Cortex API: {exc.reason}") from exc

        try:
            result = json.loads(body)
        except json.JSONDecodeError as exc:
            raise CortexApiError("Cortex API returned non-JSON data") from exc
        if not isinstance(result, dict):
            raise CortexApiError("Cortex API returned an unexpected response")
        if "err_code" in result:
            raise CortexApiError(json.dumps(result))
        return result

    @staticmethod
    def _extract_rows(value: Any) -> list[dict[str, Any]] | None:
        if isinstance(value, list):
            if any(not isinstance(row, dict) for row in value):
                raise CortexApiError("Cortex result contained a non-object row")
            return value
        if not isinstance(value, dict):
            return None
        for key in ("data", "results", "reply"):
            if key in value:
                rows = CortexXqlClient._extract_rows(value[key])
                if rows is not None:
                    return rows
        return None

    @staticmethod
    def _find_stream_id(value: Any) -> str | None:
        if isinstance(value, dict):
            stream_id = value.get("stream_id")
            if isinstance(stream_id, str) and stream_id:
                return stream_id
            for child in value.values():
                stream_id = CortexXqlClient._find_stream_id(child)
                if stream_id:
                    return stream_id
        elif isinstance(value, list):
            for child in value:
                stream_id = CortexXqlClient._find_stream_id(child)
                if stream_id:
                    return stream_id
        return None

    def _consume_stream(
        self,
        stream_id: str,
        *,
        timeout: float,
        row_consumer: Callable[[dict[str, Any]], None],
    ) -> None:
        request = Request(
            f"{self.base_url}/public_api/v1/xql/get_query_results_stream",
            data=json.dumps(
                {
                    "request_data": {
                        "stream_id": stream_id,
                        "is_gzip_compressed": True,
                    }
                }
            ).encode("utf-8"),
            headers={**self.headers, "Accept-Encoding": "gzip"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=max(60, timeout)) as response:
                stream: io.BufferedReader = io.BufferedReader(response)
                # A tenant can return both gzip transfer encoding and a gzip
                # result file, so unwrap each gzip layer detected by magic.
                for _ in range(3):
                    if stream.peek(2)[:2] != b"\x1f\x8b":
                        break
                    stream = io.BufferedReader(gzip.GzipFile(fileobj=stream))

                for line_number, raw_line in enumerate(stream, start=1):
                    if not raw_line.strip():
                        continue
                    try:
                        item = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise CortexApiError(
                            f"Cortex result stream had invalid JSON on line {line_number}"
                        ) from exc
                    if isinstance(item, dict) and "err_code" in item:
                        raise CortexApiError(json.dumps(item))
                    rows = self._extract_rows(item)
                    if rows is None and isinstance(item, dict):
                        rows = [item]
                    if rows is None:
                        raise CortexApiError(
                            f"Cortex result stream line {line_number} had no data object"
                        )
                    for row in rows:
                        row_consumer(row)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CortexApiError(
                f"Cortex stream API returned HTTP {exc.code}: {detail}"
            ) from exc
        except (URLError, OSError) as exc:
            raise CortexApiError(f"Could not retrieve Cortex result stream: {exc}") from exc

    def get_quota(self) -> dict[str, Any]:
        """Return the tenant's current XQL quota and concurrency state."""
        result = self._post("/public_api/v1/xql/get_quota", {"request_data": {}})
        reply = result.get("reply")
        if not isinstance(reply, dict) or "err_code" in reply:
            raise CortexApiError(f"Unexpected XQL quota response: {result}")
        return reply

    def run(
        self,
        query: str,
        *,
        timeframe: dict[str, int],
        limit: int,
        tenant_id: str | None,
        timeout: float,
        poll_interval: float,
        row_consumer: Callable[[dict[str, Any]], None],
    ) -> None:
        started = self._post(
            "/public_api/v1/xql/start_xql_query",
            {
                "request_data": {
                    "query": query,
                    "tenants": [tenant_id] if tenant_id else [],
                    "timeframe": timeframe,
                }
            },
        )
        raw_reply = started.get("reply")
        if isinstance(raw_reply, str):
            query_id = raw_reply
        elif isinstance(raw_reply, dict):
            query_id = (
                raw_reply.get("query_id")
                or raw_reply.get("execution_id")
                or raw_reply.get("id")
            )
        else:
            query_id = None
        if not query_id:
            raise CortexApiError(f"Start XQL response did not contain a query ID: {started}")

        deadline = time.monotonic() + timeout
        while True:
            result = self._post(
                "/public_api/v1/xql/get_query_results",
                {
                    "request_data": {
                        "query_id": query_id,
                        "pending_flag": True,
                        "limit": limit,
                        "format": "json",
                    }
                },
            )
            reply = result.get("reply", result)
            if isinstance(reply, dict):
                status = str(reply.get("status", "")).upper()
                if status in {"FAIL", "FAILED", "ERROR", "CANCELLED", "CANCELED"}:
                    raise CortexApiError(f"XQL query failed: {json.dumps(result)}")
                if status in {"SUCCESS", "COMPLETED"} or (
                    status not in {"PENDING", "RUNNING", "IN_PROGRESS"}
                    and "results" in reply
                ):
                    stream_id = self._find_stream_id(reply)
                    if stream_id:
                        self._consume_stream(
                            stream_id,
                            timeout=max(1, deadline - time.monotonic()),
                            row_consumer=row_consumer,
                        )
                        return
                    rows = self._extract_rows(reply)
                    if rows is None:
                        raise CortexApiError(
                            f"XQL response contained neither rows nor a stream ID: {result}"
                        )
                    for row in rows:
                        row_consumer(row)
                    return
            if time.monotonic() >= deadline:
                raise CortexApiError(f"Timed out waiting for query {query_id}")
            time.sleep(poll_interval)


def shard_pattern(shard: Shard) -> str:
    """Disjoint hexadecimal prefixes plus a residual for unusual/short IDs."""
    if len(shard) == 1 and shard[0].startswith("!"):
        prefix = shard[0][1:]
        if prefix and not re.fullmatch(r"[0-9a-f]+", prefix):
            raise ValueError("Invalid residual shard")
        return f"^{prefix}($|[^0-9a-f])"
    if not shard or any(not re.fullmatch(r"[0-9a-f]+", value) for value in shard):
        raise ValueError("Shard prefixes must contain lowercase hexadecimal characters")
    pattern = shard[0] if len(shard) == 1 else f"({'|'.join(shard)})"
    return f"^{pattern}"


def build_query(shard: Shard, timeframe: dict[str, int]) -> str:
    """Run query 3's nested aggregation within one frozen image-ID shard."""
    start, end = timeframe["from"], timeframe["to"]
    if type(start) is not int or type(end) is not int or not 0 <= start < end:
        raise ValueError("Timeframe must contain ordered, nonnegative Unix milliseconds")
    pattern = shard_pattern(shard)
    return f'''config case_sensitive = true
| dataset = uvm_findings
| filter _time >= to_timestamp({start}, "MILLIS")
    and _time < to_timestamp({end}, "MILLIS")
| filter asset_category = "Container Image" and asset_type = "CORE_IMAGE"
| filter asset_id != null and asset_name != null and vulnerability_id != null
| filter lowercase(asset_id) ~= "{pattern}"
{NESTED_PIPELINE}'''


def count_value(value: Any, field: str) -> int:
    """Accept exact integer counts, including API numeric strings, without rounding."""
    error = (
        f"Missing or invalid count: {field} (type={type(value).__name__}; "
        "expected a finite nonnegative integer or numeric string)"
    )
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise CortexApiError(error)
    try:
        number = Decimal(value.strip()) if isinstance(value, str) else Decimal(value)
    except (InvalidOperation, ValueError):
        raise CortexApiError(error) from None
    if not number.is_finite() or number < 0 or number != number.to_integral_value():
        raise CortexApiError(error)
    return int(number)


def read_count(record: dict[str, Any], key: str, field: str | None = None) -> int:
    """Report schema information, not image identifiers or finding contents."""
    try:
        return count_value(record.get(key), field or key)
    except CortexApiError as exc:
        raise CortexApiError(
            f"{exc}; field_present={key in record}; returned_fields={sorted(record)}"
        ) from exc


def decode_container(value: Any, expected_type: type, field: str) -> Any:
    """Decode JSON at container boundaries only; never reinterpret scalar fields."""
    original_type = type(value).__name__
    for _ in range(3):
        if not isinstance(value, str):
            break
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise CortexApiError(
                f"Invalid JSON in {field} (received_type={original_type})"
            ) from None
    if not isinstance(value, expected_type):
        raise CortexApiError(
            f"Invalid {field}: expected {expected_type.__name__}, "
            f"received_type={original_type}, decoded_type={type(value).__name__}"
        )
    return value


def validate_image(row: dict[str, Any]) -> dict[str, Any]:
    """Validate downloaded arrays without collapsing packages or ratings."""
    row = dict(row)
    if not isinstance(row.get("asset_id"), str) or not isinstance(row.get("asset_name"), str):
        raise CortexApiError("Nested image row is missing its asset_id or asset_name")
    findings = decode_container(row.get("findings"), list, "findings")
    if not findings:
        raise CortexApiError("Nested image row has no findings array")
    for field in ("finding_count", "returned_finding_count", "cve_count", "observation_count"):
        row[field] = read_count(row, field)
    finding_count = row["finding_count"]
    returned_count = row["returned_finding_count"]
    if len(findings) != finding_count or returned_count != finding_count:
        raise CortexApiError(f"Finding count mismatch for image {row['asset_id']}")
    cves: set[str] = set()
    seen: set[str] = set()
    observations = 0
    normalized_findings = []
    for index, finding in enumerate(findings):
        # values(object_create(...)) can reach the client as an array of
        # serialized JSON objects, even when the outer array is already decoded.
        finding = dict(decode_container(finding, dict, f"findings[{index}]"))
        if not isinstance(finding.get("cve_id"), str):
            raise CortexApiError(
                f"Finding is missing its CVE ID at findings[{index}]; "
                f"field_present={'cve_id' in finding}; "
                f"cve_id_type={type(finding.get('cve_id')).__name__}; "
                f"returned_fields={sorted(finding)}"
            )
        count = read_count(finding, "observation_count", "finding.observation_count")
        if count == 0:
            raise CortexApiError("Finding observation_count must be positive")
        finding["observation_count"] = count
        normalized_findings.append(finding)
        cves.add(finding["cve_id"])
        key = json.dumps(finding, sort_keys=True, separators=(",", ":"))
        if key in seen:
            raise CortexApiError("Duplicate object in distinct findings array")
        seen.add(key)
        observations += count
    if len(cves) != row["cve_count"]:
        raise CortexApiError(f"CVE count mismatch for image {row['asset_id']}")
    if observations != row["observation_count"]:
        raise CortexApiError(f"Observation count mismatch for image {row['asset_id']}")
    row["findings"] = normalized_findings
    return row


class ShardResult:
    """Stage a shard on disk so capped or failed attempts never reach stdout."""

    def __init__(self) -> None:
        self.row_count = 0
        self.image_keys: set[tuple[str, str]] = set()
        self.spool = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")

    def add(self, row: dict[str, Any], shard: Shard, limit: int) -> None:
        self.row_count += 1
        if self.row_count >= limit:
            # This attempt will be discarded and split. Do not buffer more rows.
            return
        row = validate_image(row)
        if re.match(shard_pattern(shard), row["asset_id"].lower()) is None:
            raise CortexApiError("API returned an image outside the requested shard")
        key = (row["asset_id"], row["asset_name"])
        if key in self.image_keys:
            raise CortexApiError(f"Duplicate image group in shard: {key}")
        self.image_keys.add(key)
        self.spool.write(json.dumps(row, separators=(",", ":")) + "\n")

    def images(self):
        self.spool.seek(0)
        for line in self.spool:
            yield json.loads(line)

    def close(self) -> None:
        self.spool.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--batch-limit",
        type=int,
        default=100_000,
        help="Maximum nested image rows per shard before splitting (default: 100000)",
    )
    parser.add_argument(
        "--initial-shards",
        type=int,
        choices=(1, 2, 4, 8, 16),
        default=16,
        help="Initial balanced image-ID ranges (default: 16 for large tenants)",
    )
    parser.add_argument(
        "--max-shard-depth",
        type=int,
        default=4,
        help="Maximum recursive image-ID prefix length (default: 4)",
    )
    parser.add_argument(
        "--prefix",
        help="Run only one lowercase hexadecimal image-ID prefix (for retry/resume)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Parallel XQL queries; default 3 leaves one Cortex slot free",
    )
    parser.add_argument(
        "--reserve-slots",
        type=int,
        default=1,
        help="Cortex query slots reserved for console/other users (default: 1)",
    )
    parser.add_argument(
        "--format",
        choices=("ndjson", "json"),
        default="ndjson",
        help="Output format (default: ndjson for streaming ETL)",
    )
    parser.add_argument(
        "--relative-time-ms",
        type=int,
        default=DAY_MS,
        help="Snapshot lookback when --from-ms/--to-ms are omitted (default: last 24 hours)",
    )
    parser.add_argument(
        "--previous-utc-day", action="store_true",
        help="Use yesterday 00:00 UTC to today 00:00 UTC instead of a rolling lookback",
    )
    parser.add_argument(
        "--print-query", action="store_true",
        help="Print the XQL for --prefix (or all hex prefixes) without contacting Cortex",
    )
    parser.add_argument("--from-ms", type=int, help="Fixed snapshot start in Unix milliseconds")
    parser.add_argument("--to-ms", type=int, help="Fixed snapshot end in Unix milliseconds")
    parser.add_argument("--query-timeout", type=float, default=600)
    parser.add_argument(
        "--deadline-seconds",
        type=float,
        default=1800,
        help="Fail the extraction after this freshness deadline (default: 1800)",
    )
    parser.add_argument("--poll-interval", type=float, default=3)
    parser.add_argument("--max-retries", type=int, default=8)
    return parser.parse_args()


def initial_shards(count: int, explicit_prefix: str | None) -> list[Shard]:
    if explicit_prefix is not None:
        return [(explicit_prefix,)]
    chunk_size = len(HEX_DIGITS) // count
    return [
        tuple(HEX_DIGITS[index : index + chunk_size])
        for index in range(0, len(HEX_DIGITS), chunk_size)
    ] + [("!",)]


def shard_label(shard: Shard) -> str:
    if len(shard) == 1 and shard[0].startswith("!"):
        return "residual:" + (shard[0][1:] or "root")
    if len(shard) == 1:
        return shard[0]
    if all(len(prefix) == 1 for prefix in shard):
        return f"{shard[0]}-{shard[-1]}"
    return ",".join(shard)


def split_shard(shard: Shard, max_depth: int) -> list[Shard]:
    if len(shard) == 1 and shard[0].startswith("!"):
        raise CortexApiError("Residual shard reached the row ceiling; cannot safely split non-hex IDs")
    if len(shard) > 1:
        midpoint = len(shard) // 2
        return [shard[:midpoint], shard[midpoint:]]
    prefix = shard[0]
    if len(prefix) >= max_depth:
        raise CortexApiError(
            f"Shard {shard_label(shard)} reached the row ceiling at maximum depth"
        )
    return [(prefix + digit,) for digit in HEX_DIGITS] + [("!" + prefix,)]


def is_capacity_error(exc: CortexApiError) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "too many concurrent",
            "parallel running queries",
            "reached max allowed amount",
            "http 429",
        )
    )


def is_result_limit_error(exc: CortexApiError) -> bool:
    message = str(exc).lower()
    return "max number of results" in message or "maximum number of results" in message


def run_shard(
    client: CortexXqlClient,
    shard: Shard,
    *,
    timeframe: dict[str, int],
    limit: int,
    tenant_id: str | None,
    query_timeout: float,
    poll_interval: float,
    max_retries: int,
    deadline: float,
) -> ShardResult:
    label = shard_label(shard)
    for attempt in range(max_retries + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CortexApiError("Extraction freshness deadline expired")
        result = ShardResult()
        try:
            client.run(
                build_query(shard, timeframe),
                timeframe=timeframe,
                limit=limit,
                tenant_id=tenant_id,
                timeout=min(query_timeout, remaining),
                poll_interval=poll_interval,
                row_consumer=lambda row: result.add(row, shard, limit),
            )
            if result.row_count >= limit:
                result.close()
            return result
        except CortexApiError as exc:
            result.close()
            if is_result_limit_error(exc):
                result.row_count = limit
                return result
            if not is_capacity_error(exc) or attempt >= max_retries:
                raise CortexApiError(f"shard={label}: {exc}") from exc
            delay = min(30.0, (2**attempt) + random.random())
            if delay >= deadline - time.monotonic():
                raise CortexApiError("Extraction deadline expired during rate-limit backoff") from exc
            print(
                f"shard={label} capacity retry={attempt + 1} delay={delay:.1f}s",
                file=sys.stderr,
            )
            time.sleep(delay)
        except BaseException:
            result.close()
            raise
    raise CortexApiError(f"Shard {label} exhausted its retries")


class ObjectStreamWriter:
    def __init__(self, output: TextIO, output_format: str) -> None:
        self.output = output
        self.output_format = output_format
        self.first = True
        if output_format == "json":
            self.output.write("[\n")

    def write(self, value: dict[str, Any]) -> None:
        if self.output_format == "ndjson":
            self.output.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
            self.output.write("\n")
            return
        if not self.first:
            self.output.write(",\n")
        json.dump(value, self.output, indent=2, sort_keys=True, default=str)
        self.first = False

    def flush(self) -> None:
        self.output.flush()

    def close(self) -> None:
        if self.output_format == "json":
            self.output.write("\n]\n")
        self.output.flush()


def validate_args(args: argparse.Namespace) -> str | None:
    if not 0 < args.batch_limit <= MAX_CORTEX_RESULTS:
        return f"--batch-limit must be between 1 and {MAX_CORTEX_RESULTS}"
    if not 1 <= args.max_shard_depth <= 64:
        return "--max-shard-depth must be between 1 and 64"
    if not 1 <= args.workers <= MAX_CORTEX_CONCURRENT_QUERIES:
        return f"--workers must be between 1 and {MAX_CORTEX_CONCURRENT_QUERIES}"
    if not 0 <= args.reserve_slots < MAX_CORTEX_CONCURRENT_QUERIES:
        return f"--reserve-slots must be between 0 and {MAX_CORTEX_CONCURRENT_QUERIES - 1}"
    if args.prefix is not None and not re.fullmatch(r"[0-9a-f]{1,64}", args.prefix):
        return "--prefix must contain 1-64 lowercase hexadecimal characters"
    if (args.from_ms is None) != (args.to_ms is None):
        return "--from-ms and --to-ms must be supplied together"
    if args.from_ms is not None and args.from_ms >= args.to_ms:
        return "--from-ms must be less than --to-ms"
    if args.previous_utc_day and (args.from_ms is not None or args.relative_time_ms != DAY_MS):
        return "--previous-utc-day cannot be combined with explicit dates or a custom lookback"
    if args.from_ms is not None and args.from_ms < 0:
        return "--from-ms cannot be negative"
    if not all(math.isfinite(value) for value in (
        args.query_timeout, args.deadline_seconds, args.poll_interval,
    )):
        return "Timeout, deadline, and poll interval must be finite"
    if min(
        args.relative_time_ms,
        args.query_timeout,
        args.deadline_seconds,
        args.poll_interval,
    ) <= 0:
        return "Timeframe, timeout, deadline, and poll interval values must be positive"
    if args.max_retries < 0:
        return "--max-retries cannot be negative"
    return None


def quota_used(quota: dict[str, Any] | None) -> float | None:
    if quota is None:
        return None
    value = quota.get("used_quota")
    return float(value) if isinstance(value, (int, float)) else None


def choose_worker_count(
    client: CortexXqlClient,
    *,
    requested_workers: int,
    reserve_slots: int,
    deadline: float,
) -> tuple[int, dict[str, Any] | None]:
    """Wait for tenant capacity and preserve the requested console reserve."""
    while True:
        try:
            quota = client.get_quota()
        except CortexApiError as exc:
            fallback = min(
                requested_workers,
                MAX_CORTEX_CONCURRENT_QUERIES - reserve_slots,
            )
            print(
                f"Warning: quota preflight failed ({exc}); using workers={fallback}",
                file=sys.stderr,
            )
            return fallback, None

        active_value = quota.get("current_concurrent_active_queries_count", 0)
        active = int(active_value) if isinstance(active_value, (int, float)) else 0
        available = MAX_CORTEX_CONCURRENT_QUERIES - reserve_slots - active
        if available > 0:
            workers = min(requested_workers, available)
            print(
                f"quota used={quota.get('used_quota')} license={quota.get('license_quota')} "
                f"active={active} reserve={reserve_slots} workers={workers}",
                file=sys.stderr,
            )
            return workers, quota

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CortexApiError("Extraction deadline expired waiting for XQL capacity")
        delay = min(15.0, remaining)
        print(
            f"waiting_for_capacity active={active} reserve={reserve_slots} delay={delay:.1f}s",
            file=sys.stderr,
        )
        time.sleep(delay)


def snapshot_timeframe(args: argparse.Namespace) -> dict[str, int]:
    """Choose once; every shard and retry receives these absolute boundaries."""
    if args.from_ms is not None:
        return {"from": args.from_ms, "to": args.to_ms}
    end = int(time.time() * 1000)
    if args.previous_utc_day:
        end -= end % DAY_MS
        return {"from": end - DAY_MS, "to": end}
    return {"from": end - args.relative_time_ms, "to": end}


def main() -> int:
    args = parse_args()
    validation_error = validate_args(args)
    if validation_error:
        print(validation_error, file=sys.stderr)
        return 2
    timeframe = snapshot_timeframe(args)
    if args.print_query:
        print(build_query((args.prefix,) if args.prefix else tuple(HEX_DIGITS), timeframe))
        return 0

    base_url, api_key, api_key_id = (
        os.getenv(name)
        for name in ("CORTEX_API_URL", "CORTEX_API_KEY", "CORTEX_API_KEY_ID")
    )
    if not base_url or not api_key or not api_key_id:
        print("Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.", file=sys.stderr)
        return 2

    deadline = time.monotonic() + args.deadline_seconds
    tenant_id = os.getenv("CORTEX_TENANT_ID")
    client = CortexXqlClient(base_url, api_key, api_key_id)
    try:
        worker_count, quota_before = choose_worker_count(
            client, requested_workers=args.workers,
            reserve_slots=args.reserve_slots, deadline=deadline,
        )
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    shards = deque(initial_shards(args.initial_shards, args.prefix))
    writer = ObjectStreamWriter(sys.stdout, args.format)
    pending: dict[Future[ShardResult], tuple[Shard, float]] = {}
    image_count = cve_count = finding_count = observation_count = completed_shards = 0
    print(
        f"snapshot_from_ms={timeframe['from']} snapshot_to_ms={timeframe['to']} "
        f"workers={worker_count} initial_shards={len(shards)}",
        file=sys.stderr,
    )

    try:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            try:
                while shards or pending:
                    if time.monotonic() >= deadline:
                        raise CortexApiError("Extraction freshness deadline expired")
                    while shards and len(pending) < worker_count:
                        shard = shards.popleft()
                        submitted_at = time.monotonic()
                        future = executor.submit(
                            run_shard, client, shard, timeframe=timeframe,
                            limit=args.batch_limit, tenant_id=tenant_id,
                            query_timeout=args.query_timeout, poll_interval=args.poll_interval,
                            max_retries=args.max_retries, deadline=deadline,
                        )
                        pending[future] = (shard, submitted_at)
                    done, _ = wait(
                        pending, timeout=min(5.0, max(0.1, deadline - time.monotonic())),
                        return_when=FIRST_COMPLETED,
                    )
                    for future in done:
                        shard, submitted_at = pending.pop(future)
                        result = future.result()
                        elapsed = time.monotonic() - submitted_at
                        label = shard_label(shard)
                        try:
                            if result.row_count >= args.batch_limit:
                                children = split_shard(shard, args.max_shard_depth)
                                shards.extendleft(reversed(children))
                                print(
                                    f"shard={label} rows={result.row_count} "
                                    f"split_into={len(children)} elapsed={elapsed:.1f}s",
                                    file=sys.stderr,
                                )
                                continue
                            for image in result.images():
                                writer.write(image)
                                image_count += 1
                                cve_count += int(image["cve_count"])
                                finding_count += len(image["findings"])
                                observation_count += int(image["observation_count"])
                            writer.flush()
                            completed_shards += 1
                            print(
                                f"shard={label} images={result.row_count} elapsed={elapsed:.1f}s",
                                file=sys.stderr,
                            )
                        finally:
                            result.close()
            finally:
                for future in pending:
                    future.cancel()
        writer.close()
    except (CortexApiError, OSError, ValueError, KeyboardInterrupt) as exc:
        print(f"Error: {exc or 'interrupted'}; output may be partial", file=sys.stderr)
        return 1
    finally:
        # The executor waits for active requests; release their staged files too.
        for future in pending:
            if future.done() and not future.cancelled() and future.exception() is None:
                future.result().close()

    elapsed = args.deadline_seconds - max(0.0, deadline - time.monotonic())
    quota_delta = None
    try:
        quota_after = client.get_quota()
        before_used, after_used = quota_used(quota_before), quota_used(quota_after)
        if before_used is not None and after_used is not None:
            quota_delta = after_used - before_used
    except CortexApiError as exc:
        print(f"Warning: quota postflight failed ({exc})", file=sys.stderr)
    print(
        f"complete image_rows={image_count} image_cve_pairs={cve_count} "
        f"findings={finding_count} observations={observation_count} shards={completed_shards} "
        f"elapsed={elapsed:.1f}s snapshot_from_ms={timeframe['from']} "
        f"snapshot_to_ms={timeframe['to']} quota_used_delta={quota_delta}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
