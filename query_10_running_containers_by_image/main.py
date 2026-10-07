#!/usr/bin/env python3
"""Return every telemetry-observed running container for one image.

``--image-id`` accepts either the 64-character Cortex image asset ID emitted by
Queries 8/9 or an image SHA256 digest. A Cortex asset ID is resolved to
``asset_inventory.xdm.image.identifier`` with a small XQL query before a second,
selective XQL query reads XDR container telemetry.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_CORTEX_RESULTS = 1_000_000
ASSET_ID_RE = re.compile(r"[0-9a-f]{64}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
OUTPUT_FIELDS = (
    "image_asset_id",
    "state_observed_at",
    "agent_id",
    "agent_hostname",
    "container_id",
    "container_name",
    "state",
    "image_id",
    "image_name",
    "pod_name",
    "pod_namespace",
    "pod_uid",
    "pod_ip",
    "privileged",
)


class CortexApiError(RuntimeError):
    """An HTTP or API-level error returned by Cortex Cloud."""


class CortexXqlClient:
    """Execute XQL and follow the result stream when Cortex returns one."""

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
            raise CortexApiError(
                f"Cortex API returned HTTP {exc.code}: {detail}"
            ) from exc
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
            return [row for row in value if isinstance(row, dict)]
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

    @staticmethod
    def _extract_stream_rows(value: Any) -> list[dict[str, Any]] | None:
        """Normalize a JSON array or Cortex's JSON-Lines stream wrappers."""
        if isinstance(value, dict):
            rows = CortexXqlClient._extract_rows(value)
            return rows if rows is not None else [value]
        if not isinstance(value, list):
            return None

        output: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            rows = CortexXqlClient._extract_rows(item)
            if rows is None:
                output.append(item)
            else:
                output.extend(rows)
        return output

    def _get_stream(self, stream_id: str, *, timeout: float) -> list[dict[str, Any]]:
        request = Request(
            f"{self.base_url}/public_api/v1/xql/get_query_results_stream",
            data=json.dumps(
                {
                    "request_data": {
                        "stream_id": stream_id,
                        "is_gzip_compressed": False,
                    }
                }
            ).encode("utf-8"),
            headers={**self.headers, "Accept-Encoding": "identity"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=max(60, timeout)) as response:
                body = response.read()
                if (
                    response.headers.get("Content-Encoding", "").lower() == "gzip"
                    or body.startswith(b"\x1f\x8b")
                ):
                    body = gzip.decompress(body)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CortexApiError(
                f"Cortex stream API returned HTTP {exc.code}: {detail}"
            ) from exc
        except (URLError, OSError) as exc:
            raise CortexApiError(f"Could not retrieve Cortex result stream: {exc}") from exc

        try:
            decoded = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CortexApiError("Cortex result stream was not UTF-8 JSON") from exc

        try:
            streamed: Any = json.loads(decoded)
        except json.JSONDecodeError:
            streamed = []
            try:
                for line in decoded.splitlines():
                    if line.strip():
                        streamed.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise CortexApiError(
                    f"Cortex result stream was not valid JSON Lines ({len(body)} bytes)"
                ) from exc

        if isinstance(streamed, dict) and "err_code" in streamed:
            raise CortexApiError(json.dumps(streamed))
        rows = self._extract_stream_rows(streamed)
        if rows is None:
            raise CortexApiError("Cortex result stream did not contain a data array")
        return rows

    def run(
        self,
        query: str,
        *,
        relative_time_ms: int,
        limit: int,
        tenant_id: str | None,
        timeout: float,
        poll_interval: float,
    ) -> list[dict[str, Any]]:
        started = self._post(
            "/public_api/v1/xql/start_xql_query",
            {
                "request_data": {
                    "query": query,
                    "tenants": [tenant_id] if tenant_id else [],
                    "timeframe": {"relativeTime": relative_time_ms},
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
            raise CortexApiError(
                f"Start XQL response did not contain a query ID: {started}"
            )

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
                if status in {"FAILED", "ERROR"}:
                    raise CortexApiError(f"XQL query failed: {json.dumps(result)}")
                if status in {"SUCCESS", "COMPLETED"} or (
                    status not in {"PENDING", "RUNNING", "IN_PROGRESS"}
                    and "results" in reply
                ):
                    stream_id = self._find_stream_id(reply)
                    if stream_id:
                        return self._get_stream(
                            stream_id,
                            timeout=max(1, deadline - time.monotonic()),
                        )
                    rows = self._extract_rows(reply)
                    if rows is None:
                        raise CortexApiError(
                            f"XQL response contained neither rows nor a stream ID: {result}"
                        )
                    return rows
            if time.monotonic() >= deadline:
                raise CortexApiError(f"Timed out waiting for query {query_id}")
            time.sleep(poll_interval)


def normalize_image_id(value: str) -> tuple[str, str]:
    """Return (kind, normalized value) for an asset ID or SHA256 digest."""
    normalized = value.strip().lower()
    if ASSET_ID_RE.fullmatch(normalized):
        return "asset", normalized
    digests = DIGEST_RE.findall(normalized)
    if len(digests) == 1:
        return "digest", digests[0]
    raise ValueError(
        "--image-id must be a 64-character Cortex image asset ID or contain "
        "exactly one sha256:<64 hex characters> digest"
    )


def build_image_resolution_query(image_asset_id: str) -> str:
    """Build the small lookup that maps a Cortex asset ID to its config digest."""
    identifier_kind, identifier = normalize_image_id(image_asset_id)

    if identifier_kind != "asset":
        raise ValueError("The image-resolution query requires a Cortex asset ID")
    return f'''config case_sensitive = false
| dataset = asset_inventory
| filter xdm.asset.id = "{identifier}"
| fields xdm.asset.id as image_asset_id,
         xdm.asset.type.id as image_asset_type,
         xdm.image.identifier as image_identifier,
         xdm.asset.name as image_asset_name,
         xdm.asset.strong_id as image_strong_id
| limit 2'''


def build_query(image_id: str) -> str:
    """Build the state-aware telemetry query for one config digest."""
    identifier_kind, identifier = normalize_image_id(image_id)

    if identifier_kind != "digest":
        raise ValueError("The telemetry query requires an image SHA256 digest")

    # Apply the raw image predicate before JSON extraction and deduplication so
    # a common-image lookup remains selective in a large xdr_data collection.
    # State is nested JSON inside actor_container_info.other. Filter it only
    # after retaining the newest telemetry record for each container.
    return f'''config case_sensitive = false
| dataset = xdr_data
| filter actor_container_info != null
| filter actor_container_info -> image_id contains "{identifier}"
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
        container_image_identifier = lowercase(arrayindex(regextract(container_image_id, "(sha256:[0-9a-f]{{64}})"), 0)),
        pod_ip = json_extract_scalar(container_other, "$.pod_ip")
| filter container_image_identifier != null and container_id != null
| filter container_image_identifier = "{identifier}"
| fields _time, agent_id, agent_hostname, container_id, container_name, container_state, container_image_id, container_image_name, pod_name, pod_namespace, pod_uid, pod_ip, privileged
| dedup agent_id, container_id by desc _time
| filter container_state in ("CONTAINER_RUNNING", "RUNNING")
| fields _time as state_observed_at, agent_id, agent_hostname, container_id, container_name, container_state as state, container_image_id as image_id, container_image_name as image_name, pod_name, pod_namespace, pod_uid, pod_ip, privileged'''


def resolved_config_digest(row: dict[str, Any]) -> str | None:
    """Read the config digest from a resolved Cortex image asset."""
    for key in ("image_identifier", "image_asset_name", "image_strong_id"):
        value = row.get(key)
        if isinstance(value, str):
            match = DIGEST_RE.search(value.lower())
            if match:
                return match.group(0)
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image-id",
        required=True,
        help=(
            "Cortex image asset ID from Query 8/9, a sha256 digest, or an image "
            "reference containing one sha256 digest"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=MAX_CORTEX_RESULTS,
        help="Maximum result rows requested (default: 1000000)",
    )
    parser.add_argument(
        "--relative-time-ms",
        type=int,
        default=86_400_000,
        help="Telemetry lookback in milliseconds (default: last 24 hours)",
    )
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--poll-interval", type=float, default=2)
    parser.add_argument(
        "--show-query",
        action="store_true",
        help="Print the generated XQL to stderr before executing it",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.limit <= MAX_CORTEX_RESULTS:
        print(
            f"--limit must be between 1 and {MAX_CORTEX_RESULTS}.",
            file=sys.stderr,
        )
        return 2
    if args.relative_time_ms <= 0 or args.timeout <= 0 or args.poll_interval <= 0:
        print(
            "--relative-time-ms, --timeout, and --poll-interval must be positive.",
            file=sys.stderr,
        )
        return 2

    try:
        identifier_kind, identifier = normalize_image_id(args.image_id)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    base_url = os.getenv("CORTEX_API_URL")
    api_key = os.getenv("CORTEX_API_KEY")
    api_key_id = os.getenv("CORTEX_API_KEY_ID")
    if not base_url or not api_key or not api_key_id:
        print(
            "Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.",
            file=sys.stderr,
        )
        return 2

    client = CortexXqlClient(base_url, api_key, api_key_id)
    try:
        if identifier_kind == "asset":
            resolution_query = build_image_resolution_query(identifier)
            if args.show_query:
                print("// Image asset resolution", file=sys.stderr)
                print(resolution_query, file=sys.stderr)
            image_rows = client.run(
                resolution_query,
                relative_time_ms=args.relative_time_ms,
                limit=2,
                tenant_id=os.getenv("CORTEX_TENANT_ID"),
                timeout=args.timeout,
                poll_interval=args.poll_interval,
            )
            if not image_rows:
                raise CortexApiError(f"No asset found for image ID {identifier}")
            image_digest = resolved_config_digest(image_rows[0])
            if image_digest is None:
                raise CortexApiError(
                    f"Asset {identifier} does not expose an image config digest"
                )
        else:
            image_digest = identifier

        query = build_query(image_digest)
        if args.show_query:
            print("// Running-container telemetry", file=sys.stderr)
            print(query, file=sys.stderr)
        rows = client.run(
            query,
            relative_time_ms=args.relative_time_ms,
            limit=args.limit,
            tenant_id=os.getenv("CORTEX_TENANT_ID"),
            timeout=args.timeout,
            poll_interval=args.poll_interval,
        )
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output: list[dict[str, Any]] = []
    for row in rows:
        item = {key: row.get(key) for key in OUTPUT_FIELDS if key in row}
        if identifier_kind == "asset":
            item["image_asset_id"] = identifier
        output.append(item)

    if len(rows) >= args.limit:
        print(
            f"Warning: the response reached --limit={args.limit}; Cortex may have "
            "additional matching containers.",
            file=sys.stderr,
        )
    print(json.dumps(output, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
