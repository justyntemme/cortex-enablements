#!/usr/bin/env python3
"""Print up to five running container IDs, hosts, and image identifiers.

The asset inventory stores provider-specific container properties in
``xdm.asset.raw_fields``. This utility deliberately requests that JSON and
normalizes the common container/status/host/image keys locally, because those
provider-specific names are not identical across Docker, Kubernetes, and
cloud connectors. A row is returned only when its status is explicitly
``running`` (or an equivalent active value) and all three lookup values are
available.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class CortexApiError(RuntimeError):
    """An HTTP or API-level error returned by Cortex Cloud."""


class CortexXqlClient:
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
                if status in {"FAILED", "ERROR"}:
                    raise CortexApiError(f"XQL query failed: {result}")
                if status in {"SUCCESS", "COMPLETED"}:
                    results = reply.get("results", {})
                    data = results.get("data", []) if isinstance(results, dict) else []
                    if not isinstance(data, list):
                        raise CortexApiError("XQL response results.data was not an array")
                    return [row for row in data if isinstance(row, dict)]
            if time.monotonic() >= deadline:
                raise CortexApiError(f"Timed out waiting for query {query_id}")
            time.sleep(poll_interval)


QUERY = """config case_sensitive = false
| dataset = asset_inventory
| filter xdm.asset.type.class = "Compute"
| filter xdm.asset.type.name contains "container"
| fields xdm.asset.id as asset_id, xdm.asset.name as asset_name, xdm.asset.type.name as asset_type, xdm.asset.raw_fields as raw_fields
| limit 1000"""


def _normalize_key(value: object) -> str:
    return "".join(char if char.isalnum() else "_" for char in str(value).lower()).strip("_")


def _walk_values(value: object) -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = _normalize_key(key)
            yield normalized, child
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child)


def _parse_json(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _first_value(values: Iterable[tuple[str, object]], names: set[str]) -> object | None:
    for key, value in values:
        if key in names and isinstance(value, (str, int, float)) and str(value).strip():
            return value
    return None


def _project_running_container(row: dict[str, Any]) -> dict[str, Any] | None:
    raw = _parse_json(row.get("raw_fields", {}))
    values = list(_walk_values(raw)) + list(_walk_values(row))
    state = _first_value(
        values,
        {
            "status",
            "state",
            "container_status",
            "container_state",
            "runtime_status",
            "lifecycle_state",
            "phase",
        },
    )
    if _normalize_key(state) not in {"running", "active", "started", "up"}:
        return None

    container_id = _first_value(
        values,
        {"container_id", "containerid", "container_identifier", "containerinstanceid"},
    )
    asset_id = row.get("asset_id")
    image_id = _first_value(
        values,
        {"image_id", "image_identifier", "image_digest", "digest", "runtime_image_id", "image"},
    )
    image_name = _first_value(values, {"image_name", "imagename", "runtime_image", "runtimeimage", "container_image", "containerimage"})
    host = _first_value(values, {"host", "host_name", "hostname", "host_id", "endpoint_name", "node_name"})
    if not container_id:
        container_id = asset_id
    if not container_id or not image_id or not host:
        return None
    return {
        "container_id": container_id,
        "asset_id": asset_id,
        "host": host,
        "image_id": image_id,
        "image_name": image_name,
        "status": str(state),
        "asset_name": row.get("asset_name"),
        "asset_type": row.get("asset_type"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=5, help="Number of running containers to print (default: 5)")
    parser.add_argument("--limit", type=int, default=1000, help="Rows requested from XQL (default: 1000)")
    parser.add_argument("--relative-time-ms", type=int, default=2_592_000_000, help="API timeframe in milliseconds (default: last 30 days)")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--poll-interval", type=float, default=2)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.count <= 0 or args.limit <= 0 or args.relative_time_ms <= 0 or args.timeout <= 0 or args.poll_interval <= 0:
        print("--count, --limit, --relative-time-ms, --timeout, and --poll-interval must be positive.", file=sys.stderr)
        return 2
    base_url = os.getenv("CORTEX_API_URL")
    api_key = os.getenv("CORTEX_API_KEY")
    api_key_id = os.getenv("CORTEX_API_KEY_ID")
    if not base_url or not api_key or not api_key_id:
        print("Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.", file=sys.stderr)
        return 2
    try:
        rows = CortexXqlClient(base_url, api_key, api_key_id).run(
            QUERY,
            relative_time_ms=args.relative_time_ms,
            limit=args.limit,
            tenant_id=os.getenv("CORTEX_TENANT_ID"),
            timeout=args.timeout,
            poll_interval=args.poll_interval,
        )
        projected: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            container = _project_running_container(row)
            if container is None:
                continue
            key = (str(container["container_id"]), str(container["host"]), str(container["image_id"]))
            if key in seen:
                continue
            seen.add(key)
            projected.append(container)
            if len(projected) >= args.count:
                break
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if len(projected) < args.count:
        print(
            f"Warning: found {len(projected)} running container(s) with complete container/host/image values; "
            f"requested {args.count}. The tenant may not expose provider-specific fields or may have fewer running containers.",
            file=sys.stderr,
        )
    print(json.dumps(projected, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
