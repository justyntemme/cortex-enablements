#!/usr/bin/env python3
"""Run an XQL query that returns image assets from the asset inventory."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any
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
    ) -> dict[str, Any]:
        tenants = [tenant_id] if tenant_id else []
        started = self._post(
            "/public_api/v1/xql/start_xql_query",
            {
                "request_data": {
                    "query": query,
                    "tenants": tenants,
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
                if status in {"SUCCESS", "COMPLETED", "FAILED", "ERROR"}:
                    return result
                if status not in {"PENDING", "RUNNING", "IN_PROGRESS"} and "results" in reply:
                    return result
            if time.monotonic() >= deadline:
                raise CortexApiError(f"Timed out waiting for query {query_id}")
            time.sleep(poll_interval)


QUERY = """config case_sensitive = false
| dataset = asset_inventory
| filter xdm.asset.type.class = "Compute"
| filter (xdm.asset.type.id = "CORE_IMAGE" or xdm.asset.type.id = "RUNTIME_IMAGE")
| fields xdm.asset.id as image_id, xdm.asset.name as image_name, xdm.asset.type.id as image_type_id, xdm.asset.type.name as image_type
| sort asc image_name
| limit 1000"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=1000, help="Maximum rows requested (default: 1000)")
    parser.add_argument(
        "--relative-time-ms",
        type=int,
        default=2_592_000_000,
        help="API timeframe in milliseconds (default: last 30 days)",
    )
    parser.add_argument("--timeout", type=float, default=300, help="Result polling timeout in seconds")
    parser.add_argument("--poll-interval", type=float, default=2, help="Seconds between result polls")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = os.getenv("CORTEX_API_URL")
    api_key = os.getenv("CORTEX_API_KEY")
    api_key_id = os.getenv("CORTEX_API_KEY_ID")
    if not base_url or not api_key or not api_key_id:
        print("Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.", file=sys.stderr)
        return 2
    if args.limit <= 0 or args.relative_time_ms <= 0:
        print("--limit and --relative-time-ms must be positive.", file=sys.stderr)
        return 2

    try:
        result = CortexXqlClient(base_url, api_key, api_key_id).run(
            QUERY,
            relative_time_ms=args.relative_time_ms,
            limit=args.limit,
            tenant_id=os.getenv("CORTEX_TENANT_ID"),
            timeout=args.timeout,
            poll_interval=args.poll_interval,
        )
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    reply = result.get("reply", {})
    rows = reply.get("results", {}).get("data") if isinstance(reply, dict) else None
    # XQL rows are nested under reply.results.data; do not confuse the
    # surrounding quota/status metadata with the query result set.
    print(json.dumps(result if rows is None else rows, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
