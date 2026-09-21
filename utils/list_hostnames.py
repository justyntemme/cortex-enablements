#!/usr/bin/env python3
"""Print up to five host names suitable for the host-CVE example.

The values come from ``va_endpoints.endpoint_name``, which is the exact field
accepted by ``query_3_cves_for_host``. The dataset represents endpoints known
to the vulnerability service; it does not guarantee live network reachability.
"""

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
| dataset = va_endpoints
| filter endpoint_name != null
| fields endpoint_name
| limit 100"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=5, help="Number of host names to print (default: 5)")
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
    if args.count <= 0 or args.limit <= 0 or args.relative_time_ms <= 0:
        print("--count, --limit, and --relative-time-ms must be positive.", file=sys.stderr)
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
    if rows is None:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0

    host_names: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        host_name = row.get("endpoint_name")
        if host_name is None or not str(host_name).strip() or str(host_name) in seen:
            continue
        seen.add(str(host_name))
        host_names.append(str(host_name))
        if len(host_names) >= args.count:
            break

    if len(host_names) < args.count:
        print(
            f"Warning: found {len(host_names)} host(s) in va_endpoints; requested {args.count}. "
            "The tenant may not expose endpoint vulnerability data or may have fewer known hosts.",
            file=sys.stderr,
        )
    print(json.dumps(host_names, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
