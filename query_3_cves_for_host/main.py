#!/usr/bin/env python3
"""Run an XQL query that returns all CVEs reported for one host."""

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

    def run(self, query: str, *, relative_time_ms: int, limit: int, tenant_id: str | None, timeout: float, poll_interval: float) -> dict[str, Any]:
        started = self._post("/public_api/v1/xql/start_xql_query", {"request_data": {"query": query, "tenants": [tenant_id] if tenant_id else [], "timeframe": {"relativeTime": relative_time_ms}}})
        raw_reply = started.get("reply")
        query_id = raw_reply if isinstance(raw_reply, str) else None
        if isinstance(raw_reply, dict):
            query_id = raw_reply.get("query_id") or raw_reply.get("execution_id") or raw_reply.get("id")
        if not query_id:
            raise CortexApiError(f"Start XQL response did not contain a query ID: {started}")
        deadline = time.monotonic() + timeout
        while True:
            result = self._post("/public_api/v1/xql/get_query_results", {"request_data": {"query_id": query_id, "pending_flag": True, "limit": limit, "format": "json"}})
            reply = result.get("reply", result)
            if isinstance(reply, dict):
                status = str(reply.get("status", "")).upper()
                if status in {"SUCCESS", "COMPLETED", "FAILED", "ERROR"} or (status not in {"PENDING", "RUNNING", "IN_PROGRESS"} and "results" in reply):
                    return result
            if time.monotonic() >= deadline:
                raise CortexApiError(f"Timed out waiting for query {query_id}")
            time.sleep(poll_interval)


def xql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_query(host: str) -> str:
    return f'''dataset = va_endpoints
| filter endpoint_name = "{xql_string(host)}"
| filter cves != null
| arrayexpand cves
| fields endpoint_name, cves, severity, severity_score
| sort asc cves
| limit 1000'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Host name as stored in va_endpoints.endpoint_name")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--relative-time-ms", type=int, default=2_592_000_000, help="API timeframe in milliseconds (default: last 30 days)")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--poll-interval", type=float, default=2)
    args = parser.parse_args()
    if args.limit <= 0 or args.relative_time_ms <= 0 or args.timeout <= 0 or args.poll_interval <= 0:
        parser.error("--limit, --relative-time-ms, --timeout, and --poll-interval must be positive")
    base_url, api_key, api_key_id = (os.getenv(name) for name in ("CORTEX_API_URL", "CORTEX_API_KEY", "CORTEX_API_KEY_ID"))
    if not base_url or not api_key or not api_key_id:
        print("Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.", file=sys.stderr)
        return 2
    try:
        result = CortexXqlClient(base_url, api_key, api_key_id).run(build_query(args.host), relative_time_ms=args.relative_time_ms, limit=args.limit, tenant_id=os.getenv("CORTEX_TENANT_ID"), timeout=args.timeout, poll_interval=args.poll_interval)
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    reply = result.get("reply", {})
    rows = reply.get("results", {}).get("data") if isinstance(reply, dict) else None
    print(json.dumps(result if rows is None else rows, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
