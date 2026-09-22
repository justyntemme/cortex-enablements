#!/usr/bin/env python3
"""List all Cortex Cloud container-image assets without XQL.

Uses the Asset Inventory API's Container Image category, which includes core,
registry, runtime, and any other image types present in the tenant. The
``image_id`` in each output record is the Cortex asset ID to pass to
``container_image_vulnerabilities_api/main.py``. ``image_digest`` is the
SHA-256 content digest extracted from the asset's full strong ID.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ASSETS_PATH = "/public_api/v1/assets"


class CortexApiError(RuntimeError):
    """An HTTP or API-level error returned by Cortex Cloud."""


class CortexAssetClient:
    def __init__(self, base_url: str, api_key: str, api_key_id: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": api_key,
            "x-xdr-auth-id": api_key_id,
        }

    def search(self, request_data: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{ASSETS_PATH}",
            data=json.dumps({"request_data": request_data}).encode("utf-8"),
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
        reply = result.get("reply")
        if not isinstance(reply, dict):
            raise CortexApiError("Cortex API response did not contain a reply object")
        if reply.get("err_code") is not None:
            raise CortexApiError(json.dumps(result))
        return reply


def image_record(row: dict[str, Any]) -> dict[str, Any]:
    strong_id = row.get("xdm.asset.strong_id")
    digest_match = (
        re.search(r"(?:^|@)sha256:([0-9a-f]{64})(?:$|[^0-9a-f])", strong_id, re.I)
        if isinstance(strong_id, str)
        else None
    )
    return {
        "image_id": row.get("xdm.asset.id"),
        "image_digest": f"sha256:{digest_match.group(1).lower()}" if digest_match else None,
        "image_strong_id": strong_id,
        "image_name": row.get("xdm.asset.name"),
        "image_type": row.get("xdm.asset.type.id"),
        "provider": row.get("xdm.asset.provider"),
        "last_observed": row.get("xdm.asset.last_observed"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--page-size",
        type=int,
        default=500,
        help="Assets requested per API page (default: 500)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum images to print; 0 retrieves all images (default: 0)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.page_size < 1 or args.limit < 0:
        print("--page-size must be positive and --limit must be zero or positive.", file=sys.stderr)
        return 2

    base_url, api_key, api_key_id = (
        os.getenv(name) for name in ("CORTEX_API_URL", "CORTEX_API_KEY", "CORTEX_API_KEY_ID")
    )
    if not base_url or not api_key or not api_key_id:
        print("Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.", file=sys.stderr)
        return 2

    image_filter = {
        "AND": [
            {
                "SEARCH_FIELD": "xdm.asset.type.category",
                "SEARCH_TYPE": "EQ",
                "SEARCH_VALUE": "Container Image",
            }
        ]
    }
    images: list[dict[str, Any]] = []
    offset = 0
    try:
        client = CortexAssetClient(base_url, api_key, api_key_id)
        while True:
            page_size = min(args.page_size, args.limit - len(images)) if args.limit else args.page_size
            reply = client.search(
                {
                    "filters": image_filter,
                    "search_from": offset,
                    "search_to": offset + page_size,
                }
            )
            rows = reply.get("data")
            if not isinstance(rows, list):
                raise CortexApiError("Cortex API reply.data was not an array")
            images.extend(image_record(row) for row in rows if isinstance(row, dict))
            offset += len(rows)
            metadata = reply.get("metadata")
            filtered_total = metadata.get("filter_count") if isinstance(metadata, dict) else None
            if args.limit and len(images) >= args.limit:
                break
            if not rows or (isinstance(filtered_total, int) and offset >= filtered_total):
                break
            if len(rows) < page_size:
                raise CortexApiError("Asset API returned a short page before the filtered total was reached")
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(images, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
