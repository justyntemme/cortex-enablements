#!/usr/bin/env python3
"""Get vulnerability findings for one Cortex container-image asset without XQL.

Pass the ``image_id`` from ``container_images_api/main.py`` (the Cortex asset
ID, not the SHA-256 image digest). This example resolves the image through the
Asset Inventory API, then pages through container-image Vulnerability Findings
and matches their ``asset_id`` or ``image`` digest locally. The Findings API
does not document a direct image-ID filter.
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
FINDINGS_PATH = "/vulnerability-management/v1/vulnerability-finding/search/"


class CortexApiError(RuntimeError):
    """An HTTP or API-level error returned by Cortex Cloud."""


class CortexClient:
    def __init__(self, base_url: str, api_key: str, api_key_id: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": api_key,
            "x-xdr-auth-id": api_key_id,
        }

    def request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            headers=self.headers,
            method="POST" if payload is not None else "GET",
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
        if reply.get("err_code") is not None or reply.get("ERR_CODE") is not None:
            raise CortexApiError(json.dumps(result))
        return reply


def get_image(client: CortexClient, image_id: str) -> dict[str, Any]:
    reply = client.request(f"{ASSETS_PATH}/{image_id}")
    rows = reply.get("data")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise CortexApiError(f"No asset found for image ID {image_id}")
    image = rows[0]
    if image.get("xdm.asset.id") != image_id:
        raise CortexApiError("Asset API returned a different asset ID")
    if image.get("xdm.asset.type.category") != "Container Image":
        raise CortexApiError(f"Asset {image_id} is not a Container Image")
    return image


def normalize_digest(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    match = re.search(r"(?:^|@)sha256:([0-9a-f]{64})(?:$|[^0-9a-f])", value, re.I)
    if match:
        return match.group(1).lower()
    return value.lower() if re.fullmatch(r"[0-9a-f]{64}", value, re.I) else None


def finding_matches_image(finding: dict[str, Any], image_id: str, digest: str | None) -> bool:
    finding_asset_id = finding.get("asset_id", finding.get("ASSET_ID"))
    if finding_asset_id == image_id:
        return True
    finding_digest = normalize_digest(finding.get("image", finding.get("IMAGE")))
    return digest is not None and finding_digest is not None and finding_digest == digest


def _reply_value(reply: dict[str, Any], lower: str, upper: str) -> Any:
    return reply.get(lower) if lower in reply else reply.get(upper)


def get_findings(
    client: CortexClient,
    image_id: str,
    digest: str | None,
    *,
    page_size: int,
    max_pages: int,
) -> tuple[list[dict[str, Any]], int, bool]:
    request_data: dict[str, Any] = {
        "filter": {
            "AND": [
                {
                    "SEARCH_FIELD": "ASSET_CATEGORY",
                    "SEARCH_TYPE": "EQ",
                    "SEARCH_VALUE": "Container Image",
                }
            ]
        },
        "sort": [{"FIELD": "CVSS_SCORE", "ORDER": "DESC"}],
        "page_size": page_size,
    }
    matches: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    scanned_rows = 0
    pages = 0
    while True:
        reply = client.request(FINDINGS_PATH, {"request_data": request_data})
        rows = _reply_value(reply, "data", "DATA")
        if not isinstance(rows, list):
            raise CortexApiError("Findings API reply.data/DATA was not an array")
        scanned_rows += len(rows)
        matches.extend(
            row for row in rows if isinstance(row, dict) and finding_matches_image(row, image_id, digest)
        )
        pages += 1

        next_page_token = _reply_value(reply, "next_page_token", "NEXT_PAGE_TOKEN")
        filtered_total = _reply_value(reply, "filter_count", "FILTER_COUNT")
        if max_pages and pages >= max_pages and next_page_token:
            return matches, scanned_rows, False
        if not next_page_token:
            if isinstance(filtered_total, int) and scanned_rows < filtered_total:
                raise CortexApiError(
                    "Findings API reported more filtered rows but no next_page_token; "
                    "results for this image may be incomplete"
                )
            return matches, scanned_rows, True
        if not isinstance(next_page_token, str) or next_page_token in seen_tokens:
            raise CortexApiError("Findings API returned an invalid or repeated next_page_token")
        seen_tokens.add(next_page_token)
        request_data["next_page_token"] = next_page_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True, help="Cortex image asset ID from container_images_api")
    parser.add_argument(
        "--page-size",
        type=int,
        default=10_000,
        help="Findings requested per API page (default: 10000)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=0,
        help="Maximum findings pages; 0 follows all page tokens (default: 0)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.page_size < 1 or args.max_pages < 0:
        print("--page-size must be positive and --max-pages must be zero or positive.", file=sys.stderr)
        return 2
    image_id = args.image_id.strip()
    if not image_id:
        print("--image-id must not be empty.", file=sys.stderr)
        return 2

    base_url, api_key, api_key_id = (
        os.getenv(name) for name in ("CORTEX_API_URL", "CORTEX_API_KEY", "CORTEX_API_KEY_ID")
    )
    if not base_url or not api_key or not api_key_id:
        print("Set CORTEX_API_URL, CORTEX_API_KEY, and CORTEX_API_KEY_ID first.", file=sys.stderr)
        return 2

    try:
        client = CortexClient(base_url, api_key, api_key_id)
        image = get_image(client, image_id)
        image_strong_id = image.get("xdm.asset.strong_id")
        normalized_digest = normalize_digest(image_strong_id)
        vulnerabilities, scanned_rows, complete = get_findings(
            client,
            image_id,
            normalized_digest,
            page_size=args.page_size,
            max_pages=args.max_pages,
        )
    except CortexApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "image_id": image_id,
                "image_digest": f"sha256:{normalized_digest}" if normalized_digest else None,
                "image_strong_id": image_strong_id,
                "image_name": image.get("xdm.asset.name"),
                "image_type": image.get("xdm.asset.type.id"),
                "complete": complete,
                "findings_scanned": scanned_rows,
                "vulnerabilities": vulnerabilities,
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
    )
    if not complete:
        print("Warning: stopped at --max-pages; results may be incomplete.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
