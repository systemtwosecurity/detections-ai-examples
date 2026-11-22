#!/usr/bin/env python3
"""Print (or open) a Microsoft Defender Advanced Hunting link that loads a KQL query.

Usage:
    python3 open_in_advanced_hunting.py query.kql
    pbpaste | python3 open_in_advanced_hunting.py --open
    python3 open_in_advanced_hunting.py --query 'DeviceProcessEvents | take 10'

Standard library only. Microsoft does not document the link format; the test file pins it.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import sys
import webbrowser
from pathlib import Path
from urllib.parse import quote

ADVANCED_HUNTING_URL = "https://security.microsoft.com/v2/advanced-hunting"

# Browsers and proxies start truncating or rejecting URLs past about 8 KB.
MAX_URL_LENGTH = 8000


class QueryTooLongError(ValueError):
    pass


def pack_query(kql: str) -> str:
    # The console decodes the payload as UTF-16LE: a UTF-8 payload loads as CJK characters.
    # mtime=0 keeps the link stable for the same query.
    compressed = gzip.compress(kql.encode("utf-16-le"), mtime=0)
    return base64.b64encode(compressed).decode("ascii")


def build_url(kql: str, time_range: str = "day", tenant_id: str | None = None) -> str:
    if not kql.strip():
        raise ValueError("the query is empty")
    url = f"{ADVANCED_HUNTING_URL}?query={quote(pack_query(kql), safe='')}&timeRangeId={quote(time_range, safe='')}"
    if tenant_id:
        url += f"&tid={quote(tenant_id, safe='')}"
    if len(url) > MAX_URL_LENGTH:
        raise QueryTooLongError(
            f"the link is {len(url)} characters, over the {MAX_URL_LENGTH} limit; paste the query into the console instead"
        )
    return url


def _read_query(args: argparse.Namespace) -> str:
    if args.query is not None:
        return args.query
    if args.file and args.file != "-":
        return Path(args.file).read_text(encoding="utf-8")
    return sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a Defender Advanced Hunting link for a KQL query.")
    parser.add_argument("file", nargs="?", help="file holding the KQL query; '-' or omitted reads stdin")
    parser.add_argument("--query", help="the KQL query itself, instead of a file")
    parser.add_argument(
        "--time-range",
        default="day",
        help=(
            "the console's timeRangeId, used only when the query has no time filter"
            " (default: day, which is 'Last 24 hours'; other values untested)"
        ),
    )
    parser.add_argument(
        "--tenant",
        help="Entra tenant ID to open the console in (untested; without it the console uses your last tenant)",
    )
    parser.add_argument("--open", action="store_true", help="open the link in your default browser")
    args = parser.parse_args(argv)

    try:
        url = build_url(_read_query(args), time_range=args.time_range, tenant_id=args.tenant)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(url)
    if args.open:
        webbrowser.open(url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
