from __future__ import annotations

import argparse
import asyncio
import gzip
import ipaddress
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp


async def download(args):
    target = urlsplit(args.server)
    try:
        local = ipaddress.ip_address(target.hostname).is_loopback
    except ValueError:
        local = target.hostname == "localhost"
    if (
        target.scheme not in ("http", "https")
        or not target.hostname
        or target.username
        or target.password
        or target.query
        or target.fragment
        or target.scheme == "http"
        and not local
    ):
        raise ValueError("LOG_EXPORT_REQUIRES_HTTPS_EXCEPT_LOOPBACK")
    context = ssl.create_default_context(cafile=args.ca_file)
    token = Path(args.token_file).read_text().strip()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    cursor = args.after
    async with aiohttp.ClientSession(
        trust_env=False, connector=aiohttp.TCPConnector(ssl=context), timeout=aiohttp.ClientTimeout(total=15)
    ) as session:
        opener = gzip.open if output.suffix == ".gz" else open
        with opener(output, "at" if args.after else "wt", encoding="utf-8") as f:
            output.chmod(0o600)
            while True:
                params = {"after": str(cursor), "limit": "1000"}
                if args.room:
                    params["room"] = args.room
                if args.client:
                    params["client"] = args.client
                async with session.get(
                    args.server.rstrip("/") + "/logs",
                    params=params,
                    headers={"Authorization": "Bearer " + token},
                    allow_redirects=False,
                ) as response:
                    response.raise_for_status()
                    body = await response.json()
                for event in body["events"]:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
                cursor = body["next"]
                if len(body["events"]) < 1000:
                    break
    print(f"Exported through cursor {cursor}: {output.resolve()}")


def main():
    parser = argparse.ArgumentParser(description="Download authenticated central diagnostics as JSONL")
    parser.add_argument("--server", required=True, help="https://SERVER:8443 (http for localhost testing)")
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--room")
    parser.add_argument("--client")
    parser.add_argument("--after", type=int, default=0)
    parser.add_argument("--output", default="data/export.jsonl.gz", help=".gz compresses JSONL; .jsonl is plaintext")
    asyncio.run(download(parser.parse_args()))


if __name__ == "__main__":
    main()
