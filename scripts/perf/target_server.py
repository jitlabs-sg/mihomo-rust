#!/usr/bin/env python3
import argparse
import asyncio
import os
import re
from urllib.parse import parse_qs, urlsplit


SERVER_HEADER = "mihomo-rust-perf-target/1.0"
HEADER_END = b"\r\n\r\n"
REQUEST_LINE_RE = re.compile(r"^(?P<m>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<v>\d+\.\d+)$")


def reason_phrase(code: int) -> str:
    return {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(code, "OK")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        data = await asyncio.wait_for(reader.readuntil(HEADER_END), timeout=10.0)
    except Exception:
        writer.close()
        return

    try:
        text = data.decode("iso-8859-1", errors="replace")
        first = text.splitlines()[0] if text else ""
        m = REQUEST_LINE_RE.match(first)
        if not m:
            await send_response(writer, 400, b"bad request\n")
            return
        method = m.group("m").upper()
        raw_path = m.group("path")
    except Exception:
        await send_response(writer, 400, b"bad request\n")
        return

    parsed = urlsplit(raw_path)
    path = parsed.path
    qs = parse_qs(parsed.query)
    is_head = method == "HEAD"

    if path == "/fast":
        await send_response(writer, 200, b"" if is_head else b"OK\n")
        return

    if path == "/delay":
        try:
            ms = int(qs.get("ms", ["0"])[0])
        except ValueError:
            ms = 0
        if ms > 0:
            await asyncio.sleep(ms / 1000.0)
        await send_response(writer, 200, b"" if is_head else b"OK\n")
        return

    if path == "/bytes":
        try:
            size = int(qs.get("size", ["0"])[0])
        except ValueError:
            size = 0
        size = max(0, min(size, 50 * 1024 * 1024))  # cap at 50MiB
        await send_response_stream(
            writer,
            200,
            size=size,
            content_type="application/octet-stream",
            head_only=is_head,
            chunk_factory=lambda n: b"a" * n,
        )
        return

    if path == "/random-bytes":
        try:
            size = int(qs.get("size", ["0"])[0])
        except ValueError:
            size = 0
        size = max(0, min(size, 10 * 1024 * 1024))  # cap at 10MiB
        await send_response_stream(
            writer,
            200,
            size=size,
            content_type="application/octet-stream",
            head_only=is_head,
            chunk_factory=os.urandom,
        )
        return

    if path == "/status":
        try:
            code = int(qs.get("code", ["200"])[0])
        except ValueError:
            code = 200
        body = b"" if is_head else (f"status={code}\n").encode("utf-8")
        await send_response(writer, code, body)
        return

    if path == "/close":
        writer.close()
        return

    await send_response(writer, 404, b"" if is_head else b"not found\n")


async def send_response(
    writer: asyncio.StreamWriter,
    code: int,
    body: bytes,
    content_type: str = "text/plain",
):
    headers = (
        f"HTTP/1.1 {code} {reason_phrase(code)}\r\n"
        f"Server: {SERVER_HEADER}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")
    writer.write(headers)
    if body:
        writer.write(body)
    try:
        await writer.drain()
    finally:
        writer.close()


async def send_response_stream(
    writer: asyncio.StreamWriter,
    code: int,
    size: int,
    content_type: str,
    head_only: bool,
    chunk_factory,
):
    headers = (
        f"HTTP/1.1 {code} {reason_phrase(code)}\r\n"
        f"Server: {SERVER_HEADER}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {size}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")
    writer.write(headers)

    if not head_only and size > 0:
        remaining = size
        while remaining > 0:
            n = min(65536, remaining)
            writer.write(chunk_factory(n))
            remaining -= n
            await writer.drain()

    writer.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    args = ap.parse_args()

    try:
        asyncio.run(run_server(args.listen, args.port))
    except KeyboardInterrupt:
        pass


async def run_server(host: str, port: int):
    server = await asyncio.start_server(handle_client, host, port)
    print(f"target_server listening on http://{host}:{port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    main()
