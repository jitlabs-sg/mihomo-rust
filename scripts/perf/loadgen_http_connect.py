#!/usr/bin/env python3
import argparse
import asyncio
import json
import math
import statistics
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit


@dataclass
class Summary:
    requests: int
    ok: int
    errors: int
    duration_s: float
    rps: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    p999_ms: float
    max_ms: float
    mean_ms: float
    stdev_ms: float
    top_errors: list[tuple[str, int]]


def percentile(sorted_values, p: float) -> float:
    if not sorted_values:
        return 0.0
    if p <= 0:
        return float(sorted_values[0])
    if p >= 100:
        return float(sorted_values[-1])
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_values[int(k)])
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return float(d0 + d1)


def parse_http_url(url: str) -> tuple[str, int, str, str]:
    parsed = urlsplit(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    host_header = f"{host}:{port}" if parsed.port else host
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, port, host_header, path


async def read_http_message(
    reader: asyncio.StreamReader,
    timeout_s: float,
) -> tuple[int, Optional[int]]:
    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout_s)
    header_text = header.decode("iso-8859-1", errors="replace")
    status_line = header_text.splitlines()[0] if header_text else ""
    parts = status_line.split(" ", 2)
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

    content_length = None
    for line in header_text.splitlines()[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() == "content-length":
            try:
                content_length = int(v.strip())
            except ValueError:
                content_length = None

    if content_length is not None:
        remaining = content_length
        while remaining > 0:
            chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), timeout=timeout_s)
            if not chunk:
                break
            remaining -= len(chunk)
    else:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout_s)
            if not chunk:
                break

    return code, content_length


async def one_request(
    proxy_host: str,
    proxy_port: int,
    url: str,
    timeout_s: float,
) -> tuple[bool, Optional[float], Optional[str]]:
    start = time.perf_counter_ns()
    try:
        target_host, target_port, host_header, path = parse_http_url(url)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout_s
        )

        connect_req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: mihomo-rust-loadgen/1.0\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(connect_req)
        await writer.drain()

        connect_header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout_s)
        connect_text = connect_header.decode("iso-8859-1", errors="replace")
        status_line = connect_text.splitlines()[0] if connect_text else ""
        parts = status_line.split(" ", 2)
        connect_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        if connect_code != 200:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            end = time.perf_counter_ns()
            ms = (end - start) / 1_000_000.0
            return False, ms, f"connect_status={connect_code}"

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: mihomo-rust-loadgen/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(req)
        await writer.drain()

        code, _ = await read_http_message(reader, timeout_s=timeout_s)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        end = time.perf_counter_ns()
        ms = (end - start) / 1_000_000.0
        ok = 200 <= code < 300
        return ok, ms, None if ok else f"http_status={code}"
    except Exception as e:
        end = time.perf_counter_ns()
        ms = (end - start) / 1_000_000.0
        return False, ms, str(e)


async def run_load(
    proxy_host: str,
    proxy_port: int,
    url: str,
    concurrency: int,
    duration_s: Optional[float],
    requests: Optional[int],
    timeout_s: float,
    show_errors: int,
) -> Summary:
    latencies = []
    ok = 0
    errors = 0
    err_counts: dict[str, int] = {}
    started = time.perf_counter()

    stop_at = None if duration_s is None else (started + duration_s)

    queue = None
    if requests is not None:
        queue = asyncio.Queue()
        for _ in range(requests):
            queue.put_nowait(1)

    lock = asyncio.Lock()

    async def worker():
        nonlocal ok, errors
        while True:
            if stop_at is not None and time.perf_counter() >= stop_at:
                return
            if queue is not None:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
            success, ms, _err = await one_request(
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                url=url,
                timeout_s=timeout_s,
            )
            async with lock:
                if ms is not None:
                    latencies.append(ms)
                if success:
                    ok += 1
                else:
                    errors += 1
                    if _err:
                        err_counts[_err] = err_counts.get(_err, 0) + 1

    await asyncio.gather(*[worker() for _ in range(concurrency)])

    ended = time.perf_counter()
    duration = max(0.000001, ended - started)
    total = ok + errors
    lat_sorted = sorted(latencies)
    mean = statistics.mean(lat_sorted) if lat_sorted else 0.0
    stdev = statistics.pstdev(lat_sorted) if len(lat_sorted) >= 2 else 0.0

    top_errors = sorted(err_counts.items(), key=lambda kv: kv[1], reverse=True)
    if show_errors > 0:
        top_errors = top_errors[:show_errors]
    else:
        top_errors = []

    return Summary(
        requests=total,
        ok=ok,
        errors=errors,
        duration_s=duration,
        rps=total / duration,
        p50_ms=percentile(lat_sorted, 50),
        p90_ms=percentile(lat_sorted, 90),
        p95_ms=percentile(lat_sorted, 95),
        p99_ms=percentile(lat_sorted, 99),
        p999_ms=percentile(lat_sorted, 99.9),
        max_ms=float(lat_sorted[-1]) if lat_sorted else 0.0,
        mean_ms=mean,
        stdev_ms=stdev,
        top_errors=top_errors,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-host", default="127.0.0.1")
    ap.add_argument("--proxy-port", type=int, default=7890)
    ap.add_argument("--url", required=True, help="http://host:port/path (used inside CONNECT tunnel)")
    ap.add_argument("--concurrency", type=int, default=200)
    ap.add_argument("--duration", type=float, default=None, help="seconds (default: unset)")
    ap.add_argument("--requests", type=int, default=None, help="total requests (default: unset)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--show-errors", type=int, default=0, help="print top N error kinds")
    ap.add_argument("--json", action="store_true", help="print a single-line JSON summary")
    args = ap.parse_args()

    if args.duration is None and args.requests is None:
        ap.error("one of --duration or --requests is required")

    summary = asyncio.run(
        run_load(
            proxy_host=args.proxy_host,
            proxy_port=args.proxy_port,
            url=args.url,
            concurrency=max(1, args.concurrency),
            duration_s=args.duration,
            requests=args.requests,
            timeout_s=max(0.1, args.timeout),
            show_errors=max(0, args.show_errors),
        )
    )

    print(
        "\n".join(
            [
                "=== loadgen summary (HTTP CONNECT) ===",
                f"url={args.url}",
                f"proxy={args.proxy_host}:{args.proxy_port}",
                f"requests={summary.requests} ok={summary.ok} errors={summary.errors}",
                f"duration_s={summary.duration_s:.2f} rps={summary.rps:.1f}",
                f"latency_ms p50={summary.p50_ms:.2f} p90={summary.p90_ms:.2f} p95={summary.p95_ms:.2f} p99={summary.p99_ms:.2f} p99.9={summary.p999_ms:.2f} max={summary.max_ms:.2f}",
                f"latency_ms mean={summary.mean_ms:.2f} stdev={summary.stdev_ms:.2f}",
            ]
        )
    )

    if summary.top_errors:
        print("top_errors:")
        for msg, count in summary.top_errors:
            print(f"  {count}x {msg}")

    if args.json:
        print(
            json.dumps(
                {
                    "kind": "http_connect",
                    "url": args.url,
                    "proxy_host": args.proxy_host,
                    "proxy_port": args.proxy_port,
                    "concurrency": args.concurrency,
                    "timeout_s": args.timeout,
                    "requests": summary.requests,
                    "ok": summary.ok,
                    "errors": summary.errors,
                    "duration_s": summary.duration_s,
                    "rps": summary.rps,
                    "latency_ms": {
                        "p50": summary.p50_ms,
                        "p90": summary.p90_ms,
                        "p95": summary.p95_ms,
                        "p99": summary.p99_ms,
                        "p999": summary.p999_ms,
                        "max": summary.max_ms,
                        "mean": summary.mean_ms,
                        "stdev": summary.stdev_ms,
                    },
                    "top_errors": [
                        {"error": msg, "count": count} for msg, count in summary.top_errors
                    ],
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
