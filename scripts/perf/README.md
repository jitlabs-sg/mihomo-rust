# Perf Harness

This folder contains a small, reproducible connectivity + edge-case + load harness.

## Components

- `target_server.py`: local HTTP target with endpoints:
  - `/fast`
  - `/delay?ms=50`
  - `/bytes?size=1048576`
  - `/status?code=503`
  - `/close` (abrupt close)
- `loadgen_http_proxy.py`: asyncio load generator for HTTP proxy (absolute-form requests).
- `loadgen_http_connect.py`: asyncio load generator for HTTP `CONNECT` (then does a GET inside the tunnel).
- `loadgen_socks5.py`: asyncio load generator for SOCKS5 `CONNECT` (then does a GET inside the tunnel).
- `config_direct.yaml`: runs `mihomo-rust` as a mixed inbound proxy and routes `MATCH,DIRECT`.
- `config_go_fallback.yaml`: forces routing to a Go-fallback proxy name.
- `fake_mihomo_connect.rs`: tiny fake `mihomo.exe` that only implements HTTP CONNECT forwarding (for exercising the Go-fallback chain without requiring a real upstream protocol server).

## Quick Run (Windows)

1) Start target:
`python scripts/perf/target_server.py --port 18080`

2) Start `mihomo-rust` (direct):
`.\target\release\mihomo-rust.exe -c scripts/perf/config_direct.yaml`

3) Run load:
`python scripts/perf/loadgen_http_proxy.py --proxy-port 7890 --url http://127.0.0.1:18080/fast --duration 20 --concurrency 200`

4) Test CONNECT and SOCKS5 paths:
`python scripts/perf/loadgen_http_connect.py --proxy-port 7890 --url http://127.0.0.1:18080/fast --duration 20 --concurrency 200`
`python scripts/perf/loadgen_socks5.py --proxy-port 7890 --url http://127.0.0.1:18080/fast --duration 20 --concurrency 200`

## Docker Protocol Matrix (Linux)

This runs everything inside a Docker network:

- `mh-target`: HTTP target server
- `mh-ss`: Shadowsocks server
- `mh-xray`: Xray server (vmess/vless/trojan)
- `mh-core-{rust|go}`: mihomo core under test

Prereqs:

- Build Rust linux binary to `target-linux-bullseye/release/mihomo-rust`
- Provide a Go linux binary at repo root `./mihomo` (or pass `-GoBin`)

Run:

`pwsh scripts/perf/run_docker_matrix.ps1 -Impl both -Mode full`

Notes:

- If `pwsh` is not available on Windows, use `powershell -ExecutionPolicy Bypass -File scripts\\perf\\run_docker_matrix.ps1 ...`.
- The Go binary is invoked with `-f` (config file), while Rust uses `-c` (config file). The script handles this automatically.
- In `full` mode, edge cases include:
  - `/delay?ms=50`
  - `/bytes?size=1048576`
  - `/status?code=503`
  - `/close`
