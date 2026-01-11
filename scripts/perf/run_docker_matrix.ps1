<#
.SYNOPSIS
Run a local Docker performance matrix for mihomo-rust vs mihomo (Go).

.DESCRIPTION
This script spins up a fully local, self-contained Docker testbed:
  - mh-target: HTTP target server (Python, port 18080)
  - mh-ss: Shadowsocks upstream (shadowsocks-libev, port 8388)
  - mh-xray: Xray upstream (VMess/VLESS/Trojan)
  - mh-core-rust / mh-core-go: core under test (listen 7890)

It then drives the existing Python load generators:
  - scripts/perf/loadgen_http_proxy.py
  - scripts/perf/loadgen_http_connect.py
  - scripts/perf/loadgen_socks5.py

Important limitations:
  - This is a *local Docker* test: it does NOT reflect real-world network latency/jitter.
  - For true WAN latency comparisons, run the cloud test plan (e.g. GCP) and compare there.
  - We focus on latency stability (p50/p90/p99 + stdev), not throughput.
  - Concurrency defaults are intentionally low (local client scenario). Do not "optimize" by
    cranking concurrency to hundreds; that changes what is being measured.

.PARAMETER Impl
Which implementation(s) to test: rust, go, or both.

.PARAMETER Mode
quick: baseline fast path checks
full: adds delay/bytes and functional edge cases

.PARAMETER Protocols
Protocols to test: direct, ss, vless, vmess, trojan.
Accepts either an array (`-Protocols direct ss`) or a single comma-separated string (`-Protocols direct,ss`).

.PARAMETER TestTypes
Proxy client modes to test: http_proxy, http_connect, socks5.

.PARAMETER FastConcurrency
Default: 20. Typical "daily use" concurrency for a local proxy client.

.PARAMETER BytesConcurrency
Default: 10. Lower concurrency for larger responses to avoid turning this into a throughput benchmark.

.PARAMETER KeepContainers
Do not remove containers on exit (useful for debugging).

.PARAMETER KeepCore
Reuse the core container while iterating protocols (faster, but can hide startup-only issues).

.OUTPUTS
Writes JSONL results to `scripts/perf/_tmp/results_*.jsonl` and a latency-focused CSV summary beside it.
#>
param(
  [ValidateSet('rust', 'go', 'both')]
  [string]$Impl = 'both',

  [ValidateSet('quick', 'full')]
  [string]$Mode = 'full',

  [string]$Network = 'mhproto',

  [string]$RustBin = '',
  [string]$GoBin = '',

  [string[]]$Protocols = @(),

  [ValidateSet('http_proxy', 'http_connect', 'socks5')]
  [string[]]$TestTypes = @('http_proxy', 'http_connect', 'socks5'),

  # Low concurrency by design (local client scenario; latency stability focus).
  [int]$FastConcurrency = 20,
  [int]$FastDurationSec = 15,

  # "Delay" is for stability under a small, fixed server delay (still low concurrency).
  [int]$DelayConcurrency = 20,
  [int]$DelayDurationSec = 20,

  # Big body reads; lower concurrency to avoid turning the test into throughput benchmarking.
  [int]$BytesConcurrency = 10,
  [int]$BytesDurationSec = 20,

  # Functional edge cases (close/status); keep low concurrency too.
  [int]$EdgeConcurrency = 20,
  [int]$EdgeDurationSec = 10,

  [int]$TimeoutSec = 8,

  [string]$CoreLogLevel = 'warning',

  [switch]$KeepContainers,
  [switch]$KeepCore
)

$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
  $global:PSNativeCommandUseErrorActionPreference = $false
}

function Invoke-Native {
  param(
    [Parameter(Mandatory = $true)][string]$File,
    [Parameter(Mandatory = $true)][string[]]$Args
  )
  $oldEA = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out = & $File @Args 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldEA
  }
  if ($code -ne 0) {
    throw "command failed ($code): $File $($Args -join ' ')`n$out"
  }
  return $out
}

function Invoke-Docker {
  param([Parameter(Mandatory = $true)][string[]]$Args)

  # Docker on Windows can occasionally return transient "unexpected EOF" while
  # waiting for a container. Retry a few times to avoid aborting long matrices.
  $maxRetries = 3
  for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
    try {
      return Invoke-Native -File 'docker' -Args $Args
    } catch {
      $msg = $_.Exception.Message
      if ($attempt -lt $maxRetries -and $msg -match 'unexpected EOF') {
        Start-Sleep -Seconds (2 * ($attempt + 1))
        continue
      }
      throw
    }
  }
}

function Remove-ContainerIfExists {
  param([Parameter(Mandatory = $true)][string]$Name)
  try { & docker rm -f $Name *> $null } catch { }
}

function Ensure-Network {
  param([Parameter(Mandatory = $true)][string]$Name)
  try {
    & docker network inspect $Name *> $null
  } catch {
    Invoke-Docker -Args @('network', 'create', $Name) | Out-Null
  }
}

function Write-FileUtf8NoBom {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Content
  )
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Normalize-StringList {
  param([Parameter(Mandatory = $true)][string[]]$Values)
  return @(
    $Values |
      ForEach-Object { $_ -split ',' } |
      ForEach-Object { $_.Trim() } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  )
}

function New-RustConfig {
  param(
    [Parameter(Mandatory = $true)][string]$ModeRule,
    [string]$ProxyYamlBlock = '',
    [string]$LogLevel = 'warning'
  )
  $proxiesSection = if ([string]::IsNullOrWhiteSpace($ProxyYamlBlock)) { 'proxies: []' } else { "proxies:`n$ProxyYamlBlock" }
  return @"
log-level: $LogLevel
mode: rule
external-controller: null

inbound:
  mixed:
    listen: "0.0.0.0:7890"
    udp: true

dns:
  enable: false

$proxiesSection

proxy-groups: []

rules:
  - $ModeRule
"@
}

function New-GoConfig {
  param(
    [Parameter(Mandatory = $true)][string]$ModeRule,
    [string]$ProxyYamlBlock = '',
    [string]$LogLevel = 'warning'
  )
  $proxiesSection = if ([string]::IsNullOrWhiteSpace($ProxyYamlBlock)) { 'proxies: []' } else { "proxies:`n$ProxyYamlBlock" }
  return @"
log-level: $LogLevel
mode: rule
external-controller: null

allow-lan: true
bind-address: 0.0.0.0

mixed-port: 7890

dns:
  enable: false

$proxiesSection

proxy-groups: []

rules:
  - $ModeRule
"@
}

function Invoke-Loadgen {
  param(
    [Parameter(Mandatory = $true)][string]$Kind,
    [Parameter(Mandatory = $true)][string]$ProxyHost,
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][int]$Concurrency,
    [Parameter(Mandatory = $true)][int]$DurationSec,
    [Parameter(Mandatory = $true)][int]$TimeoutSec,
    [Parameter(Mandatory = $true)][string]$NetworkName,
    [Parameter(Mandatory = $true)][string]$PerfDir
  )

  $script = switch ($Kind) {
    'http_proxy' { 'loadgen_http_proxy.py' }
    'http_connect' { 'loadgen_http_connect.py' }
    'socks5' { 'loadgen_socks5.py' }
    default { throw "unknown kind: $Kind" }
  }

  $out = Invoke-Docker -Args @(
    'run', '--rm',
    '--network', $NetworkName,
    '-v', "${PerfDir}:/perf",
    'python:3.13-slim',
    'python', "/perf/$script",
    '--proxy-host', $ProxyHost,
    '--proxy-port', '7890',
    '--url', $Url,
    '--duration', "$DurationSec",
    '--concurrency', "$Concurrency",
    '--timeout', "$TimeoutSec",
    '--show-errors', '5',
    '--json'
  )

  $jsonLine = ($out | Where-Object { $_ -match '^[{].*[}]$' } | Select-Object -Last 1)
  if (-not $jsonLine) {
    throw "loadgen did not emit JSON (kind=$Kind url=$Url):`n$out"
  }
  return ($jsonLine | ConvertFrom-Json)
}

function New-RunRow {
  param(
    [Parameter(Mandatory = $true)][string]$Impl,
    [Parameter(Mandatory = $true)][string]$Protocol,
    [Parameter(Mandatory = $true)][string]$Kind,
    [Parameter(Mandatory = $true)][int]$Concurrency,
    [Parameter(Mandatory = $true)][int]$DurationSec,
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $false)][string]$Label = ''
  )
  return [PSCustomObject]@{
    impl = $Impl
    protocol = $Protocol
    kind = $Kind
    concurrency = $Concurrency
    duration_s = $DurationSec
    url = $Url
    label = $Label
  }
}

function Format-LatencyLine {
  param([Parameter(Mandatory = $true)]$Result)
  "{0,-4} {1,-6} {2,-11} ok={3,6} err={4,6} p50={5,7:N2}ms p90={6,7:N2}ms p99={7,7:N2}ms stdev={8,7:N2}ms" -f `
    $Result.impl, $Result.protocol, $Result.kind, $Result.ok, $Result.errors, `
    $Result.latency_ms.p50, $Result.latency_ms.p90, $Result.latency_ms.p99, $Result.latency_ms.stdev
}

$perfDir = $PSScriptRoot
$repoRoot = Resolve-Path (Join-Path $perfDir '..\..')
$repoRootPath = $repoRoot.Path

$tmpDir = Join-Path $perfDir '_tmp'
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$xrayDir = Join-Path $tmpDir 'xray'
New-Item -ItemType Directory -Force -Path $xrayDir | Out-Null

$resultsPath = Join-Path $tmpDir ("results_{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$summaryCsvPath = [IO.Path]::ChangeExtension($resultsPath, '.summary.csv')

if (-not $RustBin) {
  $RustBin = Join-Path $repoRoot 'target-linux-bullseye\release\mihomo-rust'
}
if (-not $GoBin) {
  $GoBin = Join-Path $repoRoot 'mihomo'
}

if ($RustBin -and -not [IO.Path]::IsPathRooted($RustBin)) {
  $RustBin = Join-Path $repoRootPath $RustBin
}
if ($GoBin -and -not [IO.Path]::IsPathRooted($GoBin)) {
  $GoBin = Join-Path $repoRootPath $GoBin
}

if ($Impl -in @('rust', 'both') -and -not (Test-Path $RustBin)) {
  throw "Rust linux binary not found: $RustBin (build it with Docker: CARGO_TARGET_DIR=target-linux-bullseye)"
}
if ($Impl -in @('go', 'both') -and -not (Test-Path $GoBin)) {
  throw "Go linux binary not found: $GoBin"
}

Ensure-Network -Name $Network

foreach ($c in @('mh-target', 'mh-ss', 'mh-xray', 'mh-core-rust', 'mh-core-go')) {
  Remove-ContainerIfExists -Name $c
}

try {
  # Generate a self-signed cert for trojan inbound.
  $certPath = Join-Path $xrayDir 'cert.pem'
  $keyPath = Join-Path $xrayDir 'key.pem'
  if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
    Invoke-Docker -Args @(
      'run', '--rm',
      '-v', "${xrayDir}:/out",
      'alpine:3.19',
      'sh', '-lc',
      'apk add --no-cache openssl >/dev/null; openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -subj "/CN=mh-xray" -keyout /out/key.pem -out /out/cert.pem >/dev/null'
    ) | Out-Null
  }

  $xrayConfig = @"
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 10086,
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "00000000-0000-0000-0000-000000000001", "alterId": 0 } ] }
    },
    {
      "listen": "0.0.0.0",
      "port": 10087,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "00000000-0000-0000-0000-000000000002" } ], "decryption": "none" }
    },
    {
      "listen": "0.0.0.0",
      "port": 10088,
      "protocol": "trojan",
      "settings": { "clients": [ { "password": "trojan-password" } ] },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": { "certificates": [ { "certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem" } ] }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
"@
  Write-FileUtf8NoBom -Path (Join-Path $xrayDir 'config.json') -Content $xrayConfig

  # Shared infra containers.
  Invoke-Docker -Args @(
    'run', '-d',
    '--name', 'mh-target',
    '--network', $Network,
    '-v', "${perfDir}:/perf",
    'python:3.13-slim',
    'python', '/perf/target_server.py',
    '--listen', '0.0.0.0',
    '--port', '18080'
  ) | Out-Null

  Invoke-Docker -Args @(
    'run', '-d',
    '--name', 'mh-ss',
    '--network', $Network,
    'shadowsocks/shadowsocks-libev',
    'ss-server',
    '-s', '0.0.0.0',
    '-p', '8388',
    '-k', 'password123',
    '-m', 'aes-256-gcm'
  ) | Out-Null

  Invoke-Docker -Args @(
    'run', '-d',
    '--name', 'mh-xray',
    '--network', $Network,
    '-v', "${xrayDir}:/etc/xray",
    'teddysun/xray',
    'xray', 'run',
    '-config', '/etc/xray/config.json'
  ) | Out-Null

  $impls = switch ($Impl) {
    'rust' { @('rust') }
    'go' { @('go') }
    'both' { @('rust', 'go') }
  }

  $defaultProtocols = if ($Mode -eq 'quick') { @('direct', 'ss', 'trojan') } else { @('direct', 'ss', 'vmess', 'vless', 'trojan') }
  $protocols = if ($Protocols -and $Protocols.Count -gt 0) { Normalize-StringList -Values $Protocols } else { $defaultProtocols }
  $testTypes = Normalize-StringList -Values $TestTypes

  $fastUrl = 'http://mh-target:18080/fast'
  $delayUrl = 'http://mh-target:18080/delay?ms=50'
  $bytesUrl = 'http://mh-target:18080/bytes?size=1048576'
  $closeUrl = 'http://mh-target:18080/close'
  $statusUrl = 'http://mh-target:18080/status?code=503'

  $allResults = New-Object System.Collections.Generic.List[object]

  foreach ($implName in $impls) {
    $coreBin = if ($implName -eq 'rust') { $RustBin } else { $GoBin }
    $coreContainer = "mh-core-$implName"

    foreach ($proto in $protocols) {
      if (-not $KeepCore) {
        Remove-ContainerIfExists -Name $coreContainer
      }

      $proxyBlock = ''
      $rule = 'MATCH,DIRECT'
      if ($proto -ne 'direct') {
        $rule = 'MATCH,UP'
        $proxyBlock = switch ($proto) {
          'ss' {
            @"
  - name: "UP"
    type: ss
    server: mh-ss
    port: 8388
    cipher: aes-256-gcm
    password: "password123"
"@
          }
          'vmess' {
            @"
  - name: "UP"
    type: vmess
    server: mh-xray
    port: 10086
    uuid: 00000000-0000-0000-0000-000000000001
    alterId: 0
    cipher: auto
    tls: false
"@
          }
          'vless' {
            @"
  - name: "UP"
    type: vless
    server: mh-xray
    port: 10087
    uuid: 00000000-0000-0000-0000-000000000002
    tls: false
"@
          }
          'trojan' {
            @"
  - name: "UP"
    type: trojan
    server: mh-xray
    port: 10088
    password: "trojan-password"
    sni: "mh-xray"
    skip-cert-verify: true
"@
          }
          default {
            throw "unknown protocol: $proto"
          }
        }
      }

      $cfgContent = if ($implName -eq 'rust') {
        New-RustConfig -ModeRule $rule -ProxyYamlBlock $proxyBlock -LogLevel $CoreLogLevel
      } else {
        New-GoConfig -ModeRule $rule -ProxyYamlBlock $proxyBlock -LogLevel $CoreLogLevel
      }

      $cfgPath = Join-Path $tmpDir ("cfg_{0}_{1}.yaml" -f $implName, $proto)
      Write-FileUtf8NoBom -Path $cfgPath -Content $cfgContent

      $mountArgs = @(
        '-v', "${repoRoot}:/work",
        '-v', "${tmpDir}:/cfg"
      )

      $coreBinInContainer = $null
      if ($coreBin.StartsWith($repoRootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relBin = $coreBin.Substring($repoRootPath.Length).TrimStart('\', '/').Replace('\', '/')
        $coreBinInContainer = "/work/$relBin"
      } else {
        $binHostDir = Split-Path -Parent $coreBin
        $binName = Split-Path -Leaf $coreBin
        $mountArgs += @('-v', "${binHostDir}:/binhost")
        $coreBinInContainer = "/binhost/$binName"
      }

      $cfgInContainer = "/cfg/$([IO.Path]::GetFileName($cfgPath))"
      $cfgFlag = if ($implName -eq 'go') { '-f' } else { '-c' }
      # Run from /work so mihomo-rust can spawn `./mihomo` (Go-fallback) when enabled.
      $sh = "set -e; cd /work; chmod +x '$coreBinInContainer'; '$coreBinInContainer' $cfgFlag '$cfgInContainer'"

      $dockerArgs = @(
        'run', '-d',
        '--name', $coreContainer,
        '--network', $Network
      ) + $mountArgs + @(
        'debian:bullseye-slim',
        'sh', '-lc', $sh
      )
      if ($env:RUST_LOG) {
        $dockerArgs = $dockerArgs[0..3] + @('-e', "RUST_LOG=$($env:RUST_LOG)") + $dockerArgs[4..($dockerArgs.Count - 1)]
      }
      Invoke-Docker -Args $dockerArgs | Out-Null

      Start-Sleep -Seconds 1

      $runs = New-Object System.Collections.Generic.List[object]

      foreach ($k in $testTypes) {
        $runs.Add((New-RunRow -Impl $implName -Protocol $proto -Kind $k -Concurrency $FastConcurrency -DurationSec $FastDurationSec -Url $fastUrl -Label 'fast')) | Out-Null
      }

      if ($Mode -ne 'quick') {
        if ($testTypes -contains 'http_connect') {
          $runs.Add((New-RunRow -Impl $implName -Protocol $proto -Kind 'http_connect' -Concurrency $DelayConcurrency -DurationSec $DelayDurationSec -Url $delayUrl -Label 'delay_50ms')) | Out-Null
          $runs.Add((New-RunRow -Impl $implName -Protocol $proto -Kind 'http_connect' -Concurrency $BytesConcurrency -DurationSec $BytesDurationSec -Url $bytesUrl -Label 'bytes_1MiB')) | Out-Null
          $runs.Add((New-RunRow -Impl $implName -Protocol $proto -Kind 'http_connect' -Concurrency $EdgeConcurrency -DurationSec $EdgeDurationSec -Url $closeUrl -Label 'edge_close')) | Out-Null
        }
        if ($testTypes -contains 'http_proxy') {
          $runs.Add((New-RunRow -Impl $implName -Protocol $proto -Kind 'http_proxy' -Concurrency $EdgeConcurrency -DurationSec $EdgeDurationSec -Url $statusUrl -Label 'edge_status_503')) | Out-Null
        }
      }

      foreach ($r in $runs) {
        $res = Invoke-Loadgen -Kind $r.kind -ProxyHost $coreContainer -Url $r.url -Concurrency $r.concurrency -DurationSec $r.duration_s -TimeoutSec $TimeoutSec -NetworkName $Network -PerfDir $perfDir
        $res | Add-Member -NotePropertyName impl -NotePropertyValue $implName
        $res | Add-Member -NotePropertyName protocol -NotePropertyValue $proto
        $res | Add-Member -NotePropertyName label -NotePropertyValue $r.label
        $res | Add-Member -NotePropertyName started_at -NotePropertyValue (Get-Date).ToString('s')
        $allResults.Add($res) | Out-Null

        Add-Content -Path $resultsPath -Value ($res | ConvertTo-Json -Compress)
        Write-Host (Format-LatencyLine -Result $res)
      }

      if (-not $KeepCore) {
        Remove-ContainerIfExists -Name $coreContainer
      }
    }
  }

  $allResults |
    Select-Object `
      impl, protocol, kind, label, concurrency, duration_s, ok, errors, `
      @{ Name = 'p50_ms'; Expression = { $_.latency_ms.p50 } }, `
      @{ Name = 'p90_ms'; Expression = { $_.latency_ms.p90 } }, `
      @{ Name = 'p99_ms'; Expression = { $_.latency_ms.p99 } }, `
      @{ Name = 'stdev_ms'; Expression = { $_.latency_ms.stdev } } |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsvPath

  Write-Host ""
  Write-Host "Results saved:"
  Write-Host "  JSONL: $resultsPath"
  Write-Host "  CSV:   $summaryCsvPath"
} finally {
  if (-not $KeepContainers) {
    foreach ($c in @('mh-core-rust', 'mh-core-go', 'mh-target', 'mh-ss', 'mh-xray')) {
      Remove-ContainerIfExists -Name $c
    }
  }
}
