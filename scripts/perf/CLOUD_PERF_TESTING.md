# GCP 云端多点压测方案

## 概述

使用 GCP Spot VM 进行多地区压测，验证 mihomo-rust 在真实网络环境下的性能和稳定性。

**预算：$300 赠金（花不完！）**

---

## Phase 2: 快速验证（3 地区）

### 目标
确认修复后的协议在真实网络环境下正常工作

### 配置

```yaml
时间: 30-60 分钟
成本: ~$0.05

地区分布:
  us-central1 (Iowa):
    - rust-mihomo (主测试)
    - go-mihomo (baseline)
    实例: e2-standard-2 (2 vCPU, 8GB)

  asia-east1 (Taiwan):
    - client-1 (亚洲用户模拟)
    实例: e2-medium (2 vCPU, 4GB)

  europe-west1 (Belgium):
    - client-2 (欧洲用户模拟)
    实例: e2-medium (2 vCPU, 4GB)
```

### 测试矩阵

| 协议 | 入站 | 重点场景 | 验收标准 |
|------|------|----------|----------|
| Direct | http_proxy/http_connect/socks5 | 基线性能 | 接近 Go |
| Shadowsocks | 所有入站 | 稳定性 | 接近 Go |
| Trojan | http_connect/socks5 | 大流量 + 握手 | ok > 8200 |
| VLESS | http_connect | 大流量 (1MB) | ok > 8300 |
| VMess | 所有入站 | 握手 + 超时 | ok > 7500, p50 < 200ms |

### 验收标准

- ✅ 无大量 502/超时/connect failed
- ✅ p99 延迟不超过 Go 的 1.5x
- ✅ 错误率 < 5%

---

## Phase 3: 多点压测（5-7 地区）

### 目标
通过多地区并发压测，发现性能瓶颈和网络边界情况

### 配置

```yaml
时间: 1-2 小时
成本: ~$0.50 (有 $300 赠金，随便用！)

地区分布:
  # 服务器 (美国中部)
  us-central1 (Iowa):
    - rust-mihomo (主测试)
    - go-mihomo (baseline)
    实例: e2-standard-4 (4 vCPU, 16GB) # 豪一点！

  # 美国东西海岸
  us-west1 (Oregon):
    - client-1 (美西用户)
    实例: e2-medium

  us-east1 (South Carolina):
    - client-2 (美东用户)
    实例: e2-medium

  # 亚洲
  asia-east1 (Taiwan):
    - client-3 (台湾用户)
    实例: e2-medium

  asia-northeast1 (Tokyo):
    - client-4 (日本用户)
    实例: e2-medium

  # 欧洲
  europe-west1 (Belgium):
    - client-5 (欧洲用户)
    实例: e2-medium

  # 可选：南美
  southamerica-east1 (São Paulo):
    - client-6 (南美用户)
    实例: e2-medium
```

### 压测模式

#### 1. 持续负载
```yaml
模式: 恒定 QPS
目标: 测试稳定性
配置:
  - 每个 client: 500-1000 req/s
  - 总 QPS: 3000-5000 req/s
  - 持续时间: 30 分钟
```

#### 2. 波动负载
```yaml
模式: 10%-90% 交替
目标: 测试弹性
配置:
  - 低峰: 300 req/s (10%)
  - 高峰: 3000 req/s (90%)
  - 周期: 5 分钟
  - 持续时间: 30 分钟
```

#### 3. 连接风暴
```yaml
模式: 短时间大量连接
目标: 测试连接池
配置:
  - 突发: 5000 连接/秒
  - 持续: 10 秒
  - 间隔: 5 分钟
  - 重复: 5 次
```

#### 4. 大流量测试
```yaml
模式: 持续传输大文件
目标: 测试内存和 buffer 管理
配置:
  - 文件大小: 1MB-10MB
  - 并发: 50 连接
  - 持续时间: 20 分钟
```

#### 5. 混合协议
```yaml
模式: 多协议并发
目标: 测试协议切换
配置:
  - Shadowsocks: 30%
  - Trojan: 30%
  - VLESS: 20%
  - VMess: 20%
  - 持续时间: 30 分钟
```

### 监控指标

```yaml
系统指标:
  - CPU 使用率
  - 内存使用率 (RSS/VSZ)
  - 网络吞吐量 (Mbps)
  - 文件描述符数量
  - TCP 连接数 (ESTABLISHED/TIME_WAIT)

性能指标:
  - QPS (每秒请求数)
  - 延迟分布 (p50/p90/p95/p99)
  - 错误率 (%)
  - 超时率 (%)

网络指标 (多地区特有):
  - 跨区域延迟
  - 丢包率
  - 抖动 (jitter)
```

### 验收标准

| 指标 | 目标 | 说明 |
|------|------|------|
| QPS | > 3000 | 5-6 个 client 总和 |
| p50 延迟 | < 150ms | 跨区域中位数 |
| p99 延迟 | < 800ms | 跨区域 99 分位 |
| 错误率 | < 1% | 总请求数 |
| 内存增长 | < 10% | 1 小时内 |
| CPU 使用率 | < 80% | 平均值 |

---

## GCP 实例配置

### Spot VM 选择

```yaml
实例类型:
  服务器:
    - e2-standard-2: 2 vCPU, 8GB RAM ($0.067/h 标准, $0.020/h Spot)
    - e2-standard-4: 4 vCPU, 16GB RAM ($0.134/h 标准, $0.040/h Spot)

  客户端:
    - e2-medium: 2 vCPU, 4GB RAM ($0.034/h 标准, $0.010/h Spot)
    - e2-small: 2 vCPU, 2GB RAM ($0.017/h 标准, $0.005/h Spot)

Spot VM 特点:
  - 比标准实例便宜 60-91%
  - 可能被回收（30 秒警告）
  - 没有 24 小时限制（比 Preemptible 好）
  - 可设置最大运行时间
```

### 防火墙规则

```yaml
入站规则:
  - 7890: HTTP Proxy (mihomo)
  - 7891: SOCKS5 (mihomo)
  - 9090: RESTful API (mihomo)
  - 10808: Shadowsocks
  - 10809: Trojan
  - 10810: VLESS
  - 10811: VMess
  - 22: SSH (管理)

出站规则:
  - 允许所有
```

---

## 部署命令

### 1. 创建服务器实例 (us-central1)

```bash
# Rust mihomo
gcloud compute instances create rust-mihomo \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --provisioning-model=SPOT \
  --instance-termination-action=DELETE \
  --max-run-duration=7200s \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --tags=mihomo-server \
  --metadata-from-file=startup-script=setup-rust-mihomo.sh

# Go mihomo (baseline)
gcloud compute instances create go-mihomo \
  --zone=us-central1-a \
  --machine-type=e2-standard-2 \
  --provisioning-model=SPOT \
  --instance-termination-action=DELETE \
  --max-run-duration=7200s \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --tags=mihomo-server \
  --metadata-from-file=startup-script=setup-go-mihomo.sh
```

### 2. 创建客户端实例 (多地区)

```bash
# 定义地区
REGIONS=(
  "us-west1-a"
  "us-east1-b"
  "asia-east1-a"
  "asia-northeast1-a"
  "europe-west1-b"
)

# 批量创建
for i in "${!REGIONS[@]}"; do
  gcloud compute instances create "client-$((i+1))" \
    --zone="${REGIONS[$i]}" \
    --machine-type=e2-medium \
    --provisioning-model=SPOT \
    --instance-termination-action=DELETE \
    --max-run-duration=7200s \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=10GB \
    --tags=mihomo-client \
    --metadata-from-file=startup-script=setup-client.sh &
done
wait
echo "All clients created!"
```

### 3. 创建防火墙规则

```bash
# 允许 mihomo 端口
gcloud compute firewall-rules create allow-mihomo \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:7890,tcp:7891,tcp:9090,tcp:10808-10811 \
  --target-tags=mihomo-server

# 允许 SSH
gcloud compute firewall-rules create allow-ssh \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=0.0.0.0/0
```

### 4. 获取实例 IP

```bash
# 获取服务器 IP
RUST_IP=$(gcloud compute instances describe rust-mihomo \
  --zone=us-central1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

GO_IP=$(gcloud compute instances describe go-mihomo \
  --zone=us-central1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo "Rust mihomo: $RUST_IP"
echo "Go mihomo: $GO_IP"
```

### 5. 启动压测

```bash
# 在每个 client 上启动压测
for i in {1..5}; do
  ZONE=$(gcloud compute instances describe "client-$i" \
    --format='get(zone)' | xargs basename)

  gcloud compute ssh "client-$i" --zone="$ZONE" --command="
    # 持续负载测试
    python3 /opt/loadgen/loadgen_http_proxy.py \
      --target $RUST_IP:7890 \
      --qps 500 \
      --duration 1800 \
      --output /tmp/results_client${i}.json &

    echo 'Load test started on client-$i'
  " &
done
wait
```

### 6. 收集结果

```bash
# 创建结果目录
mkdir -p results/$(date +%Y%m%d_%H%M%S)

# 从每个 client 收集结果
for i in {1..5}; do
  ZONE=$(gcloud compute instances describe "client-$i" \
    --format='get(zone)' | xargs basename)

  gcloud compute scp "client-$i:/tmp/results_*.json" \
    ./results/$(date +%Y%m%d_%H%M%S)/ \
    --zone="$ZONE"
done

# 生成汇总报告
python3 analyze_results.py --input results/ --output report.html
```

### 7. 清理资源

```bash
# 删除所有实例
gcloud compute instances delete rust-mihomo go-mihomo \
  --zone=us-central1-a --quiet

for i in {1..5}; do
  ZONE=$(gcloud compute instances describe "client-$i" \
    --format='get(zone)' 2>/dev/null | xargs basename)
  if [ -n "$ZONE" ]; then
    gcloud compute instances delete "client-$i" --zone="$ZONE" --quiet &
  fi
done
wait

# 删除防火墙规则（可选，可以保留复用）
# gcloud compute firewall-rules delete allow-mihomo --quiet

echo "Cleanup complete!"
```

---

## 成本估算

### Phase 2: 快速验证（3 地区，1 小时）

```
服务器 (us-central1):
  1 × e2-standard-2 Spot × $0.020/h × 1h = $0.02
  1 × e2-standard-2 Spot × $0.020/h × 1h = $0.02

客户端 (2 地区):
  2 × e2-medium Spot × $0.010/h × 1h = $0.02

总计: $0.06
```

### Phase 3: 多点压测（7 地区，2 小时）

```
服务器 (us-central1):
  1 × e2-standard-4 Spot × $0.040/h × 2h = $0.08
  1 × e2-standard-2 Spot × $0.020/h × 2h = $0.04

客户端 (5 地区):
  5 × e2-medium Spot × $0.010/h × 2h = $0.10

总计: $0.22
```

### 总成本

```
Phase 2 + Phase 3 = $0.28

剩余赠金: $300 - $0.28 = $299.72

结论: 随便测！花不完！😂
```

### 如果想"豪"一点

```
用标准实例（不用 Spot）:
  Phase 2: ~$0.20
  Phase 3: ~$1.00
  总计: ~$1.20

用更大的实例:
  e2-standard-8 (8 vCPU, 32GB): $0.268/h
  Phase 3 服务器升级: +$0.50
  总计: ~$1.70

跑 8 小时稳定性测试:
  Phase 3 × 4 = ~$1.00

全部加起来: ~$4
剩余赠金: $296

结论: 还是花不完！😂
```

---

## 故障排查

### 1. Spot VM 被回收

```bash
# 检查实例状态
gcloud compute instances describe rust-mihomo --zone=us-central1-a

# 如果被回收，重新创建
gcloud compute instances create rust-mihomo \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --provisioning-model=SPOT \
  ...
```

### 2. 连接超时

```bash
# 检查防火墙规则
gcloud compute firewall-rules list

# 检查服务状态
gcloud compute ssh rust-mihomo --zone=us-central1-a --command="
  systemctl status mihomo-rust
  ss -tlnp | grep mihomo
"
```

### 3. 性能不达标

```bash
# 检查 CPU/内存
gcloud compute ssh rust-mihomo --zone=us-central1-a --command="
  top -b -n 1 | head -20
  free -h
"

# 检查网络
gcloud compute ssh rust-mihomo --zone=us-central1-a --command="
  iftop -t -s 5 2>/dev/null || nethogs -t -c 5
"

# 检查连接数
gcloud compute ssh rust-mihomo --zone=us-central1-a --command="
  ss -s
  cat /proc/sys/net/core/somaxconn
"
```

### 4. 跨区域延迟过高

```bash
# 测试延迟
for region in us-west1 us-east1 asia-east1 asia-northeast1 europe-west1; do
  echo "=== $region ==="
  gcloud compute ssh "client-${region}" --zone="${region}-a" --command="
    ping -c 5 $RUST_IP
  "
done
```

---

## 参考

- [GCP Spot VM 文档](https://cloud.google.com/compute/docs/instances/spot)
- [GCP 区域和可用区](https://cloud.google.com/compute/docs/regions-zones)
- [mihomo 配置文档](https://wiki.metacubex.one/)
- [gcloud CLI 参考](https://cloud.google.com/sdk/gcloud/reference)
