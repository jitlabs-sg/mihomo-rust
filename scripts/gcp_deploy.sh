#!/bin/bash
# ============================================================================
# mihomo-rust GCP 一键部署脚本
# Usage: curl -sSL <url> | bash
# ============================================================================

set -e

echo "============================================"
echo "  mihomo-rust GCP Deploy Script"
echo "============================================"

# 1. 安装依赖
echo "[1/5] Installing dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev git curl

# 2. 安装 Rust
echo "[2/5] Installing Rust..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust already installed: $(rustc --version)"
fi
source "$HOME/.cargo/env"

# 3. 克隆/更新代码
echo "[3/5] Cloning mihomo-rust..."
REPO_DIR="$HOME/mihomo-rust"
if [ -d "$REPO_DIR" ]; then
    echo "Updating existing repo..."
    cd "$REPO_DIR"
    git pull || true
else
    # TODO: 改成你的 GitHub repo
    # git clone https://github.com/YOUR_USERNAME/mihomo-rust.git "$REPO_DIR"
    echo "ERROR: Please upload source code to $REPO_DIR first"
    echo "Or set up git clone after open source"
    exit 1
fi

# 4. 编译
echo "[4/5] Building release binary..."
cd "$REPO_DIR"
cargo build --release

# 5. 安装
echo "[5/5] Installing..."
sudo cp target/release/mihomo-rust /usr/local/bin/
sudo chmod +x /usr/local/bin/mihomo-rust

# 创建配置目录
sudo mkdir -p /etc/mihomo-rust
if [ ! -f /etc/mihomo-rust/config.yaml ]; then
    sudo cp config.yaml /etc/mihomo-rust/config.yaml
fi

# 创建 systemd 服务
sudo tee /etc/systemd/system/mihomo-rust.service > /dev/null << 'EOF'
[Unit]
Description=Mihomo Rust Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mihomo-rust -c /etc/mihomo-rust/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable mihomo-rust

echo ""
echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Edit config: sudo nano /etc/mihomo-rust/config.yaml"
echo "  2. Start service: sudo systemctl start mihomo-rust"
echo "  3. Check status: sudo systemctl status mihomo-rust"
echo "  4. View logs: sudo journalctl -u mihomo-rust -f"
echo ""
echo "Default ports:"
echo "  - Mixed (HTTP+SOCKS5): 7890"
echo "  - API: 9090"
echo ""
