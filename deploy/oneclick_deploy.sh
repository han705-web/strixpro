#!/bin/bash
# StrixPro One-Click Deploy Script
# 一键部署脚本 - 启动完整的StrixPro服务

set -e

echo "=========================================="
echo "  StrixPro 一键部署"
echo "  AI驱动的自动化安全测试平台"
echo "=========================================="

cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[x]${NC} $1"; }

# 检测Python
PYTHON=""
for cmd in python3 python; do
    if command -v $cmd &> /dev/null; then
        PYTHON=$(command -v $cmd)
        break
    fi
done

if [ -z "$PYTHON" ]; then
    err "Python not found! Please install Python 3.9 or higher."
    exit 1
fi

log "Using Python: $PYTHON"

# 安装依赖
log "Installing dependencies..."
$PYTHON -m pip install -r requirements.txt -q 2>/dev/null || warn "Some deps failed, continuing..."

# 安装StrixPro
log "Installing StrixPro..."
$PYTHON -m pip install -e . -q 2>/dev/null || warn "Installation had warnings"

# 初始化
log "Initializing working directories..."
mkdir -p output plugins config

# 生成默认配置
cat > config/strixpro.json << 'CONFIG'
{
  "proxy": {"http": "", "https": "", "socks5": ""},
  "scan": {"timeout": 30, "max_concurrent": 10, "delay_min": 1.0, "delay_max": 3.0},
  "fingerprint": {"browser": "chrome", "rotate_per_request": false},
  "waf": {"enabled": true, "encoding": "auto", "random_case": true},
  "report": {"format": "markdown", "language": "zh"},
  "output_dir": "./output",
  "plugins_dir": "./plugins",
  "license_key": "",
  "log_level": "INFO"
}
CONFIG
log "Config generated: config/strixpro.json"

# 验证安装
log "Verifying installation..."
$PYTHON -c "from cli.main import cli; print('StrixPro CLI OK')" 2>/dev/null && log "CLI verified" || warn "CLI verification failed"

# 启动Web服务（后台）
if command -v screen &> /dev/null; then
    screen -dmS strixpro $PYTHON -m uvicorn web.app:app --host 0.0.0.0 --port 8765
    log "Web service started (screen session: strixpro)"
elif command -v nohup &> /dev/null; then
    nohup $PYTHON -m uvicorn web.app:app --host 0.0.0.0 --port 8765 > output/server.log 2>&1 &
    log "Web service started (PID: $!, log: output/server.log)"
else
    warn "Could not start background service (no screen/nohup)"
    warn "Start manually: $PYTHON -m uvicorn web.app:app --host 0.0.0.0 --port 8765"
fi

echo ""
echo "=========================================="
echo "  StrixPro 部署完成!"
echo "=========================================="
echo ""
echo "  CLI:    $PYTHON -m cli.main --help"
echo "  Web:    http://localhost:8765"
echo "  API:    http://localhost:8765/docs"
echo "  Config: config/strixpro.json"
echo ""
echo "  快速使用示例:"
echo "  $PYTHON -m cli.main fingerprint list"
echo "  $PYTHON -m cli.main waf generate --type xss --count 10"
echo "  $PYTHON -m cli.main audit https://example.com -o report.md"
echo ""
echo "=========================================="
