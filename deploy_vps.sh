#!/usr/bin/env bash
# xs-bigdan VPS 一键部署（Ubuntu 20.04+）
# 用法: 把 xs-bigdan.tar.gz 传到服务器家目录后:
#   cd ~ && tar xzf xs-bigdan.tar.gz && bash xs-bigdan/deploy_vps.sh
# 全程只需开头输一次 sudo 密码，总时长约 5-15 分钟(下载为主)。
set -e
cd "$(dirname "$0")"
ROOT=$(pwd)
say(){ echo; echo "===== [$(date +%H:%M:%S)] $1 ====="; }

say "1/8 系统依赖"
sudo apt update -y
sudo apt install -y python3-venv python3-pip curl

say "2/8 Python 虚拟环境 + 项目依赖"
python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

say "3/8 Chromium(浏览器层,下载约150MB)"
python -m playwright install chromium
sudo "$ROOT/.venv/bin/playwright" install-deps chromium \
  || sudo apt install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
     libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
     libxrandr2 libgbm1 libasound2

say "4/8 Node.js 22 + pi agent"
# pi 0.84.1 要求 node>=22.19.0(undici 依赖 node:webidl,Node 20 会崩)——判断 <22 才装
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -c2- | cut -d. -f1)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt install -y nodejs
fi
npm config set registry https://registry.npmmirror.com
sudo npm install -g @earendil-works/pi-coding-agent@0.84.1
command -v pi || { echo "!! pi 安装失败,把本行之前输出发给助手排查"; exit 1; }

say "5/8 ffuf Linux 版"
if [ ! -x tools/bin/ffuf ]; then
  # 国内镜像优先,60s 超时防悬挂(腾讯云直连 GitHub 常年卡死)
  (curl -fsSL -m 60 "https://ghproxy.cn/https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" | tar xz -C tools/bin ffuf) \
    || (curl -fsSL -m 60 https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz | tar xz -C tools/bin ffuf) \
    || echo "!! ffuf 下载失败(非必需,可跳过,任务照跑)"
  chmod +x tools/bin/ffuf 2>/dev/null || true
fi

say "6/8 swap 2G(内存保险)"
if ! swapon --show 2>/dev/null | grep -q swapfile; then
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

say "7/8 密钥检查"
if [ ! -f .env ]; then
  echo "!! 缺 .env(LLM key)。在 MobaXterm 左侧文件面板进入 xs-bigdan 目录,"
  echo "   右键 → New file → 命名 .env,内容照抄本机 E:/Agent/xs-bigdan/.env"
fi
[ -f credentials.txt ] || echo "!! 缺 credentials.txt(测试账号池,可后补,同上方法创建)"

say "8/8 systemd 托管(断SSH不死)"
sudo tee /etc/systemd/system/xs-bigdan.service > /dev/null << EOF
[Unit]
Description=xs-bigdan console
After=network-online.target

[Service]
User=$(whoami)
WorkingDirectory=$ROOT
ExecStart=$ROOT/.venv/bin/python -X utf8 -m webui.server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now xs-bigdan
sleep 2
systemctl status xs-bigdan --no-pager | head -4 || true

cat << 'TIP'

======================================================
 部署脚本跑完。最后一步(鼠标操作,见对话里的第3步):
 在 MobaXterm 建 SSH 隧道,然后本机浏览器开
 http://127.0.0.1:8865
 查服务器日志: journalctl -u xs-bigdan -n 50 --no-pager
======================================================
TIP
