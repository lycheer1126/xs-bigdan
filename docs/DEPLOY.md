# 云服务器部署指南（Linux 夜跑形态）

> 目标形态：4核4G 云服务器（Ubuntu 20.04+）上无人值守夜跑。
> 资源账：调度器+webui ≈ 150MB；node pi 单段 ≈ 200-300MB；Chromium 按需 ≈ 400-600MB。
> 任务**串行**执行（并发=1），峰值内存 < 1.2G，4G 足够（建议加 2G swap 保险）。

---

## 1. 代码与密钥上服务器

```bash
# 本机推送（排除运行时数据与密钥）
rsync -av --exclude runtime/ --exclude outputs/ --exclude .env \
      --exclude credentials.txt --exclude __pycache__ --exclude .git \
      /e/Agent/xs-bigdan/ ubuntu@SERVER:~/xs-bigdan/

# 密钥手动放服务器（绝不进 git！）
#   ~/xs-bigdan/.env           ← BIGDAN_LLM_KEY / BIGDAN_LLM_PROVIDER / BIGDAN_LLM_MODEL
#   ~/xs-bigdan/credentials.txt ← 测试账号池（含 scope）
#   cookies 走 webui 建任务时填，不落文件
```

## 2. 环境依赖（Ubuntu 20.04，自带 Python 3.8 可跑；建议 3.10）

```bash
cd ~/xs-bigdan
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# Chromium（browser_probe 需要；apt 装 playwright 系统依赖）
playwright install chromium
playwright install-deps chromium   # 需要 sudo

# Node.js ≥18（pi agent 底座）
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs
npm install -g @earendil-works/pi-coding-agent

# ffuf Linux 版（Windows 的 ffuf.exe 在 Linux 不可用；probe_tools 按名字探测）
curl -sL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz \
  | tar xz -C tools/bin ffuf && chmod +x tools/bin/ffuf
```

## 3. 启动与访问（安全红线）

**webui 无鉴权，绝不能 0.0.0.0 裸奔在公网**——默认绑定 `127.0.0.1`，
本机用 MobaXterm/XShell 的 SSH 隧道访问：`本地 8865 → 127.0.0.1:8865`，
浏览器开 `http://127.0.0.1:8865`。

```bash
cd ~/xs-bigdan && source .venv/bin/activate
python -X utf8 -m webui.server          # 前台试跑，确认无报错
```

## 4. systemd 托管（夜跑的关键：断 SSH 不死）

```bash
sudo tee /etc/systemd/system/xs-bigdan.service << 'EOF'
[Unit]
Description=xs-bigdan console
After=network-online.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/xs-bigdan
ExecStart=/home/ubuntu/xs-bigdan/.venv/bin/python -X utf8 -m webui.server
Restart=on-failure
RestartSec=5
# 任务进程是孤儿设计，杀 webui 不会连带杀任务（stop 用 webui 的停止按钮/taskkill 等价物）

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now xs-bigdan
systemctl status xs-bigdan --no-pager
```

## 5. 夜跑工作流

- **睡前入队**：webui 新建任务（可批量贴 URL + cookie + 想法），队列串行执行，
  一个结束自动下一个；调度器自带停止信号（BLOCKED/建议结束/预算尽），不会空烧
- **定时自动入队**（可选）：
  ```bash
  crontab -e
  # 每晚 23:00 把 targets-night.txt 里的目标入队
  0 23 * * * curl -s -X POST http://127.0.0.1:8865/api/tasks/batch \
    -H 'Content-Type: application/json' \
    -d "{\"urls_text\": $(python3 -c 'import json,sys;print(json.dumps(open("/home/ubuntu/targets-night.txt").read()))'), \"note\": \"夜跑批\"}"
  ```
- **早上收菜**：webui 任务卡片看状态/发现数，`outputs/report-*.md` 看报告；
  `journalctl -u xs-bigdan -n 100` 看调度日志

## 6. 与 Windows 本机的差异须知

| 项 | 说明 |
|---|---|
| 停止按钮 | 已适配：POSIX 走 /proc 子树 SIGKILL（连带 chromium） |
| 删除任务 | POSIX 直接 rmtree（无回收站），删除前想清楚 |
| ffuf | 必须换 Linux 二进制（见 §2），否则 agent 探测不到该工具 |
| GBK | Linux 全 UTF-8，编码坑天然消失 |
| 出口 IP | 所有测试流量从云服务器 IP 发出——SRC 侧看到的是数据中心 IP，速率红线照旧遵守 |

## 7. 资源与运维

```bash
# swap 保险（4G 机器建议加）
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile \
  && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 磁盘：jobs/ 证据与 jsdump 会累积，定期归档
du -sh ~/xs-bigdan/runtime/jobs/* | sort -h
```
