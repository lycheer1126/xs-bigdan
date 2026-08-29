#!/usr/bin/env python3
"""xs-bigdan 工具探测：扫描本机可用工具，输出 Markdown 段供 BRIEF.md 注入。

为什么需要：harness 决定"模型能看见什么"。把本机实际可用的工具清单
动态写进 BRIEF，agent 就不会 which/find 全盘找工具（浪费时间），
也不会误以为装了没有的工具（拿到空输出后空转）。

扫描范围：
1. PATH 中的工具（系统安装 / pip Scripts）
2. 本目录 tools/bin/ 下的本地二进制（{name}.exe / {name}.bat，仓库自带）

用法: python tools/bin/probe_tools.py        # 输出 markdown 段
      python tools/bin/probe_tools.py --json  # 输出 JSON 清单

注意: 本机 python3 可能是 WindowsApps stub，一律用 `python`。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

LOCAL_BIN = Path(__file__).resolve().parent

# (工具名, 一句话用途, 对应 pi-recon 场景)
TOOLS = [
    ("ffuf", "目录/参数模糊测试(快速大字典)", "xsenum.py 的高性能替代,有大字典场景用"),
    ("feroxbuster", "递归目录枚举", "深层目录发现"),
    ("ehole", "指纹识别(EHole 棱洞)", "finger -u <url> 被动指纹辅助;仅指纹模式,禁用其漏洞扫描模块(TIER 合规)"),
    ("slider_captcha_solver", "滑块验证码程序化解题(xs_auth S9)", "复刻前端加密生成 captchaVerification;依赖 pycryptodome/numpy/pillow"),
    ("dirsearch", "目录扫描(常见路径字典)", "目录枚举补充/字典基线"),
    ("browser_probe", "无头浏览器分析(SPA DOM/console/XHR/JS执行/mock登录)", "前端JS驱动优先: Vue chunk枚举/__vue__.$parent/前端签名加密/mock登录"),
    ("nuclei", "漏洞模板扫描", "已知 CVE 批量验证"),
    ("gobuster", "目录/DNS 枚举", "目录与子域枚举"),
    ("cloudfox", "云资产枚举(AWS)", "云环境权限与资产发现(需授权)"),
    ("jwt_tool", "JWT 攻击测试", "JWT 签名爆破/算法混淆/kid注入"),
    ("arjun", "HTTP 参数发现", "隐藏参数枚举"),
    ("subfinder", "子域收集", "资产扩展(需授权范围允许)"),
    ("nmap", "端口/服务扫描", "目标端口与指纹"),
    ("ncat", "端口监听/回连", "反弹/回连验证"),
    ("socat", "端口转发/监听", "流量转发与监听"),
    ("sqlmap", "SQL 注入自动化", "注入点验证(需授权)"),
    ("ysoserial", "Java 反序列化 payload 生成", "Java 链生成(仅授权靶场)"),
    ("httpx", "HTTP 探测(批量URL存活+指纹)", "批量存活与指纹"),
    ("jadx", "APK 反编译", "移动端 APK 逆向"),
    ("cast", "链上合约交互", "智能合约读取/调用"),
    ("strings", "二进制字符串提取", "固件/样本字符串分析"),
]

# 常用 python 库: 有的场景直接 import 用,不用装工具
PY_LIBS = [
    ("requests", "HTTP 请求库"),
    ("Crypto", "密码学(pycryptodome)"),
    ("web3", "以太坊交互"),
    ("bs4", "HTML 解析(BeautifulSoup)"),
    ("ldap3", "LDAP 协议交互"),
    ("pyasn1", "ASN.1 编解码"),
    ("pyasn1_modules", "ASN.1 标准模块"),
    ("playwright", "无头浏览器(配合 browser_probe.py 使用)"),
    ("boto3", "AWS SDK(云资源枚举)"),
    ("impacket", "SMB/LDAP/WinRM 协议(域渗透,需授权)"),
    ("mitmproxy", "HTTPS 中间人抓包(mitmdump 命令行)"),
]


def _local_entry(cmd: str) -> Path | None:
    """本地入口: 先 tools/bin/ 的 {cmd}.exe / .bat / .py / 无扩展, 再 tools/foundry/ 的 {cmd}.exe。"""
    for suffix in (".exe", ".bat", ".py", ""):
        p = LOCAL_BIN / f"{cmd}{suffix}"
        if p.is_file():
            return p
    p = LOCAL_BIN.parent / "foundry" / f"{cmd}.exe"
    if p.is_file():
        return p
    return None


def _has(cmd: str) -> tuple[bool, str]:
    """返回 (可用?, 来源描述)。优先 PATH，其次本地目录。"""
    w = shutil.which(cmd)
    if w:
        return True, w
    p = _local_entry(cmd)
    if p:
        return True, str(p)
    return False, ""


def _py_lib_ok(lib: str) -> bool:
    try:
        r = subprocess.run(
            [sys.executable, "-c", f"import {lib}"],
            capture_output=True,
            timeout=15,
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    available: list[tuple[str, str, str, str]] = []  # (name, desc, scene, where)
    for name, desc, scene in TOOLS:
        ok, where = _has(name)
        if ok:
            available.append((name, desc, scene, where))
    py_ok = [l for l in PY_LIBS if _py_lib_ok(l[0])]

    if "--json" in sys.argv:
        print(json.dumps({
            "python": "python",
            "tools": [t[0] for t in available],
            "py_libs": [l[0] for l in py_ok],
        }, ensure_ascii=False))
        return 0

    out: list[str] = []
    out.append("**本机工具（PATH 或 xs-bigdan/tools/bin/，按需用 `which <name>` 确认后调用；缺失的写 TOOL_MISSING）**")
    if available:
        for name, desc, scene, where in available:
            src = "PATH" if "PATH" in where or "Scripts" in where or "nmap" in where.lower() else "tools/bin"
            out.append(f"- `{name}` — {desc}（{src}）")
    else:
        out.append("- (未探测到额外工具)")
    if py_ok:
        out.append(f"**可用 Python 库（`python -c \"import xxx\"` 确认后直接用）**: {', '.join(l[0] for l in py_ok)}")
    out.append(f"**注意**: 本机 `python3` 可能是商店空壳，一律用 `python`。")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
