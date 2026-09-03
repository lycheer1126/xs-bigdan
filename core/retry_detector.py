#!/usr/bin/env python3
"""retry_detector.py — 投降检测(mastermind retry_detector 精简移植)。

检测 agent 段输出中的"过早放弃"模式 → 命中即记录 retry 事件,
下一段 prompt 强制注入重试指令(带 bypass 建议)。

关键改进 vs mastermind 原版: pi agent 结论以中文输出,
原版 25 条英文正则基本失效,此处补充中文模式对(英文保留兼容)。

用法:
    from retry_detector import detect_surrender
    res = detect_surrender(log_text)
    if res["should_retry"]:
        prompt_extra = build_retry_prompt(res["categories"], seg_no)
"""

from __future__ import annotations

import re
from typing import Dict, List

# ------------------------------------------------------------------ 模式库

SURRENDER_PATTERNS: List[dict] = [
    # --- WAF / CDN (英文 + 中文) ---
    {"pattern": r"waf\s+detected", "category": "waf", "severity": "high"},
    {"pattern": r"blocked\s+by\s+(?:the\s+)?waf", "category": "waf", "severity": "high"},
    {"pattern": r"protected\s+by\s+(?:a\s+)?waf", "category": "waf", "severity": "high"},
    {"pattern": r"waf.{0,10}(拦截|防护)", "category": "waf", "severity": "high"},
    {"pattern": r"被.{0,6}(waf|防火墙).{0,6}拦截", "category": "waf", "severity": "high"},
    {"pattern": r"cloudflare|akamai|imperva|incapsula|sucuri|fastly", "category": "cdn", "severity": "medium"},
    # --- 否定断言 ---
    {"pattern": r"no\s+vulnerability\s+found", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"appears?\s+(?:to\s+be\s+)?secure", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"seems\s+(?:to\s+be\s+)?safe", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"nothing\s+(?:interesting|suspicious)\s+found", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"(?:not\s+vulnerable|non-vulnerable)", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"(未发现|没有发现|无(?:可用|任何)).{0,10}(漏洞|安全问题|可利用|入口|线索)", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"看起来.{0,6}(安全|没问题)|应该是安全的", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"(全部|所有).{0,8}(测试|尝试).{0,6}(无果|失败|没发现)", "category": "negative_assertion", "severity": "high"},
    # --- 访问控制阻挡 ---
    {"pattern": r"403\s+forbidden", "category": "access_control", "severity": "medium"},
    {"pattern": r"401\s+unauthorized", "category": "access_control", "severity": "medium"},
    {"pattern": r"access\s+denied", "category": "access_control", "severity": "medium"},
    {"pattern": r"forbidden", "category": "access_control", "severity": "low"},
    {"pattern": r"所有.{0,4}(接口|端点).{0,6}(401|403)|全部被(401|403)", "category": "access_control", "severity": "medium"},
    {"pattern": r"(无法|不能|进不去|没权限).{0,6}(访问|绕过|进入)", "category": "access_control", "severity": "medium"},
    # --- 明确投降 ---
    {"pattern": r"gave\s+up", "category": "surrender", "severity": "critical"},
    {"pattern": r"unable\s+to\s+(?:bypass|exploit|proceed|continue)", "category": "surrender", "severity": "critical"},
    {"pattern": r"could\s+not\s+(?:bypass|exploit|find|identify)", "category": "surrender", "severity": "critical"},
    {"pattern": r"(?:stopped|halted)\s+(?:testing|scanning)", "category": "surrender", "severity": "critical"},
    {"pattern": r"(?:protection|defence)\s+detected", "category": "surrender", "severity": "high"},
    {"pattern": r"放弃|不打算|没(?:有)?办法|无能为力|到此为止|没有思路|不知道怎么(?:继续|入手)|无(?:法|从)下手", "category": "surrender", "severity": "critical"},
    {"pattern": r"(无法|不能|难以).{0,8}(绕过|利用|突破|深入)", "category": "surrender", "severity": "critical"},
    {"pattern": r"时间(?:不够|不足)|预算耗尽|没有更多时间", "category": "surrender", "severity": "medium"},
    # --- 限速 / 封禁 ---
    {"pattern": r"rate[-\s]?limit(?:ed|ing)", "category": "rate_limit", "severity": "medium"},
    {"pattern": r"too\s+many\s+requests", "category": "rate_limit", "severity": "medium"},
    {"pattern": r"blocked", "category": "generic_block", "severity": "low"},
    {"pattern": r"被(?:封|拉黑)|429", "category": "rate_limit", "severity": "medium"},
    {"pattern": r"(受限|限制|不能(?:继续)?请求)", "category": "rate_limit", "severity": "low"},
]

# 通用绕过建议(不区分漏洞类的兜底)
GENERIC_BYPASS: List[str] = [
    "换面:不要死磕同一请求/同一端点,换相邻端点、换参数名、换 HTTP 方法。",
    "换通道:直连 IP、备用域名、子域、旧版 API 路径(/v1 /api2 /internal)。",
    "降级协议:HTTP/1.1→1.0、HTTPS→HTTP、去重头(移除 Accept-Encoding/Origin)。",
    "语义绕过:编码(URL 双编码/Unicode/大小写混淆)、截断(\n 回车/%00)、参数污染(id=1&id=2)。",
    "权限视角:用已拿到的 token/cookie 换身份再试;未认证接口先收集数据再联动。",
    "从 JS 挖新线索:回到 app.js/chunk 里找漏掉的接口、调试开关、隐藏参数。",
]

BY_VULN_CLASS: Dict[str, List[str]] = {
    "sqli": ["用注释混淆 /*!50000SELECT*/", "大小写混淆 SeLeCt/UnIoN", "报错/盲注转时间盲注 SLEEP(2)", "换注入点(header/cookie/JSON body)"],
    "ssrf": ["换协议 file:// gopher:// dict://", "DNS 重绑定", "302 跳转绕过", "URL 解析差异(如 @ 符号、编码点)"],
    "rce": ["换命令分隔符(; | %0a &&)", "参数注入点转移(文件名/模板名)", "分段混淆 bash -c 编码"],
    "idor": ["换 ID 类型(数字→UUID→base64 编码 ID)", "从响应/JS 找真实 ID 池", "批量参数 id=1,2,3 / [1,2,3]"],
    "xss": ["换上下文(属性/事件/JS 变量)", "编码绕过滤(HTML 实体/Unicode)", "DOM XSS:从 sink 反推 source"],
    "lfi": ["双重编码 %252e%252e%252f", "php://filter 包装器", "路径截断 %00 或超长路径"],
    "auth": ["OAuth 参数污染 redirect_uri", "JWT alg:none/弱密钥", "密码重置流程逻辑绕过(先改邮箱再重置)"],
}


# ------------------------------------------------------------------ 检测

def detect_surrender(text: str, max_matches: int = 6) -> dict:
    """对文本做投降模式检测。

    Returns:
        {
          "should_retry": bool,
          "categories": [{"category": str, "severity": str, "matched": str}],
          "top_category": str | None,   # 最高 severity 的类别
        }
    """
    if not text:
        return {"should_retry": False, "categories": [], "top_category": None}
    hits: List[dict] = []
    seen: set = set()
    for p in SURRENDER_PATTERNS:
        if len(hits) >= max_matches:
            break
        m = re.search(p["pattern"], text, re.I)
        if m and p["pattern"] not in seen:
            seen.add(p["pattern"])
            hits.append(
                {
                    "category": p["category"],
                    "severity": p["severity"],
                    "matched": m.group(0)[:60],
                }
            )
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda h: sev_order.get(h["severity"], 9))
    top = hits[0]["category"] if hits else None
    return {"should_retry": bool(hits), "categories": hits, "top_category": top}


def build_retry_prompt(categories: List[dict], seg_no: int, hint: str = "") -> str:
    """生成强制重试提示(注入下一段 user prompt 头部)。"""
    cats = sorted({c["category"] for c in categories})
    if not cats:
        return ""
    lines = [
        "## ⚠️ 上一段疑似过早收手(harness 检测到放弃信号),本段必须继续推进:",
        f"- 检测信号: {', '.join(cats)}",
    ]
    if hint:
        lines.append(f"- 上段疑似点: {hint}")
    lines.append("- 先别下『无漏洞/安全』结论——检查是否漏了:未认证接口全扫、值池联动、JWT/泛查询闭环、403/401 绕过面。")
    for cat in cats:
        if cat == "waf":
            lines.append("- WAF 拦截:限速放慢(3-8s/请求),换编码/分块绕过,高价值点留到后面人工。")
        elif cat == "access_control":
            lines.append("- 401/403 是门不是失败:试路径操纵/方法切换/Header 注入(见 knowledge/references/403-bypass-complete.md)。")
        elif cat == "rate_limit":
            lines.append("- 限速:降低频率(3-5s),等 30s 再试 1 个安全端点确认解封。")
        elif cat == "negative_assertion":
            lines.append("- 『没发现』不等于『不存在』:换面、换字典、换参数再验证一轮,给出具体测过的清单。")
        elif cat == "surrender":
            lines.append("- 换思路继续:从 evidence/ 已有产物找断点(差一步的疑似点优先),或读 knowledge/skills/vuln_classes/SKILL.md 找新攻击面。")
        elif cat == "no_product":
            lines.append("- 上段零产物增量即收工被机械门拦截:真实测试必须留下 evidence/ 落盘产物(指纹/契约/联动记录/漏洞证据文件)或注册 FINDING,纯文字总结不算。")
            lines.append("- 本段第一优先:先按 BRIEF 当前阶段补齐最小产物并落盘(缺什么补什么:recon 段须 _fingerprint.md+契约,联动段须 _linkage_results.jsonl 记录,测试结果每条都记账),再继续新面。")
            lines.append("- 若确实无面可测,请在 RECON_DIGEST 里写明『建议结束』(harness 会做机械裁决),不许零产物静默退出。")
        elif cat in BY_VULN_CLASS:
            lines.append(f"- {cat} 绕过建议: " + "; ".join(BY_VULN_CLASS[cat]))
    lines.append("- 若 3 轮重试后仍无进展,在 RECON_DIGEST 里写明『已穷尽:具体试过什么』,允许结束。")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    # 自检
    test = "试了所有接口都 401 unauthorized,没有思路,放弃深入,未发现漏洞"
    r = detect_surrender(test)
    print(f"should_retry={r['should_retry']} top={r['top_category']} cats={[c['category'] for c in r['categories']]}")
    print(build_retry_prompt(r["categories"], 2))
