# 私有 1day 情报库（knowledge/references/1day/）

> 本库存放**网上没有公开 PoC 的 1day / 私有漏洞情报**——这是知识库最值钱的部分。
> 来源：人工提供（实战渠道/情报交换/未公开研究）。**完整 payload 必须入库**——网上查不到，模型记忆也没有。
>
> 对照：公开经典 CVE（S2-045/Shiro-550/Log4j 等）**不入本库**——模型记忆 + 联网检索即可，
> 避免百科全书化（见 cve-chains.md「通用 CVE 检索策略」）。

## 入库规范（人工提供后按此整理）

1. **一个漏洞一个文件**：`knowledge/references/1day/<编号或名称>.md`，命名含厂商/组件+漏洞点
2. **必填字段**（模板见下）：指纹信号 / 影响版本 / 完整 payload / 验证差分 / 状态标记 / 来源
3. **状态标记**（二选一，首个字段）：
   - `VERIFIED` = 已实战/复现验证过，payload 可用，可放心直接用
   - `PENDING` = 来源情报，未经本机验证，用前必须差分确认（正常请求 vs 攻击请求）
4. **payload 给完整可用形态**（原始请求包 / python 脚本 / curl 命令），能直接复制执行
5. 合规：与 cve-chains 同一 AUTHORIZATION BOUNDARY——SRC 场景只验证不深利用

## 文件模板

```markdown
---
status: PENDING          # VERIFIED | PENDING（未验证情报必须标 PENDING）
component: <厂商/组件名>
vuln: <漏洞类型: RCE/SQLi/SSRF/接管...>
date: 2026-09-01
source: <情报来源: 渠道/报告/交换...>
---

# <组件名> <漏洞点>（<CVE 编号或别名>）

## 指纹（怎么认出它）
- 响应头 / 路径 / 版本特征...

## 影响版本
- <版本范围>

## 完整 Payload
    ```bash
<可直接执行的完整 payload/请求包>
    ```

## 验证差分
- 正常请求 → <预期响应>
- 攻击请求 → <预期响应（证明漏洞存在）>

## 备注
- 利用前置条件 / 绕过点 / 注意事项
```

## 读取机制

指纹命中 → 先 grep 本目录（`grep -rn "<组件名>" knowledge/references/1day/`），
命中 VERIFIED 直接用；PENDING 先差分验证再用。未命中 → 走 cve-chains「通用 CVE 检索策略」。
