---
name: mail-code
description: >
  临时邮箱接码手册（mail.tm 免费公开 API，无需 key）——目标站支持邮箱注册/邮箱验证时，
  全自动注册自己的测试账号并接验证码，打通"无凭据 → 登录态"的通道。
  触发条件：契约/JS 显示目标有 register/signup+email 流程、邮箱激活/验证码/找回密码环节。
metadata:
  tags: "mail,register,verification-code,temp-email,auth"
  category: "offensive-security"
---

# 邮箱接码与自动注册（mail_code）

mail.tm 免费临时邮箱，公开 REST API **无需 key**。解决的问题是：目标站有邮箱注册但
BRIEF 没给账号——**注册一个自己的账号 = has_account 成立 = 认证后攻击面（越权/IDOR/业务逻辑）全部解锁**。

工具：`tools/bin/mail_code.py`（纯标准库，任意 python3 可跑）。

## 一键流程（linkage 阶段，发现邮箱注册入口后）

```bash
M=tools/bin/mail_code.py
# 1) 建临时邮箱(输出 address/password/token JSON)
python $M create
# 2) 用 address 去目标站完成注册(注册接口/表单),触发验证邮件
# 3) 轮询等验证码(优先提 6 位码,回退 \b\d{4,8}\b;默认最多 180s 可加 --timeout 300)
python $M poll --address <地址> --password <密码>
#    命中即输出 {"code": "...", "from": "...", "subject": "..."}
# 4) 回目标站完成验证/登录 → 拿到登录态
# 5) **必须落盘**(跨段续命):账号密码写入 evidence/_registered_account.txt
#    (address|password|注册时间),后续段 has_account 自动成立
```

辅助：`python $M list --address <地址> --password <密码>` 查看收件箱。

## 使用纪律

- **国内服务收不到**（微信/淘宝/抖音等屏蔽临时邮箱域）：只适合国际服务或无域屏蔽的国内站。
  目标明确屏蔽临时邮箱域（注册报"邮箱不可用"）→ 换思路（BLOCKED 或转无认证面），别在这耗。
- 域名不定期轮换：**建号前先拉 /domains**（脚本已内置）。
- 同地址重复注册 = 409：前缀随机（脚本已内置）。
- 收件延迟常见 1–3 分钟：`poll` 指数等待，超时不删号（账号可复用，加大 --timeout 重跑 poll）。
- **授权边界**：接码只为打通授权目标的注册/找回/登录链路，验证验证码可爆破/链接可预测/
  令牌复用等漏洞；**不为批量养号**。注册的账号写进报告（SRC 要求测试账号信息）。

## 与测试流程衔接

- **注册后**：优先测邮箱验证码类漏洞——验证码可爆破（重复提交不同码）、返回包可篡改
  （响应里改校验字段）、注册接口可指定他人邮箱、激活链接可预测。
- 已登录则转 business_flow 四问框架（越权/IDOR/业务逻辑）+ 值池联动。
- 注册的账号**登记进报告**（测试账号信息），纪律见 `references/src-discipline.md` §2（写操作先加后清）。
