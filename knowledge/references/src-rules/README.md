# SRC 平台规则库（按平台一文件：评分标准/受理范围/域名归属/提交策略）

> 用途：目标属于哪个 SRC 平台，就读哪个平台的规则文件——评分矩阵、无影响清单、
> 同源多洞计数规则、域名归属直接决定"测什么、怎么报、报几家"。
> 通用评级框架（跨平台）在 `references/rating-standard.md`；平台特化参数在本目录。

## 已收录

| 平台 | 文件 | 关键差异 |
|---|---|---|
| AntSRC（蚂蚁） | [antsrc.md](antsrc.md) | 金币=基础×应用系数；同域名同类型≤3；内网IP泄露=无影响；nday 时效规则；koubei 归 ASRC |

## 待收录（规则链接已存，文本到手后按 antsrc.md 模板整理）

- 58 安全：https://security.58.com/notice/detail/48
- 银联安全：https://security.unionpay.com/notice/detail?id=972 （台账已有银联实战案例：业务逻辑三合一/注册接口忽略密码）
- DXMSRC 外部漏洞处理规则 V3.0：bcebos PDF（链接见会话记录）
- 滴滴出行安全：https://sec.didichuxing.com/notice/detail?id=757

## 收录模板（新平台照此结构写）

1. 评分模型（货币/积分 × 应用系数矩阵）
2. 定级锚点（严重→低危各自的判断要点，按 Agent 判定视角提炼）
3. 无影响/不收清单（Agent 判定防坑）
4. 计数与时效规则（同源多洞、同类型上限、nday/时效）
5. 受理范围与域名归属（Scoping 红线）
6. 对 Agent 的操作映射（Scoping/报告/提交策略）
