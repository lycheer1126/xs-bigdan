---
name: subdomain-takeover
description: >
  子域名接管狩猎手册（CNAME/NS/MX 悬挂记录 → 认领第三方资源 → 可信域内容控制）。
  来源：clown skill 知识库 subdomain-takeover-test（230 行）提炼 + can-i-take-over-xyz 服务商指纹表。
  触发条件：crt.sh/子域枚举发现 CNAME 指向第三方服务 + 目标响应 NXDOMAIN/厂商默认 404。
metadata:
  tags: "subdomain-takeover,cname,dangling-dns,ns-takeover,mx-takeover"
  category: "offensive-security"
---

# 子域名接管手册（subdomain_takeover）

> **为什么值得测**：探测成本 = 子域枚举 + 逐条 CNAME 解析（被动为主），价值 = 可信域下内容控制
> （Cookie 窃取 / OAuth 回调劫持 / 钓鱼 / CSP 白名单绕过），SRC 中危起步、可判高危。
> 定位：recon 阶段子域枚举后顺手核验，linkage 阶段出报告。

## 1. 接管成立四要素

1. `sub.target.com` 有 DNS 记录（CNAME/NS/A）指向外部服务
2. 该外部资源**已注销/未认领**（删了的 S3 桶、下线的 Heroku 应用）
3. 攻击者可在该服务商**注册/认领同名资源**
4. 此后 `sub.target.com` 下的内容由攻击者控制

## 2. 检测流程

```
1. 子域收集: crt.sh / subfinder / browser_probe 证书透明度(库内 passive_recon 有方法论)
2. 逐条解析: dig CNAME sub.target.com +short  (无 dig 用 python dnspython 或在线解析)
3. CNAME 目标返回 NXDOMAIN 或厂商默认错误页 → 对 §3 指纹表
4. 命中可认领指纹 → 在该服务商注册同名资源 → 控制子域内容 = CONFIRMED
```

关键信号：CNAME 目标域本身 NXDOMAIN（域名过期/从未存在）＝最高嫌疑；
HTTP 200 但内容是厂商默认停放页 = 待核验（部分可认领）。

## 3. 服务商指纹表（CNAME 模式 → 响应特征 → 可否认领）

| 服务商 | CNAME 模式 | 指纹（HTTP 响应） | 可认领 |
|---|---|---|---|
| AWS S3 | `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` | 404 `NoSuchBucket` | ✅ 建同名桶 |
| GitHub Pages | `*.github.io` | 404 `There isn't a GitHub Pages site here` | ✅ 建仓库开 Pages |
| Heroku | `*.herokuapp.com` / `*.herokudns.com` | `No such app` | ✅ 建同名应用 |
| Azure | `*.azurewebsites.net` / `*.cloudapp.azure.com` / `*.trafficmanager.net` | 默认页/NXDOMAIN | ✅ 注册同名资源 |
| Shopify | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | ✅ |
| Fastly | CNAME 到 Fastly 边缘 | `Fastly error: unknown domain` | ✅ 服务里加域名 |
| Pantheon | `*.pantheonsite.io` | 带 Pantheon 品牌的 `404 Site Not Found` | ✅ |
| Tumblr | `*.tumblr.com`（自定义域 CNAME） | `There's nothing here` | ✅ |
| WordPress.com | CNAME 到 `*.wordpress.com` | `Do you want to register` | ✅ |
| Zendesk | `*.zendesk.com` | `Help Center Closed` / Zendesk 品牌错误页 | ✅ |
| Unbounce | `*.unbouncepages.com` | `The requested URL was not found` | ✅ |
| Ghost | `*.ghost.io` | `404 Not Found`（Ghost 错误页） | ✅ |
| Surge.sh | `*.surge.sh` | `project not found` | ✅ |
| Fly.io | `*.fly.dev` | Fly.io 默认 404 | ✅ |

> 国内对应：百度云加速/腾讯云 CDN/阿里云 CDN 的自定义源站失效场景同样适用——
> 判据不变：CNAME 目标可被任何人注册同名资源。国内云厂商默认页常带品牌标识，注意与"已认领"区分。

自动化辅助（本机装了才用，probe_tools 会报）：`subjack` / `nuclei -t takeovers/` / `dnsreaper` / `subzy`；
参考表：GitHub `can-i-take-over-xyz`（哪些服务可认领的权威清单）。

## 4. NS / MX 接管（比 CNAME 更高价值）

- **NS 接管**：`sub.target.com NS ns1.deleted-provider.com` → 注册该 NS 的域名即控制整个子域的
  全部 DNS 解析（邮件/任何子域）。定级通常高于 CNAME 接管。
- **MX 接管**：MX 记录指向已过期域名 → 注册该域名即接收 `@sub.target.com` 的全部邮件
  → 重置密码/邀请链接直接进兜 → 账号接管链。检测：`dig MX sub.target.com +short` 逐条验解析。

## 5. 误报防线（对得上才报）

- 通配符 DNS（`*.target.com` 全部解析到同一 IP）会制造大量假 CNAME——先确认目标子域是**单独配置**的记录
- 厂商默认页 ≠ 可认领：部分服务商（如 Cloudflare 未配置 DNS 的挂载）保留资源，必须实际验证"能注册同名"
- 已有内容/正常业务页 = 未失效，跳过
- 证据链：DNS 解析记录 + 目标当前响应（指纹页截图/原文）+ 认领后的控制证明（页面内容）。

## 6. 合规

- 接管验证 = 在第三方服务商注册资源并在自己子域放置标记页（"安全测试"字样）——
  **不做钓鱼、不截获他人 OAuth 流量**；验证后立即释放资源并在报告说明。
- 危害按影响面写：Cookie 作用域（父域 Cookie 可被读取）/ OAuth 回调可劫持的客户端 / 邮件接收能力。
