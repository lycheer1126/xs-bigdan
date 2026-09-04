---
name: api-gateway-bypass
description: >
  API 网关访问控制绕过手册（网关与后端路径规范化不一致 → 越权访问受保护路由）。
  来源：clown skill 知识库 api-gateway-test（503 行）提炼：路径规范化/方法覆盖/版本回退/
  限速绕过/文档泄露/Kong/Nginx/AWS API Gateway 特定绕过。
  触发条件：发现 API 网关特征（403 来自网关而非应用、/api/ 前缀、Kong/Nginx/AWS GW 指纹）。
metadata:
  tags: "api-gateway,path-normalization,access-control-bypass,kong,nginx,rate-limit"
  category: "offensive-security"
---

# API 网关绕过手册（api_gateway_bypass）

> **问题本质**：网关与后端对同一路径的理解不一致——网关按自己的规范化结果做访问控制，
> 后端按自己的规范化结果路由，两者差异 = 绕过空间。命中即未授权访问（高危）。
> **识别信号**：403 页面带网关特征（Kong/Nginx/AWSGW 字样）、`/api/` 前缀路由、
> 同一资源 `/api/x` 403 但功能上明显存在。

## 1. 路径规范化差异（首试，命中率最高）

网关拒 `/api/admin`，但后端把这些都规范化为同一资源：

```bash
# 点号系
/api/./admin        /api/admin/.       /api/./admin/.
# 斜杠系
/api//admin         /api///admin
# URL 编码
/api/%2e/admin      /api/%2e%2e/admin   /api/%2f/admin
# 分号(Spring Boot 系: ; 后被截断)
/api/;/admin        /api/admin;/        /api/.;/admin   /api/;./admin
# 反斜杠(Windows 后端)
/api\admin          /api\\admin
# 混合
/api/%2e;/admin     /api/;./admin
```

## 2. HTTP 方法覆盖

网关只拦 GET/POST，后端框架的方法覆盖头能改写实际动作：

```bash
# 头系
X-HTTP-Method-Override: DELETE      X-HTTP-Method: PUT
X-Method-Override: DELETE           X-HTTP-Method-Override: PATCH
# URL 参数系(部分框架)
?_method=DELETE
```
测试：对 403 的 GET 接口加覆盖头换成敏感方法；或对只拦写的网关，用覆盖头把 GET 变写。

## 3. API 版本回退

`/api/v2/admin` 被保护 → 旧版本常被遗忘：

```
/api/v1/admin   /api/v2.1/admin   /api/admin(无版本)
/api/v3/admin   /api/old/admin    /api/beta/admin
```
版本回退 + 路径规范化（§1）组合是常规组合拳。

## 4. 限速绕过（枚举/爆破场景的持续作业能力）

| 手法 | 做法 |
|---|---|
| XFF 轮换 | `X-Forwarded-For: 随机IP`（后端信任 XFF 计限时有效;每次换） |
| API Key 轮换 | 多账号/多 key 轮流（合规红线:仅授权测试用,不爆破他人 key） |
| 端点变体 | `/api/users` ↔ `/api/users/` ↔ `/api//users` 计数器各算各的 |
| 大小写/编码 | `/API/Users` / `/%61pi/users` 若限速按精确路径计数 |

合规：限速绕过仅用于**维持自己账号内的授权测试流量**，不用于爆破他人凭据（TIER 红线）。

## 5. API 文档泄露（信息收集层，recon 阶段顺手）

```
/swagger-ui.html   /swagger.json   /v2/swagger.json   /v3/api-docs
/api-docs          /openapi.json   /api/swagger.json   /doc  /docs
/kong              /services       /routes             (Kong admin 反代)
```
拿到文档 = 直接枚举全部接口打未授权（配合 §1/§3）；文档接口本身在决策树 18-api-linkage 有账。

## 6. 网关特化绕过

**Kong**：
- 路径规范化：`//admin`、`/admin%2f`、`%2F%2F`（Kong 路由匹配与 upstream 转发的规范化差异）
- 插件级：ACL 插件只看 consumer 组——持有任一有效 key(哪怕低权)带原头重放，部分配置下组检查被绕过

**Nginx**：
- `merge_slashes off;` 时 `//admin` 原样转发 → location 匹配 `/api/` 但后端收到 `//api/`
- `proxy_pass` 带路径 vs 不带的规范化差异（`proxy_pass http://backend/;` 会重写路径）——
  网关 location 拦 `/admin`，转发后路径变形后端命中另一 location

**AWS API Gateway**：
- 资源策略：`Deny` 条件里 IP/路径漏写（如只挡 prod stage 不挡 v1 stage）
- Lambda 授权器：token 缓存键配置不当（`cacheKey` 含被省略的 header）→ 换被省略的 header 复用他人授权缓存

## 7. 测试工具（本机有则用，probe_tools 报告为准）

- **Arjun**：参数发现（隐藏参数 + 方法覆盖探测）
- **Kiterunner**：API 端点快扫（历史路由字典爆破）
- 无工具时：ffuf + paramDict 的参数名扫描（方法论 §1）+ §1 payload 逐条打

## 8. 验证标准

- CONFIRMED：绕过路径访问到受保护资源（响应含真实业务数据），证据=被拒请求 vs 绕过请求对照
- 影响写"绕过了哪层控制、能到达什么"：网关鉴权 → 未授权访问 admin API → 敏感数据读写
- 合规：只证明可达即停，不做横向内网探测；发现的绕过路径不在报告中公开可复现细节（先报 SRC）
