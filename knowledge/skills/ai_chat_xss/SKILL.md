# AI 对话场景 XSS 升级链（self-XSS → 存储型 → 账户接管）

> 来源: 2026-08 实战文章《ai时代下衍生出的通杀: 从self-xss到任意用户接管和任意文件删除》(CChen)
> + Dify XSS / CVE-2026-26023 思路迁移。与 `agents/ai_security/SKILL.md`(prompt 注入/jailbreak)互补:
> 那个打模型,本文件打 AI 业务的前端与客户端。
>
> **核心洞察(同构性通杀)**: AI 业务为抢市场大量复用开源组件/第三方接口/通用模块,
> 同构性极高 → 在 A 厂商 AI 接口挖到的洞,去测 B 厂商相似业务命中率极高。
> 挖到一个 → 立即泛化特征(什么组件/什么模式) → 批量套同类目标。

## 识别信号(Phase 0 指纹命中即读本文件)

- AI 对话/聊天界面: 输入框 + 流式响应(SSE/event-stream)、对话历史、markdown 渲染区
- URL/路径特征: `/chat` `/ai` `/assistant` `/copilot` `/bot` `/gpt`
- JS 依赖特征(Phase 1 js_analysis 命中): marked / markdown-it / highlight.js / dompurify / react-markdown

## 攻击链总览（每一环单独看都是放弃点,链起来是高危）

```
常规注入被过滤 → markdown/代码块注入面 fuzz → self-XSS 判定(无分享≠死局)
  → 业务参数升级(?query= 自动发送 → 存储型) → 换端(web过滤≠客户端/app过滤)
  → 客户端 IPC 提权(读 HttpOnly cookie / 文件操作) → 账户接管
```

**纪律: 本链两次受挫两次转化,是"不固化失败"的教科书案例。投降检测器命中时,
优先按本链的下一环换角度,而不是换漏洞类型。**

## Step 1 注入面 fuzz（web 端，XSS 预检两步法为底）

按以下层级递进测试对话输入框（每层 1-2 个 payload,`<s>XSS</s>` 预检渲染,console 验证执行）:

1. 明文 HTML: `<s>XSS</s>` / `<img src=x onerror=console.log(1)>`
2. markdown 行内: `~123~` / `[点击](javascript:alert(1))` / `![x]("onerror="alert(1))`
3. **代码块围栏（本文核心,前端常只过滤行内不过滤代码块渲染）**——payload = 把 HTML 包进代码块渲染语法,两种等价写法:
   - 波浪线围栏: `~~~<s>123</s>~~~`
   - 反引号围栏: 三个反引号开头 + `<s>123</s>` + 三个反引号结尾（原文实战 payload 即此形态）
   变体: 加语言标注前缀 / 缩进代码块 / 多层围栏嵌套
4. 渲染位置不止对话气泡: 对话标题、重命名会话、分享页、导出 PDF/图片

## Step 2 self-XSS 判定（无分享按钮 ≠ 死局）

- 有分享/协作功能 → 直接是存储型,正常打
- 无分享按钮 → 记为 `SELF_XSS_PENDING`,进 Step 3 升级,**禁止标记为无影响放弃**

## Step 3 业务参数升级（本链的灵魂——用行业通用功能推理目标必有功能）

推理: AI 对话产品普遍有"猜你想问/热门问题/推荐提问"弹窗,点击弹窗 = 前端发一个
携带问题参数的请求(如 `?query={问题}`) → 目标大概率也有同款自动发送入口。

- JS 审计路由与参数: `query` `q` `prompt` `question` `msg` `content`(配合 js_analysis 契约产出)
- 构造: `https://target/chat?query=```<s>123</s>``` `` → 对话落库/历史可见 = 存储型 XSS
- 同理检查: 会话分享链接参数、搜索 `?keyword=` 回显、历史记录标题回填

## Step 4 换端（web 过滤好 ≠ 多端过滤好）

多端渲染引擎不同、过滤代码不同步——web 端解析失败后**必须**换端再试:

- **APK**: `jadx -d out *.apk` → 找 WebView 渲染对话内容的逻辑与过滤函数 → 同款 payload 重测
- **小程序**: 解包 .wxapkg → rich-text 组件渲染路径
- **桌面客户端**(Electron/自研壳): 找本地渲染 HTML 的模块（文件在安装目录/resources）

## Step 5 客户端 IPC 提权（最高危，条件触发: 已有存储型 XSS + 有客户端形态）

客户端 JS 审计高权限 IPC bridge / JSBridge:
- 读 HttpOnly cookie / session 的 IPC 通道（web 层读不到的,客户端桥能读）
- 文件系统操作 / 命令执行类通道
- 构造: 存储型 XSS 触发 → 调 IPC → 证明可取到核心凭据/操作文件 → **立即停,写证据**

## 合规红线（本链特有,进 highrisk 前必读 compliance-rules.md TIER 表）

- 接管验证: 仅用自己注册的两个测试账号互证,**禁止碰真实用户会话**
- IPC 文件操作: 仅在自己机器/授权环境用自建无害测试文件证明能力存在,立即停止;
  **删除任何真实文件 = TIER 3 红线**
- 自动化边界: Agent 跑到"存储型 XSS 确认"即 BLOCKED:HIGH_RISK_AUTHORIZATION,
  IPC 利用与接管验证留给人工书面授权后执行
- 通用 quick-filter 例外: 本链中 self-XSS **不是**无影响——升级路径存在时按链推进
