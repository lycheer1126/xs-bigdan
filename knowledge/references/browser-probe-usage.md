# browser_probe.py — 无头浏览器分析（高难站核心缺口）

> HTTP 层工具看不见的东西：SPA 渲染后的真实 DOM、console 报错、XHR 请求、
> localStorage 里的 token、动态加载的 JS chunk、前端签名/加密逻辑。
> 这些恰好是高难站的防线核心，`browser_probe.py` 就是补这块的。

## 工具位置与总入口

```
python tools/bin/browser_probe.py <子命令> <参数>
```

四个子命令：`open`（页面体检）、`js`（执行任意 JS）、`chunks`（枚举 JS 文件）、`login`（mock 登录）。

## 子命令用法

### open — 页面体检（第一步）
```
python tools/bin/browser_probe.py open <url> [--wait 2] [--console 20] [--xhr 30]
```
输出：title / 最终 URL / div 数 / script 数 / 表单与输入框 / 前 50 个链接 / localStorage 与 sessionStorage 键 / console 消息 / XHR 请求（方法+状态+URL）。
**信号解读**：console 里 `Vue Router`、`TypeError: xxx is not a function` = SPA 报错可借力；XHR 列表 = 接口地图，直接进 API 测试；storage 里有 token = 前端信任凭证可研究。

### js — 执行任意 JS（深度分析的万能钥匙）
```
python tools/bin/browser_probe.py js <url> '<表达式>' [--wait 2]
```
结果 JSON 化输出。典型打法：
- Vue 实例探测：`Object.keys(document.querySelector('#app').__vue__.$data)`、`document.querySelector('#app').__vue__.$parent`（版本<=2 有效，注意 3.x 用 `__vue_app__`，配 `--wait 3` 等渲染完）
- 全局对象：`Object.keys(window).filter(k => /token|key|user|config/i.test(k))`
- 抓接口配置：`JSON.stringify(window.__CONFIG__ || window._env_ || {})`
- 读 mock 登录逻辑：先 `js <url> "JSON.stringify([...document.scripts].map(s=>s.src))"` 定位 chunk，再 `chunks --save` 下载后本地 grep

### chunks — 枚举并下载全部 JS（Vue chunk 枚举）
```
python tools/bin/browser_probe.py chunks <url> [--wait 3] [--save js_dump/]
```
列出页面加载的所有 JS（含动态 import 的 chunk），`--save` 下载到本地目录。
**打完这一步**：本地 grep 关键信息——`grep -rl "encrypt\|sign\|md5\|AES\|secretKey" js_dump/`，再对命中的文件提取端点与密钥（配合 knowledge/references/js-analysis-*.md）。

### login — mock 登录（前端签名/加密登录分析）
```
python tools/bin/browser_probe.py login <url> <用户名> <密码> [--wait 4] [--xhr 20]
```
自动填表（按 input 的 name/id 匹配 user/password 字段）→ 找"登录"按钮点击 → 输出后续 XHR（看登录接口、签名参数）与 storage（看 token 落地方式）。
**典型用途**：登录参数里出现 `sign=md5(ts+key)`、`ciphertext` 之类 → 配合 `js` 子命令翻登录 chunk 的加密函数，拿到硬编码密钥后可以本地复算签名、构造任意请求。

## 调用规则

1. 高难站（SPA/Vue/React/前端有加密签名）**先 open 后 chunks**，不要上来就 ffuf——目录枚举对 SPA 收效甚微，chunk 里的接口才是真实攻击面。
2. `js` 子命令是只读探测（读内存/DOM），安全合规，随便用。
3. mock 登录用自己注册的测试账号，遵守 compliance-rules.md 的 TIER 分级。
4. 拿到的 JS 文件存到当前工作目录 `js_dump/` 或 evidence 里，供后续段复用；端点表按 js-analysis SKILL 的标准落盘。
