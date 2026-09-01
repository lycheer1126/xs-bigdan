# 高级技术速查（吸收自实战 skill 知识库——冷门但实战命中率高）

## 一、幽灵位 / Cast Attack（Java char→byte 截断，全库最独特）

原理：Java char(16bit)→byte(8bit) 静默截断，`c = chr((k<<8)|T)`——每个危险字节有 255 个候选 Unicode 字符，**WAF 看到中文、后端看到 ASCII 危险字节**。
- 三根因族：A 高 bit 截断（`(byte)ch`/`&0xFF`）；B 位运算折叠（Jetty `%2>` 折叠成 `%2E`）；C 宽松 Unicode 归一化（Fastjson 全角数字、Jackson `sHexValues[ch&0xff]`）
- 实战配方：Tomcat `filename*=UTF-8''1.陪sp`→`1.jsp` 上传；`瘍瘊`=CRLF 注入 SMTP/HttpClient 走私；`阮丯`=路径穿越；Fastjson `{"\x4_type":...}`→`@type`
- CVE 复活：Openfire `%2>%2>%2>%2>` 代替 `%u002e`；GeoServer `Ru%6>time` 绕过 Runtime 关键词；Spring4Shell `name*="㹣౬ᙡ⑳⑳..."` 绕过 class 关键词
- 假点：后端非 Java 直接停；无 WAF 时用字面 payload 即可

## 二、WAF 厂商绕过矩阵（7 家）

- **Cloudflare**：全角字符、`/*!50000UniOn*/SeLeCt`、超长参数名 >128 字符跳过检查
- **AWS WAF**：body 只查前 8KB、正则超时、不自动解 Base64
- **ModSecurity CRS**：PL1 默认弱、按规则 ID 定制绕过、文件字段 >128KB（SecRequestBodyNoFilesLimit）绕过
- **Akamai**：慢 POST、H2 push、penalty box 换新 IP
- **Imperva**：深嵌套 JSON、UTF-8 BOM、WS 升级后不过检
- **F5 ASM**：序列化数据弱检、learning mode 不拦
- **Sucuri**：alt 标签组合
- 通用：chunked 分片、HPP（PHP 尾值/ASP.NET 逗号拼接）、Content-Type 切换 JSON、连接复用第二请求降检
- 假点：WAF 返回 200 但**静默剥 payload**；429 是限速不是 WAF

## 三、反序列化全语言指纹与链选择

- 指纹表：Java `ac ed 00 05`/`rO0AB`；.NET `AAEAAAD`/ViewState `FF01`；Python pickle `80 03`；PHP `O:N:"`；Ruby Marshal `0408`；JSON.NET `$type`
- 链选择：CC6→CC7→CC5 兼容性优先；JDK<8u72 用 CC1/CC3；URLDNS 安全确认探针
- Shiro：固定密钥 AES-CBC（`kPH+bIxk5D2deZiIxcaaaA==` 等），`rememberMe=deleteMe` 是检测信号
- JDK 分段：<8u121 RMI/LDAP 远程类加载；8u121-8u190 只 LDAP；≥8u191 走 LDAP 返回 gadget 或 BeanFactory+EL
- PHP phar：file_exists/getimagesize 等任意文件操作触发；Ruby YAML.load 两代链；.NET ViewState 无 MAC 伪造；Node `_$$ND_FUNC$$_...()`

## 四、PHP 类型混淆（magic hash）

- `md5('240610708')==md5('QNKCDZO')` 都是 `0e\d+`（浮点 0.0）；SHA-1 例 `10932435112`
- 数组绕过：`password[]=x`、strcmp([]) 返回 NULL==0
- JSON 布尔：`{"password":true}`；intval 十六进制/八进制
- **PHP8 行为差异**：非数字字符串不再等于 0——先看 X-Powered-By 确认版本，PHP8 很多老 trick 失效

## 五、EL 注入 polyglot 探测

- 差分定引擎：`${7*7}`→SpEL/Java EL；`%{7*7}`→OGNL；`#{7*7}`→SpEL 变体；`${T(java.lang.Math).random()}` 确认 SpEL
- SpEL RCE：`T(java.lang.Runtime)` + IOUtils 回显；Spring Cloud Gateway CVE-2022-22947（actuator 加路由 SpEL filter）
- OGNL 沙箱绕过：`_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS` + 清 excludedClasses
- Confluence CVE-2021-26084：`queryString=\u0027+{3*3}+\u0027`

## 六、信息泄露专项

- **viewer JS XOR 藏永久钥**：`usePrivateCode` 函数、前 16 字符循环 XOR + hex 解出 COS 永久 AK/SK——**只 grep `AKID` 会当没钥**
- 文档站 GitHub PAT：`ghp_` 打进打包 JS 拉 org 数据；验证 me+个人仓 admin
- Navicat ncx：`SavePassword` 用固定钥 `libcckeylibcckey`/IV `libcciv libcciv` AES-128-CBC 解明文
- 分布式文件 master：`/version` 出 `"Model":"master"` → `/user/list` 拿 AK/SK → `/user/akInfo?ak=` 问身份
- 管理台 CI 仓钥：pipelineId+base64 auth 打 open-api DescribeMyDepots 列私仓

## 七、路径穿越高阶

- **Nginx alias 缺斜杠**：站上有 `/static` 前缀就打 `/static../etc/passwd`（`/static/../` 反被规范化挡掉）
- 仓库根当静态：能 GET 到 package.json → 打 `/config/online.yml`/`production.yml`/`.env`
- 静态桶 .NET 发布物：web.config 被拦打 `App.config`/`*.exe.config`/`bin/*.dll.config`
- 公网 VS Code：`/remote-resource?path=/proc/self/environ` 读进程环境；SSH 私钥 PEM 假钥对照连 Git 主机
- Tomcat `..;/` 路径参数规范化；AJP Ghostcat（8009）；IIS 8.3 短文件名枚举（404 vs 400 差分）

## 八、缓存欺骗/投毒三变体 + 竞态 H2 单包

- 缓存欺骗偷会话页：登录态打开 `原path/x.css`、`;.css`、`%2f.css`，再未登录打同一 URL 拿别人个人页/账单
- unkeyed 头投毒：X-Forwarded-Host/X-Forwarded-Scheme/X-Original-URL 反射即投毒
- Fat GET：GET 带 body 且缓存不含 body；参数 cloaking（`;` 分隔符 Rails 当参数、PHP 当字面量）；Vary 缺失=跨用户缓存
- 竞态 HTTP/2 单包：一个 TCP 段内多流并发（<100μs 调度差），h2load -c 1 -m 50；HTTP/1.1 last-byte 同步；Turbo Intruder gate 同放
- 竞态高危优先级：一次性兑换/券 > 余额/库存 > 邀请奖励 > 验证码确认（CVE-2022-4037 GitLab 邮箱竞态）
