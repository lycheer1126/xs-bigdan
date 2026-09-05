# 知识分布规则（分布宪法——新增/回流知识时先读本文件再落笔）

> 目的：解决"一个知识点散在多处且内容有出入"。每个知识点**有且仅有一个家**；
> 其他位置最多出现一行指针。写入前先查本表定家，写入后搜全库确认无重复。

## 唯一权威归属表

| 知识类型 | 唯一的家 | 已按此归位的例子 |
|---|---|---|
| **漏洞类打法**（某类洞怎么打：识别→payload→绕过→验证） | `skills/<漏洞类>/SKILL.md` | ssrf→hunt_ssrf；并发→race_condition；子域接管→subdomain_takeover(未接线) |
| **该漏洞类的速查卡**（特征命中后 1 分钟出第一枪） | `references/decision-trees/<NN>.md` | 树只做索引/合规/速记；细节与 skill 冲突时以 skill 为准 |
| **业务参数扰动原子**（对任意参数可做的变异） | `references/biz-mutations.md` | status→-1 / pageSize=10000 / 置空族 |
| **现场手法精选**（认什么→打哪→算成→假点） | `references/breakthrough-shortlist.md` | 认证绕过/IDOR别停/对象存储矩阵 |
| **冷门高命中技巧**（跨漏洞类的工程级技巧） | `references/advanced-techniques.md` | 幽灵位/WAF厂商矩阵/反序列化指纹 |
| **行为纪律**（会话/写操作/类型取舍红线） | `references/src-discipline.md` | 禁登出/先加后清/CORS不挖/禁停工请示 |
| **合规与操作分级** | `references/compliance-rules.md` | TIER 分级/SRC 允许-禁止 |
| **实战案例**（某站某洞的完整攻击路径复盘） | `experience/<漏洞类>.md` 台账 | ssrf.md 3案例/认证接管.md 6案例 |
| **报告规范/评级/影响写法** | `system.md 报告三闸` + `rating-standard.md` + `impact-escalation.md` | 措辞/降级/危害量化 |
| **Nday/组件利用链** | `references/cve-chains.md` + `references/1day/` | 指纹命中→grep 定位 |
| **SRC 平台规则**(评分/受理/域名归属) | `references/src-rules/<平台>.md` | 目标注记命中平台名时(antsrc 已收) |
| **工具用法**（怎么调自研/第三方工具） | `references/browser-probe-usage.md` 等工具同名文档 | browser_probe 五子命令 |
| **阶段流程/门控** | `prompts/methodology.md`（唯一） | 相位门/读取表 §13 |

## 判定流程（写入前三问）

1. **这是打法、纪律、案例、还是工具用法？** → 按上表定家
2. **这个家已经存在吗？** → 存在则写入该文件对应节；不存在则新建（skill 需 frontmatter + 接线三件套：PHASE_READ_INDEX/§13/触发条件说明）
3. **别处已有旧版本吗？** → 有则旧处改为指针（"已收敛至 X"），**禁止两处同时维护正文**

## 已知归属现状（2026-09-04 收敛后）

- ✅ SSRF：hunt_ssrf 唯一权威（06-ssrf=索引、shortlist §七/cloud §8=指针）
- ✅ 纪律：src-discipline 唯一权威（business_flow §8 只留量化阈值+指针）
- ⚠️ **IDOR 待归位**：business_flow(问3 框架) / shortlist §二(别停表) / 01-idor(速查) 三处共存，
  补充 clown idor 绕过细节时应进 **decision-trees/01-idor.md**（它已是该类速查家）并加
  "手法层无独立 skill，本树即权威" 声明——或未来升级为独立 skill 后按 ssrf 模式收敛
- ⚠️ 其余 29 棵决策树与 skills 的双轨关系按"速查层/手法层"约定运行（decision-trees/README）

## 反模式（看到即清理）

- 同一 payload 表出现在两个文件
- "见 X 文件" 的 X 不存在或内容已漂移
- 纪律性文字写在手法手册里（应指针到 src-discipline）
- 案例细节写进方法论（方法论只放可泛化的流程）
