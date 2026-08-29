# xs-bigdan Web 控制台（webui）

本地攻防控制台：任务管理 / 历史报告 / 配置，插件式模块架构——加模块不用改框架。

```bash
python -X utf8 -m webui.server            # http://127.0.0.1:8865
python -X utf8 -m webui.server --port 9000
```

> Windows 必须带 `-X utf8`（否则中文源码被按 GBK 误读）。仅绑定 127.0.0.1，
> 无鉴权，勿用 `--host 0.0.0.0` 暴露到不可信网络。

## 架构：薄控制面

```
webui/
├── server.py            # FastAPI 入口：模块注册表挂载 + /api/modules + 静态托管
├── core.py              # 项目交互层（纯函数，不依赖 FastAPI）
│                        #   只读 runtime/jobs、runtime/outputs 产物
│                        #   子进程触发 bigdan.py CLI（新建/续跑/停止）
│                        #   删除走 Windows 回收站，路径访问做越界校验
├── routes/              # 后端模块：每个文件 = 一个模块（自动扫描注册）
│   ├── tasks.py         #   任务管理
│   ├── history.py       #   历史报告
│   └── config.py        #   配置
└── static/
    ├── index.html       # 单页壳
    ├── app.js           # 框架：hash 路由 / 模块动态加载 / toast / modal / 轮询
    ├── style.css        # 深色控制台主题
    └── modules/         # 前端模块：与 routes/ 同名对应
        ├── tasks.js
        ├── history.js
        └── config.js
```

设计原则：UI 只做两件事——读 runtime/ 产物展示、以子进程触发 bigdan.py 既有 CLI。
不复制任何 agent 逻辑（延续 xs-bigdan 薄 harness 理念）。

## 新增一个模块（约 10 分钟）

### 1. 后端 `webui/routes/<key>.py`

```python
from fastapi import APIRouter
from .. import core

MODULE = {
    "key": "assets",          # 与前端文件名一致
    "title": "资产",           # 侧边导航显示名
    "icon": "shield",         # app.js ICONS 表里的 key（target/archive/sliders/shield/...）
    "desc": "一句话说明",
    "order": 4,               # 导航排序
}
router = APIRouter(prefix="/api/assets", tags=["assets"])

@router.get("")
def list_all():
    return {"items": []}
```

`routes/__init__.py` 自动扫描注册，无需改任何框架代码。

### 2. 前端 `webui/static/modules/<key>.js`

```js
window.XSModules = window.XSModules || {};
XSModules.assets = (() => {
  let el = null;
  return {
    mount(container) {
      el = container;
      el.innerHTML = `<div class="page-head"><h1>资产</h1></div>`;
      // 用 XS.api("/api/assets") 取数据渲染；XS.toast / XS.modal / XS.esc 可直接用
    },
    unmount() { el = null; },   // 离开页面时清理定时器
  };
})();
```

### 3. 数据读取约定（core.py 已提供）

| 需要 | 用 |
|---|---|
| 任务列表/统计 | `core.list_jobs()` → `{stats, jobs[]}` |
| 任务详情 | `core.job_detail(id)` → summary/runlog/digest/evidence/sessions |
| 读 job 内任意文件 | `core.read_job_file(id, rel)`（自动越界校验） |
| 报告列表/内容 | `core.list_reports()` / `core.read_report(name)` |
| 配置视图 | `core.config_view()`（密钥只显示存在性） |
| 启动/续跑/停止/删除 | `core.start_task/resume_task/stop_job/delete_task` |
| 打开本地目录 | `core.open_dir("jobs", id)` → os.startfile |

前端 `XS.api()` 自动 JSON 编解码 + 错误 toast；轮询用 `XS.poll(fn, ms)`
（框架切页时自动清理，模块 unmount 无需手动 clearInterval）。

## 运行时产物

- 任务状态机：`running`（进程存活）/ `done`（summary 有 ended_at）/ `timed_out` /
  `interrupted`（被停止或异常退出，含无 summary 但已有 BRIEF 痕迹）/ `created`（仅建目录）
- 子进程登记：`runtime/.webui/procs.json`（pid/启动时间/命令，已排除在 git 外）
- 调度器 stdout 存档：`runtime/.webui/bigdan-<id>.out.log`（任务详情页「调度器」tab）
- 危险操作：删除任务 = taskkill 进程树 + jobs 目录移入回收站 + targets.txt 移除该行

## 已知限制

- 单用户本地控制台，无登录鉴权；不要绑 0.0.0.0 公网暴露
- 新建任务要求 targets.txt 可写；LLM key 未配置时任务会启动但 pi 无输出（警告见 bigdan.py）
- 浏览器 MCP 与本服务无关；本服务直接由 Python 托管，无需外部浏览器依赖
