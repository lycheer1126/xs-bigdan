# -*- coding: utf-8 -*-
"""生成 webui 演示数据（demo- 前缀，结构完全对齐 bigdan.py 真实产物契约）。

用法: python gen_demo.py           # 生成到 E:/Agent/xs-bigdan/runtime/
清理: 删除 runtime/jobs/demo-* 与 runtime/outputs/report-*demo* 即可（控制台可删）。
"""
import json
import shutil
from datetime import datetime
from pathlib import Path

ROOT = Path(r"E:/Agent/xs-bigdan/runtime")
JOBS = ROOT / "jobs"
OUT = ROOT / "outputs"
NOW = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def w(p: Path, content: str, encoding: str = "utf-8") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding=encoding)


def finding(vtype, title, status, file, seg):
    return {"type": vtype, "title": title, "file": file, "status": status, "seg": seg}


def demo_www_01():
    j = JOBS / "demo-www-01"
    if j.exists():
        shutil.rmtree(j)
    (j / "evidence").mkdir(parents=True, exist_ok=True)
    w(j / "BRIEF.md", """# BRIEF — demo-www-01
目标: https://www.example.com (演示数据)
白名单: www.example.com, api.example.com
段预算: 每段 300s · 总预算 1200s
## 读取表
- prompts/methodology.md — 方法论(必读, 199 行)
- knowledge/skills/... — 按需读取
""")
    w(j / "session-1.log", """[2026-08-28 09:10:01] === segment 1 start ===
[+] probe: 目标指纹 Spring Boot 2.7 / 前端 Vue SPA (app.js)
[+] GET /api/user/list -> 200 | 1423B | application/json
[+] GET /actuator/health -> 200 (Spring Boot 存在)
[+] 发现 _endpoint_params.json: 3 endpoints, 完整度 0.9
[+] 值池联动: 1 条 HIGH 优先级 id 待验证
[2026-08-28 09:14:32] === segment 1 end === exit=0 findings=1 digest=Y""")
    w(j / "session-2.log", """[2026-08-28 09:14:40] === segment 2 start ===
[+] 值池消费: userId=10086 验证 /api/org/42/members -> 403 (自配对已排除)
[+] POST /api/user/info {userId:10086} -> 200 泄露手机号/身份证 (未授权)
[+] FINDING: CONFIRMED | IDOR | /api/user/info 越权读取任意用户敏感信息
[+] evidence/01-idor-user-info.txt 已保存
[2026-08-28 09:19:05] === segment 2 end === exit=0 findings=1 digest=Y""")
    w(j / "session-3.log", """[2026-08-28 09:19:12] === segment 3 start ===
[+] GET /api/user/export?type=json -> 200 全量用户导出 (未授权)
[+] FINDING: CONFIRMED | 未授权访问 | /api/user/export 全量数据导出
[+] early_stop 建议: 已测完核心面, 建议结束
[2026-08-28 09:23:40] === segment 3 end === exit=0 findings=1 digest=Y""")
    w(j / "digest-1.md", """### RECON_DIGEST (段 1)
目标状态: 指纹已确认(Spring Boot + Vue SPA)
技术栈: Java 17 / Spring Boot 2.7 / MySQL / Redis
攻击面: /api/* REST, actuator 暴露, JS 中 3 个接口带参数
已确认发现: 无
疑似点: /api/user/info 响应含手机号字段, 疑似未授权
已试路径: /actuator/env(403), /actuator/heapdump(404)
下一步建议: 验证 userId 越权 + 值池配对 /api/org/42/members""")
    w(j / "digest-3.md", """### RECON_DIGEST (段 3)
目标状态: 核心接口已测完
已确认发现: IDOR×1 + 未授权导出×1
疑似点: /api/org/{id}/members 403 需更高权限角色
已试路径: userId=10086, 10087 越权成立; export 无需认证
建议结束: 攻击面已覆盖, 建议收工""")
    summary = {
        "id": "demo-www-01", "url": "https://www.example.com", "note": "演示数据-官网主站",
        "segments": [
            {"seg": 1, "exit_code": 0, "findings": 1, "digest_saved": True},
            {"seg": 2, "exit_code": 0, "findings": 1, "digest_saved": True},
            {"seg": 3, "exit_code": 0, "findings": 1, "digest_saved": True},
        ],
        "findings": [
            finding("IDOR", "/api/user/info 越权读取任意用户敏感信息(手机号/身份证)", "CONFIRMED", "evidence/01-idor-user-info.txt", 2),
            finding("未授权访问", "/api/user/export 未授权全量用户导出", "CONFIRMED", "evidence/02-unauth-export.txt", 3),
            finding("信息泄露", "actuator/health 暴露存在(低危)", "INFO", "evidence/03-actuator.txt", 1),
        ],
        "early_stop": True, "timed_out": False,
        "job_timeout_sec": 1200, "seg_timeout_sec": 300,
        "started_at": "2026-08-28 09:10:01", "ended_at": "2026-08-28 09:23:41",
        "elapsed_sec": 820.4, "segments_planned": 3, "segments_ran": 3,
    }
    w(j / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
    w(j / "evidence" / "01-idor-user-info.txt", """=== FINDING: IDOR | /api/user/info 越权 ===
请求: POST /api/user/info
Content-Type: application/json
{"userId": "10086"}
响应: 200 OK
{"code":0,"data":{"name":"张三","phone":"138****1234","idCard":"3702**********1234","balance":12800}}
影响: 任意已登录用户可遍历 userId 读取他人敏感信息; 未授权时可匿名调用
状态: CONFIRMED""")
    w(j / "evidence" / "02-unauth-export.txt", """=== FINDING: 未授权访问 | /api/user/export ===
请求: GET /api/user/export?type=json
响应: 200 OK
{"total": 45231, "rows": [{"id":10001,"name":"***","phone":"***",...}]}
影响: 无需任何认证即可导出全量用户数据(4.5 万条)
状态: CONFIRMED""")
    w(j / "evidence" / "03-actuator.txt", "GET /actuator/health -> 200 {\"status\":\"UP\"} (INFO)")
    w(j / "evidence" / "_endpoint_params.json", json.dumps({
        "_meta": {"js_files_collected": 3, "js_files_analyzed": 3, "analysis_completeness": 0.9, "total_endpoints_extracted": 3},
        "endpoints": [
            {"path": "/api/user/list", "method": "GET", "params_optional": ["page", "size"], "source_files": ["app.js"]},
            {"path": "/api/user/info", "method": "POST", "params_required": ["userId"], "source_files": ["app.js"]},
            {"path": "/api/org/42/members", "method": "GET", "params_optional": ["memberId", "orgId"], "source_files": ["admin.js"]},
        ],
    }, ensure_ascii=False), encoding="utf-8")
    w(j / "evidence" / "_leaked_values.json", json.dumps({"values": [
        {"param": "userId", "value": "10086", "priority": "HIGH", "source_endpoint": "/api/user/list", "source_param": "id"},
        {"param": "orgId", "value": "42", "priority": "HIGH", "source_endpoint": "/api/user/list", "source_param": "orgId"},
    ]}, ensure_ascii=False), encoding="utf-8")
    w(j / "evidence" / "_linkage_results.jsonl",
      '{"ts":"2026-08-28T09:15:12","run":"demo-www-01","endpoint":"/api/user/info","param":"userId","value":"10086","hit":true,"note":"越权成立"}\n'
      '{"ts":"2026-08-28T09:16:40","run":"demo-www-01","endpoint":"/api/org/42/members","param":"orgId","value":"42","hit":false,"note":"403 需角色"}\n')
    w(j / "runlog.jsonl", "\n".join([
        '{"ts":"2026-08-28T09:10:01","run":"demo-www-01","seg":1,"budget_sec":300,"type":"segment_start"}',
        '{"ts":"2026-08-28T09:15:12","run":"demo-www-01","seg":2,"vuln_type":"IDOR","title":"/api/user/info 越权","file":"evidence/01-idor-user-info.txt","status":"CONFIRMED","type":"finding"}',
        '{"ts":"2026-08-28T09:19:30","run":"demo-www-01","seg":3,"vuln_type":"未授权访问","title":"/api/user/export 未授权导出","file":"evidence/02-unauth-export.txt","status":"CONFIRMED","type":"finding"}',
        '{"ts":"2026-08-28T09:23:38","run":"demo-www-01","seg":3,"type":"early_stop"}',
        '{"ts":"2026-08-28T09:23:41","run":"demo-www-01","seg":3,"exit_code":0,"findings":1,"digest_saved":true,"type":"segment_end"}',
    ]))
    print("demo-www-01 done")


def demo_api_02():
    j = JOBS / "demo-api-02"
    if j.exists():
        shutil.rmtree(j)
    (j / "evidence").mkdir(parents=True, exist_ok=True)
    w(j / "BRIEF.md", "# BRIEF — demo-api-02\n目标: https://api.example.com (演示数据-中断任务)")
    w(j / "session-1.log", """[2026-08-28 15:02:11] === segment 1 start ===
[+] GET /v1/status -> 200
[+] 发现 GraphQL 端点 /graphql -> 200 introspection 开启 (疑似点)
[2026-08-28 15:05:03] === segment 1 end === exit=0 findings=0 digest=Y""")
    w(j / "digest-1.md", "### RECON_DIGEST (段 1)\n疑似点: /graphql introspection 开启\n下一步建议: 批量查询字段枚举")
    summary = {
        "id": "demo-api-02", "url": "https://api.example.com", "note": "演示数据-API 网关(手动停止)",
        "segments": [{"seg": 1, "exit_code": 0, "findings": 0, "digest_saved": True}],
        "findings": [],
        "early_stop": False, "timed_out": False,
        "job_timeout_sec": 1200, "seg_timeout_sec": 300,
        "started_at": "2026-08-28 15:02:11",
        "elapsed_sec": 176.0, "segments_planned": 3, "segments_ran": 1,
    }
    w(j / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
    w(j / "runlog.jsonl", '{"ts":"2026-08-28T15:02:11","run":"demo-api-02","seg":1,"budget_sec":300,"type":"segment_start"}\n'
                          '{"ts":"2026-08-28T15:05:03","run":"demo-api-02","seg":1,"exit_code":0,"findings":0,"digest_saved":true,"type":"segment_end"}\n')
    print("demo-api-02 done")


def demo_web_03():
    j = JOBS / "demo-web-03"
    if j.exists():
        shutil.rmtree(j)
    (j / "evidence").mkdir(parents=True, exist_ok=True)
    w(j / "BRIEF.md", "# BRIEF — demo-web-03\n目标: https://web.demo.test (演示数据-超时)")
    w(j / "session-1.log", "[2026-08-28 10:40:00] === segment 1 start ===\n[+] 目录枚举进行中…(黑洞靶场特征)")
    summary = {
        "id": "demo-web-03", "url": "https://web.demo.test", "note": "演示数据-黑洞靶场(超时终止)",
        "segments": [{"seg": 1, "exit_code": 124, "findings": 0, "digest_saved": False}],
        "findings": [], "early_stop": False, "timed_out": True,
        "job_timeout_sec": 1200, "seg_timeout_sec": 300,
        "started_at": "2026-08-28 10:40:00", "ended_at": "2026-08-28 10:58:32",
        "elapsed_sec": 1200.0, "segments_planned": 3, "segments_ran": 1,
    }
    w(j / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
    w(j / "runlog.jsonl", '{"ts":"2026-08-28T10:40:00","run":"demo-web-03","seg":1,"budget_sec":300,"type":"segment_start"}')
    print("demo-web-03 done")


def demo_cms_04():
    j = JOBS / "demo-cms-04"
    if j.exists():
        shutil.rmtree(j)
    (j / "evidence").mkdir(parents=True, exist_ok=True)
    # 纯空目录：无 BRIEF/无日志 —— 代表"已创建未运行"状态
    print("demo-cms-04 done")


def demo_report():
    w(OUT / "report-20260828-092400.md", """# xs-bigdan 渗透测试报告 — demo-www-01（演示数据）

目标: https://www.example.com | 备注: 演示数据-官网主站
时间: 2026-08-28 09:10:01 ~ 09:23:41 | 耗时 820.4s | 3/3 段

## 结论

共确认 2 项中高危漏洞 + 1 项信息泄露：

### CONFIRMED 1. IDOR — /api/user/info 越权读取任意用户敏感信息
- 请求: POST /api/user/info {"userId":"10086"}
- 响应: 200，返回他人手机号/身份证号/余额
- 危害: 可遍历 userId 批量拉取用户隐私数据
- 修复: 服务端校验数据归属，禁止仅凭请求体字段取值

### CONFIRMED 2. 未授权访问 — /api/user/export 全量数据导出
- 请求: GET /api/user/export?type=json（无任何认证头）
- 响应: 200，total=45231 条用户数据
- 修复: 接口增加鉴权与权限校验，导出操作审计留痕

### INFO 3. actuator 端点暴露
- /actuator/health 匿名可达，暴露 Spring Boot 指纹
- 修复: 关闭或鉴权保护 actuator 端点

## 证据
evidence/01-idor-user-info.txt、evidence/02-unauth-export.txt、evidence/03-actuator.txt
""")


if __name__ == "__main__":
    JOBS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    demo_www_01()
    demo_api_02()
    demo_web_03()
    demo_cms_04()
    demo_report()
    print("done")
