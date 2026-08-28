#!/usr/bin/env python3
"""linkage.py — 值池联动引擎(mastermind.analysis.linkage 自包含移植)。

确定性数据层:JS 参数需求表(_endpoint_params.json) × 响应值池(_leaked_values.json)
→ PairingEngine 自动生成联动配对(UnconsumedPair),供 pi agent 按配对注入测试。

来源: mastermind-bug-bounty 2.0.0 mastermind/analysis/linkage.py
改动:
  1. 内联依赖(ValueStatus/MethodFallback/6 dataclass/read_json/write_json/now_iso)
  2. load_linkage_state 适配 xs-bigdan 目录(优先 evidence/,其次 findings/,其次根)
  3. 文件注释中文化

用法:
    from linkage import EndpointRegistry, ValuePool, PairingEngine, check_pair_completeness
    reg = EndpointRegistry.from_file(job_dir/"evidence"/"_endpoint_params.json")
    pool = ValuePool.from_file(job_dir/"evidence"/"_leaked_values.json")
    eng = PairingEngine(reg, pool)
    pairs = eng.match()                       # 全部未消费配对(CRITICAL 优先)
    result = check_pair_completeness(pairs)   # 完整性门控:有无 HIGH 未消费
    matrix = build_method_fallback_matrix("/api/x", "GET", 405)  # 方法回退矩阵
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ================================================================ 内联依赖

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: str | Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return {}


def write_json(path: str | Path, data: dict, indent: int = 2) -> bool:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=indent, ensure_ascii=False)
        os.replace(tmp, str(path))
        return True
    except (PermissionError, OSError):
        return False


class ValueStatus(str, Enum):
    PENDING = "pending"
    CONSUMING = "consuming"
    CONSUMED = "consumed"
    SKIPPED = "skipped"


class MethodFallback(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


@dataclass
class ValueEntry:
    value: str
    status: ValueStatus = ValueStatus.PENDING
    discovered_at: str = ""
    source_endpoint: str = ""
    source_param: str = ""
    priority: str = "MEDIUM"
    consumed_endpoints: list[str] = field(default_factory=list)
    unconsumed_endpoints: list[str] = field(default_factory=list)


@dataclass
class EndpointParamRequirement:
    endpoint: str
    method: str
    content_type: str = ""
    auth: str = ""
    params_required: list[str] = field(default_factory=list)
    params_optional: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class UnconsumedPair:
    value_entry: ValueEntry
    endpoint: str
    param_name: str
    method: str
    fallback_methods: list[str] = field(default_factory=list)
    priority: str = "MEDIUM"
    reason: str = ""


@dataclass
class LinkageCheckResult:
    passed: bool
    total_pairs: int = 0
    consumed_pairs: int = 0
    unconsumed_pairs: int = 0
    unconsumed: list[UnconsumedPair] = field(default_factory=list)
    critical_unconsumed: list[UnconsumedPair] = field(default_factory=list)
    block_transition: bool = False
    summary: str = ""


@dataclass
class JSAnalysisMeta:
    js_files_collected: int = 0
    js_files_analyzed: int = 0
    js_files_skipped: list[str] = field(default_factory=list)
    skipped_reason: str = ""
    analysis_completeness: float = 0.0
    files_detail: dict[str, dict] = field(default_factory=dict)
    total_endpoints_extracted: int = 0
    total_secrets_found: int = 0
    total_routes_found: int = 0
    warnings: list[str] = field(default_factory=list)
    generated_at: str = ""


@dataclass
class JSAnalysisCheckResult:
    passed: bool
    meta: JSAnalysisMeta | None = None
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: str = ""


# ================================================================ 知识常量

PARAM_ALIASES: dict[str, str] = {
    "uid": "uid", "userId": "uid", "user_id": "uid", "userid": "uid",
    "userNo": "uid", "userno": "uid", "memberId": "uid", "member_id": "uid",
    "orgId": "orgId", "org_id": "orgId", "orgid": "orgId",
    "tenantId": "orgId", "tenant_id": "orgId",
    "orderId": "orderId", "order_id": "orderId", "orderid": "orderId",
    "tradeNo": "orderId", "tradeno": "orderId",
    "token": "token", "accessToken": "token", "access_token": "token",
    "apiKey": "token", "apikey": "token", "api_key": "token",
    "secretKey": "token", "secret_key": "token",
    "email": "email", "mail": "email", "eMail": "email",
    "phone": "phone", "mobile": "phone", "tel": "phone",
    "phoneNumber": "phone", "phone_number": "phone",
    "username": "username", "userName": "username", "account": "username",
    "nickname": "username", "nickName": "username",
    "page": "page", "pageNum": "page", "pageNo": "page", "pageIndex": "page",
    "pageSize": "pageSize", "page_size": "pageSize", "limit": "pageSize",
}

SEMANTIC_GROUPS: dict[str, list[str]] = {
    "id_like": ["uid", "orgId", "orderId", "id", "userId", "user_id", "org_id", "order_id", "memberId", "tenantId", "buyerId"],
    "string_like": ["username", "email", "phone", "accountName", "name", "nickname", "keyword", "search", "query"],
    "auth_like": ["token", "apiKey", "api_key", "accessToken", "secretKey", "csrfToken", "Authorization", "X-API-Key"],
    "url_like": ["url", "redirect", "redirect_uri", "callback", "file_url", "image_url", "path", "file"],
}

METHOD_FALLBACK_ORDER: list[str] = ["GET", "POST", "PUT", "PATCH", "DELETE"]
CONTENT_TYPE_VARIANTS: list[str] = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]
METHOD_FALLBACK_TRIGGER_CODES: set[int] = {405, 500, 415, 400, 501, 503}

KNOWN_THIRD_PARTY_PATTERNS: list[str] = [
    "lodash", "moment", "jquery", "bootstrap", "vue.runtime",
    "react-dom", "react.production", "core-js", "regenerator",
    "polyfills", "webpack-runtime", "zone.js", "popper",
    "axios.min", "chart.js", "echarts", "d3.", "three.",
    "swiper", "dayjs", "marked", "highlight", "codemirror",
    "tinymce", "ckeditor", "quill", "prism", "mathjax",
    "socket.io.min", "firebase", "supabase",
]

REQUIRED_ENDPOINT_FIELDS: list[str] = ["method", "source_files"]


# ================================================================ 基础函数

def canonical_param_name(raw: str) -> str:
    return PARAM_ALIASES.get(raw, raw.lower())


def get_fallback_methods(primary_method: str, status_code: int | None = None) -> list[str]:
    if status_code is not None and status_code not in METHOD_FALLBACK_TRIGGER_CODES:
        return []
    primary = primary_method.upper()
    return [method for method in METHOD_FALLBACK_ORDER if method != primary]


def get_content_type_variants() -> list[str]:
    return CONTENT_TYPE_VARIANTS[:]


# ================================================================ ValuePool

class ValuePool:
    def __init__(self) -> None:
        self._pool: dict[str, list[ValueEntry]] = {}

    def add_value(self, param_name: str, value: str, source_endpoint: str = "", source_param: str = "", priority: str = "MEDIUM") -> ValueEntry:
        canonical = canonical_param_name(param_name)
        if canonical not in self._pool:
            self._pool[canonical] = []
        for entry in self._pool[canonical]:
            if entry.value == str(value):
                return entry
        entry = ValueEntry(
            value=str(value),
            status=ValueStatus.PENDING,
            discovered_at=now_iso(),
            source_endpoint=source_endpoint,
            source_param=param_name,
            priority=priority,
        )
        self._pool[canonical].append(entry)
        return entry

    def get_values(self, param_name: str, status: ValueStatus | None = None) -> list[ValueEntry]:
        canonical = canonical_param_name(param_name)
        if canonical not in self._pool:
            return []
        if status is None:
            return self._pool[canonical]
        return [entry for entry in self._pool[canonical] if entry.status == status]

    def mark_consumed(self, param_name: str, value: str, endpoint: str) -> None:
        canonical = canonical_param_name(param_name)
        for entry in self._pool.get(canonical, []):
            if entry.value == str(value):
                if endpoint not in entry.consumed_endpoints:
                    entry.consumed_endpoints.append(endpoint)
                if endpoint in entry.unconsumed_endpoints:
                    entry.unconsumed_endpoints.remove(endpoint)
                if not entry.unconsumed_endpoints and entry.status == ValueStatus.CONSUMING:
                    entry.status = ValueStatus.CONSUMED
                break

    def set_unconsumed_endpoints(self, param_name: str, value: str, endpoints: list[str]) -> None:
        canonical = canonical_param_name(param_name)
        for entry in self._pool.get(canonical, []):
            if entry.value == str(value):
                remaining = [endpoint for endpoint in endpoints if endpoint not in entry.consumed_endpoints]
                entry.unconsumed_endpoints = remaining
                if remaining and entry.status == ValueStatus.PENDING:
                    entry.status = ValueStatus.CONSUMING
                elif not remaining:
                    entry.status = ValueStatus.CONSUMED
                break

    def has_pending(self) -> bool:
        return any(
            entry.status in (ValueStatus.PENDING, ValueStatus.CONSUMING)
            for entries in self._pool.values()
            for entry in entries
        )

    def get_param_names(self) -> list[str]:
        return list(self._pool.keys())

    def all_entries(self) -> list[tuple[str, ValueEntry]]:
        return [(param_name, entry) for param_name, entries in self._pool.items() for entry in entries]

    def to_dict(self) -> dict:
        result: dict[str, dict] = {}
        for param_name, entries in self._pool.items():
            result[param_name] = {
                "values": [
                    {
                        "value": entry.value,
                        "status": entry.status.value,
                        "discovered_at": entry.discovered_at,
                        "source_endpoint": entry.source_endpoint,
                        "source_param": entry.source_param,
                        "priority": entry.priority,
                        "consumed_endpoints": entry.consumed_endpoints,
                        "unconsumed_endpoints": entry.unconsumed_endpoints,
                    }
                    for entry in entries
                ]
            }
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ValuePool":
        pool = cls()
        for param_name, param_data in data.items():
            entries: list[ValueEntry] = []
            for raw in param_data.get("values", []):
                entries.append(
                    ValueEntry(
                        value=raw.get("value", ""),
                        status=ValueStatus(raw.get("status", "pending")),
                        discovered_at=raw.get("discovered_at", ""),
                        source_endpoint=raw.get("source_endpoint", ""),
                        source_param=raw.get("source_param", param_name),
                        priority=raw.get("priority", "MEDIUM"),
                        consumed_endpoints=raw.get("consumed_endpoints", []),
                        unconsumed_endpoints=raw.get("unconsumed_endpoints", []),
                    )
                )
            pool._pool[param_name] = entries
        return pool

    @classmethod
    def from_file(cls, path: str | Path) -> "ValuePool":
        data = read_json(path)
        if not data:
            return cls()
        if "values" in data and isinstance(data["values"], list):
            # 扁平格式: {"values": [{param,value,priority,source_endpoint,source_param}, ...]}
            pool = cls()
            for raw in data["values"]:
                pool.add_value(
                    raw.get("param", ""),
                    raw.get("value", ""),
                    source_endpoint=raw.get("source_endpoint", ""),
                    source_param=raw.get("source_param", ""),
                    priority=raw.get("priority", "MEDIUM"),
                )
            return pool
        return cls.from_dict(data)

    def to_file(self, path: str | Path) -> bool:
        return write_json(path, self.to_dict())


# ================================================================ EndpointRegistry

class EndpointRegistry:
    def __init__(self) -> None:
        self._endpoints: dict[str, EndpointParamRequirement] = {}

    def add(self, endpoint: str, method: str, content_type: str = "", auth: str = "", params_required: list[str] | None = None, params_optional: list[str] | None = None, source_files: list[str] | None = None, notes: str = "") -> EndpointParamRequirement:
        requirement = EndpointParamRequirement(
            endpoint=endpoint,
            method=method.upper(),
            content_type=content_type,
            auth=auth,
            params_required=params_required or [],
            params_optional=params_optional or [],
            source_files=source_files or [],
            notes=notes,
        )
        self._endpoints[endpoint] = requirement
        return requirement

    def get(self, endpoint: str) -> EndpointParamRequirement | None:
        return self._endpoints.get(endpoint)

    def all_endpoints(self) -> list[str]:
        return list(self._endpoints.keys())

    def all_requirements(self) -> list[EndpointParamRequirement]:
        return list(self._endpoints.values())

    def get_all_param_names(self) -> set[str]:
        params: set[str] = set()
        for requirement in self._endpoints.values():
            for param in requirement.params_required + requirement.params_optional:
                params.add(canonical_param_name(param))
        return params

    @classmethod
    def from_file(cls, path: str | Path) -> "EndpointRegistry":
        """支持两种契约格式:
        1) mastermind 原版 dict 格式: {"endpoints": {"/api/x": {...}}}
        2) xs-bigdan 契约 list 格式: {"endpoints": [{"path": "/api/x", "method": "GET", ...}]}
        """
        data = read_json(path)
        registry = cls()
        raw = data.get("endpoints")
        if raw is None:
            raw = {key: value for key, value in data.items() if not key.startswith("_") and isinstance(value, dict)}
        if isinstance(raw, list):
            for info in raw:
                if not isinstance(info, dict):
                    continue
                endpoint = info.get("path") or info.get("endpoint") or ""
                if isinstance(endpoint, str) and (endpoint.startswith("/") or endpoint.startswith("http")):
                    registry.add(
                        endpoint=endpoint,
                        method=info.get("method", "GET"),
                        content_type=info.get("content_type", ""),
                        auth=info.get("auth", ""),
                        params_required=info.get("params_required", []),
                        params_optional=info.get("params_optional", []),
                        source_files=info.get("source_files", []),
                        notes=info.get("notes", ""),
                    )
        elif isinstance(raw, dict):
            for endpoint, info in raw.items():
                if not isinstance(info, dict):
                    continue
                if isinstance(endpoint, str) and (endpoint.startswith("/") or endpoint.startswith("http")):
                    registry.add(
                        endpoint=endpoint,
                        method=info.get("method", "GET"),
                        content_type=info.get("content_type", ""),
                        auth=info.get("auth", ""),
                        params_required=info.get("params_required", []),
                        params_optional=info.get("params_optional", []),
                        source_files=info.get("source_files", []),
                        notes=info.get("notes", ""),
                    )
        return registry


# ================================================================ PairingEngine

class PairingEngine:
    def __init__(self, registry: EndpointRegistry, pool: ValuePool):
        self.registry = registry
        self.pool = pool

    def match(self, semantic_expand: bool = True, include_optional: bool = True) -> list[UnconsumedPair]:
        pairs: list[UnconsumedPair] = []
        for requirement in self.registry.all_requirements():
            params_to_check = list(requirement.params_required)
            if include_optional:
                params_to_check.extend(requirement.params_optional)
            for param_name in params_to_check:
                canonical = canonical_param_name(param_name)
                matched_values = self._match_values(canonical, requirement.endpoint, semantic_expand)
                for entry in matched_values:
                    if entry.source_endpoint and entry.source_endpoint == requirement.endpoint:
                        # 源端点泄露的值回注源端点自身无新信息,排除自配对
                        continue
                    pairs.append(
                        UnconsumedPair(
                            value_entry=entry,
                            endpoint=requirement.endpoint,
                            param_name=param_name,
                            method=requirement.method,
                            fallback_methods=get_fallback_methods(requirement.method),
                            priority=entry.priority,
                            reason=f"{entry.source_endpoint} → {requirement.endpoint} (参数 {param_name} = {entry.value})",
                        )
                    )
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        pairs.sort(key=lambda pair: priority_order.get(pair.priority, 2))
        return pairs

    def _match_values(self, canonical_param: str, endpoint: str, semantic_expand: bool = False) -> list[ValueEntry]:
        results: list[ValueEntry] = []
        for entry in self.pool.get_values(canonical_param):
            if endpoint not in entry.consumed_endpoints and entry.status != ValueStatus.SKIPPED:
                results.append(entry)
        if semantic_expand:
            group_key = self._find_semantic_group(canonical_param)
            if group_key:
                for related_param in SEMANTIC_GROUPS.get(group_key, []):
                    if related_param == canonical_param:
                        continue
                    for entry in self.pool.get_values(related_param):
                        if endpoint not in entry.consumed_endpoints and entry.status != ValueStatus.SKIPPED:
                            results.append(entry)
        seen: set[str] = set()
        unique: list[ValueEntry] = []
        for entry in results:
            if entry.value not in seen:
                seen.add(entry.value)
                unique.append(entry)
        return unique

    @staticmethod
    def _find_semantic_group(param: str) -> str | None:
        for group_key, members in SEMANTIC_GROUPS.items():
            if param in members:
                return group_key
        return None

    def sync_consumption_state(self) -> None:
        for param_name, entry in self.pool.all_entries():
            unconsumed: list[str] = []
            for requirement in self.registry.all_requirements():
                canonical_params = {canonical_param_name(param) for param in requirement.params_required + requirement.params_optional}
                if param_name in canonical_params and requirement.endpoint not in entry.consumed_endpoints:
                    unconsumed.append(requirement.endpoint)
            self.pool.set_unconsumed_endpoints(param_name, entry.value, unconsumed)


# ================================================================ 门控与状态

def check_pair_completeness(pairs: list[UnconsumedPair], block_on_critical: bool = True) -> LinkageCheckResult:
    total = len(pairs)
    consumed = sum(1 for pair in pairs if pair.value_entry.status == ValueStatus.CONSUMED)
    unconsumed_list = [pair for pair in pairs if pair.value_entry.status != ValueStatus.CONSUMED]
    critical = [pair for pair in unconsumed_list if pair.priority in ("CRITICAL", "HIGH")]
    block = bool(block_on_critical and critical)
    lines = [
        f"Pair Completeness Check: {'PASSED' if not block else 'BLOCKED'}",
        f"  Total pairs: {total}",
        f"  Consumed: {consumed}",
        f"  Unconsumed: {len(unconsumed_list)}",
        f"  Critical/HIGH unconsumed: {len(critical)}",
    ]
    if critical:
        lines.append("  Critical unconsumed pairs:")
        for pair in critical[:10]:
            lines.append(f"    - [{pair.priority}] {pair.reason}")
        if len(critical) > 10:
            lines.append(f"    ... and {len(critical) - 10} more")
    return LinkageCheckResult(
        passed=not block,
        total_pairs=total,
        consumed_pairs=consumed,
        unconsumed_pairs=len(unconsumed_list),
        unconsumed=unconsumed_list,
        critical_unconsumed=critical,
        block_transition=block,
        summary="\n".join(lines),
    )


def load_linkage_state(job_dir: str | Path) -> tuple[EndpointRegistry, ValuePool]:
    """加载联动状态:优先 evidence/,其次 findings/,其次目录根(xs-bigdan 适配)。"""
    base = Path(job_dir)
    search_dirs = [base / "evidence", base / "findings", base]
    ep_path = vp_path = None
    for d in search_dirs:
        p = d / "_endpoint_params.json"
        if p.is_file():
            ep_path = p
            break
    for d in search_dirs:
        p = d / "_leaked_values.json"
        if p.is_file():
            vp_path = p
            break
    registry = EndpointRegistry.from_file(ep_path) if ep_path else EndpointRegistry()
    pool = ValuePool.from_file(vp_path) if vp_path else ValuePool()
    return registry, pool


def save_linkage_state(job_dir: str | Path, pool: ValuePool) -> bool:
    base = Path(job_dir)
    ev = base / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    return pool.to_file(ev / "_leaked_values.json")


def build_method_fallback_matrix(endpoint: str, primary_method: str, status_code: int) -> list[dict[str, Any]]:
    fallback_methods = get_fallback_methods(primary_method, status_code)
    if not fallback_methods:
        return []
    matrix: list[dict[str, Any]] = []
    for method in fallback_methods:
        if method in ("GET", "DELETE", "OPTIONS", "HEAD"):
            matrix.append({"method": method, "content_type": None, "description": f"{method} {endpoint} (fallback from {primary_method} {status_code})"})
        else:
            for content_type in CONTENT_TYPE_VARIANTS:
                matrix.append({
                    "method": method,
                    "content_type": content_type,
                    "description": f"{method} {endpoint} Content-Type={content_type} (fallback from {primary_method} {status_code})",
                })
    return matrix


def is_known_third_party(filename: str) -> bool:
    fn_lower = filename.lower()
    return any(pattern in fn_lower for pattern in KNOWN_THIRD_PARTY_PATTERNS)


def extract_js_analysis_meta(endpoint_params: dict) -> JSAnalysisMeta:
    meta_raw = endpoint_params.get("_meta", {})
    if not meta_raw:
        return JSAnalysisMeta(warnings=["_meta section missing — analysis tracking not enabled"])
    files_detail = meta_raw.get("files_detail", {})
    if not isinstance(files_detail, dict):
        files_detail = {}
    return JSAnalysisMeta(
        js_files_collected=meta_raw.get("js_files_collected", 0),
        js_files_analyzed=meta_raw.get("js_files_analyzed", 0),
        js_files_skipped=meta_raw.get("js_files_skipped", []),
        skipped_reason=meta_raw.get("skipped_reason", ""),
        analysis_completeness=float(meta_raw.get("analysis_completeness", 0)),
        files_detail=files_detail,
        total_endpoints_extracted=meta_raw.get("total_endpoints_extracted", len(endpoint_params.get("endpoints", endpoint_params)) - (1 if "_meta" in endpoint_params else 0)),
        total_secrets_found=meta_raw.get("total_secrets_found", 0),
        total_routes_found=meta_raw.get("total_routes_found", 0),
        warnings=list(meta_raw.get("warnings", [])),
        generated_at=meta_raw.get("generated_at", ""),
    )


def check_js_analysis_completeness(endpoint_params: dict, min_endpoints: int = 3, min_completeness: float = 0.8) -> JSAnalysisCheckResult:
    failures: list[str] = []
    warnings: list[str] = []
    endpoints = endpoint_params.get("endpoints", {})
    if not endpoints:
        endpoints = {key: value for key, value in endpoint_params.items() if not key.startswith("_")}
    if not endpoints and endpoint_params and not any(key.startswith("_") for key in endpoint_params):
        endpoints = dict(endpoint_params)
    meta = extract_js_analysis_meta(endpoint_params)
    if not endpoint_params:
        failures.append("_endpoint_params.json is empty or missing")
        return JSAnalysisCheckResult(passed=False, meta=meta, failures=failures, summary="BLOCKED: _endpoint_params.json is empty")
    if not endpoints:
        failures.append("No endpoints found in _endpoint_params.json")
    if meta.js_files_collected == 0:
        failures.append("js_files_collected = 0 — no JS files were downloaded")
    else:
        if meta.js_files_analyzed == 0:
            failures.append(f"js_files_analyzed = 0 — {meta.js_files_collected} JS files were downloaded but NONE were deep-read")
        else:
            unanalyzed = [
                filename
                for filename, detail in meta.files_detail.items()
                if isinstance(detail, dict) and not detail.get("analyzed", False) and not is_known_third_party(filename)
            ]
            if unanalyzed:
                failures.append(f"{len(unanalyzed)} non-3rd-party JS files were not analyzed: {unanalyzed[:5]}{' ...' if len(unanalyzed) > 5 else ''}")
    if meta.analysis_completeness < min_completeness:
        failures.append(f"analysis_completeness = {meta.analysis_completeness:.0%} < required {min_completeness:.0%}")
    if meta.total_endpoints_extracted < min_endpoints:
        failures.append(f"total_endpoints_extracted = {meta.total_endpoints_extracted} < min {min_endpoints}")
    missing_fields: list[str] = []
    for endpoint_name, endpoint_info in endpoints.items():
        if not isinstance(endpoint_info, dict):
            continue
        for field_name in REQUIRED_ENDPOINT_FIELDS:
            if not endpoint_info.get(field_name):
                missing_fields.append(f"{endpoint_name}: missing '{field_name}'")
    if missing_fields:
        failures.append(f"{len(missing_fields)} endpoints have missing required fields")
        for missing in missing_fields[:5]:
            failures.append(f"  - {missing}")
        if len(missing_fields) > 5:
            failures.append(f"  ... and {len(missing_fields) - 5} more")
    passed = len(failures) == 0
    summary_lines = [
        f"JS Analysis Completeness: {'PASSED' if passed else 'BLOCKED'}",
        f"  Files: {meta.js_files_analyzed}/{meta.js_files_collected} analyzed (completeness: {meta.analysis_completeness:.0%})",
        f"  Endpoints extracted: {meta.total_endpoints_extracted}",
    ]
    for failure in failures:
        summary_lines.append(f"  FAIL: {failure}")
    for warning in meta.warnings + warnings:
        summary_lines.append(f"  WARN: {warning}")
    return JSAnalysisCheckResult(
        passed=passed,
        meta=meta,
        failures=failures,
        warnings=meta.warnings + warnings,
        summary="\n".join(summary_lines),
    )


# ================================================================ 自检

if __name__ == "__main__":
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    # 构造端点需求表(模拟 pi agent JS 分析产物)
    (tmp / "_endpoint_params.json").write_text(json.dumps({
        "_meta": {"js_files_collected": 3, "js_files_analyzed": 3, "analysis_completeness": 0.9, "total_endpoints_extracted": 3},
        "endpoints": {
            "/api/user/list": {"method": "GET", "params_optional": ["userId"], "source_files": ["app.js"]},
            "/api/user/info": {"method": "GET", "params_required": ["userId"], "source_files": ["app.js"]},
            "/api/org/42/members": {"method": "GET", "params_optional": ["memberId", "orgId"], "source_files": ["admin.js"]},
        },
    }, ensure_ascii=False), encoding="utf-8")
    # 构造值池(模拟响应挖掘产物,扁平格式)
    (tmp / "_leaked_values.json").write_text(json.dumps({"values": [
        {"param": "id", "value": "10086", "priority": "HIGH", "source_endpoint": "/api/user/list", "source_param": "id"},
        {"param": "orgId", "value": "42", "priority": "HIGH", "source_endpoint": "/api/user/list", "source_param": "orgId"},
        {"param": "token", "value": "eyJhbGciOiJIUzI1NiJ9.xxx", "priority": "CRITICAL", "source_endpoint": "/api/login", "source_param": "accessToken"},
    ]}, ensure_ascii=False), encoding="utf-8")

    reg = EndpointRegistry.from_file(tmp / "_endpoint_params.json")
    pool = ValuePool.from_file(tmp / "_leaked_values.json")
    eng = PairingEngine(reg, pool)
    pairs = eng.match()
    print(f"联动配对 {len(pairs)} 条:")
    for p in pairs:
        print(f"  [{p.priority}] {p.reason} method={p.method}")
    gate = check_pair_completeness(pairs)
    print(f"\n门控: {'BLOCKED' if gate.block_transition else 'PASSED'} ({gate.summary.splitlines()[1].strip()})")
    # 方法回退
    m = build_method_fallback_matrix("/api/user/info", "GET", 405)
    print(f"\n405 回退矩阵 {len(m)} 条, 首条: {m[0]['description'] if m else '无'}")
    # JS 完整性门控
    js_check = check_js_analysis_completeness(json.loads((tmp / "_endpoint_params.json").read_text(encoding="utf-8")))
    print(f"\nJS 门控: {'PASSED' if js_check.passed else 'FAILED'}")
