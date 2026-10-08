#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
给已有 findings 表补齐 APK 静态线路字段。幂等，可重复跑。只加字段 / 扩 status 选项。

取代草案 migrations/1791435161_apk_findings_fields.js（DRAFT — NOT APPLIED，切勿直接跑在任何库上）。
落地方式对齐 ReconLab 现有 scripts/upgrade_contract_v2.py：走 PocketBase HTTP API，而不是 pb_migrations。

注意事项（来自旧草案，落库前必须记住）：
  1. 只「加字段 / 扩选项」，不动任何既有数据，不改其它 collection，不改 hooks / 路由。
  2. 不要对共享库或生产库执行。只用于隔离的一次性库（本次是 127.0.0.1:8097）。
     默认密码只是本地夹具。
  3. locator / verify_hooks 优先用 json（maxSize 20000）。若该 PocketBase 拒绝 json 类型，
     退化为 text 存 JSON 字符串，并打印 fallback（回写侧已是 JSON.stringify 友好结构）。
  4. status 选项会并入 suspected / testing / auto_verified / blocked，同时保留
     new / confirmed / false_positive / fixed，绝不删既有取值。
     静态线路写入方只允许落 suspected / testing / blocked；
     auto_verified 归动态 verifier、confirmed 归人工。schema 允许不等于静态段可写。
  5. findings 不存在则直接失败，本脚本不创建 collection。
  6. findings.confidence 在契约里已经是 number。本脚本绝不改它的类型。
     文本档位用新列 confidence_tier（text、可空，取值 static-candidate / static-strong），
     与数字 confidence 并存。APK 静态线路只读写 confidence_tier，不读不写数字 confidence，
     也不把档位折算成数字，不得把档位字符串写入 verify_hooks。
     confidence_tier 已存在则不重复添加。若它已存在但不是 text，拒绝升级，不替换。
  7. 回滚在改 schema 之前会先查 findings 行。即将删掉的 status 取值若仍被行使用
     （suspected / testing / auto_verified / blocked / rejected / inconclusive），
     只打印哪些取值、各有多少行，不 PATCH，退出码 2。原有 new / confirmed / false_positive / fixed 不拦截。
  8. findings.queue_item_id 是 text、可空，用来指回 review_queue 记录 id。
     已存在且不是 text 则拒绝升级（exit 2），不 PATCH，也不改它的类型。
     回滚与 cwe / locator / verify_hooks / confidence_tier 一起删除。
     回滚不删除、不改类型 findings.confidence。

用法:
    python3 migrations/upgrade_apk_fields.py --url http://127.0.0.1:8097 \
        --email admin@reconlab.local
    python3 migrations/upgrade_apk_fields.py --rollback

纯标准库实现，不需要 pip 装东西。
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ORIGINAL_STATUS = ["new", "confirmed", "false_positive", "fixed"]
STATUS_EXTRAS = ["suspected", "testing", "auto_verified", "blocked"]
ROLLBACK_EXTRAS = set(STATUS_EXTRAS + ["rejected", "inconclusive"])
NEW_FIELD_NAMES = ("cwe", "locator", "verify_hooks", "confidence_tier", "queue_item_id")
# 回滚会从 schema 拿掉、因此行里一旦出现就必须拒绝回滚的 status。
ROLLBACK_DROP_STATUS = (
    "suspected",
    "testing",
    "auto_verified",
    "blocked",
    "rejected",
    "inconclusive",
)


def request(method, url, body=None, token=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
        return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"message": raw[:800]}
        return exc.code, payload


def superuser_token(base, email, password):
    status, payload = request(
        "POST",
        base + "/api/collections/_superusers/auth-with-password",
        {"identity": email, "password": password},
    )
    if status != 200 or not payload.get("token"):
        print("超级管理员登录失败 (%s): %s" % (status, payload))
        return None
    return payload["token"]


def load_findings(base, token):
    status, existing = request("GET", base + "/api/collections?perPage=200", token=token)
    if status != 200:
        print("读取表结构失败 (%s): %s" % (status, existing))
        return None, None
    items = existing.get("items", [])
    findings = None
    for collection in items:
        if collection.get("name") == "findings":
            findings = collection
            break
    return items, findings


def new_field_specs(json_type):
    locator_type = "json" if json_type else "text"
    return [
        {"name": "cwe", "type": "text", "required": False},
        {
            "name": "locator",
            "type": locator_type,
            "required": False,
            "maxSize": 20000,
        },
        {
            "name": "verify_hooks",
            "type": locator_type,
            "required": False,
            "maxSize": 20000,
        },
        {"name": "confidence_tier", "type": "text", "required": False},
        {"name": "queue_item_id", "type": "text", "required": False},
    ]


def json_rejected(payload):
    text = json.dumps(payload, ensure_ascii=False).lower()
    return "json" in text


def patch_fields(base, token, collection_id, fields):
    return request(
        "PATCH",
        "%s/api/collections/%s" % (base, collection_id),
        {"fields": fields},
        token=token,
    )


def upgrade(base, token, findings):
    fields = json.loads(json.dumps(findings.get("fields") or []))
    have = {field.get("name") for field in fields}
    for field in fields:
        if field.get("name") == "confidence" and field.get("type") != "number":
            print("拒绝升级: findings.confidence 已是 %s，本脚本不改它的类型" % field.get("type"))
            return 2
        if field.get("name") == "confidence_tier" and field.get("type") != "text":
            print("拒绝升级: findings.confidence_tier 已是 %s，本脚本不改它的类型" % field.get("type"))
            return 2
        if field.get("name") == "queue_item_id" and field.get("type") != "text":
            print("拒绝升级: findings.queue_item_id 已是 %s，本脚本不改它的类型" % field.get("type"))
            return 2
    missing_names = [name for name in NEW_FIELD_NAMES if name not in have]
    status_field = None
    for field in fields:
        if field.get("name") == "status" and field.get("type") == "select":
            status_field = field
            break
    if status_field is None:
        print("findings.status 不是 select，拒绝改写")
        return 2

    current_values = list(status_field.get("values") or [])
    merged_values = list(current_values)
    added_values = []
    for value in ORIGINAL_STATUS + STATUS_EXTRAS:
        if value not in merged_values:
            merged_values.append(value)
            added_values.append(value)
    # 绝不丢掉已有取值（上面只追加）。
    for value in current_values:
        if value not in merged_values:
            merged_values.append(value)

    if not missing_names and merged_values == current_values:
        print("nothing changed")
        return 0

    def build(use_json):
        merged = json.loads(json.dumps(fields))
        specs = {spec["name"]: spec for spec in new_field_specs(use_json)}
        for name in missing_names:
            if any(field.get("name") == name for field in merged):
                continue
            merged.append(specs[name])
        for field in merged:
            if field.get("name") == "status" and field.get("type") == "select":
                field["values"] = list(merged_values)
        return merged

    status, result = patch_fields(base, token, findings["id"], build(True))
    used_fallback = False
    if status not in (200, 201) and missing_names and json_rejected(result):
        print("json 类型被拒绝，locator / verify_hooks 退化为 text: %s" % result)
        status, result = patch_fields(base, token, findings["id"], build(False))
        used_fallback = True
    if status not in (200, 201):
        print("补字段失败 (%s): %s" % (status, result))
        return 2

    parts = []
    if missing_names:
        parts.append("字段 +%s" % ", ".join(missing_names))
    if added_values:
        parts.append("status +%s" % ", ".join(added_values))
    if used_fallback:
        parts.append("json→text fallback")
    print("已升级 findings: %s" % ("; ".join(parts) if parts else "已写回"))
    return 0



def records_page(base, token, filter_expr):
    query = urllib.parse.urlencode({"perPage": "1", "filter": filter_expr})
    return request(
        "GET",
        "%s/api/collections/findings/records?%s" % (base, query),
        token=token,
    )


def rollback_blocked_by_rows(base, token):
    """返回 (totalItems, {value: count})。过滤语法被拒绝时换 PocketBase 0.23 接受的写法。失败返回 None。"""
    joined = "||".join("status='%s'" % value for value in ROLLBACK_DROP_STATUS)
    joined_spaced = " || ".join("status='%s'" % value for value in ROLLBACK_DROP_STATUS)
    variants = ["(" + joined + ")", "(" + joined_spaced + ")", joined_spaced]
    last = None
    chosen = None
    for expr in variants:
        status, payload = records_page(base, token, expr)
        last = (status, payload, expr)
        if status == 200 and isinstance(payload, dict) and "totalItems" in payload:
            chosen = expr
            total = int(payload.get("totalItems") or 0)
            break
    else:
        print("回滚前的 status 占用检查失败，拒绝改 schema (%s): %s" % (last[0], last[1]))
        return None
    if total == 0:
        return 0, {}
    counts = {}
    for value in ROLLBACK_DROP_STATUS:
        counted = None
        for expr in ("(status='%s')" % value, "status='%s'" % value):
            status, payload = records_page(base, token, expr)
            if status == 200 and isinstance(payload, dict) and "totalItems" in payload:
                counted = int(payload.get("totalItems") or 0)
                break
        if counted is None:
            print("回滚前无法计数 status=%s (%s): %s" % (value, status, payload))
            return None
        counts[value] = counted
    return total, counts


def rollback(base, token, findings):
    fields = json.loads(json.dumps(findings.get("fields") or []))
    status_field = None
    for field in fields:
        if field.get("name") == "status" and field.get("type") == "select":
            status_field = field
            break
    if status_field is None:
        print("findings.status 不是 select，拒绝回滚")
        return 2
    current_values = list(status_field.get("values") or [])
    missing_original = [value for value in ORIGINAL_STATUS if value not in current_values]
    extras = [value for value in current_values if value not in ORIGINAL_STATUS]
    bad = [value for value in extras if value not in ROLLBACK_EXTRAS]
    if missing_original or bad:
        print(
            "拒绝回滚: status 当前=%s；缺少既有值=%s；不允许的额外值=%s"
            % (current_values, missing_original, bad)
        )
        return 2

    # 删除 queue_item_id 以及 cwe / locator / verify_hooks / confidence_tier。不碰数字 confidence。
    present = [name for name in NEW_FIELD_NAMES if any(field.get("name") == name for field in fields)]
    values_differ = current_values != ORIGINAL_STATUS
    if not present and not values_differ:
        print("nothing changed")
        print("removed: (none)")
        return 0

    blocked = rollback_blocked_by_rows(base, token)
    if blocked is None:
        return 2
    total, counts = blocked
    if total > 0:
        print("拒绝回滚: findings 有 %d 行使用即将移除的 status，未修改 schema" % total)
        for value in ROLLBACK_DROP_STATUS:
            count = counts.get(value, 0)
            if count:
                print("  %s: %d" % (value, count))
        return 2

    merged = [field for field in fields if field.get("name") not in NEW_FIELD_NAMES]
    for field in merged:
        if field.get("name") == "status" and field.get("type") == "select":
            field["values"] = list(ORIGINAL_STATUS)
    status, result = patch_fields(base, token, findings["id"], merged)
    if status not in (200, 201):
        print("回滚失败 (%s): %s" % (status, result))
        return 2
    print("removed: %s" % (", ".join(present) if present else "(none)"))
    if values_differ:
        print("status 取值已回滚为: %s" % ", ".join(ORIGINAL_STATUS))
    else:
        print("status 取值未改")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8097")
    parser.add_argument("--email", default="admin@reconlab.local")
    parser.add_argument("--password", default=os.environ.get("RECONLAB_ADMIN_PASSWORD"))
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    token = superuser_token(base, args.email, args.password)
    if not token:
        return 1
    _items, findings = load_findings(base, token)
    if findings is None:
        if _items is None:
            return 1
        print("findings collection 不存在，拒绝创建")
        return 2
    if args.rollback:
        return rollback(base, token, findings)
    return upgrade(base, token, findings)


if __name__ == "__main__":
    sys.exit(main())
