#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
findings APK 字段升级的端到端检查。纯标准库。

用法:
    python3 migrations/apk_fields_e2e_test.py --url http://127.0.0.1:8097 \
        --email admin@reconlab.local

会自己调用 upgrade_apk_fields.py（含第二次幂等、--rollback、再升级）。
结束时库保持已升级。
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
UPGRADE = os.path.join(HERE, "upgrade_apk_fields.py")
ORIGINAL_STATUS = ["new", "confirmed", "false_positive", "fixed"]
WANTED_STATUS = ORIGINAL_STATUS + ["suspected", "testing", "auto_verified", "blocked"]
NEW_NAMES = ("cwe", "locator", "verify_hooks", "confidence_tier", "queue_item_id")
DROP_STATUS = (
    "suspected",
    "testing",
    "auto_verified",
    "blocked",
    "rejected",
    "inconclusive",
)
KEEP_STATUS = ("new", "confirmed", "false_positive", "fixed")

PASS = []
FAIL = []


def http(method, url, body=None, token=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        status = exc.code
    try:
        parsed = json.loads(payload) if payload else {}
    except ValueError:
        parsed = {"_raw": payload[:800]}
    return status, parsed


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("pass %s" % name)
    else:
        FAIL.append((name, detail))
        print("fail %s  %s" % (name, detail))


def field_names(collection):
    return [field.get("name") for field in collection.get("fields") or []]


def field_ids(collection):
    return {field.get("name"): field.get("id") for field in collection.get("fields") or []}


def snapshot(items):
    out = {}
    for collection in items:
        out[collection.get("name")] = {
            "id": collection.get("id"),
            "fields": field_names(collection),
            "ids": field_ids(collection),
            "raw": collection,
        }
    return out


def findings_of(items):
    for collection in items:
        if collection.get("name") == "findings":
            return collection
    return None


def status_values(collection):
    for field in collection.get("fields") or []:
        if field.get("name") == "status" and field.get("type") == "select":
            return list(field.get("values") or [])
    return None


def field_by_name(collection, name):
    if not collection:
        return None
    for field in collection.get("fields") or []:
        if field.get("name") == name:
            return field
    return None


def confidence_is_text(collection):
    field = field_by_name(collection, "confidence")
    return bool(field) and field.get("type") == "text" and not field.get("required")


def run_upgrade(base, email, password, rollback=False):
    cmd = [sys.executable, UPGRADE, "--url", base, "--email", email, "--password", password]
    if rollback:
        cmd.append("--rollback")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print("--- upgrade%s stdout ---" % (" --rollback" if rollback else ""))
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        print("--- upgrade stderr ---")
        sys.stdout.write(proc.stderr)
    print("--- upgrade exit %s ---" % proc.returncode)
    return proc.returncode, proc.stdout


def load_collections(base, token):
    status, payload = http("GET", base + "/api/collections?perPage=200", token=token)
    if status != 200:
        return status, payload, None
    return status, payload, payload.get("items") or []


def as_obj(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value



def delete_drop_status_rows(base, token):
    """只删 status 属于六个将被回滚拿掉的取值的 findings 行。保留 new/confirmed/false_positive/fixed。"""
    deleted = []
    page = 1
    filt = "(" + "||".join("status='%s'" % value for value in DROP_STATUS) + ")"
    while True:
        query = urllib.parse.urlencode({"perPage": "200", "page": str(page), "filter": filt})
        st, payload = http(
            "GET",
            "%s/api/collections/findings/records?%s" % (base, query),
            token=token,
        )
        if st != 200:
            print("fail list drop-status rows %s %s" % (st, payload))
            break
        items = payload.get("items") or []
        for item in items:
            status_value = item.get("status")
            if status_value in KEEP_STATUS or status_value not in DROP_STATUS:
                print("skip delete findings %s status=%s" % (item.get("id"), status_value))
                continue
            dst, dbody = http(
                "DELETE",
                "%s/api/collections/findings/records/%s" % (base, item.get("id")),
                token=token,
            )
            if dst not in (200, 204):
                print("warn delete findings %s %s %s" % (item.get("id"), dst, dbody))
            else:
                deleted.append((item.get("id"), status_value))
        total_pages = int(payload.get("totalPages") or 1)
        if page >= total_pages:
            break
        page += 1
    return deleted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8097")
    parser.add_argument("--email", default="admin@reconlab.local")
    parser.add_argument("--password", default=os.environ.get("RECONLAB_ADMIN_PASSWORD"))
    args = parser.parse_args()
    base = args.url.rstrip("/")

    status, payload = http(
        "POST",
        base + "/api/collections/_superusers/auth-with-password",
        {"identity": args.email, "password": args.password},
    )
    if status != 200 or not payload.get("token"):
        print("管理员登录失败: %s %s" % (status, payload))
        return 1
    token = payload["token"]

    status, payload, items = load_collections(base, token)
    if items is None:
        print("读取表结构失败: %s %s" % (status, payload))
        return 1
    before = snapshot(items)
    if "findings" not in before:
        print("findings collection 不存在")
        return 1
    others_before = {name: spec["fields"] for name, spec in before.items() if name != "findings"}

    code, _out = run_upgrade(base, args.email, args.password)
    status, payload, items = load_collections(base, token)
    findings = findings_of(items or [])
    names = field_names(findings) if findings else []
    values = status_values(findings) if findings else None
    conf = field_by_name(findings, "confidence")
    qid = field_by_name(findings, "queue_item_id")
    check(
        "a upgrade exit 0 and findings has cwe/locator/verify_hooks/confidence_tier/queue_item_id plus extended status; confidence stays number",
        code == 0
        and findings is not None
        and all(name in names for name in NEW_NAMES)
        and conf is not None
        and conf.get("type") == "number"
        and field_by_name(findings, "confidence_tier") is not None
        and field_by_name(findings, "confidence_tier").get("type") == "text"
        and field_by_name(findings, "confidence_tier").get("required") in (False, None)
        and qid is not None
        and qid.get("type") == "text"
        and qid.get("required") in (False, None)
        and values is not None
        and all(value in values for value in WANTED_STATUS),
        "exit=%s names=%s status=%s confidence=%s queue_item_id=%s" % (code, names, values, conf, qid),
    )

    ids_before_second = field_ids(findings) if findings else {}
    preexisting = [name for name in ids_before_second if name not in NEW_NAMES]
    code2, out2 = run_upgrade(base, args.email, args.password)
    status, payload, items = load_collections(base, token)
    findings = findings_of(items or [])
    ids_after = field_ids(findings) if findings else {}
    ids_ok = all(ids_after.get(name) == ids_before_second.get(name) for name in preexisting)
    # 第二次不得重建已有字段（含刚加上的三个，只要第一次已经落上）。
    all_stable = all(ids_after.get(name) == ids_before_second.get(name) for name in ids_before_second)
    qid_after = field_by_name(findings, "queue_item_id")
    check(
        "b second upgrade exit 0 and pre-existing field ids unchanged",
        code2 == 0 and "nothing changed" in out2 and ids_ok and all_stable,
        "exit=%s nothing_changed=%s ids_ok=%s all_stable=%s before=%s after=%s"
        % (code2, "nothing changed" in out2, ids_ok, all_stable, ids_before_second, ids_after),
    )
    check(
        "b2 queue_item_id stays text, not required, and its field id is stable",
        code2 == 0
        and qid_after is not None
        and qid_after.get("type") == "text"
        and qid_after.get("required") in (False, None)
        and ids_before_second.get("queue_item_id")
        and ids_after.get("queue_item_id") == ids_before_second.get("queue_item_id"),
        "before=%s after=%s field=%s" % (
            ids_before_second.get("queue_item_id"),
            ids_after.get("queue_item_id"),
            qid_after,
        ),
    )

    created_id = None
    body = {
        "title": "apk-fields-e2e",
        "status": "suspected",
        "cwe": "CWE-862",
        "confidence_tier": "static-candidate",
        "locator": {"stage": "decompile_manifest", "component": "GuardedActivity"},
        "verify_hooks": {"verifier_plugin": None, "executed": False},
    }
    st, created = http("POST", base + "/api/collections/findings/records", body, token=token)
    if st not in (200, 201):
        check("c create findings and read back", False, "create %s %s" % (st, json.dumps(created, ensure_ascii=False)[:800]))
    else:
        created_id = created.get("id")
        st, fetched = http(
            "GET",
            "%s/api/collections/findings/records/%s" % (base, created_id),
            token=token,
        )
        loc = as_obj(fetched.get("locator")) if st == 200 else None
        hooks = as_obj(fetched.get("verify_hooks")) if st == 200 else None
        hooks_text = json.dumps(hooks, ensure_ascii=False) if not isinstance(hooks, str) else hooks
        ok = (
            st == 200
            and fetched.get("status") == "suspected"
            and fetched.get("cwe") == "CWE-862"
            and fetched.get("confidence_tier") == "static-candidate"
            and fetched.get("confidence") != "static-candidate"
            and "static-candidate" not in (hooks_text or "")
            and loc == body["locator"]
            and hooks == body["verify_hooks"]
        )
        check(
            "c create findings and read back",
            ok,
            "get %s %s" % (st, json.dumps(fetched, ensure_ascii=False)[:800]),
        )
        if created_id:
            dst, dbody = http(
                "DELETE",
                "%s/api/collections/findings/records/%s" % (base, created_id),
                token=token,
            )
            if dst not in (200, 204):
                print("warn delete findings %s %s" % (dst, dbody))

    ids_before_block = field_ids(findings) if findings else {}
    values_before_block = status_values(findings) if findings else None
    st, blocked_row = http(
        "POST",
        base + "/api/collections/findings/records",
        {"title": "apk-fields-e2e-rollback-block", "status": "suspected"},
        token=token,
    )
    if st not in (200, 201) or not blocked_row.get("id"):
        check(
            "d0 rollback refuses while a drop-status row exists and schema stays",
            False,
            "create suspected %s %s" % (st, json.dumps(blocked_row, ensure_ascii=False)[:800]),
        )
    else:
        code_block, out_block = run_upgrade(base, args.email, args.password, rollback=True)
        status, payload, items = load_collections(base, token)
        findings = findings_of(items or [])
        ids_after_block = field_ids(findings) if findings else {}
        values_after_block = status_values(findings) if findings else None
        check(
            "d0 rollback exits 2 while suspected row exists and schema stays (confidence still number, status still has suspected)",
            code_block == 2
            and "未修改 schema" in out_block
            and "suspected" in out_block
            and ids_after_block == ids_before_block
            and values_after_block == values_before_block
            and field_by_name(findings, "confidence") is not None
            and field_by_name(findings, "confidence").get("type") == "number"
            and field_by_name(findings, "confidence_tier") is not None
            and field_by_name(findings, "confidence_tier").get("type") == "text"
            and values_after_block is not None
            and "suspected" in values_after_block,
            "exit=%s ids_same=%s values=%s confidence=%s stdout=%s"
            % (
                code_block,
                ids_after_block == ids_before_block,
                values_after_block,
                field_by_name(findings, "confidence"),
                out_block.strip(),
            ),
        )

    removed = delete_drop_status_rows(base, token)
    print("deleted drop-status findings rows: %s" % removed)

    code_rb, _out_rb = run_upgrade(base, args.email, args.password, rollback=True)
    status, payload, items = load_collections(base, token)
    findings = findings_of(items or [])
    names = field_names(findings) if findings else []
    values = status_values(findings) if findings else None
    gone = all(name not in names for name in NEW_NAMES)
    check(
        "d rollback removes cwe/locator/verify_hooks/confidence_tier/queue_item_id, keeps numeric confidence, restores exactly the original four status values",
        code_rb == 0
        and gone
        and values == ORIGINAL_STATUS
        and field_by_name(findings, "confidence") is not None
        and field_by_name(findings, "confidence").get("type") == "number"
        and "confidence_tier" not in names
        and "queue_item_id" not in names,
        "exit=%s names=%s status=%s" % (code_rb, names, values),
    )

    code3, _out3 = run_upgrade(base, args.email, args.password)
    status, payload, items = load_collections(base, token)
    findings = findings_of(items or [])
    names = field_names(findings) if findings else []
    values = status_values(findings) if findings else None
    check(
        "d2 re-upgrade leaves the server upgraded, confidence_tier text, queue_item_id text, confidence still number",
        code3 == 0
        and all(name in names for name in NEW_NAMES)
        and field_by_name(findings, "confidence") is not None
        and field_by_name(findings, "confidence").get("type") == "number"
        and field_by_name(findings, "confidence_tier") is not None
        and field_by_name(findings, "confidence_tier").get("type") == "text"
        and field_by_name(findings, "queue_item_id") is not None
        and field_by_name(findings, "queue_item_id").get("type") == "text"
        and field_by_name(findings, "queue_item_id").get("required") in (False, None)
        and values is not None
        and all(value in (values or []) for value in WANTED_STATUS),
        "exit=%s names=%s status=%s confidence=%s" % (code3, names, values, field_by_name(findings, "confidence")),
    )

    after = snapshot(items or [])
    others_after = {name: spec["fields"] for name, spec in after.items() if name != "findings"}
    check(
        "e other collections and their field names unchanged",
        len(before) == len(after) and others_before == others_after,
        "before_count=%s after_count=%s mismatched=%s"
        % (
            len(before),
            len(after),
            [name for name in set(others_before) | set(others_after) if others_before.get(name) != others_after.get(name)],
        ),
    )

    print("passed %d / failed %d" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
