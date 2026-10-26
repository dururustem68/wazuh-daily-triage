# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Demo/test mode: synthetic Wazuh data in memory plus a tiny OpenSearch query engine.

Lets you try the UI, the collector and the tools without a real cluster. The supported
query/aggregation subset is exactly what this application uses. All IP addresses are
from the documentation ranges (RFC 5737).
"""
from __future__ import annotations

import fnmatch
import random
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from .collector import _parse

UTC = UTC


def _fmt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ------------------------------------------------------------------ data generation
AGENTS = [("001", "web01", "10.0.0.11"), ("002", "db01", "10.0.0.12"), ("003", "jenkins", "10.0.0.13"),
          ("004", "k8s-cp1", "10.0.0.21"), ("005", "k8s-w1", "10.0.0.31"), ("006", "k8s-w2", "10.0.0.32"),
          ("007", "laptop-ops", "10.0.0.50"), ("008", "mail01", "10.0.0.14")]
SCANNERS = ["203.0.113.10", "203.0.113.45", "198.51.100.77", "192.0.2.150", "203.0.113.205"]
PATHS = ["/.env", "/.git/config", "/wp-login.php", "/.aws/credentials", "/phpinfo.php", "/", "/admin",
         "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/actuator/env", "/.env.production"]

RULES = {
    "31101": (5, "Web server 400 error code.", ["web", "accesslog", "attack"]),
    "31151": (10, "Multiple web server 400 error codes from same source ip.", ["web", "accesslog", "web_scan", "recon"]),
    "31153": (10, "Multiple common web attacks from same source ip.", ["web", "accesslog", "attack"]),
    "5715": (3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"]),
    "5710": (5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed", "invalid_login"]),
    "5712": (10, "sshd: brute force trying to get access to the system. Non existent user.", ["syslog", "sshd", "authentication_failures"]),
    "550": (7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified"]),
    "554": (5, "File added to the system.", ["ossec", "syscheck", "syscheck_entry_added"]),
    "533": (7, "Listened ports status (netstat) changed (new port opened or closed).", ["ossec"]),
    "2902": (7, "New dpkg (Debian Package) installed.", ["syslog", "dpkg", "config_changed"]),
    "23505": (10, "CVE-2026-0001 affects openssl", ["vulnerability-detector"]),
    "100212": (5, "Jenkins: 401 with Basic Auth username", ["web_auth"]),
    "100213": (12, "Jenkins: Basic Auth brute force from same IP", ["web_bruteforce"]),
    "110014": (10, "K8s secret changed", ["k8s_audit", "k8s_secret"]),
    "60602": (9, "Windows application error event.", ["windows", "windows_application"]),
    "502": (3, "Wazuh server started.", ["ossec"]),
    "506": (3, "Wazuh agent stopped.", ["ossec"]),
}


def _ev(ts: datetime, rid: str, agent: tuple, **data) -> dict:
    lvl, desc, groups = RULES[rid]
    full_log = data.pop("full_log", "")
    ev = {"timestamp": _fmt(ts), "rule": {"id": rid, "level": lvl, "description": desc, "groups": groups},
          "agent": {"id": agent[0], "name": agent[1], "ip": agent[2]},
          "manager": {"name": "wazuh-manager-worker-0"}, "full_log": full_log,
          "location": data.pop("location", "/var/log/syslog"), "decoder": {"name": data.pop("decoder", "syslog")}}
    if data:
        ev["data"] = data
    return ev


def generate(now: datetime | None = None, days: int = 18, seed: int = 7) -> list[dict]:
    rnd = random.Random(seed)
    now = now or datetime.now(UTC)
    start = now - timedelta(days=days)
    ev: list[dict] = []
    web, jenkins = AGENTS[0], AGENTS[2]
    t = start
    while t < now:
        hour_factor = 1.6 if 17 <= t.hour <= 20 else 1.0
        # web scanner noise (baseline)
        for _ in range(int(rnd.randint(25, 45) * hour_factor)):
            ip = rnd.choice(SCANNERS[:4])
            path = rnd.choice(PATHS)
            code = rnd.choice(["404", "404", "403"])
            ts = t + timedelta(seconds=rnd.randint(0, 3599))
            ev.append(_ev(ts, "31101", web, srcip=ip, url=path, id=code, protocol="GET", decoder="web-accesslog",
                          location="/var/log/nginx/access.log",
                          full_log=f'{ip} - - [..] "GET {path} HTTP/1.1" {code} 153 "-" "Mozilla/5.0"'))
        if rnd.random() < 0.25:
            ev.append(_ev(t + timedelta(minutes=rnd.randint(0, 59)), "31151", web, srcip=rnd.choice(SCANNERS[:4]),
                          decoder="web-accesslog"))
        # routine team ssh logins
        if t.hour in (6, 9, 14) and rnd.random() < 0.7:
            ag = rnd.choice(AGENTS[1:6])
            ev.append(_ev(t + timedelta(minutes=rnd.randint(0, 59)), "5715", ag, srcip="100.124.10.5", dstuser="deploy",
                          full_log="sshd[1234]: Accepted publickey for deploy from 100.124.10.5 port 50122 ssh2"))
        # windows application errors
        for _ in range(rnd.randint(0, 3)):
            ev.append(_ev(t + timedelta(minutes=rnd.randint(0, 59)), "60602", AGENTS[6],
                          location="EventChannel", decoder="windows_eventchannel",
                          full_log="Faulting application name: Teams.exe"))
        # listening-port changes (baseline)
        if rnd.random() < 0.3:
            ev.append(_ev(t + timedelta(minutes=rnd.randint(0, 59)), "533", jenkins, location="netstat listening ports",
                          full_log="ossec: output: 'netstat listening ports': tcp 0.0.0.0:3478"))
        t += timedelta(hours=1)

    # daily package updates ~06:00Z
    d = start.replace(hour=6, minute=0, second=0, microsecond=0)
    while d < now:
        for ag in AGENTS[:6]:
            ev.append(_ev(d + timedelta(minutes=rnd.randint(0, 20)), "2902", ag, location="/var/log/dpkg.log",
                          decoder="dpkg-decoder", full_log="status installed libssl3:amd64 3.0.13-0ubuntu3.6"))
        d += timedelta(days=1)

    # --- interesting events in the last 24 hours ---------------------------
    burst = now - timedelta(hours=9)
    for i in range(1600):  # Jenkins Basic Auth brute force against a single path
        ts = burst + timedelta(seconds=i * 0.06)
        ev.append(_ev(ts, "100212", jenkins, srcip="192.0.2.45", url="/manage", id="401", srcuser="admin",
                      decoder="web-accesslog", location="/var/log/nginx/access.log",
                      full_log='192.0.2.45 - admin [..] "GET /manage HTTP/1.1" 401 0 "-" "Mozilla/5.0 Chrome/91.0.4472.124"'))
        if i % 20 == 19:
            ev.append(_ev(ts, "100213", jenkins, srcip="192.0.2.45", url="/manage", id="401", srcuser="admin",
                          decoder="web-accesslog", location="/var/log/nginx/access.log"))
    # SSH brute force against db01 (should not be internet-facing)
    b2 = now - timedelta(hours=4, minutes=12)
    for i in range(240):
        ev.append(_ev(b2 + timedelta(seconds=i * 2), "5710", AGENTS[1], srcip="198.51.100.23", srcuser=f"user{i % 30}",
                      full_log=f"sshd[2211]: Invalid user user{i % 30} from 198.51.100.23 port 4{i:04d}"))
        if i % 40 == 39:
            ev.append(_ev(b2 + timedelta(seconds=i * 2), "5712", AGENTS[1], srcip="198.51.100.23"))
    # FIM: /etc/sudoers modified (level 7+)
    ev.append(_ev(now - timedelta(hours=3, minutes=40), "550", AGENTS[1], location="syscheck",
                  full_log="File '/etc/sudoers' modified", decoder="syscheck_integrity_changed"))
    ev[-1]["syscheck"] = {"path": "/etc/sudoers", "event": "modified"}
    # k8s secret changes
    for k in range(3):
        e = _ev(now - timedelta(hours=2, minutes=k), "110014", AGENTS[3], location="/k8s-audit/audit.json",
                decoder="json")
        e["data"] = {"verb": "patch", "user": {"username": "system:serviceaccount:cattle-system:rancher"},
                     "objectRef": {"resource": "secrets", "namespace": "cattle-tokens", "name": f"token-ab{k}"},
                     "responseStatus": {"code": "200"}}
        ev.append(e)
    # newly seen rule: vulnerability burst, same count on every Linux agent
    for ag in AGENTS[:6]:
        for j in range(12):
            e = _ev(now - timedelta(hours=18, minutes=j), "23505", ag, location="vulnerability-detector")
            e["data"] = {"vulnerability": {"cve": f"CVE-2026-{1000 + j}", "severity": "High",
                                           "package": {"name": "openssl"}}}
            ev.append(e)
    # mail01 agent stopped 30 hours ago
    ev.append(_ev(now - timedelta(hours=30), "506", AGENTS[7], location="wazuh-agent"))
    ev.sort(key=lambda e: e["timestamp"])
    return ev


def generate_vulns() -> list[dict]:
    rnd = random.Random(3)
    out = []
    pk = ["linux-image-6.8.0-139-generic", "openssl", "libxml2", "python3.12", "curl", "sudo"]
    for a in AGENTS[:7]:
        for _ in range(rnd.randint(20, 60)):
            sev = rnd.choices(["Critical", "High", "Medium", "Low"], [1, 4, 8, 3])[0]
            det = datetime.now(UTC) - timedelta(days=rnd.randint(1, 120), hours=rnd.randint(0, 23))
            out.append({"agent": {"id": a[0], "name": a[1]}, "package": {"name": rnd.choice(pk)},
                        "vulnerability": {"id": f"CVE-2025-{rnd.randint(1000, 9999)}", "severity": sev,
                                          "detected_at": _iso(det)}})
    return out


# ------------------------------------------------------------------ query engine
def _get(doc: Any, path: str):
    cur = doc
    for p in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _vals(doc, path) -> list:
    v = _get(doc, path)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


_DM = re.compile(r"^now(?:([+-])(\d+)([smhdw]))?(?:/[dh])?$")


def _date(v) -> datetime:
    if isinstance(v, datetime):
        return v
    m = _DM.match(str(v))
    if m:
        dt = datetime.now(UTC)
        if m.group(1):
            n = int(m.group(2))
            delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n), "h": timedelta(hours=n),
                     "d": timedelta(days=n), "w": timedelta(weeks=n)}[m.group(3)]
            dt = dt + delta if m.group(1) == "+" else dt - delta
        return dt
    return _parse(str(v))


def _cmp_val(field, v):
    if field == "timestamp" or field.endswith("_at") or field == "ts":
        return _date(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return str(v)


def _match(doc, q: dict) -> bool:
    if not q:
        return True
    (kind, body), = q.items()
    if kind == "match_all":
        return True
    if kind == "match_none":
        return False
    if kind == "bool":
        for c in body.get("filter", []) + body.get("must", []):
            if not _match(doc, c):
                return False
        for c in body.get("must_not", []):
            if _match(doc, c):
                return False
        sh = body.get("should", [])
        if sh and not any(_match(doc, c) for c in sh):
            return False
        return True
    if kind == "range":
        (field, cond), = body.items()
        vals = _vals(doc, field)
        if not vals:
            return False
        x = _cmp_val(field, vals[0])
        for op, lim in cond.items():
            if op in ("format", "time_zone"):
                continue
            y = _cmp_val(field, lim)
            if op == "gte" and not x >= y or op == "gt" and not x > y or op == "lte" and not x <= y \
                    or op == "lt" and not x < y:
                return False
        return True
    if kind == "term":
        (field, val), = body.items()
        if isinstance(val, dict):
            val = val.get("value")
        return str(val) in [str(x) for x in _vals(doc, field)]
    if kind == "terms":
        (field, vals), = body.items()
        have = {str(x) for x in _vals(doc, field)}
        return bool(have & {str(v) for v in vals})
    if kind == "prefix":
        (field, val), = body.items()
        if isinstance(val, dict):
            val = val.get("value")
        return any(str(x).startswith(str(val)) for x in _vals(doc, field))
    if kind == "exists":
        return bool(_vals(doc, body["field"]))
    if kind == "query_string":
        return _qs(doc, body["query"])
    raise ValueError(f"demo engine does not support: {kind}")


def _qs(doc, s: str) -> bool:
    """Simple query_string: `a:b AND c:d OR e:f`, NOT, wildcards (*), free text."""
    ors = re.split(r"\s+OR\s+", s.strip())
    for part in ors:
        ok = True
        for tok in re.split(r"\s+AND\s+", part):
            neg = tok.startswith("NOT ")
            tok = tok[4:] if neg else tok
            tok = tok.strip().strip("()")
            if ":" in tok and not tok.startswith("http"):
                f, v = tok.split(":", 1)
                v = v.strip('"')
                hit = any(fnmatch.fnmatch(str(x), v) for x in _vals(doc, f))
            else:
                hit = tok.strip('"').lower() in str(doc.get("full_log", "")).lower()
            if hit == neg:
                ok = False
                break
        if ok:
            return True
    return False


_IV = {"m": 60, "h": 3600, "d": 86400}


def _interval(s: str) -> int:
    return int(s[:-1]) * _IV[s[-1]]


def _agg(docs: list[dict], spec: dict) -> dict:
    sub = spec.get("aggs") or spec.get("aggregations") or {}
    if "terms" in spec:
        t = spec["terms"]
        counts: dict[Any, list] = {}
        for d in docs:
            for v in _vals(d, t["field"]):
                counts.setdefault(v, []).append(d)
        items = list(counts.items())
        order = t.get("order", {"_count": "desc"})
        if "_key" in order:
            items.sort(key=lambda kv: kv[0], reverse=order["_key"] == "desc")
        else:
            items.sort(key=lambda kv: (-len(kv[1]), str(kv[0])))
        size = t.get("size", 10)
        out = []
        for k, ds in items[:size]:
            b = {"key": k, "doc_count": len(ds)}
            for n, s in sub.items():
                b[n] = _agg(ds, s)
            out.append(b)
        return {"buckets": out, "sum_other_doc_count": sum(len(ds) for _, ds in items[size:])}
    if "date_histogram" in spec:
        h = spec["date_histogram"]
        iv = _interval(h.get("fixed_interval") or h.get("interval", "1h"))
        bk: dict[int, list] = {}
        for d in docs:
            ts = int(_date(_get(d, h["field"])).timestamp())
            bk.setdefault(ts - ts % iv, []).append(d)
        keys = set(bk)
        if h.get("extended_bounds") and h.get("min_doc_count", 1) == 0:
            lo = int(_date(h["extended_bounds"]["min"]).timestamp())
            hi = int(_date(h["extended_bounds"]["max"]).timestamp())
            k = lo - lo % iv
            while k <= hi:
                keys.add(k)
                k += iv
        out = []
        for k in sorted(keys):
            ds = bk.get(k, [])
            if len(ds) < h.get("min_doc_count", 1):
                continue
            b = {"key": k * 1000, "key_as_string": _iso(datetime.fromtimestamp(k, UTC)), "doc_count": len(ds)}
            for n, s in sub.items():
                b[n] = _agg(ds, s)
            out.append(b)
        return {"buckets": out}
    if "min" in spec or "max" in spec:
        op = "min" if "min" in spec else "max"
        f = spec[op]["field"]
        vals = [v for d in docs for v in _vals(d, f)]
        if not vals:
            return {"value": None}
        if f == "timestamp" or f.endswith("_at"):
            dts = [_date(v) for v in vals]
            dt = min(dts) if op == "min" else max(dts)
            return {"value": dt.timestamp() * 1000, "value_as_string": _iso(dt)}
        nums = [float(v) for v in vals]
        return {"value": min(nums) if op == "min" else max(nums)}
    if "cardinality" in spec:
        return {"value": len({str(v) for d in docs for v in _vals(d, spec["cardinality"]["field"])})}
    if "filter" in spec:
        ds = [d for d in docs if _match(d, spec["filter"])]
        b = {"doc_count": len(ds)}
        for n, s in sub.items():
            b[n] = _agg(ds, s)
        return b
    if "top_hits" in spec:
        th = spec["top_hits"]
        ds = _sort(docs, th.get("sort"))[: th.get("size", 3)]
        return {"hits": {"total": {"value": len(docs)}, "hits": [{"_source": _src(d, th.get("_source"))} for d in ds]}}
    raise ValueError(f"demo engine does not support agg: {list(spec)}")


def _sort(docs, sort):
    if not sort:
        return docs
    (field, o), = sort[0].items()
    desc = (o if isinstance(o, str) else o.get("order", "asc")) == "desc"
    return sorted(docs, key=lambda d: str(_get(d, field) or ""), reverse=desc)


def _src(d, fields):
    if not fields:
        return deepcopy(d)
    out: dict = {}
    for f in fields:
        v = _get(d, f)
        if v is None:
            continue
        cur = out
        parts = f.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = deepcopy(v)
    return out


class FakeIndexer:
    def __init__(self, alerts: list[dict] | None = None, vulns: list[dict] | None = None):
        self.alerts = alerts if alerts is not None else generate()
        self.vulns = vulns if vulns is not None else generate_vulns()
        self.docs: dict[str, dict[str, dict]] = {}
        self.ep = type("E", (), {"url": "demo://indexer"})()

    async def close(self):
        pass

    def _pool(self, index: str) -> list[dict]:
        if index.startswith("wazuh-alerts"):
            return self.alerts
        if "vulnerab" in index:
            return self.vulns
        return list(self.docs.get(index, {}).values())

    async def search(self, index, body):
        docs = [d for d in self._pool(index) if _match(d, body.get("query") or {})]
        res = {"hits": {"total": {"value": len(docs), "relation": "eq"},
                        "hits": [{"_source": _src(d, body.get("_source"))}
                                 for d in _sort(docs, body.get("sort"))[: body.get("size", 10)]]}}
        if body.get("aggs"):
            res["aggregations"] = {n: _agg(docs, s) for n, s in body["aggs"].items()}
        return res

    async def count(self, index, query):
        return sum(1 for d in self._pool(index) if _match(d, query))

    async def cluster_health(self):
        return {"cluster_name": "demo-cluster", "status": "green", "number_of_nodes": 1, "active_shards": 42, "unassigned_shards": 0,
                "active_shards_percent_as_number": 100.0}

    async def allocation(self):
        return [{"node": "wazuh-indexer-0", "disk.percent": "63", "shards": "42"}]

    async def index_exists(self, index):
        return index in self.docs

    async def create_index(self, index, body):
        self.docs.setdefault(index, {})

    async def put_doc(self, index, doc_id, doc, refresh=True):
        self.docs.setdefault(index, {})[doc_id] = deepcopy(doc)

    async def get_doc(self, index, doc_id):
        d = self.docs.get(index, {}).get(doc_id)
        return deepcopy(d) if d else None

    async def delete_doc(self, index, doc_id):
        self.docs.get(index, {}).pop(doc_id, None)


class FakeAPI:
    """Demo/test stand-in for the Wazuh API, including an in-memory custom rules directory."""

    def __init__(self):
        self.ep = type("E", (), {"url": "demo://api"})()
        self.files: dict[str, str] = {}
        self.loaded: dict[str, dict] = {}     # rules "loaded" by the last restart
        self.restarts = 0
        self.fail_validation = False

    async def close(self):
        pass

    async def info(self):
        return {"api_version": "4.14.8", "hostname": "wazuh-manager-master-0"}

    async def manager_status(self):
        return {"wazuh-analysisd": "running", "wazuh-remoted": "running", "wazuh-db": "running",
                "wazuh-modulesd": "running", "wazuh-syscheckd": "running", "wazuh-logcollector": "running",
                "wazuh-authd": "running", "wazuh-monitord": "running", "wazuh-maild": "stopped",
                "wazuh-execd": "running", "wazuh-integratord": "stopped", "wazuh-csyslogd": "stopped",
                "wazuh-dbd": "stopped", "wazuh-agentlessd": "stopped", "wazuh-clusterd": "running",
                "wazuh-apid": "running"}

    async def cluster_health(self):
        return {"enabled": "yes", "running": "yes", "nodes": {
            "wazuh-manager-master": {"type": "master", "version": "4.14.8", "n_active_agents": 0},
            "wazuh-manager-worker-0": {"type": "worker", "version": "4.14.8", "n_active_agents": 7}}}

    async def agents_summary(self):
        return {"connection": {"active": 7, "disconnected": 1, "never_connected": 0, "pending": 0, "total": 8}}

    async def agents(self, status=None, search=None, limit=100):
        now = datetime.now(UTC)
        rows = [{"id": a[0], "name": a[1], "ip": a[2], "status": "active", "version": "Wazuh v4.14.6",
                 "lastKeepAlive": _iso(now - timedelta(seconds=30)), "os": {"name": "Ubuntu", "version": "24.04"},
                 "group": ["default"], "node_name": "wazuh-manager-worker-0"} for a in AGENTS]
        rows[7].update(status="disconnected", lastKeepAlive=_iso(now - timedelta(hours=30)))
        if status:
            rows = [r for r in rows if r["status"] in status.split(",")]
        if search:
            rows = [r for r in rows if search in r["name"] or search == r["id"]]
        return rows[:limit]

    async def manager_errors(self, limit=30):
        now = datetime.now(UTC)
        return [{"timestamp": _iso(now - timedelta(hours=h)), "tag": "wazuh-modulesd:vulnerability-scanner",
                 "level": "error", "description": "Error updating the CVE feed: timeout"} for h in (2, 14)]

    async def rules(self, rule_ids):
        out = []
        for r in rule_ids:
            if str(r) in self.loaded:
                out.append(self.loaded[str(r)])
            elif r in RULES:
                lvl, desc, groups = RULES[r]
                out.append({"id": int(r), "level": lvl, "description": desc, "groups": groups,
                            "filename": "local_rules.xml" if r.startswith("1") and len(r) == 6 else "0xxx-rules.xml",
                            "relative_dirname": "etc/rules", "details": {}})
        return out

    async def logtest(self, event, log_format="syslog", location="daily-triage"):
        import re as _re
        user = _re.search(r"Invalid user (\S+)", event)
        if user:  # deployed child rules of 5710 with a <user> pattern (OS_Regex-like ^a$|^b$)
            for content in self.files.values():
                for m in _re.finditer(r'<rule id="(\d+)" level="(\d+)">\s*<if_sid>5710</if_sid>\s*<user>([^<]+)</user>',
                                      content):
                    if _re.search(m.group(3), user.group(1)):
                        return {"output": {"rule": {"id": m.group(1), "level": int(m.group(2))},
                                           "decoder": {"name": "sshd"}}, "alert": True, "messages": []}
        if "Invalid user" in event:
            return {"output": {"rule": {"id": "5710", "level": 5, "description": RULES["5710"][1]},
                               "decoder": {"name": "sshd"}, "data": {"srcip": "198.51.100.23"}},
                    "alert": True, "messages": []}
        return {"output": {"rule": {"id": "1002", "level": 2, "description": "Unknown problem somewhere in the system."},
                           "decoder": {"name": "syslog"}}, "alert": False, "messages": []}

    # --- rule deployment -------------------------------------------------
    def reset_token(self):
        pass

    async def cluster_running(self):
        return False

    async def rule_file_get(self, name):
        return self.files.get(name)

    async def rule_file_put(self, name, content):
        self.files[name] = content
        return {}

    async def rule_file_delete(self, name):
        self.files.pop(name, None)

    async def config_validation(self, cluster):
        return [{"name": "demo-manager", "status": "KO" if self.fail_validation else "OK"}]

    async def restart(self, cluster):
        import re as _re
        self.restarts += 1
        self.loaded = {}
        for name, content in self.files.items():
            for m in _re.finditer(r'<rule id="(\d+)" level="(\d+)"', content):
                self.loaded[m.group(1)] = {"id": int(m.group(1)), "level": int(m.group(2)), "filename": name,
                                           "description": "deployed", "groups": [], "relative_dirname": "etc/rules"}
        return {}
