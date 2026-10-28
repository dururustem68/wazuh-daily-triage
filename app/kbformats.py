# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Human-friendly knowledge import formats and downloadable templates.

Besides the YAML/JSON list (seed format) the import accepts:

* **TXT** — one entry per block, blocks separated by a line ``---``::

      [baseline] 31101 web scanner noise, ~6,000 a day
      rules: 31101, 100211
      Free text: why this is normal, what would make it abnormal.

* **CSV** (Excel "Save as CSV", comma or semicolon): columns ``kind, title, body, rule_ids``.

Kinds can be written in English or in the UI languages (``karar``, ``gürültü``, ``ders`` …).
"""
from __future__ import annotations

import csv
import io
import json
import re

import yaml

from .store import KNOWLEDGE_KINDS

KIND_ALIASES = {
    # tr
    "bağlam": "context", "baglam": "context", "ortam": "context", "ortam bilgisi": "context",
    "gürültü": "baseline", "gurultu": "baseline", "bilinen gürültü": "baseline", "normal": "baseline",
    "karar": "decision", "açık": "open_item", "acik": "open_item", "açık madde": "open_item", "takip": "open_item",
    "istek": "request", "not": "request", "ders": "lesson", "kural": "rule_draft", "kural taslağı": "rule_draft",
    # es
    "contexto": "context", "ruido": "baseline", "decisión": "decision", "decision": "decision",
    "pendiente": "open_item", "solicitud": "request", "lección": "lesson", "leccion": "lesson",
    # de
    "kontext": "context", "rauschen": "baseline", "entscheidung": "decision", "offen": "open_item",
    "anfrage": "request", "lektion": "lesson",
    # en synonyms
    "noise": "baseline", "known noise": "baseline", "open": "open_item", "open item": "open_item",
    "note": "request", "rule": "rule_draft",
}


def norm_kind(k) -> str:
    k = str(k or "").strip().lower().replace("-", "_")
    if k in KNOWLEDGE_KINDS:
        return k
    return KIND_ALIASES.get(k, KIND_ALIASES.get(k.replace("_", " "), k))


def _rules(v) -> list[str]:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x for x in re.split(r"[\s,;]+", str(v or "")) if x]


_RULE_KEYS = {"rule", "rules", "kural", "kurallar", "regla", "reglas", "regel", "regeln", "rule_ids"}
_KEY_KEYS = {"key", "anahtar"}


def _head(line: str) -> tuple[str, str] | None:
    """`[kind] title` → (kind, title). Plain string operations: no regex on user-supplied text."""
    line = line.strip()
    if not line.startswith("["):
        return None
    end = line.find("]")
    kind, title = line[1:end].strip(), line[end + 1:].strip()
    return (kind, title) if end > 1 and kind and title else None


def _field(line: str, names: set[str]) -> str | None:
    """`name: value` / `name = value` when name is one of `names`; otherwise None."""
    cut = min((i for i in (line.find(":"), line.find("=")) if i > 0), default=-1)
    if cut < 0 or line[:cut].strip().lower() not in names:
        return None
    return line[cut + 1:].strip()


def _blocks(text: str) -> list[list[str]]:
    out: list[list[str]] = [[]]
    for ln in text.splitlines():
        st = ln.strip()
        if len(st) >= 3 and set(st) == {"-"}:
            out.append([])
        else:
            out[-1].append(ln)
    return out


def parse_txt(text: str) -> list[dict]:
    items: list[dict] = []
    for block in _blocks(text):
        lines = [ln.rstrip()[:10_000] for ln in block if not ln.lstrip().startswith("#")]
        while lines and not lines[0].strip():
            lines.pop(0)
        if not lines:
            continue
        h = _head(lines[0])
        if not h:
            items.append({"_error": f"first line must look like [kind] title — got {lines[0].strip()[:60]!r}"})
            continue
        it: dict = {"kind": norm_kind(h[0]), "title": h[1]}
        body = []
        for ln in lines[1:]:
            r, k = _field(ln, _RULE_KEYS), _field(ln, _KEY_KEYS)
            if r is not None and "rule_ids" not in it:
                it["rule_ids"] = _rules(r)
            elif k and "key" not in it:
                it["key"] = k
            else:
                body.append(ln)
        it["body"] = "\n".join(body).strip()
        items.append(it)
    return items


def parse_csv(text: str) -> list[dict]:
    text = text.lstrip("﻿")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
    out = []
    for r in rows:
        r = {str(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        if not any(r.values()):
            continue
        kind = r.get("kind") or r.get("tür") or r.get("tur") or r.get("tipo") or r.get("art")
        title = r.get("title") or r.get("başlık") or r.get("baslik") or r.get("título") or r.get("titel")
        body = r.get("body") or r.get("açıklama") or r.get("aciklama") or r.get("detalle") or r.get("text") or ""
        rules = r.get("rule_ids") or r.get("rules") or r.get("kurallar") or r.get("reglas") or r.get("regeln") or ""
        it = {"kind": norm_kind(kind), "title": title or "", "body": body, "rule_ids": _rules(rules)}
        if r.get("key"):
            it["key"] = r["key"]
        out.append(it)
    return out


def parse_import(text: str, filename: str = "") -> list:
    """YAML/JSON list, CSV or TXT — chosen by file extension, else by content."""
    name = filename.lower()
    if name.endswith(".csv"):
        return parse_csv(text)
    if name.endswith(".txt"):
        return parse_txt(text)
    stripped = text.lstrip("﻿").lstrip()
    if not name and _head(next((ln for ln in stripped.splitlines()
                                if ln.strip() and not ln.strip().startswith("#")), "")):
        return parse_txt(text)
    if stripped.startswith(("[", "{")):
        try:
            data = json.loads(stripped)
            return [{**d, "kind": norm_kind(d.get("kind"))} if isinstance(d, dict) else d for d in data] \
                if isinstance(data, list) else data
        except ValueError:
            pass
    data = yaml.safe_load(text)
    if isinstance(data, list):
        return [{**d, "kind": norm_kind(d.get("kind"))} if isinstance(d, dict) else d for d in data]
    if data is None:
        return []
    if isinstance(data, str) and "," in text.splitlines()[0]:
        return parse_csv(text)
    return data


# ------------------------------------------------------------------ templates

_TXT = {
    "en": """# Knowledge base — import template (TXT)
# One entry per block; separate entries with a line containing only ---
# First line:  [kind] title
#   kind: context (environment facts) · baseline (known noise) · decision (agreed rule of thumb)
#         open_item (follow-up) · request (note for the next run) · lesson (lesson learned)
# Optional line:  rules: 31101, 100211   (related Wazuh rule ids)
# Everything else is the body. Lines starting with # are ignored.
# Upload it on the Knowledge page → Import (run the preview first).

[context] web01 is the public reverse proxy
Runs nginx in front of all customer apps; 403/404 scans from the Internet are expected.
---
[baseline] 31101 web scanner noise, about 6,000 a day
rules: 31101, 100211
Scanners hit /, .env, .git/config and get 403/404. Abnormal: a 2xx answer, or a 10x jump.
---
[decision] Do not recommend closing Jenkins to the Internet
Customer pipelines trigger it; accepted risk. Judge findings by the compensating controls.
---
[lesson] Level-0 rules are never indexed
rules: 100210
A suppression rule always counts 0; check the parent rule and logtest instead.
""",
    "tr": """# Bilgi tabanı — içe aktarma şablonu (TXT)
# Her kayıt bir blok; kayıtları yalnızca --- içeren bir satırla ayırın
# İlk satır:  [tür] başlık
#   tür: bağlam (ortam bilgisi) · gürültü (bilinen normal) · karar (üzerinde anlaşılan kural)
#        açık (takip edilecek madde) · istek (sonraki koşu için not) · ders (çıkarılan ders)
#   (İngilizce adlar da geçer: context, baseline, decision, open_item, request, lesson)
# İsteğe bağlı satır:  kurallar: 31101, 100211   (ilgili Wazuh kural numaraları)
# Geri kalan her şey açıklamadır. # ile başlayan satırlar yok sayılır.
# Bilgi tabanı sayfası → İçe aktar ile yükleyin (önce önizleme).

[bağlam] web01 dışa açık reverse proxy
Tüm müşteri uygulamalarının önünde nginx çalışır; internetten gelen 403/404 taramaları beklenir.
---
[gürültü] 31101 web tarayıcı gürültüsü, günde ~6.000
kurallar: 31101, 100211
Tarayıcılar /, .env, .git/config yollarını dener ve 403/404 alır. Anormal: 2xx yanıt ya da 10 kat artış.
---
[karar] Jenkins'in internete kapatılması önerilmesin
Müşteri pipeline'ları tetikliyor; kabul edilmiş risk. Bulgular telafi edici kontrollere göre değerlendirilsin.
---
[ders] Level 0 kurallar indekse yazılmaz
kurallar: 100210
Bastırma kuralının sayısı hep 0 görünür; üst kurala ve logtest'e bakın.
""",
}
_TXT["es"] = _TXT["en"]
_TXT["de"] = _TXT["en"]

_CSV_ROWS = {
    "en": [("context", "web01 is the public reverse proxy", "nginx in front of all customer apps", ""),
           ("baseline", "31101 web scanner noise, about 6,000 a day", "403/404 scans; abnormal: 2xx or 10x jump",
            "31101 100211"),
           ("decision", "Do not recommend closing Jenkins to the Internet", "Accepted risk", "")],
    "tr": [("bağlam", "web01 dışa açık reverse proxy", "Tüm müşteri uygulamalarının önünde nginx", ""),
           ("gürültü", "31101 web tarayıcı gürültüsü, günde ~6.000", "403/404 taramaları; anormal: 2xx ya da 10 kat artış",
            "31101 100211"),
           ("karar", "Jenkins'in internete kapatılması önerilmesin", "Kabul edilmiş risk", "")],
}


def template(fmt: str, lang: str) -> tuple[str, str, str]:
    """(content, media type, file name) for a downloadable import template."""
    if fmt == "csv":
        rows = _CSV_ROWS.get(lang, _CSV_ROWS["en"])
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";" if lang in ("tr", "de", "es") else ",")   # what Excel expects there
        w.writerow(["kind", "title", "body", "rule_ids"])
        w.writerows(rows)
        return "﻿" + buf.getvalue(), "text/csv; charset=utf-8", "knowledge-template.csv"
    if fmt == "yaml":
        txt = parse_txt(_TXT.get(lang, _TXT["en"]))
        head = "# Knowledge base — import template (YAML list: kind, title, body, rule_ids, optional key)\n"
        return head + yaml.safe_dump(txt, allow_unicode=True, sort_keys=False, width=120), \
            "application/yaml", "knowledge-template.yaml"
    return _TXT.get(lang, _TXT["en"]), "text/plain; charset=utf-8", "knowledge-template.txt"
