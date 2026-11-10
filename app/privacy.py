# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Personal data (GDPR / KVKK) handling.

Two jobs:

1. **Masking at the LLM boundary** (``privacy.mode: mask``). Everything sent to the model — system prompt,
   collected summary, tool results — passes through :class:`Masker`. Personal data is replaced by stable
   pseudonyms (``<email:3f9a1c>``): the same value always gets the same token, so the model can still correlate
   events without seeing the value. Tool arguments and the model's answer are un-masked before they are used or
   stored, so tools keep working (``ip_profile <ip:…>``) and reports show the real values to the human reviewer.
   Secrets (passwords, tokens, private keys) are replaced irreversibly.

2. **Detection in the logs** (``privacy.detect``). A sample of the window's alerts is scanned for personal
   data that should not be in a SIEM in clear text (e-mail addresses, national IDs, IBANs, card numbers,
   phone numbers, plaintext passwords). The result feeds a flag and the report, so the review recommends
   masking at the source.

Detectors validate check digits (Luhn, TCKN, Belgian national number, French NIR, IBAN mod 97) to keep false
positives low. This is best-effort pseudonymisation, not a DLP product.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

# ------------------------------------------------------------------ validators


def luhn_ok(d: str) -> bool:
    s, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0


def card_ok(d: str) -> bool:
    """Luhn + a real issuer prefix (so epoch-millisecond timestamps and counters are not taken for cards)."""
    n = len(d)
    if not 13 <= n <= 19 or len(set(d)) <= 2 or not luhn_ok(d):
        return False
    if n == 13:
        return d[0] == "4"
    return (d[0] == "4" or d[:2] in {"34", "37", "35", "62", "65"} or "51" <= d[:2] <= "55"
            or "2221" <= d[:4] <= "2720" or d[:4] in {"6011", "9792"} or "644" <= d[:3] <= "649"
            or d[:2] in {"50", "56", "57", "58", "63", "67"})


def tckn_ok(d: str) -> bool:
    """Turkish national ID (T.C. Kimlik No): 11 digits, first non-zero, two check digits."""
    if len(d) != 11 or d[0] == "0" or len(set(d)) == 1:
        return False
    n = [int(c) for c in d]
    d10 = ((n[0] + n[2] + n[4] + n[6] + n[8]) * 7 - (n[1] + n[3] + n[5] + n[7])) % 10
    return d10 == n[9] and sum(n[:10]) % 10 == n[10]


def be_nn_ok(d: str) -> bool:
    """Belgian national register number: YYMMDD + 3-digit serial + mod-97 check (1900s or 2000s)."""
    if len(d) != 11 or len(set(d)) == 1:
        return False
    body, chk = int(d[:9]), int(d[9:])
    mm = int(d[2:4])
    if not (0 <= mm <= 12 or 20 <= mm <= 32 or 40 <= mm <= 52):
        return False
    return chk in (97 - body % 97, 97 - int("2" + d[:9]) % 97)


def nir_ok(d: str) -> bool:
    """French social security number (NIR): 13 digits + 2-digit key = 97 - n mod 97."""
    if len(d) != 15 or d[0] not in "1278":
        return False
    return int(d[13:]) == 97 - int(d[:13]) % 97


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    r = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in r)) % 97 == 1
    except ValueError:
        return False


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# ------------------------------------------------------------------ detectors

# (kind, regex, validator on the match → bool, reversible?)
_NB = r"(?<![\w.\-/:@#])"     # not glued to an identifier, path, run id or hash
_NA = r"(?![\w\-/@])"


@dataclass(frozen=True)
class Detector:
    kind: str
    rx: re.Pattern
    ok: Callable[[str], bool] | None = None
    secret: bool = False      # irreversible replacement, never shown again


SECRET_KEYS = r"pass(?:word|wd)?|parola|şifre|sifre|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key"

DETECTORS: list[Detector] = [
    Detector("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
             secret=True),
    Detector("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), secret=True),
    Detector("bearer", re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/=\-]{8,}"), secret=True),
    Detector("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), secret=True),
    # key=value / "key":"value" / key: value — the value only
    Detector("password", re.compile(rf"(?i)(?<![A-Za-z])(?:{SECRET_KEYS})[\"']?\s*[=:]\s*[\"']?"
                                    r"(?P<v>[^\s\"'&,;}{\]\[]{3,})"), secret=True),
    Detector("email", re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")),
    Detector("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), iban_ok),
    Detector("card", re.compile(_NB + r"(?:\d[ -]?){12,18}\d" + r"(?![\d\w\-])"),
             lambda m: card_ok(_digits(m))),
    Detector("national_id_fr", re.compile(_NB + r"[1278] ?\d{2} ?\d{2} ?\d{2} ?\d{3} ?\d{3} ?\d{2}" + r"(?!\d)"),
             lambda m: nir_ok(_digits(m))),
    Detector("national_id_be", re.compile(_NB + r"\d{2}\.?\d{2}\.?\d{2}-?\d{3}\.?\d{2}" + r"(?![\d\w\-])"),
             lambda m: be_nn_ok(_digits(m))),
    Detector("national_id_tr", re.compile(_NB + r"[1-9]\d{10}" + r"(?![\d\w\-])"), tckn_ok),
    Detector("phone", re.compile(_NB + r"(?:\+\d{1,3}(?:[ .-]?\(?\d\)?){7,12}"
                                 r"|0 ?5\d{2}[ .-]?\d{3}[ .-]?\d{2}[ .-]?\d{2})" + r"(?![\d\w])"),
             lambda m: 10 <= len(_digits(m)) <= 15),
]
KINDS = [d.kind for d in DETECTORS] + ["ip"]
_IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
_TOKEN = re.compile(r"<(?P<k>[a-z_][a-z0-9_]*):(?P<h>[0-9a-f]{6,32})>")
TOKEN_HEX = 16          # 64 bit: no realistic collision inside the registry, no brute-force table
_random_salt: bytes | None = None


def salt_source(env=os.environ) -> str:
    """Where the pseudonym key comes from: ``PRIVACY_SALT``, ``APP_SECRET`` or ``random`` (per process)."""
    if env.get("PRIVACY_SALT"):
        return "PRIVACY_SALT"
    if env.get("APP_SECRET"):
        return "APP_SECRET"
    return "random"


def _salt() -> bytes:
    """HMAC key for pseudonyms. There is deliberately no built-in default: with a publicly known key
    anyone holding a token could confirm a guessed value (an IP, a phone number, a national id).
    Without ``PRIVACY_SALT``/``APP_SECRET`` a random key is drawn per process — safe, but pseudonyms
    then change on every restart."""
    global _random_salt
    v = os.environ.get("PRIVACY_SALT") or os.environ.get("APP_SECRET")
    if v:
        return v.encode()
    if _random_salt is None:
        _random_salt = secrets.token_bytes(32)
    return _random_salt


class _Registry:
    """Token → value map of one scope (bounded), so a pseudonym resolves in a later tool call or MCP request."""

    def __init__(self, cap: int = 200_000):
        self.cap = cap
        self.m: OrderedDict[str, str] = OrderedDict()

    def put(self, tok: str, val: str):
        self.m[tok] = val
        self.m.move_to_end(tok)
        while len(self.m) > self.cap:
            self.m.popitem(last=False)

    def get(self, tok: str) -> str | None:
        return self.m.get(tok)


class _Registries:
    """One registry per scope (the environment id).

    A pseudonym created for one environment must not resolve in another: with one shared map, an MCP
    client limited to environment A could pass a token it saw there to a tool of environment B — or
    simply guess — and have B's real value substituted into a query.
    """

    def __init__(self):
        self._by_scope: dict[str, _Registry] = {}

    def scope(self, name: str = "") -> _Registry:
        r = self._by_scope.get(name)
        if r is None:
            r = self._by_scope[name] = _Registry()
        return r

    # the pre-0.10 single registry is the unnamed scope
    def put(self, tok: str, val: str):
        self.scope().put(tok, val)

    def get(self, tok: str) -> str | None:
        return self.scope().get(tok)


REGISTRY = _Registries()

# ------------------------------------------------------------------ custom detectors
MAX_PATTERN = 200
_UNSAFE = [
    (re.compile(r"\\[1-9]|\(\?P=|\(\?P<[^>]*>.*\\g<"), "back-references"),
    (re.compile(r"\(\?<?[=!]"), "look-around"),
    (re.compile(r"\(\?[a-zA-Z]*[^:)a-zA-Z<P]"), "this group syntax"),
    # a quantified group that itself contains a quantifier or alternation: (a+)+, (a|aa)*, (.*a){3,}
    (re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d*,\d*\}|\|)(?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,?\d*\})"),
     "a repeated group that contains a repetition or alternative"),
    (re.compile(r"\.[+*][+*?]?(?:\.|\\[wWsSdD]|\[[^\]]*\])[+*]|(?:\\[wWsSdD]|\[[^\]]*\])[+*][+*?]?\.[+*]"
                r"|(\\[wWsSdD])[+*][+*?]?\1[+*]"), "adjacent unbounded wildcards"),
]
_PROBES = ("a", "1", " ", "a1", "a ", "ab", "<>")


def _probe(c) -> None:
    """Time the compiled pattern on inputs built to trigger backtracking; reject what grows too fast."""
    import time
    for n, budget in ((16, 0.02), (20, 0.02), (24, 0.02), (500, 0.05)):
        for unit in _PROBES:
            text = unit * n + "\x00"
            t0 = time.perf_counter()
            c.search(text)
            if time.perf_counter() - t0 > budget:
                raise ValueError("the pattern is too slow on repetitive text (catastrophic backtracking)")


def compile_custom(pattern: str):
    """Compile a user-supplied pattern so that it can never stall a run.

    With ``google-re2`` installed the pattern is compiled by RE2 (linear time by construction). Without
    it, only a conservative subset of the standard syntax is accepted: no back-references, no
    look-around, no nested or adjacent unbounded repetition. Either way the pattern is short.
    """
    p = str(pattern or "")
    if not p.strip():
        raise ValueError("empty pattern")
    if len(p) > MAX_PATTERN:
        raise ValueError(f"pattern is longer than {MAX_PATTERN} characters")
    try:
        import re2
    except ImportError:
        re2 = None
    if re2 is not None:
        try:
            return re2.compile(p)
        except Exception as e:  # noqa: BLE001 - re2.error
            raise ValueError(f"not a valid RE2 pattern: {e}") from e
    for rx, what in _UNSAFE:
        if rx.search(p):
            raise ValueError(f"{what} is not allowed in custom patterns (it can make matching very slow)")
    try:
        c = re.compile(p)
    except re.error as e:
        raise ValueError(f"not a valid pattern: {e}") from e
    if c.match(""):
        raise ValueError("the pattern matches empty text")
    _probe(c)
    return c


def _allow_rx(a: str):
    try:
        return re.compile(a)
    except re.error:
        return compile_custom(a)


class Masker:
    """Pseudonymise personal data in text sent to an LLM, and map the pseudonyms back.

    ``kinds``: which detectors apply (default: all). ``ips``: ``keep`` (default — IPs are needed for the analysis),
    ``public`` (pseudonymise public addresses, keep private/internal ones) or ``all``. ``allow``: regexes for values
    that are never masked (service accounts such as ``noreply@…``).
    """

    def __init__(self, kinds: list[str] | None = None, ips: str = "keep", allow: list[str] | None = None,
                 enabled: bool = True, scope: str = "", custom: list[tuple[str, str]] | None = None,
                 disabled: list[str] | None = None):
        self.enabled = enabled
        self.scope = scope
        secret = {d.kind for d in DETECTORS if d.secret}
        base = set(kinds or KINDS)
        self.kinds = (base - set(disabled or ())) | (base & secret)      # a profile can never switch a secret off
        self.ips = ips
        self.allow = [_allow_rx(a) for a in allow or []]
        self.custom = [(name, compile_custom(rx)) for name, rx in custom or []]
        self.counts: dict[str, int] = {}

    def _tok(self, kind: str, val: str) -> str:
        h = hmac.new(_salt(), f"{self.scope}|{kind}:{val}".encode() if self.scope else f"{kind}:{val}".encode(),
                     hashlib.sha256).hexdigest()[:TOKEN_HEX]
        tok = f"<{kind}:{h}>"
        REGISTRY.scope(self.scope).put(tok, val)
        return tok

    def _allowed(self, v: str) -> bool:
        return any(a.search(v) for a in self.allow)

    def mask(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        for d in DETECTORS:
            if d.kind not in self.kinds:
                continue

            def rep(m, d=d):
                full = m.group(0)
                val = m.groupdict().get("v") or full
                if (d.ok and not d.ok(val)) or self._allowed(val):
                    return full
                self.counts[d.kind] = self.counts.get(d.kind, 0) + 1
                new = f"<{d.kind}>" if d.secret else self._tok(d.kind, val)
                if m.groupdict().get("v"):
                    a, b = m.start("v") - m.start(), m.end("v") - m.start()
                    return full[:a] + new + full[b:]
                return new
            text = d.rx.sub(rep, text)
        for name, rx in self.custom:
            def crep(m, name=name):
                v = m.group(0)
                if not v or "<" in v or self._allowed(v):      # never re-mask a token
                    return v
                self.counts[name] = self.counts.get(name, 0) + 1
                return self._tok(name, v)
            text = rx.sub(crep, text[:2_000_000])
        if self.ips != "keep" and "ip" in self.kinds:
            def iprep(m):
                v = m.group(0)
                try:
                    ip = ipaddress.ip_address(v)
                except ValueError:
                    return v
                if self.ips == "public" and (ip.is_private or ip.is_loopback or ip.is_link_local):
                    return v
                if self._allowed(v):
                    return v
                self.counts["ip"] = self.counts.get("ip", 0) + 1
                return self._tok("ip", v)
            text = _IPV4.sub(iprep, text)
        return text

    @staticmethod
    def unmask(text: str, scope: str = "") -> str:
        if not text or "<" not in text:
            return text
        reg = REGISTRY.scope(scope)
        return _TOKEN.sub(lambda m: reg.get(m.group(0)) or m.group(0), text)

    @classmethod
    def unmask_obj(cls, o, scope: str = ""):
        if isinstance(o, str):
            return cls.unmask(o, scope)
        if isinstance(o, list):
            return [cls.unmask_obj(x, scope) for x in o]
        if isinstance(o, dict):
            return {k: cls.unmask_obj(v, scope) for k, v in o.items()}
        return o


def masker_for(env, profile=None) -> Masker | None:
    """The environment's masker: the standard profile plus what the site added in the settings page."""
    p = getattr(env, "privacy", None)
    if not p or p.mode == "off":
        return None
    allow = list(p.allow) + list(getattr(profile, "allow", None) or [])
    custom = [(d.name, d.pattern) for d in getattr(profile, "custom", None) or []]
    return Masker(kinds=p.kinds or None, ips=p.ips, allow=allow, scope=getattr(env, "id", ""),
                  custom=custom, disabled=list(getattr(profile, "disabled", None) or []))


def profile_info(env, profile=None) -> dict:
    """What a run records about the masking in force (no patterns, no values)."""
    p = getattr(env, "privacy", None)
    return {"mode": getattr(p, "mode", "off"), "ips": getattr(p, "ips", "keep"),
            "profile_version": int(getattr(profile, "version", 0) or 0),
            "custom": [d.name for d in getattr(profile, "custom", None) or []],
            "disabled": list(getattr(profile, "disabled", None) or [])}


# ------------------------------------------------------------------ LLM wrapper


class MaskingLLM:
    """Wraps an LLM client: what goes out is masked, what comes back is un-masked."""

    def __init__(self, inner, masker: Masker):
        self.inner = inner
        self.masker = masker
        self.name = getattr(inner, "name", "llm")

    def _msg(self, m: dict) -> dict:
        m = dict(m)
        if isinstance(m.get("content"), str):
            m["content"] = self.masker.mask(m["content"])
        if m.get("tool_calls"):
            m["tool_calls"] = [{**c, "input": json.loads(self.masker.mask(json.dumps(c.get("input") or {},
                                                                                    ensure_ascii=False)))}
                               for c in m["tool_calls"]]
        return m

    async def complete(self, system, messages, tools, force_tool=None):
        r = await self.inner.complete(self.masker.mask(system), [self._msg(m) for m in messages], tools,
                                      force_tool=force_tool)
        r.text = Masker.unmask(r.text or "", self.masker.scope)
        for c in r.tool_calls:
            c.input = Masker.unmask_obj(c.input, self.masker.scope)
        return r

    def __getattr__(self, n):
        return getattr(self.inner, n)


# ------------------------------------------------------------------ detection in logs


def scan(text: str, kinds: set[str] | None = None) -> dict[str, int]:
    """Validated personal-data hits in ``text`` per kind (no values returned)."""
    out: dict[str, int] = {}
    for d in DETECTORS:
        if kinds and d.kind not in kinds:
            continue
        for m in d.rx.finditer(text):
            val = m.groupdict().get("v") or m.group(0)
            if d.ok and not d.ok(val):
                continue
            out[d.kind] = out.get(d.kind, 0) + 1
    return out


def scan_alerts(hits: list[dict], kinds: set[str] | None = None, allow: list[str] | None = None,
                top: int = 15) -> dict:
    """Group personal-data hits by rule × agent × location; examples are fully masked."""
    allow_rx = [re.compile(a) for a in allow or []]
    groups: dict[tuple, dict] = {}
    totals: dict[str, int] = {}
    affected = 0
    for h in hits:
        s = h.get("_source") or h
        payload = {k: s.get(k) for k in ("full_log", "data") if s.get(k)}
        desc = str((s.get("rule") or {}).get("description") or "")
        in_desc = scan(desc, kinds) if desc else {}
        txt = json.dumps({**payload, "rule_description": desc}, ensure_ascii=False, default=str)
        for a in allow_rx:
            txt = a.sub("", txt)
        found = scan(txt, kinds)
        if not found:
            continue
        affected += 1
        r = s.get("rule") or {}
        key = (str(r.get("id", "")), (s.get("agent") or {}).get("name", ""), s.get("location", ""))
        g = groups.setdefault(key, {"rule_id": key[0], "rule": r.get("description", ""), "agent": key[1],
                                    "location": key[2], "decoder": (s.get("decoder") or {}).get("name", ""),
                                    "alerts": 0, "kinds": {}, "example": ""})
        g["alerts"] += 1
        if in_desc:   # the rule itself copies personal data into rule.description (indexed, mailed, dashboards)
            g["in_rule_description"] = True
        for k, n in found.items():
            g["kinds"][k] = g["kinds"].get(k, 0) + n
            totals[k] = totals.get(k, 0) + n
        if not g["example"]:
            ex = Masker(ips="keep").mask(str(s.get("full_log") or txt) + (f" | rule: {desc}" if in_desc else ""))
            g["example"] = ex[:300]
    rows = sorted(groups.values(), key=lambda g: (-len([k for k in g["kinds"] if k in SENSITIVE]), -g["alerts"]))
    return {"sampled": len(hits), "affected_alerts": affected, "kinds": totals, "sources": rows[:top]}


# kinds that are clearly a leak (special care) — the rest (e-mail, phone) are often legitimate in auth logs
SENSITIVE = {"password", "private_key", "jwt", "bearer", "aws_key", "card", "iban",
             "national_id_tr", "national_id_be", "national_id_fr"}
