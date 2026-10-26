// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Rüstem Duru
// Small dependency-free client script (CSP: 'self' only). UI strings come from the #i18n JSON block.
"use strict";

let T = {};
try { T = JSON.parse(document.getElementById("i18n").textContent); } catch (e) { T = {}; }
const tr = (k, n) => (T[k] || k).replace("{n}", n);

async function api(url, method = "POST", body) {
  const r = await fetch(url, {
    method, headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin",
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || data.error || `HTTP ${r.status}`);
  return data;
}

function poll(env, runId, el, reload) {
  const tick = async () => {
    try {
      const s = await api(`/api/e/${env}/r/${runId}/status`, "GET");
      if (s.status === "done" || s.status === "error") {
        if (reload) { location.reload(); return; }
        el.innerHTML = s.status === "done"
          ? `${escapeHtml(tr("done"))} <a href="/e/${env}/r/${runId}">${escapeHtml(tr("open"))}</a>`
          : `${escapeHtml(tr("error"))} ${escapeHtml(s.error || "")}`;
        document.querySelectorAll(`[data-run="${env}"]`).forEach(b => { b.disabled = false; b.textContent = tr("now"); });
        return;
      }
      el.textContent = "⏳ " + (s.stage || tr("starting")) + "…";
    } catch (e) { el.textContent = tr("status_fail") + " " + e.message; }
    setTimeout(tick, 2500);
  };
  tick();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

document.addEventListener("DOMContentLoaded", () => {
  // histogram bar heights (CSP forbids inline style attributes)
  document.querySelectorAll(".hist .bar[data-h]").forEach(b => { b.style.height = b.dataset.h + "%"; });
  document.querySelectorAll("[data-w]").forEach(b => { b.style.width = b.dataset.w + "%"; });
  document.querySelectorAll("[data-ah]").forEach(b => { b.style.height = b.dataset.ah + "%"; });
  document.querySelectorAll("[data-print]").forEach(b => b.addEventListener("click", () => window.print()));
  document.querySelectorAll("select[data-autosubmit]").forEach(s => s.addEventListener("change", () => s.form.submit()));

  // start a run
  document.querySelectorAll("[data-run]").forEach(btn => btn.addEventListener("click", async () => {
    const env = btn.dataset.run;
    const hoursSel = btn.dataset.hoursFrom && document.getElementById(btn.dataset.hoursFrom);
    const hours = hoursSel && hoursSel.value ? parseInt(hoursSel.value, 10) : null;
    btn.disabled = true; btn.textContent = tr("running");
    const el = document.querySelector(`[data-runstate="${env}"]`);
    try {
      const r = await api(`/api/e/${env}/run`, "POST", { hours });
      poll(env, r.run_id, el, false);
    } catch (e) { el.textContent = tr("failed_start") + " " + e.message; btn.disabled = false; btn.textContent = tr("now"); }
  }));
  document.querySelectorAll("[data-poll]").forEach(el => poll(el.dataset.runstate, el.dataset.poll, el, !!el.dataset.reload));

  // finding feedback
  document.querySelectorAll("[data-finding]").forEach(box => {
    box.querySelector("[data-save]").addEventListener("click", async () => {
      const out = box.querySelector(".saved");
      const body = {};
      box.querySelectorAll("[data-k]").forEach(i => body[i.dataset.k] = i.value);
      try {
        const r = await api(box.dataset.finding, "POST", body);
        out.textContent = r.knowledge_id ? tr("saved_baseline") : tr("saved");
      } catch (e) { out.textContent = tr("error") + " " + e.message; }
    });
  });

  // answer a question
  document.querySelectorAll("[data-answer]").forEach(box => {
    box.querySelector("[data-save]").addEventListener("click", async () => {
      const ta = box.querySelector("textarea");
      try {
        await api(box.dataset.answer, "POST", { answer: ta.value });
        box.outerHTML = `<p class="answer">✓ ${escapeHtml(ta.value)}</p>`;
      } catch (e) { alertInline(box, e.message); }
    });
  });

  // copy code
  document.querySelectorAll("[data-copy-prev]").forEach(b => b.addEventListener("click", () => {
    copyText(b.previousElementSibling.textContent, b);
  }));

  // knowledge base
  const kf = document.querySelector("[data-kadd]");
  if (kf) kf.addEventListener("submit", async ev => {
    ev.preventDefault();
    const f = new FormData(kf);
    const ids = (f.get("rule_ids") || "").split(",").map(s => s.trim()).filter(Boolean);
    try {
      await api(kf.dataset.kadd, "POST", { kind: f.get("kind"), title: f.get("title"), body: f.get("body"), rule_ids: ids });
      location.reload();
    } catch (e) { alertInline(kf, e.message); }
  });
  // knowledge import (YAML) — preview first, then import
  const ki = document.querySelector("[data-kimport]");
  if (ki) {
    const fileIn = ki.querySelector("[data-kfile]");
    fileIn.addEventListener("change", async () => {
      if (fileIn.files[0]) ki.querySelector("textarea").value = await fileIn.files[0].text();
    });
    ki.addEventListener("submit", async ev => {
      ev.preventDefault();
      const f = new FormData(ki), out = ki.querySelector(".kimport-out");
      const dry = f.get("dry_run") === "on";
      try {
        const r = await api(ki.dataset.kimport, "POST", { text: f.get("text"), update: f.get("update") === "on", dry_run: dry });
        out.innerHTML = (dry ? `<b>${escapeHtml(tr("kb_io_dry"))}:</b> ` : "")
          + escapeHtml(tr("kb_io_result").replace("{added}", r.added).replace("{updated}", r.updated)
                       .replace("{skipped}", r.skipped).replace("{errors}", r.errors.length))
          + (r.errors.length ? `<ul class="bad">${r.errors.map(e => `<li>${escapeHtml(e)}</li>`).join("")}</ul>` : "");
        if (!dry && (r.added || r.updated)) setTimeout(() => location.reload(), 1500);
      } catch (e) { out.innerHTML = `<p class="bad">${escapeHtml(e.message)}</p>`; }
    });
  }

  document.querySelectorAll("[data-k]").forEach(card => {
    if (card.tagName !== "ARTICLE") return;
    const url = card.dataset.k;
    card.querySelectorAll("[data-set]").forEach(b => b.addEventListener("click", async () => {
      await api(url, "POST", { status: b.dataset.set }); location.reload();
    }));
    // rule drafts: commands / deploy / remove
    const out = card.querySelector(".rd-out");
    const show = html => { out.hidden = false; out.innerHTML = html; };
    const listHtml = (cls, title, items) => items && items.length
      ? `<div class="${cls}"><b>${escapeHtml(title)}</b><ul>${items.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul></div>` : "";
    const rep = card.querySelector("[data-copy-report]");
    if (rep) rep.addEventListener("click", () => copyText(cardReport(card), rep));
    const stepsHtml = rec => `<ul class="steps">${(rec.steps || []).map(s =>
      `<li class="${s.ok ? "ok" : "bad"}">${s.ok ? "✓" : "✗"} ${escapeHtml(s.step)} ${escapeHtml(s.detail || "")}</li>`).join("")}</ul>`
      + (rec.error ? `<p class="bad">${escapeHtml(rec.error)}</p>` : "");
    const cmds = card.querySelector("[data-cmds]");
    if (cmds) cmds.addEventListener("click", async () => {
      cmds.disabled = true;
      try {
        const v = await api(url + "/rule", "GET");
        show(listHtml("bad", tr("rd_errors"), v.analysis.errors) + listHtml("warn", tr("rd_risky"), v.analysis.risky)
          + (v.deploy_enabled ? "" : `<p class="muted">${escapeHtml(tr("rd_disabled"))}</p>`)
          + `<p class="muted">${escapeHtml(tr("rd_cmds_note"))}</p><pre class="code">${escapeHtml(v.commands)}</pre>`
          + `<button class="btn small" data-copy-out>${escapeHtml(tr("copy"))}</button>`);
        out.querySelector("[data-copy-out]").addEventListener("click", ev => {
          navigator.clipboard.writeText(v.commands); ev.target.textContent = tr("copied"); });
      } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); }
      cmds.disabled = false;
    });
    const ver = card.querySelector("[data-verify]");
    if (ver) ver.addEventListener("click", async () => {
      ver.disabled = true;
      try { await api(url + "/verify", "POST"); location.reload(); }
      catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); ver.disabled = false; }
    });
    const pro = card.querySelector("[data-promote]");
    if (pro) pro.addEventListener("click", async () => {
      pro.disabled = true;
      let p;
      try { p = await api(url + "/promote", "GET"); } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); pro.disabled = false; return; }
      const blocks = [["pr_block", p.block], ["pr_script", p.script]];
      if (p.catalog_file) blocks.push(["pr_catalog", p.catalog_md]);
      show(`<div class="promo">${listHtml("bad", tr("rd_errors"), p.errors)}
        <b>${escapeHtml(tr("pr_steps"))}</b><ol>${p.steps.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ol>
        ${blocks.map(([k, v], i) => `<details ${i === 1 ? "open" : ""}><summary>${escapeHtml(tr(k))}</summary>
          <pre class="code">${escapeHtml(v)}</pre><button class="btn small" data-pcopy="${i}">${escapeHtml(tr("copy"))}</button></details>`).join("")}
        <div class="row"><button class="btn small primary" data-pdone ${p.still_deployed ? "disabled" : ""}>${escapeHtml(tr("pr_mark"))}</button>
        ${p.still_deployed ? `<span class="small muted">${escapeHtml(tr("pr_remove_first"))}</span>` : ""}</div></div>`);
      out.querySelectorAll("[data-pcopy]").forEach(b => b.addEventListener("click", () => copyText(blocks[+b.dataset.pcopy][1], b)));
      const done = out.querySelector("[data-pdone]");
      done.addEventListener("click", async () => {
        if (!confirm(tr("pr_mark_confirm"))) return;
        try { await api(url + "/promoted", "POST"); location.reload(); } catch (e) { alertInline(out, e.message); }
      });
      pro.disabled = false;
    });
    const dep = card.querySelector("[data-deploy]");
    if (dep) dep.addEventListener("click", async () => {
      let v;
      try { v = await api(url + "/rule", "GET"); } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); return; }
      const a = v.analysis;
      if (a.errors.length) { show(listHtml("bad", tr("rd_errors"), a.errors)); return; }
      let confirmText = "";
      if (a.risky.length) {
        confirmText = prompt(tr("rd_type_ids").replace("{reasons}", a.risky.join("\n")).replace("{ids}", a.ids.join(",")));
        if (confirmText === null) return;
      } else if (!confirm(tr("rd_confirm").replace("{file}", v.file))) return;
      card.querySelectorAll("button").forEach(b => b.disabled = true);
      show(`<p>⏳ ${escapeHtml(tr("rd_working"))}</p>`);
      try {
        const rec = await api(url + "/deploy", "POST", { confirm: confirmText });
        show(stepsHtml(rec));
        setTimeout(() => location.reload(), rec.state === "deployed" ? 2500 : 8000);
      } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); card.querySelectorAll("button").forEach(b => b.disabled = false); }
    });
    const und = card.querySelector("[data-undeploy]");
    if (und) und.addEventListener("click", async () => {
      let v;
      try { v = await api(url + "/rule", "GET"); } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); return; }
      if (!confirm(tr("rd_unconfirm").replace("{file}", v.file))) return;
      card.querySelectorAll("button").forEach(b => b.disabled = true);
      show(`<p>⏳ ${escapeHtml(tr("rd_working"))}</p>`);
      try { const rec = await api(url + "/undeploy", "POST"); show(stepsHtml(rec)); setTimeout(() => location.reload(), 2500); }
      catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); card.querySelectorAll("button").forEach(b => b.disabled = false); }
    });

    const del = card.querySelector("[data-del]");
    if (del) del.addEventListener("click", async () => {
      if (del.dataset.confirm !== "1") { del.dataset.confirm = "1"; del.textContent = tr("sure"); return; }
      await api(url, "DELETE"); card.remove();
    });
    const ed = card.querySelector("[data-edit]");
    if (ed) ed.addEventListener("click", () => {
      const t = card.querySelector(".ktitle");
      const form = document.createElement("div");
      form.className = "kform";
      const xmlPre = card.querySelector("pre.code"), isDraft = !!card.querySelector(".rd-out");
      form.innerHTML = `<input value="${escapeHtml(t.textContent)}"><textarea rows="5" data-body></textarea>`
        + (isDraft ? `<label class="small muted">Rule XML</label><textarea rows="10" class="mono" data-xml></textarea>` : "")
        + `<div class="row"><button class="btn small primary">${escapeHtml(tr("save"))}</button></div>`;
      fetchBody(card, form.querySelector("[data-body]"));
      if (isDraft) form.querySelector("[data-xml]").value = xmlPre ? xmlPre.textContent.trim() : "";
      card.appendChild(form); ed.disabled = true;
      form.querySelector("button").addEventListener("click", async () => {
        const data = { title: form.querySelector("input").value, body: form.querySelector("[data-body]").value };
        if (isDraft) data.xml = form.querySelector("[data-xml]").value;
        try { await api(url, "POST", data); location.reload(); } catch (e) { alertInline(form, e.message); }
      });
    });
  });

  // open a chat about a finding
  document.querySelectorAll("[data-chat-finding]").forEach(b => b.addEventListener("click", async () => {
    b.disabled = true;
    try { const r = await api(b.dataset.chatFinding, "POST"); location.href = r.url; }
    catch (e) { b.disabled = false; alert(e.message); }
  }));

  // recommendation inbox: one decision applies to every occurrence, then the next item
  const card = document.getElementById("inbox");
  if (card) card.querySelectorAll("[data-status]").forEach(b => b.addEventListener("click", async () => {
    const out = card.querySelector(".saved");
    card.querySelectorAll("button").forEach(x => x.disabled = true);
    try {
      await api(card.dataset.act, "POST", { refs: JSON.parse(card.dataset.refs), user_status: b.dataset.status,
                                            user_note: card.querySelector("[data-note]").value });
      location.href = card.dataset.next;   // the same index now shows the next item
    } catch (e) { out.textContent = tr("error") + " " + e.message; card.querySelectorAll("button").forEach(x => x.disabled = false); }
  }));

  // connection test
  document.querySelectorAll("[data-check]").forEach(btn => btn.addEventListener("click", async () => {
    const box = document.getElementById("checks");
    btn.disabled = true; btn.textContent = tr("testing"); box.hidden = false; box.textContent = tr("testing");
    try {
      const r = await api(`/api/e/${btn.dataset.check}/check`, "POST");
      box.innerHTML = "<ul class='checklist'>" + r.results.map(x =>
        `<li class="${x.ok ? "ok" : "bad"}"><b>${escapeHtml(x.ok ? tr("ok") : tr("fail"))}</b> ${escapeHtml(x.label)} — <span class="small">${escapeHtml(x.detail)}</span></li>`).join("") + "</ul>";
    } catch (e) { box.textContent = tr("error") + " " + e.message; }
    btn.disabled = false; btn.textContent = tr("test");
  }));

  // notification test
  document.querySelectorAll("[data-notify-test]").forEach(btn => btn.addEventListener("click", async () => {
    const box = document.getElementById("checks");
    btn.disabled = true; box.hidden = false; box.textContent = tr("testing");
    try {
      const r = await api(`/api/e/${btn.dataset.notifyTest}/notify-test`, "POST");
      box.innerHTML = r.results.length ? "<ul class='checklist'>" + r.results.map(x =>
        `<li class="${x.ok ? "ok" : "bad"}"><b>${escapeHtml(x.ok ? tr("ok") : tr("fail"))}</b> ${escapeHtml(x.channel)} — <span class="small">${escapeHtml(x.detail)}</span></li>`).join("") + "</ul>"
        : escapeHtml(r.message || "");
    } catch (e) { box.textContent = tr("error") + " " + e.message; }
    btn.disabled = false;
  }));

  // chat
  const chat = document.querySelector("[data-chat]");
  if (chat) initChat(chat);
});

function fetchBody(card, ta) { const raw = card.querySelector(".kraw"); ta.value = raw ? raw.value : ""; }

function alertInline(el, msg) {
  let p = el.querySelector(".err");
  if (!p) { p = document.createElement("p"); p.className = "err small"; el.appendChild(p); }
  p.textContent = msg;
}

function initChat(chat) {
  const msgs = document.getElementById("msgs");
  const form = document.getElementById("composer");
  const ta = form.querySelector("textarea");
  let session = chat.dataset.session || null;
  msgs.scrollTop = msgs.scrollHeight;
  document.querySelectorAll("[data-suggest]").forEach(li => li.addEventListener("click", () => { ta.value = li.textContent; ta.focus(); }));
  ta.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    const text = ta.value.trim();
    if (!text) return;
    const hint = msgs.querySelector(".hint"); if (hint) hint.remove();
    add("user", `<span class="ut">${escapeHtml(text)}</span>`);
    ta.value = ""; form.querySelector("button").disabled = true;
    const pend = add("assistant pending", escapeHtml(tr("thinking")));
    try {
      const r = await api(chat.dataset.chat, "POST", { text, session });
      if (!session) { session = r.session; history.replaceState(null, "", `?s=${session}`); }
      pend.classList.remove("pending");
      let html = r.html;
      if (r.trace && r.trace.length) {
        html += `<details class="small"><summary>${escapeHtml(tr("tools", r.trace.length))}</summary><ol>` +
          r.trace.map(t => `<li><code>${escapeHtml(t.tool)}</code> ${escapeHtml(JSON.stringify(t.input))}</li>`).join("") + "</ol></details>";
      }
      if (r.proposals && r.proposals.length) html += `<p class="small"><a href="k?status=proposed">${escapeHtml(tr("proposals", r.proposals.length))}</a></p>`;
      pend.innerHTML = html;
    } catch (e) { pend.classList.remove("pending"); pend.innerHTML = `<span class="err">${escapeHtml(tr("error"))} ${escapeHtml(e.message)}</span>`; }
    form.querySelector("button").disabled = false;
    msgs.scrollTop = msgs.scrollHeight;
  });
  function add(cls, html) {
    const d = document.createElement("div"); d.className = "msg " + cls; d.innerHTML = html; msgs.appendChild(d);
    msgs.scrollTop = msgs.scrollHeight; return d;
  }
}

// plain-text report of a knowledge card (to paste into a chat / ticket)
function cardReport(card) {
  const t = sel => { const e = card.querySelector(sel); return e ? e.innerText.trim() : ""; };
  const lines = [t(".ktitle"), Array.from(card.querySelectorAll(".row .pill")).map(p => p.innerText.trim()).join(" · ")];
  const body = card.querySelector(".kraw"); if (body && body.value.trim()) lines.push("", body.value.trim());
  card.querySelectorAll(":scope > p.small").forEach(p => lines.push("", p.innerText.trim()));
  const steps = Array.from(card.querySelectorAll("ul.steps li")).map(li => li.innerText.trim());
  const out = card.querySelector(".rd-out");
  if (out && !out.hidden && out.innerText.trim()) lines.push("", out.innerText.trim());
  else if (steps.length) lines.push("", ...steps);
  const xml = card.querySelector("pre.code"); if (xml) lines.push("", "```xml", xml.textContent.trim(), "```");
  return lines.filter((x, i) => x || lines[i - 1]).join("\n");
}

function copyText(text, btn) {
  const done = () => { if (btn) { const o = btn.textContent; btn.textContent = tr("copied"); setTimeout(() => btn.textContent = o, 1500); } };
  if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done); return; }
  const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); done(); } finally { ta.remove(); }
}
