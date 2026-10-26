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
    navigator.clipboard.writeText(b.previousElementSibling.textContent); b.textContent = tr("copied");
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
      form.innerHTML = `<input value="${escapeHtml(t.textContent)}"><textarea rows="5"></textarea>
        <div class="row"><button class="btn small primary">${escapeHtml(tr("save"))}</button></div>`;
      fetchBody(card, form.querySelector("textarea"));
      card.appendChild(form); ed.disabled = true;
      form.querySelector("button").addEventListener("click", async () => {
        await api(url, "POST", { title: form.querySelector("input").value, body: form.querySelector("textarea").value });
        location.reload();
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
