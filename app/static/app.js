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

  // copy a finding / question as plain text
  document.querySelectorAll("[data-copy-text]").forEach(b => b.addEventListener("click", () => {
    copyText(b.dataset.copyText, b);
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
  document.querySelectorAll("[data-noise-mode]").forEach(b => b.addEventListener("click", async () => {
    const row = b.closest("[data-noise]");
    b.disabled = true;
    try {
      const k = await api(row.dataset.noise, "POST", { rule_id: row.dataset.rule, mode: b.dataset.noiseMode });
      b.replaceWith(Object.assign(document.createElement("a"), {
        href: location.pathname.replace(/\/noise$/, "/k") + (b.dataset.noiseMode === "skeleton" ? "?kind=rule_draft" : "?kind=request"),
        textContent: "✓ " + tr("nm_done"), className: "small" }));
    } catch (e) {
      b.disabled = false;
      const err = Object.assign(document.createElement("div"), { className: "small bad", textContent: e.message });
      b.after(err);
    }
  }));

  const ki = document.querySelector("[data-kimport]");
  if (ki) {
    const fileIn = ki.querySelector("[data-kfile]");
    fileIn.addEventListener("change", async () => {
      if (fileIn.files[0]) {
        ki.querySelector("textarea").value = await fileIn.files[0].text();
        ki.querySelector("[name=filename]").value = fileIn.files[0].name;
      }
    });
    ki.addEventListener("submit", async ev => {
      ev.preventDefault();
      const f = new FormData(ki), out = ki.querySelector(".kimport-out");
      const dry = f.get("dry_run") === "on";
      try {
        const r = await api(ki.dataset.kimport, "POST", { text: f.get("text"), update: f.get("update") === "on",
                                                           dry_run: dry, filename: f.get("filename") || "" });
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
        out.querySelector("[data-copy-out]").addEventListener("click", ev => copyText(v.commands, ev.target));
      } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); }
      cmds.disabled = false;
    });
    const wi = card.querySelector("[data-whatif]");
    if (wi) wi.addEventListener("click", async () => {
      wi.disabled = true;
      show(`<p class="muted">${escapeHtml(tr("wi_working"))}</p>`);
      try {
        const v = await api(url + "/whatif?days=14", "GET");
        if (!v.ok) { show(listHtml("bad", tr("rd_errors"), v.errors)); wi.disabled = false; return; }
        const n = x => Number(x || 0).toLocaleString();
        const pairs = a => (a || []).filter(x => x[0]).map(x => `${escapeHtml(x[0])} (${n(x[1])})`).join(", ") || "—";
        show(v.rules.map(r => {
          if (r.note) return `<p><b>${escapeHtml(r.id)}</b>: ${escapeHtml(r.note)}</p>`;
          const lvls = Object.entries(r.parent_levels || {}).map(([k, c]) => `L${k}: ${n(c)}`).join(" · ");
          const lost = r.high_before && !r.high_after;
          return `<div class="whatif"><b>${escapeHtml(tr("wi_title").replace("{id}", r.id).replace("{days}", v.days))}</b>
            <table class="tbl"><tbody>
            <tr><td>${escapeHtml(tr("wi_parent"))} (${escapeHtml((r.parents || []).join(", "))})</td><td>${n(r.parent_events)} · ${lvls}</td></tr>
            <tr><td>${escapeHtml(tr("wi_matched"))}</td><td><b>${n(r.estimated)}</b> (${n(r.per_day)}/${escapeHtml(tr("wi_day"))}, %${Math.round((r.share || 0) * 1000) / 10})
              ${r.exact ? "" : `<span class="muted">· ${escapeHtml(tr("wi_sample").replace("{s}", n(r.sampled)))}</span>`}</td></tr>
            <tr><td>${escapeHtml(tr("wi_level"))}</td><td>→ L${escapeHtml(String(r.new_level ?? "?"))}</td></tr>
            <tr class="${lost ? "bad" : ""}"><td>${escapeHtml(tr("wi_high").replace("{l}", r.high_level))}</td><td>${n(r.high_before)} → ${n(r.high_after)}</td></tr>
            <tr><td>${escapeHtml(tr("wi_agents"))}</td><td>${pairs(r.top_agents)}</td></tr>
            <tr><td>${escapeHtml(tr("wi_ips"))}</td><td>${pairs(r.top_srcips)}</td></tr>
            <tr><td>${escapeHtml(tr("wi_locs"))}</td><td>${pairs(r.top_locations)}</td></tr>
            </tbody></table>
            ${(r.examples || []).length ? `<b>${escapeHtml(tr("wi_ex"))}</b><pre class="code">${escapeHtml(r.examples.join("\n"))}</pre>` : ""}
            ${(r.unmatched_examples || []).length ? `<b>${escapeHtml(tr("wi_unex"))}</b><pre class="code">${escapeHtml(r.unmatched_examples.join("\n"))}</pre>` : ""}
            ${(r.not_evaluated || []).length ? `<p class="warn">${escapeHtml(tr("wi_skipped"))}: ${escapeHtml(r.not_evaluated.join(", "))}</p>` : ""}
            </div>`;
        }).join("") + `<p class="muted">${escapeHtml(tr("wi_note"))}</p>`);
      } catch (e) { show(`<p class="bad">${escapeHtml(e.message)}</p>`); }
      wi.disabled = false;
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

  // incident record drafts
  document.querySelectorAll("[data-incident]").forEach(box => {
    const url = box.dataset.incident, md = box.querySelector(".inc-md"), area = box.querySelector(".inc-box");
    const render = () => {
      area.hidden = false;
      area.innerHTML = `<textarea rows="22" class="mono">${escapeHtml(md.value)}</textarea>
        <div class="row small"><button class="btn small primary" data-inc-save>${escapeHtml(tr("save"))}</button>
        <button class="btn small" data-inc-copy>${escapeHtml(tr("copy"))}</button>
        <button class="btn small" data-inc-dl>${escapeHtml(tr("inc_download"))}</button>
        <button class="btn small" data-inc-regen>${escapeHtml(tr("inc_regen"))}</button>
        ${box.dataset.zammad === "1" ? `<button class="btn small" data-inc-ticket="zammad">${escapeHtml(tr("inc_ticket"))}</button>` : ""}
        ${box.dataset.jira === "1" ? `<button class="btn small" data-inc-ticket="jira">${escapeHtml(tr("inc_ticket_jira"))}</button>` : ""}
        <span class="small muted inc-msg"></span></div>`;
      const ta = area.querySelector("textarea"), msg = area.querySelector(".inc-msg");
      area.querySelector("[data-inc-save]").addEventListener("click", async () => {
        try { await api(url + "/save", "POST", { md: ta.value }); md.value = ta.value; msg.textContent = tr("saved"); }
        catch (e) { msg.textContent = e.message; }
      });
      area.querySelector("[data-inc-copy]").addEventListener("click", ev => copyText(ta.value, ev.target));
      area.querySelector("[data-inc-dl]").addEventListener("click", () => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(new Blob([ta.value], { type: "text/markdown" }));
        a.download = box.dataset.file; a.click(); URL.revokeObjectURL(a.href);
      });
      area.querySelector("[data-inc-regen]").addEventListener("click", () => generate());
      area.querySelectorAll("[data-inc-ticket]").forEach(tk => tk.addEventListener("click", async () => {
        tk.disabled = true;
        try {
          const t = await api(url + "/ticket", "POST", { md: ta.value, provider: tk.dataset.incTicket });
          msg.innerHTML = `<a href="${escapeHtml(t.url)}" target="_blank" rel="noopener">#${escapeHtml(String(t.number))}</a>`;
        } catch (e) { msg.textContent = e.message; tk.disabled = false; }
      }));
    };
    const generate = async () => {
      area.hidden = false; area.innerHTML = `<p class="small">⏳ ${escapeHtml(tr("inc_working"))}</p>`;
      try { const r = await api(url, "POST"); md.value = r.md; box.dataset.file = r.id + ".md"; render(); }
      catch (e) { area.innerHTML = `<p class="bad small">${escapeHtml(e.message)}</p>`; }
    };
    box.querySelector("[data-inc-open]").addEventListener("click", () => {
      if (!area.hidden) { area.hidden = true; return; }
      md.value ? render() : generate();
    });
  });

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
});

function fetchBody(card, ta) { const raw = card.querySelector(".kraw"); ta.value = raw ? raw.value : ""; }

function alertInline(el, msg) {
  let p = el.querySelector(".err");
  if (!p) { p = document.createElement("p"); p.className = "err small"; el.appendChild(p); }
  p.textContent = msg;
}

// plain-text report of a knowledge card (to paste into a ticket)
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

let liveRegion;
function announce(msg) {
  if (!liveRegion) {
    liveRegion = document.createElement("div");
    liveRegion.className = "sr-only";
    liveRegion.setAttribute("role", "status");
    liveRegion.setAttribute("aria-live", "polite");
    document.body.appendChild(liveRegion);
  }
  liveRegion.textContent = "";
  setTimeout(() => { liveRegion.textContent = msg; }, 30);
}

function copyText(text, btn) {
  const done = ok => {
    announce(tr(ok ? "copied" : "copy_failed"));
    if (!btn || !ok) return;
    const o = btn.textContent;
    btn.textContent = tr("copied");
    setTimeout(() => { btn.textContent = o; }, 1500);
  };
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } finally { ta.remove(); }
    done(ok);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => done(true), fallback);
    return;
  }
  fallback();
}

// ---------------------------------------------------------------- settings / watch / backup (0.10)
function setPath(obj, path, val) {
  const parts = path.split(".");
  let cur = obj;
  parts.slice(0, -1).forEach(p => { cur = cur[p] = cur[p] || {}; });
  cur[parts[parts.length - 1]] = val;
}

function formObject(form) {
  const out = {}, multi = {};
  form.querySelectorAll("[name]").forEach(el => {
    const type = el.dataset.type || "";
    if (type === "multi" || type === "multi-or-null" || type === "times") {
      const m = multi[el.name] = multi[el.name] || { type, vals: [] };
      if (type === "times") { if (el.value) m.vals.push(el.value); } else if (el.checked) m.vals.push(el.value);
      return;
    }
    if (el.type === "radio") { if (el.checked) setPath(out, el.name, el.value); return; }
    if (el.type === "checkbox") { setPath(out, el.name, el.checked); return; }
    if (el.type === "file" || el.type === "password") return;
    let v = el.value;
    if (type === "lines") v = v.split("\n").map(s => s.trim()).filter(Boolean);
    else if (type === "list-or-null") v = v.trim() ? v.split(/[,\s]+/).filter(Boolean) : null;
    else if (el.type === "number") v = type === "float" ? parseFloat(v) : parseInt(v, 10);
    setPath(out, el.name, v);
  });
  Object.entries(multi).forEach(([name, m]) => {
    setPath(out, name, (m.type !== "multi" && !m.vals.length) ? null : m.vals);
  });
  return out;
}

function note(form, msg, bad) {
  const el = form.querySelector(".saved");
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle("err", !!bad);
  announce(msg);
}

function maskProfile(form) {
  const custom = [];
  form.querySelectorAll("[data-custom-rows] tr").forEach(row => {
    const c = {};
    row.querySelectorAll("[data-c]").forEach(i => { c[i.dataset.c] = i.value.trim(); });
    if (c.name || c.pattern) custom.push(c);
  });
  const disabled = [];
  form.querySelectorAll("[data-detector]").forEach(i => { if (!i.checked && !i.disabled) disabled.push(i.dataset.detector); });
  const allow = form.querySelector("[data-allow]").value.split("\n").map(s => s.trim()).filter(Boolean);
  return { custom, allow, disabled };
}

async function fileB64(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  let s = "";
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
  return btoa(s);
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-settings]").forEach(form => form.addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      await api(form.dataset.settings, "POST", { [form.dataset.section]: formObject(form) });
      note(form, "✓ " + tr("saved"));
      if (form.dataset.section !== "backup") setTimeout(() => location.reload(), 600);
    } catch (e) { note(form, tr("error") + " " + e.message, true); }
  }));

  document.querySelectorAll("form[data-mask]").forEach(form => {
    const save = async confirmOff => {
      try {
        await api(form.dataset.mask, "POST", { mask: maskProfile(form), confirm: confirmOff });
        note(form, "✓ " + tr("saved"));
        setTimeout(() => location.reload(), 600);
      } catch (e) {
        if (!confirmOff && /^confirm:/.test(e.message)) {
          if (window.confirm(tr("set_confirm_off") + "\n\n" + e.message.replace(/^confirm:\s*/, ""))) return save(true);
          return note(form, "");
        }
        note(form, tr("error") + " " + e.message, true);
      }
    };
    form.addEventListener("submit", ev => { ev.preventDefault(); save(false); });
    const rows = form.querySelector("[data-custom-rows]");
    form.querySelector("[data-row-add]").addEventListener("click", () => {
      const trEl = document.createElement("tr");
      trEl.innerHTML = '<td><input data-c="name" placeholder="x_customer_no" maxlength="26"></td>'
        + '<td><input data-c="pattern" class="mono" placeholder="CUST-\\d{6}" maxlength="200"></td>'
        + '<td><input data-c="description" maxlength="200"></td>'
        + '<td><button type="button" class="btn small ghost" data-row-del>✕</button></td>';
      rows.appendChild(trEl);
    });
    rows.addEventListener("click", ev => { if (ev.target.matches("[data-row-del]")) ev.target.closest("tr").remove(); });
    const pv = form.querySelector("[data-preview]");
    pv.addEventListener("click", async () => {
      const out = form.querySelector("[data-preview-out]");
      try {
        const r = await api(pv.dataset.preview, "POST", { text: form.querySelector("[data-preview-in]").value, mask: maskProfile(form) });
        const counts = Object.entries(r.counts).map(([k, n]) => `${k}: ${n}`).join(" · ");
        out.textContent = r.masked + (counts ? "\n\n— " + counts : "");
      } catch (e) { out.textContent = tr("error") + " " + e.message; }
      out.hidden = false;
    });
    const imp = form.querySelector("[data-mask-import]");
    imp.addEventListener("change", async () => {
      if (!imp.files.length) return;
      const text = await imp.files[0].text();
      const send = async confirmOff => {
        try {
          await api(imp.dataset.maskImport, "POST", { text, confirm: confirmOff });
          location.reload();
        } catch (e) {
          if (!confirmOff && /^confirm:/.test(e.message) && window.confirm(tr("set_confirm_off"))) return send(true);
          note(form, tr("error") + " " + e.message, true);
        }
      };
      send(false);
    });
  });

  document.querySelectorAll("[data-suggestion]").forEach(box => box.querySelectorAll("[data-act]").forEach(b =>
    b.addEventListener("click", async () => {
      try {
        await api(box.dataset.suggestion, "POST", { event_id: box.dataset.event, action: b.dataset.act });
        location.reload();
      } catch (e) { note(box, tr("error") + " " + e.message, true); }
    })));

  document.querySelectorAll("[data-post]").forEach(b => b.addEventListener("click", async () => {
    if (b.dataset.confirm && !window.confirm(b.dataset.confirm)) return;
    const host = b.closest(".card, .tools") || document.body;
    b.disabled = true;
    try {
      const r = await api(b.dataset.post, "POST");
      if (r && r.events !== undefined) note(host, tr("set_scan").replace("{n}", r.events));
      setTimeout(() => location.reload(), b.dataset.reload ? 900 : 300);
    } catch (e) { note(host, tr("error") + " " + e.message, true); b.disabled = false; }
  }));

  document.querySelectorAll("select[data-autosubmit-get]").forEach(s => s.addEventListener("change", () => {
    const u = new URL(location.href);
    if (s.value) u.searchParams.set(s.dataset.autosubmitGet, s.value); else u.searchParams.delete(s.dataset.autosubmitGet);
    location.href = u.toString();
  }));

  document.querySelectorAll("form[data-backup-export]").forEach(form => form.addEventListener("submit", async ev => {
    ev.preventDefault();
    const p1 = form.querySelector("[name=passphrase]").value, p2 = form.querySelector("[name=passphrase2]").value;
    if (p1 !== p2) return note(form, tr("bk_mismatch"), true);
    note(form, tr("bk_working"));
    try {
      const r = await api(form.dataset.backupExport, "POST", {
        passphrase: p1, to_s3: form.querySelector("[name=to_s3]").checked,
        include_runs: form.querySelector("[name=include_runs]").checked });
      const bin = atob(r.data_b64), buf = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([buf], { type: "application/octet-stream" }));
      a.download = r.filename; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      form.reset();
      note(form, "✓ " + tr("bk_done").replace("{n}", r.bytes.toLocaleString()) + (r.s3 ? " · " + r.s3 : "")
        + (r.s3_error ? " · S3: " + r.s3_error : ""), !!r.s3_error);
    } catch (e) { note(form, tr("error") + " " + e.message, true); }
  }));

  document.querySelectorAll("form[data-backup-import]").forEach(form => {
    const out = form.querySelector("[data-import-out]");
    const real = form.querySelector('[data-dry="0"]');
    form.querySelector("[name=file]").addEventListener("change", () => { real.disabled = true; out.textContent = ""; });
    form.querySelectorAll("[name=mode]").forEach(r => r.addEventListener("change", () => { real.disabled = true; }));
    form.addEventListener("submit", async ev => {
      ev.preventDefault();
      const dry = (ev.submitter && ev.submitter.dataset.dry) !== "0";
      const file = form.querySelector("[name=file]").files[0];
      if (!file) return;
      note(form, tr("bk_working"));
      try {
        const r = await api(form.dataset.backupImport, "POST", {
          data_b64: await fileB64(file), passphrase: form.querySelector("[name=passphrase]").value,
          mode: form.querySelector("[name=mode]:checked").value, dry_run: dry });
        const lines = Object.entries(r.kinds).map(([k, v]) => tr("bk_plan").replace("{kind}", k)
          .replace("{add}", v.add).replace("{change}", v.change).replace("{same}", v.unchanged));
        if (r.rule_drafts_reset) lines.push(tr("bk_reset").replace("{n}", r.rule_drafts_reset));
        if (r.other_env) lines.push(tr("bk_other_env").replace("{env}", r.archive.env));
        out.innerHTML = `<div class="muted">${escapeHtml(r.archive.env_name || "")} · ${escapeHtml(r.archive.created_at || "")} · ${escapeHtml(r.archive.app_version || "")}</div>`
          + lines.map(l => `<div>${escapeHtml(l)}</div>`).join("");
        real.disabled = !dry;
        note(form, dry ? "" : "✓ " + tr("bk_imported"));
        if (!dry) setTimeout(() => location.reload(), 1500);
      } catch (e) { real.disabled = true; note(form, tr("error") + " " + e.message, true); }
    });
  });
});
