# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Messages added in 0.11 (dashboard, charts, MITRE ATT&CK, SSO roles). Merged into ``app.i18n.CATALOG``; the
parity check there covers these keys too. ATT&CK tactic and technique names stay in English (MITRE's names)."""
from __future__ import annotations

EN: dict[str, str] = {
    "nav.overview": "Overview", "nav.attack": "ATT&CK", "nav.signed_in": "Signed in as {who}",
    "role.admin": "administrator", "role.viewer": "read-only",
    "auth.no_role": "You are signed in, but your account has no role in this application. Ask an administrator to "
                    "add you to one of the groups in SSO_ADMIN_GROUPS or SSO_VIEWER_GROUPS.",
    "dash.envs": "Environments", "dash.period": "Period",
    "dash.period.24h": "24 h", "dash.period.7d": "7 days", "dash.period.30d": "30 days",
    "dash.vs_prev": "compared with the previous {p}", "dash.vs_prev_short": "vs prev.",
    "dash.k.alerts": "Alerts", "dash.k.high": "Level {n}+", "dash.k.crit": "Critical (12+)",
    "dash.k.agents": "Agents reporting", "dash.k.agents_sub": "with alerts in the period",
    "dash.k.inbox": "Recommendations", "dash.k.urgent": "{n} urgent", "dash.k.questions": "Open questions",
    "dash.k.proposals": "{n} knowledge proposal(s)",
    "dash.vol": "Alert volume", "dash.sev": "Severity",
    "dash.legend.total": "All alerts", "dash.legend.high": "Level {n}+", "dash.legend.crit": "Critical",
    "band.critical": "Critical", "band.high": "High", "band.medium": "Medium", "band.low": "Low",
    "band.range": "level {a}–{b}",
    "dash.att": "MITRE ATT&CK tactics", "dash.att_open": "Open the matrix",
    "dash.att_tech": "{n} techniques", "dash.att_silent": "no alerts",
    "dash.att_none": "No alert in this period carries an ATT&CK mapping.",
    "dash.mitre_share": "{p} % of the alerts carry an ATT&CK mapping",
    "dash.top_rules": "Top rules at level {n}+", "dash.top_agents": "Most active agents",
    "dash.top_src": "Top source addresses", "dash.none": "No data in this period.", "dash.work": "Work queue",
    "dash.nodata": "The numbers could not be loaded — the indexer did not answer. The work queue below still works.",
    "att.title": "MITRE ATT&CK",
    "att.intro": "Alerts grouped by the ATT&CK tactics and techniques of the Wazuh rules that raised them. "
                 "Deterministic — no AI involved.",
    "att.days": "{d} d", "att.k.mapped": "Alerts with a mapping", "att.of_total": "of {n}",
    "att.k.tech": "Techniques seen", "att.k.tactics": "in {n} tactics", "att.k.new": "New techniques",
    "att.k.silent": "Tactics without alerts", "att.matrix": "Tactic × technique",
    "att.legend": "fewer → more alerts", "att.n_tech": "{n} techn.",
    "att.cell_tip": "{id} {name}: {n} alerts, {h} at level {l}+, {a} agent(s); rules {rules}",
    "att.new": "new", "att.list": "Techniques",
    "att.c.tech": "Technique", "att.c.tactics": "Tactics", "att.c.count": "Alerts", "att.c.trend": "Change",
    "att.c.agents": "Agents", "att.c.rules": "Rules", "att.c.last": "Last seen",
    "att.new_title": "First seen in {d} days", "att.silent_title": "Tactics without alerts",
    "att.silent_lb": "No alert in the {d} days before either:",
    "att.silent_note": "No rule carrying these tactics matched in the period. Either nothing of that kind happened, "
                       "or your rules do not detect it. A hint for a detection gap — not a measured coverage.",
    "att.gone": "Seen in the previous period, not in this one",
    "att.cross": "A rule mapped to several tactics lists its techniques under each of them, as the Wazuh dashboard "
                 "does. Cells link to the technique on attack.mitre.org.",
    "att.none": "No alert in this period carries an ATT&CK mapping. Wazuh rules get one through a <mitre> block; "
                "the Wazuh ruleset has it for many rules, custom rules need it added.",
    "att.error": "The ATT&CK data could not be loaded — the indexer did not answer.",
    "att.filter": "Tactic: {t}", "att.clear": "show all",
}

TR: dict[str, str] = {
    "nav.overview": "Genel bakış", "nav.attack": "ATT&CK", "nav.signed_in": "Giriş yapan: {who}",
    "role.admin": "yönetici", "role.viewer": "salt okunur",
    "auth.no_role": "Giriş yaptınız ama hesabınızın bu uygulamada bir rolü yok. Bir yöneticiden sizi SSO_ADMIN_GROUPS "
                    "ya da SSO_VIEWER_GROUPS içindeki gruplardan birine eklemesini isteyin.",
    "dash.envs": "Ortamlar", "dash.period": "Dönem",
    "dash.period.24h": "24 saat", "dash.period.7d": "7 gün", "dash.period.30d": "30 gün",
    "dash.vs_prev": "önceki {p} ile karşılaştırmalı", "dash.vs_prev_short": "öncekine göre",
    "dash.k.alerts": "Alarm", "dash.k.high": "Seviye {n}+", "dash.k.crit": "Kritik (12+)",
    "dash.k.agents": "Veri gönderen ajan", "dash.k.agents_sub": "dönemde alarmı olan",
    "dash.k.inbox": "Öneriler", "dash.k.urgent": "{n} acil", "dash.k.questions": "Açık sorular",
    "dash.k.proposals": "{n} bilgi tabanı önerisi",
    "dash.vol": "Alarm hacmi", "dash.sev": "Önem dağılımı",
    "dash.legend.total": "Tüm alarmlar", "dash.legend.high": "Seviye {n}+", "dash.legend.crit": "Kritik",
    "band.critical": "Kritik", "band.high": "Yüksek", "band.medium": "Orta", "band.low": "Düşük",
    "band.range": "seviye {a}–{b}",
    "dash.att": "MITRE ATT&CK taktikleri", "dash.att_open": "Matrisi aç",
    "dash.att_tech": "{n} teknik", "dash.att_silent": "alarm yok",
    "dash.att_none": "Bu dönemde ATT&CK eşlemesi taşıyan alarm yok.",
    "dash.mitre_share": "Alarmların %{p}'i ATT&CK eşlemesi taşıyor",
    "dash.top_rules": "Seviye {n}+ en sık kurallar", "dash.top_agents": "En hareketli ajanlar",
    "dash.top_src": "En sık kaynak adresler", "dash.none": "Bu dönemde veri yok.", "dash.work": "İş listesi",
    "dash.nodata": "Sayılar yüklenemedi — indexer cevap vermedi. Aşağıdaki iş listesi yine çalışır.",
    "att.title": "MITRE ATT&CK",
    "att.intro": "Alarmlar, onları üreten Wazuh kurallarının ATT&CK taktik ve tekniklerine göre gruplanır. "
                 "Deterministiktir — yapay zekâ kullanılmaz.",
    "att.days": "{d} g", "att.k.mapped": "Eşlemesi olan alarm", "att.of_total": "{n} içinde",
    "att.k.tech": "Görülen teknik", "att.k.tactics": "{n} taktikte", "att.k.new": "Yeni teknik",
    "att.k.silent": "Alarmı olmayan taktik", "att.matrix": "Taktik × teknik",
    "att.legend": "az → çok alarm", "att.n_tech": "{n} tekn.",
    "att.cell_tip": "{id} {name}: {n} alarm, {h} tanesi seviye {l}+, {a} ajan; kurallar {rules}",
    "att.new": "yeni", "att.list": "Teknikler",
    "att.c.tech": "Teknik", "att.c.tactics": "Taktikler", "att.c.count": "Alarm", "att.c.trend": "Değişim",
    "att.c.agents": "Ajan", "att.c.rules": "Kurallar", "att.c.last": "Son görülme",
    "att.new_title": "{d} gün içinde ilk kez görülen", "att.silent_title": "Alarmı olmayan taktikler",
    "att.silent_lb": "Öncesindeki {d} günde de alarm yok:",
    "att.silent_note": "Bu taktikleri taşıyan hiçbir kural dönem içinde eşleşmedi. Ya bu türden bir şey olmadı ya da "
                       "kurallarınız bunu algılamıyor. Bir tespit boşluğu ipucudur — ölçülmüş bir kapsam değildir.",
    "att.gone": "Önceki dönemde görülen, bu dönemde görülmeyen",
    "att.cross": "Birden çok taktiğe eşlenmiş bir kuralın teknikleri, Wazuh panosunda olduğu gibi her taktiğin "
                 "altında listelenir. Hücreler attack.mitre.org'daki tekniğe bağlanır.",
    "att.none": "Bu dönemde ATT&CK eşlemesi taşıyan alarm yok. Wazuh kuralları bunu bir <mitre> bloğuyla alır; "
                "Wazuh kural setinde birçok kuralda vardır, özel kurallara eklenmesi gerekir.",
    "att.error": "ATT&CK verisi yüklenemedi — indexer cevap vermedi.",
    "att.filter": "Taktik: {t}", "att.clear": "tümünü göster",
}

ES: dict[str, str] = {
    "nav.overview": "Resumen", "nav.attack": "ATT&CK", "nav.signed_in": "Sesión de {who}",
    "role.admin": "administrador", "role.viewer": "solo lectura",
    "auth.no_role": "Ha iniciado sesión, pero su cuenta no tiene ningún rol en esta aplicación. Pida a un "
                    "administrador que le añada a uno de los grupos de SSO_ADMIN_GROUPS o SSO_VIEWER_GROUPS.",
    "dash.envs": "Entornos", "dash.period": "Periodo",
    "dash.period.24h": "24 h", "dash.period.7d": "7 días", "dash.period.30d": "30 días",
    "dash.vs_prev": "comparado con los {p} anteriores", "dash.vs_prev_short": "vs. anterior",
    "dash.k.alerts": "Alertas", "dash.k.high": "Nivel {n}+", "dash.k.crit": "Críticas (12+)",
    "dash.k.agents": "Agentes que informan", "dash.k.agents_sub": "con alertas en el periodo",
    "dash.k.inbox": "Recomendaciones", "dash.k.urgent": "{n} urgentes", "dash.k.questions": "Preguntas abiertas",
    "dash.k.proposals": "{n} propuesta(s) de conocimiento",
    "dash.vol": "Volumen de alertas", "dash.sev": "Gravedad",
    "dash.legend.total": "Todas las alertas", "dash.legend.high": "Nivel {n}+", "dash.legend.crit": "Críticas",
    "band.critical": "Crítica", "band.high": "Alta", "band.medium": "Media", "band.low": "Baja",
    "band.range": "nivel {a}–{b}",
    "dash.att": "Tácticas de MITRE ATT&CK", "dash.att_open": "Abrir la matriz",
    "dash.att_tech": "{n} técnicas", "dash.att_silent": "sin alertas",
    "dash.att_none": "Ninguna alerta de este periodo tiene correspondencia ATT&CK.",
    "dash.mitre_share": "El {p} % de las alertas tiene correspondencia ATT&CK",
    "dash.top_rules": "Reglas más frecuentes de nivel {n}+", "dash.top_agents": "Agentes más activos",
    "dash.top_src": "Direcciones de origen más frecuentes", "dash.none": "Sin datos en este periodo.",
    "dash.work": "Cola de trabajo",
    "dash.nodata": "No se pudieron cargar las cifras: el indexer no respondió. La cola de trabajo sigue funcionando.",
    "att.title": "MITRE ATT&CK",
    "att.intro": "Alertas agrupadas por las tácticas y técnicas ATT&CK de las reglas de Wazuh que las generaron. "
                 "Determinista: sin IA.",
    "att.days": "{d} d", "att.k.mapped": "Alertas con correspondencia", "att.of_total": "de {n}",
    "att.k.tech": "Técnicas vistas", "att.k.tactics": "en {n} tácticas", "att.k.new": "Técnicas nuevas",
    "att.k.silent": "Tácticas sin alertas", "att.matrix": "Táctica × técnica",
    "att.legend": "menos → más alertas", "att.n_tech": "{n} técn.",
    "att.cell_tip": "{id} {name}: {n} alertas, {h} de nivel {l}+, {a} agente(s); reglas {rules}",
    "att.new": "nueva", "att.list": "Técnicas",
    "att.c.tech": "Técnica", "att.c.tactics": "Tácticas", "att.c.count": "Alertas", "att.c.trend": "Cambio",
    "att.c.agents": "Agentes", "att.c.rules": "Reglas", "att.c.last": "Última vez",
    "att.new_title": "Vistas por primera vez en {d} días", "att.silent_title": "Tácticas sin alertas",
    "att.silent_lb": "Tampoco hubo alertas en los {d} días anteriores:",
    "att.silent_note": "Ninguna regla con estas tácticas coincidió en el periodo. O no ocurrió nada de ese tipo, o sus "
                       "reglas no lo detectan. Es una pista de un hueco de detección, no una cobertura medida.",
    "att.gone": "Vistas en el periodo anterior, no en este",
    "att.cross": "Una regla asociada a varias tácticas muestra sus técnicas bajo cada una, como el panel de Wazuh. "
                 "Las celdas enlazan con la técnica en attack.mitre.org.",
    "att.none": "Ninguna alerta de este periodo tiene correspondencia ATT&CK. Las reglas de Wazuh la obtienen con un "
                "bloque <mitre>; el conjunto de reglas de Wazuh lo incluye en muchas, a las propias hay que añadirlo.",
    "att.error": "No se pudieron cargar los datos ATT&CK: el indexer no respondió.",
    "att.filter": "Táctica: {t}", "att.clear": "mostrar todo",
}

DE: dict[str, str] = {
    "nav.overview": "Übersicht", "nav.attack": "ATT&CK", "nav.signed_in": "Angemeldet als {who}",
    "role.admin": "Administrator", "role.viewer": "nur lesend",
    "auth.no_role": "Sie sind angemeldet, aber Ihr Konto hat in dieser Anwendung keine Rolle. Bitten Sie einen "
                    "Administrator, Sie einer der Gruppen in SSO_ADMIN_GROUPS oder SSO_VIEWER_GROUPS hinzuzufügen.",
    "dash.envs": "Umgebungen", "dash.period": "Zeitraum",
    "dash.period.24h": "24 h", "dash.period.7d": "7 Tage", "dash.period.30d": "30 Tage",
    "dash.vs_prev": "verglichen mit den vorherigen {p}", "dash.vs_prev_short": "ggü. vorher",
    "dash.k.alerts": "Alarme", "dash.k.high": "Stufe {n}+", "dash.k.crit": "Kritisch (12+)",
    "dash.k.agents": "Meldende Agenten", "dash.k.agents_sub": "mit Alarmen im Zeitraum",
    "dash.k.inbox": "Empfehlungen", "dash.k.urgent": "{n} dringend", "dash.k.questions": "Offene Fragen",
    "dash.k.proposals": "{n} Wissensvorschlag/-vorschläge",
    "dash.vol": "Alarmvolumen", "dash.sev": "Schweregrad",
    "dash.legend.total": "Alle Alarme", "dash.legend.high": "Stufe {n}+", "dash.legend.crit": "Kritisch",
    "band.critical": "Kritisch", "band.high": "Hoch", "band.medium": "Mittel", "band.low": "Niedrig",
    "band.range": "Stufe {a}–{b}",
    "dash.att": "MITRE-ATT&CK-Taktiken", "dash.att_open": "Matrix öffnen",
    "dash.att_tech": "{n} Techniken", "dash.att_silent": "keine Alarme",
    "dash.att_none": "Kein Alarm in diesem Zeitraum hat eine ATT&CK-Zuordnung.",
    "dash.mitre_share": "{p} % der Alarme haben eine ATT&CK-Zuordnung",
    "dash.top_rules": "Häufigste Regeln ab Stufe {n}", "dash.top_agents": "Aktivste Agenten",
    "dash.top_src": "Häufigste Quelladressen", "dash.none": "Keine Daten in diesem Zeitraum.",
    "dash.work": "Arbeitsliste",
    "dash.nodata": "Die Zahlen konnten nicht geladen werden — der Indexer hat nicht geantwortet. Die Arbeitsliste "
                   "unten funktioniert trotzdem.",
    "att.title": "MITRE ATT&CK",
    "att.intro": "Alarme, gruppiert nach den ATT&CK-Taktiken und -Techniken der Wazuh-Regeln, die sie ausgelöst haben. "
                 "Deterministisch — ohne KI.",
    "att.days": "{d} T", "att.k.mapped": "Alarme mit Zuordnung", "att.of_total": "von {n}",
    "att.k.tech": "Gesehene Techniken", "att.k.tactics": "in {n} Taktiken", "att.k.new": "Neue Techniken",
    "att.k.silent": "Taktiken ohne Alarme", "att.matrix": "Taktik × Technik",
    "att.legend": "weniger → mehr Alarme", "att.n_tech": "{n} Techn.",
    "att.cell_tip": "{id} {name}: {n} Alarme, {h} ab Stufe {l}, {a} Agent(en); Regeln {rules}",
    "att.new": "neu", "att.list": "Techniken",
    "att.c.tech": "Technik", "att.c.tactics": "Taktiken", "att.c.count": "Alarme", "att.c.trend": "Änderung",
    "att.c.agents": "Agenten", "att.c.rules": "Regeln", "att.c.last": "Zuletzt",
    "att.new_title": "Zum ersten Mal seit {d} Tagen", "att.silent_title": "Taktiken ohne Alarme",
    "att.silent_lb": "Auch in den {d} Tagen davor kein Alarm:",
    "att.silent_note": "Keine Regel mit diesen Taktiken hat im Zeitraum angeschlagen. Entweder ist nichts dieser Art "
                       "passiert, oder Ihre Regeln erkennen es nicht. Ein Hinweis auf eine Erkennungslücke — keine "
                       "gemessene Abdeckung.",
    "att.gone": "Im vorherigen Zeitraum gesehen, in diesem nicht",
    "att.cross": "Eine Regel mit mehreren Taktiken führt ihre Techniken unter jeder davon auf, wie das Wazuh-Dashboard. "
                 "Die Zellen verlinken auf die Technik bei attack.mitre.org.",
    "att.none": "Kein Alarm in diesem Zeitraum hat eine ATT&CK-Zuordnung. Wazuh-Regeln erhalten sie über einen "
                "<mitre>-Block; das Wazuh-Regelwerk hat ihn bei vielen Regeln, eigenen Regeln muss er hinzugefügt werden.",
    "att.error": "Die ATT&CK-Daten konnten nicht geladen werden — der Indexer hat nicht geantwortet.",
    "att.filter": "Taktik: {t}", "att.clear": "alle zeigen",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
