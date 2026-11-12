# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Messages added in 0.11.1 (background jobs, proxy time-outs, interrupted deployments)."""
from __future__ import annotations

EN: dict[str, str] = {
    "job.gone": "This background job is no longer known (finished more than an hour ago, or the application "
                "restarted). Reload the page to see the stored result.",
    "job.proxy": "The proxy in front of the application gave up waiting (HTTP {n}). The operation may still be "
                 "running — reload the page in a minute to see its result.",
    "job.lost": "Lost contact with the application while waiting. The operation continues on the server; reload "
                "the page to see its result.",
    "job.elapsed": "{n} s",
    "rd.state.interrupted": "Interrupted — check the manager",
    "rd.running_note": "A deployment is running in the background — this page refreshes when it finishes.",
}

TR: dict[str, str] = {
    "job.gone": "Bu arka plan işi artık bilinmiyor (bir saatten önce bitti ya da uygulama yeniden başladı). "
                "Kayıtlı sonucu görmek için sayfayı yenileyin.",
    "job.proxy": "Uygulamanın önündeki vekil sunucu beklemeyi bıraktı (HTTP {n}). İşlem hâlâ sürüyor olabilir — "
                 "sonucu görmek için bir dakika sonra sayfayı yenileyin.",
    "job.lost": "Beklerken uygulamayla bağlantı koptu. İşlem sunucuda devam ediyor; sonucu görmek için sayfayı "
                "yenileyin.",
    "job.elapsed": "{n} sn",
    "rd.state.interrupted": "Yarıda kaldı — yöneticiyi kontrol edin",
    "rd.running_note": "Arka planda bir dağıtım sürüyor — bittiğinde bu sayfa kendiliğinden yenilenir.",
}

ES: dict[str, str] = {
    "job.gone": "Esta tarea en segundo plano ya no se conoce (terminó hace más de una hora o la aplicación se "
                "reinició). Recarga la página para ver el resultado guardado.",
    "job.proxy": "El proxy delante de la aplicación dejó de esperar (HTTP {n}). La operación puede seguir en "
                 "curso — recarga la página en un minuto para ver el resultado.",
    "job.lost": "Se perdió el contacto con la aplicación mientras se esperaba. La operación continúa en el "
                "servidor; recarga la página para ver el resultado.",
    "job.elapsed": "{n} s",
    "rd.state.interrupted": "Interrumpida — revisa el manager",
    "rd.running_note": "Hay una implementación en segundo plano — esta página se actualiza cuando termina.",
}

DE: dict[str, str] = {
    "job.gone": "Dieser Hintergrundauftrag ist nicht mehr bekannt (vor über einer Stunde beendet oder die "
                "Anwendung wurde neu gestartet). Lade die Seite neu, um das gespeicherte Ergebnis zu sehen.",
    "job.proxy": "Der Proxy vor der Anwendung hat das Warten aufgegeben (HTTP {n}). Der Vorgang läuft "
                 "möglicherweise weiter — lade die Seite in einer Minute neu, um das Ergebnis zu sehen.",
    "job.lost": "Die Verbindung zur Anwendung ist beim Warten abgebrochen. Der Vorgang läuft auf dem Server "
                "weiter; lade die Seite neu, um das Ergebnis zu sehen.",
    "job.elapsed": "{n} s",
    "rd.state.interrupted": "Unterbrochen — Manager prüfen",
    "rd.running_note": "Im Hintergrund läuft eine Bereitstellung — diese Seite aktualisiert sich, wenn sie fertig ist.",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
