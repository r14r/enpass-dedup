#!/usr/bin/env python3
"""Enpass Duplicate Cleaner: localhost-only Streamlit UI for JSON exports."""
from __future__ import annotations

import hashlib
import json
from collections import Counter

import streamlit as st

from enpass_dedupe import VERSION, UserError, choose_keep, groups_for
from web_core import (
    csv_report,
    export_clean_json,
    group_id,
    item_rows,
    input_kind,
    backup_restore_steps,
    parse_upload,
    selections_to_plan,
    summary,
)

st.set_page_config(
    page_title="Enpass Duplicate Cleaner",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# No unsafe HTML containing user-controlled data is rendered.
st.markdown("""
<style>
.block-container {padding-top: 2rem; padding-bottom: 3rem; max-width: 1420px;}
[data-testid="stMetric"] {background: rgba(128,128,128,.07); padding: 1rem; border-radius: .75rem;}
.small-muted {color: #82848b; font-size: .87rem;}
</style>
""", unsafe_allow_html=True)

st.title("🔐 Enpass Duplicate Cleaner")
st.caption(f"Version {VERSION} · Enpass JSON und verschlüsselte Backup-Dateien · Nur lokal auf 127.0.0.1")
st.info("Dieses Tool verändert **niemals** deinen aktiven Enpass-Tresor oder die hochgeladene Quelldatei. Passwörter werden nicht in der Oberfläche angezeigt.")

with st.sidebar:
    st.header("1 · Export laden")
    st.caption("Vorher in Enpass ein verschlüsseltes Backup anlegen. JSON-Exporte sind **unverschlüsselt**.")
    source_upload = st.file_uploader(
        "Enpass-Datei (.json / .enpassbackup)", type=["json", "enpassbackup"],
        accept_multiple_files=False,
        help="JSON wird lokal analysiert (bis 25 MiB). Verschlüsselte Backups werden nur für den Wiederherstellungs-Assistenten angenommen.",
    )
    st.divider()
    st.header("2 · Analyse")
    keep_strategy = st.selectbox("Behalten-Vorschlag", ["newest", "oldest", "richest"],
                                 format_func=lambda v: {"newest": "Neuester Eintrag", "oldest": "Ältester Eintrag", "richest": "Meiste Informationen"}[v])
    include_archived = st.checkbox("Archiv einbeziehen", value=False)
    include_trashed = st.checkbox("Papierkorb einbeziehen", value=False)
    fuzzy = st.checkbox("Ähnliche Titel finden", value=False)
    threshold = st.slider("Ähnlichkeit", 0.5, 1.0, 0.85, step=0.05, disabled=not fuzzy) if fuzzy else 0.0
    show_usernames = st.checkbox("Benutzernamen in Ansichten/Berichten anzeigen", value=False)
    st.divider()
    st.caption("Datenschutz: keine Cloud-Verarbeitung durch dieses Tool, kein Passwort-Logging, keine serverseitigen Exportdateien. Browser-Downloads bleiben unverschlüsselt.")

if source_upload is None:
    st.subheader("So funktioniert es")
    st.markdown("""
1. **JSON:** Enpass-Tresor exportieren und sofort analysieren. **ENPASSBACKUP:** Datei auswählen, Wiederherstellung in Enpass durchführen und den anschließend erstellten JSON-Export laden.
2. Exakte Duplikate, gleiche Zugangsdaten und mögliche Passwortkonflikte prüfen.
3. Für jede Gruppe festlegen, welchen Eintrag du **behalten** möchtest.
4. Den CSV-Prüfbericht, einen Plan oder einen geprüften bereinigten JSON-Export herunterladen.

**Wichtig:** Den bereinigten JSON-Export **nicht** in einen bereits gefüllten Tresor importieren: Enpass entfernt dadurch keine vorhandenen Einträge. Fehlende Passkeys und mögliche nicht exportierte Inhalte müssen vor jeder Wiederherstellung gesondert berücksichtigt werden.
""")
    st.stop()

try:
    source_kind = input_kind(source_upload.name)
except UserError as exc:
    st.error(str(exc))
    st.stop()

if source_kind == "enpassbackup":
    st.subheader("🔒 Verschlüsseltes Enpass-Backup")
    st.success(f"Backup ausgewählt: {source_upload.name} ({source_upload.size / 1024 / 1024:.1f} MiB)")
    st.warning(
        "Enpass-Backups sind verschlüsselt. Diese App kann .enpassbackup nicht selbst "
        "entschlüsseln und fordert deshalb **kein Master-Passwort** an. "
        "Die Datei wird weder analysiert noch konvertiert; die Wiederherstellung erfolgt nur in Enpass."
    )
    st.markdown("**Wiederherstellung und Export**")
    for step, description in enumerate(backup_restore_steps(), start=1):
        st.write(f"{step}. {description}")
    st.link_button("Offizielle Enpass-Anleitung zur Wiederherstellung", "https://help.enpass.io/personal/latest/all/restoring-your-existing-enpass-data")
    st.caption("Die App kann nicht überprüfen, ob der nachfolgende JSON-Export tatsächlich aus dieser Backup-Datei stammt.")
    converted_upload = st.file_uploader(
        "JSON-Export aus dem wiederhergestellten Tresor laden", type=["json"],
        key="converted_json", accept_multiple_files=False,
    )
    if converted_upload is None:
        st.info("Nach der Wiederherstellung die JSON-Datei hier auswählen. Die anschließende Analyse ist identisch zum JSON-Direktimport.")
        st.stop()
    same_source = st.checkbox(
        "Ich bestätige, dass dieser JSON-Export aus dem separat wiederhergestellten Backup stammt.",
        key=f"backup_confirm_{source_upload.name}_{source_upload.size}_{converted_upload.name}",
    )
    if not same_source:
        st.stop()
    uploaded = converted_upload
else:
    uploaded = source_upload

try:
    raw = uploaded.getvalue()
    document = parse_upload(raw)
    items = document["items"]
    groups = groups_for(items, include_trashed=include_trashed,
                        include_archived=include_archived, fuzzy_threshold=threshold)
except (UserError, TypeError, OverflowError) as exc:
    st.error(f"Export kann nicht analysiert werden: {exc}")
    st.stop()

file_sha = hashlib.sha256(raw).hexdigest()
options_key = f"{file_sha}:{int(include_archived)}:{int(include_trashed)}:{threshold}:{keep_strategy}"

st.caption(f"Geladen: **{uploaded.name}** · {len(items)} Einträge · SHA-256: `{file_sha[:16]}…` · {len(groups)} Kandidatengruppen")

# Initialise conservative defaults; explicit decisions remain scoped to the
# uploaded file *and* filter choices, never reused for a different export.
selections = {}
for group in groups:
    key_root = f"{options_key}/{group_id(group)}"
    akey, kkey = f"approve:{key_root}", f"keep:{key_root}"
    if akey not in st.session_state:
        st.session_state[akey] = group.kind == "exact"
    if kkey not in st.session_state:
        st.session_state[kkey] = choose_keep(list(group.indices), items, keep_strategy)
    selections[group_id(group)] = {"approved": st.session_state[akey], "keep": st.session_state[kkey]}

error = None
try:
    plan, skipped_exacts = selections_to_plan(
        raw, items, groups, selections, keep_strategy=keep_strategy,
        include_trashed=include_trashed, include_archived=include_archived,
        fuzzy_threshold=threshold,
    )
    metrics = summary(items, groups, plan)
except (UserError, ValueError, TypeError) as exc:
    error = str(exc)
    skipped_exacts = 0
    plan = None
    metrics = {"items": len(items), "exact": sum(g.kind == "exact" for g in groups),
               "review": sum(g.kind != "exact" for g in groups), "removed": 0, "remaining": len(items)}

cols = st.columns(5)
for column, key, title in zip(cols, ["items", "exact", "review", "removed", "remaining"],
                               ["Datensätze", "Exakte Gruppen", "Prüffälle", "Zur Entfernung", "Verbleiben"]):
    column.metric(title, metrics[key])

if error:
    st.error(f"Bereinigungsplan blockiert: {error}")
elif skipped_exacts:
    st.warning(f"{skipped_exacts} exakte Gruppen wurden ausgelassen, weil deine manuelle Entscheidung dieselben Einträge bereits umfasst.")

overview_tab, review_tab, export_tab = st.tabs(["📊 Übersicht", "🔎 Duplikate prüfen", "📦 Export & Validierung"])

with overview_tab:
    count = Counter(g.kind for g in groups)
    text = {
        "exact": ("Exakt", "Gleicher vollständiger Inhalt, abgesehen von technischen Identifikatoren/Zeitstempeln. Standardmäßig zur Bereinigung ausgewählt."),
        "credentials": ("Gleiche Zugangsdaten", "Identische Anmeldedaten, aber abweichende Zusatzinformationen. Nur manuell auswählen."),
        "conflict": ("Passwortkonflikt", "Gleicher erkannter Zugang, unterschiedliche Passwörter. Nicht automatisch entfernen."),
        "possible": ("Ähnliche Titel", "Nur Verdacht: gleicher Benutzer/Host, ähnliche Titel. Nicht automatisch entfernen."),
    }
    for kind, (title, help_text) in text.items():
        c1, c2 = st.columns([1, 6])
        c1.metric(title, count[kind])
        c2.write(help_text)
    if groups:
        st.divider()
        st.write("**Kandidaten im Überblick**")
        st.dataframe([
            {"Gruppe": n, "Typ": group.kind,
             "Titel": items[group.indices[0]].get("title", ""),
             "Einträge": len(group.indices),
             "Indices": ", ".join(str(i) for i in group.indices[:12])}
            for n, group in enumerate(groups, 1)
        ], hide_index=True, use_container_width=True)
    else:
        st.success("Keine Duplikat-Kandidaten mit den gewählten Einstellungen erkannt.")

with review_tab:
    st.write("Bei exakten Duplikaten ist die Bereinigung zunächst markiert. Für andere Gruppentypen ist eine **bewusste Einzelauswahl** erforderlich.")
    left, right, third = st.columns([1.5, 1, 1])
    with left:
        filter_kind = st.selectbox("Gruppenfilter", ["all", "exact", "credentials", "conflict", "possible"],
                                   format_func=lambda k: {"all": "Alle", "exact": "Exakt", "credentials": "Gleiche Zugangsdaten",
                                                          "conflict": "Passwortkonflikte", "possible": "Ähnliche Titel"}[k])
    filtered = [g for g in groups if filter_kind == "all" or g.kind == filter_kind]
    with right:
        page_size = st.selectbox("Pro Seite", [10, 20, 50], index=1)
    with third:
        page_max = max(1, (len(filtered) + page_size - 1) // page_size)
        page = st.number_input("Seite", min_value=1, max_value=page_max, value=1)
    show = filtered[(page - 1) * page_size:page * page_size]
    if not show:
        st.info("Keine Gruppen in dieser Auswahl.")
    for group in show:
        first = items[group.indices[0]]
        key_root = f"{options_key}/{group_id(group)}"
        akey, kkey = f"approve:{key_root}", f"keep:{key_root}"
        title = str(first.get("title") or "(Ohne Titel)").replace("\n", " ")[:90]
        icons = {"exact": "✅", "credentials": "🟠", "conflict": "🔴", "possible": "🔍"}
        with st.expander(f"{icons[group.kind]} {group.kind.upper()} · {title} · {len(group.indices)} Einträge", expanded=False):
            if group.kind == "exact":
                st.caption("Exakter Inhaltsvergleich; UUID und technische Zeitstempel ausgenommen.")
            elif group.kind == "credentials":
                st.warning("Zusatzinformationen weichen ab. Vor dem Entfernen Notizen, Anhänge, TOTP und benutzerdefinierte Felder prüfen.")
            elif group.kind == "conflict":
                st.error("Unterschiedliche Passwörter! Es könnte sich um alte und neue Zugänge handeln. Nicht ohne externe Überprüfung löschen.")
            else:
                st.warning("Nur ein Ähnlichkeits-Treffer. Möglicherweise zwei unabhängige Einträge.")
            st.selectbox("Diesen Eintrag behalten", list(group.indices), key=kkey,
                         format_func=lambda i: f"#{i} · {str(items[i].get('title') or '(Ohne Titel)')[:60]} · {str(items[i].get('updated_at') or 'ohne Datum')[:16]}")
            st.dataframe(item_rows(group, items, st.session_state[kkey], show_usernames),
                         hide_index=True, use_container_width=True)
            st.checkbox("Andere Einträge dieser Gruppe für Entfernung vormerken", key=akey,
                        help="Wird nichts ausgewählt, bleiben sämtliche Einträge unverändert.")
    st.caption("Gruppen können sich überlappen. Wähle für überschneidende manuelle Gruppen nur eine; exakte Teilgruppen werden automatisch ausgenommen.")

with export_tab:
    st.subheader("Ergebnis erzeugen")
    st.warning("Ein bereinigter JSON-Export ist **keine direkte Bereinigung des aktiven Enpass-Tresors**. Ein Import in einen nichtleeren Tresor kann neue Duplikate erzeugen. Immer zuerst ein verschlüsseltes Enpass-Backup erstellen.")
    if plan is None:
        st.error("Bitte zuerst die widersprüchlichen Entscheidungen im Reiter 'Duplikate prüfen' auflösen.")
    else:
        is_manual = any(d["kind"] != "exact" for d in plan["decisions"])
        if is_manual:
            st.warning("Mindestens eine Entscheidung betrifft unterschiedliche Zusatzdaten, Passwörter oder Ähnlichkeitstreffer.")
        accepted = st.checkbox("Ich habe ein Backup und verstehe, dass im bereinigten Export ausgewählte Einträge unwiederbringlich fehlen.", value=False)
        accepted_manual = st.checkbox("Ich habe alle manuell markierten Gruppen inklusive möglicher Passwort-/Datenkonflikte geprüft.", value=False, disabled=not is_manual) if is_manual else True
        removed = sum(len(d["remove"]) for d in plan["decisions"])
        st.write(f"**{removed}** von **{len(items)}** Datensätzen werden nur aus dem neuen Export entfernt.")

        plan_bytes = (json.dumps(plan, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        csv_bytes = csv_report(items, groups, plan, show_usernames=show_usernames)
        d1, d2 = st.columns(2)
        with d1:
            st.download_button("📄 Prüfbericht als CSV", data=csv_bytes,
                               file_name="enpass-review.csv", mime="text/csv", use_container_width=True)
        with d2:
            st.download_button("📝 Bereinigungsplan als JSON", data=plan_bytes,
                               file_name="enpass-plan.json", mime="application/json", use_container_width=True)
        if removed and accepted and accepted_manual:
            try:
                clean_bytes = export_clean_json(document, raw, plan)
                st.success(f"Validierung erfolgreich: {len(items) - removed} unveränderte Einträge, Export-Metadaten erhalten.")
                st.download_button("⬇️ Geprüften bereinigten JSON-Export herunterladen",
                                   data=clean_bytes, file_name="enpass-cleaned.json",
                                   mime="application/json", type="primary", use_container_width=True)
            except (UserError, ValueError, TypeError) as exc:
                st.error(f"Validierung fehlgeschlagen: {exc}")
        else:
            st.button("⬇️ Bereinigten Export herunterladen", disabled=True, use_container_width=True,
                      help="Benötigt mindestens eine Auswahl sowie die Sicherheitsbestätigung(en).")
        st.caption("Berichte enthalten Titel und optional Benutzernamen, aber keine Passwörter oder TOTP-Werte. CSV/Plan/Export werden ausschließlich im Speicher erzeugt.")
