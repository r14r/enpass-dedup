"""Pure, offline Streamlit workflow helpers for Enpass JSON exports.

No file writes, caches, plaintext password displays, or external requests.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter
from typing import Any

from enpass_dedupe import (
    Group,
    UserError,
    choose_keep,
    clean_terminal,
    field_values,
    groups_for,
    make_plan,
    richness,
    safe_csv_cell,
    timestamp,
    unique_field,
    validate_plan,
    verify_export,
)

MAX_FILE_BYTES = 25 * 1024 * 1024
# Streamlit accepts encrypted backups so users can enter the restore workflow,
# but backup bytes are NEVER decrypted, parsed, or written by this application.
BACKUP_EXTENSION = ".enpassbackup"
JSON_EXTENSION = ".json"


def input_kind(filename: str) -> str:
    """Identify supported input routes without trusting file contents or extensions as plaintext."""
    if not isinstance(filename, str) or not filename.strip():
        raise UserError("Eine Datei mit gültigem Namen auswählen.")
    lower = filename.strip().lower()
    if lower.endswith(JSON_EXTENSION):
        return "json"
    if lower.endswith(BACKUP_EXTENSION):
        return "enpassbackup"
    raise UserError("Unterstützt werden nur .json und .enpassbackup.")


def backup_restore_steps() -> tuple[str, ...]:
    """Only Enpass can safely unlock the proprietary, encrypted backup."""
    return (
        "In Enpass eine getrennte Testumgebung / einen getrennten Tresor vorbereiten; "
        "nicht den bestehenden Tresor überschreiben.",
        "In Enpass den Dialog für das Wiederherstellen aus einer Backup-Datei öffnen.",
        "Die .enpassbackup-Datei in Enpass auswählen und dort mit Master-Passwort "
        "(und ggf. Keyfile) entsperren.",
        "Nach der Wiederherstellung in Enpass Datei → Exportieren → JSON wählen.",
        "Den exportierten JSON-Datensatz unten auswählen, um Duplikate zu prüfen.",
    )



def parse_upload(raw: bytes) -> dict[str, Any]:
    """Read a JSON export in memory while preventing huge/invalid uploads."""
    if not isinstance(raw, bytes) or not raw:
        raise UserError("Bitte eine nicht leere Enpass-JSON-Datei hochladen.")
    if len(raw) > MAX_FILE_BYTES:
        raise UserError("Datei zu groß (max. 25 MiB).")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise UserError("Ungültige JSON-Datei oder nicht lesbarer Text.") from exc
    if not isinstance(document, dict) or not isinstance(document.get("items"), list):
        raise UserError("Enpass-Export erwartet: JSON-Objekt mit einer 'items'-Liste.")
    if not all(isinstance(item, dict) for item in document["items"]):
        raise UserError("Ungültiger Export: 'items' enthält Nicht-Objekte.")
    return document


def group_id(group: Group) -> str:
    return f"{group.kind}:{','.join(map(str, group.indices))}"


def selections_to_plan(
    raw: bytes,
    items: list[dict],
    groups: list[Group],
    selections: dict[str, dict],
    *,
    keep_strategy: str = "newest",
    include_trashed: bool = False,
    include_archived: bool = False,
    fuzzy_threshold: float = 0.0,
) -> tuple[dict, int]:
    """Validate every review choice and prefer manual choices to overlapping exacts.

    No manual group selection happens without an explicit user approval.
    Exact groups can be safely preselected; overlapping exact groups are
    silently skipped when an explicit manual choice supersedes them.
    Overlapping manual choices are rejected, rather than arbitrarily deleting.
    """
    candidate_decisions = []
    for group in groups:
        selection = selections.get(group_id(group), {})
        if not selection.get("approved", group.kind == "exact"):
            continue
        keep = selection.get("keep", choose_keep(list(group.indices), items, keep_strategy))
        if type(keep) is not int or keep not in group.indices:
            raise UserError("Ein ungültiger Datensatz wurde zum Behalten ausgewählt.")
        candidate_decisions.append({
            "kind": group.kind,
            "keep": keep,
            "remove": [i for i in group.indices if i != keep],
        })

    manual = [d for d in candidate_decisions if d["kind"] != "exact"]
    exact = [d for d in candidate_decisions if d["kind"] == "exact"]
    used_by_manual: set[int] = set()
    for decision in manual:
        members = {decision["keep"], *decision["remove"]}
        if used_by_manual & members:
            raise UserError("Mehrere manuelle Gruppen überschneiden sich. Bitte nur eine davon aktivieren.")
        used_by_manual.update(members)
    skipped = 0
    chosen = list(manual)
    used = set(used_by_manual)
    for decision in exact:
        members = {decision["keep"], *decision["remove"]}
        if used & members:
            skipped += 1
            continue
        chosen.append(decision)
        used.update(members)

    options = {
        "include_trashed": include_trashed,
        "include_archived": include_archived,
        "fuzzy_threshold": fuzzy_threshold,
    }
    plan = make_plan(raw, items, groups, "exact", keep_strategy, options)
    plan["decisions"] = chosen
    # All selections must still match the backend's independently detected groups.
    validate_plan(plan, raw, items)
    return plan, skipped


def export_clean_json(document: dict, raw: bytes, plan: dict) -> bytes:
    """Export without modifying source metadata, items, or order; verify result."""
    removed = validate_plan(plan, raw, document["items"])
    clean = {**document, "items": [item for n, item in enumerate(document["items"]) if n not in removed]}
    verify_export(document, clean, removed)
    output = (json.dumps(clean, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    verify_export(document, json.loads(output), removed)
    return output


def summary(items: list[dict], groups: list[Group], plan: dict) -> dict[str, int]:
    by_type = Counter(g.kind for g in groups)
    return {
        "items": len(items),
        "exact": by_type["exact"],
        "review": by_type["credentials"] + by_type["conflict"] + by_type["possible"],
        "removed": sum(len(d["remove"]) for d in plan["decisions"]),
        "remaining": len(items) - sum(len(d["remove"]) for d in plan["decisions"]),
    }


def item_rows(group: Group, items: list[dict], keep: int, show_usernames: bool) -> list[dict]:
    result = []
    for index in group.indices:
        item = items[index]
        notes = bool(item.get("note") or item.get("notes"))
        result.append({
            "#": index,
            "Titel": clean_terminal(item.get("title") or "(Ohne Titel)"),
            "Benutzername": clean_terminal(unique_field(item, "username", "email")) if show_usernames else "••••",
            "Passwort": "vorhanden" if field_values(item, "password") else "—",
            "Notizen": "vorhanden" if notes else "—",
            "Anhänge": richness(item)[0],
            "Geändert (UTC)": str(item.get("updated_at") or item.get("modified_at") or "—")[:25],
            "Auswahl": "BEHALTEN" if index == keep else "Entfernen falls bestätigt",
        })
    return result


def csv_report(items: list[dict], groups: list[Group], plan: dict, *, show_usernames: bool = False) -> bytes:
    decisions = {(d["kind"], frozenset([d["keep"], *d["remove"]])): d for d in plan["decisions"]}
    f = io.StringIO()
    writer = csv.writer(f)
    writer.writerow(["group", "type", "index", "title", "username", "selection", "notes", "attachments"])
    for number, group in enumerate(groups, start=1):
        decision = decisions.get((group.kind, frozenset(group.indices)))
        for idx in group.indices:
            item = items[idx]
            selection = "keep" if decision and idx == decision["keep"] else ("remove" if decision else "review")
            cols = [number, group.kind, idx, clean_terminal(item.get("title") or ""),
                    unique_field(item, "username", "email") if show_usernames else "[hidden]",
                    selection, bool(item.get("note") or item.get("notes")), richness(item)[0]]
            writer.writerow([safe_csv_cell(x) for x in cols])
    return f.getvalue().encode("utf-8")
