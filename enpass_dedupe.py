#!/usr/bin/env python3
"""Privacy-preserving Enpass JSON duplicate analyzer (Python 3.10+, stdlib only).

This tool NEVER touches the Enpass vault itself. The output is a *new* JSON export
and must NOT be imported into a nonempty Enpass vault as a deduplication method.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VERSION = "1.2.1"
PLAN_VERSION = 1
VOLATILE_KEYS = {
    "uuid", "id", "created_at", "updated_at", "last_used", "last_used_at",
    "usage_count", "last_modified", "modified_at", "last_accessed", "revision",
}
CREDENTIAL_CATEGORIES = {"login", "password", "uncategorized"}
VALID_KINDS = {"exact", "credentials", "conflict", "possible"}


class UserError(Exception):
    pass


def json_digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def signature(item: dict) -> str:
    # All unknown top-level and nested fields are retained for comparisons.
    # Only common top-level record identifiers and activity timestamps are ignored.
    return json_digest({k: v for k, v in item.items() if k not in VOLATILE_KEYS})


def fold(value: object) -> str:
    return " ".join(str(value or "").split()).casefold()


def clean_terminal(value: object) -> str:
    # Terminal-safe: strip control characters, truncate very long titles.
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value or ""))
    return s[:75] + ("…" if len(s) > 75 else "")


def field_values(item: dict, field_type: str) -> list[str]:
    fields = item.get("fields", [])
    if not isinstance(fields, list):
        return []
    values = []
    for field in fields:
        if not isinstance(field, dict) or fold(field.get("type")) != field_type:
            continue
        value = field.get("value")
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    return values


def unique_field(item: dict, *types: str) -> str:
    vals = [v for name in types for v in field_values(item, name)]
    distinct = {x for x in vals} if "password" in types else {fold(x) for x in vals}
    return vals[0] if len(distinct) == 1 else ""


def domain(item: dict) -> str:
    for url in field_values(item, "url"):
        raw = url if "://" in url else "//" + url
        try:
            host = (urlparse(raw).hostname or "").lower().removeprefix("www.")
            if host:
                return host
        except ValueError:
            pass
    return ""


def record_key(item: dict) -> tuple[str, str, str, str] | None:
    category = fold(item.get("category"))
    if category not in CREDENTIAL_CATEGORIES:
        return None
    title = fold(item.get("title"))
    user = fold(unique_field(item, "username", "email"))
    host = domain(item)
    password = unique_field(item, "password")
    if not (user and password and (title or host)):
        return None
    return (category, title, user, host)


def is_flag(item: dict, *keys: str) -> bool:
    for key in keys:
        val = item.get(key, False)
        if val is True or (isinstance(val, (int, float)) and val != 0):
            return True
        if isinstance(val, str) and val.lower() in {"true", "yes", "1"}:
            return True
    return False


def eligible(item: dict, include_trashed: bool, include_archived: bool) -> bool:
    if not include_trashed and is_flag(item, "trashed", "deleted", "is_trashed", "is_deleted"):
        return False
    if not include_archived and is_flag(item, "archived", "is_archived"):
        return False
    return True


def richness(item: dict) -> tuple[int, int]:
    # Prefer actual information, particularly attachments and nonempty custom fields.
    nonempty = 0
    for f in item.get("fields", []) if isinstance(item.get("fields"), list) else []:
        if isinstance(f, dict) and str(f.get("value") or "").strip():
            nonempty += 1
    attachments = item.get("attachments")
    nattachments = len(attachments) if isinstance(attachments, (list, dict)) else 0
    return nattachments, nonempty + int(bool(item.get("note")))


def timestamp(item: dict) -> float:
    for key in ("updated_at", "last_modified", "modified_at", "created_at"):
        val = item.get(key)
        if isinstance(val, (int, float)):
            return float(val) / (1000 if val > 1e11 else 1)
        if isinstance(val, str):
            try:
                return float(val) / (1000 if float(val) > 1e11 else 1)
            except ValueError:
                try:
                    return datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    pass
    return 0.0


def choose_keep(indices: list[int], items: list[dict], strategy: str) -> int:
    if strategy == "newest":
        return max(indices, key=lambda i: (timestamp(items[i]), richness(items[i]), -i))
    if strategy == "oldest":
        # A missing timestamp is not treated as artificially old.
        return min(indices, key=lambda i: (timestamp(items[i]) or float("inf"), -richness(items[i])[0], i))
    if strategy == "richest":
        return max(indices, key=lambda i: (richness(items[i]), timestamp(items[i]), -i))
    raise UserError("Ungültige Aufbewahrungsstrategie")


@dataclass(frozen=True)
class Group:
    kind: str
    indices: tuple[int, ...]


def groups_for(items: list[dict], include_trashed: bool = False,
               include_archived: bool = False, fuzzy_threshold: float = 0) -> list[Group]:
    active = [i for i, obj in enumerate(items)
              if eligible(obj, include_trashed, include_archived)]
    exact: dict[str, list[int]] = defaultdict(list)
    matching: dict[tuple, list[int]] = defaultdict(list)
    for i in active:
        exact[signature(items[i])].append(i)
        key = record_key(items[i])
        if key is not None:
            matching[key].append(i)
    result: list[Group] = [Group("exact", tuple(v)) for v in exact.values() if len(v) > 1]
    for indices in matching.values():
        if len(indices) < 2:
            continue
        fingerprints = {signature(items[i]) for i in indices}
        if len(fingerprints) == 1:
            continue  # Already covered as an exact group
        pw = {unique_field(items[i], "password") for i in indices}
        result.append(Group("credentials" if len(pw) == 1 else "conflict", tuple(indices)))

    if fuzzy_threshold:
        # Restrict comparisons to matching account + domain; avoid accidental matches.
        buckets: dict[tuple, list[int]] = defaultdict(list)
        for i in active:
            key = record_key(items[i])
            if key and key[2] and key[3]:
                buckets[(key[0], key[2], key[3])].append(i)
        seen = set()
        for bucket in buckets.values():
            # Safeguard against unexpectedly enormous O(n^2) groups.
            if len(bucket) > 250:
                continue
            for pos, first in enumerate(bucket):
                for second in bucket[pos + 1:]:
                    a, b = items[first], items[second]
                    if fold(a.get("title")) == fold(b.get("title")):
                        continue
                    if difflib.SequenceMatcher(None, fold(a.get("title")),
                                               fold(b.get("title"))).ratio() < fuzzy_threshold:
                        continue
                    pair = (first, second)
                    if pair not in seen:
                        seen.add(pair)
                        result.append(Group("possible", pair))
    order = {"exact": 0, "credentials": 1, "conflict": 2, "possible": 3}
    return sorted(result, key=lambda g: (order[g.kind], g.indices[0]))


def read_export(path: Path) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        doc = json.loads(raw)
    except FileNotFoundError as exc:
        raise UserError(f"Eingabedatei nicht gefunden: {path}") from exc
    except (OSError, ValueError) as exc:
        raise UserError(f"JSON kann nicht gelesen werden: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
        raise UserError("Ungültiges Enpass-JSON: erwartetes Objekt mit einer 'items'-Liste")
    if not all(isinstance(x, dict) for x in doc["items"]):
        raise UserError("Ungültiges Enpass-JSON: items enthält Nicht-Objekte")
    return doc, raw


def private_write(path: Path, contents: str, force: bool = False) -> None:
    path = path.expanduser().absolute()
    if path.is_symlink():
        raise UserError(f"Ausgabe darf kein Symlink sein: {path}")
    if path.exists() and not force:
        raise UserError(f"Datei existiert (mit --force ersetzen): {path}")
    if not path.parent.is_dir():
        raise UserError(f"Zielordner existiert nicht: {path.parent}")
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".enpass-dedupe-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(contents)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        raise UserError(f"Ausgabe konnte nicht gespeichert werden: {exc}") from exc
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path: Path, data: object, force: bool = False) -> None:
    private_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n", force)


def display_item(i: int, obj: dict, usernames: bool = False) -> str:
    user = unique_field(obj, "username", "email")
    username_text = clean_terminal(user) if usernames and user else ("[versteckt]" if user else "—")
    uid = str(obj.get("uuid") or "")
    uuid_short = uid[:12] if uid else "—"
    return (f"#{i:>4} {clean_terminal(obj.get('title', '(ohne Titel)'))!s:<40} "
            f"User: {username_text:<24} UUID: {uuid_short:<12} "
            f"Datum: {datetime.fromtimestamp(timestamp(obj), timezone.utc).strftime('%Y-%m-%d') if timestamp(obj) > 0 else '—'} "
            f"Anhänge: {richness(obj)[0]}")


def group_rows(items: list[dict], groups: list[Group], strategy: str, usernames: bool) -> list[dict]:
    rows = []
    for number, g in enumerate(groups, 1):
        keep = choose_keep(list(g.indices), items, strategy)
        rows.append({
            "group": number, "kind": g.kind, "keep_suggestion": keep,
            "members": [{"index": idx, "title": clean_terminal(items[idx].get("title")),
                         "username": clean_terminal(unique_field(items[idx], "username", "email"))
                         if usernames else ("[versteckt]" if unique_field(items[idx], "username", "email") else ""),
                         "uuid": str(items[idx].get("uuid", "")),
                         "updated_at": items[idx].get("updated_at"),
                         "attachments": richness(items[idx])[0]}
                        for idx in g.indices]
        })
    return rows


def describe(groups: list[Group], items: list[dict], *, usernames: bool = False,
             limit: int = 0, strategy: str = "newest") -> str:
    counts = Counter(g.kind for g in groups)
    lines = [f"Einträge gesamt: {len(items)} | Kandidatengruppen: {len(groups)}",
             f"Exakt: {counts['exact']} | Gleiche Zugangsdaten: {counts['credentials']} | "
             f"Passwortkonflikt: {counts['conflict']} | Ähnliche Titel: {counts['possible']}",
             "Passwörter und TOTP-Daten werden nie angezeigt."]
    for n, group in enumerate(groups[:limit] if limit else groups, start=1):
        lines.append(f"\nGruppe {n} [{group.kind}] – Behalten-Vorschlag: "
                     f"#{choose_keep(list(group.indices), items, strategy)}")
        lines.extend("  " + display_item(i, items[i], usernames) for i in group.indices)
    if limit and len(groups) > limit:
        lines.append(f"\n... {len(groups)-limit} weitere Gruppen (mit --limit 0 alle anzeigen)")
    return "\n".join(lines)


def make_plan(raw: bytes, items: list[dict], groups: list[Group],
              policy: str, keep: str, options: dict) -> dict:
    if policy == "same-credentials":
        allowed = {"exact", "credentials"}
    else:
        allowed = {"exact"}
    chosen = [g for g in groups if g.kind in allowed]
    # If a credentials group contains any exact subgroups, its removal choice
    # supersedes those exact groups to avoid intersecting plan operations.
    if policy == "same-credentials":
        covered = set().union(*(set(g.indices) for g in chosen if g.kind == "credentials")) \
            if any(g.kind == "credentials" for g in chosen) else set()
        chosen = [g for g in chosen if g.kind != "exact" or not (set(g.indices) & covered)]
    decisions = []
    for g in chosen:
        keeper = choose_keep(list(g.indices), items, keep)
        decisions.append({"kind": g.kind, "keep": keeper,
                          "remove": [idx for idx in g.indices if idx != keeper]})
    return {
        "schema_version": PLAN_VERSION, "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_items": len(items), "created_utc": datetime.now(timezone.utc).isoformat(),
        "policy": policy, "keep_strategy": keep, "options": options,
        "decisions": decisions,
    }


def load_plan(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UserError(f"Plan konnte nicht gelesen werden: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != PLAN_VERSION:
        raise UserError("Ungültige oder nicht unterstützte Planversion")
    if not isinstance(data.get("decisions"), list) or not isinstance(data.get("options"), dict):
        raise UserError("Ungültiger Plan")
    return data


def validate_plan(plan: dict, raw: bytes, items: list[dict]) -> set[int]:
    if plan.get("source_sha256") != hashlib.sha256(raw).hexdigest():
        raise UserError("Quelldatei seit Planerstellung verändert (SHA-256-Prüfung fehlgeschlagen)")
    if plan.get("source_items") != len(items):
        raise UserError("Die Anzahl der Quelldatensätze stimmt nicht überein")
    opts = plan["options"]
    groups = groups_for(items, bool(opts.get("include_trashed")),
                        bool(opts.get("include_archived")), float(opts.get("fuzzy_threshold", 0)))
    group_sets = {(g.kind, frozenset(g.indices)) for g in groups}
    removed: set[int] = set()
    kept: set[int] = set()
    for decision in plan["decisions"]:
        if not isinstance(decision, dict) or decision.get("kind") not in VALID_KINDS:
            raise UserError("Unbekannte Entscheidung im Plan")
        keep, remove = decision.get("keep"), decision.get("remove")
        if not isinstance(keep, int) or isinstance(keep, bool) or not isinstance(remove, list):
            raise UserError("Ungültiger Plan: keep/remove")
        if not remove or any(not isinstance(i, int) or isinstance(i, bool) or i < 0 or i >= len(items) for i in remove):
            raise UserError("Ungültige Lösch-Indizes")
        if keep < 0 or keep >= len(items) or keep in remove or len(set(remove)) != len(remove):
            raise UserError("Ungültige Auswahl zu behaltender Einträge")
        if (decision["kind"], frozenset([keep, *remove])) not in group_sets:
            raise UserError("Plan enthält eine nicht verifizierbare Kandidatengruppe")
        if set(remove) & (removed | kept) or keep in removed:
            raise UserError("Widersprüchliche/überschneidende Löschentscheidungen im Plan")
        removed.update(remove)
        kept.add(keep)
    return removed


def prevent_input_overwrite(inputs: list[Path], output: Path) -> None:
    if any(p.expanduser().resolve() == output.expanduser().resolve() for p in inputs):
        raise UserError("Das Ausgabeverzeichnis darf die Eingabe- oder Plandatei nicht überschreiben")


def safe_csv_cell(value: object) -> object:
    """Prevent CSV formula execution when reports are opened in spreadsheets."""
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_report(path: Path, rows: list[dict], fmt: str, rendered: str, force: bool) -> None:
    if fmt == "text":
        private_write(path, rendered + "\n", force)
    elif fmt == "json":
        write_json(path, {"groups": rows}, force)
    else:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["group", "type", "index", "keep_suggestion", "title", "username", "uuid", "updated_at", "attachments"])
        for row in rows:
            for member in row["members"]:
                writer.writerow([safe_csv_cell(v) for v in [
                    row["group"], row["kind"], member["index"], row["keep_suggestion"],
                    member["title"], member["username"], member["uuid"],
                    member["updated_at"], member["attachments"]]])
        private_write(path, out.getvalue(), force)


def verify_export(origin: dict, clean: dict, removed: set[int]) -> None:
    expected = [obj for i, obj in enumerate(origin["items"]) if i not in removed]
    if clean["items"] != expected:
        raise UserError("Verifikation fehlgeschlagen: verbliebene Einträge wurden verändert")
    if {k: v for k, v in clean.items() if k != "items"} != {k: v for k, v in origin.items() if k != "items"}:
        raise UserError("Verifikation fehlgeschlagen: Export-Metadaten wurden verändert")


def add_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include-trashed", action="store_true", help="Papierkorb-Einträge berücksichtigen")
    parser.add_argument("--include-archived", action="store_true", help="Archivierte Einträge berücksichtigen")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enpass-Duplikate offline erkennen und sicher als neues JSON exportieren",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    stats = sub.add_parser("stats", help="Statistiken des Enpass-Exports", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    stats.add_argument("input", type=Path)
    add_filters(stats)

    scan = sub.add_parser("scan", help="Duplikatgruppen ermitteln, Bericht erstellen", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    scan.add_argument("input", type=Path)
    scan.add_argument("--mode", choices=("all", "exact", "credentials", "conflict", "possible"), default="all")
    scan.add_argument("--report", type=Path, help="Bericht als Datei speichern (keine Passwörter enthalten)")
    scan.add_argument("--format", choices=("text", "json", "csv"), default="text")
    scan.add_argument("--limit", type=int, default=50, help="Maximale Gruppenanzeige; 0 für alle")
    scan.add_argument("--show-usernames", action="store_true", help="Benutzernamen im Bericht offenlegen")
    scan.add_argument("--keep", choices=("newest", "oldest", "richest"), default="newest")
    scan.add_argument("--fuzzy-threshold", type=float, default=0, help="Ähnliche Titel berücksichtigen (0=aus, sonst 0.5 bis 1.0)")
    scan.add_argument("--force", action="store_true", help="Bestehenden Bericht ersetzen")
    add_filters(scan)

    plan = sub.add_parser("plan", help="Automatischen Löschvorschlag als JSON erzeugen", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    plan.add_argument("input", type=Path)
    plan.add_argument("--output", required=True, type=Path, help="Ausgabedatei für den Prüfplan")
    plan.add_argument("--policy", choices=("exact", "same-credentials"), default="exact",
                      help="same-credentials kann unterschiedliche Notizen/Anhänge entfernen")
    plan.add_argument("--keep", choices=("newest", "oldest", "richest"), default="newest")
    plan.add_argument("--acknowledge-metadata-loss", action="store_true",
                      help="Risiko unterschiedlicher Zusatzdaten für same-credentials ausdrücklich akzeptieren")
    plan.add_argument("--force", action="store_true")
    add_filters(plan)

    review = sub.add_parser("review", help="Kandidatengruppen interaktiv prüfen und Plan bearbeiten")
    review.add_argument("input", type=Path)
    review.add_argument("--plan", required=True, type=Path)
    review.add_argument("--show-usernames", action="store_true")
    review.add_argument("--fuzzy-threshold", type=float, default=None,
                        help="Zusätzliche ähnliche Titel anzeigen (0=aus, sonst 0.5 bis 1.0)")

    apply = sub.add_parser("apply", help="Geprüften Plan auf einen neuen Export anwenden")
    apply.add_argument("input", type=Path)
    apply.add_argument("--plan", required=True, type=Path)
    apply.add_argument("--output", required=True, type=Path)
    apply.add_argument("--yes", action="store_true", help="Bestätigungsfrage überspringen")
    apply.add_argument("--force", action="store_true", help="Bestehenden bereinigten Export ersetzen")

    verify = sub.add_parser("verify", help="Bereinigten Export gegen Ursprungsdatei und Plan prüfen")
    verify.add_argument("input", type=Path)
    verify.add_argument("--plan", required=True, type=Path)
    verify.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def check_fuzzy(val: float) -> None:
    if val and not 0.5 <= val <= 1:
        raise UserError("--fuzzy-threshold muss 0 oder im Bereich [0.5, 1.0] liegen")


def main() -> int:
    args = parse_args()
    origin, raw = read_export(args.input)
    items = origin["items"]
    if args.command == "stats":
        active = [item for item in items if eligible(item, args.include_trashed, args.include_archived)]
        print(f"Einträge insgesamt: {len(items)} | berücksichtigt: {len(active)}")
        print("Kategorien:")
        for category, count in Counter(str(item.get("category", "(unbekannt)")) for item in active).most_common():
            print(f"  {clean_terminal(category)}: {count}")
        print(f"Mit Anhängen: {sum(richness(x)[0] > 0 for x in active)}")
        return 0

    if args.command == "scan":
        check_fuzzy(args.fuzzy_threshold)
        if args.limit < 0:
            raise UserError("--limit darf nicht negativ sein")
        candidates = groups_for(items, args.include_trashed, args.include_archived, args.fuzzy_threshold)
        chosen = [g for g in candidates if args.mode == "all" or g.kind == args.mode]
        shown = chosen[:args.limit] if args.limit else chosen
        report_text = describe(chosen, items, usernames=args.show_usernames, limit=args.limit, strategy=args.keep)
        print(report_text)
        if args.report:
            prevent_input_overwrite([args.input], args.report)
            rows = group_rows(items, shown, args.keep, args.show_usernames)
            write_report(args.report, rows, args.format, report_text, args.force)
            print(f"\nBericht geschrieben: {args.report}")
        return 0

    if args.command == "plan":
        if args.policy == "same-credentials" and not args.acknowledge_metadata_loss:
            raise UserError("--policy same-credentials erfordert --acknowledge-metadata-loss")
        prevent_input_overwrite([args.input], args.output)
        candidates = groups_for(items, args.include_trashed, args.include_archived)
        options = {"include_trashed": args.include_trashed, "include_archived": args.include_archived,
                   "fuzzy_threshold": 0}
        plan_doc = make_plan(raw, items, candidates, args.policy, args.keep, options)
        removed = validate_plan(plan_doc, raw, items)
        write_json(args.output, plan_doc, args.force)
        print(f"Prüfplan: {args.output} | Entscheidungen: {len(plan_doc['decisions'])} | Entfernen: {len(removed)}")
        print("Originaldaten unverändert. Weitere Kandidaten mit 'review' prüfen.")
        return 0

    if args.command == "review":
        if not sys.stdin.isatty():
            raise UserError("review braucht ein interaktives Terminal")
        plan_doc = load_plan(args.plan)
        validate_plan(plan_doc, raw, items)
        opts = plan_doc["options"]
        threshold = (float(opts.get("fuzzy_threshold", 0)) if args.fuzzy_threshold is None
                     else args.fuzzy_threshold)
        check_fuzzy(threshold)
        opts["fuzzy_threshold"] = threshold
        candidates = groups_for(items, bool(opts.get("include_trashed")),
                                bool(opts.get("include_archived")), threshold)
        current = list(plan_doc["decisions"])
        for index, group in enumerate(candidates, start=1):
            members = set(group.indices)
            old = next((d for d in current if d["kind"] == group.kind
                        and set([d["keep"], *d["remove"]]) == members), None)
            if old:
                current.remove(old)
            # The user may replace several auto-selected exact groups with a
            # single manually reviewed candidate group. Do not discard the
            # original approvals unless a new keep decision is confirmed.
            embedded = [d for d in current if set([d["keep"], *d["remove"]]) <= members]
            blocked = set()
            for d in current:
                if d not in embedded:
                    blocked.update([d["keep"], *d["remove"]])
            available = [i for i in group.indices if i not in blocked]
            if len(available) < 2:
                if old:
                    current.append(old)
                continue
            print(f"\n[{index}/{len(candidates)}] {group.kind.upper()} – "
                  f"Vorsicht: Unterschiede können Notizen, TOTP, Anhänge oder Passkeys betreffen")
            for i in available:
                print("  " + display_item(i, items[i], args.show_usernames))
            default = old["keep"] if old and old["keep"] in available else None
            print(f"  Eingabe: k INDEX (diesen behalten), s (überspringen), "
                  f"Enter ({'behalten #' + str(default) if default is not None else 'überspringen'}), q (abbrechen)")
            choice = input("  > ").strip().lower()
            if choice == "q":
                print("Abbruch: Plan nicht gespeichert.")
                return 1
            if choice == "" and default is not None:
                current.append(old)
                continue
            if choice in ("", "s"):
                continue
            match = re.fullmatch(r"k\s+(\d+)", choice)
            if not match or int(match[1]) not in available:
                raise UserError("Ungültige Auswahl; Plan nicht gespeichert")
            keep_idx = int(match[1])
            for d in embedded:
                current.remove(d)
            current.append({"kind": group.kind, "keep": keep_idx,
                            "remove": [i for i in available if i != keep_idx]})
        plan_doc["decisions"] = current
        validate_plan(plan_doc, raw, items)
        write_json(args.plan, plan_doc, force=True)
        print(f"Plan gespeichert: {args.plan} | zu entfernen: "
              f"{sum(len(d['remove']) for d in current)}")
        return 0

    if args.command in {"apply", "verify"}:
        plan_doc = load_plan(args.plan)
        removed = validate_plan(plan_doc, raw, items)
        if args.command == "apply":
            prevent_input_overwrite([args.input, args.plan], args.output)
            if not args.yes:
                if not sys.stdin.isatty():
                    raise UserError("Ohne interaktives Terminal ist --yes notwendig")
                print(f"{len(removed)} von {len(items)} Einträgen aus NEUEM JSON-Export entfernen.")
                if input("Fortfahren? Tippe JA: ").strip() != "JA":
                    print("Abgebrochen.")
                    return 1
            clean = {**origin, "items": [obj for i, obj in enumerate(items) if i not in removed]}
            verify_export(origin, clean, removed)
            write_json(args.output, clean, args.force)
            reloaded, _ = read_export(args.output)
            verify_export(origin, reloaded, removed)
            print(f"Bereinigter Export: {args.output} | Einträge: {len(items)} -> {len(clean['items'])}")
            print("Enpass-Vault NICHT geändert! Nicht in einen bereits gefüllten Tresor importieren.")
        else:
            clean, _ = read_export(args.output)
            verify_export(origin, clean, removed)
            print(f"OK: {len(clean['items'])} unveränderte Datensätze, "
                  f"{len(removed)} planmäßig entfernt; übrige Exportfelder identisch.")
        return 0
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (UserError, KeyboardInterrupt) as error:
        print(f"Fehler: {error or 'Abgebrochen'}", file=sys.stderr)
        sys.exit(2)
