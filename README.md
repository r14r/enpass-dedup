# Enpass Duplicate Cleaner (macOS)

A **localhost-only Streamlit interface** and fully functional Python CLI to inspect Enpass JSON exports, review duplicate candidates, and create a validated **separate** cleaned export. The application does **not** modify Enpass or its vault database.

## Start on macOS

Requirements: Python 3.10+ and Streamlit (CLI works using the standard library alone).

```bash
# Clone
 git clone https://github.com/r14r/enpass-dedup.git
 cd enpass-dedup

# Without just:
 python3 -m venv .venv
 .venv/bin/python -m pip install -r requirements.txt
 .venv/bin/python -m streamlit run app.py

# Alternatively, with just:
 just bootstrap
 just web
 # In a second terminal:
 just open
```

Open **http://127.0.0.1:8501** in your browser. The included `.streamlit/config.toml` binds to localhost and disables Streamlit usage telemetry. Do not expose this server to the Internet or run it on a shared server: exported JSON contains plaintext credentials.

## Supported input formats

| Input | App behavior | Limitation |
| --- | --- | --- |
| `.json` | Parse and analyze locally; provide duplicate reports, review and cleaned JSON | Plaintext, 25 MiB limit; data not always fully represented (e.g. passkeys) |
| `.enpassbackup` | Accept as the starting point for a guided Enpass backup restore, then accept the restored vault's JSON export for analysis | **No direct decryption**: backup is encrypted; the application never requests or stores the Enpass master password. |

**Why is a conversion required?** Enpass encrypts `.enpassbackup` with the vault key. Its supported restore route is Enpass itself, not a documented Python decoder. To avoid compromising user credentials, the app never attempts to parse or decrypt the encrypted file. The app cannot cryptographically prove that the follow-up JSON belongs to the selected backup. Follow the [official Enpass restore instructions](https://help.enpass.io/personal/latest/all/restoring-your-existing-enpass-data), restore only into an isolated test vault, and then export that test vault as JSON through Enpass. Do not restore over a production vault merely to run deduplication.

## Workflow

1. Create an **encrypted Enpass backup** first. Export one vault as JSON to a local, non-synchronized directory.
2. Use the sidebar to upload the JSON file (25 MiB limit), or select `.enpassbackup` and follow its guided Enpass restore/export steps, then upload the resulting JSON, select inclusion of archived/trash records, and optionally enable similar-title matching.
3. Browse four kinds of candidates:
   - `exact`: identical content apart from common record IDs and activity timestamps; **selected by default**.
   - `credentials`: same login credentials, different metadata; **review only**.
   - `conflict`: same account identity, different passwords; **review only**.
   - `possible`: similar title, same username/domain; **review only**, opt-in fuzzy search.
4. In **Duplikate prüfen**, choose a specific record to retain in each group and confirm whether its other records should be removed from the *new export*. Potentially overlapping manual groups must be resolved; explicit manual decisions supersede overlapping automatic exact groups.
5. In **Export & Validierung**, download a password-free CSV report, JSON removal plan, and (after required safety confirmations) a validated cleaned JSON.

**Do not import the cleaned file into a nonempty Enpass vault:** importing does not delete existing duplicates and can create further copies. Validate restoration into a **separate empty test vault** and compare notes, 2FA, attachments, custom fields, categories and any passkeys that JSON may not support. For live deduplication, use the review CSV to manually remove records in Enpass.

### Command line (stdlib, no Streamlit required)

```bash
python3 enpass_dedupe.py stats vault.json
python3 enpass_dedupe.py scan vault.json --mode all --limit 0 --report review.csv --format csv
python3 enpass_dedupe.py plan vault.json --policy exact --keep newest --output plan.json
python3 enpass_dedupe.py review vault.json --plan plan.json
python3 enpass_dedupe.py apply vault.json --plan plan.json --output cleaned.json --yes
python3 enpass_dedupe.py verify vault.json --plan plan.json --output cleaned.json
python3 enpass_dedupe.py --help
```

The CLI accepts **JSON only**; `.enpassbackup` goes through the Enpass restore workflow described above. The CLI writes reports/new exports with `0600` permissions. Unlike the Streamlit app, CLI outputs are saved locally to disk. For full CLI options, see `python3 enpass_dedupe.py <command> --help`.

### Test

```bash
python3 -m unittest discover -s . -p 'test_*.py' -v
# or
just ci
```

Tests operate entirely on synthetic credentials. No real Enpass export is checked into this repository.

## Data protection

- All duplicate classification and export transformations are local. No network API calls, external services or remote-model integration are used by application code.
- Streamlit temporarily retains upload and generated download bytes **in process memory** during the browser session. Data travels between the browser and the localhost Streamlit process; it is **not sent to a cloud backend by this app**.
- No credentials or TOTP values are printed to the UI, CSV report, app logs, or review plan. Titles, usernames (if explicitly enabled) and other metadata can themselves be sensitive.
- The original export is never overwritten. The export is serialized to a new JSON buffer and checked against the original element-by-element before download. A plan is bound to the exact source SHA-256.
- Do not sync, attach, email, upload to GitHub or leave plaintext JSON exports on an unencrypted drive. FileVault is recommended. The `.gitignore` excludes generic `*.json` except the **synthetic** example.
- Some Enpass data and passkeys may not be representable in JSON; the app cannot prove Enpass import compatibility.

## Files

| File | Description |
| --- | --- |
| `app.py` | Streamlit frontend |
| `web_core.py` | Pure upload, plan, CSV and clean-export logic |
| `enpass_dedupe.py` | Original CLI and classification/validation engine |
| `test_enpass_dedupe.py` | Existing CLI regression tests |
| `tests/test_web_core.py` | Streamlit backend safety tests |
| `.streamlit/config.toml` | localhost-only server configuration |
| `justfile` | `bootstrap`, `web`, `ci` commands |
| `example_synthetic.json` | Fake-data example (not real secrets) |