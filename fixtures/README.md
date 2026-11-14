# Sample data

All files are fictional and safe to share. Nothing here is real company or personal data.

## samples/ — normal files (upload succeeds)

| File | What it is |
|---|---|
| `access-policy.pdf` | 2-page access control policy for a fictional company |
| `quarterly-briefing.txt` | Short text briefing |
| `incident-notes.md` | Markdown incident notes |
| `vendor-contacts.csv` | Small CSV with invented contacts |
| `network-diagram.png` | Simple diagram image |

## adverse/ — bad files (on purpose)

These files are **deliberately broken**. They exist to prove that VaultShare spots unsafe input and explains why. They are not supposed to open normally.

| File | Why it is bad | Expected result in VaultShare |
|---|---|---|
| `not-really.pdf` | Plain text renamed to `.pdf`, so PDF readers cannot open it | Rejected: `CONTENT_TYPE_MISMATCH` (high severity) |
| `report.pdf.exe` | Double extension that hides a program behind a document name | Rejected: `TYPE_NOT_ALLOWED` |
| `empty.txt` | Empty file (0 bytes) | Rejected: `FILE_EMPTY` |
| `formula-injection.csv` | A cell starting with `=` that Excel would run as a formula | Upload is allowed (CSV is a permitted type and the file is only stored encrypted). It shows the risk the CSV exports guard against: VaultShare's own exports prefix such cells with `'` so they cannot run (test "CSV export neutralises spreadsheet formulas") |
