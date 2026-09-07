# Architecture

WARDEN-11 uses a modular case-based architecture:

```text
case
  -> scope
  -> patrol module
  -> SQLite storage
  -> findings
  -> reports
  -> dashboard
```

Modules:

- `web.rs`
- `secrets.rs`
- `passwords.rs`
- `hashes.rs`
- `report.rs`
- `db.rs`
- `scope.rs`
- `case.rs`
