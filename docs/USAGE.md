# Usage

```bash
warden11 new cases/audit --title "Authorized patrol"
warden11 scope-add cases/audit https://example.com
warden11 web-audit cases/audit --yes-authorized
warden11 secrets cases/audit ./my-project
warden11 passwords cases/audit passwords.txt
warden11 hashes cases/audit hashes.txt
warden11 report cases/audit
```
