# Oracle Identity & Access Management Dashboard

This workspace now has two layers:

- `server-app/`: the hosted IAM dashboard server, multi-environment registry, UI, and Linux install or upgrade utilities
- root prototype files: the earlier local static collector and HTML snapshot used to bootstrap the first version

The active platform is the hosted server app in:

- `server-app/app.py`
- `server-app/static/`
- `server-app/install.sh`
- `server-app/upgrade.sh`

## Hosted server app

The current server build follows a reusable dashboard-server model:

1. environments are stored in a SQLite-backed registry
2. the UI adds and edits IAM environments from `Administration`
3. collectors connect to each environment over SSH
4. installer and upgrade utilities deploy the app as a Linux `systemd` service

See `server-app/README.md` for install and upgrade details.

## Local prototype

The root-level `index.html`, `scripts/Refresh-IamDashboard.ps1`, and `data/` files are still here as the original prototype path, but they are no longer the primary deployment model.

## Security note

Local credential files such as `config/targets.local.json` are intentionally kept out of source control. For shared or production environments, prefer a dedicated read-only account and rotate any temporary passwords after the initial setup.
