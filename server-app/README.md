# Oracle Identity & Access Management Dashboard Server

This directory contains the hosted IAM dashboard server, its administration API, and
the install and upgrade utilities used to deploy it as a Linux systemd service.

## What is here

- `app.py`: HTTP server and environment administration API
- `collect_environment.py`: collector entry point used by manual jobs and the scheduler
- `collector.py`: SSH-based server and product metric collection
- `config_store.py`: default configuration and environment normalization
- `environment_registry.py`: SQLite-backed environment registry
- `job_runner.py`: bootstrap, runtime env files, snapshot persistence, and collector job state
- `scheduler_jobs.sh`: host scheduler entry point for due environment collectors
- `static/`: dashboard UI assets
- `deploy/oracledash.service`: systemd service template
- `deploy/crontab.iam-monitoring`: cron template for the host scheduler
- `install.sh`: wrapper entry point
- `install_oracledash.sh`: bundle-aware installer
- `upgrade.sh`: bundle-aware upgrade utility with backup creation

## Install

From a Linux staging folder that contains this directory's files:

```bash
sudo bash ./install.sh
```

If you do not pass `--port`, the installer prompts for the service port and defaults to `8081`.
The installer also prompts for the default per-environment collector interval and defaults to `60` minutes.

You can also install directly from an archive:

```bash
sudo bash ./install.sh --archive /tmp/iam-monitoring.tar.gz
sudo bash ./install.sh --archive /tmp/iam-monitoring.zip
```

Default runtime paths:

- install directory: `/opt/iam-monitoring`
- runtime env file: `/etc/iam-monitoring.env`
- state directory: `/var/lib/iam-monitoring/state`
- log directory: `/var/log/iam-monitoring`
- service name: `iam-monitoring`
- service port: `8081`
- host cron file: `/etc/cron.d/iam-monitoring`
- per-environment runtime env files: `/var/lib/iam-monitoring/state/runtime_env`
- environment snapshots: `/var/lib/iam-monitoring/state/snapshots`

Fresh installs start with an empty environment registry.
Runtime service settings come from `/etc/iam-monitoring.env`.
Saved IAM environments are stored in the SQLite registry under `/var/lib/iam-monitoring/state`.
The host scheduler wakes every 5 minutes and only runs an environment when that environment's saved interval is due.

Post-install checks:

- service status: `sudo systemctl status iam-monitoring --no-pager`
- health check: `curl http://127.0.0.1:8081/healthz`
- response headers: `curl -I http://127.0.0.1:8081/healthz`
- service logs: `sudo journalctl -u iam-monitoring -n 100 --no-pager`
- scheduler log: `sudo tail -F /var/log/iam-monitoring/scheduler.log`

## Environment lifecycle

- Add environments from `Administration -> Environments`.
- Use `Administration -> Help` for version, runtime layout, health checks, and service commands.
- Use `Save And Bootstrap` when adding an environment.
- Bootstrap uses the saved initial SSH user and password, or the saved initial private key, one time.
- After bootstrap, the dashboard switches that environment to its installed runtime key for ongoing `Run Jobs Now` and scheduled collection.
- `Run Jobs Now` is available on each environment under `Operations`.

## Upgrade

Run an in-place upgrade from a newer bundle:

```bash
sudo bash ./upgrade.sh
```

Or upgrade from an archive:

```bash
sudo bash ./upgrade.sh --archive /tmp/iam-monitoring.tar.gz
```

The upgrade utility:

- creates a backup under `/opt/iam-monitoring-backup`
- preserves the runtime environment file and state directory
- stages the new application bundle into the install directory
- refreshes the Python virtual environment
- validates the Python modules
- updates the systemd service file
- refreshes the host cron scheduler entry

After install, use the dashboard `Administration` page to add one or more IAM environments.
