# Oracle Identity & Access Management Dashboard Server

This directory contains the hosted IAM dashboard server, its administration API, and
the install and upgrade utilities used to deploy it as a Linux systemd service.

## Quick Install

From the Linux host, download the current GitHub source bundle, extract it, and run the installer:

```bash
cd /tmp
curl -L https://github.com/my-oracle-user/iam-monitoring/archive/refs/heads/main.tar.gz -o iam-monitoring-main.tar.gz
tar -xzf iam-monitoring-main.tar.gz
cd iam-monitoring-main/server-app
sudo bash ./install.sh
```

The installer prompts for the service port and defaults to `8081`.
It also prompts for the default collector interval and defaults to `60` minutes.

If the server needs an outbound proxy for GitHub update checks, add these to `/etc/iam-monitoring.env`
after install and then restart `iam-monitoring`:

```bash
IAM_MONITORING_HTTP_PROXY=http://www-proxy-phx.oraclecorp.com:80
IAM_MONITORING_HTTPS_PROXY=http://www-proxy-phx.oraclecorp.com:80
IAM_MONITORING_NO_PROXY=127.0.0.1,localhost
```

You can also save update-check proxy details from `Administration -> Help -> GitHub Update Proxy`.
Those UI-saved values take effect immediately for the dashboard's `Check For Updates` action.

## Quick Upgrade

From the Linux host, run the installed upgrader against the latest GitHub source bundle:

```bash
sudo bash -lc 'curl -L https://github.com/my-oracle-user/iam-monitoring/archive/refs/heads/main.tar.gz -o /tmp/iam-monitoring-main.tar.gz && bash /opt/iam-monitoring/upgrade.sh --archive /tmp/iam-monitoring-main.tar.gz'
```

That keeps the existing runtime env file, state directory, and saved environments in place.

If you only need the upgrade download itself to use a proxy, your current pattern also works:

```bash
sudo bash -lc '
export http_proxy=http://www-proxy-phx.oraclecorp.com:80
export https_proxy=http://www-proxy-phx.oraclecorp.com:80
curl -L https://github.com/my-oracle-user/iam-monitoring/archive/refs/heads/main.tar.gz -o /tmp/iam-monitoring-main.tar.gz && \
bash /opt/iam-monitoring/upgrade.sh --archive /tmp/iam-monitoring-main.tar.gz
'
```

For the dashboard service's own `Check For Updates` button, put the proxy settings in `/etc/iam-monitoring.env`
and restart the service.

Or save them from `Administration -> Help -> GitHub Update Proxy` if you want that GitHub check to work
without editing the Linux env file directly.

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

Optional proxy settings for the dashboard service:

- `IAM_MONITORING_HTTP_PROXY=http://proxy.example.com:80`
- `IAM_MONITORING_HTTPS_PROXY=http://proxy.example.com:80`
- `IAM_MONITORING_NO_PROXY=127.0.0.1,localhost`

After changing `/etc/iam-monitoring.env`, restart the service:

```bash
sudo systemctl restart iam-monitoring
```

The Help page can also store proxy settings inside the dashboard registry for `Check For Updates`.
That UI path applies immediately and is useful when admins should not edit `/etc/iam-monitoring.env`
just to make the GitHub version check work.

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
