#!/usr/bin/env python3
import json
import mimetypes
import os
import re
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen

from collector import (
    build_environment_error_dashboard,
    collect_environment_dashboard,
    collect_monitoring_server,
    extract_environment_overview,
    hydrate_dashboard_payload,
)
from config_store import (
    load_config,
)
from environment_registry import (
    delete_environment,
    get_environment,
    list_environments,
    migrate_config_environments,
    save_environment,
)
from job_runner import (
    bootstrap_environment_runtime,
    build_pending_dashboard,
    clear_environment_runtime_state,
    collect_environment_now,
    environment_overview_from_snapshot,
    get_default_collection_minutes,
    launch_collection_job,
    load_environment_snapshot,
    read_job_status,
)
from notification_store import (
    get_notification_settings,
    notification_payload,
    save_notification_recipient,
    save_notification_settings,
    delete_notification_recipient,
)
from support_store import (
    get_update_proxy_settings,
    save_update_proxy_settings,
)
from upgrade_runtime import (
    append_upgrade_log,
    queue_github_upgrade,
    read_upgrade_status,
    write_upgrade_status,
)


APP_ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_ROOT = os.path.join(APP_ROOT, "static")
CONFIG_PATH = os.path.join(APP_ROOT, "config.json")
VERSION_PATH = os.path.join(APP_ROOT, "VERSION")
STATE_ROOT = os.path.join(APP_ROOT, "state")
DB_PATH = os.environ.get(
    "IAM_MONITORING_DB_PATH",
    os.environ.get("IAM_DASHBOARD_DB_PATH", os.path.join(STATE_ROOT, "iam-monitoring.sqlite")),
)
HOST = os.environ.get("IAM_MONITORING_HOST", os.environ.get("IAM_DASHBOARD_HOST", "0.0.0.0"))
PORT = int(os.environ.get("IAM_MONITORING_PORT", os.environ.get("IAM_DASHBOARD_PORT", "8081")))
CACHE_SECONDS = int(os.environ.get("IAM_MONITORING_CACHE_SECONDS", os.environ.get("IAM_DASHBOARD_CACHE_SECONDS", "60")))
LOG_DIR = os.environ.get("IAM_MONITORING_LOG_DIR", os.path.join(os.path.dirname(DB_PATH), "logs"))
CONFIG_FILE_PATH = os.environ.get("IAM_MONITORING_CONFIG", "/etc/iam-monitoring.env")
SERVICE_NAME = "iam-monitoring"
SERVICE_FILE_PATH = "/etc/systemd/system/{0}.service".format(SERVICE_NAME)
UPGRADE_SERVICE_NAME = "iam-monitoring-upgrader"
UPGRADE_SERVICE_FILE_PATH = "/etc/systemd/system/{0}.service".format(UPGRADE_SERVICE_NAME)
CRON_FILE_PATH = "/etc/cron.d/iam-monitoring"
GITHUB_OWNER = os.environ.get("IAM_MONITORING_GITHUB_OWNER", "my-oracle-user")
GITHUB_REPO = os.environ.get("IAM_MONITORING_GITHUB_REPO", "iam-monitoring")
GITHUB_BRANCH = os.environ.get("IAM_MONITORING_GITHUB_BRANCH", "main")


def read_version():
    try:
        with open(VERSION_PATH, "r", encoding="utf-8") as handle:
            return handle.read().strip() or "unknown"
    except Exception:
        return "unknown"


def read_int_env(primary_name, legacy_name, default_value):
    raw_value = os.environ.get(primary_name, os.environ.get(legacy_name, str(default_value)))
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return default_value


def build_help_details():
    version = read_version()
    state_dir = os.path.dirname(DB_PATH)
    scheduler_minutes = read_int_env("IAM_MONITORING_SCHEDULER_MINUTES", "IAM_DASHBOARD_SCHEDULER_MINUTES", 5)
    default_collection_minutes = get_default_collection_minutes()
    local_health_host = "127.0.0.1" if HOST in ("0.0.0.0", "::") else HOST
    runtime_env_dir = os.path.join(state_dir, "runtime_env")
    snapshot_dir = os.path.join(state_dir, "snapshots")
    job_state_dir = os.path.join(state_dir, "job_state")
    update_proxy = merge_update_check_proxy_settings()
    return {
        "productName": "Oracle Identity & Access Management Dashboard",
        "version": version,
        "packageName": "iam-monitoring",
        "platform": "Linux systemd service",
        "serviceName": SERVICE_NAME,
        "serviceFile": SERVICE_FILE_PATH,
        "upgradeServiceName": UPGRADE_SERVICE_NAME,
        "upgradeServiceFile": UPGRADE_SERVICE_FILE_PATH,
        "serviceUser": os.environ.get("IAM_MONITORING_SERVICE_USER", SERVICE_NAME),
        "installDirectory": APP_ROOT,
        "runtimeEnvFile": CONFIG_FILE_PATH,
        "databasePath": DB_PATH,
        "stateDirectory": state_dir,
        "runtimeEnvDirectory": runtime_env_dir,
        "snapshotDirectory": snapshot_dir,
        "jobStateDirectory": job_state_dir,
        "logDirectory": LOG_DIR,
        "schedulerLogPath": os.path.join(LOG_DIR, "scheduler.log"),
        "cronFile": CRON_FILE_PATH,
        "host": HOST,
        "port": PORT,
        "healthPath": "/healthz",
        "healthUrl": "http://{0}:{1}/healthz".format(local_health_host, PORT),
        "schedulerWakeMinutes": scheduler_minutes,
        "defaultCollectionMinutes": default_collection_minutes,
        "updateProxy": update_proxy,
        "githubUpgrade": {
            "enabled": True,
            "repoUrl": github_repo_url(),
            "archiveUrl": github_archive_url(),
            "branch": GITHUB_BRANCH,
            "serviceName": UPGRADE_SERVICE_NAME,
            "status": read_upgrade_status(DB_PATH),
        },
        "checks": [
            {
                "label": "Service status",
                "command": "sudo systemctl status {0} --no-pager".format(SERVICE_NAME),
            },
            {
                "label": "Upgrade helper status",
                "command": "sudo systemctl status {0} --no-pager".format(UPGRADE_SERVICE_NAME),
            },
            {
                "label": "Service logs",
                "command": "sudo journalctl -u {0} -n 100 --no-pager".format(SERVICE_NAME),
            },
            {
                "label": "Health check",
                "command": "curl http://127.0.0.1:{0}/healthz".format(PORT),
            },
            {
                "label": "Health response headers",
                "command": "curl -I http://127.0.0.1:{0}/healthz".format(PORT),
            },
            {
                "label": "Scheduler log",
                "command": "sudo tail -F {0}".format(os.path.join(LOG_DIR, "scheduler.log")),
            },
        ],
        "notes": [
            "This dashboard is installed as a Linux systemd service and uses a host cron scheduler for due environment collectors.",
            "Administration is where environments, notifications, and support details live. Environment pages stay focused on that selected IAM environment.",
            "Use Save And Bootstrap when adding an environment so the dashboard can switch from the initial SSH login to its installed runtime key for ongoing collection.",
            "Fresh installs start with an empty SQLite environment registry and pick up runtime settings from the local environment file.",
            "If GitHub update checks need an outbound proxy, save it under Administration / Help / GitHub Update Proxy. The Linux env file remains the service-level fallback.",
            "GitHub upgrades can be queued from Administration / Help. The helper downloads the bundle and runs its bundled upgrade.sh before the main service restarts on the new build.",
        ],
    }


def github_repo_url():
    return "https://github.com/{0}/{1}".format(GITHUB_OWNER, GITHUB_REPO)


def github_archive_url():
    return "https://github.com/{0}/{1}/archive/refs/heads/{2}.tar.gz".format(
        GITHUB_OWNER,
        GITHUB_REPO,
        GITHUB_BRANCH,
    )


def github_version_url():
    return "https://raw.githubusercontent.com/{0}/{1}/{2}/server-app/VERSION".format(
        GITHUB_OWNER,
        GITHUB_REPO,
        GITHUB_BRANCH,
    )


def build_github_upgrade_response(status_payload):
    return {
        "enabled": True,
        "repoUrl": github_repo_url(),
        "archiveUrl": github_archive_url(),
        "branch": GITHUB_BRANCH,
        "serviceName": UPGRADE_SERVICE_NAME,
        "status": status_payload,
    }


def _letter_version_value(value):
    total = 0
    for character in str(value or "").strip().lower():
        if not ("a" <= character <= "z"):
            return None
        total = (total * 26) + (ord(character) - 96)
    return total


def _parse_version_value(value):
    text = str(value or "").strip().lower()
    if not text:
        return None
    match = re.match(r"^(\d+)([a-z]+)$", text)
    if match:
        return ("letter", int(match.group(1)), _letter_version_value(match.group(2)))
    if re.match(r"^\d+(?:\.\d+)+$", text):
        return ("dot", tuple(int(part) for part in text.split(".")))
    if re.match(r"^\d+$", text):
        return ("number", int(text))
    return None


def compare_version_values(local_version, remote_version):
    if str(local_version or "").strip() == str(remote_version or "").strip():
        return 0
    local_parsed = _parse_version_value(local_version)
    remote_parsed = _parse_version_value(remote_version)
    if not local_parsed or not remote_parsed or local_parsed[0] != remote_parsed[0]:
        return None
    if local_parsed[1:] < remote_parsed[1:]:
        return -1
    if local_parsed[1:] > remote_parsed[1:]:
        return 1
    return 0


def env_update_check_proxy_settings():
    return {
        "httpProxy": str(
            os.environ.get(
                "IAM_MONITORING_HTTP_PROXY",
                os.environ.get("http_proxy", os.environ.get("HTTP_PROXY", "")),
            )
            or ""
        ).strip(),
        "httpsProxy": str(
            os.environ.get(
                "IAM_MONITORING_HTTPS_PROXY",
                os.environ.get("https_proxy", os.environ.get("HTTPS_PROXY", "")),
            )
            or ""
        ).strip(),
        "noProxy": str(
            os.environ.get(
                "IAM_MONITORING_NO_PROXY",
                os.environ.get("no_proxy", os.environ.get("NO_PROXY", "")),
            )
            or ""
        ).strip(),
    }


def proxy_settings_have_values(proxy_settings):
    proxy_settings = proxy_settings or {}
    return bool(
        str(proxy_settings.get("httpProxy") or "").strip()
        or str(proxy_settings.get("httpsProxy") or "").strip()
        or str(proxy_settings.get("noProxy") or "").strip()
    )


def proxy_settings_have_routing(proxy_settings):
    proxy_settings = proxy_settings or {}
    return bool(
        str(proxy_settings.get("httpProxy") or "").strip()
        or str(proxy_settings.get("httpsProxy") or "").strip()
    )


def merge_update_check_proxy_settings(saved_settings=None, env_settings=None):
    saved_settings = saved_settings or get_update_proxy_settings(DB_PATH)
    env_settings = env_settings or env_update_check_proxy_settings()
    effective_settings = {
        "httpProxy": str(saved_settings.get("httpProxy") or env_settings.get("httpProxy") or "").strip(),
        "httpsProxy": str(saved_settings.get("httpsProxy") or env_settings.get("httpsProxy") or "").strip(),
        "noProxy": str(saved_settings.get("noProxy") or env_settings.get("noProxy") or "").strip(),
    }
    saved_configured = proxy_settings_have_values(saved_settings)
    env_configured = proxy_settings_have_values(env_settings)
    if saved_configured and env_configured:
        source = "dashboard_and_env"
        source_label = "Dashboard saved proxy with service env fallback"
    elif saved_configured:
        source = "dashboard"
        source_label = "Dashboard saved proxy"
    elif env_configured:
        source = "service_env"
        source_label = "Service env file"
    else:
        source = "none"
        source_label = "No proxy configured"
    return {
        "savedSettings": {
            "httpProxy": str(saved_settings.get("httpProxy") or "").strip(),
            "httpsProxy": str(saved_settings.get("httpsProxy") or "").strip(),
            "noProxy": str(saved_settings.get("noProxy") or "").strip(),
            "configured": saved_configured,
        },
        "envSettings": {
            "httpProxy": str(env_settings.get("httpProxy") or "").strip(),
            "httpsProxy": str(env_settings.get("httpsProxy") or "").strip(),
            "noProxy": str(env_settings.get("noProxy") or "").strip(),
            "configured": env_configured,
        },
        "effectiveSettings": effective_settings,
        "savedConfigured": saved_configured,
        "envConfigured": env_configured,
        "configured": proxy_settings_have_routing(effective_settings),
        "source": source,
        "sourceLabel": source_label,
    }


def update_check_proxy_hint(proxy_context=None):
    proxy_context = proxy_context or merge_update_check_proxy_settings()
    if proxy_context.get("configured"):
        return (
            "Proxy is already configured for GitHub update checks. Recheck the proxy host, "
            "port, and any required SSL or egress policy."
        )
    return (
        "If this host requires an outbound proxy, save it under Administration / Help / "
        "GitHub Update Proxy, or set IAM_MONITORING_HTTP_PROXY and "
        "IAM_MONITORING_HTTPS_PROXY in /etc/iam-monitoring.env and restart iam-monitoring."
    )


def build_update_check_payload():
    current_version = read_version()
    proxy_context = merge_update_check_proxy_settings()
    proxy_settings = proxy_context.get("effectiveSettings") or {}
    payload = {
        "currentVersion": current_version,
        "remoteVersion": "",
        "repoUrl": github_repo_url(),
        "versionUrl": github_version_url(),
        "branch": GITHUB_BRANCH,
        "checkedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "idle",
        "message": "",
        "proxyConfigured": bool(proxy_context.get("configured")),
        "proxySource": proxy_context.get("source") or "none",
        "proxySourceLabel": proxy_context.get("sourceLabel") or "No proxy configured",
    }
    try:
        request = Request(payload["versionUrl"], headers={"User-Agent": "iam-monitoring-update-check"})
        proxy_handler_settings = {}
        if proxy_settings.get("httpProxy"):
            proxy_handler_settings["http"] = proxy_settings.get("httpProxy")
        if proxy_settings.get("httpsProxy"):
            proxy_handler_settings["https"] = proxy_settings.get("httpsProxy")
        if proxy_handler_settings:
            opener = build_opener(ProxyHandler(proxy_handler_settings))
            response_handle = opener.open(request, timeout=6)
        else:
            response_handle = urlopen(request, timeout=6)
        with response_handle as response:
            remote_version = response.read().decode("utf-8").strip()
        if not remote_version:
            raise ValueError("GitHub did not return a VERSION value.")
        payload["remoteVersion"] = remote_version
        comparison = compare_version_values(current_version, remote_version)
        if comparison == 0:
            payload["status"] = "current"
            payload["message"] = "This dashboard is up to date with GitHub {0}.".format(GITHUB_BRANCH)
        elif comparison == -1:
            payload["status"] = "update_available"
            payload["message"] = "GitHub {0} has a newer version available: {1}.".format(GITHUB_BRANCH, remote_version)
        elif comparison == 1:
            payload["status"] = "ahead"
            payload["message"] = "This dashboard is ahead of GitHub {0}.".format(GITHUB_BRANCH)
        else:
            payload["status"] = "different"
            payload["message"] = "GitHub {0} reports version {1}; compare it with the running version {2}.".format(
                GITHUB_BRANCH,
                remote_version,
                current_version,
            )
    except Exception as exc:
        payload["status"] = "error"
        payload["message"] = "GitHub update check failed: {0} {1}".format(str(exc), update_check_proxy_hint(proxy_context))
    return payload


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def build_configured_environment_overview(environment):
    server = environment.get("server") or {}
    return {
        "id": environment.get("id"),
        "name": environment.get("name"),
        "description": environment.get("description"),
        "environmentType": environment.get("environmentType"),
        "host": server.get("host"),
        "status": "configured",
        "generatedAtLocal": None,
        "actualHostname": None,
        "products": environment.get("products") or {},
        "sshMode": server.get("sshMode"),
        "authType": server.get("authType"),
        "collection": environment.get("collection") or {},
        "bootstrap": environment.get("bootstrap") or {},
        "summary": {
            "totalApps": 0,
            "healthyApps": 0,
            "warningApps": 0,
            "downApps": 0,
        },
    }


def load_runtime_config():
    config = load_config(CONFIG_PATH)
    migrate_config_environments(DB_PATH, config)
    return config


class DashboardCache(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.monitoring_entry = {"data": None, "generated": 0, "error": None}
        self.environment_entries = {}

    def _expired(self, generated_at):
        return not generated_at or (time.time() - generated_at) > CACHE_SECONDS

    def invalidate(self, environment_id=None):
        with self.lock:
            self.monitoring_entry = {"data": None, "generated": 0, "error": None}
            if environment_id is None:
                self.environment_entries = {}
            else:
                self.environment_entries.pop(environment_id, None)

    def get_monitoring(self, config, force=False):
        with self.lock:
            if force or self.monitoring_entry["data"] is None or self._expired(self.monitoring_entry["generated"]):
                try:
                    self.monitoring_entry["data"] = collect_monitoring_server(config.get("monitoring_server") or {})
                    self.monitoring_entry["generated"] = time.time()
                    self.monitoring_entry["error"] = None
                except Exception as exc:
                    self.monitoring_entry["error"] = str(exc)
                    if self.monitoring_entry["data"] is None:
                        raise

            payload = dict(self.monitoring_entry["data"] or {})
            if self.monitoring_entry["error"]:
                payload["collectorError"] = self.monitoring_entry["error"]
            return payload

    def get_environment(self, config, environment_id, force=False):
        environment = get_environment(DB_PATH, environment_id, include_secret=True)
        if not environment:
            raise KeyError("Unknown environment: {0}".format(environment_id))

        try:
            payload = collect_environment_now(DB_PATH, environment_id, trigger="api_force") if force else load_environment_snapshot(DB_PATH, environment_id)
        except Exception as exc:
            payload = load_environment_snapshot(DB_PATH, environment_id) or build_pending_dashboard(environment, str(exc))
            payload["collectorError"] = str(exc)

        if not payload:
            payload = build_pending_dashboard(environment)
        payload = hydrate_dashboard_payload(payload)
        payload["job"] = read_job_status(DB_PATH, environment_id)
        return payload

    def get_app_shell(self, config, force=False):
        with self.lock:
            monitoring_cache = dict(self.monitoring_entry["data"] or {})
            monitoring_error = self.monitoring_entry["error"]

        monitoring = {
            "name": (config.get("monitoring_server") or {}).get("name"),
            "host": (config.get("monitoring_server") or {}).get("host"),
            "description": (config.get("monitoring_server") or {}).get("description"),
            "servicePort": (config.get("monitoring_server") or {}).get("servicePort"),
            "status": "configured",
        }
        if monitoring_cache:
            monitoring.update(monitoring_cache)
        if monitoring_error:
            monitoring["collectorError"] = monitoring_error

        environments = []
        for environment in list_environments(DB_PATH, include_secret=False):
            snapshot_overview = environment_overview_from_snapshot(DB_PATH, environment)
            environments.append(snapshot_overview or build_configured_environment_overview(environment))

        return {
            "title": config.get("dashboard_title") or "Oracle Identity & Access Management Dashboard",
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "generatedAtLocal": time.strftime("%A, %B %d %Y %H:%M:%S %Z"),
            "monitoringServer": monitoring,
            "environments": environments,
            "operations": config.get("operations") or {},
            "help": build_help_details(),
        }


CACHE = DashboardCache()


def parse_json_body(request_handler):
    length = int(request_handler.headers.get("Content-Length") or "0")
    raw_body = request_handler.rfile.read(length) if length > 0 else b"{}"
    if not raw_body:
        return {}
    return json.loads(raw_body.decode("utf-8"))


def send_notification_test(db_path, payload):
    payload = payload or {}
    settings = get_notification_settings(db_path, include_secret=True)
    if not settings.get("smtpHost") or not settings.get("smtpPort"):
        raise ValueError("SMTP host and port are required before sending a test email.")
    if not settings.get("senderEmail"):
        raise ValueError("Sender email is required before sending a test email.")

    target_email = str(payload.get("targetEmail") or "").strip()
    if not target_email:
        raise ValueError("Test email target is required.")

    message = EmailMessage()
    sender_name = settings.get("senderName") or "Oracle Identity & Access Management Dashboard"
    message["Subject"] = "Oracle Identity & Access Management Dashboard notification test"
    message["From"] = "{0} <{1}>".format(sender_name, settings.get("senderEmail"))
    message["To"] = target_email
    message.set_content(
        "This is a test email from Oracle Identity & Access Management Dashboard.\n\n"
        "If you received this message, the SMTP configuration is working."
    )

    host = settings.get("smtpHost")
    port = int(settings.get("smtpPort") or 0)
    username = settings.get("smtpUsername") or ""
    password = settings.get("smtpPassword") or ""
    mode = settings.get("securityMode") or "starttls"
    timeout = 20

    if mode == "ssl":
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=context, timeout=timeout) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as server:
            server.ehlo()
            if mode == "starttls":
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message)

    return {"sent": True, "targetEmail": target_email}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query or "")

        if path == "/healthz":
            return self.handle_healthz()

        if path == "/api/app":
            return self.handle_app_shell(query)

        if path == "/api/admin/environments":
            return self.handle_admin_environments()

        if path == "/api/admin/notifications":
            return self.handle_admin_notifications()

        if path == "/api/admin/updates/check":
            return self.handle_admin_update_check()

        if path == "/api/admin/upgrade/status":
            return self.handle_admin_upgrade_status()

        match = re.match(r"^/api/admin/environments/([^/]+)/jobs$", path)
        if match:
            return self.handle_environment_jobs(match.group(1))

        match = re.match(r"^/api/environments/([^/]+)/dashboard$", path)
        if match:
            return self.handle_environment_dashboard(match.group(1), query)

        if path == "/" or path == "":
            return self.handle_file(os.path.join(STATIC_ROOT, "index.html"))

        if path.startswith("/assets/"):
            return self.handle_file(os.path.join(STATIC_ROOT, path.lstrip("/")))

        self.send_error(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"

        if path == "/api/admin/environments":
            return self.handle_create_environment()

        match = re.match(r"^/api/admin/environments/([^/]+)/bootstrap$", path)
        if match:
            return self.handle_bootstrap_environment(match.group(1))

        match = re.match(r"^/api/admin/environments/([^/]+)/jobs/run$", path)
        if match:
            return self.handle_run_environment_job(match.group(1))

        if path == "/api/admin/notifications/recipients":
            return self.handle_save_notification_recipient()

        if path == "/api/admin/notifications/test":
            return self.handle_notification_test()

        if path == "/api/admin/upgrade/run":
            return self.handle_run_github_upgrade()

        self.send_error(404, "Not found")

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        if path == "/api/admin/notifications/settings":
            return self.handle_save_notification_settings()
        if path == "/api/admin/help/proxy":
            return self.handle_save_update_proxy_settings()
        match = re.match(r"^/api/admin/environments/([^/]+)$", path)
        if match:
            return self.handle_update_environment(match.group(1))
        self.send_error(404, "Not found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        match = re.match(r"^/api/admin/notifications/recipients/([^/]+)$", path)
        if match:
            return self.handle_delete_notification_recipient(match.group(1))
        match = re.match(r"^/api/admin/environments/([^/]+)$", path)
        if match:
            return self.handle_delete_environment(match.group(1))
        self.send_error(404, "Not found")

    def send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def handle_app_shell(self, query):
        try:
            config = load_runtime_config()
            force = str((query.get("force") or ["0"])[0]).strip() in ("1", "true", "yes")
            payload = CACHE.get_app_shell(config, force=force)
            self.send_json(200, payload)
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def handle_healthz(self):
        self.send_json(200, {"status": "ok"})

    def handle_environment_dashboard(self, environment_id, query):
        try:
            config = load_runtime_config()
            force = str((query.get("force") or ["0"])[0]).strip() in ("1", "true", "yes")
            payload = CACHE.get_environment(config, environment_id, force=force)
            self.send_json(200, payload)
        except KeyError:
            self.send_json(404, {"error": "Environment not found."})
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def handle_admin_environments(self):
        try:
            config = load_runtime_config()
            payload = {
                "environments": list_environments(DB_PATH, include_secret=False),
                "monitoringServer": config.get("monitoring_server") or {},
                "operations": config.get("operations") or {},
                "defaultCollectionMinutes": get_default_collection_minutes(),
            }
            self.send_json(200, payload)
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def handle_admin_notifications(self):
        try:
            self.send_json(200, notification_payload(DB_PATH))
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def handle_admin_update_check(self):
        try:
            self.send_json(200, build_update_check_payload())
        except Exception as exc:
            self.send_json(
                200,
                {
                    "currentVersion": read_version(),
                    "remoteVersion": "",
                    "repoUrl": github_repo_url(),
                    "versionUrl": github_version_url(),
                    "branch": GITHUB_BRANCH,
                    "checkedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "status": "error",
                    "message": "GitHub update check failed: {0}".format(str(exc)),
                    "proxyConfigured": False,
                    "proxySource": "none",
                    "proxySourceLabel": "No proxy configured",
                },
            )

    def handle_save_update_proxy_settings(self):
        try:
            payload = parse_json_body(self)
            settings = save_update_proxy_settings(DB_PATH, payload)
            self.send_json(
                200,
                {
                    "settings": settings,
                    "proxy": merge_update_check_proxy_settings(saved_settings=settings),
                },
            )
        except Exception as exc:
            if isinstance(exc, PermissionError):
                upgrade_state_dir = os.path.join(os.path.dirname(DB_PATH), "upgrade")
                service_user = os.environ.get("IAM_MONITORING_SERVICE_USER", "iam-monitoring")
                self.send_json(
                    400,
                    {
                        "error": (
                            "GitHub upgrade state is not writable by the dashboard service. "
                            "Repair {0} ownership back to the {1} service user and retry."
                        ).format(upgrade_state_dir, service_user)
                    },
                )
                return
            self.send_json(400, {"error": str(exc)})

    def handle_admin_upgrade_status(self):
        try:
            self.send_json(
                200,
                {
                    "enabled": True,
                    "repoUrl": github_repo_url(),
                    "archiveUrl": github_archive_url(),
                    "branch": GITHUB_BRANCH,
                    "serviceName": UPGRADE_SERVICE_NAME,
                    "status": read_upgrade_status(DB_PATH),
                },
            )
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def handle_run_github_upgrade(self):
        try:
            load_runtime_config()
            update_check = build_update_check_payload()
            current_version = read_version()
            remote_version = str(update_check.get("remoteVersion") or "").strip()
            update_proxy = merge_update_check_proxy_settings()

            if update_check.get("status") == "error":
                raise ValueError(update_check.get("message") or "GitHub version check failed.")

            if update_check.get("status") in ("current", "ahead"):
                status_name = "current" if update_check.get("status") == "current" else "ahead"
                message = (
                    "You are already on the latest version."
                    if status_name == "current"
                    else (update_check.get("message") or "This dashboard is already ahead of the GitHub branch.")
                )
                append_upgrade_log(DB_PATH, message)
                status = write_upgrade_status(
                    DB_PATH,
                    {
                        "status": status_name,
                        "requestedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "startedAt": "",
                        "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "message": message,
                        "repoUrl": github_repo_url(),
                        "archiveUrl": github_archive_url(),
                        "branch": GITHUB_BRANCH,
                        "currentVersion": current_version,
                        "targetVersion": remote_version or current_version,
                        "requestId": "",
                        "lastError": "",
                    },
                )
                self.send_json(
                    200,
                    {
                        "alreadyCurrent": True,
                        "message": message,
                        "updateCheck": update_check,
                        "upgrade": build_github_upgrade_response(status),
                    },
                )
                return

            status = queue_github_upgrade(
                DB_PATH,
                {
                    "requestedBy": "ui",
                    "repoUrl": github_repo_url(),
                    "archiveUrl": github_archive_url(),
                    "branch": GITHUB_BRANCH,
                    "currentVersion": current_version,
                    "targetVersion": remote_version,
                    "proxySettings": update_proxy.get("effectiveSettings") or {},
                },
            )
            self.send_json(
                202,
                {
                    "alreadyCurrent": False,
                    "message": update_check.get("message") or "GitHub upgrade queued.",
                    "updateCheck": update_check,
                    "upgrade": build_github_upgrade_response(status),
                },
            )
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_create_environment(self):
        try:
            payload = parse_json_body(self)
            load_runtime_config()
            environment = save_environment(DB_PATH, payload)
            CACHE.invalidate()
            self.send_json(201, {"environment": get_environment(DB_PATH, environment.get("id"), include_secret=False)})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_update_environment(self, environment_id):
        try:
            payload = parse_json_body(self)
            load_runtime_config()
            if not get_environment(DB_PATH, environment_id, include_secret=True):
                return self.send_json(404, {"error": "Environment not found."})
            environment = save_environment(DB_PATH, payload, environment_id=environment_id)
            CACHE.invalidate(environment_id)
            self.send_json(200, {"environment": get_environment(DB_PATH, environment.get("id"), include_secret=False)})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_delete_environment(self, environment_id):
        try:
            load_runtime_config()
            deleted = delete_environment(DB_PATH, environment_id)
            if not deleted:
                return self.send_json(404, {"error": "Environment not found."})
            clear_environment_runtime_state(DB_PATH, environment_id)
            CACHE.invalidate(environment_id)
            self.send_json(200, {"deleted": True})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_bootstrap_environment(self, environment_id):
        try:
            load_runtime_config()
            if not get_environment(DB_PATH, environment_id, include_secret=True):
                return self.send_json(404, {"error": "Environment not found."})
            environment = bootstrap_environment_runtime(DB_PATH, environment_id)
            job_status, started = launch_collection_job(DB_PATH, environment_id, trigger="bootstrap")
            CACHE.invalidate(environment_id)
            self.send_json(
                200,
                {
                    "environment": get_environment(DB_PATH, environment_id, include_secret=False),
                    "runtimeEnvPath": ((environment.get("bootstrap") or {}).get("runtimeEnvPath")) or "",
                    "collectorJob": job_status,
                    "collectorJobStarted": bool(started),
                    "collectorJobAlreadyRunning": not bool(started) and job_status.get("status") == "running",
                },
            )
        except KeyError:
            self.send_json(404, {"error": "Environment not found."})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_environment_jobs(self, environment_id):
        try:
            load_runtime_config()
            if not get_environment(DB_PATH, environment_id, include_secret=True):
                return self.send_json(404, {"error": "Environment not found."})
            snapshot = load_environment_snapshot(DB_PATH, environment_id)
            self.send_json(
                200,
                {
                    "collectorJob": read_job_status(DB_PATH, environment_id),
                    "lastSnapshot": extract_environment_overview(snapshot) if snapshot else None,
                },
            )
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_run_environment_job(self, environment_id):
        try:
            load_runtime_config()
            if not get_environment(DB_PATH, environment_id, include_secret=True):
                return self.send_json(404, {"error": "Environment not found."})
            job_status, started = launch_collection_job(DB_PATH, environment_id, trigger="manual")
            self.send_json(
                200,
                {
                    "collectorJob": job_status,
                    "collectorJobStarted": bool(started),
                    "collectorJobAlreadyRunning": not bool(started) and job_status.get("status") == "running",
                },
            )
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_save_notification_settings(self):
        try:
            payload = parse_json_body(self)
            settings = save_notification_settings(DB_PATH, payload)
            self.send_json(200, {"settings": settings})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_save_notification_recipient(self):
        try:
            payload = parse_json_body(self)
            recipients = save_notification_recipient(DB_PATH, payload)
            self.send_json(200, {"recipients": recipients})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_delete_notification_recipient(self, recipient_id):
        try:
            deleted = delete_notification_recipient(DB_PATH, recipient_id)
            if not deleted:
                return self.send_json(404, {"error": "Recipient not found."})
            self.send_json(200, {"deleted": True, "recipients": notification_payload(DB_PATH)["recipients"]})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_notification_test(self):
        try:
            payload = parse_json_body(self)
            result = send_notification_test(DB_PATH, payload)
            self.send_json(200, result)
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def handle_file(self, path):
        full_path = os.path.abspath(path)
        if not full_path.startswith(os.path.abspath(STATIC_ROOT)):
            return self.send_error(403, "Forbidden")
        if not os.path.isfile(full_path):
            return self.send_error(404, "Not found")
        content_type = mimetypes.guess_type(full_path)[0] or "application/octet-stream"
        with open(full_path, "rb") as handle:
            content = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("IAM dashboard listening on http://{0}:{1}".format(HOST, PORT))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
