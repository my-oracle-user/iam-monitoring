import copy
import json
import os
import re


DEFAULT_OAM_CHECKS = [
    {"product": "oam", "name": "OAM Console", "url": "http://localhost:7001/oamconsole"},
    {"product": "oam", "name": "OAM Access", "url": "http://localhost:14150/access"},
    {"product": "oam", "name": "Fusion Middleware EM", "url": "http://localhost:7201/em"},
]

DEFAULT_OUD_CHECKS = [
    {"product": "oud", "name": "OUDSM", "url": "http://localhost:7101/oudsm"},
]

DEFAULT_OIG_CHECKS = []


def deep_copy(value):
    return copy.deepcopy(value)


def slugify(value):
    text = re.sub(r"[^a-zA-Z0-9]+", "-", str(value or "")).strip("-").lower()
    return text or "environment"


def coerce_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "y", "on"):
        return True
    if text in ("0", "false", "no", "n", "off"):
        return False
    return default


def as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_optional_int(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def default_collection_minutes():
    return max(
        5,
        as_int(
            os.environ.get(
                "IAM_MONITORING_DEFAULT_COLLECTION_MINUTES",
                os.environ.get("IAM_DASHBOARD_DEFAULT_COLLECTION_MINUTES", "60"),
            ),
            60,
        ),
    )


def sanitize_schedule_minutes(value, default):
    return max(5, as_int(value, default))


def preserve_secret(new_value, existing_value, allow_blank=False):
    if new_value is None:
        return existing_value or ""
    if allow_blank and new_value == "":
        return ""
    value = str(new_value).strip()
    if not value and existing_value:
        return existing_value
    return value


def parse_csv_or_list(value, fallback=None):
    fallback = fallback or []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return list(fallback)
    text = str(value).strip()
    if not text:
        return list(fallback)
    return [item.strip() for item in text.split(",") if item.strip()]


def normalize_checks(checks, default_checks):
    source = checks if checks is not None else default_checks
    normalized = []
    for check in source:
        item = check or {}
        name = str(item.get("name") or "").strip()
        url = str(item.get("url") or "").strip()
        product = str(item.get("product") or "generic").strip().lower() or "generic"
        if name and url:
            normalized.append({
                "product": product,
                "name": name,
                "url": url,
            })
    return normalized


def normalize_environment_type(value, fallback=""):
    text = str(value or "").strip().lower()
    if text in ("oam", "oig", "oid", "oud"):
        return text
    return fallback


def normalize_ssh_mode(value, fallback="root_password"):
    text = str(value or "").strip().lower()
    if text in ("root_password", "user_password_sudo", "root_key", "user_key_sudo"):
        return text
    return fallback


def normalize_ssh_profile_payload(
    payload,
    existing=None,
    default_host="",
    default_username="root",
    default_port=22,
    default_mode="root_password",
):
    payload = payload or {}
    existing = existing or {}
    ssh_mode = normalize_ssh_mode(payload.get("sshMode") or existing.get("sshMode"), default_mode)
    profile = {
        "mode": "ssh",
        "host": str(payload.get("host") or existing.get("host") or default_host).strip(),
        "port": as_int(payload.get("port") or existing.get("port") or default_port, default_port),
        "username": str(payload.get("username") or existing.get("username") or default_username).strip() or default_username,
        "sshMode": ssh_mode,
        "authType": "private_key" if ssh_mode.endswith("_key") else "password",
        "sudoRequired": ssh_mode.endswith("_sudo"),
        "password": preserve_secret(
            payload.get("password"),
            existing.get("password"),
            allow_blank=coerce_bool(payload.get("clearPassword"), False),
        ),
        "privateKeyPath": str(payload.get("privateKeyPath") or existing.get("privateKeyPath") or "").strip(),
        "passphrase": preserve_secret(
            payload.get("passphrase"),
            existing.get("passphrase"),
            allow_blank=coerce_bool(payload.get("clearPassphrase"), False),
        ),
    }
    if ssh_mode.startswith("root_"):
        profile["username"] = "root"
        profile["sudoRequired"] = False
    return profile


def repair_bootstrap_server_profile(environment):
    environment = environment or {}
    server = environment.get("server") or {}
    bootstrap = environment.get("bootstrap") or {}
    initial_mode = normalize_ssh_mode(bootstrap.get("initialSshMode"), "")
    runtime_key_path = str(bootstrap.get("runtimeKeyPath") or "").strip()
    bootstrap_ready = str(bootstrap.get("status") or "").strip().lower() == "ready"
    current_mode = normalize_ssh_mode(server.get("sshMode"), "")
    current_key_path = str(server.get("privateKeyPath") or "").strip()

    if not initial_mode or not bootstrap_ready:
        return environment

    # Older builds overwrote the saved SSH profile with the runtime key profile.
    # Repair the user-facing server settings so the UI still reflects the original bootstrap login.
    if current_mode in ("root_key", "user_key_sudo") or (runtime_key_path and current_key_path == runtime_key_path):
        server["sshMode"] = initial_mode
        server["authType"] = "private_key" if "_key" in initial_mode else "password"
        if server["authType"] == "password":
            server["privateKeyPath"] = ""
            server["passphrase"] = ""
        elif runtime_key_path and current_key_path == runtime_key_path:
            server["privateKeyPath"] = ""
        environment["server"] = server

    return environment


def default_process_matchers(products):
    matchers = []
    if products.get("oam") or products.get("weblogic"):
        matchers.extend(["AdminServer", "weblogic", "oam", "ohs"])
    if products.get("oud"):
        matchers.extend(["oud"])
    if products.get("oig"):
        matchers.extend(["oig", "oim"])
    if not matchers:
        matchers = ["sshd", "python"]
    return matchers


def default_environment(name=None, host=None):
    schedule_minutes = default_collection_minutes()
    products = {
        "oam": True,
        "oud": True,
        "oig": False,
        "weblogic": True,
    }
    return {
        "id": slugify(name or host or "iam-environment"),
        "name": name or "IAM Environment",
        "description": "Starter Oracle IAM environment.",
        "environmentType": "",
        "server": {
            "mode": "ssh",
            "host": host or "",
            "port": 22,
            "username": "root",
            "sshMode": "root_password",
            "authType": "password",
            "sudoRequired": False,
            "password": "",
            "privateKeyPath": "",
            "passphrase": "",
        },
        "products": products,
        "serverMetrics": {
            "scriptDirectory": "/refresh/home/auto/bin",
            "processMatchers": default_process_matchers(products),
        },
        "weblogic": {
            "enabled": False,
            "adminUrl": "",
            "adminUsername": "weblogic",
            "adminPassword": "",
            "adminHost": {
                "mode": "ssh",
                "host": "",
                "port": 22,
                "username": "root",
                "sshMode": "root_password",
                "authType": "password",
                "sudoRequired": False,
                "password": "",
                "privateKeyPath": "",
                "passphrase": "",
            },
            "jstatPath": "/refresh/home/jdk-21.0.5/bin/jstat",
            "serverNames": ["AdminServer", "oam_server1"],
        },
        "oam": {
            "checks": deep_copy(DEFAULT_OAM_CHECKS),
        },
        "oud": {
            "host": host or "",
            "port": None,
            "domainHome": "",
            "instanceHome": "",
            "statusPath": "/refresh/home/Instances/oudinst/OUD/bin/status",
            "bindDn": "cn=Directory Manager",
            "bindPassword": "",
            "ldapPort": 1389,
            "adminPort": 4444,
            "ldapUrl": "ldap://localhost:1389",
            "checks": deep_copy(DEFAULT_OUD_CHECKS),
        },
        "oig": {
            "checks": deep_copy(DEFAULT_OIG_CHECKS),
        },
        "collection": {
            "enabled": True,
            "scheduleMinutes": schedule_minutes,
        },
        "bootstrap": {
            "status": "pending",
            "strategy": "initial_ssh_then_runtime_key",
            "initialSshMode": "root_password",
            "runtimeKeyPath": "",
            "runtimeEnvPath": "",
            "lastBootstrappedAt": "",
            "message": "Bootstrap uses the initial SSH access one time and then switches the environment to the installed runtime key for ongoing collection.",
        },
        "operations": {
            "installMethod": "environment_ssh",
            "upgradeMethod": "environment_ssh",
        },
    }


def default_config():
    return {
        "dashboard_title": "Oracle Identity & Access Management Dashboard",
        "monitoring_server": {
            "name": "IAM Monitoring Server",
            "host": "celvpvm04314.us.oracle.com",
            "description": "Hosted dashboard server for Oracle IAM monitoring and administration.",
            "servicePort": 8081,
            "processMatchers": ["iam-monitoring", "python", "sshd"],
        },
        "operations": {
            "installMethod": "environment_ssh",
            "upgradeMethod": "environment_ssh",
        },
        "environments": [],
    }


def map_legacy_checks(checks):
    mapped = []
    for check in checks or []:
        item = check or {}
        name = str(item.get("name") or "").strip()
        url = str(item.get("url") or "").strip()
        product = "oam"
        label = name.lower()
        if "oud" in label:
            product = "oud"
        elif "oig" in label:
            product = "oig"
        mapped.append({
            "product": product,
            "name": name,
            "url": url,
        })
    return mapped


def normalize_environment(payload, existing=None):
    base = default_environment(
        (payload or {}).get("name") or (existing or {}).get("name"),
        ((payload or {}).get("server") or {}).get("host") or ((existing or {}).get("server") or {}).get("host"),
    )
    existing = existing or {}
    payload = payload or {}

    server_payload = payload.get("server") or {}
    existing_server = existing.get("server") or {}
    products_payload = payload.get("products") or {}
    existing_products = existing.get("products") or base.get("products") or {}
    collection_payload = payload.get("collection") or {}
    existing_collection = existing.get("collection") or {}
    bootstrap_payload = payload.get("bootstrap") or {}
    existing_bootstrap = existing.get("bootstrap") or {}

    products = {
        "oam": coerce_bool(products_payload.get("oam"), existing_products.get("oam", True)),
        "oud": coerce_bool(products_payload.get("oud"), existing_products.get("oud", True)),
        "oig": coerce_bool(products_payload.get("oig"), existing_products.get("oig", False)),
        "weblogic": coerce_bool(products_payload.get("weblogic"), existing_products.get("weblogic", True)),
    }

    server_metrics_payload = payload.get("serverMetrics") or {}
    existing_server_metrics = existing.get("serverMetrics") or {}

    oam_payload = payload.get("oam") or {}
    oud_payload = payload.get("oud") or {}
    oig_payload = payload.get("oig") or {}
    weblogic_payload = payload.get("weblogic") or {}
    existing_weblogic = existing.get("weblogic") or {}
    operations_payload = payload.get("operations") or {}
    environment_type = normalize_environment_type(
        payload.get("environmentType"),
        normalize_environment_type((existing or {}).get("environmentType"), ""),
    )
    existing_oud = existing.get("oud") or {}
    oud_host = str(
        oud_payload.get("host")
        or existing_oud.get("host")
        or server_payload.get("host")
        or existing_server.get("host")
        or base["oud"].get("host")
        or ""
    ).strip()
    oud_instance_home = str(
        oud_payload.get("instanceHome")
        or existing_oud.get("instanceHome")
        or base["oud"].get("instanceHome")
        or ""
    ).strip()
    derived_status_path = ""
    if oud_instance_home:
        derived_status_path = "{0}/OUD/bin/status".format(oud_instance_home.rstrip("/"))
    ldap_port = as_int(
        oud_payload.get("ldapPort")
        or existing_oud.get("ldapPort")
        or base["oud"].get("ldapPort")
        or 1389,
        1389,
    )
    admin_port = as_int(
        oud_payload.get("adminPort")
        or existing_oud.get("adminPort")
        or base["oud"].get("adminPort")
        or 4444,
        4444,
    )
    derived_ldap_url = "ldap://localhost:{0}".format(ldap_port)
    weblogic_enabled = coerce_bool(
        weblogic_payload.get("enabled"),
        existing_weblogic.get("enabled", products.get("weblogic")),
    )

    environment = {
        "id": str(payload.get("id") or existing.get("id") or base.get("id")).strip() or base.get("id"),
        "name": str(payload.get("name") or existing.get("name") or base.get("name")).strip() or base.get("name"),
        "description": str(payload.get("description") or existing.get("description") or base.get("description")).strip(),
        "environmentType": environment_type,
        "server": {
            "mode": "ssh",
            "host": str(server_payload.get("host") or existing_server.get("host") or oud_host or base["server"]["host"]).strip(),
            "port": as_int(server_payload.get("port") or existing_server.get("port") or base["server"]["port"], 22),
            "username": str(server_payload.get("username") or existing_server.get("username") or base["server"]["username"]).strip() or "root",
            "sshMode": normalize_ssh_mode(
                server_payload.get("sshMode") or existing_server.get("sshMode"),
                "root_password",
            ),
            "authType": str(server_payload.get("authType") or existing_server.get("authType") or base["server"]["authType"]).strip() or "password",
            "sudoRequired": coerce_bool(server_payload.get("sudoRequired"), existing_server.get("sudoRequired", False)),
            "password": preserve_secret(
                server_payload.get("password"),
                existing_server.get("password"),
                allow_blank=coerce_bool(server_payload.get("clearPassword"), False),
            ),
            "privateKeyPath": str(server_payload.get("privateKeyPath") or existing_server.get("privateKeyPath") or "").strip(),
            "passphrase": preserve_secret(
                server_payload.get("passphrase"),
                existing_server.get("passphrase"),
                allow_blank=coerce_bool(server_payload.get("clearPassphrase"), False),
            ),
        },
        "products": products,
        "serverMetrics": {
            "scriptDirectory": str(
                server_metrics_payload.get("scriptDirectory")
                or existing_server_metrics.get("scriptDirectory")
                or base["serverMetrics"]["scriptDirectory"]
            ).strip(),
            "processMatchers": parse_csv_or_list(
                server_metrics_payload.get("processMatchers"),
                existing_server_metrics.get("processMatchers") or default_process_matchers(products),
            ),
        },
        "weblogic": {
            "enabled": weblogic_enabled,
            "adminUrl": str(
                weblogic_payload.get("adminUrl")
                or existing_weblogic.get("adminUrl")
                or ""
            ).strip(),
            "adminUsername": str(
                weblogic_payload.get("adminUsername")
                or existing_weblogic.get("adminUsername")
                or base["weblogic"].get("adminUsername")
                or "weblogic"
            ).strip() or "weblogic",
            "adminPassword": preserve_secret(
                weblogic_payload.get("adminPassword"),
                existing_weblogic.get("adminPassword"),
                allow_blank=coerce_bool(weblogic_payload.get("clearAdminPassword"), False),
            ),
            "adminHost": normalize_ssh_profile_payload(
                weblogic_payload.get("adminHost"),
                existing_weblogic.get("adminHost"),
                default_host="",
                default_username="root",
                default_port=22,
                default_mode="root_password",
            ),
            "jstatPath": str(
                weblogic_payload.get("jstatPath")
                or existing_weblogic.get("jstatPath")
                or base["weblogic"]["jstatPath"]
            ).strip(),
            "serverNames": parse_csv_or_list(
                weblogic_payload.get("serverNames"),
                existing_weblogic.get("serverNames") or base["weblogic"]["serverNames"],
            ),
        },
        "oam": {
            "checks": normalize_checks(
                oam_payload.get("checks") if "checks" in oam_payload else (existing.get("oam") or {}).get("checks"),
                DEFAULT_OAM_CHECKS,
            ),
        },
        "oud": {
            "host": oud_host,
            "port": as_optional_int(
                oud_payload.get("port")
                if "port" in oud_payload
                else existing_oud.get("port")
            ),
            "domainHome": str(
                oud_payload.get("domainHome")
                or existing_oud.get("domainHome")
                or base["oud"].get("domainHome")
                or ""
            ).strip(),
            "instanceHome": oud_instance_home,
            "statusPath": str(
                oud_payload.get("statusPath")
                or existing_oud.get("statusPath")
                or derived_status_path
                or base["oud"]["statusPath"]
            ).strip(),
            "bindDn": str(
                oud_payload.get("bindDn")
                or existing_oud.get("bindDn")
                or base["oud"]["bindDn"]
            ).strip(),
            "bindPassword": preserve_secret(
                oud_payload.get("bindPassword"),
                existing_oud.get("bindPassword") or environment_server_password(server_payload, existing_server),
                allow_blank=coerce_bool(oud_payload.get("clearBindPassword"), False),
            ),
            "ldapPort": ldap_port,
            "adminPort": admin_port,
            "ldapUrl": str(
                oud_payload.get("ldapUrl")
                or existing_oud.get("ldapUrl")
                or derived_ldap_url
                or base["oud"]["ldapUrl"]
            ).strip(),
            "checks": normalize_checks(
                oud_payload.get("checks") if "checks" in oud_payload else existing_oud.get("checks"),
                DEFAULT_OUD_CHECKS,
            ),
        },
        "oig": {
            "checks": normalize_checks(
                oig_payload.get("checks") if "checks" in oig_payload else (existing.get("oig") or {}).get("checks"),
                DEFAULT_OIG_CHECKS,
            ),
        },
        "collection": {
            "enabled": coerce_bool(
                collection_payload.get("enabled"),
                existing_collection.get("enabled", True),
            ),
            "scheduleMinutes": sanitize_schedule_minutes(
                collection_payload.get("scheduleMinutes")
                or collection_payload.get("intervalMinutes")
                or existing_collection.get("scheduleMinutes")
                or default_collection_minutes(),
                default_collection_minutes(),
            ),
        },
        "bootstrap": {
            "status": str(
                bootstrap_payload.get("status")
                or existing_bootstrap.get("status")
                or base["bootstrap"].get("status")
            ).strip() or "pending",
            "strategy": str(
                bootstrap_payload.get("strategy")
                or existing_bootstrap.get("strategy")
                or base["bootstrap"].get("strategy")
            ).strip() or "initial_ssh_then_runtime_key",
            "initialSshMode": str(
                bootstrap_payload.get("initialSshMode")
                or existing_bootstrap.get("initialSshMode")
                or server_payload.get("sshMode")
                or existing_server.get("sshMode")
                or base["bootstrap"].get("initialSshMode")
            ).strip() or "root_password",
            "runtimeKeyPath": str(
                bootstrap_payload.get("runtimeKeyPath")
                or existing_bootstrap.get("runtimeKeyPath")
                or base["bootstrap"].get("runtimeKeyPath")
                or ""
            ).strip(),
            "runtimeEnvPath": str(
                bootstrap_payload.get("runtimeEnvPath")
                or existing_bootstrap.get("runtimeEnvPath")
                or base["bootstrap"].get("runtimeEnvPath")
                or ""
            ).strip(),
            "lastBootstrappedAt": str(
                bootstrap_payload.get("lastBootstrappedAt")
                or existing_bootstrap.get("lastBootstrappedAt")
                or base["bootstrap"].get("lastBootstrappedAt")
                or ""
            ).strip(),
            "message": str(
                bootstrap_payload.get("message")
                or existing_bootstrap.get("message")
                or base["bootstrap"].get("message")
            ).strip(),
        },
        "operations": {
            "installMethod": str(
                operations_payload.get("installMethod")
                or (existing.get("operations") or {}).get("installMethod")
                or "environment_ssh"
            ).strip(),
            "upgradeMethod": str(
                operations_payload.get("upgradeMethod")
                or (existing.get("operations") or {}).get("upgradeMethod")
                or "environment_ssh"
            ).strip(),
        },
    }

    if not environment["serverMetrics"]["processMatchers"]:
        environment["serverMetrics"]["processMatchers"] = default_process_matchers(products)

    ssh_mode = normalize_ssh_mode(
        server_payload.get("sshMode") or existing_server.get("sshMode"),
        environment["server"].get("sshMode") or "root_password",
    )
    environment["server"]["sshMode"] = ssh_mode
    environment["server"]["authType"] = "private_key" if ssh_mode.endswith("_key") else "password"
    if ssh_mode.startswith("root_"):
        environment["server"]["username"] = "root"
        environment["server"]["sudoRequired"] = False
    else:
        environment["server"]["sudoRequired"] = True

    if not environment["oam"]["checks"] and products.get("oam"):
        environment["oam"]["checks"] = deep_copy(DEFAULT_OAM_CHECKS)

    if not environment["oud"]["checks"] and products.get("oud"):
        environment["oud"]["checks"] = deep_copy(DEFAULT_OUD_CHECKS)

    environment["weblogic"]["enabled"] = bool(products.get("weblogic"))

    return environment


def environment_server_password(server_payload, existing_server):
    candidate = (server_payload or {}).get("password")
    if candidate:
        return str(candidate).strip()
    return str((existing_server or {}).get("password") or "").strip()


def normalize_config(config):
    config = config or {}
    defaults = default_config()
    monitoring_server = config.get("monitoring_server") or {}
    operations = config.get("operations") or {}
    environments = [normalize_environment(item) for item in config.get("environments", [])]

    return {
        "dashboard_title": str(config.get("dashboard_title") or defaults["dashboard_title"]).strip(),
        "monitoring_server": {
            "name": str(monitoring_server.get("name") or defaults["monitoring_server"]["name"]).strip(),
            "host": str(monitoring_server.get("host") or defaults["monitoring_server"]["host"]).strip(),
            "description": str(
                monitoring_server.get("description") or defaults["monitoring_server"]["description"]
            ).strip(),
            "servicePort": as_int(
                monitoring_server.get("servicePort") or defaults["monitoring_server"]["servicePort"],
                defaults["monitoring_server"]["servicePort"],
            ),
            "processMatchers": parse_csv_or_list(
                monitoring_server.get("processMatchers"),
                defaults["monitoring_server"]["processMatchers"],
            ),
        },
        "operations": {
            "installMethod": str(operations.get("installMethod") or defaults["operations"]["installMethod"]).strip(),
            "upgradeMethod": str(operations.get("upgradeMethod") or defaults["operations"]["upgradeMethod"]).strip(),
        },
        "environments": environments or defaults["environments"],
    }


def migrate_legacy_config(config):
    if not config or "targets" not in config:
        return normalize_config(config)

    monitoring_target = None
    application_target = None
    for target in config.get("targets", []):
        role = str((target or {}).get("role") or "").lower()
        if monitoring_target is None and "monitoring" in role:
            monitoring_target = target
        elif application_target is None and ("oam" in str((target or {}).get("name") or "").lower() or target.get("oam") or target.get("oud")):
            application_target = target

    if monitoring_target is None and config.get("targets"):
        monitoring_target = config["targets"][0]
    if application_target is None and len(config.get("targets", [])) > 1:
        application_target = config["targets"][1]

    migrated = default_config()
    migrated["dashboard_title"] = config.get("dashboard_title") or migrated["dashboard_title"]

    if monitoring_target:
        migrated["monitoring_server"]["name"] = monitoring_target.get("name") or "IAM Monitoring Server"
        migrated["monitoring_server"]["host"] = monitoring_target.get("host") or migrated["monitoring_server"]["host"]
        migrated["monitoring_server"]["processMatchers"] = monitoring_target.get("process_matchers") or migrated["monitoring_server"]["processMatchers"]

    if application_target:
        legacy_checks = map_legacy_checks(application_target.get("app_checks") or [])
        seed = default_environment(
            application_target.get("name") or "Imported IAM Environment",
            application_target.get("host"),
        )
        seed["description"] = "Imported from the earlier dashboard target configuration."
        seed["server"]["host"] = application_target.get("host") or seed["server"]["host"]
        seed["server"]["username"] = application_target.get("username") or seed["server"]["username"]
        seed["server"]["password"] = application_target.get("password") or seed["server"]["password"]
        seed["serverMetrics"]["scriptDirectory"] = application_target.get("script_directory") or seed["serverMetrics"]["scriptDirectory"]
        seed["serverMetrics"]["processMatchers"] = application_target.get("process_matchers") or seed["serverMetrics"]["processMatchers"]
        if application_target.get("oam"):
            seed["weblogic"]["jstatPath"] = (application_target.get("oam") or {}).get("jstat_path") or seed["weblogic"]["jstatPath"]
            seed["weblogic"]["serverNames"] = (application_target.get("oam") or {}).get("server_names") or seed["weblogic"]["serverNames"]
        if application_target.get("oud"):
            legacy_oud = application_target.get("oud") or {}
            seed["oud"]["statusPath"] = legacy_oud.get("status_path") or seed["oud"]["statusPath"]
            seed["oud"]["bindDn"] = legacy_oud.get("bind_dn") or seed["oud"]["bindDn"]
            seed["oud"]["bindPassword"] = legacy_oud.get("bind_password") or seed["oud"]["bindPassword"]
            seed["oud"]["ldapUrl"] = legacy_oud.get("ldap_url") or seed["oud"]["ldapUrl"]
        if legacy_checks:
            seed["oam"]["checks"] = [item for item in legacy_checks if item["product"] == "oam"]
            seed["oud"]["checks"] = [item for item in legacy_checks if item["product"] == "oud"] or seed["oud"]["checks"]
            seed["oig"]["checks"] = [item for item in legacy_checks if item["product"] == "oig"]
        migrated["environments"] = [normalize_environment(seed)]

    return normalize_config(migrated)


def load_config(path):
    if not os.path.isfile(path):
        config = normalize_config(default_config())
        save_config(path, config)
        return config

    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    if "targets" in raw and "environments" not in raw:
        raw = migrate_legacy_config(raw)
        save_config(path, raw)
        return raw

    config = normalize_config(raw)
    if config != raw:
        save_config(path, config)
    return config


def save_config(path, config):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    temp_path = "{0}.tmp".format(path)
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=False)
        handle.write("\n")
    os.replace(temp_path, path)


def find_environment(config, environment_id):
    for environment in config.get("environments", []):
        if environment.get("id") == environment_id:
            return environment
    return None


def unique_environment_id(config, base_id, exclude_id=None):
    existing_ids = [item.get("id") for item in config.get("environments", []) if item.get("id") != exclude_id]
    candidate = slugify(base_id)
    if candidate not in existing_ids:
        return candidate
    index = 2
    while True:
        trial = "{0}-{1}".format(candidate, index)
        if trial not in existing_ids:
            return trial
        index += 1


def upsert_environment(config, payload, environment_id=None):
    config.setdefault("environments", [])
    existing = find_environment(config, environment_id or payload.get("id"))
    normalized = normalize_environment(payload, existing)
    normalized["id"] = unique_environment_id(config, normalized.get("id") or normalized.get("name"), existing.get("id") if existing else None)

    if existing:
        for index, environment in enumerate(config["environments"]):
            if environment.get("id") == existing.get("id"):
                config["environments"][index] = normalized
                return normalized

    config["environments"].append(normalized)
    return normalized


def delete_environment(config, environment_id):
    environments = config.get("environments", [])
    updated = [environment for environment in environments if environment.get("id") != environment_id]
    deleted = len(updated) != len(environments)
    config["environments"] = updated
    return deleted


def serialize_environment(environment, include_sensitive=False):
    environment = environment or {}
    server = environment.get("server") or {}
    oud = environment.get("oud") or {}
    weblogic = environment.get("weblogic") or {}
    weblogic_admin_host = weblogic.get("adminHost") or {}

    payload = {
        "id": environment.get("id"),
        "name": environment.get("name"),
        "description": environment.get("description"),
        "environmentType": normalize_environment_type(environment.get("environmentType"), ""),
        "server": {
            "mode": server.get("mode") or "ssh",
            "host": server.get("host") or "",
            "port": server.get("port") or 22,
            "username": server.get("username") or "",
            "sshMode": normalize_ssh_mode(server.get("sshMode"), "root_password"),
            "authType": server.get("authType") or "password",
            "sudoRequired": bool(server.get("sudoRequired")),
            "privateKeyPath": server.get("privateKeyPath") or "",
            "hasPassword": bool(server.get("password")),
            "hasPassphrase": bool(server.get("passphrase")),
        },
        "products": deep_copy(environment.get("products") or {}),
        "serverMetrics": deep_copy(environment.get("serverMetrics") or {}),
        "weblogic": {
            "enabled": bool(weblogic.get("enabled")),
            "adminUrl": weblogic.get("adminUrl") or "",
            "adminUsername": weblogic.get("adminUsername") or "",
            "adminPassword": "",
            "hasAdminPassword": bool(weblogic.get("adminPassword")),
            "adminHost": {
                "mode": weblogic_admin_host.get("mode") or "ssh",
                "host": weblogic_admin_host.get("host") or "",
                "port": weblogic_admin_host.get("port") or 22,
                "username": weblogic_admin_host.get("username") or "",
                "sshMode": normalize_ssh_mode(weblogic_admin_host.get("sshMode"), "root_password"),
                "authType": weblogic_admin_host.get("authType") or "password",
                "sudoRequired": bool(weblogic_admin_host.get("sudoRequired")),
                "privateKeyPath": weblogic_admin_host.get("privateKeyPath") or "",
                "hasPassword": bool(weblogic_admin_host.get("password")),
                "hasPassphrase": bool(weblogic_admin_host.get("passphrase")),
            },
            "jstatPath": weblogic.get("jstatPath") or "",
            "serverNames": deep_copy(weblogic.get("serverNames") or []),
        },
        "oam": deep_copy(environment.get("oam") or {}),
        "collection": deep_copy(environment.get("collection") or {}),
        "bootstrap": deep_copy(environment.get("bootstrap") or {}),
        "oud": {
            "host": oud.get("host") or "",
            "port": oud.get("port"),
            "domainHome": oud.get("domainHome") or "",
            "instanceHome": oud.get("instanceHome") or "",
            "statusPath": oud.get("statusPath") or "",
            "bindDn": oud.get("bindDn") or "",
            "bindPassword": "",
            "hasBindPassword": bool(oud.get("bindPassword")),
            "ldapPort": oud.get("ldapPort") or 1389,
            "adminPort": oud.get("adminPort") or 4444,
            "ldapUrl": oud.get("ldapUrl") or "",
            "checks": deep_copy(oud.get("checks") or []),
        },
        "oig": deep_copy(environment.get("oig") or {}),
        "operations": deep_copy(environment.get("operations") or {}),
    }

    if include_sensitive:
        payload["server"]["password"] = server.get("password") or ""
        payload["server"]["passphrase"] = server.get("passphrase") or ""
        payload["weblogic"]["adminPassword"] = weblogic.get("adminPassword") or ""
        payload["weblogic"]["adminHost"]["password"] = weblogic_admin_host.get("password") or ""
        payload["weblogic"]["adminHost"]["passphrase"] = weblogic_admin_host.get("passphrase") or ""
        payload["oud"]["bindPassword"] = oud.get("bindPassword") or ""

    return payload
